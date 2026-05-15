use crate::config::{CcType, guest_os_features_for};
use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Ensure the GCS bucket exists.
pub async fn ensure_bucket(
    project: &str,
    bucket: &str,
    location: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    // Extract region from zone (e.g. "us-central1-a" -> "us-central1").
    let region = location
        .rsplit_once('-')
        .map(|(r, _)| r)
        .unwrap_or(location);

    // Check if bucket exists.
    match runner
        .run_capture(
            "gcloud",
            &["storage", "buckets", "describe", &format!("gs://{bucket}")],
        )
        .await
    {
        Ok(_) => return Ok(()),
        Err(CloudError::CommandFailed { .. }) => {} // doesn't exist, create it
        Err(e) => return Err(e),
    }

    runner
        .run_capture(
            "gcloud",
            &[
                "storage",
                "buckets",
                "create",
                &format!("gs://{bucket}"),
                "--project",
                project,
                "--location",
                region,
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create bucket: {e}"),
        })?;

    Ok(())
}

/// Upload image file to GCS.
pub async fn upload_image(
    bucket: &str,
    source_path: &str,
    runner: &dyn CommandRunner,
    _verbose: bool,
) -> Result<String, CloudError> {
    let filename = std::path::Path::new(source_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("image.raw.tar.gz");
    let gcs_uri = format!("gs://{bucket}/{filename}");

    // Use `gcloud storage cp` (Go-native) instead of `gsutil cp` (Python).
    // gsutil's parallel composite upload mode (triggered for files >150 MB)
    // spawns Python multiprocessing workers that crash on macOS with the
    // bundled gcloud SDK Python. `gcloud storage` handles parallel transfer
    // natively and avoids the issue.
    runner
        .run_stream(
            "gcloud",
            &["storage", "cp", source_path, &gcs_uri],
            true,
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to upload image: {e}"),
        })?;

    Ok(gcs_uri)
}

/// Register a GCS object as a GCE image.
///
/// The image is registered with custom Secure Boot variables (PK / KEK /
/// db / dbx) sourced from `certs_dir`. PK, KEK, and db are required;
/// `kernel.crt` (additional db entry) and `dbx.crt` are optional. The
/// resulting image has Secure Boot enabled and its UEFI variables seeded
/// with the supplied certs instead of GCE's placeholder PK + Microsoft
/// KEK/db defaults.
///
/// Returns `Ok(false)` if the image already exists (idempotent).
pub async fn register_image(
    project: &str,
    image_name: &str,
    gcs_uri: &str,
    cc_types: &[CcType],
    certs_dir: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    let features_flag = guest_os_features_for(cc_types);
    let project_flag = format!("--project={project}");
    let source_uri_flag = format!("--source-uri={gcs_uri}");

    let cert_flags = secure_boot_cert_flags(certs_dir)?;

    let mut args: Vec<String> = vec![
        "compute".into(),
        "images".into(),
        "create".into(),
        image_name.into(),
        project_flag,
        source_uri_flag,
        features_flag,
        "--format=json".into(),
    ];
    args.extend(cert_flags);

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match runner.run_capture("gcloud", &arg_refs).await {
        Ok(_) => Ok(true),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("already exists") =>
        {
            tracing::info!("image '{image_name}' already exists, skipping registration");
            Ok(false)
        }
        Err(e) => Err(CloudError::ImageUploadFailed {
            message: format!("failed to register image: {e}"),
        }),
    }
}

/// Build the `--platform-key-file` / `--key-exchange-key-file` /
/// `--signature-database-file` / `--forbidden-database-file` flags for a
/// `gcloud compute images create` call.
///
/// Expected layout under `certs_dir` (PK / KEK / db / kernel are all
/// required; dbx is optional):
///   PK.crt        → --platform-key-file
///   KEK.crt       → --key-exchange-key-file
///   db.crt        ┐
///   kernel.crt    ┴→ --signature-database-file=db.crt,kernel.crt
///   dbx.crt       → --forbidden-database-file        (optional)
///
/// `gcloud` accepts a comma-separated list of files for the db/dbx flags,
/// matching the original deployment shell that passed
/// `--signature-database-file=db.crt,kernel.crt`.
///
/// Returns an error if any required cert is missing. Secure Boot is a
/// hard requirement of every GCE image atakit registers — there is no
/// "soft fallback" to GCE's default Microsoft KEK/db.
fn secure_boot_cert_flags(certs_dir: &str) -> Result<Vec<String>, CloudError> {
    let dir = std::path::Path::new(certs_dir);
    let pk = dir.join("PK.crt");
    let kek = dir.join("KEK.crt");
    let db = dir.join("db.crt");
    let kernel = dir.join("kernel.crt");
    let dbx = dir.join("dbx.crt");

    let mut missing = Vec::new();
    if !pk.exists() {
        missing.push("PK.crt");
    }
    if !kek.exists() {
        missing.push("KEK.crt");
    }
    if !db.exists() {
        missing.push("db.crt");
    }
    if !kernel.exists() {
        missing.push("kernel.crt");
    }
    if !missing.is_empty() {
        return Err(CloudError::ImageUploadFailed {
            message: format!(
                "secure boot certs missing from '{certs_dir}': {} — \
                 GCE images registered by atakit must carry custom \
                 PK/KEK/db. Ensure the base image archive (.atabi) was \
                 imported with its secure_boot_certs/ directory intact.",
                missing.join(", "),
            ),
        });
    }

    let db_files = format!("{},{}", db.display(), kernel.display());
    let mut flags = vec![
        format!("--platform-key-file={}", pk.display()),
        format!("--key-exchange-key-file={}", kek.display()),
        format!("--signature-database-file={db_files}"),
    ];
    if dbx.exists() {
        flags.push(format!("--forbidden-database-file={}", dbx.display()));
    }

    Ok(flags)
}

/// Check if a GCE image already exists.
pub async fn check_image_exists(
    project: &str,
    image_name: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    match runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "images",
                "describe",
                image_name,
                "--project",
                project,
                "--format=json",
            ],
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(CloudError::CommandFailed { stderr, .. }) if stderr.contains("was not found") => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Delete a GCE image.
pub async fn delete_image(
    project: &str,
    image_name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "images",
                "delete",
                image_name,
                "--project",
                project,
                "--quiet",
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. }) if stderr.contains("was not found") => {
            tracing::debug!("image '{image_name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("image/{image_name}"),
            message: e.to_string(),
        }),
    }
}

/// Delete a GCS bucket and all contents.
pub async fn delete_bucket(bucket: &str, runner: &dyn CommandRunner) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "gcloud",
            &["storage", "rm", "--recursive", &format!("gs://{bucket}")],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("BucketNotFoundException")
                || stderr.contains("No URLs matched")
                || stderr.contains("not found")
                || stderr.contains("does not exist") =>
        {
            tracing::debug!("bucket '{bucket}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("bucket/{bucket}"),
            message: e.to_string(),
        }),
    }
}
