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
/// Returns `Ok(false)` if the image already exists (idempotent).
pub async fn register_image(
    project: &str,
    image_name: &str,
    gcs_uri: &str,
    cc_types: &[CcType],
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    let features_flag = guest_os_features_for(cc_types);
    match runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "images",
                "create",
                image_name,
                "--project",
                project,
                "--source-uri",
                gcs_uri,
                &features_flag,
                "--format=json",
            ],
        )
        .await
    {
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
