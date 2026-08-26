use std::io::{Cursor, Read, Seek};
use std::path::PathBuf;

use sha2::{Digest, Sha256, Sha384};

use crate::data::DataRoots;
use crate::image::ContainerEngine;
use crate::manifest::Manifest;
use crate::WorkloadError;

/// Options for inspecting a workload.
pub struct InspectOptions {
    /// Path to an `.atawl` archive.
    pub archive: Option<PathBuf>,
    /// Path to a workload source directory.
    pub workload_dir: Option<PathBuf>,
    /// Fingerprint of the publishing key, for dir mode only.
    ///
    /// Directory inspection builds the manifest to compute PCR23, and the
    /// publisher is measured, so a PCR23 computed without it would not match
    /// the one any build of the same directory produces. Archive mode ignores
    /// this: the archive already carries its publisher.
    pub publisher: Option<String>,
    /// Container engine override (for dir mode).
    pub engine: Option<ContainerEngine>,
    /// Show verbose output from container commands.
    pub verbose: bool,
    /// Root for logical measured-data paths in dir mode. Defaults to
    /// `<workload_dir>/measured-data`.
    pub measured_data_root: Option<PathBuf>,
    /// Root for logical unmeasured-data declarations in dir mode. Defaults to
    /// `<workload_dir>/unmeasured-data`.
    pub unmeasured_data_root: Option<PathBuf>,
}

/// Result of inspecting a workload.
pub struct InspectResult {
    /// SHA-256 of manifest bytes as `0x<64-hex-chars>` (the event hash).
    pub sha256: String,
    /// Final PCR23 register value as `0x<64-hex-chars>`: `SHA-256(zeros_32 || sha256)`.
    pub pcr23_sha256: String,
    /// Final SHA-384 PCR23 register value.
    pub pcr23_sha384: String,
    /// SHA-384 of manifest bytes as `0x<96-hex-chars>`.
    pub sha384: String,
    /// SHA-256 hash of the manifest as `sha256:<64-hex-chars>`.
    pub manifest_hash: String,
    /// Parsed manifest.
    pub manifest: Manifest,
    /// Raw canonical manifest JSON, exactly as measured.
    pub manifest_raw: String,
}

/// Inspect a workload from an `.atawl` archive or a source directory.
pub async fn inspect_workload(opts: &InspectOptions) -> Result<InspectResult, WorkloadError> {
    if let Some(ref archive_path) = opts.archive {
        inspect_archive(archive_path)
    } else if let Some(ref workload_dir) = opts.workload_dir {
        let publisher = opts.publisher.as_deref().ok_or_else(|| {
            WorkloadError::Validation(
                "inspecting a workload directory requires a publisher, because the \
                 publisher is measured and PCR23 cannot be computed without it"
                    .to_string(),
            )
        })?;
        inspect_dir(
            workload_dir,
            publisher,
            opts.engine,
            opts.verbose,
            opts.measured_data_root.as_ref(),
            opts.unmeasured_data_root.as_ref(),
        )
        .await
    } else {
        Err(WorkloadError::Validation(
            "either --archive or --dir must be specified".into(),
        ))
    }
}

/// Inspect from an `.atawl` archive: extract manifest, compute PCR23.
fn inspect_archive(archive_path: &std::path::Path) -> Result<InspectResult, WorkloadError> {
    let file = std::fs::File::open(archive_path).map_err(|e| WorkloadError::ReadFile {
        path: archive_path.to_path_buf(),
        source: e,
    })?;
    inspect_archive_reader(file)
}

/// Inspect an `.atawl` archive from one immutable byte snapshot.
pub fn inspect_workload_archive_bytes(bytes: &[u8]) -> Result<InspectResult, WorkloadError> {
    inspect_archive_reader(Cursor::new(bytes))
}

fn inspect_archive_reader<R>(reader: R) -> Result<InspectResult, WorkloadError>
where
    R: Read + Seek,
{
    let decoder = crate::archive::open_decoder(reader)?;
    let mut archive = tar::Archive::new(decoder);

    let mut manifest_json = None;
    let mut manifest_toml = false;
    for entry in archive.entries().map_err(WorkloadError::Io)? {
        let mut entry = entry.map_err(WorkloadError::Io)?;
        let path = entry.path().map_err(WorkloadError::Io)?;
        if let Some(filename) = path.file_name() {
            if filename == "manifest.json" {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(WorkloadError::Io)?;
                manifest_json = Some(content);
                break;
            } else if filename == "manifest.toml" {
                // A `manifest.toml` archive is format 1, which records no
                // publisher. Note it so the failure can name what was found,
                // and keep scanning in case a manifest.json follows.
                manifest_toml = true;
            }
        }
    }

    if let Some(raw) = manifest_json {
        build_result_json(raw)
    } else if manifest_toml {
        Err(WorkloadError::Validation(format!(
            "archive contains a format-1 manifest.toml, which records no publisher and so cannot yield a publisher-qualified identifier; rebuild it from its source with `atakit workload build <workload-directory>` to create manifest format {}",
            crate::FORMAT_VERSION
        )))
    } else {
        Err(WorkloadError::Validation(
            "neither manifest.json nor manifest.toml found in archive".into(),
        ))
    }
}

/// Inspect from a workload source directory: parse config, build manifest, compute PCR23.
async fn inspect_dir(
    workload_dir: &std::path::Path,
    publisher: &str,
    engine_override: Option<ContainerEngine>,
    verbose: bool,
    measured_data_root: Option<&PathBuf>,
    unmeasured_data_root: Option<&PathBuf>,
) -> Result<InspectResult, WorkloadError> {
    let workload_dir = if workload_dir.is_absolute() {
        workload_dir.to_path_buf()
    } else {
        std::fs::canonicalize(workload_dir).map_err(WorkloadError::Io)?
    };

    let config = crate::config::WorkloadConfig::from_dir(&workload_dir)?;
    let data_roots = DataRoots::resolve(&workload_dir, measured_data_root, unmeasured_data_root);
    let warnings =
        crate::validate::validate_config_with_roots(&config, &workload_dir, &data_roots)?;
    for w in &warnings {
        tracing::warn!("{}", w);
    }

    let name = &config.workload.name;
    let version = &config.workload.version;
    let resolved_image = crate::manifest::resolve_image_ref(&config.workload.image, name, version);

    // Stage measured-data files into a temp dir for hashing
    let temp_dir = tempfile::tempdir().map_err(WorkloadError::Io)?;
    let staging = crate::archive::StagingDir::create(temp_dir.path(), name)?;

    // Stage measured-data (from [package] section)
    let measured_paths = config.measured_data_paths();
    if !measured_paths.is_empty() {
        staging.stage_measured_data(measured_paths, &data_roots.measured)?;
    }

    // We need to stage the image to compute hashes, but for dir mode we need
    // a container engine to save the image. Handle each image source type.
    let tar_name = crate::archive::image_tar_name(name);
    stage_image(
        &config.workload.image,
        &resolved_image,
        &tar_name,
        &staging,
        &workload_dir,
        engine_override,
        verbose,
    )
    .await?;

    // Stage dependency images.
    let mut dep_names: Vec<_> = config.dependencies.keys().collect();
    dep_names.sort();
    for dep_name in &dep_names {
        let dep = &config.dependencies[*dep_name];
        let dep_resolved = crate::manifest::resolve_image_ref(&dep.image, dep_name, version);
        let dep_tar = crate::archive::image_tar_name(dep_name);
        stage_image(
            &dep.image,
            &dep_resolved,
            &dep_tar,
            &staging,
            &workload_dir,
            engine_override,
            verbose,
        )
        .await?;
    }

    // Hash all staged content
    let mut hashes = crate::hash::hash_directory(&staging.root, "measured-data")?;
    let image_hashes = crate::hash::hash_directory(&staging.root, "images")?;
    hashes.extend(image_hashes);

    // Extract per-service image IDs from the staged tars.
    let mut images = std::collections::BTreeMap::new();
    images.insert(name.clone(), build_image_meta(&staging, &tar_name)?);
    for dep_name in &dep_names {
        let dep_tar = crate::archive::image_tar_name(dep_name);
        images.insert((*dep_name).clone(), build_image_meta(&staging, &dep_tar)?);
    }

    // Resolve environment (workload + dependencies)
    let environment = crate::manifest::resolve_environment(
        &config.workload.env_file,
        &config.workload.environment,
        &workload_dir,
    )?;
    let mut dep_environments = std::collections::BTreeMap::new();
    for dep_name in &dep_names {
        let dep = &config.dependencies[*dep_name];
        let dep_env =
            crate::manifest::resolve_environment(&dep.env_file, &dep.environment, &workload_dir)?;
        dep_environments.insert((*dep_name).clone(), dep_env);
    }

    // Build manifest
    let unmeasured_data = crate::manifest::normalize_unmeasured_data(
        config.unmeasured_data_paths(),
        &data_roots.unmeasured,
    );
    let unmeasured_env_files =
        crate::manifest::resolve_unmeasured_env_allowlists(&config, &data_roots.unmeasured)?;
    let manifest = crate::manifest::build_manifest(
        &config,
        publisher,
        &resolved_image,
        environment,
        dep_environments,
        hashes,
        unmeasured_data,
        unmeasured_env_files,
        images,
    )?;
    let manifest_raw = crate::manifest::serialize_canonical_json(&manifest)?;

    build_result_json(manifest_raw)
}

fn build_image_meta(
    staging: &crate::archive::StagingDir,
    tar_name: &str,
) -> Result<crate::manifest::ManifestImage, WorkloadError> {
    let path = staging.image_tar_path(tar_name);
    let image_id = crate::image_meta::read_image_id(&path)?;
    Ok(crate::manifest::ManifestImage {
        archive: format!("images/{tar_name}"),
        image_id,
    })
}

/// Stage a single container image into the staging directory.
async fn stage_image(
    source: &crate::config::ImageSource,
    resolved_ref: &str,
    tar_name: &str,
    staging: &crate::archive::StagingDir,
    workload_dir: &std::path::Path,
    engine_override: Option<ContainerEngine>,
    verbose: bool,
) -> Result<(), WorkloadError> {
    match source {
        crate::config::ImageSource::File { file } => {
            let src = workload_dir.join(file);
            staging.stage_image_file(&src, tar_name)?;
        }
        crate::config::ImageSource::Registry(reference) => {
            let engine = match engine_override {
                Some(e) => e,
                None => ContainerEngine::detect().await?,
            };
            engine.pull_image(reference).await?;
            engine
                .save_image(reference, &staging.image_tar_path(tar_name))
                .await?;
        }
        crate::config::ImageSource::Build {
            build,
            containerfile,
            args,
        } => {
            let engine = match engine_override {
                Some(e) => e,
                None => ContainerEngine::detect().await?,
            };
            let context = workload_dir.join(build);
            engine
                .build_image(
                    &context,
                    containerfile.as_deref(),
                    resolved_ref,
                    args,
                    verbose,
                )
                .await?;
            engine
                .save_image(resolved_ref, &staging.image_tar_path(tar_name))
                .await?;
        }
    }
    Ok(())
}

/// Compute PCR23 and build InspectResult from raw manifest JSON (v2).
fn build_result_json(manifest_raw: String) -> Result<InspectResult, WorkloadError> {
    let mut value: serde_json::Value =
        serde_json::from_str(&manifest_raw).map_err(|e| WorkloadError::Json(e.to_string()))?;
    validate_json_manifest_format(&value)?;
    reject_legacy_service_disks(&mut value)?;
    let manifest: Manifest =
        serde_json::from_value(value).map_err(|e| WorkloadError::Json(e.to_string()))?;
    compute_pcr_result(manifest, manifest_raw)
}

fn validate_json_manifest_format(value: &serde_json::Value) -> Result<(), WorkloadError> {
    let format = value
        .get("meta")
        .and_then(|meta| meta.get("format"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            WorkloadError::Validation(format!(
                "workload archive manifest.json is missing integer meta.format; rebuild it from its source with `atakit workload build <workload-directory>` to create manifest format {}",
                crate::FORMAT_VERSION
            ))
        })?;

    if format == u64::from(crate::FORMAT_VERSION) {
        return Ok(());
    }
    if format > u64::from(crate::FORMAT_VERSION) {
        return Err(WorkloadError::Validation(format!(
            "workload manifest format {format} is newer than supported format {}; upgrade atakit to a version that supports workload manifest format {format}",
            crate::FORMAT_VERSION
        )));
    }
    // No older manifest records a publisher, and none allows one to be derived,
    // so an older archive cannot produce the identifier its workload is
    // registered under. Rebuilding is the only correct answer; converting would
    // invent a publisher.
    Err(WorkloadError::Validation(format!(
        "workload manifest format {format} predates the publisher-qualified identifier and cannot be converted, because it records no publisher; rebuild it from its source with `atakit workload build <workload-directory>` to create manifest format {}",
        crate::FORMAT_VERSION
    )))
}

/// Reject a legacy `config.disks` mapping on the service or any dependency.
///
/// `config.storage` replaced `config.disks` before the current manifest format.
/// Only one format is accepted now, so a manifest still carrying `disks` is
/// malformed rather than merely old, and converting it would be guesswork.
fn reject_legacy_service_disks(value: &mut serde_json::Value) -> Result<(), WorkloadError> {
    let Some(config) = value
        .get_mut("config")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Ok(());
    };
    reject_legacy_disks_for_service("config", config)?;
    if let Some(dependencies) = config
        .get_mut("dependencies")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (name, dependency) in dependencies {
            if let Some(dependency) = dependency.as_object_mut() {
                reject_legacy_disks_for_service(
                    &format!("config.dependencies.{name}"),
                    dependency,
                )?;
            }
        }
    }
    Ok(())
}

fn reject_legacy_disks_for_service(
    context: &str,
    service: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), WorkloadError> {
    if service
        .get("disks")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|disks| !disks.is_empty())
    {
        return Err(WorkloadError::Json(format!(
            "{context}.disks is not supported in manifest format 3; use {context}.storage"
        )));
    }
    Ok(())
}

/// Compute PCR23 from raw manifest bytes.
fn compute_pcr_result(
    manifest: Manifest,
    manifest_raw: String,
) -> Result<InspectResult, WorkloadError> {
    let mut hasher = Sha256::new();
    hasher.update(manifest_raw.as_bytes());
    let event_hash = hasher.finalize();
    let hex = format!("{:x}", event_hash);

    // Final PCR23 = SHA-256(zeros_32 || event_hash)
    let mut extend_hasher = Sha256::new();
    extend_hasher.update([0u8; 32]);
    extend_hasher.update(event_hash);
    let pcr23_sha256 = format!("0x{:x}", extend_hasher.finalize());

    let event_hash384 = Sha384::digest(manifest_raw.as_bytes());
    let mut extend_hasher384 = Sha384::new();
    extend_hasher384.update([0u8; 48]);
    extend_hasher384.update(event_hash384);
    let pcr23_sha384 = format!("0x{:x}", extend_hasher384.finalize());

    Ok(InspectResult {
        sha256: format!("0x{hex}"),
        pcr23_sha256,
        pcr23_sha384,
        sha384: format!("0x{:x}", event_hash384),
        manifest_hash: format!("sha256:{hex}"),
        manifest,
        manifest_raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal manifest JSON (v2) that parses successfully.
    fn minimal_manifest_json() -> String {
        serde_json::json!({
            "meta": {
                "format": 7,
                "publisher": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "name": "test",
                "version": "v0.0.1"
            },
            "config": {
                "image": "test:v0.0.1",
                "base-image-mode": "blacklist",
                "base-image": [],
                "ports": [],
                "restart": "no",
                "command": null,
                "entrypoint": null,
                "session-ttl": 0,
                "atakit-portal": false,
                "gid-group": "test",
                "measured-data": false,
                "unmeasured-data": false,
                "environment": {},
                "storage": {},
                "dependencies": null,
                "firewall-ports": [],
                "baby-container": null,
                "boot-disk-size": null,
                "cap-add": [],
                "cap-drop": [],
                "logging": {
                    "driver": "k8s-file",
                    "options": {"max-file": "5", "max-size": "50m"},
                    "log-readers": []
                },
                "workload-logs": false
            },
            "disks": {},
            "hashes": {
                "images/test.tar": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }
        })
        .to_string()
    }

    #[test]
    fn event_hash_and_pcr23_are_distinct() {
        let result = build_result_json(minimal_manifest_json()).unwrap();
        assert_ne!(
            result.sha256, result.pcr23_sha256,
            "event hash (sha256) and final PCR23 must be different values"
        );
    }

    #[test]
    fn pcr23_is_extend_of_event_hash() {
        let manifest = minimal_manifest_json();
        let result = build_result_json(manifest.clone()).unwrap();

        // Recompute independently.
        let event_hash = {
            let mut h = Sha256::new();
            h.update(manifest.as_bytes());
            h.finalize()
        };
        let expected_pcr23 = {
            let mut h = Sha256::new();
            h.update([0u8; 32]);
            h.update(event_hash);
            format!("0x{:x}", h.finalize())
        };

        assert_eq!(result.pcr23_sha256, expected_pcr23);
        assert_eq!(result.sha256, format!("0x{:x}", event_hash));
    }

    #[test]
    fn sha256_is_event_hash_not_pcr23() {
        let result = build_result_json(minimal_manifest_json()).unwrap();

        assert!(result.sha256.starts_with("0x"));
        assert_eq!(result.sha256.len(), 66);

        assert!(result.pcr23_sha256.starts_with("0x"));
        assert_eq!(result.pcr23_sha256.len(), 66);

        assert!(result.manifest_hash.starts_with("sha256:"));

        let sha256_hex = result.sha256.strip_prefix("0x").unwrap();
        let manifest_hex = result.manifest_hash.strip_prefix("sha256:").unwrap();
        assert_eq!(sha256_hex, manifest_hex);
    }

    /// `config.storage` replaced `config.disks`. A manifest at the current
    /// format carrying `disks` is malformed, and is refused rather than
    /// converted.
    #[test]
    fn legacy_disks_are_rejected_at_the_current_format() {
        let mut value: serde_json::Value = serde_json::from_str(&minimal_manifest_json()).unwrap();
        value["config"].as_object_mut().unwrap().remove("storage");
        value["config"]["disks"] = serde_json::json!({ "data": "/data" });
        let err = match build_result_json(value.to_string()) {
            Ok(_) => panic!("expected a legacy disk mount to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("config.disks is not supported"));
    }

    #[test]
    fn unsupported_older_json_format_reports_rebuild_command() {
        let mut value: serde_json::Value = serde_json::from_str(&minimal_manifest_json()).unwrap();
        value["meta"]["format"] = serde_json::json!(1);

        let err = match build_result_json(value.to_string()) {
            Ok(_) => panic!("expected manifest format 1 to fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("workload manifest format 1"));
        assert!(message.contains("records no publisher"));
        assert!(message.contains("atakit workload build <workload-directory>"));
        assert!(message.contains("manifest format 7"));
    }

    /// Format 6 was the last format before `meta.publisher` and was accepted
    /// until this change. It is refused now for the same reason as any older
    /// one: it names no publisher, so it cannot produce the identifier its
    /// workload is registered under.
    #[test]
    fn the_format_before_publisher_is_refused() {
        let mut value: serde_json::Value = serde_json::from_str(&minimal_manifest_json()).unwrap();
        value["meta"]["format"] = serde_json::json!(6);

        let err = match build_result_json(value.to_string()) {
            Ok(_) => panic!("expected manifest format 6 to fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("workload manifest format 6"), "{message}");
        assert!(message.contains("records no publisher"), "{message}");
    }

    #[test]
    fn newer_json_format_reports_atakit_upgrade() {
        let mut value: serde_json::Value = serde_json::from_str(&minimal_manifest_json()).unwrap();
        value["meta"]["format"] = serde_json::json!(8);

        let err = match build_result_json(value.to_string()) {
            Ok(_) => panic!("expected manifest format 8 to fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("workload manifest format 8 is newer"));
        assert!(message.contains("upgrade atakit"));
    }

    #[test]
    fn missing_json_format_reports_rebuild_command() {
        let mut value: serde_json::Value = serde_json::from_str(&minimal_manifest_json()).unwrap();
        value["meta"].as_object_mut().unwrap().remove("format");

        let err = match build_result_json(value.to_string()) {
            Ok(_) => panic!("expected missing manifest format to fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("manifest.json is missing integer meta.format"));
        assert!(message.contains("atakit workload build <workload-directory>"));
    }
}
