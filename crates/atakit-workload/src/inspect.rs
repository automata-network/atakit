use std::io::Read;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::image::ContainerEngine;
use crate::manifest::Manifest;
use crate::WorkloadError;

/// Options for inspecting a workload.
pub struct InspectOptions {
    /// Path to an `.atawl` archive.
    pub archive: Option<PathBuf>,
    /// Path to a workload source directory.
    pub workload_dir: Option<PathBuf>,
    /// Container engine override (for dir mode).
    pub engine: Option<ContainerEngine>,
    /// Show verbose output from container commands.
    pub verbose: bool,
}

/// Result of inspecting a workload.
pub struct InspectResult {
    /// SHA-256 of manifest bytes as `0x<64-hex-chars>` (the event hash).
    pub sha256: String,
    /// Final PCR23 register value as `0x<64-hex-chars>`: `SHA-256(zeros_32 || sha256)`.
    pub pcr23: String,
    /// SHA-256 hash of the manifest as `sha256:<64-hex-chars>`.
    pub manifest_hash: String,
    /// Parsed manifest.
    pub manifest: Manifest,
    /// Raw manifest string (JSON for v2, TOML for v1 archives).
    pub manifest_raw: String,
}

/// Inspect a workload from an `.atawl` archive or a source directory.
pub async fn inspect_workload(
    opts: &InspectOptions,
) -> Result<InspectResult, WorkloadError> {
    if let Some(ref archive_path) = opts.archive {
        inspect_archive(archive_path)
    } else if let Some(ref workload_dir) = opts.workload_dir {
        inspect_dir(workload_dir, opts.engine, opts.verbose).await
    } else {
        Err(WorkloadError::Validation(
            "either --archive or --dir must be specified".into(),
        ))
    }
}

/// Inspect from an `.atawl` archive: extract manifest, compute PCR23.
/// Supports both v2 (manifest.json) and v1 (manifest.toml) archives.
fn inspect_archive(archive_path: &std::path::Path) -> Result<InspectResult, WorkloadError> {
    let file = std::fs::File::open(archive_path).map_err(|e| WorkloadError::ReadFile {
        path: archive_path.to_path_buf(),
        source: e,
    })?;
    let decoder = crate::archive::open_decoder(file)?;
    let mut archive = tar::Archive::new(decoder);

    let mut manifest_json = None;
    let mut manifest_toml = None;
    for entry in archive.entries().map_err(WorkloadError::Io)? {
        let mut entry = entry.map_err(WorkloadError::Io)?;
        let path = entry.path().map_err(WorkloadError::Io)?;
        if let Some(filename) = path.file_name() {
            if filename == "manifest.json" {
                let mut content = String::new();
                entry.read_to_string(&mut content).map_err(WorkloadError::Io)?;
                manifest_json = Some(content);
                break; // v2 found, stop scanning
            } else if filename == "manifest.toml" {
                let mut content = String::new();
                entry.read_to_string(&mut content).map_err(WorkloadError::Io)?;
                manifest_toml = Some(content);
                // Don't break: keep scanning in case manifest.json appears
                // later in the tar. For real v1 archives this scans the
                // entire tar, but v1 is the legacy path.
            }
        }
    }

    if let Some(raw) = manifest_json {
        build_result_json(raw)
    } else if let Some(raw) = manifest_toml {
        build_result_toml(raw)
    } else {
        Err(WorkloadError::Validation(
            "neither manifest.json nor manifest.toml found in archive".into(),
        ))
    }
}

/// Inspect from a workload source directory: parse config, build manifest, compute PCR23.
async fn inspect_dir(
    workload_dir: &std::path::Path,
    engine_override: Option<ContainerEngine>,
    verbose: bool,
) -> Result<InspectResult, WorkloadError> {
    let workload_dir = if workload_dir.is_absolute() {
        workload_dir.to_path_buf()
    } else {
        std::fs::canonicalize(workload_dir).map_err(WorkloadError::Io)?
    };

    let config = crate::config::WorkloadConfig::from_dir(&workload_dir)?;
    let warnings = crate::validate::validate_config(&config, &workload_dir)?;
    for w in &warnings {
        tracing::warn!("{}", w);
    }

    let name = &config.workload.name;
    let version = &config.workload.version;
    let resolved_image =
        crate::manifest::resolve_image_ref(&config.workload.image, name, version);

    // Stage measured-data files into a temp dir for hashing
    let temp_dir = tempfile::tempdir().map_err(WorkloadError::Io)?;
    let staging = crate::archive::StagingDir::create(temp_dir.path(), name)?;

    // Stage measured-data (from [package] section)
    let measured_paths = config.measured_data_paths();
    if !measured_paths.is_empty() {
        staging.stage_measured_data(measured_paths, &workload_dir)?;
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
        let dep_resolved =
            crate::manifest::resolve_image_ref(&dep.image, dep_name, version);
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
    images.insert(
        name.clone(),
        build_image_meta(&staging, &tar_name)?,
    );
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
        let dep_env = crate::manifest::resolve_environment(
            &dep.env_file,
            &dep.environment,
            &workload_dir,
        )?;
        dep_environments.insert((*dep_name).clone(), dep_env);
    }

    // Build manifest
    let manifest = crate::manifest::build_manifest(
        &config,
        &resolved_image,
        environment,
        dep_environments,
        hashes,
        images,
    );
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
                .build_image(&context, containerfile.as_deref(), resolved_ref, args, verbose)
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
    let manifest: Manifest =
        serde_json::from_str(&manifest_raw).map_err(|e| WorkloadError::Json(e.to_string()))?;
    compute_pcr_result(manifest, manifest_raw)
}

/// Compute PCR23 and build InspectResult from raw manifest TOML (v1 compat).
fn build_result_toml(manifest_raw: String) -> Result<InspectResult, WorkloadError> {
    let v1: crate::manifest_v1::ManifestV1 =
        toml::from_str(&manifest_raw).map_err(|e| WorkloadError::ParseConfig {
            path: "manifest.toml".into(),
            source: e,
        })?;
    let manifest = crate::manifest_v1::convert_to_current(v1);
    compute_pcr_result(manifest, manifest_raw)
}

/// Shared PCR23 computation from raw manifest bytes.
fn compute_pcr_result(manifest: Manifest, manifest_raw: String) -> Result<InspectResult, WorkloadError> {
    let mut hasher = Sha256::new();
    hasher.update(manifest_raw.as_bytes());
    let event_hash = hasher.finalize();
    let hex = format!("{:x}", event_hash);

    // Final PCR23 = SHA-256(zeros_32 || event_hash)
    let mut extend_hasher = Sha256::new();
    extend_hasher.update([0u8; 32]);
    extend_hasher.update(event_hash);
    let pcr23_hex = format!("0x{:x}", extend_hasher.finalize());

    Ok(InspectResult {
        sha256: format!("0x{hex}"),
        pcr23: pcr23_hex,
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
                "format": 2,
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
                "disks": {},
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
            result.sha256, result.pcr23,
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

        assert_eq!(result.pcr23, expected_pcr23);
        assert_eq!(result.sha256, format!("0x{:x}", event_hash));
    }

    #[test]
    fn sha256_is_event_hash_not_pcr23() {
        let result = build_result_json(minimal_manifest_json()).unwrap();

        assert!(result.sha256.starts_with("0x"));
        assert_eq!(result.sha256.len(), 66);

        assert!(result.pcr23.starts_with("0x"));
        assert_eq!(result.pcr23.len(), 66);

        assert!(result.manifest_hash.starts_with("sha256:"));

        let sha256_hex = result.sha256.strip_prefix("0x").unwrap();
        let manifest_hex = result.manifest_hash.strip_prefix("sha256:").unwrap();
        assert_eq!(sha256_hex, manifest_hex);
    }

    #[test]
    fn v1_toml_compat() {
        let toml = r#"
[meta]
format = 1
name = "old-workload"
version = "v0.1.0"

[config]
image = "old:v0.1.0"
base-image-mode = "blacklist"
cvm_agent = true

[hashes]
"images/old.tar" = "sha256:abcd"
"#;
        let result = build_result_toml(toml.to_string()).unwrap();
        assert_eq!(result.manifest.meta.name, "old-workload");
        assert!(result.manifest.config.atakit_portal);
        assert_eq!(result.manifest.config.gid_group, "old-workload");
        // Omitted restart in v1 must default to "no", not "".
        assert_eq!(result.manifest.config.restart, "no");
    }

    #[test]
    fn v1_dependency_restart_defaults_to_no() {
        let toml = r#"
[meta]
format = 1
name = "with-dep"
version = "v0.1.0"

[config]
image = "main:v0.1.0"
base-image-mode = "blacklist"

[config.dependencies.sidecar]
image = "sidecar:latest"

[hashes]
"images/main.tar" = "sha256:aaaa"
"images/sidecar.tar" = "sha256:bbbb"
"#;
        let result = build_result_toml(toml.to_string()).unwrap();
        let deps = result.manifest.config.dependencies.unwrap();
        let sidecar = &deps["sidecar"];
        assert_eq!(sidecar.restart, "no");
    }
}
