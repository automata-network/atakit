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
    /// PCR23 measurement as `0x<64-hex-chars>`.
    pub pcr23: String,
    /// SHA-256 hash of the manifest as `sha256:<64-hex-chars>`.
    pub manifest_hash: String,
    /// Parsed manifest.
    pub manifest: Manifest,
    /// Raw manifest TOML string.
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

/// Inspect from an `.atawl` archive: extract manifest.toml, compute PCR23.
fn inspect_archive(archive_path: &std::path::Path) -> Result<InspectResult, WorkloadError> {
    let file = std::fs::File::open(archive_path).map_err(|e| WorkloadError::ReadFile {
        path: archive_path.to_path_buf(),
        source: e,
    })?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    let mut manifest_raw = None;
    for entry in archive.entries().map_err(WorkloadError::Io)? {
        let mut entry = entry.map_err(WorkloadError::Io)?;
        let path = entry.path().map_err(WorkloadError::Io)?;
        if path.file_name().is_some_and(|f| f == "manifest.toml") {
            let mut content = String::new();
            entry.read_to_string(&mut content).map_err(WorkloadError::Io)?;
            manifest_raw = Some(content);
            break;
        }
    }

    let manifest_raw = manifest_raw.ok_or_else(|| {
        WorkloadError::Validation("manifest.toml not found in archive".into())
    })?;

    build_result(manifest_raw)
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

    // Stage measured-data + signing files into a temp dir for hashing
    let temp_dir = tempfile::tempdir().map_err(WorkloadError::Io)?;
    let staging = crate::archive::StagingDir::create(temp_dir.path(), name)?;

    // Stage measured-data
    if !config.workload.measured_data.is_empty() {
        staging.stage_measured_data(&config.workload.measured_data, &workload_dir)?;
    }
    if let Some(ref signing) = config.signing {
        if signing.enable {
            let auth = workload_dir.join(signing.auth_info.as_ref().unwrap());
            let policy = workload_dir.join(signing.policy.as_ref().unwrap());
            staging.stage_signing_files(&auth, &policy)?;
        }
    }

    // We need to stage the image to compute hashes, but for dir mode we need
    // a container engine to save the image. Handle each image source type.
    let tar_name = crate::archive::image_tar_name(name);
    match &config.workload.image {
        crate::config::ImageSource::File { file } => {
            let src = workload_dir.join(file);
            staging.stage_image_file(&src, &tar_name)?;
        }
        crate::config::ImageSource::Registry(reference) => {
            let engine = match engine_override {
                Some(e) => e,
                None => ContainerEngine::detect().await?,
            };
            engine.pull_image(reference).await?;
            engine
                .save_image(reference, &staging.image_tar_path(&tar_name))
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
                .build_image(&context, containerfile.as_deref(), &resolved_image, args, verbose)
                .await?;
            engine
                .save_image(&resolved_image, &staging.image_tar_path(&tar_name))
                .await?;
        }
    }

    // Hash all staged content
    let mut hashes = crate::hash::hash_directory(&staging.root, "measured-data")?;
    let image_hashes = crate::hash::hash_directory(&staging.root, "images")?;
    hashes.extend(image_hashes);

    // Resolve environment
    let environment = crate::manifest::resolve_environment(
        &config.workload.env_file,
        &config.workload.environment,
        &workload_dir,
    )?;

    // Build manifest
    let manifest = crate::manifest::build_manifest(&config, &resolved_image, environment, hashes);
    let manifest_raw = toml::to_string_pretty(&manifest)?;

    build_result(manifest_raw)
}

/// Compute PCR23 and build InspectResult from raw manifest TOML.
fn build_result(manifest_raw: String) -> Result<InspectResult, WorkloadError> {
    let manifest: Manifest =
        toml::from_str(&manifest_raw).map_err(|e| WorkloadError::ParseConfig {
            path: "manifest.toml".into(),
            source: e,
        })?;

    let mut hasher = Sha256::new();
    hasher.update(manifest_raw.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{:x}", digest);

    Ok(InspectResult {
        pcr23: format!("0x{hex}"),
        manifest_hash: format!("sha256:{hex}"),
        manifest,
        manifest_raw,
    })
}
