use std::path::PathBuf;

use atakit_core::ProgressReporter;

use crate::archive::{self, StagingDir};
use crate::config::{ImageSource, WorkloadConfig};
use crate::hash;
use crate::image::ContainerEngine;
use crate::manifest;
use crate::validate;
use crate::WorkloadError;

/// Options for `build_workload`.
pub struct BuildOptions {
    /// Directory containing `atakit-workload.toml`.
    pub workload_dir: PathBuf,
    /// Output directory for the `.atawl` file. Defaults to `workload_dir`.
    pub output_dir: Option<PathBuf>,
    /// Explicit container engine override.
    pub engine: Option<ContainerEngine>,
    /// Show verbose output from container commands.
    pub verbose: bool,
}

/// Result of a successful build.
pub struct BuildResult {
    /// Path to the created `.atawl` archive.
    pub archive_path: PathBuf,
    /// SHA-256 hash of the archive file.
    pub archive_hash: String,
    /// Workload name.
    pub name: String,
    /// Workload version.
    pub version: String,
    /// Number of container images in the archive.
    pub image_count: usize,
    /// Number of measured-data files.
    pub measured_file_count: usize,
}

/// Build a workload: parse config, resolve images, stage files, create archive.
pub async fn build_workload(
    opts: &BuildOptions,
    progress: &dyn ProgressReporter,
) -> Result<BuildResult, WorkloadError> {
    let workload_dir = &opts.workload_dir;
    let output_dir = opts.output_dir.as_deref().unwrap_or(workload_dir);

    // 1. Parse config
    let handle = progress.create("Reading atakit-workload.toml...", 0);
    let config = WorkloadConfig::from_dir(workload_dir)?;
    handle.finish();

    let name = config.workload.name.clone();
    let version = config.workload.version.clone();

    // 2. Validate
    let handle = progress.create("Validating config...", 0);
    let warnings = validate::validate_config(&config, workload_dir)?;
    handle.finish();
    for w in &warnings {
        tracing::warn!("{}", w);
    }

    // Until dependencies are fully implemented, treat their presence as a hard error
    // to avoid generating archives whose manifests reference unstaged dependency
    // images or files.
    if warnings.iter().any(|w| w.contains("[dependencies]")) {
        return Err(WorkloadError::Validation(
            "dependencies are not yet supported in workloads".to_string(),
        ));
    }

    // 3. Create staging directory
    let temp_dir = tempfile::tempdir().map_err(WorkloadError::Io)?;
    let staging = StagingDir::create(temp_dir.path(), &name)?;

    // 4. Resolve image
    let resolved_image = manifest::resolve_image_ref(&config.workload.image, &name, &version);
    let tar_name = archive::image_tar_name(&name);
    let mut image_count = 0;

    match &config.workload.image {
        ImageSource::Registry(reference) => {
            let engine = resolve_engine(opts).await?;
            let handle = progress.create(&format!("Pulling {reference}..."), 0);
            engine.pull_image(reference).await?;
            engine
                .save_image(reference, &staging.image_tar_path(&tar_name))
                .await?;
            handle.finish();
            image_count += 1;
        }
        ImageSource::Build {
            build,
            containerfile,
            args,
        } => {
            let engine = resolve_engine(opts).await?;
            let handle = progress.create(&format!("Building {resolved_image}..."), 0);
            let context = workload_dir.join(build);
            engine
                .build_image(
                    &context,
                    containerfile.as_deref(),
                    &resolved_image,
                    args,
                    opts.verbose,
                )
                .await?;
            engine
                .save_image(&resolved_image, &staging.image_tar_path(&tar_name))
                .await?;
            handle.finish();
            image_count += 1;
        }
        ImageSource::File { file } => {
            let src = workload_dir.join(file);
            let handle = progress.create(&format!("Loading {file}..."), 0);
            staging.stage_image_file(&src, &tar_name)?;
            handle.finish();
            image_count += 1;
        }
    }

    // 5. Collect measured-data
    let measured_file_count = if config.workload.measured_data.is_empty()
        && config.signing.as_ref().is_none_or(|s| !s.enable)
    {
        0
    } else {
        let handle = progress.create("Collecting measured-data...", 0);
        let mut count =
            staging.stage_measured_data(&config.workload.measured_data, workload_dir)?;

        // Stage signing files under measured-data/signing/
        if let Some(ref signing) = config.signing {
            if signing.enable {
                let auth = workload_dir.join(signing.auth_info.as_ref().unwrap());
                let policy = workload_dir.join(signing.policy.as_ref().unwrap());
                staging.stage_signing_files(&auth, &policy)?;
                count += 2;
            }
        }
        handle.finish();
        count
    };

    // 6. Resolve environment
    let environment = manifest::resolve_environment(
        &config.workload.env_file,
        &config.workload.environment,
        workload_dir,
    )?;

    // 7. Hash all content
    let handle = progress.create("Hashing content...", 0);
    let mut hashes = hash::hash_directory(&staging.root, "measured-data")?;
    let image_hashes = hash::hash_directory(&staging.root, "images")?;
    hashes.extend(image_hashes);
    handle.finish();

    // 8. Generate manifest
    let handle = progress.create("Generating manifest.toml...", 0);
    let m = manifest::build_manifest(&config, &resolved_image, environment, hashes);
    let manifest_toml = toml::to_string_pretty(&m)?;
    staging.write_manifest(&manifest_toml)?;
    handle.finish();

    // 9. Create archive
    let handle = progress.create(
        &format!(
            "Writing {name}-{version}.atawl ({image_count} image{}, {measured_file_count} measured file{})...",
            if image_count != 1 { "s" } else { "" },
            if measured_file_count != 1 { "s" } else { "" },
        ),
        0,
    );
    let archive_path = archive::create_archive(&staging.root, &name, &version, output_dir)?;
    handle.finish();

    // 10. Hash archive
    let archive_hash = hash::hash_file(&archive_path)?;

    Ok(BuildResult {
        archive_path,
        archive_hash,
        name,
        version,
        image_count,
        measured_file_count,
    })
}

async fn resolve_engine(opts: &BuildOptions) -> Result<ContainerEngine, WorkloadError> {
    match opts.engine {
        Some(e) => Ok(e),
        None => ContainerEngine::detect().await,
    }
}
