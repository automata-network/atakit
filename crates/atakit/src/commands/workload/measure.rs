use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use flate2::read::GzDecoder;
use tar::Archive;
use tracing::info;

use workload_compose::{MeasureConfig, WorkloadManifest, measure};

use crate::Env;

#[derive(Args)]
pub struct Measure {
    /// Path to the workload package (tar.gz)
    #[arg()]
    package: PathBuf,

    /// Output format
    #[arg(long, default_value = "json")]
    format: OutputFormat,
}

#[derive(Clone, Copy, Default, clap::ValueEnum)]
enum OutputFormat {
    #[default]
    Json,
    Text,
}

impl Measure {
    pub fn run(self, _env: &Env) -> Result<()> {
        // Create a temporary directory for extraction
        let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
        let extract_path = temp_dir.path();

        info!(package = %self.package.display(), "Extracting workload package");

        // Extract the tar.gz
        extract_tar_gz(&self.package, extract_path)?;

        // Read the manifest.json
        let manifest_path = extract_path.join("manifest.json");
        let manifest: WorkloadManifest = {
            let content = fs::read_to_string(&manifest_path)
                .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse {}", manifest_path.display()))?
        };

        info!(workload = %manifest.name, "Loaded manifest");

        // Extract image digests using workload-compose helper
        let image_digests = manifest.extract_image_digests(extract_path)?;

        let mut config = MeasureConfig::cvm();
        config.image_digests = image_digests;

        // Run measurement
        info!("Running measurement");
        let measurement = measure(extract_path, &manifest.docker_compose, &config)
            .map_err(|e| anyhow::anyhow!("Measurement failed: {}", e))?;

        // Output results
        match self.format {
            OutputFormat::Text => {
                println!("=== Manifest ({} bytes) ===", measurement.manifest.len());
                println!();

                for svc in &measurement.services {
                    println!("=== Service: {} ===", svc.service_name);
                    println!("Image digest: {}", svc.image_digest);
                    println!("Volumes: {:?}", svc.volumes);
                    println!("Mounted files ({}):", svc.mount_files.len());
                    for file in &svc.mount_files {
                        println!("  {} -> {}", file.path, file.hash);
                    }
                    println!();
                    println!("Isolated docker-compose:");
                    println!("{}", svc.docker_compose);
                    println!();
                }
            }
            OutputFormat::Json => {
                info!("raw: {}", serde_json::to_string_pretty(&measurement)?);
                info!("pcr value: {}", measurement.pcr_value());
                info!("measurements: {}", serde_json::to_string_pretty(&measurement.events())?);
            }
        }

        info!(
            services = measurement.services.len(),
            "Measurement complete"
        );

        Ok(())
    }
}

/// Extract a tar.gz archive to the specified directory.
fn extract_tar_gz(archive_path: &Path, dest: &Path) -> Result<()> {
    let file = File::open(archive_path)
        .with_context(|| format!("Failed to open {}", archive_path.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    archive
        .unpack(dest)
        .with_context(|| format!("Failed to extract {}", archive_path.display()))?;

    Ok(())
}
