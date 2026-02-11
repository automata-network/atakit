use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use tracing::info;

use workload_compose::measure::measure_package;

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
        // Run measurement
        info!("Running measurement");
        let measurement = measure_package(self.package)?;

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
                info!(
                    "measurements: {}",
                    serde_json::to_string_pretty(&measurement.events())?
                );
            }
        }

        info!(
            services = measurement.services.len(),
            "Measurement complete"
        );

        Ok(())
    }
}
