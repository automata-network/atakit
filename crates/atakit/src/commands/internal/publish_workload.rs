use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::types::AtakitConfig;
use crate::Config;

#[derive(Args)]
pub struct PublishWorkload {
    /// Ethereum RPC URL
    #[arg(long)]
    pub rpc_url: String,

    /// Private key for transaction signing (hex)
    #[arg(long)]
    pub private_key: String,

    /// Names of workloads to publish (publishes all if omitted)
    pub workloads: Vec<String>,
}

impl PublishWorkload {
    pub fn run(self, _config: &Config) -> Result<()> {
        let atakit_config = AtakitConfig::load()?;
        let artifact_dir = std::env::current_dir()?.join("ata_artifacts");

        let targets: Vec<String> = if self.workloads.is_empty() {
            atakit_config
                .workloads
                .iter()
                .map(|w| w.name.clone())
                .collect()
        } else {
            self.workloads.clone()
        };

        for name in &targets {
            let tar_path = artifact_dir.join(format!("{}.tar.gz", name));
            if !tar_path.exists() {
                bail!(
                    "Workload package not found: {}. Run `atakit build-workload` first.",
                    tar_path.display()
                );
            }

            let measurement = compute_sha256(&tar_path)?;
            info!(
                workload = %name,
                package = %tar_path.display(),
                sha256 = %format!("0x{}", measurement),
                "Workload measurement computed"
            );

            // TODO: Ethereum contract interaction via alloy.
            // When the contract ABI is finalized, add alloy dependency and
            // implement WorkloadRegistry.registerWorkload(measurement, ...).
            info!(
                rpc = %self.rpc_url,
                measurement = %format!("0x{}", measurement),
                "On-chain registration not yet implemented"
            );
        }

        Ok(())
    }
}

fn compute_sha256(path: &PathBuf) -> Result<String> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}
