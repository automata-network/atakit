mod aws;
mod azure;
mod gcp;

pub use aws::DeployAws;
pub use azure::DeployAzure;
pub use gcp::DeployGcp;

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use tracing::info;

use crate::config::{self, Config};

#[derive(Subcommand)]
pub enum DeployRaw {
    /// Deploy onto AWS using aws_disk.vmdk
    Aws(DeployAws),
    /// Deploy onto GCP using gcp_disk.tar.gz
    Gcp(DeployGcp),
    /// Deploy onto Azure using azure_disk.vhd
    Azure(DeployAzure),
}

impl DeployRaw {
    pub fn run(self, config: &Config) -> Result<()> {
        match self {
            DeployRaw::Aws(cmd) => cmd.run(config),
            DeployRaw::Gcp(cmd) => cmd.run(config),
            DeployRaw::Azure(cmd) => cmd.run(config),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for deploy commands
// ---------------------------------------------------------------------------

pub(crate) fn resolve_workload_dir(
    add_workload: &Option<PathBuf>,
    cfg: &Config,
) -> Result<PathBuf> {
    let dir = match add_workload {
        Some(path) => path.clone(),
        None => cfg.workload_dir.clone(),
    };

    let dir = if dir.is_relative() {
        std::env::current_dir()?.join(&dir)
    } else {
        dir
    };

    if !dir.is_dir() {
        bail!("Workload directory not found: {}", dir.display());
    }

    Ok(dir)
}

pub(crate) fn resolve_bucket(
    cfg: &Config,
    bucket: &Option<String>,
    csp: &str,
    vm_name: &str,
) -> String {
    if let Some(b) = bucket {
        return b.clone();
    }

    let artifact_file = cfg
        .artifact_dir
        .join(format!("{}_{}_bucket", csp, vm_name));
    if let Ok(content) = std::fs::read_to_string(&artifact_file) {
        let b = content.trim().to_string();
        if !b.is_empty() {
            info!(bucket = %b, "Using existing bucket name from artifacts");
            return b;
        }
    }

    let b = config::generate_name(vm_name, 6);
    info!(bucket = %b, "No bucket provided, using generated name");
    b
}
