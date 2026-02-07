use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use tracing::info;

use crate::Config;

#[derive(Args)]
pub struct UpdateDisk {
    /// Path to the disk image
    pub disk_path: PathBuf,
    /// Path to the workload directory to copy into the disk
    pub workload_path: PathBuf,
}

impl UpdateDisk {
    pub fn run(self, cfg: &Config) -> Result<()> {
        if !self.workload_path.is_dir() {
            bail!(
                "Workload directory not found: {}",
                self.workload_path.display()
            );
        }

        let disk_str = self.disk_path.to_string_lossy();
        info!(
            disk = %self.disk_path.display(),
            workload = %self.workload_path.display(),
            "Updating disk"
        );
        cfg.run_script("update_disk.sh", &[&disk_str], &self.workload_path)
    }
}
