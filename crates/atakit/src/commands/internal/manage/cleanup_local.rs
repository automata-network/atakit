use anyhow::Result;
use clap::Args;
use tracing::info;

use crate::Config;

#[derive(Args)]
pub struct CleanupLocal {}

impl CleanupLocal {
    pub fn run(self, cfg: &Config) -> Result<()> {
        info!("Cleaning up local artifacts");

        let disk_files = ["aws_disk.vmdk", "gcp_disk.tar.gz", "azure_disk.vhd"];

        for disk in &disk_files {
            let path = cfg.disk_dir.join(disk);
            if path.exists() {
                std::fs::remove_file(&path)?;
                info!(path = %path.display(), "Removed");
            }

            let bundle = cfg.disk_dir.join(format!("{}.bundle", disk));
            if bundle.exists() {
                std::fs::remove_file(&bundle)?;
                info!(path = %bundle.display(), "Removed");
            }
        }

        if cfg.artifact_dir.is_dir() {
            for entry in std::fs::read_dir(&cfg.artifact_dir)? {
                let entry = entry?;
                let ft = entry.file_type()?;
                if ft.is_file() || ft.is_symlink() {
                    std::fs::remove_file(entry.path())?;
                }
            }
            info!(path = %cfg.artifact_dir.display(), "Cleaned artifact directory");
        }

        info!("Local cleanup complete");
        Ok(())
    }
}
