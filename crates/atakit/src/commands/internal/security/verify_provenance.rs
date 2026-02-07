use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::Config;

#[derive(Args)]
pub struct VerifyProvenance {
    /// Path to disk image (e.g., aws_disk.vmdk, azure_disk.vhd, gcp_disk.tar.gz)
    pub disk_file: PathBuf,
    /// Path to build provenance bundle (defaults to <DISK_FILE>.bundle)
    pub bundle_file: Option<PathBuf>,
}

impl VerifyProvenance {
    pub fn run(self, cfg: &Config) -> Result<()> {
        let disk = self.disk_file.to_string_lossy();
        match &self.bundle_file {
            Some(bf) => {
                let bundle = bf.to_string_lossy();
                cfg.run_script_default("verify_build_provenance.sh", &[&disk, &bundle])
            }
            None => cfg.run_script_default("verify_build_provenance.sh", &[&disk]),
        }
    }
}
