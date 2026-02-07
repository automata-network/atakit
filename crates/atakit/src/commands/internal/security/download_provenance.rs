use anyhow::Result;
use clap::Args;
use tracing::info;

use crate::Config;

#[derive(Args)]
pub struct DownloadProvenance {}

impl DownloadProvenance {
    pub fn run(self, cfg: &Config) -> Result<()> {
        info!("Downloading SLSA build provenance");
        cfg.run_script_default("get_build_provenance.sh", &[])
    }
}
