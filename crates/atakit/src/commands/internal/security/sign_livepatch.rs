use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use tracing::info;

use crate::Config;

#[derive(Args)]
pub struct SignLivepatch {
    /// Path to the livepatch file (e.g., /path/to/livepatch.ko)
    pub livepatch_file: PathBuf,
}

impl SignLivepatch {
    pub fn run(self, cfg: &Config) -> Result<()> {
        let file = self.livepatch_file.to_string_lossy();
        cfg.run_script_default("sign_livepatch.sh", &[&file])?;
        info!(file = %self.livepatch_file.display(), "Livepatch signed successfully");
        Ok(())
    }
}
