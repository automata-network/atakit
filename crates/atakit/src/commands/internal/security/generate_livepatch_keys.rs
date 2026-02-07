use anyhow::Result;
use clap::Args;

use crate::Config;

#[derive(Args)]
pub struct GenerateLivepatchKeys {}

impl GenerateLivepatchKeys {
    pub fn run(self, cfg: &Config) -> Result<()> {
        cfg.run_script_default("generate_livepatch_keys.sh", &[])
    }
}
