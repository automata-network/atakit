use anyhow::Result;
use clap::Args;

use crate::{Config, Csp};

#[derive(Args)]
pub struct GetDisk {
    /// Cloud service provider (aws, gcp, azure)
    pub csp: Csp,
}

impl GetDisk {
    pub fn run(self, cfg: &Config) -> Result<()> {
        cfg.run_script_default("get_disk_image.sh", &[self.csp.as_str()])
    }
}
