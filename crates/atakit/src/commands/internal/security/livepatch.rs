use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::{Config, Csp};

#[derive(Args)]
pub struct Livepatch {
    /// Cloud service provider (aws, gcp, azure)
    pub csp: Csp,
    /// Name of the virtual machine
    pub vm_name: String,
    /// Path to the livepatch file
    pub livepatch_path: PathBuf,
}

impl Livepatch {
    pub fn run(self, cfg: &Config) -> Result<()> {
        let path = self.livepatch_path.to_string_lossy();
        cfg.run_script_default("livepatch.sh", &[self.csp.as_str(), &self.vm_name, &path])
    }
}
