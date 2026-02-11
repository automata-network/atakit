use anyhow::Result;
use clap::Args;

use crate::{Config, Csp};

#[derive(Args)]
pub struct GetLogs {
    /// Cloud service provider (aws, gcp, azure)
    pub csp: Csp,
    /// Name of the virtual machine
    pub vm_name: String,
}

impl GetLogs {
    pub fn run(self, cfg: &Config) -> Result<()> {
        cfg.run_script_default("get_cvm_logs.sh", &[self.csp.as_str(), &self.vm_name])
    }
}
