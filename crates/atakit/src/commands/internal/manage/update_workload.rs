use anyhow::Result;
use clap::Args;
use tracing::info;

use crate::{Config, Csp};

#[derive(Args)]
pub struct UpdateWorkload {
    /// Cloud service provider (aws, gcp, azure)
    pub csp: Csp,
    /// Name of the virtual machine
    pub vm_name: String,
}

impl UpdateWorkload {
    pub fn run(self, cfg: &Config) -> Result<()> {
        cfg.run_script_default("update_remote_workload.sh", &[self.csp.as_str(), &self.vm_name])?;
        info!("Updating golden measurements");
        cfg.run_script_default("get_golden_measurements.sh", &[self.csp.as_str(), &self.vm_name])?;
        Ok(())
    }
}
