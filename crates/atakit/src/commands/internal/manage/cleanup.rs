use anyhow::Result;
use clap::Args;

use crate::{Config, Csp};

#[derive(Args)]
pub struct Cleanup {
    /// Cloud service provider (aws, gcp, azure)
    pub csp: Csp,
    /// Name of the virtual machine
    pub vm_name: String,
}

impl Cleanup {
    pub fn run(self, cfg: &Config) -> Result<()> {
        let artifact_dir_str = cfg.artifact_dir.to_string_lossy().to_string();
        let script = match self.csp {
            Csp::Aws => "cleanup_aws_vm.sh",
            Csp::Gcp => "cleanup_gcp_vm.sh",
            Csp::Azure => "cleanup_azure_vm.sh",
        };
        cfg.run_script_default(script, &[&self.vm_name, &artifact_dir_str])
    }
}
