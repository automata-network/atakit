mod cleanup;
mod cleanup_local;
mod get_disk;
mod get_logs;
mod update_disk;
mod update_workload;

pub use cleanup::Cleanup;
pub use cleanup_local::CleanupLocal;
pub use get_disk::GetDisk;
pub use get_logs::GetLogs;
pub use update_disk::UpdateDisk;
pub use update_workload::UpdateWorkload;

use anyhow::Result;
use clap::Subcommand;

use crate::Config;

#[derive(Subcommand)]
pub enum Manage {
    /// Update the workload on a deployed CVM
    UpdateWorkload(UpdateWorkload),
    /// Get the disk image for a specific Cloud Provider
    GetDisk(GetDisk),
    /// Update the workload on a specified disk file
    UpdateDisk(UpdateDisk),
    /// Retrieve logs from a deployed CVM
    GetLogs(GetLogs),
    /// Clean up resources for a specific Cloud Provider and VM Name
    Cleanup(Cleanup),
    /// Remove all locally downloaded disk images, build provenance, and artifacts
    CleanupLocal(CleanupLocal),
}

impl Manage {
    pub fn run(self, config: &Config) -> Result<()> {
        match self {
            Manage::UpdateWorkload(cmd) => cmd.run(config),
            Manage::GetDisk(cmd) => cmd.run(config),
            Manage::UpdateDisk(cmd) => cmd.run(config),
            Manage::GetLogs(cmd) => cmd.run(config),
            Manage::Cleanup(cmd) => cmd.run(config),
            Manage::CleanupLocal(cmd) => cmd.run(config),
        }
    }
}
