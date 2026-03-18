use clap::{Args, Subcommand};

/// Workload subcommand.
#[derive(Subcommand)]
pub enum WorkloadCommand {
    /// Create a new workload directory with a starter config
    New(NewArgs),
}

/// Arguments for `workload new`.
#[derive(Args)]
pub struct NewArgs {
    /// Name of the workload to create
    pub name: String,
}
