use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Workload subcommand.
#[derive(Subcommand)]
pub enum WorkloadCommand {
    /// Create a new workload directory with a starter config
    Create(CreateArgs),
    /// Build an .atawl archive from atakit-workload.toml
    Build(BuildArgs),
}

/// Arguments for `workload create`.
#[derive(Args)]
pub struct CreateArgs {
    /// Name of the workload to create
    pub name: String,
}

/// Arguments for `workload build`.
#[derive(Args)]
pub struct BuildArgs {
    /// Workload directory (default: current directory)
    #[arg(short, long)]
    pub dir: Option<PathBuf>,
    /// Output directory for .atawl file (default: workload directory)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Container engine override (docker or podman)
    #[arg(long, value_parser = ["docker", "podman"])]
    pub engine: Option<String>,
}
