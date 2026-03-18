mod commands;
mod progress;

use anyhow::Result;
use atakit_core::Env;
use atakit_image::ImageCommand;
use atakit_workload::cli::WorkloadCommand;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// atakit -- All-in-one tool for creation, provisioning, and management of CVMs.
#[derive(Parser)]
#[command(name = "atakit", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage CVM base images
    #[command(subcommand)]
    Image(ImageCommand),
    /// Manage workloads
    #[command(subcommand)]
    Workload(WorkloadCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let env = Env::from_env();

    match cli.command {
        Command::Image(cmd) => match cmd {
            ImageCommand::Ls(args) => commands::image::run_ls(args, &env).await,
            ImageCommand::Pull(args) => commands::image::run_pull(args, &env).await,
            ImageCommand::Rm(args) => commands::image::run_rm(args, &env).await,
        },
        Command::Workload(cmd) => match cmd {
            WorkloadCommand::New(args) => commands::workload::run_new(args),
        },
    }
}
