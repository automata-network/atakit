use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
pub mod env;
pub mod instances;
pub mod registry;
mod types;

pub use env::Env;

#[cfg(feature = "internal")]
mod config;
#[cfg(feature = "internal")]
pub(crate) use config::Config;
#[cfg(feature = "internal")]
pub(crate) use csp::Csp;

#[derive(Parser)]
#[command(name = "atakit", about = "CVM base image deployment toolkit")]
struct Cli {
    #[command(subcommand)]
    command: AtaKit,
}

#[derive(Subcommand)]
enum AtaKit {
    /// CVM base image operations
    #[command(subcommand)]
    Image(commands::image::Image),

    /// Build a workload package from docker-compose definitions
    BuildWorkload(commands::build_workload::BuildWorkload),

    /// Deploy a CVM instance to a cloud provider or local QEMU
    Deploy(commands::deploy::Deploy),

    /// Internal development commands (requires --features internal)
    #[cfg(feature = "internal")]
    #[command(subcommand)]
    Internal(commands::internal::Internal),

    /// Publish a workload to the WorkloadRegistry contract
    PublishWorkload(commands::publish_workload::PublishWorkload),

    /// Manage contract registry information
    #[command(subcommand)]
    Registry(commands::registry::Registry),
}

impl AtaKit {
    async fn run(self, env: &Env) -> Result<()> {
        match self {
            AtaKit::Image(cmd) => cmd.run(env).await,
            AtaKit::BuildWorkload(cmd) => cmd.run(env),
            AtaKit::Deploy(cmd) => cmd.run(env).await,
            #[cfg(feature = "internal")]
            AtaKit::Internal(cmd) => cmd.run().await,
            AtaKit::PublishWorkload(cmd) => cmd.run(env).await,
            AtaKit::Registry(cmd) => cmd.run(env).await,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let cli = Cli::parse();
    let env = Env::from_env();
    cli.command.run(&env).await
}
