mod deploy;
mod deploy_raw;
mod manage;
mod publish_workload;
mod security;
mod sim_agent;

use anyhow::Result;
use clap::Subcommand;

use crate::Config;

#[derive(Subcommand)]
pub enum Internal {
    /// Publish a built workload to the on-chain registry
    PublishWorkload(publish_workload::PublishWorkload),

    /// Deploy workloads to cloud platforms using atakit.json
    Deploy(deploy::Deploy),

    /// Start a simulated CVM agent for local development
    SimAgent(sim_agent::SimAgent),

    /// Deploy a CVM to a cloud provider (raw disk image mode)
    #[command(subcommand)]
    DeployRaw(deploy_raw::DeployRaw),

    /// Manage deployed CVMs and resources
    #[command(subcommand)]
    Manage(manage::Manage),

    /// Security operations (provenance, signing, livepatch)
    #[command(subcommand)]
    Security(security::Security),
}

impl Internal {
    pub async fn run(self) -> Result<()> {
        let config = Config::detect()?;
        config.check_dependencies()?;

        match self {
            Internal::PublishWorkload(cmd) => cmd.run(&config),
            Internal::Deploy(cmd) => cmd.run(&config),
            Internal::SimAgent(cmd) => cmd.run().await,
            Internal::DeployRaw(cmd) => cmd.run(&config),
            Internal::Manage(cmd) => cmd.run(&config),
            Internal::Security(cmd) => cmd.run(&config),
        }
    }
}
