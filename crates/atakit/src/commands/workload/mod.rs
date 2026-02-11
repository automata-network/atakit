mod build;
mod measure;
mod packager;
mod publish;

use anyhow::Result;
use clap::Subcommand;

use crate::Env;

pub use build::ImageMode;

#[derive(Subcommand)]
pub enum Workload {
    /// Build a workload package from docker-compose definitions
    Build(build::BuildWorkload),

    /// Measure a workload package and output event logs for PCR23 extension
    Measure(measure::Measure),

    /// Publish a workload to the WorkloadRegistry contract
    Publish(publish::PublishWorkload),
}

impl Workload {
    pub async fn run(self, env: &Env) -> Result<()> {
        match self {
            Workload::Build(cmd) => cmd.run(env),
            Workload::Measure(cmd) => cmd.run(env),
            Workload::Publish(cmd) => cmd.run(env).await,
        }
    }
}
