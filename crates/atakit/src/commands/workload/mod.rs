mod measure;

use anyhow::Result;
use clap::Subcommand;

use crate::Env;

#[derive(Subcommand)]
pub enum Workload {
    /// Measure a workload package and output event logs for PCR23 extension
    Measure(measure::Measure),
}

impl Workload {
    pub fn run(self, env: &Env) -> Result<()> {
        match self {
            Workload::Measure(cmd) => cmd.run(env),
        }
    }
}
