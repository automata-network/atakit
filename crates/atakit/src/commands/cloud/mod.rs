mod destroy;

use anyhow::Result;
use clap::Subcommand;

use crate::env::Env;

/// Cloud resource management.
#[derive(Subcommand)]
pub enum Cloud {
    /// Destroy a deployed CVM instance and its associated resources
    Destroy(destroy::Destroy),
}

impl Cloud {
    pub async fn run(self, env: &Env) -> Result<()> {
        match self {
            Cloud::Destroy(cmd) => cmd.run(env).await,
        }
    }
}
