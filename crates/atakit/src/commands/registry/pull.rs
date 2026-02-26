use anyhow::Result;
use clap::Args;

use crate::Env;

/// Pull deployment files from the remote repository.
#[derive(Args)]
pub struct Pull {
    /// Branch to pull (defaults to current branch)
    #[arg(long)]
    pub branch: Option<String>,
}

impl Pull {
    pub async fn run(self, env: &Env) -> Result<()> {
        let store = env.registry_store();

        println!("Pulling deployments...");

        let chains = store.pull(self.branch.as_deref()).await?;

        if chains.is_empty() {
            println!("No deployment files found.");
        } else {
            println!("Updated {} chain(s):", chains.len());
            for chain in &chains {
                println!("  - {}", chain);
            }
        }

        Ok(())
    }
}
