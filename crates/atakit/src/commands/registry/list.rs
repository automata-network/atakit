use anyhow::Result;
use clap::Args;

use crate::Env;

/// List contract addresses for the current branch.
#[derive(Args)]
pub struct List {
    /// Show a specific chain ID only
    #[arg(long)]
    pub chain: Option<String>,

    /// Branch to list (defaults to current branch)
    #[arg(long)]
    pub branch: Option<String>,
}

impl List {
    pub async fn run(self, env: &Env) -> Result<()> {
        let store = env.registry_store();
        let branch = self.branch.unwrap_or_else(|| {
            store.current_branch().unwrap_or_else(|_| "main".to_string())
        });

        // Auto-pull if no data exists
        store.ensure_data(&branch).await?;

        println!("Registry: {}", branch);
        println!();

        if let Some(chain_id) = &self.chain {
            // Show specific chain
            match store.load_chain(&branch, chain_id)? {
                Some(addresses) => {
                    println!("Chain {chain_id}:");
                    for (name, addr) in &addresses {
                        println!("  {name}: {addr}");
                    }
                }
                None => {
                    println!("No contracts found for chain {chain_id}");
                }
            }
        } else {
            // Show all chains
            let chains = store.list_chains(&branch)?;
            if chains.is_empty() {
                println!("No contract deployments found.");
                println!("Run 'atakit registry pull' to fetch from remote.");
                return Ok(());
            }

            for chain_id in &chains {
                if let Some(addresses) = store.load_chain(&branch, chain_id)? {
                    println!("Chain {chain_id}:");
                    for (name, addr) in &addresses {
                        println!("  {name}: {addr}");
                    }
                    println!();
                }
            }
        }

        Ok(())
    }
}
