mod list;
mod pull;
mod query;
mod switch;

use anyhow::Result;
use clap::Subcommand;

use crate::Env;

#[derive(Subcommand)]
pub enum Registry {
    /// Switch to a different registry branch
    Switch(switch::Switch),
    /// List contract addresses for the current branch
    #[command(name = "ls")]
    List(list::List),
    /// Pull deployment files from the remote repository
    Pull(pull::Pull),
    /// Query on-chain registry data
    #[command(subcommand)]
    Query(query::Query),
}

impl Registry {
    pub async fn run(self, env: &Env) -> Result<()> {
        match self {
            Registry::Switch(cmd) => cmd.run(env),
            Registry::List(cmd) => cmd.run(env).await,
            Registry::Pull(cmd) => cmd.run(env).await,
            Registry::Query(cmd) => cmd.run(env).await,
        }
    }
}
