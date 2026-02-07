mod ls;
mod pull;
mod rm;

use anyhow::Result;
use clap::Subcommand;

use crate::Env;

#[derive(Subcommand)]
pub enum Image {
    /// List available CVM base image releases
    #[command(name = "ls")]
    List(ls::List),
    /// Pull a CVM base image from a release
    #[command(name = "pull")]
    Download(pull::Download),
    /// Remove locally downloaded CVM base images
    #[command(name = "rm")]
    Delete(rm::Delete),
}

impl Image {
    pub async fn run(self, env: &Env) -> Result<()> {
        match self {
            Image::List(cmd) => cmd.run(env).await,
            Image::Download(cmd) => cmd.run(env).await,
            Image::Delete(cmd) => cmd.run(env).await,
        }
    }
}
