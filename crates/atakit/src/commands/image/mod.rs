mod ls;
mod pull;
mod rm;

#[cfg(feature = "internal")]
mod fetch_dev_profile;
#[cfg(feature = "internal")]
mod publish;
#[cfg(feature = "internal")]
mod types;

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

    /// [internal] Fetch platform profile from a running CVM agent
    #[cfg(feature = "internal")]
    #[command(name = "fetch-dev-profile")]
    FetchDevProfile(fetch_dev_profile::FetchDevProfile),

    /// [internal] Publish base image to the BaseImageRegistry contract
    #[cfg(feature = "internal")]
    #[command(name = "publish")]
    Publish(publish::Publish),
}

impl Image {
    pub async fn run(self, env: &Env) -> Result<()> {
        match self {
            Image::List(cmd) => cmd.run(env).await,
            Image::Download(cmd) => cmd.run(env).await,
            Image::Delete(cmd) => cmd.run(env).await,

            #[cfg(feature = "internal")]
            Image::FetchDevProfile(cmd) => cmd.run(env).await,
            #[cfg(feature = "internal")]
            Image::Publish(cmd) => cmd.run(env).await,
        }
    }
}
