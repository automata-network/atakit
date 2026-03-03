use anyhow::{Result, bail};
use clap::{Args, Subcommand};

use crate::env::Env;

#[derive(Subcommand)]
pub enum Config {
    /// Set or show the default container engine
    DefaultContainerEngine(DefaultContainerEngine),
}

#[derive(Args)]
pub struct DefaultContainerEngine {
    /// Engine to set (docker or podman). Omit to show current value.
    pub engine: Option<String>,
}

impl Config {
    pub fn run(self, env: &Env) -> Result<()> {
        match self {
            Config::DefaultContainerEngine(cmd) => cmd.run(env),
        }
    }
}

impl DefaultContainerEngine {
    fn run(self, env: &Env) -> Result<()> {
        match self.engine {
            Some(engine) => {
                if engine != "docker" && engine != "podman" {
                    bail!("Unsupported engine '{engine}'. Must be 'docker' or 'podman'.");
                }
                let mut config = env.global_config();
                config.default_container_engine = Some(engine.clone());
                env.save_global_config(&config)?;
                println!("Default container engine set to '{engine}'.");
                Ok(())
            }
            None => {
                let config = env.global_config();
                match config.default_container_engine {
                    Some(engine) => println!("{engine}"),
                    None => println!("not set"),
                }
                Ok(())
            }
        }
    }
}
