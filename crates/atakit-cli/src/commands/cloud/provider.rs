use anyhow::Result;
use owo_colors::OwoColorize;

use crate::config::Config;

pub fn run(config: &Config) -> Result<()> {
    if config.cloud.providers.is_empty() {
        eprintln!("No providers configured. Add entries under [cloud.providers] in config.toml.");
        return Ok(());
    }
    for (name, p) in &config.cloud.providers {
        eprintln!("  {:<20} {} {}", name.bold(), p.platform, p.region);
    }
    Ok(())
}
