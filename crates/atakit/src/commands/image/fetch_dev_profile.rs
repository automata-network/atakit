//! Fetch platform profile from a running CVM agent for development.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use crate::Env;
use super::types::PlatformProfileResponse;
use automata_linux_release::ImageRef;

#[derive(Parser)]
pub struct FetchDevProfile {
    /// IP address of the CVM agent
    ip: String,

    /// Port of the CVM agent (default: 8000)
    #[arg(long, default_value = "8000")]
    port: u16,

    /// Base image version (e.g., "1.0.0")
    #[arg(long, default_value = "automata-linux:dev")]
    image: ImageRef,
}

impl FetchDevProfile {
    pub async fn run(self, env: &Env) -> Result<()> {
        let url = format!("https://{}:{}/platform-profile", self.ip, self.port);

        info!(url = %url, "Fetching platform profile from CVM agent");

        // Build a client that accepts self-signed/invalid certs (dev mode)
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        let response = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch platform profile from {}", url))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to fetch platform profile: {} - {}", status, body);
        }

        let profile: PlatformProfileResponse = response
            .json()
            .await
            .context("Failed to parse platform profile response")?;

        info!(
            cloud_type = %profile.cloud_type,
            tee_type = %profile.tee_type,
            machine_type = %profile.machine_type,
            pcr_count = profile.pcrs.len(),
            "Received platform profile"
        );

        // Create dev profiles directory
        let profiles_dir = env.image_profiles_dir(&self.image);
        std::fs::create_dir_all(&profiles_dir)
            .with_context(|| format!("Failed to create directory: {}", profiles_dir.display()))?;

        // Save profile to file
        let filename = profile.filename();
        let filepath = profiles_dir.join(&filename);

        let json = serde_json::to_string_pretty(&profile)
            .context("Failed to serialize profile")?;

        std::fs::write(&filepath, json)
            .with_context(|| format!("Failed to write profile to {}", filepath.display()))?;

        info!(path = %filepath.display(), "Saved platform profile");

        println!("Platform profile saved to {}", filepath.display());
        println!("  Cloud: {}", profile.cloud_type);
        println!("  TEE: {}", profile.tee_type);
        println!("  Machine: {}", profile.machine_type);
        println!("  PCRs: {}", profile.pcrs.len());

        Ok(())
    }
}
