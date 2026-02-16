use std::path::PathBuf;

use alloy::primitives::B256;
use anyhow::{Context, Result};
use clap::Args;
use cvm_agent::client::{AdditionalFile, update_workload};
use tracing::info;

use crate::Config;

#[derive(Args)]
pub struct UpdateWorkload {
    /// IP address of the CVM
    pub ip: String,

    /// Path to the workload tar.gz (pre-built via `atakit workload build`)
    #[arg(long)]
    pub workload_path: PathBuf,

    /// Owner private key (hex encoded) for operator signature
    #[arg(long, env = "ATAKIT_OWNER_PRIVATE_KEY")]
    pub owner_private_key: B256,

    /// Directory containing additional data files to upload alongside the workload.
    /// All files in this directory will be included.
    #[arg(long)]
    pub additional_data_dir: Option<PathBuf>,
}

impl UpdateWorkload {
    pub async fn run(self, _cfg: &Config) -> Result<()> {
        let additional_files = match &self.additional_data_dir {
            Some(dir) => load_additional_files_from_dir(dir).await?,
            None => Vec::new(),
        };

        update_workload(&self.ip, &self.workload_path, additional_files, self.owner_private_key)
            .await?;

        info!("Workload update completed successfully");
        Ok(())
    }
}

async fn load_additional_files_from_dir(dir: &std::path::Path) -> Result<Vec<AdditionalFile>> {
    let mut files = Vec::new();
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("Failed to read additional data dir: {}", dir.display()))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let data = tokio::fs::read(&path).await.with_context(|| {
            format!("Failed to read additional file: {}", path.display())
        })?;

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        info!(path = %path.display(), "Loading additional file");

        files.push(AdditionalFile {
            source: filename.clone(),
            dest: format!("/{}", filename),
            data,
        });
    }

    Ok(files)
}
