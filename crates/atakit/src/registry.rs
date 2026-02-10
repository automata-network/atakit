//! Registry store for managing contract deployment addresses.
//!
//! Stores contract addresses in `~/.atakit/registry/{branch}/{chain_id}.json`
//! Configuration is stored in `~/.atakit/registry/config.json`

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const GITHUB_REPO: &str = "automata-network/automata-tee-workload-measurement";
const DEPLOYMENTS_PATH: &str = "deployment";
const DEFAULT_BRANCH: &str = "main";

/// Registry configuration stored in `~/.atakit/registry/config.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryConfig {
    /// Current active branch.
    #[serde(default)]
    pub branch: String,
}

/// Contract addresses for a specific chain.
pub type ContractAddresses = BTreeMap<String, String>;

/// Registry store for managing contract deployment information.
pub struct RegistryStore {
    base_dir: PathBuf,
    http: reqwest::Client,
}

impl RegistryStore {
    /// Create a new registry store.
    ///
    /// `base_dir` is typically `~/.atakit/registry`.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Get the base directory for the registry.
    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    /// Path to the config file (`~/.atakit/registry/config.json`).
    fn config_path(&self) -> PathBuf {
        self.base_dir.join("config.json")
    }

    /// Get the directory for a specific branch.
    fn branch_dir(&self, branch: &str) -> PathBuf {
        self.base_dir.join(branch)
    }

    /// Get the path for a chain's contract addresses.
    fn chain_path(&self, branch: &str, chain_id: &str) -> PathBuf {
        self.branch_dir(branch).join(format!("{}.json", chain_id))
    }

    /// Load the registry configuration.
    pub fn load_config(&self) -> Result<RegistryConfig> {
        let path = self.config_path();
        if !path.exists() {
            return Ok(RegistryConfig {
                branch: DEFAULT_BRANCH.to_string(),
            });
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;

        let mut config: RegistryConfig = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", path.display()))?;

        if config.branch.is_empty() {
            config.branch = DEFAULT_BRANCH.to_string();
        }

        Ok(config)
    }

    /// Save the registry configuration.
    pub fn save_config(&self, config: &RegistryConfig) -> Result<()> {
        std::fs::create_dir_all(&self.base_dir)
            .with_context(|| format!("Failed to create directory: {}", self.base_dir.display()))?;

        let path = self.config_path();
        let content = serde_json::to_string_pretty(config)
            .context("Failed to serialize config")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write config: {}", path.display()))?;

        Ok(())
    }

    /// Switch to a different branch.
    pub fn switch_branch(&self, branch: &str) -> Result<()> {
        let config = RegistryConfig {
            branch: branch.to_string(),
        };
        self.save_config(&config)
    }

    /// Get the current branch.
    pub fn current_branch(&self) -> Result<String> {
        Ok(self.load_config()?.branch)
    }

    /// Check if the branch directory exists and has files.
    pub fn branch_has_data(&self, branch: &str) -> bool {
        let dir = self.branch_dir(branch);
        if !dir.exists() {
            return false;
        }

        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                    return true;
                }
            }
        }
        false
    }

    /// List all chain files for a branch.
    pub fn list_chains(&self, branch: &str) -> Result<Vec<String>> {
        let dir = self.branch_dir(branch);
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut chains = Vec::new();
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    chains.push(stem.to_string());
                }
            }
        }

        chains.sort();
        Ok(chains)
    }

    /// Load contract addresses for a specific chain.
    pub fn load_chain(&self, branch: &str, chain_id: &str) -> Result<Option<ContractAddresses>> {
        let path = self.chain_path(branch, chain_id);
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read: {}", path.display()))?;

        let addresses: ContractAddresses = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse: {}", path.display()))?;

        Ok(Some(addresses))
    }

    /// Save contract addresses for a specific chain.
    pub fn save_chain(
        &self,
        branch: &str,
        chain_id: &str,
        addresses: &ContractAddresses,
    ) -> Result<()> {
        let dir = self.branch_dir(branch);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create directory: {}", dir.display()))?;

        let path = self.chain_path(branch, chain_id);
        let content = serde_json::to_string_pretty(addresses)
            .context("Failed to serialize addresses")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write: {}", path.display()))?;

        Ok(())
    }

    /// Pull deployment files from the remote GitHub repository.
    pub async fn pull(&self, branch: &str) -> Result<Vec<String>> {
        // First, list files in the deployments directory
        let files = self.list_remote_files(branch).await?;

        let mut saved = Vec::new();
        for file in &files {
            if file.ends_with(".json") {
                let content = self.fetch_remote_file(branch, file).await?;
                let chain_id = file.trim_end_matches(".json");

                // Parse and save
                let addresses: ContractAddresses = serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse remote file: {}", file))?;

                self.save_chain(branch, chain_id, &addresses)?;
                saved.push(chain_id.to_string());
            }
        }

        Ok(saved)
    }

    /// List files in the remote deployments directory.
    async fn list_remote_files(&self, branch: &str) -> Result<Vec<String>> {
        let url = format!(
            "https://api.github.com/repos/{}/contents/{}?ref={}",
            GITHUB_REPO, DEPLOYMENTS_PATH, branch
        );

        let response = self
            .http
            .get(&url)
            .header("User-Agent", "atakit")
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .with_context(|| format!("Failed to fetch: {}", url))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "GitHub API returned {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }

        #[derive(Deserialize)]
        struct GithubFile {
            name: String,
            #[serde(rename = "type")]
            file_type: String,
        }

        let files: Vec<GithubFile> = response
            .json()
            .await
            .context("Failed to parse GitHub API response")?;

        Ok(files
            .into_iter()
            .filter(|f| f.file_type == "file")
            .map(|f| f.name)
            .collect())
    }

    /// Fetch a file from the remote repository.
    async fn fetch_remote_file(&self, branch: &str, filename: &str) -> Result<String> {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}/{}",
            GITHUB_REPO, branch, DEPLOYMENTS_PATH, filename
        );

        let response = self
            .http
            .get(&url)
            .header("User-Agent", "atakit")
            .send()
            .await
            .with_context(|| format!("Failed to fetch: {}", url))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Failed to fetch {}: {}",
                filename,
                response.status()
            );
        }

        response
            .text()
            .await
            .with_context(|| format!("Failed to read response for: {}", filename))
    }

    /// Ensure the branch has data, pulling from remote if needed.
    pub async fn ensure_data(&self, branch: &str) -> Result<()> {
        if !self.branch_has_data(branch) {
            tracing::info!("No local data for branch '{}', fetching from remote...", branch);
            self.pull(branch).await?;
        }
        Ok(())
    }
}
