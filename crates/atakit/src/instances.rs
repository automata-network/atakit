//! Instance management for tracking deployed VMs.
//!
//! Stores instance metadata in `~/.atakit/instances/{platform}/{instance_name}.json`

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Metadata for a deployed instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceRecord {
    /// Instance name (same as deployment name).
    pub name: String,
    /// Cloud platform (gcp, azure).
    pub platform: String,
    /// Public IP address if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    /// GCP zone or Azure region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// GCP project ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Azure resource group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_group: Option<String>,
    /// Image version used for deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_version: Option<String>,
    /// Timestamp when the instance was created (Unix seconds).
    #[serde(default)]
    pub created_at: u64,
}

/// Instance store for managing deployed instances.
pub struct InstanceStore {
    base_dir: PathBuf,
}

impl InstanceStore {
    /// Create a new instance store.
    ///
    /// `base_dir` is typically `~/.atakit/instances`.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Get the directory for a specific platform.
    fn platform_dir(&self, platform: &str) -> PathBuf {
        self.base_dir.join(platform)
    }

    /// Get the path for an instance record.
    fn instance_path(&self, platform: &str, name: &str) -> PathBuf {
        self.platform_dir(platform).join(format!("{}.json", name))
    }

    /// Save an instance record.
    pub fn save(&self, record: &InstanceRecord) -> Result<()> {
        let dir = self.platform_dir(&record.platform);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create directory: {}", dir.display()))?;

        let path = self.instance_path(&record.platform, &record.name);
        let content = serde_json::to_string_pretty(record)
            .context("Failed to serialize instance record")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write instance record: {}", path.display()))?;

        Ok(())
    }

    /// Load an instance record.
    pub fn load(&self, platform: &str, name: &str) -> Result<Option<InstanceRecord>> {
        let path = self.instance_path(platform, name);
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read instance record: {}", path.display()))?;

        let record: InstanceRecord = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse instance record: {}", path.display()))?;

        Ok(Some(record))
    }

    /// Delete an instance record.
    pub fn delete(&self, platform: &str, name: &str) -> Result<bool> {
        let path = self.instance_path(platform, name);
        if !path.exists() {
            return Ok(false);
        }

        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to delete instance record: {}", path.display()))?;

        Ok(true)
    }

    /// List all instances for a platform.
    pub fn list_platform(&self, platform: &str) -> Result<Vec<InstanceRecord>> {
        let dir = self.platform_dir(platform);
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut records = Vec::new();
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(record) = serde_json::from_str::<InstanceRecord>(&content) {
                        records.push(record);
                    }
                }
            }
        }

        // Sort by creation time (newest first).
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(records)
    }

    /// List all instances across all platforms.
    pub fn list_all(&self) -> Result<Vec<InstanceRecord>> {
        let mut all_records = Vec::new();

        if !self.base_dir.exists() {
            return Ok(all_records);
        }

        for entry in std::fs::read_dir(&self.base_dir)
            .with_context(|| format!("Failed to read directory: {}", self.base_dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(platform) = entry.file_name().to_str() {
                    let records = self.list_platform(platform)?;
                    all_records.extend(records);
                }
            }
        }

        // Sort by creation time (newest first).
        all_records.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(all_records)
    }

    /// Find an instance by name across all platforms.
    pub fn find_by_name(&self, name: &str) -> Result<Option<InstanceRecord>> {
        for platform in &["gcp", "azure"] {
            if let Some(record) = self.load(platform, name)? {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }
}

/// Create an instance record from deployment info.
pub fn create_record(
    name: &str,
    platform: &str,
    public_ip: Option<String>,
    zone: Option<String>,
    project_id: Option<String>,
    resource_group: Option<String>,
    image_version: Option<String>,
) -> InstanceRecord {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    InstanceRecord {
        name: name.to_string(),
        platform: platform.to_string(),
        public_ip,
        zone,
        project_id,
        resource_group,
        image_version,
        created_at,
    }
}
