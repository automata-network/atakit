use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{CcType, PlatformKind};
use crate::error::CloudError;

/// Persisted state of images uploaded to cloud providers.
///
/// Stored at `data_dir/cloud/images.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudImages {
    pub format: u32,
    /// image_ref -> provider_name -> upload record.
    #[serde(default)]
    pub images: BTreeMap<String, BTreeMap<String, CloudImage>>,
}

/// Record of a single image uploaded to a single provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudImage {
    pub platform: PlatformKind,
    /// GCE image name (GCP) or image definition name (Azure).
    pub cloud_name: String,
    /// GCS bucket (GCP only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Gallery resource group (Azure only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gallery_rg: Option<String>,
    /// Gallery name (Azure only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gallery: Option<String>,
    /// Image version (Azure only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_version: Option<String>,
    /// CC types registered on this image.
    pub cc_types: Vec<CcType>,
    /// When the image was uploaded.
    pub uploaded_at: DateTime<Utc>,
}

impl Default for CloudImages {
    fn default() -> Self {
        Self {
            format: 1,
            images: BTreeMap::new(),
        }
    }
}

impl CloudImages {
    /// Path to the cloud images state file.
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("cloud").join("images.json")
    }

    /// Load from disk. Returns default (empty) if file doesn't exist.
    pub fn load(data_dir: &Path) -> Result<Self, CloudError> {
        let path = Self::path(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path).map_err(|e| CloudError::State {
            message: format!("failed to read {}: {e}", path.display()),
        })?;
        serde_json::from_str(&content).map_err(|e| CloudError::State {
            message: format!("failed to parse {}: {e}", path.display()),
        })
    }

    /// Save to disk (atomic write).
    pub fn save(&self, data_dir: &Path) -> Result<(), CloudError> {
        let path = Self::path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CloudError::State {
                message: format!("failed to create {}: {e}", parent.display()),
            })?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| CloudError::State {
            message: format!("failed to serialize cloud images: {e}"),
        })?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json).map_err(|e| CloudError::State {
            message: format!("failed to write {}: {e}", tmp.display()),
        })?;
        std::fs::rename(&tmp, &path).map_err(|e| CloudError::State {
            message: format!(
                "failed to rename {} -> {}: {e}",
                tmp.display(),
                path.display()
            ),
        })?;
        Ok(())
    }

    /// Record a successful image upload.
    pub fn record(&mut self, image_ref: &str, provider_name: &str, record: CloudImage) {
        self.images
            .entry(image_ref.to_string())
            .or_default()
            .insert(provider_name.to_string(), record);
    }

    /// Remove a specific image+provider entry. Returns the removed record.
    pub fn remove(&mut self, image_ref: &str, provider_name: &str) -> Option<CloudImage> {
        let providers = self.images.get_mut(image_ref)?;
        let removed = providers.remove(provider_name);
        if providers.is_empty() {
            self.images.remove(image_ref);
        }
        removed
    }

    /// Look up an image+provider entry.
    pub fn get(&self, image_ref: &str, provider_name: &str) -> Option<&CloudImage> {
        self.images.get(image_ref)?.get(provider_name)
    }

    /// Find all entries whose image_ref is not in the referenced set.
    /// Returns (image_ref, provider_name) pairs.
    pub fn unreferenced(&self, referenced: &[String]) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for (image_ref, providers) in &self.images {
            if !referenced.contains(image_ref) {
                for provider_name in providers.keys() {
                    result.push((image_ref.clone(), provider_name.clone()));
                }
            }
        }
        result
    }

    /// Flat list of all entries as (image_ref, provider_name, record) triples.
    pub fn entries(&self) -> Vec<(&str, &str, &CloudImage)> {
        let mut out = Vec::new();
        for (image_ref, providers) in &self.images {
            for (provider_name, record) in providers {
                out.push((image_ref.as_str(), provider_name.as_str(), record));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> CloudImage {
        CloudImage {
            platform: PlatformKind::Gcp,
            cloud_name: "dev-baseimage-v0-0-1-debug".to_string(),
            bucket: Some("atakit-upload-dev-baseimage-v0-0-1-debug".to_string()),
            gallery_rg: None,
            gallery: None,
            image_version: None,
            cc_types: vec![CcType::SevSnp, CcType::Tdx],
            uploaded_at: Utc::now(),
        }
    }

    #[test]
    fn record_and_get() {
        let mut ci = CloudImages::default();
        ci.record("img:v1", "gcp-sea", sample_record());
        assert!(ci.get("img:v1", "gcp-sea").is_some());
        assert!(ci.get("img:v1", "other").is_none());
    }

    #[test]
    fn remove_entry() {
        let mut ci = CloudImages::default();
        ci.record("img:v1", "gcp-sea", sample_record());
        let removed = ci.remove("img:v1", "gcp-sea");
        assert!(removed.is_some());
        assert!(ci.images.is_empty());
    }

    #[test]
    fn remove_one_provider_keeps_others() {
        let mut ci = CloudImages::default();
        ci.record("img:v1", "gcp-sea", sample_record());
        ci.record("img:v1", "azure-east", sample_record());
        ci.remove("img:v1", "gcp-sea");
        assert!(ci.get("img:v1", "azure-east").is_some());
    }

    #[test]
    fn unreferenced() {
        let mut ci = CloudImages::default();
        ci.record("img:v1", "gcp-sea", sample_record());
        ci.record("img:v2", "gcp-sea", sample_record());
        let unref = ci.unreferenced(&["img:v1".to_string()]);
        assert_eq!(unref.len(), 1);
        assert_eq!(unref[0].0, "img:v2");
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut ci = CloudImages::default();
        ci.record("img:v1", "gcp-sea", sample_record());
        ci.save(dir.path()).unwrap();
        let loaded = CloudImages::load(dir.path()).unwrap();
        assert!(loaded.get("img:v1", "gcp-sea").is_some());
    }

    #[test]
    fn load_missing_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let ci = CloudImages::load(dir.path()).unwrap();
        assert!(ci.images.is_empty());
    }
}
