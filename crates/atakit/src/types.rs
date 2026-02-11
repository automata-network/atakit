#![allow(dead_code)]

use std::path::Path;

use anyhow::{Context, Result};
use automata_linux_release::ImageRef;
use indexmap::IndexMap;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// atakit.json configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AtakitConfig {
    pub workloads: Vec<WorkloadDef>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub disks: Vec<DiskDef>,
    #[serde(default)]
    pub deployment: IndexMap<String, DeploymentDef>,
}

impl AtakitConfig {
    /// Load atakit.json from the given directory (or current working directory).
    pub fn load_from(dir: &Path) -> Result<Self> {
        let path = dir.join("atakit.json");
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let config: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        for wl in &config.workloads {
            if !wl.version.starts_with("v") {
                anyhow::bail!(
                    "Workload {} has invalid version {}, must start with 'v'",
                    wl.name,
                    wl.version
                );
            }
        }
        Ok(config)
    }

    /// Load atakit.json from the current working directory.
    pub fn load() -> Result<Self> {
        Self::load_from(&std::env::current_dir()?)
    }
}

#[derive(Debug, Deserialize)]
pub struct WorkloadDef {
    pub name: String,
    /// Relative path to the docker-compose file.
    pub docker_compose: String,
    pub image: ImageRef,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct DiskDef {
    pub name: String,
    pub size: String,
    #[serde(default)]
    pub encryption: Option<DiskEncryption>,
}

#[derive(Debug, Deserialize)]
pub struct DiskEncryption {
    pub enable: bool,
    #[serde(default = "default_key_security")]
    pub encryption_key_security: String,
}

fn default_key_security() -> String {
    "standard".to_string()
}

#[derive(Debug, Deserialize)]
pub struct DeploymentDef {
    pub workload: String,
    /// Image version tag for automata-linux disk images (e.g. "v0.5.0").
    /// If omitted, uses the latest available release with disk images.
    #[serde(default)]
    pub image: Option<ImageRef>,
    #[serde(default)]
    pub platforms: IndexMap<String, PlatformConfig>,
}

#[derive(Debug, Deserialize)]
pub struct PlatformConfig {
    #[serde(default)]
    pub vmtype: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}

// ---------------------------------------------------------------------------
// Workload manifest (embedded inside the tar.gz package)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
pub struct WorkloadManifest {
    pub name: ImageRef,
    pub docker_compose: String,
    pub image: ImageRef,
    pub measured_files: Vec<String>,
    pub additional_data_files: Vec<String>,
    pub docker_images: Vec<DockerImageEntry>,
    pub enable_cvm_agent: Vec<String>,
    pub atakit_version: String,
}

#[derive(Debug, serde::Serialize)]
pub struct DockerImageEntry {
    pub service: String,
    /// For pre-published images (no build directive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_tag: Option<String>,
    /// Filename of the saved tar inside the package (for locally built images).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_tar: Option<String>,
}
