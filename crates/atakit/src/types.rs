#![allow(dead_code)]

use std::path::Path;

use anyhow::{Context, Result, bail};
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

    pub fn workload<'a>(&'a self, name: Option<&str>) -> anyhow::Result<&'a WorkloadDef> {
        let workload = if self.workloads.len() == 1 && name.is_none() {
            &self.workloads[0]
        } else if let Some(ref name) = name {
            self.workloads
                .iter()
                .find(|w| w.name == *name)
                .ok_or_else(|| {
                    let available: Vec<_> = self.workloads.iter().map(|w| &w.name).collect();
                    anyhow::anyhow!(
                        "Workload '{}' not found. Available: {}",
                        name,
                        available
                            .iter()
                            .map(|n| n.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?
        } else {
            let names: Vec<_> = self.workloads.iter().map(|w| &w.name).collect();
            bail!(
                "Multiple workloads defined. Specify one with available: {}",
                names
                    .iter()
                    .map(|n| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        Ok(workload)
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

impl WorkloadDef {
    pub fn package_name(&self) -> String {
        format!("{}-{}.tar.gz", self.name, self.version)
    }
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
