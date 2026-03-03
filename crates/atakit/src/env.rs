use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result};
use automata_linux_release::{ImageRef, ImageStore};
use serde::{Deserialize, Serialize};

use crate::instances::InstanceStore;
use crate::registry::RegistryStore;
use crate::types::{AtakitConfig, WorkloadDef};

const CONFIG_FILENAME: &str = "atakit.json";
const GLOBAL_CONFIG_FILENAME: &str = "config.json";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_container_engine: Option<String>,
}

/// OVMF firmware embedded at compile time.
const OVMF_BYTES: &[u8] = include_bytes!("../../../deps/ovmf.fd");

/// Runtime context shared across all commands.
pub struct Env {
    /// Base atakit directory (`~/.atakit`).
    atakit_dir: PathBuf,
    /// Local directory for storing downloaded CVM base images.
    pub image_dir: PathBuf,
    /// Path to the `atakit.json` config file, if found.
    pub config_file: Option<PathBuf>,
    pub project_artifact_dir: PathBuf,
    pub image_repo: String,
}

impl Env {
    /// Build context from environment.
    ///
    /// - `atakit_dir` defaults to `$HOME/.atakit`.
    /// - `image_dir` defaults to `$HOME/.atakit/images`.
    /// - `config_file` is located by walking up from the current directory.
    /// - `project_artifact_dir` defaults to `ata_artifacts` in the directory containing `atakit.json`.
    pub fn from_env() -> Self {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let atakit_dir = home.join(".atakit");
        let config_file = find_config();
        let project_artifact_dir = config_file
            .as_ref()
            .and_then(|f| f.parent().map(|d| d.join("ata_artifacts")))
            .unwrap_or_else(|| PathBuf::from("ata_artifacts"));

        Self {
            atakit_dir: atakit_dir.clone(),
            image_dir: atakit_dir.join("images"),
            config_file,
            project_artifact_dir,
            image_repo: automata_linux_release::REPO.to_string(),
        }
    }

    /// Return the directory containing `atakit.json`, if found.
    pub fn config_dir(&self) -> Result<&std::path::Path> {
        let config_path = self.config_file.as_ref().context("atakit.json not found")?;
        Ok(config_path.parent().unwrap_or(std::path::Path::new(".")))
    }

    pub fn config(&self) -> Result<AtakitConfig> {
        AtakitConfig::load_from(self.config_dir()?)
    }

    /// Directory for QEMU-related files (`~/.atakit/qemu`).
    pub fn qemu_dir(&self) -> PathBuf {
        self.atakit_dir.join("qemu")
    }

    /// Directory for QEMU instance (`~/.atakit/qemu/{name}`).
    pub fn qemu_disk_dir(&self, name: &str) -> PathBuf {
        self.qemu_dir().join(name)
    }

    /// Path to the OVMF firmware file (`~/.atakit/qemu/ovmf.fd`).
    pub fn ovmf_path(&self) -> PathBuf {
        self.qemu_dir().join("ovmf.fd")
    }

    pub fn workload_package(&self, workload: &WorkloadDef) -> PathBuf {
        self.project_artifact_dir
            .join(&workload.name)
            .join(workload.package_name())
    }

    /// Ensure OVMF firmware is extracted to `~/.atakit/qemu/ovmf.fd`.
    ///
    /// This is idempotent — if the file already exists, it does nothing.
    pub fn ensure_ovmf(&self) -> Result<PathBuf> {
        let path = self.ovmf_path();
        if path.exists() {
            return Ok(path);
        }

        let qemu_dir = self.qemu_dir();
        std::fs::create_dir_all(&qemu_dir)
            .with_context(|| format!("Failed to create {}", qemu_dir.display()))?;

        std::fs::write(&path, OVMF_BYTES)
            .with_context(|| format!("Failed to write {}", path.display()))?;

        Ok(path)
    }

    /// Directory for instance records (`~/.atakit/instances`).
    pub fn instances_dir(&self) -> PathBuf {
        self.atakit_dir.join("instances")
    }

    /// Get an instance store for managing deployed instances.
    pub fn instance_store(&self) -> InstanceStore {
        InstanceStore::new(self.instances_dir())
    }

    /// Directory for dev platform profiles (`~/.atakit/images/dev/profiles`).
    pub fn image_profiles_dir(&self, image: &ImageRef) -> PathBuf {
        self.image_dir
            .join(&image.repository)
            .join(&image.tag)
            .join("profiles")
    }

    /// Directory for registry data (`~/.atakit/registry`).
    pub fn registry_dir(&self) -> PathBuf {
        self.atakit_dir.join("registry")
    }

    /// Get a registry store for managing contract deployments.
    pub fn registry_store(&self) -> RegistryStore {
        RegistryStore::new(self.registry_dir())
    }

    /// Path to the global config file (`~/.atakit/config.json`).
    fn global_config_path(&self) -> PathBuf {
        self.atakit_dir.join(GLOBAL_CONFIG_FILENAME)
    }

    /// Read the global config. Returns `Default` if the file is missing or unreadable.
    pub fn global_config(&self) -> GlobalConfig {
        let path = self.global_config_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Write the global config to `~/.atakit/config.json`, creating the directory if needed.
    pub fn save_global_config(&self, config: &GlobalConfig) -> Result<()> {
        std::fs::create_dir_all(&self.atakit_dir)
            .with_context(|| format!("Failed to create {}", self.atakit_dir.display()))?;
        let json = serde_json::to_string_pretty(config)?;
        std::fs::write(self.global_config_path(), json)
            .with_context(|| format!("Failed to write {}", self.global_config_path().display()))?;
        Ok(())
    }

    pub fn image_store(&self) -> ImageStore {
        ImageStore::new(self.image_dir.clone())
    }
}

/// Walk from the current directory upward looking for `atakit.json`.
fn find_config() -> Option<PathBuf> {
    let mut dir = env::current_dir().ok()?;
    loop {
        let candidate = dir.join(CONFIG_FILENAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}
