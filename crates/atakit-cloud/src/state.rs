use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::PlatformKind;
use crate::error::CloudError;

const FORMAT_VERSION: u32 = 1;

/// Persistent deployment state stored as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployState {
    pub format: u32,
    pub instance_name: String,
    pub workload_name: String,
    pub workload_version: String,
    pub target_name: String,
    /// Provider name from [cloud.providers] at deploy time.
    #[serde(default)]
    pub provider_name: String,
    pub platform: PlatformKind,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: DeployStatus,
    pub image_ref: String,
    pub archive_path: String,
    pub archive_hash: String,
    pub init_env: PersistedInitEnv,
    pub resources: ResourceSet,
}

/// Current deployment lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeployStatus {
    Deploying { step: u32, total: u32 },
    Deployed { ip: String },
    Failed { step: String, message: String },
    Destroying,
    Destroyed,
}

/// Init environment config persisted for re-deploys.
/// Stores reference names into `[chains.*]` and `[keys.*]` config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedInitEnv {
    pub chain: String,
    pub owner_key: String,
    pub gas_wallet: String,
}

/// Cloud provider resources tracked in state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp: Option<GcpResources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure: Option<AzureResources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsResources>,
}

/// GCP-specific resource tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GcpResources {
    pub project: String,
    pub zone: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
}

/// Azure-specific resource tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AzureResources {
    pub subscription: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gallery_rg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gallery: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_definition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsg: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
}

/// AWS-specific resource tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AwsResources {
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ami: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
}

/// Base directory for deployment state files.
fn deployments_dir(data_dir: &Path) -> PathBuf {
    let new_path = data_dir.join("cloud").join("deployments");
    // Migrate from old path if it exists and new path doesn't.
    let old_path = data_dir.join("deployments");
    if old_path.is_dir() && !old_path.is_symlink() && !new_path.exists() {
        if let Some(parent) = new_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::rename(&old_path, &new_path).is_ok() {
            tracing::info!("migrated deployments to {}", new_path.display());
        }
    }
    new_path
}

/// Path to a specific state file.
fn state_path(data_dir: &Path, target: &str, instance: &str) -> PathBuf {
    deployments_dir(data_dir)
        .join(target)
        .join(format!("{instance}.state.json"))
}

/// Parameters for creating a new deployment state.
pub struct NewDeployParams {
    pub instance_name: String,
    pub workload_name: String,
    pub workload_version: String,
    pub target_name: String,
    pub provider_name: String,
    pub platform: PlatformKind,
    pub image_ref: String,
    pub archive_path: String,
    pub archive_hash: String,
    pub init_env: PersistedInitEnv,
    /// Total number of steps in the deployment plan.
    pub total_steps: u32,
}

impl DeployState {
    /// Create a new deploy state in "deploying" status.
    pub fn new(params: NewDeployParams) -> Self {
        let now = Utc::now();
        Self {
            format: FORMAT_VERSION,
            instance_name: params.instance_name,
            workload_name: params.workload_name,
            workload_version: params.workload_version,
            target_name: params.target_name,
            provider_name: params.provider_name,
            platform: params.platform,
            created_at: now,
            updated_at: now,
            status: DeployStatus::Deploying {
                step: 0,
                total: params.total_steps,
            },
            image_ref: params.image_ref,
            archive_path: params.archive_path,
            archive_hash: params.archive_hash,
            init_env: params.init_env,
            resources: ResourceSet::default(),
        }
    }

    /// Load state from disk.
    pub fn load(data_dir: &Path, target: &str, instance: &str) -> Result<Self, CloudError> {
        let path = state_path(data_dir, target, instance);
        let content = fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CloudError::StateNotFound {
                    instance: format!("{target}/{instance}"),
                }
            } else {
                CloudError::IoPath {
                    path: path.clone(),
                    source: e,
                }
            }
        })?;
        let state: DeployState = serde_json::from_str(&content).map_err(|e| CloudError::State {
            message: format!("failed to parse {}: {e}", path.display()),
        })?;
        Ok(state)
    }

    /// Save state to disk (atomic via temp file + rename).
    pub fn save(&mut self, data_dir: &Path) -> Result<(), CloudError> {
        self.updated_at = Utc::now();
        let path = state_path(data_dir, &self.target_name, &self.instance_name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| CloudError::IoPath {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &json).map_err(|e| CloudError::IoPath {
            path: tmp.clone(),
            source: e,
        })?;
        fs::rename(&tmp, &path).map_err(|e| CloudError::IoPath {
            path: path.clone(),
            source: e,
        })?;
        Ok(())
    }

    /// Delete state file from disk.
    pub fn delete(data_dir: &Path, target: &str, instance: &str) -> Result<(), CloudError> {
        let path = state_path(data_dir, target, instance);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| CloudError::IoPath {
                path: path.clone(),
                source: e,
            })?;
        }
        // Clean up empty target directory.
        let target_dir = deployments_dir(data_dir).join(target);
        if target_dir.is_dir() {
            let _ = fs::remove_dir(&target_dir); // ignore error if not empty
        }
        Ok(())
    }

    /// Update status and persist.
    pub fn set_status(&mut self, status: DeployStatus, data_dir: &Path) -> Result<(), CloudError> {
        self.status = status;
        self.save(data_dir)
    }

    /// Update deploying step progress.
    pub fn advance_step(&mut self, step: u32, data_dir: &Path) -> Result<(), CloudError> {
        if let DeployStatus::Deploying { total, .. } = &self.status {
            let total = *total;
            self.status = DeployStatus::Deploying { step, total };
            self.save(data_dir)?;
        }
        Ok(())
    }

    /// Apply resource updates from a completed step.
    pub fn apply_resource_updates(&mut self, updates: &crate::plan::ResourceUpdates) {
        // Route to the correct platform resource set.
        if self.resources.azure.is_some() {
            self.apply_azure_resource_updates(updates);
        } else if self.resources.aws.is_some() {
            self.apply_aws_resource_updates(updates);
        } else {
            self.apply_gcp_resource_updates(updates);
        }
    }

    fn apply_aws_resource_updates(&mut self, updates: &crate::plan::ResourceUpdates) {
        let aws = self.resources.aws.get_or_insert_with(AwsResources::default);
        if let Some(ref b) = updates.bucket {
            aws.bucket = Some(b.clone());
        }
        if let Some(ref s) = updates.snapshot {
            aws.snapshot = Some(s.clone());
        }
        if let Some(ref i) = updates.image {
            aws.ami = Some(i.clone());
        }
        if let Some(ref f) = updates.firewall_rule {
            aws.security_group = Some(f.clone());
        }
        if let Some(ref i) = updates.instance {
            aws.instance = Some(i.clone());
        }
        if let Some(ref ip) = updates.external_ip {
            aws.external_ip = Some(ip.clone());
        }
    }

    fn apply_gcp_resource_updates(&mut self, updates: &crate::plan::ResourceUpdates) {
        let gcp = self.resources.gcp.get_or_insert_with(GcpResources::default);
        if let Some(ref b) = updates.bucket {
            gcp.bucket = Some(b.clone());
        }
        if let Some(ref i) = updates.image {
            gcp.image = Some(i.clone());
        }
        if let Some(ref f) = updates.firewall_rule {
            gcp.firewall_rule = Some(f.clone());
        }
        if !updates.disks.is_empty() {
            gcp.disks.extend(updates.disks.iter().cloned());
        }
        if let Some(ref i) = updates.instance {
            gcp.instance = Some(i.clone());
        }
        if let Some(ref ip) = updates.external_ip {
            gcp.external_ip = Some(ip.clone());
        }
    }

    fn apply_azure_resource_updates(&mut self, updates: &crate::plan::ResourceUpdates) {
        let az = self
            .resources
            .azure
            .get_or_insert_with(AzureResources::default);
        if let Some(ref rg) = updates.resource_group {
            az.resource_group = Some(rg.clone());
        }
        if let Some(ref sa) = updates.storage_account {
            az.storage_account = Some(sa.clone());
        }
        if let Some(ref grg) = updates.gallery_rg {
            az.gallery_rg = Some(grg.clone());
        }
        if let Some(ref g) = updates.gallery {
            az.gallery = Some(g.clone());
        }
        if let Some(ref def) = updates.image_definition {
            az.image_definition = Some(def.clone());
        }
        if let Some(ref ver) = updates.image_version {
            az.image_version = Some(ver.clone());
        }
        if let Some(ref n) = updates.nsg {
            az.nsg = Some(n.clone());
        }
        if let Some(ref f) = updates.firewall_rule {
            az.nsg = Some(f.clone());
        }
        if !updates.disks.is_empty() {
            az.disks.extend(updates.disks.iter().cloned());
        }
        if let Some(ref i) = updates.instance {
            az.instance = Some(i.clone());
        }
        if let Some(ref ip) = updates.external_ip {
            az.external_ip = Some(ip.clone());
        }
    }
}

/// List all deployment states across all targets.
pub fn list_deployments(data_dir: &Path) -> Result<Vec<DeployState>, CloudError> {
    let base = deployments_dir(data_dir);
    if !base.is_dir() {
        return Ok(Vec::new());
    }
    let mut states = Vec::new();
    let targets = fs::read_dir(&base).map_err(|e| CloudError::IoPath {
        path: base.clone(),
        source: e,
    })?;
    for target_entry in targets.flatten() {
        if !target_entry.path().is_dir() {
            continue;
        }
        let target_name = target_entry.file_name().to_string_lossy().to_string();
        let entries = match fs::read_dir(target_entry.path()) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let instance_name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .strip_suffix(".state")
                .unwrap_or(path.file_stem().and_then(|s| s.to_str()).unwrap_or(""));
            match DeployState::load(data_dir, &target_name, instance_name) {
                Ok(state) => states.push(state),
                Err(e) => {
                    tracing::warn!("skipping corrupt state file {}: {e}", path.display());
                }
            }
        }
    }
    states.sort_by_key(|a| a.created_at);
    Ok(states)
}

/// Find a unique (target, instance) pair, or error on ambiguity.
pub fn find_instance(
    data_dir: &Path,
    instance: &str,
    target_filter: Option<&str>,
) -> Result<(String, String), CloudError> {
    if let Some(target) = target_filter {
        // Explicit target - just check it exists.
        let path = state_path(data_dir, target, instance);
        if path.exists() {
            return Ok((target.to_string(), instance.to_string()));
        }
        return Err(CloudError::StateNotFound {
            instance: format!("{target}/{instance}"),
        });
    }

    // Scan all targets for this instance name.
    let base = deployments_dir(data_dir);
    if !base.is_dir() {
        return Err(CloudError::StateNotFound {
            instance: instance.to_string(),
        });
    }
    let mut matches = Vec::new();
    if let Ok(targets) = fs::read_dir(&base) {
        for target_entry in targets.flatten() {
            if !target_entry.path().is_dir() {
                continue;
            }
            let target_name = target_entry.file_name().to_string_lossy().to_string();
            let path = state_path(data_dir, &target_name, instance);
            if path.exists() {
                matches.push(target_name);
            }
        }
    }

    match matches.len() {
        0 => Err(CloudError::StateNotFound {
            instance: instance.to_string(),
        }),
        1 => Ok((matches.into_iter().next().unwrap(), instance.to_string())),
        _ => Err(CloudError::AmbiguousInstance {
            instance: instance.to_string(),
            matches: matches.iter().map(|t| format!("{t}/{instance}")).collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn state_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "test-instance".into(),
            workload_name: "my-workload".into(),
            workload_version: "v0.0.1".into(),
            target_name: "prod-gcp".into(),
            provider_name: "gcp-test".into(),
            platform: PlatformKind::Gcp,
            image_ref: "automata-linux:v0.1.6".into(),
            archive_path: "/tmp/my-workload-v0.0.1.atawl".into(),
            archive_hash: "abc123".into(),
            init_env: PersistedInitEnv::default(),
            total_steps: 7,
        });
        state.resources.gcp = Some(GcpResources {
            project: "my-project".into(),
            zone: "us-central1-a".into(),
            ..Default::default()
        });
        state.save(dir.path()).unwrap();

        let loaded = DeployState::load(dir.path(), "prod-gcp", "test-instance").unwrap();
        assert_eq!(loaded.instance_name, "test-instance");
        assert_eq!(loaded.workload_name, "my-workload");
        assert_eq!(loaded.format, 1);
        assert!(matches!(
            loaded.status,
            DeployStatus::Deploying { step: 0, total: 7 }
        ));
    }

    #[test]
    fn list_empty() {
        let dir = TempDir::new().unwrap();
        let states = list_deployments(dir.path()).unwrap();
        assert!(states.is_empty());
    }

    #[test]
    fn find_instance_unique() {
        let dir = TempDir::new().unwrap();
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "web".into(),
            workload_name: "my-app".into(),
            workload_version: "v1".into(),
            target_name: "staging".into(),
            provider_name: "gcp-test".into(),
            platform: PlatformKind::Gcp,
            image_ref: "img:v1".into(),
            archive_path: "/tmp/a.atawl".into(),
            archive_hash: "hash".into(),
            init_env: PersistedInitEnv::default(),
            total_steps: 7,
        });
        state.save(dir.path()).unwrap();

        let (target, instance) = find_instance(dir.path(), "web", None).unwrap();
        assert_eq!(target, "staging");
        assert_eq!(instance, "web");
    }

    #[test]
    fn find_instance_ambiguous() {
        let dir = TempDir::new().unwrap();
        for target in &["staging", "prod"] {
            let mut state = DeployState::new(NewDeployParams {
                instance_name: "web".into(),
                workload_name: "app".into(),
                workload_version: "v1".into(),
                target_name: target.to_string(),
                provider_name: "gcp-test".into(),
                platform: PlatformKind::Gcp,
                image_ref: "img:v1".into(),
                archive_path: "/tmp/a.atawl".into(),
                archive_hash: "hash".into(),
                init_env: PersistedInitEnv::default(),
                total_steps: 7,
            });
            state.save(dir.path()).unwrap();
        }

        let err = find_instance(dir.path(), "web", None).unwrap_err();
        assert!(matches!(err, CloudError::AmbiguousInstance { .. }));
    }

    #[test]
    fn find_instance_with_target() {
        let dir = TempDir::new().unwrap();
        for target in &["staging", "prod"] {
            let mut state = DeployState::new(NewDeployParams {
                instance_name: "web".into(),
                workload_name: "app".into(),
                workload_version: "v1".into(),
                target_name: target.to_string(),
                provider_name: "gcp-test".into(),
                platform: PlatformKind::Gcp,
                image_ref: "img:v1".into(),
                archive_path: "/tmp/a.atawl".into(),
                archive_hash: "hash".into(),
                init_env: PersistedInitEnv::default(),
                total_steps: 7,
            });
            state.save(dir.path()).unwrap();
        }

        let (target, _) = find_instance(dir.path(), "web", Some("prod")).unwrap();
        assert_eq!(target, "prod");
    }

    #[test]
    fn delete_state() {
        let dir = TempDir::new().unwrap();
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "del-me".into(),
            workload_name: "app".into(),
            workload_version: "v1".into(),
            target_name: "staging".into(),
            provider_name: "gcp-test".into(),
            platform: PlatformKind::Gcp,
            image_ref: "img:v1".into(),
            archive_path: "/tmp/a.atawl".into(),
            archive_hash: "hash".into(),
            init_env: PersistedInitEnv::default(),
            total_steps: 7,
        });
        state.save(dir.path()).unwrap();

        DeployState::delete(dir.path(), "staging", "del-me").unwrap();
        assert!(DeployState::load(dir.path(), "staging", "del-me").is_err());
    }
}
