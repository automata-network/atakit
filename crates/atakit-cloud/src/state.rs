use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::PlatformKind;
use crate::error::CloudError;

/// Format 3 records the workload publisher. Format 2 cannot be migrated: the
/// publisher is not derivable from a name and version, and it is now an input
/// to the workload identifier, so a format 2 deployment cannot be resolved to a
/// registered workload at all.
const FORMAT_VERSION: u32 = 3;
pub const DEFAULT_PORTAL_INIT_PORT: u16 = 1024;
pub const DEFAULT_PORTAL_STATUS_PORT: u16 = 2024;

/// Guest-facing portal ports used by cloud deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalPorts {
    pub status: u16,
    pub init: u16,
}

impl PortalPorts {
    pub fn firewall_entries(self) -> Vec<String> {
        vec![format!("{}/tcp", self.status), format!("{}/tcp", self.init)]
    }

    pub fn is_default_portal_entry(entry: &str) -> bool {
        matches!(entry, "2024/tcp" | "1024/tcp")
    }
}

impl Default for PortalPorts {
    fn default() -> Self {
        Self {
            status: DEFAULT_PORTAL_STATUS_PORT,
            init: DEFAULT_PORTAL_INIT_PORT,
        }
    }
}

/// Persistent deployment state stored as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployState {
    /// Launch-time choice, retained after the private credential is removed.
    #[serde(default)]
    pub init_auth_required: Option<bool>,
    #[serde(default)]
    pub init_auth_key_file: Option<String>,
    pub format: u32,
    pub instance_name: String,
    /// Owner fingerprint of the workload's publisher. Stored rather than the
    /// derived identifier so the state still shows a readable reference and can
    /// recompute the identifier, instead of holding an opaque hash whose
    /// provenance cannot be checked.
    pub workload_publisher: String,
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
    /// Provider image selector used to create and manage cloud resources.
    pub image_ref: String,
    /// Canonical base-image identity used only as an optional verifier subject
    /// default. It is never a collateral or policy trust source.
    pub base_image_ref: Option<String>,
    pub archive_path: String,
    pub archive_hash: String,
    pub init_env: PersistedInitEnv,
    #[serde(default)]
    pub portal_ports: PortalPorts,
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
#[serde(deny_unknown_fields)]
pub struct PersistedInitEnv {
    pub chain: String,
    pub owner_key: String,
    pub gas_wallet: String,
    /// Optional prover credential key name.
    #[serde(default)]
    pub prover_credential: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qemu: Option<QemuResources>,
}

/// Local QEMU-specific resource tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QemuResources {
    /// Per-instance directory (overlays + serial log + swtpm state).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instance_dir: String,
    /// PID of the running `qemu-system-x86_64` process. 0 until the
    /// `StartLocalVm` step records it.
    #[serde(default)]
    pub pid: u32,
    /// Absolute path to the qcow2 image the boot overlay is backed by
    /// (typically `<image_store>/.../qemu_disk.qcow2`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_disk: String,
    /// Absolute path to the per-instance boot overlay (qcow2).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub boot_overlay: String,
    /// Absolute paths of per-instance data-disk qcow2 files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_disks: Vec<String>,
    /// Host port forwarded to guest port 2024 (portal status endpoint).
    #[serde(default)]
    pub host_status_port: u16,
    /// Host port forwarded to guest port 1024 (portal init endpoint).
    #[serde(default)]
    pub host_init_port: u16,
    /// Path to the unix-socket chardev that `-serial chardev:ser` is wired
    /// to. `cloud ssh` socats into this for an interactive serial console;
    /// `cloud serial` keeps tailing the chardev's `logfile=` (`serial.log`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub serial_sock: String,
    /// Guest port → host port for workload-declared TCP ports.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub workload_port_map: BTreeMap<u16, u16>,
    /// Address the operator can reach the VM at — always `127.0.0.1` for
    /// QEMU; stored explicitly so `status` / `list` can read it uniformly
    /// with the cloud platforms.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub external_ip: String,
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
    /// Owner fingerprint of the workload's publisher. Stored rather than the
    /// derived identifier so the state still shows a readable reference and can
    /// recompute the identifier, instead of holding an opaque hash whose
    /// provenance cannot be checked.
    pub workload_publisher: String,
    pub workload_name: String,
    pub workload_version: String,
    pub target_name: String,
    pub provider_name: String,
    pub platform: PlatformKind,
    pub image_ref: String,
    pub base_image_ref: Option<String>,
    pub archive_path: String,
    pub archive_hash: String,
    pub init_env: PersistedInitEnv,
    pub portal_ports: PortalPorts,
    /// Total number of steps in the deployment plan.
    pub total_steps: u32,
}

impl DeployState {
    /// Saved launch mode, not a live query of the portal.
    pub fn init_auth_mode(&self) -> &'static str {
        match self.init_auth_required {
            Some(true) => "authenticated",
            Some(false) => "unsigned",
            None if self.init_auth_key_file.is_some() => "authenticated",
            None => "unknown (not recorded)",
        }
    }

    /// Create a new deploy state in "deploying" status.
    pub fn new(params: NewDeployParams) -> Self {
        let now = Utc::now();
        Self {
            init_auth_required: None,
            init_auth_key_file: None,
            format: FORMAT_VERSION,
            instance_name: params.instance_name,
            workload_publisher: params.workload_publisher,
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
            base_image_ref: params.base_image_ref,
            archive_path: params.archive_path,
            archive_hash: params.archive_hash,
            init_env: params.init_env,
            portal_ports: params.portal_ports,
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
        decode_deploy_state(&content, &path)
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
        write_state_file(&path, self)
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
        // Route to the correct platform resource set. Qemu is checked first
        // because cloud arms use the {gcp,azure,aws} fields, all of which are
        // None on qemu deployments.
        if self.resources.qemu.is_some() {
            self.apply_qemu_resource_updates(updates);
        } else if self.resources.azure.is_some() {
            self.apply_azure_resource_updates(updates);
        } else if self.resources.aws.is_some() {
            self.apply_aws_resource_updates(updates);
        } else {
            self.apply_gcp_resource_updates(updates);
        }
    }

    fn apply_qemu_resource_updates(&mut self, updates: &crate::plan::ResourceUpdates) {
        let q = self
            .resources
            .qemu
            .get_or_insert_with(QemuResources::default);
        if let Some(ref dir) = updates.qemu_instance_dir {
            q.instance_dir = dir.clone();
        }
        if let Some(pid) = updates.qemu_pid {
            q.pid = pid;
        }
        if let Some(ref p) = updates.qemu_base_disk {
            q.base_disk = p.clone();
        }
        if let Some(ref p) = updates.qemu_boot_overlay {
            q.boot_overlay = p.clone();
        }
        if !updates.disks.is_empty() {
            q.data_disks.extend(updates.disks.iter().cloned());
        }
        if let Some(p) = updates.qemu_host_status_port {
            q.host_status_port = p;
        }
        if let Some(p) = updates.qemu_host_init_port {
            q.host_init_port = p;
        }
        if let Some(ref s) = updates.qemu_serial_sock {
            q.serial_sock = s.clone();
        }
        if !updates.qemu_workload_port_map.is_empty() {
            for (g, h) in &updates.qemu_workload_port_map {
                q.workload_port_map.insert(*g, *h);
            }
        }
        if let Some(ref ip) = updates.external_ip {
            q.external_ip = ip.clone();
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

fn decode_deploy_state(content: &str, path: &Path) -> Result<DeployState, CloudError> {
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|e| CloudError::State {
            message: format!("failed to parse {}: {e}", path.display()),
        })?;
    let format = value
        .get("format")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| CloudError::State {
            message: format!(
                "failed to parse {}: missing or invalid format",
                path.display()
            ),
        })?;
    let format = u32::try_from(format).map_err(|_| CloudError::State {
        message: format!(
            "failed to parse {}: unsupported format {format}",
            path.display()
        ),
    })?;

    // No format below the current one can be migrated. The publisher is an
    // input to the workload identifier and is not derivable from a name and
    // version, so an older deployment cannot be resolved to a registered
    // workload at all. Migration would have to invent the value it is missing.
    if format != FORMAT_VERSION {
        return Err(CloudError::State {
            message: format!(
                "failed to parse {}: format {format} predates publisher-qualified workload \
                 identifiers and cannot be migrated, because the publisher is not derivable from \
                 a name and version. Redeploy the instance.",
                path.display()
            ),
        });
    }

    let state: DeployState = serde_json::from_value(value).map_err(|e| CloudError::State {
        message: format!("failed to parse {}: {e}", path.display()),
    })?;
    Ok(state)
}

fn write_state_file(path: &Path, state: &DeployState) -> Result<(), CloudError> {
    let json = serde_json::to_string_pretty(state)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &json).map_err(|e| CloudError::IoPath {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| CloudError::IoPath {
        path: path.to_path_buf(),
        source: e,
    })
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

    fn test_state() -> DeployState {
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "test-instance".into(),
            workload_publisher:
                "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f".to_string(),
            workload_name: "my-workload".into(),
            workload_version: "v0.0.1".into(),
            target_name: "prod-gcp".into(),
            provider_name: "gcp-test".into(),
            platform: PlatformKind::Gcp,
            image_ref: "automata-linux:v0.1.6".into(),
            base_image_ref: Some("automata-linux:v0.1.6".into()),
            archive_path: "/tmp/my-workload-v0.0.1.atawl".into(),
            archive_hash: "abc123".into(),
            init_env: PersistedInitEnv::default(),
            portal_ports: PortalPorts::default(),
            total_steps: 7,
        });
        state.resources.gcp = Some(GcpResources {
            project: "my-project".into(),
            zone: "us-central1-a".into(),
            firewall_rule: Some("test-instance-ingress".into()),
            disks: vec!["test-instance-data".into()],
            instance: Some("test-instance".into()),
            external_ip: Some("192.0.2.10".into()),
            ..Default::default()
        });
        state
    }

    fn format_1_value(sp1_payer: serde_json::Value) -> serde_json::Value {
        let mut value = serde_json::to_value(test_state()).unwrap();
        value["format"] = serde_json::json!(1);
        let init_env = value["init_env"].as_object_mut().unwrap();
        init_env.remove("prover_credential");
        init_env.insert("sp1_payer".into(), sp1_payer);
        value
    }

    fn write_state_value(dir: &Path, value: &serde_json::Value) -> PathBuf {
        let path = state_path(dir, "prod-gcp", "test-instance");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path
    }

    #[test]
    fn init_auth_mode_survives_credential_removal_and_serialization() {
        let mut state = test_state();
        assert_eq!(state.init_auth_mode(), "unknown (not recorded)");
        state.init_auth_key_file = Some("credential.json".into());
        assert_eq!(state.init_auth_mode(), "authenticated");
        state.init_auth_required = Some(true);
        state.init_auth_key_file = None;
        let encoded = serde_json::to_string(&state).unwrap();
        let mut decoded: DeployState = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.init_auth_mode(), "authenticated");
        decoded.init_auth_required = Some(false);
        assert_eq!(decoded.init_auth_mode(), "unsigned");
        let mut legacy = serde_json::to_value(&decoded).unwrap();
        legacy.as_object_mut().unwrap().remove("init_auth_required");
        let decoded: DeployState = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.init_auth_mode(), "unknown (not recorded)");
    }

    #[test]
    fn state_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut state = test_state();
        state.image_ref = "automata-linux:v0.1.6-provider-alias".into();
        state.base_image_ref = Some("automata-linux:v0.1.6".into());
        state.save(dir.path()).unwrap();

        let loaded = DeployState::load(dir.path(), "prod-gcp", "test-instance").unwrap();
        assert_eq!(loaded.instance_name, "test-instance");
        assert_eq!(loaded.workload_name, "my-workload");
        assert_eq!(loaded.format, FORMAT_VERSION);
        assert!(matches!(
            loaded.status,
            DeployStatus::Deploying { step: 0, total: 7 }
        ));
        assert_eq!(loaded.image_ref, "automata-linux:v0.1.6-provider-alias");
        assert_eq!(
            loaded.base_image_ref.as_deref(),
            Some("automata-linux:v0.1.6")
        );
    }

    #[test]
    fn persisted_init_environment_rejects_sp1_payer() {
        let error = serde_json::from_value::<PersistedInitEnv>(serde_json::json!({
            "chain": "hoodi",
            "owner_key": "owner",
            "gas_wallet": "gas",
            "sp1_payer": "prover"
        }))
        .unwrap_err();
        assert!(error.to_string().contains("sp1_payer"));
    }

    /// Formats below the current one are refused, not migrated.
    ///
    /// The publisher is an input to the workload identifier and is not
    /// derivable from a name and version, so an older deployment cannot be
    /// resolved to a registered workload. Migration would have to invent the
    /// value it lacks, and a deployment silently pointing at the wrong
    /// workload is worse than one that refuses to load.
    #[test]
    fn older_formats_are_refused_with_a_reason_and_a_remedy() {
        for older in [1, 2] {
            let dir = TempDir::new().unwrap();
            let mut value = format_1_value(serde_json::Value::Null);
            value["format"] = serde_json::json!(older);
            let path = write_state_value(dir.path(), &value);

            let error = DeployState::load(dir.path(), "prod-gcp", "test-instance")
                .expect_err("an older format must not load");
            let message = error.to_string();
            assert!(
                message.contains(&format!("format {older}")),
                "the failure must name the format; got {message}"
            );
            assert!(
                message.contains("publisher"),
                "the failure must say why it cannot be migrated; got {message}"
            );
            assert!(
                message.contains("Redeploy"),
                "the failure must say what to do; got {message}"
            );
            assert!(path.exists(), "a refused load must not remove the file");
        }
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
            workload_publisher:
                "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f".to_string(),
            workload_name: "my-app".into(),
            workload_version: "v1".into(),
            target_name: "staging".into(),
            provider_name: "gcp-test".into(),
            platform: PlatformKind::Gcp,
            image_ref: "img:v1".into(),
            base_image_ref: Some("img:v1".into()),
            archive_path: "/tmp/a.atawl".into(),
            archive_hash: "hash".into(),
            init_env: PersistedInitEnv::default(),
            portal_ports: PortalPorts::default(),
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
                workload_publisher:
                    "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f".to_string(),
                workload_name: "app".into(),
                workload_version: "v1".into(),
                target_name: target.to_string(),
                provider_name: "gcp-test".into(),
                platform: PlatformKind::Gcp,
                image_ref: "img:v1".into(),
                base_image_ref: Some("img:v1".into()),
                archive_path: "/tmp/a.atawl".into(),
                archive_hash: "hash".into(),
                init_env: PersistedInitEnv::default(),
                portal_ports: PortalPorts::default(),
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
                workload_publisher:
                    "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f".to_string(),
                workload_name: "app".into(),
                workload_version: "v1".into(),
                target_name: target.to_string(),
                provider_name: "gcp-test".into(),
                platform: PlatformKind::Gcp,
                image_ref: "img:v1".into(),
                base_image_ref: Some("img:v1".into()),
                archive_path: "/tmp/a.atawl".into(),
                archive_hash: "hash".into(),
                init_env: PersistedInitEnv::default(),
                portal_ports: PortalPorts::default(),
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
            workload_publisher:
                "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f".to_string(),
            workload_name: "app".into(),
            workload_version: "v1".into(),
            target_name: "staging".into(),
            provider_name: "gcp-test".into(),
            platform: PlatformKind::Gcp,
            image_ref: "img:v1".into(),
            base_image_ref: Some("img:v1".into()),
            archive_path: "/tmp/a.atawl".into(),
            archive_hash: "hash".into(),
            init_env: PersistedInitEnv::default(),
            portal_ports: PortalPorts::default(),
            total_steps: 7,
        });
        state.save(dir.path()).unwrap();

        DeployState::delete(dir.path(), "staging", "del-me").unwrap();
        assert!(DeployState::load(dir.path(), "staging", "del-me").is_err());
    }
}
