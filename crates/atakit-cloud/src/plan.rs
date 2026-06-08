use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::CcType;

/// Group `"port/proto"` entries by port number, sorted numerically.
fn group_ports(ports: &[String]) -> Vec<(u16, Vec<&str>)> {
    let mut by_port: BTreeMap<u16, Vec<&str>> = BTreeMap::new();
    for entry in ports {
        let (port_str, proto) = entry.split_once('/').unwrap_or((entry, "tcp"));
        if let Ok(port) = port_str.parse::<u16>() {
            by_port.entry(port).or_default().push(proto);
        }
    }
    by_port.into_iter().collect()
}

/// Compact inline format: `"1024/tcp, 3000, 2222"`.
pub fn format_ports_inline(ports: &[String]) -> String {
    let mut parts = Vec::new();
    for (port, protos) in group_ports(ports) {
        if protos.contains(&"tcp") && protos.contains(&"udp") {
            parts.push(port.to_string());
        } else {
            for proto in protos {
                parts.push(format!("{port}/{proto}"));
            }
        }
    }
    parts.join(", ")
}

/// Grouped bullet list, one port per line with protocols in parens.
///
/// Returns lines like `"- 1024 (tcp)"`, `"- 3000 (tcp, udp)"`.
/// Caller handles the indent prefix.
pub fn format_ports_list(ports: &[String]) -> Vec<String> {
    group_ports(ports)
        .into_iter()
        .map(|(port, protos)| format!("- {port} ({})", protos.join(", ")))
        .collect()
}

/// A deployment execution plan.
pub struct DeployPlan {
    pub steps: Vec<DeployStep>,
}

/// Individual deployment step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeployStep {
    CheckDeps,
    UploadImage {
        bucket: String,
        image_name: String,
        /// Local file to upload. `None` means the image is assumed to already
        /// exist in GCE -- the step verifies existence but skips upload.
        source_path: Option<String>,
        /// Local secure-boot cert directory (containing PK.crt / KEK.crt /
        /// db.crt / kernel.crt). When set, the certs are passed to
        /// `gcloud compute images create` so the resulting image carries
        /// custom Secure Boot variables instead of GCE's placeholder PK.
        certs_dir: Option<String>,
        /// CC capabilities to register on the image. Multiple types produce a
        /// GCE image usable with either CC mode.
        cc_types: Vec<CcType>,
        /// Delete and re-register the image even if it already exists.
        force: bool,
    },
    OpenPorts {
        firewall_rule: String,
        ports: Vec<String>,
    },
    CreateDisks {
        disks: Vec<DiskSpec>,
        /// Resource group the disks live in. `None` for providers without
        /// resource groups (GCP); `Some` for Azure.
        resource_group: Option<String>,
    },
    CreateInstance {
        instance_name: String,
        machine_type: String,
        zone: String,
        image: String,
        cc_type: CcType,
        metadata: Vec<(String, String)>,
        disks: Vec<DiskSpec>,
        boot_disk_size_gb: Option<u64>,
    },
    WaitForPortal {
        timeout_secs: u64,
    },
    InitializeWorkload {
        archive_path: String,
    },
    // Azure-specific steps.
    CreateResourceGroup {
        name: String,
        region: String,
    },
    UploadImageAzure {
        resource_group: String,
        storage_account: String,
        gallery_rg: String,
        gallery: String,
        image_definition: String,
        image_version: String,
        source_path: Option<String>,
        certs_dir: Option<String>,
        cc_types: Vec<CcType>,
        force: bool,
    },
    CreateInstanceAzure {
        instance_name: String,
        vm_size: String,
        image_id: String,
        /// Original image ref (e.g. "automata-linux:v0.1.6") for resource naming.
        image_ref: String,
        cc_type: CcType,
        resource_group: String,
        nsg: String,
        metadata: Vec<(String, String)>,
        disks: Vec<DiskSpec>,
        boot_disk_size_gb: Option<u64>,
    },
    // AWS-specific steps.
    UploadImageAws {
        bucket: String,
        /// AMI name registered for the imported snapshot.
        image_name: String,
        /// Local VMDK file to upload. `None` means the AMI is assumed to
        /// already exist -- the step verifies existence but skips upload.
        source_path: Option<String>,
        /// Local secure-boot directory containing `aws-uefi-blob.bin`. The
        /// blob seeds the AMI's UEFI variables via `register-image
        /// --uefi-data`. atakit requires Secure Boot on every CVM deploy.
        certs_dir: Option<String>,
        /// Delete and re-register the AMI even if it already exists.
        force: bool,
    },
    CreateInstanceAws {
        instance_name: String,
        instance_type: String,
        /// AMI name; the AMI id is resolved by name at execution time.
        image_name: String,
        security_group: String,
        metadata: Vec<(String, String)>,
        disks: Vec<DiskSpec>,
        boot_disk_size_gb: Option<u64>,
    },
    // QEMU-specific steps.
    /// Provision a local QEMU instance: create the boot-disk qcow2 overlay,
    /// create one qcow2 per data disk, start swtpm with `--terminate`,
    /// allocate free host ports for the portal forwards (+ optional ssh), and
    /// spawn `qemu-system-x86_64` detached. Returns external_ip = 127.0.0.1
    /// plus the recorded pid, instance dir, and host-port mapping.
    StartLocalVm {
        instance_dir: String,
        base_disk: String,
        boot_overlay: String,
        boot_disk_size_gb: Option<u64>,
        ovmf_path: String,
        data_disks: Vec<DiskSpec>,
        metadata: Vec<(String, String)>,
        /// Workload-declared `"port/proto"` entries. TCP entries are forwarded
        /// guest→same-host-port for predictability; non-tcp entries are
        /// ignored (qemu user-mode networking has no UDP hostfwd in practice).
        workload_ports: Vec<String>,
    },
}

/// Persistent disk specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSpec {
    /// Cloud disk resource name (e.g. `{instance}-{disk_name}`).
    pub name: String,
    /// Manifest disk name, used as device-name/serial for CVM agent discovery.
    pub device_name: String,
    /// LUN / device index for cloud attachment.
    pub index: u32,
    pub size_gb: u64,
    pub disk_type: String,
}

/// A destroy execution plan.
pub struct DestroyPlan {
    pub steps: Vec<DestroyStep>,
}

/// Individual destroy step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DestroyStep {
    DeleteInstance {
        name: String,
    },
    DeleteDisks {
        names: Vec<String>,
        /// Resource group the disks live in. `None` for providers without
        /// resource groups (GCP); `Some` for Azure.
        resource_group: Option<String>,
    },
    DeleteFirewall {
        name: String,
    },
    DeleteImage {
        name: String,
    },
    DeleteBucket {
        name: String,
    },
    // Azure-specific destroy steps.
    DeleteResourceGroup {
        name: String,
    },
    DeleteImageVersion {
        gallery_rg: String,
        gallery: String,
        image_definition: String,
        image_version: String,
    },
    DeleteImageDefinition {
        gallery_rg: String,
        gallery: String,
        image_definition: String,
    },
    // AWS-specific destroy steps.
    DeleteSecurityGroup {
        name: String,
    },
    /// Deregister the AMI and delete its backing snapshots.
    DeleteAmi {
        name: String,
    },
    DeleteS3Bucket {
        name: String,
    },
    // QEMU-specific destroy steps.
    /// Stop the running qemu process (SIGTERM, then SIGKILL on grace timeout).
    /// swtpm self-terminates with the VM when launched with `--terminate`.
    StopLocalVm {
        pid: u32,
    },
    /// Remove the per-instance directory (overlays + serial log + swtpm state).
    RemoveLocalInstanceDir {
        path: String,
    },
}

/// Result from executing a deploy step, with resource updates.
pub struct StepResult {
    pub resource_updates: ResourceUpdates,
}

/// Resource names created or discovered during a step.
#[derive(Debug, Clone, Default)]
pub struct ResourceUpdates {
    // GCP fields.
    pub bucket: Option<String>,
    pub image: Option<String>,
    pub firewall_rule: Option<String>,
    pub disks: Vec<String>,
    pub instance: Option<String>,
    pub external_ip: Option<String>,
    // Azure fields.
    pub resource_group: Option<String>,
    pub storage_account: Option<String>,
    pub gallery_rg: Option<String>,
    pub gallery: Option<String>,
    pub image_definition: Option<String>,
    pub image_version: Option<String>,
    pub nsg: Option<String>,
    // AWS fields.
    pub snapshot: Option<String>,
    // QEMU fields.
    pub qemu_pid: Option<u32>,
    pub qemu_instance_dir: Option<String>,
    pub qemu_base_disk: Option<String>,
    pub qemu_boot_overlay: Option<String>,
    pub qemu_host_status_port: Option<u16>,
    pub qemu_host_init_port: Option<u16>,
    /// Path to the unix-socket chardev that `-serial chardev:ser` is wired to.
    /// `cloud ssh` socats into this for an interactive console.
    pub qemu_serial_sock: Option<String>,
    /// Guest port → host port for workload-declared TCP ports.
    pub qemu_workload_port_map: BTreeMap<u16, u16>,
}

impl fmt::Display for DeployStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeployStep::CheckDeps => write!(f, "Check cloud CLI dependencies"),
            DeployStep::UploadImage {
                image_name,
                source_path,
                ..
            } => {
                if source_path.is_some() {
                    write!(f, "Upload base image '{image_name}'")
                } else {
                    write!(f, "Verify base image '{image_name}'")
                }
            }
            DeployStep::OpenPorts {
                firewall_rule,
                ports,
            } => {
                write!(
                    f,
                    "Open ports {} (rule: {firewall_rule})",
                    format_ports_inline(ports)
                )
            }
            DeployStep::CreateDisks { disks, .. } => {
                let names: Vec<_> = disks.iter().map(|d| d.name.as_str()).collect();
                write!(f, "Create persistent disks: {}", names.join(", "))
            }
            DeployStep::CreateInstance { instance_name, .. } => {
                write!(f, "Create VM instance '{instance_name}'")
            }
            DeployStep::WaitForPortal { timeout_secs } => {
                write!(f, "Wait for portal (timeout: {timeout_secs}s)")
            }
            DeployStep::InitializeWorkload { .. } => {
                write!(f, "Initialize workload on CVM")
            }
            DeployStep::CreateResourceGroup { name, .. } => {
                write!(f, "Create resource group '{name}'")
            }
            DeployStep::UploadImageAzure {
                image_definition,
                source_path,
                ..
            } => {
                if source_path.is_some() {
                    write!(f, "Upload base image '{image_definition}'")
                } else {
                    write!(f, "Verify base image '{image_definition}'")
                }
            }
            DeployStep::CreateInstanceAzure { instance_name, .. } => {
                write!(f, "Create VM instance '{instance_name}'")
            }
            DeployStep::UploadImageAws {
                image_name,
                source_path,
                ..
            } => {
                if source_path.is_some() {
                    write!(f, "Upload base image '{image_name}'")
                } else {
                    write!(f, "Verify base image '{image_name}'")
                }
            }
            DeployStep::CreateInstanceAws { instance_name, .. } => {
                write!(f, "Create VM instance '{instance_name}'")
            }
            DeployStep::StartLocalVm { data_disks, .. } => {
                if data_disks.is_empty() {
                    write!(f, "Start local QEMU VM")
                } else {
                    write!(f, "Start local QEMU VM ({} data disk(s))", data_disks.len())
                }
            }
        }
    }
}

impl fmt::Display for DestroyStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DestroyStep::DeleteInstance { name } => write!(f, "Delete VM instance '{name}'"),
            DestroyStep::DeleteDisks { names, .. } => {
                write!(f, "Delete disks: {}", names.join(", "))
            }
            DestroyStep::DeleteFirewall { name } => write!(f, "Delete firewall rule '{name}'"),
            DestroyStep::DeleteImage { name } => write!(f, "Delete GCE image '{name}'"),
            DestroyStep::DeleteBucket { name } => write!(f, "Delete GCS bucket '{name}'"),
            DestroyStep::DeleteResourceGroup { name } => {
                write!(f, "Delete resource group '{name}'")
            }
            DestroyStep::DeleteImageVersion {
                image_definition,
                image_version,
                ..
            } => write!(
                f,
                "Delete image version '{image_definition}:{image_version}'"
            ),
            DestroyStep::DeleteImageDefinition {
                image_definition, ..
            } => write!(f, "Delete image definition '{image_definition}'"),
            DestroyStep::DeleteSecurityGroup { name } => {
                write!(f, "Delete security group '{name}'")
            }
            DestroyStep::DeleteAmi { name } => write!(f, "Delete AMI '{name}'"),
            DestroyStep::DeleteS3Bucket { name } => write!(f, "Delete S3 bucket '{name}'"),
            DestroyStep::StopLocalVm { pid } => write!(f, "Stop local QEMU VM (pid {pid})"),
            DestroyStep::RemoveLocalInstanceDir { path } => {
                write!(f, "Remove instance directory '{path}'")
            }
        }
    }
}
