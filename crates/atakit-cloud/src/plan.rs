use std::fmt;

use serde::{Deserialize, Serialize};

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
        source_path: String,
    },
    OpenPorts {
        firewall_rule: String,
        ports: Vec<String>,
    },
    CreateDisks {
        disks: Vec<DiskSpec>,
    },
    CreateInstance {
        instance_name: String,
        machine_type: String,
        zone: String,
        image: String,
    },
    WaitForAgent {
        timeout_secs: u64,
    },
    InitializeWorkload {
        archive_path: String,
    },
}

/// Persistent disk specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSpec {
    pub name: String,
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
    DeleteInstance { name: String },
    DeleteDisks { names: Vec<String> },
    DeleteFirewall { name: String },
    DeleteImage { name: String },
    DeleteBucket { name: String },
}

/// Result from executing a deploy step, with resource updates.
pub struct StepResult {
    pub resource_updates: ResourceUpdates,
}

/// Resource names created or discovered during a step.
#[derive(Debug, Clone, Default)]
pub struct ResourceUpdates {
    pub bucket: Option<String>,
    pub image: Option<String>,
    pub firewall_rule: Option<String>,
    pub disks: Vec<String>,
    pub instance: Option<String>,
    pub external_ip: Option<String>,
}

impl fmt::Display for DeployStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeployStep::CheckDeps => write!(f, "Check cloud CLI dependencies"),
            DeployStep::UploadImage { image_name, .. } => {
                write!(f, "Upload base image '{image_name}'")
            }
            DeployStep::OpenPorts {
                firewall_rule,
                ports,
            } => {
                write!(f, "Open ports {} (rule: {firewall_rule})", ports.join(", "))
            }
            DeployStep::CreateDisks { disks } => {
                let names: Vec<_> = disks.iter().map(|d| d.name.as_str()).collect();
                write!(f, "Create persistent disks: {}", names.join(", "))
            }
            DeployStep::CreateInstance { instance_name, .. } => {
                write!(f, "Create VM instance '{instance_name}'")
            }
            DeployStep::WaitForAgent { timeout_secs } => {
                write!(f, "Wait for CVM agent (timeout: {timeout_secs}s)")
            }
            DeployStep::InitializeWorkload { .. } => {
                write!(f, "Initialize workload on CVM")
            }
        }
    }
}

impl fmt::Display for DestroyStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DestroyStep::DeleteInstance { name } => write!(f, "Delete VM instance '{name}'"),
            DestroyStep::DeleteDisks { names } => {
                write!(f, "Delete disks: {}", names.join(", "))
            }
            DestroyStep::DeleteFirewall { name } => write!(f, "Delete firewall rule '{name}'"),
            DestroyStep::DeleteImage { name } => write!(f, "Delete GCE image '{name}'"),
            DestroyStep::DeleteBucket { name } => write!(f, "Delete GCS bucket '{name}'"),
        }
    }
}
