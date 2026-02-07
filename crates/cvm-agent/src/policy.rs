use serde::Serialize;

// ---------------------------------------------------------------------------
// CVM Agent Policy (config/cvm_agent/cvm_agent_policy.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CvmAgentPolicy {
    pub cvm_config: CvmConfig,
    pub workload_config: WorkloadConfig,
}

#[derive(Debug, Serialize)]
pub struct CvmConfig {
    pub emulation_mode: EmulationMode,
    pub firewall: Firewall,
    pub https_server: HttpsServer,
    pub container_api: ContainerApi,
    pub maintenance_mode: MaintenanceMode,
    pub disk_config: DiskConfig,
}

#[derive(Debug, Serialize)]
pub struct EmulationMode {
    pub enable: bool,
    pub cloud_provider: String,
    pub tee_type: String,
    pub emulation_data_path: String,
    pub enable_emulation_data_update: bool,
}

#[derive(Debug, Serialize)]
pub struct Firewall {
    pub allowed_ports: Vec<PortSettings>,
    pub maintenance_mode_host_port: String,
}

#[derive(Debug, Serialize)]
pub struct PortSettings {
    pub name: String,
    pub protocol: String,
    pub port: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HttpsServer {
    pub enable_tls: bool,
    pub enable_auth: bool,
}

#[derive(Debug, Serialize)]
pub struct ContainerApi {
    pub container_engine: String,
    pub container_owner: String,
}

#[derive(Debug, Serialize)]
pub struct MaintenanceMode {
    pub allow: bool,
    pub signal: String,
}

#[derive(Debug, Serialize)]
pub struct DiskConfig {
    pub enable: bool,
    /// Multi-disk entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<DiskEntry>,
}

#[derive(Debug, Serialize)]
pub struct DiskEntry {
    pub serial: String,
    pub disk_mount_point: String,
    pub disk_encryption: DiskEncryptionConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskEncryptionConfig {
    pub enable: bool,
    pub encryption_key_security: String,
}

#[derive(Debug, Serialize)]
pub struct WorkloadConfig {
    pub services: ServicePolicy,
    pub image_signature_verification: ImgSigVerify,
}

#[derive(Debug, Serialize)]
pub struct ServicePolicy {
    pub allow_remove: bool,
    pub allow_add_new_service: bool,
    pub allow_update: Vec<String>,
    pub skip_measurement: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ImgSigVerify {
    pub enable: bool,
    pub auth_info_file_path: String,
    pub signature_verification_policy_path: String,
}

impl Default for CvmAgentPolicy {
    fn default() -> Self {
        Self {
            cvm_config: CvmConfig {
                emulation_mode: EmulationMode {
                    enable: false,
                    cloud_provider: "azure".into(),
                    tee_type: "snp".into(),
                    emulation_data_path: "./emulation_mode_data".into(),
                    enable_emulation_data_update: true,
                },
                firewall: Firewall {
                    allowed_ports: vec![
                        PortSettings {
                            name: "allow_agent_local".into(),
                            protocol: "tcp".into(),
                            port: "7999".into(),
                            direction: None,
                        },
                        PortSettings {
                            name: "allow_agent_external".into(),
                            protocol: "tcp".into(),
                            port: "8000".into(),
                            direction: None,
                        },
                    ],
                    maintenance_mode_host_port: "2222".into(),
                },
                https_server: HttpsServer {
                    enable_tls: true,
                    enable_auth: true,
                },
                container_api: ContainerApi {
                    container_engine: "podman".into(),
                    container_owner: "automata".into(),
                },
                maintenance_mode: MaintenanceMode {
                    allow: false,
                    signal: "SIGUSR2".into(),
                },
                disk_config: DiskConfig {
                    enable: false,
                    disks: vec![],
                },
            },
            workload_config: WorkloadConfig {
                services: ServicePolicy {
                    allow_remove: false,
                    allow_add_new_service: false,
                    allow_update: vec![],
                    skip_measurement: vec![],
                },
                image_signature_verification: ImgSigVerify {
                    enable: false,
                    auth_info_file_path: "/data/workload/secrets/auth_info.json".into(),
                    signature_verification_policy_path:
                        "/data/workload/config/cvm_agent/sample_image_verify_policy.json".into(),
                },
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Input types for building policy from structured data
// ---------------------------------------------------------------------------

/// A parsed port mapping for firewall policy generation.
pub struct PortInput {
    pub service: String,
    pub host_port: u16,
    pub protocol: String,
}

/// A disk configuration input, decoupled from atakit config types.
pub struct DiskInput {
    pub serial: String,
    pub mount_point: String,
    pub encryption_enabled: bool,
    pub encryption_key_security: String,
}

impl CvmAgentPolicy {
    /// Append firewall rules from structured port inputs.
    pub fn with_ports(mut self, ports: &[PortInput]) -> Self {
        for p in ports {
            self.cvm_config.firewall.allowed_ports.push(PortSettings {
                name: format!("allow_{}_{}", p.service, p.host_port),
                protocol: p.protocol.clone(),
                port: p.host_port.to_string(),
                direction: None,
            });
        }
        self
    }

    /// Add a disk entry to the CVM agent policy.
    pub fn with_disk(mut self, disk: DiskInput) -> Self {
        self.cvm_config.disk_config.enable = true;
        self.cvm_config.disk_config.disks.push(DiskEntry {
            serial: disk.serial,
            disk_mount_point: disk.mount_point,
            disk_encryption: DiskEncryptionConfig {
                enable: disk.encryption_enabled,
                encryption_key_security: disk.encryption_key_security,
            },
        });
        self
    }
}
