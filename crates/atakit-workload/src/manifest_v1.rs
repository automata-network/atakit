//! V1 manifest deserialization for backward-compatible reading of old archives.
//!
//! These types mirror the format-1 `manifest.toml` layout. They are
//! Deserialize-only; new archives always use format 2 (canonical JSON).

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::manifest::{
    Manifest, ManifestBabyContainer, ManifestConfig, ManifestDependency, ManifestDisk,
    ManifestDiskEncryption, ManifestFirewallPort, ManifestMeta, StringOrArrayOut,
};

fn default_restart_v1() -> String {
    "no".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ManifestV1 {
    pub meta: ManifestMetaV1,
    pub config: ManifestConfigV1,
    #[serde(default)]
    pub disks: BTreeMap<String, ManifestDiskV1>,
    pub hashes: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestMetaV1 {
    pub format: u32,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct ManifestConfigV1 {
    pub image: String,
    #[serde(rename = "base-image-mode")]
    pub base_image_mode: String,
    #[serde(default, rename = "base-image")]
    pub base_image: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default = "default_restart_v1")]
    pub restart: String,
    #[serde(default)]
    pub command: Option<StringOrArrayOut>,
    #[serde(default)]
    pub entrypoint: Option<StringOrArrayOut>,
    #[serde(default)]
    pub ttl: u64,
    #[serde(default)]
    pub cvm_agent: bool,
    #[serde(default, rename = "measured-data")]
    pub measured_data: Vec<String>,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub disks: BTreeMap<String, String>,
    #[serde(default)]
    pub dependencies: Option<BTreeMap<String, ManifestDependencyV1>>,
    #[serde(default, rename = "firewall-ports")]
    pub firewall_ports: Vec<ManifestFirewallPort>,
    #[serde(default, rename = "baby-container")]
    pub baby_container: Option<ManifestBabyContainer>,
    #[serde(default, rename = "boot-disk-size")]
    pub boot_disk_size: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestDependencyV1 {
    pub image: String,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default = "default_restart_v1")]
    pub restart: String,
    #[serde(default)]
    pub command: Option<StringOrArrayOut>,
    #[serde(default)]
    pub entrypoint: Option<StringOrArrayOut>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default, rename = "measured-data")]
    pub measured_data: Vec<String>,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: Vec<String>,
    #[serde(default)]
    pub disks: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestDiskV1 {
    pub index: u32,
    pub size: String,
    #[serde(default)]
    pub bind_fs: bool,
    #[serde(default)]
    pub encryption: Option<ManifestDiskEncryptionV1>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestDiskEncryptionV1 {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub key_security: String,
}

/// Convert a v1 manifest to the current (v2) Manifest struct.
pub fn convert_to_current(v1: ManifestV1) -> Manifest {
    let workload_name = v1.meta.name.clone();

    let dependencies = v1.config.dependencies.map(|deps| {
        deps.into_iter()
            .map(|(name, dep)| {
                let has_measured = !dep.measured_data.is_empty();
                let has_unmeasured = !dep.unmeasured_data.is_empty();
                (
                    name,
                    ManifestDependency {
                        image: dep.image,
                        ports: dep.ports,
                        restart: dep.restart,
                        command: dep.command,
                        entrypoint: dep.entrypoint,
                        atakit_portal: false,
                        gid_group: workload_name.clone(),
                        environment: dep.environment,
                        depends_on: dep.depends_on,
                        measured_data: has_measured,
                        unmeasured_data: has_unmeasured,
                        disks: dep.disks,
                        cap_add: Vec::new(),
                        cap_drop: Vec::new(),
                    },
                )
            })
            .collect()
    });

    let disks = v1
        .disks
        .into_iter()
        .map(|(name, d)| {
            let encryption = d.encryption.and_then(|e| convert_encryption_v1(&e));
            // v1 `bind_fs` is dropped: removed in format 2 (manual --uidmap/--gidmap
            // plus the shared GID scheme makes bindfs redundant).
            let _ = d.bind_fs;
            (
                name,
                ManifestDisk {
                    index: d.index,
                    size: d.size,
                    encryption,
                },
            )
        })
        .collect();

    Manifest {
        meta: ManifestMeta {
            format: v1.meta.format,
            name: v1.meta.name,
            version: v1.meta.version,
        },
        config: ManifestConfig {
            image: v1.config.image,
            base_image_mode: v1.config.base_image_mode,
            base_image: v1.config.base_image,
            ports: v1.config.ports,
            restart: v1.config.restart,
            command: v1.config.command,
            entrypoint: v1.config.entrypoint,
            session_ttl: v1.config.ttl,
            atakit_portal: v1.config.cvm_agent,
            gid_group: workload_name,
            measured_data: !v1.config.measured_data.is_empty(),
            unmeasured_data: !v1.config.unmeasured_data.is_empty(),
            environment: v1.config.environment,
            disks: v1.config.disks,
            dependencies,
            firewall_ports: {
                // Inject always-allowed portal ports so v1 manifests
                // get the same firewall behavior as v2 manifests.
                use std::collections::HashSet;
                let mut open: HashSet<(u16, String)> = v1
                    .config
                    .firewall_ports
                    .iter()
                    .map(|fp| (fp.port, fp.protocol.clone()))
                    .collect();
                for port in [1024, 2024] {
                    open.insert((port, "tcp".to_string()));
                }
                let mut ports: Vec<ManifestFirewallPort> = open
                    .into_iter()
                    .map(|(port, protocol)| ManifestFirewallPort { port, protocol })
                    .collect();
                ports.sort_by(|a, b| {
                    a.port
                        .cmp(&b.port)
                        .then_with(|| a.protocol.cmp(&b.protocol))
                });
                ports
            },
            baby_container: v1.config.baby_container,
            boot_disk_size: v1.config.boot_disk_size,
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
        },
        disks,
        hashes: v1.hashes,
        // Format 1 archives predate per-service image metadata. We have no
        // way to reconstruct image-ids without re-staging the bundled tars,
        // and v1 conversion is read-only (used only for `inspect`, never
        // re-emitted), so an empty map is correct.
        images: BTreeMap::new(),
    }
}

/// Convert v1 encryption to v2. Returns None if encryption was disabled.
fn convert_encryption_v1(v1: &ManifestDiskEncryptionV1) -> Option<ManifestDiskEncryption> {
    if !v1.enable {
        return None;
    }
    let bind = match v1.key_security.as_str() {
        "strong" => vec!["platform".to_string(), "workload".to_string()],
        _ => vec!["workload".to_string()],
    };
    Some(ManifestDiskEncryption {
        unlock_method: vec!["tpm".to_string()],
        bind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_to_current_injects_portal_ports() {
        let toml_str = r#"
            [meta]
            format = 1
            name = "old-wl"
            version = "v0.0.1"

            [config]
            image = "old-wl:v0.0.1"
            base-image-mode = "blacklist"
            ports = ["3000:3000"]
            restart = "no"

            [hashes]
        "#;
        let v1: ManifestV1 = toml::from_str(toml_str).unwrap();
        let manifest = convert_to_current(v1);

        let port_set: std::collections::HashSet<(u16, &str)> = manifest
            .config
            .firewall_ports
            .iter()
            .map(|fp| (fp.port, fp.protocol.as_str()))
            .collect();

        // Portal ports injected (TCP only) even though the v1 manifest had none.
        assert!(port_set.contains(&(1024, "tcp")));
        assert!(port_set.contains(&(2024, "tcp")));
        assert!(!port_set.contains(&(1024, "udp")));
        assert!(!port_set.contains(&(2024, "udp")));
        assert_eq!(manifest.config.firewall_ports.len(), 2);
        // Sorted by port then protocol.
        let ports: Vec<u16> = manifest
            .config
            .firewall_ports
            .iter()
            .map(|fp| fp.port)
            .collect();
        assert!(ports.windows(2).all(|w| w[0] <= w[1]));
    }
}
