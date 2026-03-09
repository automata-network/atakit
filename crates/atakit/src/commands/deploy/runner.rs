use alloy::primitives::Address;
use anyhow::Result;

use csp::{
    CloudResource, CloudResourceConfig, CloudResourceManager, DataDiskConfig, InstanceInfo,
    PortRule, Protocol,
};

use crate::env::Env;

use super::config::{DeploymentConfig, PortDef, ProviderKind, ResolvedPaths};

/// Execute the deployment workflow for the given configuration.
pub async fn deploy(
    config: &DeploymentConfig,
    paths: &ResolvedPaths,
    operator_address: Address,
    force_upload_image: bool,
    env: &Env,
    quiet: bool,
) -> Result<InstanceInfo> {
    let mut metadata = build_metadata(&config.metadata);

    // Add operator address to metadata (checksummed hex with 0x prefix)
    metadata.push(("operator-pubkey".to_string(), operator_address.to_checksum(None)));

    let port_rules = build_port_rules(&config.ports);

    let data_disks: Vec<DataDiskConfig> = config
        .disks
        .iter()
        .map(|d| DataDiskConfig {
            name: d.name.clone(),
            size: d.size.clone(),
        })
        .collect();

    let resource = match config.provider {
        ProviderKind::Gcp => {
            let gcp_opts = config.gcp.as_ref().cloned().unwrap_or_default();
            let gcp_config = csp::gcp::GcpConfig {
                vm_name: config.name.clone(),
                vm_type: config.vm_type.clone(),
                zone: gcp_opts.zone,
                project_id: gcp_opts.project_id,
                bucket_name: gcp_opts.bucket_name,
                image_name: gcp_opts.image_name,
                secure_boot_dir: paths.secure_boot_dir.clone(),
                quiet,
                port_rules: port_rules.clone(),
                data_disks: vec![],
            };
            CloudResource::Gcp(csp::gcp::Gcp::new(gcp_config).await?)
        }
        ProviderKind::Azure => {
            let azure_opts = config.azure.as_ref().cloned().unwrap_or_default();
            let azure_config = csp::azure::AzureConfig {
                vm_name: config.name.clone(),
                vm_type: config.vm_type.clone(),
                region: azure_opts.region,
                resource_group: azure_opts.resource_group,
                storage_account: azure_opts.storage_account,
                container_name: azure_opts.container_name,
                secure_boot_dir: paths.secure_boot_dir.clone(),
                port_rules: port_rules.clone(),
                data_disks: vec![],
                gallery_name: azure_opts.gallery_name,
                quiet,
            };
            CloudResource::Azure(csp::azure::Azure::new(azure_config).await?)
        }
        ProviderKind::Qemu => {
            let qemu_opts = config.qemu.as_ref().cloned().unwrap_or_default();
            let instance_dir = qemu_opts
                .instance_dir
                .unwrap_or_else(|| env.qemu_disk_dir(&config.name));
            let ovmf_path = match qemu_opts.ovmf_path {
                Some(p) => p,
                None => env.ensure_ovmf()?,
            };
            let qemu_config = csp::qemu::QemuConfig {
                vm_name: config.name.clone(),
                instance_dir,
                ovmf_path,
                disk_tar_gz: paths.image.clone(),
                quiet,
                port_rules: port_rules.clone(),
            };
            CloudResource::Qemu(csp::qemu::Qemu::new(qemu_config)?)
        }
    };

    let rc = CloudResourceConfig {
        name: config.name.clone(),
        image_path: paths.image.clone(),
        image_version: paths
            .image_ref
            .as_ref()
            .map(|r| r.to_string()),
        force_upload_image,
        port_rules,
        data_disks,
        metadata,
        preserve: vec![],
    };

    let mut manager = CloudResourceManager::new(resource, rc);
    manager.deploy().await
}

// ── Converters ───────────────────────────────────────────────────

fn build_metadata(map: &std::collections::HashMap<String, String>) -> csp::Metadata {
    map.iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn build_port_rules(ports: &[PortDef]) -> Vec<PortRule> {
    ports
        .iter()
        .map(|p| PortRule {
            port: p.port,
            protocol: match p.protocol.as_str() {
                "udp" => Protocol::Udp,
                _ => Protocol::Tcp,
            },
        })
        .collect()
}
