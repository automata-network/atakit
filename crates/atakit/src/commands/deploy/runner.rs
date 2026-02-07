use alloy::primitives::Address;
use anyhow::Result;
use tracing::info;

use csp::{
    BlockStorage, CloudProvider, Compute, ImageManager, InstanceInfo, Metadata, Networking,
    PortRule, Protocol,
};

use crate::env::Env;

use super::config::{DeploymentConfig, PortDef, ProviderKind, ResolvedPaths};

/// Execute the deployment workflow for the given configuration.
pub async fn deploy(
    config: &DeploymentConfig,
    paths: &ResolvedPaths,
    operator_address: Address,
    env: &Env,
) -> Result<InstanceInfo> {
    let quiet = config.quiet.unwrap_or(false);
    let mut metadata = build_metadata(&config.metadata);

    // Add operator address to metadata (checksummed hex with 0x prefix)
    metadata.push(("operator-pubkey".to_string(), operator_address.to_checksum(None)));

    let port_rules = build_port_rules(&config.ports);

    match config.provider {
        ProviderKind::Gcp => deploy_gcp(config, paths, quiet, &metadata, &port_rules).await,
        ProviderKind::Azure => deploy_azure(config, paths, quiet, &metadata).await,
        ProviderKind::Qemu => deploy_qemu(config, paths, env, quiet, &metadata, &port_rules).await,
    }
}

// ── GCP ──────────────────────────────────────────────────────────

async fn deploy_gcp(
    config: &DeploymentConfig,
    paths: &ResolvedPaths,
    quiet: bool,
    metadata: &Metadata,
    port_rules: &[PortRule],
) -> Result<InstanceInfo> {
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
        port_rules: port_rules.to_vec(),
    };

    let mut gcp = csp::gcp::Gcp::new(gcp_config).await?;

    info!("Checking GCP dependencies");
    gcp.check_deps().await?;

    info!("Uploading disk image");
    gcp.upload_image(&paths.image, paths.version.as_deref()).await?;

    if !port_rules.is_empty() {
        info!("Configuring firewall rules");
        gcp.open_ports(port_rules).await?;
    }

    for disk in &config.disks {
        info!(disk = %disk.name, size = %disk.size, "Creating persistent disk");
        gcp.create_disk(&disk.name, &disk.size).await?;
    }

    info!("Creating CVM instance");
    let instance = gcp.create_instance(metadata).await?;

    info!(
        name = %instance.name,
        ip = instance.public_ip.as_deref().unwrap_or("(pending)"),
        "Deployment complete"
    );

    Ok(instance)
}

// ── Azure ────────────────────────────────────────────────────────

async fn deploy_azure(
    config: &DeploymentConfig,
    paths: &ResolvedPaths,
    quiet: bool,
    metadata: &Metadata,
) -> Result<InstanceInfo> {
    let azure_opts = config.azure.as_ref().cloned().unwrap_or_default();

    let azure_config = csp::azure::AzureConfig {
        vm_name: config.name.clone(),
        vm_type: config.vm_type.clone(),
        region: azure_opts.region,
        resource_group: azure_opts.resource_group,
        storage_account: azure_opts.storage_account,
        container_name: azure_opts.container_name,
        quiet,
    };

    let mut azure = csp::azure::Azure::new(azure_config).await?;

    info!("Checking Azure dependencies");
    azure.check_deps().await?;

    info!("Uploading disk image");
    azure.upload_image(&paths.image, paths.version.as_deref()).await?;

    info!("Creating CVM instance");
    let instance = azure.create_instance(metadata).await?;

    info!(
        name = %instance.name,
        ip = instance.public_ip.as_deref().unwrap_or("(pending)"),
        "Deployment complete"
    );

    Ok(instance)
}

// ── QEMU ─────────────────────────────────────────────────────────

async fn deploy_qemu(
    config: &DeploymentConfig,
    paths: &ResolvedPaths,
    env: &Env,
    quiet: bool,
    metadata: &Metadata,
    port_rules: &[PortRule],
) -> Result<InstanceInfo> {
    let qemu_opts = config.qemu.as_ref().cloned().unwrap_or_default();

    let instance_dir = qemu_opts
        .instance_dir
        .unwrap_or_else(|| env.qemu_disk_dir(&config.name));

    // Use explicit path from config, or extract embedded OVMF to ~/.atakit/qemu/
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
        port_rules: port_rules.to_vec(),
    };

    let mut qemu = csp::qemu::Qemu::new(qemu_config)?;

    info!("Checking QEMU dependencies");
    qemu.check_deps().await?;

    info!("Extracting disk image");
    qemu.upload_image(&paths.image, paths.version.as_deref()).await?;

    for disk in &config.disks {
        info!(disk = %disk.name, size = %disk.size, "Creating data disk");
        qemu.create_disk(&disk.name, &disk.size).await?;
    }

    info!("Launching QEMU instance");
    let instance = qemu.create_instance(metadata).await?;

    info!(name = %instance.name, "QEMU session complete");

    Ok(instance)
}

// ── Converters ───────────────────────────────────────────────────

fn build_metadata(map: &std::collections::HashMap<String, String>) -> Metadata {
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
