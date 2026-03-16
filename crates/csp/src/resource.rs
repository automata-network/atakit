use std::path::PathBuf;

use anyhow::Result;
use tracing::info;

use crate::{
    azure, gcp, qemu, BlockStorage, CloudProvider, Compute, DataDiskConfig, ImageManager,
    InstanceInfo, Metadata, Networking, PortRule,
};

// ── Types ────────────────────────────────────────────────────────

/// Configuration for the cloud resources to manage.
pub struct CloudResourceConfig {
    pub name: String,
    pub image_path: PathBuf,
    pub image_version: Option<String>,
    pub force_upload_image: bool,
    pub port_rules: Vec<PortRule>,
    pub data_disks: Vec<DataDiskConfig>,
    pub metadata: Metadata,
    /// Resources to preserve during destroy.
    pub preserve: Vec<Preserve>,
}

/// Resource types that can be preserved during destroy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Preserve {
    Image,
    Firewall,
    Disks,
    PublicIp,
}

/// Wraps a concrete provider instance.
pub enum CloudResource {
    Gcp(gcp::Gcp),
    Azure(azure::Azure),
    Qemu(qemu::Qemu),
}

// ── Manager ──────────────────────────────────────────────────────

/// Manages cloud resources through a unified deploy/destroy interface.
///
/// Wraps a [`CloudResource`] provider and a [`CloudResourceConfig`] describing
/// the resources to manage. [`deploy()`](Self::deploy) and
/// [`destroy()`](Self::destroy) orchestrate the full lifecycle without
/// additional parameters.
pub struct CloudResourceManager {
    resource: CloudResource,
    config: CloudResourceConfig,
}

/// Dispatch a trait method call across all provider variants.
macro_rules! dispatch {
    ($res:expr, $method:ident ( $($arg:expr),* $(,)? )) => {
        match $res {
            CloudResource::Gcp(p) => p.$method($($arg),*).await,
            CloudResource::Azure(p) => p.$method($($arg),*).await,
            CloudResource::Qemu(p) => p.$method($($arg),*).await,
        }
    };
}

impl CloudResourceManager {
    pub fn new(resource: CloudResource, config: CloudResourceConfig) -> Self {
        Self { resource, config }
    }

    /// Orchestrate a full deployment.
    ///
    /// Flow: check_deps → upload_image → open_ports (skip QEMU) →
    /// create_disk × N → create_instance.
    pub async fn deploy(&mut self) -> Result<InstanceInfo> {
        info!("Checking dependencies");
        dispatch!(&self.resource, check_deps())?;

        info!("Uploading disk image");
        let version = self.config.image_version.as_deref();
        let force = self.config.force_upload_image;
        dispatch!(
            &mut self.resource,
            upload_image(&self.config.image_path, version, force)
        )?;

        // Open ports — QEMU handles port forwarding via its launch command.
        if !self.config.port_rules.is_empty() {
            match &mut self.resource {
                CloudResource::Gcp(p) => {
                    info!("Configuring firewall rules");
                    p.open_ports(&self.config.port_rules).await?;
                }
                CloudResource::Azure(p) => {
                    info!("Configuring network security group");
                    p.open_ports(&self.config.port_rules).await?;
                }
                CloudResource::Qemu(_) => {}
            }
        }

        for disk in &self.config.data_disks {
            info!(disk = %disk.name, size = %disk.size, "Creating data disk");
            dispatch!(&mut self.resource, create_disk(&disk.name, &disk.size))?;
        }

        info!("Creating instance");
        let instance =
            dispatch!(&mut self.resource, create_instance(&self.config.metadata))?;

        info!(
            name = %instance.name,
            ip = instance.public_ip.as_deref().unwrap_or("(pending)"),
            "Deployment complete"
        );

        Ok(instance)
    }

    /// Tear down deployed resources.
    ///
    /// Flow: destroy_instance → cleanup VM resources → close_ports →
    /// delete_disk × N → delete_image.
    /// Honors [`CloudResourceConfig::preserve`] to skip specific resource types.
    pub async fn destroy(&mut self) -> Result<()> {
        let name = self.config.name.clone();

        info!(name = %name, "Destroying instance");
        match &mut self.resource {
            CloudResource::Azure(azure) => {
                let preserve_pip = self.config.preserve.contains(&Preserve::PublicIp);
                // Query associated resources before VM deletion.
                let resources = azure.query_vm_resources(&name).await;
                azure.destroy_instance(&name).await?;
                azure.cleanup_vm_resources(&resources, preserve_pip).await?;
            }
            CloudResource::Gcp(p) => p.destroy_instance(&name).await?,
            CloudResource::Qemu(p) => p.destroy_instance(&name).await?,
        }

        if !self.config.preserve.contains(&Preserve::Firewall) {
            match &mut self.resource {
                CloudResource::Gcp(p) => {
                    info!("Removing firewall rules");
                    p.close_ports().await?;
                }
                CloudResource::Azure(p) => {
                    info!("Removing network security group");
                    p.close_ports().await?;
                }
                CloudResource::Qemu(_) => {}
            }
        }

        if !self.config.preserve.contains(&Preserve::Disks) {
            for disk in &self.config.data_disks {
                info!(disk = %disk.name, "Deleting data disk");
                dispatch!(&mut self.resource, delete_disk(&disk.name))?;
            }
        }

        if !self.config.preserve.contains(&Preserve::Image) {
            let version = self.config.image_version.as_deref();
            info!("Deleting disk image");
            dispatch!(&mut self.resource, delete_image(version))?;
        }

        Ok(())
    }
}
