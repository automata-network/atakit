pub mod cmd;
pub mod gcp;
pub mod azure;
pub mod qemu;

use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;

// ── Cloud service provider ──────────────────────────────────────────

#[derive(Clone, Debug)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Csp {
    Aws,
    Gcp,
    Azure,
}

impl Csp {
    pub fn as_str(&self) -> &str {
        match self {
            Csp::Aws => "aws",
            Csp::Gcp => "gcp",
            Csp::Azure => "azure",
        }
    }

    pub fn disk_filename(&self) -> &str {
        match self {
            Csp::Aws => "aws_disk.vmdk",
            Csp::Gcp => "gcp_disk.tar.gz",
            Csp::Azure => "azure_disk.vhd",
        }
    }
}

impl std::fmt::Display for Csp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Common types ────────────────────────────────────────────────────

/// Disk image format expected by the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskFormat {
    /// Raw disk compressed as `disk.raw` inside a tar.gz (GCP).
    TarGz,
    /// Azure VHD.
    Vhd,
    /// VMware VMDK (AWS).
    Vmdk,
    /// Uncompressed raw disk (QEMU).
    Raw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A single port rule for firewall configuration.
#[derive(Clone, Debug)]
pub struct PortRule {
    pub port: u16,
    pub protocol: Protocol,
}

/// Information about a running VM instance.
#[derive(Clone, Debug)]
pub struct InstanceInfo {
    pub name: String,
    pub public_ip: Option<String>,
}

/// Key-value metadata attached to a VM at creation time.
///
/// Mapped to provider-specific mechanisms:
/// - GCP: `--metadata key=value`
/// - Azure: `--tags key=value`
/// - QEMU: `-fw_cfg` or SMBIOS entries
pub type Metadata = Vec<(String, String)>;

// ── Core trait ──────────────────────────────────────────────────────

/// Identity and dependency checks. Every provider implements this.
#[async_trait]
pub trait CloudProvider: Send + Sync {
    /// Human-readable provider name (e.g. `"gcp"`, `"azure"`, `"qemu"`).
    fn name(&self) -> &str;

    /// Disk image format this provider expects.
    fn disk_format(&self) -> DiskFormat;

    /// Verify that required CLI tools and credentials are available.
    async fn check_deps(&self) -> Result<()>;
}

// ── Capability traits ──────────────────────────────────────────────

/// Upload and manage bootable VM images.
#[async_trait]
pub trait ImageManager: CloudProvider {
    /// Upload a local disk image and register it as a bootable VM image.
    ///
    /// If `version` is provided, it's used to create a versioned image name
    /// (e.g., "myvm-v0.5.0"). If an image with that name already exists,
    /// the upload is skipped unless `force` is true.
    ///
    /// When `force` is true, the existing image is deleted before uploading.
    async fn upload_image(&mut self, disk_path: &Path, version: Option<&str>, force: bool) -> Result<()>;

    /// Check if an image with the given version already exists.
    async fn image_exists(&self, version: Option<&str>) -> bool;

    /// Delete a previously registered image.
    async fn delete_image(&mut self, version: Option<&str>) -> Result<()>;
}

/// VM instance lifecycle.
#[async_trait]
pub trait Compute: CloudProvider {
    /// Create and launch a VM instance, returning its info on success.
    ///
    /// `metadata` contains provider-agnostic key-value pairs that will be
    /// attached to the instance via the provider's native metadata mechanism.
    async fn create_instance(&mut self, metadata: &Metadata) -> Result<InstanceInfo>;

    /// Terminate and delete the VM instance and its directly-associated
    /// resources.
    async fn destroy_instance(&mut self, name: &str) -> Result<()>;

    /// Query information about a running instance by name.
    async fn instance_info(&self, name: &str) -> Result<InstanceInfo>;
}

/// Firewall / network rules.
///
/// Only implement for providers that require explicit port management.
/// QEMU bakes ports into the launch command; Azure handles it implicitly.
#[async_trait]
pub trait Networking: CloudProvider {
    /// Open the given ports in the provider's firewall.
    async fn open_ports(&mut self, ports: &[PortRule]) -> Result<()>;

    /// Remove all firewall rules previously created by [`open_ports`].
    async fn close_ports(&mut self) -> Result<()>;
}

/// Persistent data disks that outlive VM instances.
///
/// Only implement for providers that support independent persistent disks.
#[async_trait]
pub trait BlockStorage: CloudProvider {
    /// Create a new persistent disk.
    ///
    /// `size` uses provider-native notation (e.g. `"100GB"`, `"100G"`).
    async fn create_disk(&mut self, name: &str, size: &str) -> Result<()>;

    /// Delete a persistent disk.
    async fn delete_disk(&mut self, name: &str) -> Result<()>;

    /// Check whether a disk with the given name already exists.
    async fn disk_exists(&self, name: &str) -> Result<bool>;
}

/// Retrieve serial console output from a running instance.
#[async_trait]
pub trait Logs: CloudProvider {
    async fn serial_logs(&self, name: &str) -> Result<String>;
}
