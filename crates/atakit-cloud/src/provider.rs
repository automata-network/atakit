use std::collections::BTreeMap;

use crate::config::{CcType, CloudTarget};
use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::{DeployPlan, DeployStep, DestroyPlan, DestroyStep, StepResult};
use crate::state::{DeployState, PersistedInitEnv, PortalPorts};

/// Options for a deploy operation.
pub struct DeployOptions {
    pub instance_name: String,
    pub target_name: String,
    pub target: CloudTarget,
    pub image_ref: String,
    /// Local disk image file path for upload. `None` means the image is assumed
    /// to already exist in GCE (e.g. a bare GCE image name was passed).
    pub source_image_path: Option<String>,
    /// Local secure-boot cert directory for the base image, if available.
    pub source_image_certs_dir: Option<String>,
    pub archive_path: String,
    pub archive_hash: String,
    pub workload_name: String,
    pub workload_version: String,
    pub init_env: PersistedInitEnv,
    pub metadata: BTreeMap<String, String>,
    pub force_image: bool,
    pub skip_init: bool,
    /// CC capabilities for image registration. Resolved by the CLI
    /// (precedence: --cc-types > [cloud.images] > inferred cc_type).
    pub cc_types: Vec<CcType>,
    /// Host ports from the workload manifest (format: "host:container" or "port").
    pub workload_ports: Vec<String>,
    pub portal_ports: PortalPorts,
    /// Disks from the workload manifest: (disk_name, index, size_gb).
    pub workload_disks: Vec<(String, u32, u64)>,
    /// Minimum boot/OS disk size in GB. Cloud default if None.
    pub boot_disk_size_gb: Option<u64>,
}

/// Open the deploy-selected portal ports plus workload-declared ports.
///
/// Manifest v2 currently injects the historical portal defaults
/// (`1024/tcp`, `2024/tcp`) into `firewall_ports`. Drop those entries here
/// and re-add the deploy-selected ports so overrides do not leave the old
/// portal ports exposed just because the manifest builder emitted them.
pub fn deployment_firewall_ports(opts: &DeployOptions) -> Vec<String> {
    let mut ports = opts.portal_ports.firewall_entries();
    for entry in &opts.workload_ports {
        if PortalPorts::is_default_portal_entry(entry) {
            continue;
        }
        if !ports.contains(entry) {
            ports.push(entry.clone());
        }
    }
    ports
}

/// Options for a destroy operation.
pub struct DestroyOptions {
    /// Resources to preserve. Recognised tokens: "image", "disks", "firewall".
    /// "image" is added by the CLI by default (preserved unless `--clean-image`
    /// is passed); "disks" and "firewall" come from `--preserve`.
    pub preserve: Vec<String>,
}

/// Abstraction over cloud providers (GCP, Azure).
#[async_trait::async_trait]
pub trait CloudProvider: Send + Sync {
    /// Check that required CLI tools are installed and authenticated.
    fn check_deps(&self) -> Result<(), CloudError>;

    /// Generate a deployment plan.
    async fn plan_deploy(&self, opts: &DeployOptions) -> Result<DeployPlan, CloudError>;

    /// Execute a single deployment step.
    async fn execute_step(
        &self,
        step: &DeployStep,
        runner: &dyn CommandRunner,
        verbose: bool,
    ) -> Result<StepResult, CloudError>;

    /// Generate a destroy plan from current state.
    fn plan_destroy(
        &self,
        state: &DeployState,
        opts: &DestroyOptions,
    ) -> Result<DestroyPlan, CloudError>;

    /// Execute a single destroy step.
    async fn execute_destroy_step(
        &self,
        step: &DestroyStep,
        runner: &dyn CommandRunner,
        verbose: bool,
    ) -> Result<(), CloudError>;

    /// Query the live external IP of an instance.
    async fn get_instance_ip(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<Option<String>, CloudError>;

    /// Get serial console output.
    async fn get_serial_output(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<String, CloudError>;

    /// Build the SSH command args for exec.
    fn ssh_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError>;

    /// Build the serial console command args for exec.
    fn serial_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError>;
}
