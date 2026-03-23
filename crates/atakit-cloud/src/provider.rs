use std::collections::BTreeMap;

use crate::config::CloudTarget;
use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::{DeployPlan, DeployStep, DestroyPlan, DestroyStep, StepResult};
use crate::state::{DeployState, PersistedAgentEnv};

/// Options for a deploy operation.
pub struct DeployOptions {
    pub instance_name: String,
    pub target_name: String,
    pub target: CloudTarget,
    pub image_ref: String,
    /// Local disk image file path for upload. `None` means the image is assumed
    /// to already exist in GCE (e.g. a bare GCE image name was passed).
    pub source_image_path: Option<String>,
    pub archive_path: String,
    pub archive_hash: String,
    pub workload_name: String,
    pub workload_version: String,
    pub agent_env: PersistedAgentEnv,
    pub metadata: BTreeMap<String, String>,
    pub force_image: bool,
    pub skip_init: bool,
}

/// Options for a destroy operation.
pub struct DestroyOptions {
    /// Resources to preserve: "image", "disks", "firewall".
    pub preserve: Vec<String>,
    /// Also delete the GCE image. Default: true.
    pub delete_image: bool,
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
