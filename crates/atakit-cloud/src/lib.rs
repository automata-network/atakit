pub mod azure;
pub mod config;
pub mod error;
pub mod exec;
pub mod gcp;
pub mod init;
pub mod naming;
pub mod plan;
pub mod provider;
pub mod state;

#[cfg(feature = "cli")]
pub mod cli;

pub use config::{CcType, CloudConfig, CloudTarget, PlatformKind, validate_target};
pub use error::CloudError;
pub use exec::{CommandOutput, CommandRunner, ProcessRunner};
pub use init::AgentConfig;
pub use naming::{AzureResourceNames, ResourceNames};
pub use plan::{
    DeployPlan, DeployStep, DestroyPlan, DestroyStep, DiskSpec, ResourceUpdates, StepResult,
};
pub use provider::{CloudProvider, DeployOptions, DestroyOptions};
pub use state::{
    AzureResources, DeployState, DeployStatus, GcpResources, NewDeployParams, PersistedAgentEnv,
    ResourceSet,
};
