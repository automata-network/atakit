use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Cloud deployment subcommand.
#[derive(Subcommand)]
pub enum CloudCommand {
    /// Deploy a workload to a cloud CVM
    #[command(arg_required_else_help = true)]
    Deploy(DeployArgs),
    /// Destroy a cloud deployment
    Destroy(DestroyArgs),
    /// Show deployment status
    Status(StatusArgs),
    /// List all deployments
    #[command(alias = "list")]
    Ls(ListArgs),
    /// SSH into a deployed instance
    Ssh(SshArgs),
    /// View serial console output
    Serial(SerialArgs),
    /// Manage cloud images
    #[command(subcommand)]
    Image(CloudImageCommand),
    /// Manage cloud providers
    #[command(subcommand)]
    Provider(CloudProviderCommand),
    /// Initialize a deployed instance with a workload
    #[command(arg_required_else_help = true)]
    Init(InitArgs),
}

/// Cloud image subcommands.
#[derive(Subcommand)]
pub enum CloudImageCommand {
    /// List uploaded cloud images
    #[command(alias = "list")]
    Ls(CloudImageLsArgs),
    /// Upload a base image to a cloud provider
    Upload(CloudImageUploadArgs),
    /// Remove an uploaded cloud image
    Rm(CloudImageRmArgs),
    /// Remove images not referenced by any target or active deployment
    Gc(CloudImageGcArgs),
}

/// Cloud provider subcommands.
#[derive(Subcommand)]
pub enum CloudProviderCommand {
    /// List configured cloud providers
    #[command(alias = "list")]
    Ls,
}

/// Arguments for `cloud deploy`.
#[derive(Args)]
pub struct DeployArgs {
    /// Workload source: name:version (store ref), path to .atawl file, or omit for dir mode
    pub source: Option<String>,

    /// Target name from [cloud.targets.<name>]
    #[arg(long)]
    pub target: Option<String>,

    /// Instance name (default: {workload}-{target})
    #[arg(long)]
    pub name: Option<String>,

    /// Base image: repository:tag (from image store), path to .atabi file, or existing GCE image name
    #[arg(long)]
    pub image: Option<String>,

    /// Force re-upload of base image even if it exists
    #[arg(long)]
    pub force_image: bool,

    /// CC types for image registration (comma-separated: SEV_SNP,TDX).
    /// Overrides [cloud.images] lookup. Default: inferred from vmtype.
    #[arg(long, value_delimiter = ',')]
    pub cc_types: Vec<String>,

    /// Additional metadata key=value pairs
    #[arg(long, value_name = "KEY=VALUE")]
    pub metadata: Vec<String>,

    /// Owner key file path override
    #[arg(long)]
    pub owner_key: Option<String>,

    /// Relay key file path override
    #[arg(long)]
    pub relay_key: Option<String>,

    /// RPC URL override
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Session registry address override
    #[arg(long)]
    pub session_registry: Option<String>,

    /// Workload directory (default: current directory)
    #[arg(short, long, conflicts_with = "source")]
    pub dir: Option<PathBuf>,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,

    /// Keep going on non-fatal errors
    #[arg(short = 'k', long)]
    pub keep_going: bool,

    /// Skip CVM agent initialization (steps 6-7)
    #[arg(long)]
    pub skip_init: bool,

    /// Deploy only the base image VM without a workload (for measurements)
    #[arg(long)]
    pub image_only: bool,

    /// Skip workload freshness check (deploy even if source files are newer than the archive)
    #[arg(long)]
    pub force: bool,

    /// Directory containing unmeasured-data files (overrides workload dir)
    #[arg(long, value_name = "DIR")]
    pub unmeasured_data_dir: Option<PathBuf>,
}

/// Arguments for `cloud destroy`.
#[derive(Args)]
pub struct DestroyArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,

    /// Resources to preserve (comma-separated: image, disks, firewall)
    #[arg(long, value_delimiter = ',')]
    pub preserve: Vec<String>,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
}

/// Arguments for `cloud status`.
#[derive(Args)]
pub struct StatusArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,

    /// Query live status from cloud provider
    #[arg(long)]
    pub live: bool,
}

/// Arguments for `cloud list`.
#[derive(Args)]
pub struct ListArgs {
    /// Filter by target name
    #[arg(long)]
    pub target: Option<String>,
}

/// Arguments for `cloud ssh`.
#[derive(Args)]
pub struct SshArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,
}

/// Arguments for `cloud image ls`.
#[derive(Args)]
pub struct CloudImageLsArgs {
    /// Verify images exist in cloud (queries provider APIs)
    #[arg(long)]
    pub live: bool,
}

/// Arguments for `cloud image upload`.
#[derive(Args)]
pub struct CloudImageUploadArgs {
    /// Image to upload (repository:tag or .atabi path)
    pub image: String,

    /// Provider name from [cloud.providers.<name>]
    #[arg(long)]
    pub provider: String,

    /// Delete and re-upload if the image already exists
    #[arg(long)]
    pub force: bool,

    /// CC types for image registration (comma-separated: SEV_SNP,TDX).
    /// Overrides [cloud.images] lookup.
    #[arg(long, value_delimiter = ',')]
    pub cc_types: Vec<String>,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
}

/// Arguments for `cloud image rm`.
#[derive(Args)]
pub struct CloudImageRmArgs {
    /// Image reference to remove (e.g. dev-baseimage:v0.0.1-debug)
    pub image: String,

    /// Provider to remove from
    #[arg(long)]
    pub provider: String,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
}

/// Arguments for `cloud image gc`.
#[derive(Args)]
pub struct CloudImageGcArgs {
    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
}

/// Arguments for `cloud init`.
#[derive(Args)]
pub struct InitArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Workload source: name:version (store ref) or path to .atawl file
    pub source: Option<String>,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,

    /// Workload directory (default: current directory)
    #[arg(short, long, conflicts_with = "source")]
    pub dir: Option<PathBuf>,

    /// RPC URL override
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Session registry address override
    #[arg(long)]
    pub session_registry: Option<String>,

    /// Owner key file path override
    #[arg(long)]
    pub owner_key: Option<String>,

    /// Relay key file path override
    #[arg(long)]
    pub relay_key: Option<String>,

    /// Agent wait timeout in seconds
    #[arg(long, default_value = "300")]
    pub timeout: u64,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,

    /// Skip workload freshness check
    #[arg(long)]
    pub force: bool,

    /// Directory containing unmeasured-data files (overrides workload dir)
    #[arg(long, value_name = "DIR")]
    pub unmeasured_data_dir: Option<PathBuf>,
}

/// Arguments for `cloud serial`.
#[derive(Args)]
pub struct SerialArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,
}
