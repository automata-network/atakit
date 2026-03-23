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

/// Arguments for `cloud serial`.
#[derive(Args)]
pub struct SerialArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,
}
