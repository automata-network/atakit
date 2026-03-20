use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Workload subcommand.
#[derive(Subcommand)]
pub enum WorkloadCommand {
    /// Create a new workload directory with a starter config
    Create(CreateArgs),
    /// Build an .atawl archive from atakit-workload.toml
    Build(BuildArgs),
    /// Show workload details and PCR23 measurement
    Info(InfoArgs),
    /// Publish a workload spec to the on-chain WorkloadRegistry
    Publish(PublishArgs),
    /// Deactivate a workload on the on-chain WorkloadRegistry
    Deactivate(DeactivateArgs),
    /// Query on-chain workload spec by workload ID
    Spec(SpecArgs),
}

/// Arguments for `workload create`.
#[derive(Args)]
pub struct CreateArgs {
    /// Name of the workload to create
    pub name: String,
}

/// Arguments for `workload build`.
#[derive(Args)]
pub struct BuildArgs {
    /// Workload directory (default: current directory)
    #[arg(short, long)]
    pub dir: Option<PathBuf>,
    /// Output directory for .atawl file (default: workload directory)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Container engine override (docker or podman)
    #[arg(long, value_parser = ["docker", "podman"])]
    pub engine: Option<String>,
}

/// Arguments for `workload info`.
#[derive(Args)]
pub struct InfoArgs {
    /// Path to .atawl archive
    pub archive: Option<PathBuf>,
    /// Workload directory (alternative to archive)
    #[arg(short, long, conflicts_with = "archive")]
    pub dir: Option<PathBuf>,
    /// Container engine override (for --dir mode)
    #[arg(long, value_parser = ["docker", "podman"])]
    pub engine: Option<String>,
}

/// Arguments for `workload deactivate`.
#[derive(Args)]
pub struct DeactivateArgs {
    /// Path to .atawl archive
    pub archive: Option<PathBuf>,
    /// Workload directory (alternative to archive)
    #[arg(short, long, conflicts_with = "archive")]
    pub dir: Option<PathBuf>,
    /// Ethereum RPC URL
    #[arg(long)]
    pub rpc_url: Option<String>,
    /// Session registry contract address
    #[arg(long)]
    pub session_registry: Option<String>,
    /// Owner private key hex for signing transactions
    #[arg(long)]
    pub owner_key: Option<String>,
    /// Relay private key hex for submitting transactions
    #[arg(long)]
    pub relay_key: Option<String>,
    /// Signature expiration offset in seconds
    #[arg(long, default_value = "300")]
    pub expire_offset: u64,
    /// Container engine override (for --dir mode)
    #[arg(long, value_parser = ["docker", "podman"])]
    pub engine: Option<String>,
}

/// Arguments for `workload publish`.
#[derive(Args)]
pub struct PublishArgs {
    /// Path to .atawl archive
    pub archive: Option<PathBuf>,
    /// Workload directory (alternative to archive)
    #[arg(short, long, conflicts_with = "archive")]
    pub dir: Option<PathBuf>,
    /// Ethereum RPC URL
    #[arg(long)]
    pub rpc_url: Option<String>,
    /// Session registry contract address
    #[arg(long)]
    pub session_registry: Option<String>,
    /// Owner private key hex for signing transactions
    #[arg(long)]
    pub owner_key: Option<String>,
    /// Relay private key hex for submitting transactions
    #[arg(long)]
    pub relay_key: Option<String>,
    /// Signature expiration offset in seconds
    #[arg(long, default_value = "300")]
    pub expire_offset: u64,
    /// Session TTL in seconds (0 = contract default of 30 days)
    #[arg(long, default_value = "0")]
    pub ttl: u64,
    /// Container engine override (for --dir mode)
    #[arg(long, value_parser = ["docker", "podman"])]
    pub engine: Option<String>,
    /// Base image IDs for whitelist/blacklist (hex bytes32)
    #[arg(long)]
    pub base_image_id: Vec<String>,
}

/// Arguments for `workload spec`.
#[derive(Args)]
pub struct SpecArgs {
    /// Workload ID (hex bytes32, with or without 0x prefix)
    pub id: String,
    /// Ethereum RPC URL
    #[arg(long)]
    pub rpc_url: Option<String>,
    /// Session registry contract address
    #[arg(long)]
    pub session_registry: Option<String>,
}
