use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Workload subcommand.
#[derive(Subcommand)]
pub enum WorkloadCommand {
    /// Create a new workload directory with a starter config
    Create(CreateArgs),
    /// Build an .atawl archive from atakit-workload.toml
    Build(BuildArgs),
    /// Show workload details and integrity measurement
    Info(InfoArgs),
    /// Publish a workload spec to the on-chain WorkloadRegistry
    Publish(PublishArgs),
    /// Deactivate a workload on the on-chain WorkloadRegistry
    Deactivate(DeactivateArgs),
    /// Query on-chain workload spec by workload ID
    Spec(SpecArgs),
    /// List local and/or remote workloads
    Ls(LsArgs),
    /// Download a workload from a repository
    Pull(PullArgs),
    /// Upload a workload to a repository
    Push(PushArgs),
    /// Import a local .atawl file into the store
    Import(ImportArgs),
    /// Export a workload archive from the store
    Export(ExportArgs),
    /// Add a workload from on-chain spec (metadata only)
    Add(AddArgs),
    /// Remove a workload from the local store
    Rm(RmArgs),
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
    /// Skip importing the built archive into the local workload store
    #[arg(long)]
    pub no_store: bool,
    /// Use gzip compression instead of zstd
    #[arg(long)]
    pub gz: bool,
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
    /// Workload reference (name:version, 0x<workload_id>, or path to .atawl)
    pub archive: Option<PathBuf>,
    /// Workload directory (alternative to archive)
    #[arg(short, long, conflicts_with = "archive")]
    pub dir: Option<PathBuf>,
    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
    /// Chain config name (references [chains.<name>])
    #[arg(long)]
    pub chain: Option<String>,
    /// Owner key name (references [keys.<name>])
    #[arg(long)]
    pub owner_key: Option<String>,
    /// Relay key name for transaction submission (references [keys.<name>])
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
    /// Chain config name (references [chains.<name>])
    #[arg(long)]
    pub chain: Option<String>,
    /// Owner key name (references [keys.<name>])
    #[arg(long)]
    pub owner_key: Option<String>,
    /// Relay key name for transaction submission (references [keys.<name>])
    #[arg(long)]
    pub relay_key: Option<String>,
    /// Signature expiration offset in seconds
    #[arg(long, default_value = "300")]
    pub expire_offset: u64,
    /// Session TTL in seconds (overrides config; 0 = contract default of 30 days)
    #[arg(long = "session-ttl")]
    pub session_ttl: Option<u64>,
    /// Container engine override (for --dir mode)
    #[arg(long, value_parser = ["docker", "podman"])]
    pub engine: Option<String>,
    /// Override base image IDs (hex bytes32). If omitted, derived from the manifest's base-image list.
    #[arg(long)]
    pub base_image_id: Vec<String>,
    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
}

/// Arguments for `workload spec`.
#[derive(Args)]
pub struct SpecArgs {
    /// Workload ID (hex bytes32, with or without 0x prefix)
    pub id: String,
    /// Chain config name (references [chains.<name>])
    #[arg(long)]
    pub chain: Option<String>,
}

/// Arguments for `workload ls`.
#[derive(Args)]
pub struct LsArgs {
    /// Show remote workloads from a repository
    #[arg(long)]
    pub remote: bool,
    /// Show both local and remote workloads
    #[arg(long, conflicts_with = "remote")]
    pub all: bool,
    /// Filter by name substring
    #[arg(long)]
    pub name: Option<String>,
    /// Filter by owner fingerprint
    #[arg(long)]
    pub owner: Option<String>,
    /// Max results for remote queries
    #[arg(long)]
    pub limit: Option<u32>,
    /// Workload repository name, http(s) URL, or owner/repo path
    #[arg(long)]
    pub repository: Option<String>,
    /// Show full source repository list without truncation
    #[arg(short = 'w', long)]
    pub wide: bool,
}

/// Arguments for `workload pull`.
#[derive(Args)]
pub struct PullArgs {
    /// Workload reference (name:version or 0x<workload_id>)
    pub reference: String,
    /// Workload repository name, http(s) URL, or owner/repo path
    #[arg(long)]
    pub repository: Option<String>,
    /// Verify archive PCR23 against on-chain spec
    #[arg(long)]
    pub verify: bool,
    /// Force overwrite if already in store
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `workload push`.
#[derive(Args)]
pub struct PushArgs {
    /// Workload reference (name:version) or path to .atawl file
    pub source: Option<String>,
    /// Workload directory (for auto-detect)
    #[arg(short, long)]
    pub dir: Option<PathBuf>,
    /// Workload repository name, http(s) URL, or owner/repo path
    #[arg(long)]
    pub repository: Option<String>,
    /// Skip the confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
}

/// Arguments for `workload import`.
#[derive(Args)]
pub struct ImportArgs {
    /// Path to .atawl file
    pub archive: PathBuf,
    /// Force overwrite if already in store
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `workload export`.
#[derive(Args)]
pub struct ExportArgs {
    /// Workload reference (name:version)
    pub reference: String,
    /// Output directory (default: current directory)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Arguments for `workload add`.
#[derive(Args)]
pub struct AddArgs {
    /// Workload reference (name:version or 0x<workload_id>), or path to .atawl file
    pub reference: String,
    /// Chain config name (references [chains.<name>])
    #[arg(long)]
    pub chain: Option<String>,
    /// Force overwrite if already in store
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `workload rm`.
#[derive(Args)]
pub struct RmArgs {
    /// Workload reference (name:version)
    pub reference: String,
    /// Remove only the archive blob, keep metadata
    #[arg(long)]
    pub blob_only: bool,
}
