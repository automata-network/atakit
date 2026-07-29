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
    /// Initialize a CVM portal directly (e.g. local QEMU)
    #[command(arg_required_else_help = true)]
    Init(Box<InitArgs>),
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
    /// Root for logical measured-data paths (default: <workload-dir>/measured-data)
    #[arg(long, value_name = "DIR")]
    pub measured_data_root: Option<PathBuf>,
    /// Root for logical unmeasured-data declarations (default: <workload-dir>/unmeasured-data)
    #[arg(long, value_name = "DIR")]
    pub unmeasured_data_root: Option<PathBuf>,
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
    /// Root for logical measured-data paths in --dir mode
    #[arg(long, value_name = "DIR")]
    pub measured_data_root: Option<PathBuf>,
    /// Root for logical unmeasured-data declarations in --dir mode
    #[arg(long, value_name = "DIR")]
    pub unmeasured_data_root: Option<PathBuf>,
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
    /// Owner-operation validity window in seconds. If omitted, falls back to
    /// `[owner_operations] op_expiry_seconds` (default 300).
    #[arg(long)]
    pub op_expiry_seconds: Option<u64>,
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
    /// Owner-operation validity window in seconds. If omitted, falls back to
    /// `[owner_operations] op_expiry_seconds` (default 300).
    #[arg(long)]
    pub op_expiry_seconds: Option<u64>,
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

/// Arguments for `workload init`.
#[derive(Args)]
pub struct InitArgs {
    /// Portal address: "host" or "host:port" (default port 1024;
    /// status port = init port + 1000).
    pub address: String,

    /// Workload source: name:version (store ref) or path to .atawl file
    pub source: Option<String>,

    /// Workload directory (default: current directory)
    #[arg(short, long, conflicts_with = "source")]
    pub dir: Option<PathBuf>,

    /// Platform string sent as `platform.declared` in the init payload
    #[arg(long, value_parser = ["gcp", "azure", "qemu"], default_value = "qemu")]
    pub platform: String,

    /// Chain config name override (references [chains.<name>])
    #[arg(long)]
    pub chain: Option<String>,

    /// Owner key name override (references [keys.<name>])
    #[arg(long)]
    pub owner_key: Option<String>,

    /// Gas wallet key name override (references [keys.<name>])
    #[arg(long)]
    pub gas_wallet: Option<String>,

    /// Timeout in seconds after POST /init for proving, registration, and portal Running.
    /// Defaults to 900 seconds plus owner_operations.op_expiry_seconds plus 60 seconds.
    #[arg(long, value_name = "SECONDS")]
    pub init_timeout: Option<u64>,

    /// Timeout in seconds for the POST /init multipart upload.
    #[arg(long, default_value = "300", value_name = "SECONDS")]
    pub init_upload_timeout: u64,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,

    /// Skip workload freshness check
    #[arg(long)]
    pub skip_freshness_check: bool,

    /// Root containing logical unmeasured-data files (default: <workload-dir>/unmeasured-data)
    #[arg(long, value_name = "DIR", conflicts_with = "unmeasured_data_dir")]
    pub unmeasured_data_root: Option<PathBuf>,

    /// Deprecated alias for --unmeasured-data-root
    #[arg(long, value_name = "DIR")]
    pub unmeasured_data_dir: Option<PathBuf>,

    /// Passphrase for an encrypted data disk, as NAME=VALUE. NAME must be a
    /// disk declared in the workload manifest with `passphrase` in its
    /// unlock_method. Repeatable (one per disk). Per-VM secret — supply at
    /// init time rather than persisting in config.
    #[arg(long, value_name = "NAME=VALUE")]
    pub disk_passphrase: Vec<String>,

    /// Expected base image for TLS attestation measurement policy (name:version).
    #[arg(long, value_name = "NAME:VERSION")]
    pub base_image: Option<String>,

    /// Signed measurement pack JSON file or directory.
    #[arg(long, value_name = "PATH")]
    pub measurements: Option<PathBuf>,

    /// Trusted measurement-pack publisher public key, as SEC1 ES256K hex.
    #[arg(long, value_name = "HEX")]
    pub measurement_publisher_key: Vec<String>,

    /// Trusted Azure MAA RSA public key, as hex PKCS#1 DER or hex JWK JSON.
    #[arg(long, value_name = "HEX")]
    pub azure_maa_key: Vec<String>,

    /// Trusted GCP vTPM AK root certificate, as hex X.509 DER.
    #[arg(long, value_name = "HEX")]
    pub gcp_ak_root_cert: Vec<String>,

    /// Trusted AMD SEV-SNP ARK root certificate, as hex X.509 DER.
    #[arg(long, value_name = "HEX")]
    pub amd_ark_root_cert: Vec<String>,

    /// AMD SEV-SNP certificate revocation list, as hex DER.
    #[arg(long, value_name = "HEX")]
    pub amd_snp_crl: Vec<String>,

    /// atakit Intel TDX DCAP collateral version 1 JSON file for offline verification.
    #[arg(long, value_name = "PATH")]
    pub tdx_dcap_collateral: Option<PathBuf>,

    /// Direct HTTP PCCS/PCS URL for verifier-side Intel TDX DCAP collateral fetch.
    #[arg(long, value_name = "URL")]
    pub tdx_dcap_pccs_url: Option<String>,

    /// Automata on-chain collateral RPC URL for verifier-side Intel TDX DCAP lookup.
    #[arg(long = "tdx-dcap-automata-collateral-rpc-url", value_name = "URL")]
    pub tdx_dcap_automata_collateral_rpc_url: Option<String>,

    /// Automata PCS DAO address override for verifier-side Intel TDX DCAP collateral lookup.
    #[arg(long = "tdx-dcap-automata-pcs-dao", value_name = "ADDRESS")]
    pub tdx_dcap_automata_pcs_dao: Option<String>,

    /// Automata PCCS read strategy. Direct concurrent calls are the default.
    #[arg(
        long = "tdx-dcap-automata-read-strategy",
        value_parser = ["direct-concurrent", "multicall3"],
        default_value = "direct-concurrent"
    )]
    pub tdx_dcap_automata_read_strategy: String,

    /// Multicall3 address override for Automata PCCS reads.
    #[arg(long = "tdx-dcap-automata-multicall3-address", value_name = "ADDRESS")]
    pub tdx_dcap_automata_multicall3_address: Option<String>,

    /// One-shot override: trust only this live TLS certificate SHA-256.
    #[arg(long, value_name = "0xSHA256")]
    pub trust_tls_cert_sha256: Option<String>,

    /// UNSAFE: skip TLS attestation and accept the portal self-signed certificate.
    #[arg(long, conflicts_with = "trust_tls_cert_sha256")]
    pub unsafe_skip_tls_attestation: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::WorkloadCommand;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: WorkloadCommand,
    }

    #[test]
    fn workload_init_uses_the_shared_initialization_timeout_flag() {
        let cli = TestCli::try_parse_from(["test", "init", "127.0.0.1"])
            .expect("workload init arguments");
        let WorkloadCommand::Init(args) = cli.command else {
            panic!("expected workload init command");
        };
        assert_eq!(args.init_timeout, None);

        let cli = TestCli::try_parse_from(["test", "init", "127.0.0.1", "--init-timeout", "1400"])
            .expect("workload init arguments");
        let WorkloadCommand::Init(args) = cli.command else {
            panic!("expected workload init command");
        };
        assert_eq!(args.init_timeout, Some(1400));

        assert!(
            TestCli::try_parse_from(["test", "init", "127.0.0.1", "--timeout", "1400",]).is_err()
        );
    }
}
