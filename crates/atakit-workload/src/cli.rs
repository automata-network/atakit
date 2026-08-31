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
    /// Named ES256K key whose owner fingerprint is the publisher. The workload
    /// identifier is derived from it, so it cannot be computed without one.
    /// Defaults to [publish] owner_key.
    #[arg(long)]
    pub signing_key: Option<String>,
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
    /// Key whose fingerprint is the publisher, for --dir mode
    ///
    /// The publisher is measured, so PCR23 cannot be computed for a directory
    /// without it. Defaults to `[publish] owner_key`. Ignored when inspecting
    /// an archive, which already records its publisher.
    #[arg(long, value_name = "KEY")]
    pub signing_key: Option<String>,
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
    /// Workload reference (<publisher>/<name>:<version> or 0x<workload_id>), or
    /// path to a .atawl file
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

    /// URI the portal should use to download the ATAWL instead of receiving
    /// the local archive. Requires --atawl-sha256.
    #[arg(long, value_name = "URI", requires = "atawl_sha256")]
    pub atawl_uri: Option<String>,

    /// SHA-256 of the complete remote ATAWL. Must match the locally resolved
    /// workload archive used for manifest and policy planning.
    #[arg(long, value_name = "SHA256", requires = "atawl_uri")]
    pub atawl_sha256: Option<String>,

    /// Workload directory (default: current directory)
    #[arg(short, long, conflicts_with = "source")]
    pub dir: Option<PathBuf>,

    /// Platform string sent as `platform.declared` in the init payload
    #[arg(
        long,
        value_parser = ["gcp", "azure", "aws", "qemu"],
        default_value = "qemu"
    )]
    pub platform: String,

    /// Chain config name override (references [chains.<name>])
    #[arg(long)]
    pub chain: Option<String>,

    /// PCR collection policy used only when effective chain registration is off.
    #[arg(long, value_name = "PATH")]
    pub pcr_policy: Option<PathBuf>,

    /// Owner key name override (references [keys.<name>])
    #[arg(long)]
    pub owner_key: Option<String>,

    /// Gas wallet key name override (references [keys.<name>])
    #[arg(long)]
    pub gas_wallet: Option<String>,

    /// Timeout in seconds for non-transfer /init work and waiting for portal Running.
    /// Defaults to 900 seconds plus owner_operations.op_expiry_seconds plus 60 seconds.
    #[arg(long, value_name = "SECONDS")]
    pub init_timeout: Option<u64>,

    /// Timeout in seconds for the ATAWL upload or portal download only.
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

    /// Optional expected base-image assertion for portal TLS attestation.
    #[arg(long, value_name = "NAME:VERSION")]
    pub base_image: Option<String>,

    /// Explicit signed measurement pack for offline portal TLS verification.
    #[arg(long, value_name = "PATH")]
    pub measurements: Option<PathBuf>,

    /// Trusted measurement-pack publisher public key, as SEC1 ES256K hex.
    #[arg(long, value_name = "HEX")]
    pub measurement_publisher_key: Vec<String>,

    /// Trusted Azure MAA signing certificate file, PEM or DER. The public key
    /// and its expiry are both taken from the certificate.
    #[arg(long, value_name = "PATH")]
    pub azure_maa_cert: Vec<PathBuf>,

    /// Trusted GCP vTPM AK root certificate file, PEM or DER.
    #[arg(long, value_name = "PATH")]
    pub gcp_ak_root_cert: Vec<PathBuf>,

    /// Trusted AWS Nitro Enclaves root certificate file, PEM or DER.
    #[arg(long, value_name = "PATH")]
    pub aws_nitro_root_cert: Vec<PathBuf>,

    /// Maximum accepted age of an AWS NitroTPM attestation document.
    #[arg(
        long,
        value_name = "SECONDS",
        requires = "aws_document_allowed_future_clock_difference_seconds"
    )]
    pub aws_document_maximum_age_seconds: Option<u64>,

    /// Maximum accepted future clock difference for an AWS NitroTPM attestation document.
    #[arg(
        long,
        value_name = "SECONDS",
        requires = "aws_document_maximum_age_seconds"
    )]
    pub aws_document_allowed_future_clock_difference_seconds: Option<u64>,

    /// Trusted AMD SEV-SNP ARK root certificate file, PEM or DER.
    #[arg(long, value_name = "PATH")]
    pub amd_ark_root_cert: Vec<PathBuf>,

    /// AMD SEV-SNP certificate revocation list file, PEM or DER.
    #[arg(long, value_name = "PATH")]
    pub amd_snp_crl: Vec<PathBuf>,

    /// Trusted atakit AMD SEV-SNP security policy version 1 JSON file.
    #[arg(long, value_name = "PATH")]
    pub amd_snp_security_policy: Option<PathBuf>,

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

    #[test]
    fn workload_init_accepts_aws_as_the_declared_platform() {
        let cli = TestCli::try_parse_from(["test", "init", "127.0.0.1", "--platform", "aws"])
            .expect("AWS workload init arguments");
        let WorkloadCommand::Init(args) = cli.command else {
            panic!("expected workload init command");
        };
        assert_eq!(args.platform, "aws");
    }

    #[test]
    fn workload_init_remote_atawl_flags_must_be_supplied_together() {
        let hash = "11".repeat(32);
        let cli = TestCli::try_parse_from([
            "test",
            "init",
            "127.0.0.1",
            "--atawl-uri",
            "http://repo.internal/workload.atawl",
            "--atawl-sha256",
            &hash,
        ])
        .expect("remote ATAWL workload init arguments");
        let WorkloadCommand::Init(args) = cli.command else {
            panic!("expected workload init command");
        };
        assert_eq!(args.atawl_sha256.as_deref(), Some(hash.as_str()));

        assert!(
            TestCli::try_parse_from(["test", "init", "127.0.0.1", "--atawl-sha256", &hash,])
                .is_err()
        );
    }
}
