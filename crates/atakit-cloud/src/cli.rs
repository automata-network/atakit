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
    /// Verify current session evidence without deployment policy or a transaction
    #[command(arg_required_else_help = true)]
    VerifySession(VerifySessionArgs),
    /// Create, rotate, renew, recover, or inspect portal sessions
    #[command(subcommand)]
    Session(SessionCommand),
}

/// Portal session lifecycle subcommands.
#[derive(Subcommand)]
pub enum SessionCommand {
    /// Create a new session
    New(SessionMutationArgs),
    /// Rotate the current session key
    RotateKey(SessionMutationArgs),
    /// Renew the current session
    Renew(SessionMutationArgs),
    /// Recover an older session into a new current session
    Recover(SessionRecoverArgs),
    /// Show one lifecycle request or the portal's selected request
    Status(SessionStatusArgs),
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
#[derive(Args, Clone)]
pub struct DeployArgs {
    /// Workload source: name:version (store ref), path to .atawl file, or omit for dir mode
    pub source: Option<String>,

    /// Target name(s) from [cloud.targets.<name>]. Repeatable, or comma-separated.
    /// Passing multiple targets fans out into a concurrent multi-target deploy
    /// (instance names auto-generated per target; --name and interactive
    /// confirmation are not supported in multi mode).
    #[arg(long, value_delimiter = ',')]
    pub target: Vec<String>,

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

    /// Chain config name override (references [chains.<name>])
    #[arg(long)]
    pub chain: Option<String>,

    /// Owner key name override (references [keys.<name>])
    #[arg(long)]
    pub owner_key: Option<String>,

    /// Gas wallet key name override (references [keys.<name>])
    #[arg(long)]
    pub gas_wallet: Option<String>,

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

    /// Timeout in seconds for the POST /init multipart upload.
    #[arg(long, default_value = "300", value_name = "SECONDS")]
    pub init_upload_timeout: u64,

    /// Timeout in seconds after POST /init for proving, registration, and portal Running.
    /// Defaults to 900 seconds plus owner_operations.op_expiry_seconds plus 60 seconds.
    #[arg(long, value_name = "SECONDS")]
    pub init_timeout: Option<u64>,

    /// Deploy only the base image VM without a workload (for measurements)
    #[arg(long)]
    pub image_only: bool,

    /// Skip workload freshness check (deploy even if source files are newer than the archive)
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
    /// deploy time rather than persisting in config.
    #[arg(long, value_name = "NAME=VALUE")]
    pub disk_passphrase: Vec<String>,

    /// Override OS boot disk size (e.g. "100GB", "1TB"). Default is 4GB.
    /// Takes precedence over the target's `boot_disk_size` and the workload
    /// manifest's minimum. Must be >= the workload minimum.
    #[arg(long, value_name = "SIZE")]
    pub boot_disk_size: Option<String>,

    /// Existing operator-managed static public IP resource to attach.
    /// GCP: reserved address name. Azure: Public IP name. AWS: Elastic IP
    /// allocation ID once supported.
    #[arg(long, value_name = "REF")]
    pub static_ip: Option<String>,

    /// Azure resource group containing --static-ip.
    #[arg(long, value_name = "RG")]
    pub static_ip_resource_group: Option<String>,

    /// CVM portal /init port. Default: 1024.
    #[arg(long, value_name = "PORT")]
    pub init_port: Option<u16>,

    /// CVM portal /status port. Default: 2024.
    #[arg(long, value_name = "PORT")]
    pub status_port: Option<u16>,

    /// Expected base image for TLS attestation measurement policy (name:version).
    #[arg(long, value_name = "NAME:VERSION")]
    pub base_image: Option<String>,

    /// Signed measurement pack JSON file or directory.
    #[arg(long, value_name = "PATH")]
    pub measurements: Option<PathBuf>,

    /// PCR collection policy used only when effective chain registration is off.
    #[arg(long, value_name = "PATH")]
    pub pcr_policy: Option<PathBuf>,

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

/// Arguments for `cloud destroy`.
#[derive(Args, Clone)]
pub struct DestroyArgs {
    /// Instance name(s) (or target/instance). Repeatable: multiple instances
    /// destroy concurrently.
    #[arg(required = true)]
    pub instance: Vec<String>,

    /// Target name (for disambiguation, applied to all listed instances)
    #[arg(long)]
    pub target: Option<String>,

    /// Resources to preserve (comma-separated: disks, firewall). Images are
    /// always preserved by default; pass `--clean-image` to opt in to deletion.
    #[arg(long, value_delimiter = ',')]
    pub preserve: Vec<String>,

    /// Delete the base image (and its staging bucket on GCP/AWS) when
    /// destroying. Default is to preserve the image so it can be reused by
    /// future deploys. The image is auto-preserved if any other active
    /// deployment still references it.
    #[arg(long)]
    pub clean_image: bool,

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

    /// PCR collection policy used only when effective chain registration is off.
    #[arg(long, value_name = "PATH")]
    pub pcr_policy: Option<PathBuf>,

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

/// Arguments for `cloud verify-session`.
#[derive(Args)]
pub struct VerifySessionArgs {
    /// Optional local deployment name (or target/instance) used only to fill
    /// missing subject identity fields.
    pub instance: Option<String>,

    /// Target name for disambiguating a local deployment shortcut.
    #[arg(long)]
    pub target: Option<String>,

    /// Portal host or IP supplied by the verifier.
    #[arg(long, value_name = "HOST")]
    pub host: Option<String>,

    /// Portal HTTPS status port. Defaults to 2024 with --host.
    #[arg(long, value_name = "PORT")]
    pub status_port: Option<u16>,

    /// Expected canonical workload reference.
    #[arg(long, value_name = "NAME:VERSION")]
    pub workload_ref: Option<String>,

    /// Verification report output path.
    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,

    #[command(flatten)]
    pub verification: SessionVerificationArgs,
}

/// Trust inputs shared by session verification and lifecycle commands.
#[derive(Args, Clone, Default)]
pub struct SessionVerificationArgs {
    /// Chain config used only for read-only trust, collateral, and session-state checks.
    #[arg(long)]
    pub chain: Option<String>,

    /// Manually trusted SHA-256 PCR23 value for the workload manifest.
    /// This must be supplied with --trusted-workload-pcr23-sha384.
    #[arg(
        long,
        value_name = "0xBYTES32",
        requires = "trusted_workload_pcr23_sha384"
    )]
    pub trusted_workload_pcr23_sha256: Option<String>,

    /// Manually trusted SHA-384 PCR23 value for the workload manifest.
    /// This must be supplied with --trusted-workload-pcr23-sha256.
    #[arg(
        long,
        value_name = "0xBYTES48",
        requires = "trusted_workload_pcr23_sha256"
    )]
    pub trusted_workload_pcr23_sha384: Option<String>,

    /// Expected base image for the signed measurement policy.
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

    /// Trusted atakit AMD SEV-SNP security policy version 1 JSON file.
    #[arg(long, value_name = "PATH")]
    pub amd_snp_security_policy: Option<PathBuf>,

    /// TDX DCAP collateral JSON file.
    #[arg(long, value_name = "PATH")]
    pub tdx_dcap_collateral: Option<PathBuf>,

    /// Direct HTTP PCCS/PCS URL for GCP TDX collateral.
    #[arg(long, value_name = "URL")]
    pub tdx_dcap_pccs_url: Option<String>,

    /// Automata on-chain collateral RPC URL for read-only GCP TDX lookup.
    #[arg(long = "tdx-dcap-automata-collateral-rpc-url", value_name = "URL")]
    pub tdx_dcap_automata_collateral_rpc_url: Option<String>,

    /// Automata PCS DAO address override for read-only GCP TDX lookup.
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
}

/// Common arguments for a session-changing operation.
#[derive(Args, Clone)]
pub struct SessionMutationArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,

    /// Owner key name override (references [keys.<name>])
    #[arg(long)]
    pub owner_key: Option<String>,

    /// Complete owner-authorization window in seconds.
    /// Defaults to 900 seconds plus [owner_operations] op_expiry_seconds.
    /// An explicit value replaces that calculated default.
    #[arg(long, value_name = "SECONDS")]
    pub op_expiry_seconds: Option<u64>,

    /// Maximum time to wait for completion. Defaults to the complete owner-
    /// authorization window plus 60 seconds.
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,

    #[command(flatten)]
    pub verification: SessionVerificationArgs,
}

/// Arguments for `cloud session recover`.
#[derive(Args, Clone)]
pub struct SessionRecoverArgs {
    #[command(flatten)]
    pub mutation: SessionMutationArgs,

    /// Older chain session to recover.
    #[arg(long, value_name = "0xBYTES32")]
    pub old_session_id: String,
}

/// Arguments for `cloud session status`.
#[derive(Args, Clone)]
pub struct SessionStatusArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,

    /// Exact lifecycle request hash. Omit to read `/session/status`.
    #[arg(long, value_name = "0xBYTES32")]
    pub request_hash: Option<String>,

    /// Wait until the selected request completes or fails.
    #[arg(long)]
    pub wait: bool,

    /// Maximum wait time in seconds.
    #[arg(long, default_value = "300", value_name = "SECONDS")]
    pub timeout: u64,

    #[command(flatten)]
    pub verification: SessionVerificationArgs,
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: CloudCommand,
    }

    #[test]
    fn verify_session_accepts_repeatable_manual_azure_maa_keys() {
        let cli = TestCli::try_parse_from([
            "test",
            "verify-session",
            "azure-vm",
            "--azure-maa-key",
            "aa",
            "--azure-maa-key",
            "bb",
        ])
        .expect("verify-session arguments");

        let CloudCommand::VerifySession(args) = cli.command else {
            panic!("expected verify-session command");
        };
        assert_eq!(args.verification.azure_maa_key, ["aa", "bb"]);
    }

    #[test]
    fn verify_session_accepts_explicit_remote_subject() {
        let cli = TestCli::try_parse_from([
            "test",
            "verify-session",
            "--host",
            "203.0.113.10",
            "--status-port",
            "2024",
            "--base-image",
            "automata-linux:v1",
            "--workload-ref",
            "example:v1",
            "--chain",
            "hoodi",
        ])
        .expect("verify-session arguments");
        let CloudCommand::VerifySession(args) = cli.command else {
            panic!("expected verify-session command");
        };
        assert_eq!(args.instance, None);
        assert_eq!(args.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(args.status_port, Some(2024));
        assert_eq!(args.workload_ref.as_deref(), Some("example:v1"));
        assert_eq!(
            args.verification.base_image.as_deref(),
            Some("automata-linux:v1")
        );
        assert_eq!(args.verification.chain.as_deref(), Some("hoodi"));
    }

    #[test]
    fn verify_session_accepts_automata_multicall3_options() {
        let cli = TestCli::try_parse_from([
            "test",
            "verify-session",
            "gcp-vm",
            "--tdx-dcap-automata-read-strategy",
            "multicall3",
            "--tdx-dcap-automata-multicall3-address",
            "0x1111111111111111111111111111111111111111",
        ])
        .expect("verify-session arguments");
        let CloudCommand::VerifySession(args) = cli.command else {
            panic!("expected verify-session command");
        };
        assert_eq!(
            args.verification.tdx_dcap_automata_read_strategy,
            "multicall3"
        );
        assert_eq!(
            args.verification
                .tdx_dcap_automata_multicall3_address
                .as_deref(),
            Some("0x1111111111111111111111111111111111111111")
        );
    }

    #[test]
    fn trusted_workload_pcr23_banks_are_shared_by_verification_and_lifecycle_commands() {
        let sha256 = format!("0x{}", "55".repeat(32));
        let sha384 = format!("0x{}", "66".repeat(48));
        let cli = TestCli::try_parse_from([
            "test",
            "verify-session",
            "gcp-vm",
            "--trusted-workload-pcr23-sha256",
            &sha256,
            "--trusted-workload-pcr23-sha384",
            &sha384,
        ])
        .expect("verify-session arguments");
        let CloudCommand::VerifySession(args) = cli.command else {
            panic!("expected verify-session command");
        };
        assert_eq!(
            args.verification.trusted_workload_pcr23_sha256.as_deref(),
            Some(sha256.as_str())
        );
        assert_eq!(
            args.verification.trusted_workload_pcr23_sha384.as_deref(),
            Some(sha384.as_str())
        );

        let cli = TestCli::try_parse_from([
            "test",
            "session",
            "renew",
            "gcp-vm",
            "--trusted-workload-pcr23-sha256",
            &sha256,
            "--trusted-workload-pcr23-sha384",
            &sha384,
        ])
        .expect("session renew arguments");
        let CloudCommand::Session(SessionCommand::Renew(args)) = cli.command else {
            panic!("expected session renew command");
        };
        assert_eq!(
            args.verification.trusted_workload_pcr23_sha256.as_deref(),
            Some(sha256.as_str())
        );
        assert_eq!(
            args.verification.trusted_workload_pcr23_sha384.as_deref(),
            Some(sha384.as_str())
        );

        let help = TestCli::try_parse_from(["test", "verify-session", "--help"])
            .err()
            .expect("verify-session help response")
            .to_string();
        assert!(help.contains("--trusted-workload-pcr23-sha256 <0xBYTES32>"));
        assert!(help.contains("--trusted-workload-pcr23-sha384 <0xBYTES48>"));
    }

    #[test]
    fn session_lifecycle_commands_parse_exact_arguments() {
        let cli =
            TestCli::try_parse_from(["test", "session", "new", "gcp-vm"]).expect("new arguments");
        assert!(matches!(
            cli.command,
            CloudCommand::Session(SessionCommand::New(_))
        ));

        let cli = TestCli::try_parse_from([
            "test",
            "session",
            "rotate-key",
            "gcp-vm",
            "--owner-key",
            "owner",
            "--chain",
            "hoodi-fork",
        ])
        .expect("rotate-key arguments");
        let CloudCommand::Session(SessionCommand::RotateKey(args)) = cli.command else {
            panic!("expected session rotate-key command");
        };
        assert_eq!(args.instance, "gcp-vm");
        assert_eq!(args.owner_key.as_deref(), Some("owner"));
        assert_eq!(args.verification.chain.as_deref(), Some("hoodi-fork"));

        let cli = TestCli::try_parse_from(["test", "session", "renew", "gcp-vm"])
            .expect("renew arguments");
        assert!(matches!(
            cli.command,
            CloudCommand::Session(SessionCommand::Renew(_))
        ));

        let cli = TestCli::try_parse_from([
            "test",
            "session",
            "recover",
            "gcp-vm",
            "--old-session-id",
            "0x11",
        ])
        .expect("recover arguments");
        let CloudCommand::Session(SessionCommand::Recover(args)) = cli.command else {
            panic!("expected session recover command");
        };
        assert_eq!(args.old_session_id, "0x11");

        let cli = TestCli::try_parse_from([
            "test",
            "session",
            "status",
            "gcp-vm",
            "--request-hash",
            "0x22",
            "--wait",
        ])
        .expect("status arguments");
        let CloudCommand::Session(SessionCommand::Status(args)) = cli.command else {
            panic!("expected session status command");
        };
        assert!(args.wait);
        assert_eq!(args.request_hash.as_deref(), Some("0x22"));
    }

    #[test]
    fn lifecycle_help_explains_proof_aware_deadline_and_wait() {
        let help = TestCli::try_parse_from(["test", "session", "new", "--help"])
            .err()
            .expect("session new help response")
            .to_string();
        assert!(help.contains("--op-expiry-seconds <SECONDS>"));
        assert!(help.contains("900 seconds plus [owner_operations] op_expiry_seconds"));
        assert!(help.contains("explicit value replaces that calculated default"));
        assert!(help.contains("authorization window plus 60 seconds"));
    }

    #[test]
    fn session_relay_commands_are_not_available() {
        assert!(TestCli::try_parse_from(["test", "relay-session", "example-vm"]).is_err());
        assert!(TestCli::try_parse_from(["test", "register", "example-vm"]).is_err());
        assert!(TestCli::try_parse_from([
            "test",
            "session",
            "new",
            "example-vm",
            "--gas-wallet",
            "gas"
        ])
        .is_err());
        assert!(TestCli::try_parse_from([
            "test",
            "session",
            "new",
            "example-vm",
            "--unsafe-skip-tls-attestation"
        ])
        .is_err());
    }

    #[test]
    fn deploy_initialization_timeout_is_separate_and_reaches_every_target() {
        let cli = TestCli::try_parse_from([
            "test",
            "deploy",
            "workload:v1",
            "--target",
            "gcp-tdx,azure-sev-snp",
            "--init-timeout",
            "1500",
        ])
        .expect("deploy arguments");
        let CloudCommand::Deploy(args) = cli.command else {
            panic!("expected deploy command");
        };

        assert_eq!(args.init_timeout, Some(1500));
        assert_eq!(args.target, ["gcp-tdx", "azure-sev-snp"]);
        for target in args.target.iter().cloned() {
            let mut single_target_args = args.clone();
            single_target_args.target = vec![target];
            assert_eq!(single_target_args.init_timeout, Some(1500));
        }
    }

    #[test]
    fn initialization_timeouts_use_calculated_defaults_until_overridden() {
        let cli = TestCli::try_parse_from(["test", "deploy", "workload:v1", "--target", "gcp-tdx"])
            .expect("deploy arguments");
        let CloudCommand::Deploy(args) = cli.command else {
            panic!("expected deploy command");
        };
        assert_eq!(args.init_timeout, None);

        let cli = TestCli::try_parse_from(["test", "init", "gcp-vm", "workload:v1"])
            .expect("init arguments");
        let CloudCommand::Init(args) = cli.command else {
            panic!("expected init command");
        };
        assert_eq!(args.init_timeout, None);

        let cli = TestCli::try_parse_from([
            "test",
            "init",
            "gcp-vm",
            "workload:v1",
            "--init-timeout",
            "1400",
        ])
        .expect("init arguments");
        let CloudCommand::Init(args) = cli.command else {
            panic!("expected init command");
        };
        assert_eq!(args.init_timeout, Some(1400));

        assert!(TestCli::try_parse_from([
            "test",
            "init",
            "gcp-vm",
            "workload:v1",
            "--timeout",
            "1400",
        ])
        .is_err());
    }

    #[test]
    fn portal_readiness_timeout_remains_300_seconds() {
        assert_eq!(crate::init::PORTAL_READINESS_TIMEOUT_SECONDS, 300);
    }

    #[test]
    fn command_help_distinguishes_initialization_and_upload_timeouts() {
        let deploy_help = TestCli::try_parse_from(["test", "deploy", "--help"])
            .err()
            .expect("deploy help response")
            .to_string();
        assert!(deploy_help.contains("--init-timeout <SECONDS>"));
        assert!(deploy_help.contains("proving, registration, and portal Running"));
        assert!(deploy_help.contains("--init-upload-timeout <SECONDS>"));

        let init_help = TestCli::try_parse_from(["test", "init", "--help"])
            .err()
            .expect("init help response")
            .to_string();
        assert!(init_help.contains("--init-timeout <SECONDS>"));
        assert!(init_help.contains("proving, registration, and portal Running"));
        assert!(init_help.contains("--init-upload-timeout <SECONDS>"));
    }
}
