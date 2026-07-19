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
    /// Submit a prepared portal session with the operator gas wallet
    #[command(arg_required_else_help = true)]
    Register(RegisterArgs),
    /// Verify the current session evidence locally without registry state
    #[command(arg_required_else_help = true)]
    VerifySession(VerifySessionArgs),
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

    /// TDX DCAP QuoteCollateralV3 JSON file for offline GCP TDX TLS verification.
    #[arg(long, value_name = "PATH")]
    pub tdx_dcap_collateral: Option<PathBuf>,

    /// Direct HTTP PCCS/PCS URL for verifier-side GCP TDX DCAP collateral fetch.
    #[arg(long, value_name = "URL")]
    pub tdx_dcap_pccs_url: Option<String>,

    /// Automata on-chain collateral RPC URL for verifier-side GCP TDX DCAP lookup.
    #[arg(long = "tdx-dcap-automata-collateral-rpc-url", value_name = "URL")]
    pub tdx_dcap_automata_collateral_rpc_url: Option<String>,

    /// Automata PCS DAO address override for verifier-side GCP TDX DCAP collateral lookup.
    #[arg(long = "tdx-dcap-automata-pcs-dao", value_name = "ADDRESS")]
    pub tdx_dcap_automata_pcs_dao: Option<String>,

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

    /// Agent wait timeout in seconds
    #[arg(long, default_value = "300")]
    pub timeout: u64,

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

    /// TDX DCAP QuoteCollateralV3 JSON file for offline GCP TDX TLS verification.
    #[arg(long, value_name = "PATH")]
    pub tdx_dcap_collateral: Option<PathBuf>,

    /// Direct HTTP PCCS/PCS URL for verifier-side GCP TDX DCAP collateral fetch.
    #[arg(long, value_name = "URL")]
    pub tdx_dcap_pccs_url: Option<String>,

    /// Automata on-chain collateral RPC URL for verifier-side GCP TDX DCAP lookup.
    #[arg(long = "tdx-dcap-automata-collateral-rpc-url", value_name = "URL")]
    pub tdx_dcap_automata_collateral_rpc_url: Option<String>,

    /// Automata PCS DAO address override for verifier-side GCP TDX DCAP collateral lookup.
    #[arg(long = "tdx-dcap-automata-pcs-dao", value_name = "ADDRESS")]
    pub tdx_dcap_automata_pcs_dao: Option<String>,

    /// One-shot override: trust only this live TLS certificate SHA-256.
    #[arg(long, value_name = "0xSHA256")]
    pub trust_tls_cert_sha256: Option<String>,

    /// UNSAFE: skip TLS attestation and accept the portal self-signed certificate.
    #[arg(long, conflicts_with = "trust_tls_cert_sha256")]
    pub unsafe_skip_tls_attestation: bool,
}

/// Arguments for `cloud register`.
#[derive(Args)]
pub struct RegisterArgs {
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,

    /// Chain config name override (references [chains.<name>])
    #[arg(long)]
    pub chain: Option<String>,

    /// Gas wallet key name override (references [keys.<name>])
    #[arg(long)]
    pub gas_wallet: Option<String>,

    /// Portal and transaction wait timeout in seconds
    #[arg(long, default_value = "300")]
    pub timeout: u64,

    /// Wait for a future lifecycle successor instead of returning for the current active session.
    #[arg(long)]
    pub wait_for_successor: bool,

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

    /// TDX DCAP QuoteCollateralV3 JSON file for offline GCP TDX TLS verification.
    #[arg(long, value_name = "PATH")]
    pub tdx_dcap_collateral: Option<PathBuf>,

    /// Direct HTTP PCCS/PCS URL for verifier-side GCP TDX DCAP collateral fetch.
    #[arg(long, value_name = "URL")]
    pub tdx_dcap_pccs_url: Option<String>,

    /// Automata on-chain collateral RPC URL for verifier-side GCP TDX DCAP lookup.
    #[arg(long = "tdx-dcap-automata-collateral-rpc-url", value_name = "URL")]
    pub tdx_dcap_automata_collateral_rpc_url: Option<String>,

    /// Automata PCS DAO address override for verifier-side GCP TDX DCAP collateral lookup.
    #[arg(long = "tdx-dcap-automata-pcs-dao", value_name = "ADDRESS")]
    pub tdx_dcap_automata_pcs_dao: Option<String>,

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
    /// Instance name (or target/instance)
    pub instance: String,

    /// Target name (for disambiguation)
    #[arg(long)]
    pub target: Option<String>,

    /// Chain config used only as a read-only trust/collateral source.
    #[arg(long)]
    pub chain: Option<String>,

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

    /// TDX DCAP QuoteCollateralV3 JSON file.
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
        assert_eq!(args.azure_maa_key, ["aa", "bb"]);
    }
}
