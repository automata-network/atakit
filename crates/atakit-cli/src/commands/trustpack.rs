//! Produce and inspect `.atatp` trust packs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use atakit_attestation::{
    BaseImageMeasurements, MeasurementPackArtifact, BASE_IMAGE_MEASUREMENT_PACK_SCHEMA,
};
use atakit_attestation_client::{
    read_trust_pack, read_trust_pack_file, required_trust_inputs, validate_collateral_trust_pack,
    validate_workload_trust_pack, ArchiveLimits, RequiredTrustInput, TrustPack, TrustPackBuilder,
    TrustPackKind, TrustPackReadOptions,
};
use clap::{Args, Subcommand};
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature, SigningKey};
use owo_colors::OwoColorize;
use serde::Deserialize;

use crate::config::Config;

/// ECDSA secp256k1, matching `ALGO_ID_ES256K` in the registry contracts.
const ES256K_TYPE_ID: u8 = 3;

#[derive(Subcommand)]
pub enum TrustPackCommand {
    /// Build a signed `.atatp` trust pack
    Build(BuildArgs),
    /// Verify a `.atatp` trust pack and print what it contains
    Inspect(InspectArgs),
}

#[derive(Args)]
pub struct BuildArgs {
    #[command(subcommand)]
    pub command: BuildCommand,
}

#[derive(Subcommand)]
pub enum BuildCommand {
    /// Build policy and measurements for one workload
    Workload(Box<WorkloadBuildArgs>),
    /// Build platform trust roots, policy, and optional vendor collateral
    Collateral(Box<CollateralBuildArgs>),
}

#[derive(Args)]
pub struct CommonBuildArgs {
    /// Human label identifying the publisher. Never used in a trust decision.
    #[arg(long)]
    pub issuer: Option<String>,
    /// Informational revision for this issuer and kind.
    #[arg(long, default_value_t = 1)]
    pub revision: u64,
    /// Start of the validity window, Unix seconds. Defaults to now.
    #[arg(long)]
    pub not_before: Option<u64>,
    /// Exact intended end of the validity window, Unix seconds.
    #[arg(long, conflicts_with = "valid_for")]
    pub not_after: Option<u64>,
    /// Validity duration such as `12h`, `30d`, or `4w`.
    #[arg(long, conflicts_with = "not_after")]
    pub valid_for: Option<String>,
    /// Name of a provisioned ES256K key in `[keys]`.
    #[arg(long)]
    pub signing_key: Option<String>,
    /// Where to write the archive.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct WorkloadBuildArgs {
    /// Compiled `.atawl` whose measured policy is packed.
    pub workload: PathBuf,
    /// Base-image measurement pack JSON. Repeat for every included base image.
    /// The `.sig` and `.pubkey` files are read from beside it.
    #[arg(long, required = true)]
    pub measurement_pack: Vec<PathBuf>,
    #[command(flatten)]
    pub common: CommonBuildArgs,
}

#[derive(Args)]
pub struct CollateralBuildArgs {
    /// Typed TOML file naming platforms and local collateral files.
    #[arg(long)]
    pub config: PathBuf,
    #[command(flatten)]
    pub common: CommonBuildArgs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollateralConfig {
    platforms: Vec<String>,
    #[serde(default)]
    gcp_ak_root_cert: Option<PathBuf>,
    #[serde(default)]
    aws_nitro_root_cert: Option<PathBuf>,
    #[serde(default)]
    amd_ark_root_cert: Vec<PathBuf>,
    #[serde(default)]
    azure_maa_cert: Vec<PathBuf>,
    #[serde(default)]
    amd_snp_security_policy: Vec<PathBuf>,
    #[serde(default)]
    amd_snp_crl: Vec<PathBuf>,
    #[serde(default)]
    tdx_dcap_collateral: Vec<PathBuf>,
    #[serde(default)]
    aws_document_limits: Option<PathBuf>,
}

#[derive(Args)]
pub struct InspectArgs {
    /// The `.atatp` archive to read.
    pub archive: PathBuf,
    /// Payload namespace the archive must occupy.
    #[arg(long)]
    pub kind: String,
    /// Uncompressed SEC1 secp256k1 publisher public key, as `0x04...`.
    #[arg(long)]
    pub publisher_key: String,
    /// Verification time, Unix seconds. Defaults to now.
    #[arg(long)]
    pub at: Option<u64>,
    /// Require this exact `trust-pack.json` digest.
    #[arg(long)]
    pub pin: Option<String>,
}

pub async fn build(args: BuildArgs, config: &Config) -> Result<()> {
    match args.command {
        BuildCommand::Workload(args) => build_workload(*args, config).await,
        BuildCommand::Collateral(args) => build_collateral(*args, config),
    }
}

async fn build_workload(args: WorkloadBuildArgs, config: &Config) -> Result<()> {
    if args.workload.extension().and_then(|value| value.to_str()) != Some("atawl") {
        bail!(
            "workload trust-pack input must be a compiled .atawl archive: {}",
            args.workload.display()
        );
    }
    let signing_key = resolve_signing_key(&args.common, config)?;
    let publisher = alloy_ext::core::primitives::B256::from(atakit_cvm_encoding::key_fingerprint(
        ES256K_TYPE_ID,
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    ));
    let inspected = atakit_workload::inspect_workload(&atakit_workload::InspectOptions {
        publisher: None,
        archive: Some(args.workload.clone()),
        workload_dir: None,
        engine: None,
        verbose: false,
        measured_data_root: None,
        unmeasured_data_root: None,
    })
    .await
    .with_context(|| format!("inspect workload {}", args.workload.display()))?;
    let policy = super::workload::policy::resolve(&inspected, publisher, None, &[])?;

    let (not_before, not_after) = resolve_validity(&args.common)?;
    let mut builder = TrustPackBuilder::new(
        TrustPackKind::WorkloadTrust,
        issuer(&args.common),
        args.common.revision,
        not_before,
        not_after,
    );
    let packed_value = serde_json::to_value(&policy.packed)?;
    let packed_json = serde_json_canonicalizer::to_vec(&packed_value)?;
    builder
        .insert("payload/workload-spec.json", packed_json)
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    let mut supplied_ids = BTreeSet::new();
    for path in &args.measurement_pack {
        let loaded = load_measurement_pack(path)?;
        if !supplied_ids.insert(loaded.base_image_id) {
            bail!(
                "more than one --measurement-pack describes base image 0x{}",
                hex::encode(loaded.base_image_id)
            );
        }
        let stem = format!("0x{}", hex::encode(loaded.base_image_id));
        for (suffix, bytes) in [
            ("json", loaded.artifact.json),
            ("sig", loaded.artifact.signature),
            ("pubkey", loaded.pubkey_file),
        ] {
            builder
                .insert(format!("payload/measurement-packs/{stem}.{suffix}"), bytes)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
        }
    }

    let expected_workload = atakit_cvm_types::AppRef::new(
        publisher.into(),
        policy.packed.name.clone(),
        policy.packed.version.clone(),
    );
    finish_build(
        builder,
        TrustPackKind::WorkloadTrust,
        &args.common,
        &signing_key,
        |pack| {
            validate_workload_trust_pack(pack, &expected_workload)
                .map(|_| ())
                .map_err(|error| anyhow::anyhow!("{error}"))
        },
    )
}

fn build_collateral(args: CollateralBuildArgs, config: &Config) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read collateral config {}", args.config.display()))?;
    let collateral: CollateralConfig = toml::from_str(&text)
        .with_context(|| format!("parse collateral config {}", args.config.display()))?;
    validate_collateral_config(&collateral)?;

    let signing_key = resolve_signing_key(&args.common, config)?;
    let (not_before, not_after) = resolve_validity(&args.common)?;
    let mut builder = TrustPackBuilder::new(
        TrustPackKind::CollateralTrust,
        issuer(&args.common),
        args.common.revision,
        not_before,
        not_after,
    );
    let base = args.config.parent().unwrap_or_else(|| Path::new("."));

    if let Some(path) = &collateral.gcp_ak_root_cert {
        insert_file(
            &mut builder,
            "payload/roots/gcp-ak-root.pem",
            &resolve_config_path(base, path),
        )?;
    }
    if let Some(path) = &collateral.aws_nitro_root_cert {
        insert_file(
            &mut builder,
            "payload/roots/aws-nitro-root.pem",
            &resolve_config_path(base, path),
        )?;
    }
    if let Some(path) = &collateral.aws_document_limits {
        insert_file(
            &mut builder,
            "payload/aws-document-limits.json",
            &resolve_config_path(base, path),
        )?;
    }
    for path in &collateral.amd_ark_root_cert {
        let path = resolve_config_path(base, path);
        insert_file(
            &mut builder,
            &format!("payload/roots/amd-ark-{}.pem", file_stem(&path)?),
            &path,
        )?;
    }
    for path in &collateral.azure_maa_cert {
        let path = resolve_config_path(base, path);
        insert_file(
            &mut builder,
            &format!("payload/azure-maa/{}.pem", file_stem(&path)?),
            &path,
        )?;
    }
    for path in &collateral.amd_snp_security_policy {
        let path = resolve_config_path(base, path);
        insert_file(
            &mut builder,
            &format!("payload/amd-snp-security-policy/{}.json", file_stem(&path)?),
            &path,
        )?;
    }
    for path in &collateral.amd_snp_crl {
        let path = resolve_config_path(base, path);
        insert_file(
            &mut builder,
            &format!("payload/amd-snp-crl/{}.der", file_stem(&path)?),
            &path,
        )?;
    }
    for path in &collateral.tdx_dcap_collateral {
        let path = resolve_config_path(base, path);
        insert_file(
            &mut builder,
            &format!("payload/tdx-dcap/{}.json", file_stem(&path)?),
            &path,
        )?;
    }

    finish_build(
        builder,
        TrustPackKind::CollateralTrust,
        &args.common,
        &signing_key,
        |pack| {
            validate_collateral_trust_pack(pack)
                .map(|_| ())
                .map_err(|error| anyhow::anyhow!("{error}"))
        },
    )
}

fn finish_build(
    builder: TrustPackBuilder,
    kind: TrustPackKind,
    common: &CommonBuildArgs,
    signing_key: &SigningKey,
    validate: impl FnOnce(&TrustPack) -> Result<()>,
) -> Result<()> {
    let archive = builder
        .build(|message| {
            let signature: Signature = signing_key.sign(message);
            Ok::<_, std::convert::Infallible>(signature.to_bytes().to_vec())
        })
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let verify_at = builder_index_start(&builder)?;
    let options = TrustPackReadOptions::new(kind, public_key.clone(), verify_at);
    let pack = read_trust_pack(&archive, &options).map_err(|error| anyhow::anyhow!("{error}"))?;
    validate(&pack)?;

    if let Some(parent) = common.out.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(&common.out, &archive)
        .with_context(|| format!("write {}", common.out.display()))?;

    let public_key = format!("0x{}", hex::encode(public_key));
    println!("{} {}", "Wrote".green(), common.out.display());
    println!("{:<16}{}", "Kind:", kind.as_str());
    println!("{:<16}{}", "Issuer:", pack.index.issuer);
    println!(
        "{:<16}{} to {}",
        "Valid:", pack.index.not_before, pack.index.not_after
    );
    println!("{:<16}{} bytes", "Archive:", archive.len());
    println!("{:<16}{}", "Public key:", public_key);
    println!("{:<16}{}", "Digest:", pack.digest_hex());
    match kind {
        TrustPackKind::WorkloadTrust => {
            println!("VERIFIERD_WORKLOAD_PUBLISHER_PUBKEY=\"{public_key}\"");
            println!(
                "VERIFIERD_WORKLOAD_TRUST_PACK_SHA256=\"{}\"",
                pack.digest_hex()
            );
        }
        TrustPackKind::CollateralTrust => {
            println!("VERIFIERD_COLLATERAL_PUBLISHER_PUBKEY=\"{public_key}\"");
            println!(
                "VERIFIERD_COLLATERAL_TRUST_PACK_SHA256=\"{}\"",
                pack.digest_hex()
            );
        }
    }
    Ok(())
}

/// Read `not_before` from the canonical index instead of duplicating validity
/// resolution inside `finish_build`.
fn builder_index_start(builder: &TrustPackBuilder) -> Result<u64> {
    let bytes = builder
        .index_bytes()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    value["not_before"]
        .as_u64()
        .context("generated trust-pack index has no not_before")
}

struct LoadedMeasurementPack {
    artifact: MeasurementPackArtifact,
    pubkey_file: Vec<u8>,
    base_image_id: [u8; 32],
}

fn load_measurement_pack(path: &Path) -> Result<LoadedMeasurementPack> {
    let json =
        std::fs::read(path).with_context(|| format!("read measurement pack {}", path.display()))?;
    let sig_path = path.with_extension("sig");
    let signature = std::fs::read(&sig_path)
        .with_context(|| format!("read measurement signature {}", sig_path.display()))?;
    let pubkey_path = path.with_extension("pubkey");
    let pubkey_file = std::fs::read(&pubkey_path)
        .with_context(|| format!("read measurement publisher key {}", pubkey_path.display()))?;
    let publisher_key = parse_publisher_key(&pubkey_file)
        .with_context(|| format!("parse {}", pubkey_path.display()))?;
    let artifact = MeasurementPackArtifact {
        json,
        signature,
        publisher_key,
    };
    let pack = artifact
        .verify()
        .with_context(|| format!("verify measurement pack {}", path.display()))?;
    if pack.schema != BASE_IMAGE_MEASUREMENT_PACK_SCHEMA {
        bail!(
            "{} is {}, not a base-image measurement pack",
            path.display(),
            pack.schema
        );
    }
    let _: BaseImageMeasurements = pack
        .body(BASE_IMAGE_MEASUREMENT_PACK_SCHEMA)
        .with_context(|| format!("parse base-image measurements in {}", path.display()))?;

    let claimed_publisher = canonical_id(&pack.subject.publisher, "subject.publisher")?;
    let derived_publisher =
        atakit_cvm_encoding::key_fingerprint(ES256K_TYPE_ID, &artifact.publisher_key);
    if claimed_publisher != derived_publisher {
        bail!(
            "{} public key derives publisher 0x{}, but the signed subject claims {}",
            path.display(),
            hex::encode(derived_publisher),
            pack.subject.publisher
        );
    }
    let reference =
        atakit_cvm_types::AppRef::new(claimed_publisher, pack.subject.name, pack.subject.version);
    let base_image_id = atakit_cvm_encoding::base_image_id(&reference);
    let claimed_id = canonical_id(&pack.subject.id, "subject.id")?;
    if claimed_id != base_image_id {
        bail!(
            "{} signed subject derives base-image ID 0x{}, but claims {}",
            path.display(),
            hex::encode(base_image_id),
            pack.subject.id
        );
    }
    Ok(LoadedMeasurementPack {
        artifact,
        pubkey_file,
        base_image_id,
    })
}

fn parse_publisher_key(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).context("publisher key is not UTF-8")?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let raw = text
        .strip_prefix("0x")
        .context("publisher key must start with 0x")?;
    if raw.len() != 130 || !raw.starts_with("04") {
        bail!("publisher key must be a 65-byte uncompressed SEC1 point beginning 0x04");
    }
    if !raw
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("publisher key must use lowercase hexadecimal with no surrounding whitespace");
    }
    hex::decode(raw).context("publisher key is not hexadecimal")
}

fn validate_collateral_config(config: &CollateralConfig) -> Result<()> {
    if config.platforms.is_empty() {
        bail!("collateral config must list at least one platform");
    }
    for platform in &config.platforms {
        let (cloud, tee) = match platform.as_str() {
            "gcp-tdx" => ("gcp", "tdx"),
            "gcp-sev-snp" => ("gcp", "sev-snp"),
            "azure-tdx" => ("azure", "tdx"),
            "azure-sev-snp" => ("azure", "sev-snp"),
            "aws-sev-snp" => ("aws", "sev-snp"),
            other => bail!("unsupported collateral platform {other:?}"),
        };
        for required in required_trust_inputs(cloud, tee) {
            let present = match required {
                RequiredTrustInput::GcpAkRoot => config.gcp_ak_root_cert.is_some(),
                RequiredTrustInput::AzureMaaSigningCertificate => !config.azure_maa_cert.is_empty(),
                RequiredTrustInput::AmdArkRoot => !config.amd_ark_root_cert.is_empty(),
                RequiredTrustInput::AmdSnpSecurityPolicy => {
                    !config.amd_snp_security_policy.is_empty()
                }
                RequiredTrustInput::AwsNitroRoot => config.aws_nitro_root_cert.is_some(),
                RequiredTrustInput::AwsDocumentLimits => config.aws_document_limits.is_some(),
            };
            if !present {
                bail!(
                    "collateral config platform {platform} is missing {}",
                    required.name()
                );
            }
        }
    }
    Ok(())
}

fn insert_file(builder: &mut TrustPackBuilder, payload: &str, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    builder
        .insert(payload.to_string(), bytes)
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn resolve_config_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn file_stem(path: &Path) -> Result<String> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && !value.contains('/'))
        .map(str::to_string)
        .with_context(|| format!("{} has no usable file name", path.display()))
}

fn resolve_signing_key(common: &CommonBuildArgs, config: &Config) -> Result<SigningKey> {
    let key = super::workload::resolve_owner_key(common.signing_key.as_deref(), config)?;
    let raw = key.strip_prefix("0x").unwrap_or(&key);
    let bytes = hex::decode(raw).context("signing key is not valid hex")?;
    SigningKey::from_slice(&bytes).context("signing key must be a 32-byte ES256K key")
}

fn issuer(common: &CommonBuildArgs) -> String {
    common
        .issuer
        .clone()
        .or_else(|| common.signing_key.clone())
        .unwrap_or_else(|| "configured-publisher".to_string())
}

fn resolve_validity(common: &CommonBuildArgs) -> Result<(u64, u64)> {
    let not_before = common.not_before.unwrap_or_else(now_unix);
    let not_after = match (&common.valid_for, common.not_after) {
        (Some(duration), None) => not_before
            .checked_add(parse_duration(duration)?)
            .context("trust-pack validity overflows Unix seconds")?,
        (None, Some(not_after)) => not_after,
        (None, None) => bail!("use --valid-for <duration> or --not-after <unix-seconds>"),
        (Some(_), Some(_)) => bail!("--valid-for and --not-after cannot be used together"),
    };
    if not_before >= not_after {
        bail!("not_before {not_before} must be before not_after {not_after}");
    }
    Ok((not_before, not_after))
}

fn parse_duration(value: &str) -> Result<u64> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .context("duration needs a unit: s, m, h, d, or w")?;
    let amount: u64 = value[..split]
        .parse()
        .with_context(|| format!("invalid duration {value:?}"))?;
    if amount == 0 {
        bail!("duration must be greater than zero");
    }
    let multiplier = match &value[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => bail!("duration unit must be s, m, h, d, or w"),
    };
    amount
        .checked_mul(multiplier)
        .context("duration overflows seconds")
}

fn canonical_id(value: &str, field: &str) -> Result<[u8; 32]> {
    if !atakit_core::is_canonical_id(value) {
        bail!("{field} must be canonical lowercase 0x-prefixed bytes32");
    }
    let bytes = hex::decode(&value[2..]).with_context(|| format!("decode {field}"))?;
    Ok(bytes.try_into().expect("canonical ID is exactly 32 bytes"))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub fn inspect(args: InspectArgs) -> Result<()> {
    let kind = parse_kind(&args.kind)?;
    let raw = args
        .publisher_key
        .strip_prefix("0x")
        .unwrap_or(&args.publisher_key);
    let publisher_key = hex::decode(raw).context("--publisher-key is not valid hex")?;
    let now = args.at.unwrap_or_else(now_unix);

    let mut options = TrustPackReadOptions::new(kind, publisher_key, now);
    if let Some(pin) = args.pin.as_deref() {
        let raw = pin.strip_prefix("0x").unwrap_or(pin);
        let digest: [u8; 32] = hex::decode(raw)
            .context("--pin is not valid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("--pin must be 32 bytes"))?;
        options = options.pinned(digest);
    }

    let pack = read_trust_pack_file(&args.archive, &options)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    println!("{}", "Verified".green());
    println!("{:<14}{}", "Kind:", pack.kind.as_str());
    println!("{:<14}{}", "Issuer:", pack.index.issuer);
    println!("{:<14}{}", "Revision:", pack.index.revision);
    println!(
        "{:<14}{} to {}",
        "Valid:", pack.index.not_before, pack.index.not_after
    );
    println!("{:<14}{}", "Digest:", pack.digest_hex());
    println!("{:<14}", "Payload:");
    for (path, bytes) in &pack.payload {
        println!("  {:<48}{} bytes", path, bytes.len());
    }

    let limits = ArchiveLimits::default();
    let total: u64 = pack.payload.values().map(|bytes| bytes.len() as u64).sum();
    let largest = pack
        .payload
        .values()
        .map(|bytes| bytes.len() as u64)
        .max()
        .unwrap_or(0);
    println!(
        "{:<14}{} of {} entries, {} of {} bytes, largest entry {} of {}",
        "Against limits:",
        pack.payload.len(),
        limits.max_entries,
        total,
        limits.max_total_bytes,
        largest,
        limits.max_entry_bytes
    );
    Ok(())
}

fn parse_kind(value: &str) -> Result<TrustPackKind> {
    TrustPackKind::parse(value).map_err(|error| anyhow::anyhow!("{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn human_durations_are_exact_and_bounded() {
        assert_eq!(parse_duration("30d").unwrap(), 30 * 24 * 60 * 60);
        assert_eq!(parse_duration("4w").unwrap(), 4 * 7 * 24 * 60 * 60);
        assert!(parse_duration("30").is_err());
        assert!(parse_duration("0d").is_err());
        assert!(parse_duration("1month").is_err());
    }

    #[test]
    fn publisher_key_file_requires_the_uncompressed_canonical_form() {
        let valid = format!("0x04{}\n", "11".repeat(64));
        assert_eq!(parse_publisher_key(valid.as_bytes()).unwrap().len(), 65);
        assert!(parse_publisher_key(format!("0x02{}", "11".repeat(32)).as_bytes()).is_err());
        assert!(parse_publisher_key(valid.to_uppercase().as_bytes()).is_err());
        assert!(parse_publisher_key(format!(" {valid}").as_bytes()).is_err());
    }

    #[test]
    fn collateral_platforms_require_their_complete_trust_inputs() {
        let missing = CollateralConfig {
            platforms: vec!["aws-sev-snp".to_string()],
            gcp_ak_root_cert: None,
            aws_nitro_root_cert: Some("aws.pem".into()),
            amd_ark_root_cert: vec!["ark.pem".into()],
            azure_maa_cert: Vec::new(),
            amd_snp_security_policy: Vec::new(),
            amd_snp_crl: Vec::new(),
            tdx_dcap_collateral: Vec::new(),
            aws_document_limits: Some("limits.json".into()),
        };
        let error = validate_collateral_config(&missing).unwrap_err();
        assert!(error.to_string().contains("amd-snp-security-policy"));
    }

    #[tokio::test]
    async fn workload_command_builds_a_validated_pack_and_refuses_a_bad_inner_signature() {
        let directory = tempfile::tempdir().unwrap();
        let workload_key = SigningKey::from_slice(&[0x31; 32]).unwrap();
        let workload_private_key = directory.path().join("workload.key");
        std::fs::write(
            &workload_private_key,
            format!("0x{}\n", hex::encode(workload_key.to_bytes())),
        )
        .unwrap();
        let workload_publisher = atakit_cvm_encoding::key_fingerprint(
            ES256K_TYPE_ID,
            workload_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );

        let base_key = SigningKey::from_slice(&[0x32; 32]).unwrap();
        let base_publisher = atakit_cvm_encoding::key_fingerprint(
            ES256K_TYPE_ID,
            base_key.verifying_key().to_encoded_point(false).as_bytes(),
        );
        let base_reference = atakit_cvm_types::AppRef::new(base_publisher, "automata-linux", "v1");
        let base_image_id = atakit_cvm_encoding::base_image_id(&base_reference);
        let measurement = atakit_attestation::MeasurementPack {
            schema: BASE_IMAGE_MEASUREMENT_PACK_SCHEMA.to_string(),
            revision: 1,
            published_at: 1_787_356_800,
            subject: atakit_attestation::Subject {
                publisher: format!("0x{}", hex::encode(base_publisher)),
                name: "automata-linux".to_string(),
                version: "v1".to_string(),
                id: format!("0x{}", hex::encode(base_image_id)),
                uri: None,
                archive_sha256: None,
            },
            measurements: serde_json::to_value(BaseImageMeasurements {
                profiles: Vec::new(),
            })
            .unwrap(),
        };
        let measurement = MeasurementPackArtifact::sign(&measurement, &base_key).unwrap();
        let measurement_json = directory.path().join("measurement-pack.json");
        std::fs::write(&measurement_json, &measurement.json).unwrap();
        std::fs::write(
            measurement_json.with_extension("sig"),
            &measurement.signature,
        )
        .unwrap();
        std::fs::write(
            measurement_json.with_extension("pubkey"),
            format!("{}\n", measurement.publisher_key_text()),
        )
        .unwrap();

        let manifest = serde_json::json!({
            "meta": {
                "format": atakit_workload::FORMAT_VERSION,
                "publisher": format!("0x{}", hex::encode(workload_publisher)),
                "name": "example-workload",
                "version": "v1"
            },
            "config": {
                "image": "example-workload:v1",
                "base-image-mode": "whitelist",
                "base-image": [base_reference.to_string()],
                "depends_on": [],
                "gid-group": "workload",
                "logging": {
                    "driver": "journald",
                    "options": {},
                    "log-readers": []
                },
                "workload-logs": false
            },
            "hashes": {}
        });
        let manifest = serde_json_canonicalizer::to_vec(&manifest).unwrap();
        let archive_path = directory.path().join("example.atawl");
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "manifest.json", manifest.as_slice())
            .unwrap();
        let tar = tar.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).unwrap();
        std::fs::write(&archive_path, encoder.finish().unwrap()).unwrap();

        let mut config = Config::default();
        config.keys.insert(
            "workload-publisher".to_string(),
            crate::config::KeySpec {
                key_type: crate::config::KeyType::Es256k,
                mode: crate::config::KeyMode::Provisioned,
                file: Some(workload_private_key.display().to_string()),
                command: None,
                env: None,
                timeout_secs: None,
            },
        );
        let output = directory.path().join("workload.atatp");
        let common = CommonBuildArgs {
            issuer: Some("example-workload-publisher".to_string()),
            revision: 1,
            not_before: Some(100),
            not_after: Some(200),
            valid_for: None,
            signing_key: Some("workload-publisher".to_string()),
            out: output.clone(),
        };
        build_workload(
            WorkloadBuildArgs {
                workload: archive_path.clone(),
                measurement_pack: vec![measurement_json.clone()],
                common,
            },
            &config,
        )
        .await
        .unwrap();

        let options = TrustPackReadOptions::new(
            TrustPackKind::WorkloadTrust,
            workload_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            100,
        );
        let pack = read_trust_pack_file(&output, &options).unwrap();
        let workload_reference =
            atakit_cvm_types::AppRef::new(workload_publisher, "example-workload", "v1");
        assert_eq!(
            validate_workload_trust_pack(&pack, &workload_reference).unwrap(),
            vec![base_image_id]
        );

        std::fs::write(measurement_json.with_extension("sig"), [0u8; 64]).unwrap();
        let refused_output = directory.path().join("refused.atatp");
        let error = build_workload(
            WorkloadBuildArgs {
                workload: archive_path,
                measurement_pack: vec![measurement_json],
                common: CommonBuildArgs {
                    issuer: None,
                    revision: 1,
                    not_before: Some(100),
                    not_after: Some(200),
                    valid_for: None,
                    signing_key: Some("workload-publisher".to_string()),
                    out: refused_output.clone(),
                },
            },
            &config,
        )
        .await
        .expect_err("a bad inner signature must fail before output is written");
        assert!(format!("{error:#}").contains("signature"), "got {error:#}");
        assert!(!refused_output.exists());
    }
}
