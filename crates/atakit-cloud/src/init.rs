use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atakit_attestation::{
    amd_snp_ark_from_cert_table, amd_snp_vcek_cert_table, amd_snp_vcek_request,
    select_azure_maa_manual_trust_key, verify_measurement_pack, verify_tls_attestation, AkBinding,
    AzureMaaTrustKey, CheckResult, EvidenceSummary, MeasurementPolicy, TlsAttestationResponse,
    TrustAnchors, VerificationCheck, VerificationInputs, VerificationReport, VerifiedTlsIdentity,
};
use atakit_core::{NullReporter, ProgressHandle, ProgressReporter};
use atakit_image::encode_image_ref_path_segment;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use dcap_qvl::config::PckCa;
use dcap_qvl::quote::Quote;
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::CloudError;

pub const INIT_SCHEMA_VERSION: u32 = 2;
pub const PORTAL_READINESS_TIMEOUT_SECONDS: u64 = 300;
pub const PORTAL_PROOF_TIMEOUT_SECONDS: u64 = 900;
pub const INITIALIZATION_COMPLETION_BUFFER_SECONDS: u64 = 60;

pub fn initialization_timeout_seconds(
    explicit_timeout: Option<u64>,
    owner_operation_expiry_seconds: u64,
) -> u64 {
    explicit_timeout.unwrap_or_else(|| {
        PORTAL_PROOF_TIMEOUT_SECONDS
            .saturating_add(owner_operation_expiry_seconds)
            .saturating_add(INITIALIZATION_COMPLETION_BUFFER_SECONDS)
    })
}

const DEFAULT_TDX_DCAP_AUTOMATA_CHAIN: &str = "hoodi";
const DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL: &str = "https://ethereum-hoodi-rpc.publicnode.com";
const DEFAULT_TDX_DCAP_AUTOMATA_PCS_DAO: &str = "0xb6d715f2f630314cDC1EdE1a550F14822c38b245";
const DEFAULT_TDX_DCAP_AUTOMATA_PCK_DAO: &str = "0x399c1927C72A3913B10f399D383ae4Ff1083aC24";
const DEFAULT_TDX_DCAP_AUTOMATA_TCB_EVAL_DAO: &str = "0x7a675f882ba46a4F2ae95DFc9f07cBD16AF1fd9B";
const DEFAULT_TDX_DCAP_AUTOMATA_FMSPC_TCB_DAOS_BY_EVAL: &[(u64, &str)] = &[
    (17, "0x3A1fDF33420026d145C59bC6b3129bA81E9bF68e"),
    (18, "0xc6f31a3c102d7c2C43a9972BA8B1409278D41fF5"),
    (19, "0x74A0b849030BC8afaAfFf8F46126E3c13E365C7b"),
    (20, "0x34cE5cfD6472c5759cC9451ed2Cb13A0b2c8d1f3"),
    (21, "0xf5536eB1Aa53CF9e1cfA11498749f151278D04bf"),
];
const DEFAULT_TDX_DCAP_AUTOMATA_ENCLAVE_IDENTITY_DAOS_BY_EVAL: &[(u64, &str)] = &[
    (17, "0xE6fE85B78cb82e3b9C8AE57d754C86fe6774aF64"),
    (18, "0x07ea7bD47684A331e012CFb9a797dF48C8Cb7DA7"),
    (19, "0x299c1ae8101aF3d3483793dAfFe8ea9E098D7E17"),
    (20, "0x63191CE92eA7d42998B2EDC5573a948b3c441Ae7"),
    (21, "0x1649dd096557f5d2c317127F81F31Df98c43D6D4"),
];
const DEFAULT_TDX_DCAP_AUTOMATA_TCB_INFO_VERSION: u64 = 3;
const DEFAULT_TDX_DCAP_AUTOMATA_TD_QE_IDENTITY_VERSION: u64 = 4;
const AUTOMATA_PCS_CA_ROOT: u64 = 0;
const AUTOMATA_PCS_CA_PROCESSOR: u64 = 1;
const AUTOMATA_PCS_CA_PLATFORM: u64 = 2;
const AUTOMATA_TCB_ID_TDX: u64 = 1;
const AUTOMATA_ENCLAVE_ID_TD_QE: u64 = 2;

/// Init-time configuration sent to the portal via POST /init.
#[derive(Debug, Clone)]
pub struct InitConfig {
    /// Sent verbatim as `platform.declared` in the init JSON (e.g. "gcp", "azure", "qemu").
    pub platform: String,
    pub chain: InitChainConfig,
    pub owner_operations: atakit_config::OwnerOperationsConfig,
    pub owner_key: InitKeyConfig,
    pub gas_wallet: InitKeyConfig,
    /// Backend-neutral credential delegated to the selected prover daemon.
    /// The internal field name is retained during the compatibility cycle.
    pub prover_credential: Option<InitKeyConfig>,
    /// Operator-supplied per-disk passphrases, keyed by manifest disk name.
    /// Forwarded as `disks.<name>.passphrase` in the init JSON for disks
    /// whose manifest `unlock_method` includes `"passphrase"`. Empty for
    /// the common no-encryption / TPM-only case (then the `disks` field is
    /// omitted from the JSON entirely). Passphrases are per-VM secrets, so
    /// they come from the `--disk-passphrase NAME=VALUE` CLI flag rather
    /// than persisted config. Validate names against the declared disks
    /// with [`parse_disk_passphrases`] before populating this.
    pub disks: BTreeMap<String, String>,
}

/// Verifier-side source for Intel TDX DCAP collateral.
#[derive(Debug, Clone, Default)]
pub struct TdxDcapCollateralConfig {
    pub source: TdxDcapCollateralSource,
}

#[derive(Debug, Clone, Default)]
pub enum TdxDcapCollateralSource {
    /// Do not fetch collateral before verification. If the endpoint response
    /// does not already carry collateral, GCP TDX verification fails closed.
    /// This is retained for internal callers; the CLI defaults to Automata
    /// on-chain PCCS for GCP TDX.
    #[default]
    None,
    /// Load a `dcap_qvl::QuoteCollateralV3` JSON document from disk.
    File(PathBuf),
    /// Fetch `QuoteCollateralV3` from a direct HTTP PCCS/PCS endpoint.
    HttpPccs { url: String },
    /// Read collateral through Automata's on-chain PCCS contracts.
    ///
    /// This is intentionally modeled separately from HTTP PCCS: the access
    /// path is chain RPC plus contract calls, not the PCS/PCCS HTTP API.
    AutomataOnchainPccs {
        chain: Option<String>,
        rpc_url: Option<String>,
        pcs_dao: Option<String>,
        pck_dao: Option<String>,
        fmspc_tcb_dao: Option<String>,
        enclave_identity_dao: Option<String>,
    },
}

/// Verifier-side source for Azure MAA signing keys.
///
/// The portal includes the Azure MAA JWT in `/tls-attestation`, but the
/// verifier still needs a trust anchor for the JWT signing key. For the CLI
/// default path this is derived from the configured SessionRegistry, matching
/// the on-chain registration verifier's MAA key registry rather than requiring
/// operators to pass `--azure-maa-key` manually.
#[derive(Debug, Clone, Default)]
pub struct AzureMaaTrustConfig {
    pub source: AzureMaaTrustSource,
}

#[derive(Debug, Clone, Default)]
pub enum AzureMaaTrustSource {
    /// Do not resolve Azure MAA signing keys automatically.
    #[default]
    None,
    /// Resolve MaaKeyRegistry through SessionRegistry -> AkCollateralVerifier.
    OnchainRegistry {
        rpc_url: String,
        session_registry: String,
    },
}

/// Build a verifier-side TDX DCAP collateral config from CLI-style options.
pub fn tdx_dcap_collateral_config(
    collateral_file: Option<PathBuf>,
    pccs_url: Option<String>,
    automata_collateral_rpc_url: Option<String>,
    automata_pcs_dao: Option<String>,
) -> Result<TdxDcapCollateralConfig, CloudError> {
    let selected = usize::from(collateral_file.is_some())
        + usize::from(pccs_url.is_some())
        + usize::from(automata_collateral_rpc_url.is_some() || automata_pcs_dao.is_some());
    if selected > 1 {
        return Err(CloudError::Config {
            message: "choose only one TDX DCAP collateral source: --tdx-dcap-collateral, --tdx-dcap-pccs-url, or --tdx-dcap-automata-*".to_string(),
        });
    }
    let source = if let Some(path) = collateral_file {
        TdxDcapCollateralSource::File(path)
    } else if let Some(url) = pccs_url {
        TdxDcapCollateralSource::HttpPccs { url }
    } else if automata_collateral_rpc_url.is_some() || automata_pcs_dao.is_some() {
        TdxDcapCollateralSource::AutomataOnchainPccs {
            chain: Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN.to_string()),
            rpc_url: automata_collateral_rpc_url,
            pcs_dao: automata_pcs_dao,
            pck_dao: None,
            fmspc_tcb_dao: None,
            enclave_identity_dao: None,
        }
    } else {
        TdxDcapCollateralSource::AutomataOnchainPccs {
            chain: Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN.to_string()),
            rpc_url: Some(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL.to_string()),
            pcs_dao: Some(DEFAULT_TDX_DCAP_AUTOMATA_PCS_DAO.to_string()),
            pck_dao: Some(DEFAULT_TDX_DCAP_AUTOMATA_PCK_DAO.to_string()),
            fmspc_tcb_dao: None,
            enclave_identity_dao: None,
        }
    };
    Ok(TdxDcapCollateralConfig { source })
}

/// Build verifier-side Automata on-chain trust config from the available chain
/// config. This is independent of portal registration policy: registration
/// controls session submission, while the verifier may still read collateral
/// and trust roots from the chain as a data source.
pub fn azure_maa_trust_config_from_init_chain(chain: &InitChainConfig) -> AzureMaaTrustConfig {
    if chain.rpc_url.trim().is_empty() || is_zero_eth_address(&chain.session_registry) {
        return AzureMaaTrustConfig::default();
    }
    AzureMaaTrustConfig {
        source: AzureMaaTrustSource::OnchainRegistry {
            rpc_url: chain.rpc_url.clone(),
            session_registry: chain.session_registry.clone(),
        },
    }
}

/// Parse `--disk-passphrase NAME=VALUE` entries into a name→passphrase map,
/// validating each NAME against the disks the workload manifest declares.
///
/// `declared` maps each declared disk name to its `unlock_method` list (from
/// the manifest). The checks — which the portal would otherwise apply later
/// (at `/init`, or worse at disk-create time mid-boot) — are done here so the
/// operator gets a fast, clear error before anything is uploaded:
///
/// - **Unknown disk** — a `NAME` not in `declared` (operator typo).
/// - **Orphan passphrase** — `NAME` is declared but its `unlock_method` does
///   not include `"passphrase"`, so the passphrase would be ignored.
/// - **Missing passphrase** — a declared disk lists `"passphrase"` in its
///   `unlock_method` but no `--disk-passphrase` was supplied for it (the
///   common "I forgot the passphrase" mistake).
/// - Malformed entries, empty names, empty values, and duplicate names.
///
/// The passphrase value is taken verbatim after the first `=` (so it may
/// contain `=`); only the name is trimmed.
pub fn parse_disk_passphrases(
    raw: &[String],
    declared: &BTreeMap<String, Vec<String>>,
) -> Result<BTreeMap<String, String>, CloudError> {
    let uses_passphrase = |methods: &[String]| methods.iter().any(|m| m == "passphrase");

    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for entry in raw {
        let (name, value) =
            entry
                .split_once('=')
                .ok_or_else(|| CloudError::InvalidDiskPassphrase {
                    message: format!("expected NAME=VALUE, got {entry:?}"),
                })?;
        let name = name.trim();
        if name.is_empty() {
            return Err(CloudError::InvalidDiskPassphrase {
                message: format!("empty disk name in {entry:?}"),
            });
        }
        if value.is_empty() {
            return Err(CloudError::InvalidDiskPassphrase {
                message: format!("empty passphrase for disk '{name}'"),
            });
        }
        let Some(methods) = declared.get(name) else {
            let mut names: Vec<&str> = declared.keys().map(String::as_str).collect();
            names.sort_unstable();
            let names = if names.is_empty() {
                "(none)".to_string()
            } else {
                names.join(", ")
            };
            return Err(CloudError::InvalidDiskPassphrase {
                message: format!(
                    "disk '{name}' is not declared in the workload manifest; \
                     declared disks: {names}"
                ),
            });
        };
        if !uses_passphrase(methods) {
            return Err(CloudError::InvalidDiskPassphrase {
                message: format!(
                    "disk '{name}' does not use passphrase unlock \
                     (unlock_method = {methods:?}); --disk-passphrase only \
                     applies to disks with \"passphrase\" in their unlock_method"
                ),
            });
        }
        if out.insert(name.to_string(), value.to_string()).is_some() {
            return Err(CloudError::InvalidDiskPassphrase {
                message: format!("duplicate --disk-passphrase for disk '{name}'"),
            });
        }
    }

    // Reverse check: every disk that declares passphrase unlock must have
    // been given one — the common "operator forgot --disk-passphrase" case.
    for (name, methods) in declared {
        if uses_passphrase(methods) && !out.contains_key(name) {
            return Err(CloudError::InvalidDiskPassphrase {
                message: format!(
                    "disk '{name}' requires a passphrase (its unlock_method \
                     includes \"passphrase\") but none was supplied; \
                     pass --disk-passphrase {name}=<value>"
                ),
            });
        }
    }

    Ok(out)
}

/// Chain config section of the init payload.
#[derive(Debug, Clone)]
pub struct InitChainConfig {
    pub rpc_url: String,
    pub session_registry: String,
    pub workload_registry: String,
    pub base_image_registry: String,
    /// Portal-side chain-registration policy (`"required"` |
    /// `"optional"` | `"off"`). `None` ⇒ field omitted from the
    /// `/init` JSON; the portal falls back to its `"required"`
    /// default. Operators who want to disable submission while
    /// debugging chain-side prerequisites should set this to
    /// `"off"` in their `[chains.<name>]` config.
    pub registration: Option<String>,
    /// Optional configured EIP-155 chain id. Forwarded as `chain.chain_id`
    /// when set. The portal reads the effective value from `rpc_url` and
    /// warns that this configured value is ignored.
    pub chain_id: Option<u64>,
    /// On-chain TEE verification policy (`auto`, `solidity`, or `zk`).
    pub tee_backend: String,
    /// Resolved top-level prover profile.
    pub prover: Option<InitProverConfig>,
}

#[derive(Debug, Clone)]
pub struct InitProverConfig {
    pub backend: String,
    pub execution: String,
    pub endpoint: String,
    pub credential: Option<String>,
    pub options: BTreeMap<String, String>,
}

/// Key config section of the init payload.
#[derive(Debug, Clone)]
pub struct InitKeyConfig {
    pub mode: String,
    pub key_type: String,
    pub private_key: Option<String>,
}

/// Build the portal config JSON from an InitConfig.
fn build_portal_config_json(config: &InitConfig) -> serde_json::Value {
    let mut owner_key = serde_json::json!({
        "mode": config.owner_key.mode,
        "type": config.owner_key.key_type,
    });
    if let Some(ref pk) = config.owner_key.private_key {
        owner_key["private_key"] = serde_json::Value::String(pk.clone());
    }

    let mut gas_wallet = serde_json::json!({
        "mode": config.gas_wallet.mode,
        "type": config.gas_wallet.key_type,
    });
    if let Some(ref pk) = config.gas_wallet.private_key {
        gas_wallet["private_key"] = serde_json::Value::String(pk.clone());
    }

    let mut chain = serde_json::json!({
        "rpc_url": config.chain.rpc_url,
        "contracts": {
            "session_registry": config.chain.session_registry,
            "workload_registry": config.chain.workload_registry,
            "base_image_registry": config.chain.base_image_registry,
        },
        "tee_backend": config.chain.tee_backend,
    });
    // `registration` and `chain_id` are only included when set. The portal's
    // "section present, no registration field → required" default continues
    // to apply.
    if let Some(ref reg) = config.chain.registration {
        chain["registration"] = serde_json::Value::String(reg.clone());
    }
    if let Some(id) = config.chain.chain_id {
        chain["chain_id"] = serde_json::Value::Number(id.into());
    }
    let prover_credential = config.prover_credential.as_ref().map(|credential| {
        let mut value = serde_json::json!({
            "mode": credential.mode,
            "type": credential.key_type,
        });
        if let Some(ref pk) = credential.private_key {
            value["private_key"] = serde_json::Value::String(pk.clone());
        }
        value
    });

    let mut portal_config = serde_json::json!({
        "format": INIT_SCHEMA_VERSION,
        "platform": {
            "declared": &config.platform,
        },
        "chain": chain,
        "owner_operations": config.owner_operations,
        "owner_key": owner_key,
        "gas_wallet": gas_wallet,
        "prover_credential": prover_credential,
    });
    if let Some(prover) = config.chain.prover.clone() {
        portal_config["prover"] = serde_json::json!({
            "backend": prover.backend,
            "execution": prover.execution,
            "endpoint": prover.endpoint,
            "options": prover.options,
        });
    }

    // Only emit `disks` when there is at least one passphrase. The portal
    // treats an absent `disks` field as an empty map.
    if !config.disks.is_empty() {
        let disks: serde_json::Map<String, serde_json::Value> = config
            .disks
            .iter()
            .map(|(name, passphrase)| {
                (
                    name.clone(),
                    serde_json::json!({ "passphrase": passphrase }),
                )
            })
            .collect();
        portal_config["disks"] = serde_json::Value::Object(disks);
    }

    portal_config
}

#[derive(Debug, Clone)]
pub struct VerifiedPortalTls {
    pub client: reqwest::Client,
    pub identity: VerifiedTlsIdentity,
    pub manual_override: Option<TlsManualOverride>,
    /// Independently trusted inputs retained for current-session
    /// verification. This is absent for a manual TLS certificate override.
    pub session_verification: Option<crate::session::PortalSessionVerificationContext>,
}

#[derive(Debug, Clone)]
pub struct TlsManualOverride {
    pub live_cert_sha256: String,
    pub report: VerificationReport,
    pub report_path: Option<PathBuf>,
}

pub fn cloud_tls_attestation_report_path(
    data_dir: &Path,
    target_name: &str,
    instance_name: &str,
) -> PathBuf {
    data_dir
        .join("cloud")
        .join("deployments")
        .join(target_name)
        .join(format!("{instance_name}.tls-attestation-report.json"))
}

pub fn workload_tls_attestation_report_path(
    cache_dir: &Path,
    host: &str,
    status_port: u16,
) -> PathBuf {
    cache_dir.join("tls-attestation").join(format!(
        "{}-{status_port}.tls-attestation-report.json",
        sanitize_report_name(host)
    ))
}

fn sanitize_report_name(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "portal".to_string()
    } else {
        out
    }
}

pub fn write_tls_attestation_report(
    report: &VerificationReport,
    path: &Path,
) -> Result<(), CloudError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| CloudError::IoPath {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let bytes = serde_json::to_vec_pretty(report)?;
    std::fs::write(path, bytes).map_err(|source| CloudError::IoPath {
        path: path.to_path_buf(),
        source,
    })
}

/// Load an offline measurement policy for TLS attestation.
///
/// V1 accepts either a measurement-pack JSON file or a directory containing
/// `measurement-pack.json` and `measurement-pack.sig`. If no explicit path is
/// supplied, a `--base-image name:version` lookup searches the local atakit
/// data directory under `baseimage/measurements/<name>/<version>/`.
pub fn load_measurement_policy(
    measurements: Option<&Path>,
    base_image: Option<&str>,
    measurement_publisher_keys: &[String],
    data_dir: Option<&Path>,
) -> Result<Option<MeasurementPolicy>, CloudError> {
    let base_image_ref = base_image.map(parse_base_image_ref).transpose()?;
    let (json_path, sig_path, source) = if let Some(path) = measurements {
        let (json_path, sig_path) = measurement_pack_paths(path);
        let source = json_path.display().to_string();
        (json_path, sig_path, source)
    } else if let Some((name, version)) = base_image_ref {
        let Some(data_dir) = data_dir else {
            return Err(CloudError::Config {
                message: "--base-image local measurement lookup requires a data directory"
                    .to_string(),
            });
        };
        let path = select_local_measurement_pack_dir(data_dir, name, version)?.path;
        let (json_path, sig_path) = measurement_pack_dir_paths(&path);
        (json_path, sig_path, format!("local:{}", path.display()))
    } else {
        return Ok(None);
    };

    let json = std::fs::read(&json_path).map_err(|source| CloudError::IoPath {
        path: json_path.clone(),
        source,
    })?;
    let sig = std::fs::read(&sig_path).map_err(|source| CloudError::IoPath {
        path: sig_path.clone(),
        source,
    })?;
    if sig.is_empty() {
        return Err(CloudError::Config {
            message: format!(
                "measurement pack signature is empty: {}",
                sig_path.display()
            ),
        });
    }

    let trusted_keys = parse_measurement_publisher_keys(measurement_publisher_keys)?;
    let pack =
        verify_measurement_pack(&json, &sig, &trusted_keys).map_err(|e| CloudError::Config {
            message: e.to_string(),
        })?;
    if let Some((name, version)) = base_image_ref {
        if pack.base_image.name != name || pack.base_image.version != version {
            return Err(CloudError::Config {
                message: format!(
                    "measurement pack is for {}:{}, not {name}:{version}",
                    pack.base_image.name, pack.base_image.version
                ),
            });
        }
    }

    Ok(Some(MeasurementPolicy { source, pack }))
}

/// Return whether either file for the automatic local pack lookup exists.
///
/// Callers use this only to choose local-versus-chain precedence. Once a local
/// pack artifact exists, loading or signature errors must fail closed instead
/// of falling back to a different policy source.
pub fn local_measurement_pack_exists(
    data_dir: &Path,
    base_image: &str,
) -> Result<bool, CloudError> {
    let (name, version) = parse_base_image_ref(base_image)?;
    Ok(select_local_measurement_pack_dir(data_dir, name, version)?.detected)
}

fn parse_base_image_ref(value: &str) -> Result<(&str, &str), CloudError> {
    let Some((name, version)) = value.split_once(':') else {
        return Err(CloudError::Config {
            message: format!("expected --base-image NAME:VERSION, got {value:?}"),
        });
    };
    if name.is_empty() || version.is_empty() {
        return Err(CloudError::Config {
            message: format!("expected --base-image NAME:VERSION, got {value:?}"),
        });
    }
    Ok((name, version))
}

fn parse_measurement_publisher_keys(values: &[String]) -> Result<Vec<Vec<u8>>, CloudError> {
    parse_hex_blobs(values, "--measurement-publisher-key")
}

pub fn load_tls_trust_anchors(
    gcp_ak_root_certs: &[String],
    azure_maa_keys: &[String],
    amd_ark_root_certs: &[String],
) -> Result<TrustAnchors, CloudError> {
    Ok(TrustAnchors {
        gcp_roots: parse_hex_blobs(gcp_ak_root_certs, "--gcp-ak-root-cert")?,
        azure_maa_keys: parse_hex_blobs(azure_maa_keys, "--azure-maa-key")?,
        amd_ark_roots: parse_hex_blobs(amd_ark_root_certs, "--amd-ark-root-cert")?,
        ..TrustAnchors::default()
    })
}

fn parse_hex_blobs(values: &[String], flag: &str) -> Result<Vec<Vec<u8>>, CloudError> {
    values
        .iter()
        .map(|value| {
            let raw = value.strip_prefix("0x").unwrap_or(value);
            hex::decode(raw).map_err(|e| CloudError::Config {
                message: format!("invalid {flag} hex: {e}"),
            })
        })
        .collect()
}

fn measurement_pack_paths(path: &Path) -> (PathBuf, PathBuf) {
    if path.is_dir() {
        return measurement_pack_dir_paths(path);
    }
    let sig_path = if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        path.with_extension("sig")
    } else {
        PathBuf::from(format!("{}.sig", path.display()))
    };
    (path.to_path_buf(), sig_path)
}

fn measurement_pack_dir_paths(path: &Path) -> (PathBuf, PathBuf) {
    (
        path.join("measurement-pack.json"),
        path.join("measurement-pack.sig"),
    )
}

fn local_measurement_pack_dir(data_dir: &Path, name: &str, version: &str) -> PathBuf {
    data_dir
        .join("baseimage")
        .join("measurements")
        .join(encode_image_ref_path_segment(name))
        .join(encode_image_ref_path_segment(version))
}

fn legacy_local_measurement_pack_dir(data_dir: &Path, name: &str, version: &str) -> PathBuf {
    data_dir
        .join("baseimage")
        .join("measurements")
        .join(legacy_measurement_path_segment(name))
        .join(legacy_measurement_path_segment(version))
}

fn legacy_measurement_path_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => ch,
            _ => '_',
        })
        .collect()
}

struct LocalMeasurementPackSelection {
    path: PathBuf,
    detected: bool,
}

fn select_local_measurement_pack_dir(
    data_dir: &Path,
    name: &str,
    version: &str,
) -> Result<LocalMeasurementPackSelection, CloudError> {
    let new_path = local_measurement_pack_dir(data_dir, name, version);
    if measurement_pack_artifact_exists(&new_path)? {
        return Ok(LocalMeasurementPackSelection {
            path: new_path,
            detected: true,
        });
    }

    let legacy_path = legacy_local_measurement_pack_dir(data_dir, name, version);
    if measurement_pack_artifact_exists(&legacy_path)? {
        return Ok(LocalMeasurementPackSelection {
            path: legacy_path,
            detected: true,
        });
    }

    Ok(LocalMeasurementPackSelection {
        path: new_path,
        detected: false,
    })
}

fn measurement_pack_artifact_exists(dir: &Path) -> Result<bool, CloudError> {
    let (json, signature) = measurement_pack_dir_paths(dir);
    Ok(path_exists(&json)? || path_exists(&signature)?)
}

fn path_exists(path: &Path) -> Result<bool, CloudError> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(CloudError::IoPath {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Fetch and verify the portal's TLS attestation, then return a client pinned
/// to the attested self-signed certificate.
pub async fn bootstrap_portal_tls(
    host: &str,
    status_port: u16,
    measurement_policy: Option<MeasurementPolicy>,
    trust_anchors: TrustAnchors,
    tdx_dcap_collateral: TdxDcapCollateralConfig,
    trust_tls_cert_sha256: Option<&str>,
    report_path: Option<&Path>,
) -> Result<VerifiedPortalTls, CloudError> {
    bootstrap_portal_tls_with_trust_config(
        host,
        status_port,
        measurement_policy,
        trust_anchors,
        AzureMaaTrustConfig::default(),
        tdx_dcap_collateral,
        trust_tls_cert_sha256,
        report_path,
    )
    .await
}

/// Fetch and verify the portal's TLS attestation with verifier-side trust
/// material resolved from configured sources before the attestation checks run.
// Keep the independently sourced trust inputs explicit at this protocol boundary.
#[allow(clippy::too_many_arguments)]
pub async fn bootstrap_portal_tls_with_trust_config(
    host: &str,
    status_port: u16,
    measurement_policy: Option<MeasurementPolicy>,
    mut trust_anchors: TrustAnchors,
    azure_maa_trust: AzureMaaTrustConfig,
    tdx_dcap_collateral: TdxDcapCollateralConfig,
    trust_tls_cert_sha256: Option<&str>,
    report_path: Option<&Path>,
) -> Result<VerifiedPortalTls, CloudError> {
    let nonce = random_nonce()?;
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
    let url = format!("https://{host}:{status_port}/tls-attestation?nonce={nonce_b64}");
    let bootstrap = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })?;

    let resp =
        bootstrap
            .get(&url)
            .send()
            .await
            .map_err(|e| CloudError::PortalTlsAttestationFailed {
                message: format!("request failed: {e}"),
            })?;
    let live_peer_cert_der = peer_cert_der(&resp)?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
        let live_hash = format!("0x{}", hex::encode(live_sha));
        let report = endpoint_failure_report(status.as_u16(), &body, &live_hash);
        let written_report_path = if let Some(path) = report_path {
            write_tls_attestation_report(&report, path)?;
            Some(path.to_path_buf())
        } else {
            None
        };
        if trust_tls_cert_sha256 == Some(live_hash.as_str()) {
            let client = pinned_client(&live_peer_cert_der, Duration::from_secs(300))?;
            return Ok(VerifiedPortalTls {
                client,
                identity: VerifiedTlsIdentity {
                    cert_der: live_peer_cert_der,
                    cert_sha256: live_sha,
                    base_image_id: None,
                    platform_profile_id: None,
                    variant_id: None,
                },
                manual_override: Some(TlsManualOverride {
                    live_cert_sha256: live_hash,
                    report,
                    report_path: written_report_path,
                }),
                session_verification: None,
            });
        }
        let report_location = written_report_path
            .as_ref()
            .map(|path| format!("\nfailure report: {}", path.display()))
            .unwrap_or_default();
        return Err(CloudError::PortalTlsAttestationFailed {
            message: format!(
                "portal returned {status}: {body}{report_location}\nmanual override after inspection: --trust-tls-cert-sha256 {live_hash}"
            ),
        });
    }

    let mut response = resp.json::<TlsAttestationResponse>().await.map_err(|e| {
        CloudError::PortalTlsAttestationFailed {
            message: format!("invalid response JSON: {e}"),
        }
    })?;
    // Manual keys remain available until the committed session evidence is
    // fetched. The key that verifies fresh TLS evidence may differ from the
    // key that signed the retained session MAA JWT.
    let manual_azure_maa_keys = trust_anchors.azure_maa_keys.clone();

    if let Err(detail) = resolve_tdx_dcap_collateral(&mut response, &tdx_dcap_collateral).await {
        let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
        let live_hash = format!("0x{}", hex::encode(live_sha));
        let report = tls_preverification_failure_report(
            &response,
            &live_hash,
            "gcp-tdx-dcap-collateral",
            detail,
        );
        return handle_tls_attestation_failure(
            report,
            live_peer_cert_der,
            trust_tls_cert_sha256,
            report_path,
        );
    }

    if let Err(detail) =
        resolve_azure_maa_trust(&response, &azure_maa_trust, &mut trust_anchors).await
    {
        let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
        let live_hash = format!("0x{}", hex::encode(live_sha));
        let report =
            tls_preverification_failure_report(&response, &live_hash, "azure-maa-trust", detail);
        return handle_tls_attestation_failure(
            report,
            live_peer_cert_der,
            trust_tls_cert_sha256,
            report_path,
        );
    }

    let azure_snp_cert_table = if response.platform.cloud.eq_ignore_ascii_case("azure")
        && response.platform.tee.eq_ignore_ascii_case("sev-snp")
    {
        match fetch_azure_snp_cert_table(&response).await {
            Ok(table) => Some(table),
            Err(detail) => {
                let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
                let live_hash = format!("0x{}", hex::encode(live_sha));
                let report = tls_preverification_failure_report(
                    &response,
                    &live_hash,
                    "azure-snp-amd-collateral",
                    detail,
                );
                return handle_tls_attestation_failure(
                    report,
                    live_peer_cert_der,
                    trust_tls_cert_sha256,
                    report_path,
                );
            }
        }
    } else {
        None
    };

    if let Err(detail) = resolve_chain_trust_anchors(
        &response,
        &azure_maa_trust,
        &mut trust_anchors,
        azure_snp_cert_table.as_deref(),
    )
    .await
    {
        let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
        let live_hash = format!("0x{}", hex::encode(live_sha));
        let report = tls_preverification_failure_report(
            &response,
            &live_hash,
            "automata-onchain-trust",
            detail,
        );
        return handle_tls_attestation_failure(
            report,
            live_peer_cert_der,
            trust_tls_cert_sha256,
            report_path,
        );
    }

    let session_verification = measurement_policy.clone().map(|measurement_policy| {
        crate::session::PortalSessionVerificationContext {
            platform: response.platform.clone(),
            measurement_policy,
            trust_anchors: trust_anchors.clone(),
            azure_maa_trust: azure_maa_trust.clone(),
            manual_azure_maa_keys: manual_azure_maa_keys.clone(),
            azure_snp_cert_table: azure_snp_cert_table.clone(),
            tdx_dcap_collateral: response.collateral.get("gcpTdxDcap").cloned(),
        }
    });
    match verify_tls_attestation(VerificationInputs {
        nonce,
        live_peer_cert_der: live_peer_cert_der.clone(),
        response,
        measurement_policy,
        trust_anchors,
    }) {
        Ok(identity) => {
            let client = pinned_client(&identity.cert_der, Duration::from_secs(300))?;
            Ok(VerifiedPortalTls {
                client,
                identity,
                manual_override: None,
                session_verification,
            })
        }
        Err(failure) => handle_tls_attestation_failure(
            *failure.report,
            live_peer_cert_der,
            trust_tls_cert_sha256,
            report_path,
        ),
    }
}

async fn resolve_tdx_dcap_collateral(
    response: &mut TlsAttestationResponse,
    config: &TdxDcapCollateralConfig,
) -> Result<(), String> {
    if !is_tdx(response) || has_gcp_tdx_collateral(&response.collateral) {
        return Ok(());
    }
    let collateral = match &config.source {
        TdxDcapCollateralSource::None => return Ok(()),
        TdxDcapCollateralSource::File(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("read TDX DCAP collateral file {}: {e}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                format!(
                    "parse TDX DCAP collateral file {} as JSON: {e}",
                    path.display()
                )
            })?;
            let collateral_value = value.get("gcpTdxDcap").unwrap_or(&value).clone();
            let _: dcap_qvl::QuoteCollateralV3 = serde_json::from_value(collateral_value.clone())
                .map_err(|e| {
                format!(
                    "parse TDX DCAP collateral file {} as QuoteCollateralV3: {e}",
                    path.display()
                )
            })?;
            collateral_value
        }
        TdxDcapCollateralSource::HttpPccs { url } => {
            let evidence = response
                .tee_evidence
                .as_ref()
                .ok_or_else(|| "GCP TDX response is missing teeEvidence".to_string())?;
            let quote = URL_SAFE_NO_PAD
                .decode(&evidence.report)
                .map_err(|e| format!("decode teeEvidence.report for DCAP collateral fetch: {e}"))?;
            let client = dcap_qvl::collateral::CollateralClient::with_default_http(url.clone())
                .map_err(|e| format!("build DCAP collateral client for {url}: {e:#}"))?;
            serde_json::to_value(
                client
                    .fetch(&quote)
                    .await
                    .map_err(|e| format!("fetch TDX DCAP collateral from {url}: {e:#}"))?,
            )
            .map_err(|e| format!("serialize TDX DCAP collateral from {url}: {e}"))?
        }
        TdxDcapCollateralSource::AutomataOnchainPccs {
            chain,
            rpc_url,
            pcs_dao,
            pck_dao,
            fmspc_tcb_dao,
            enclave_identity_dao,
        } => {
            let chain = chain.as_deref().unwrap_or(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN);
            let rpc_url = rpc_url
                .as_deref()
                .unwrap_or(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL);
            let evidence = response
                .tee_evidence
                .as_ref()
                .ok_or_else(|| "GCP TDX response is missing teeEvidence".to_string())?;
            let quote = URL_SAFE_NO_PAD
                .decode(&evidence.report)
                .map_err(|e| format!("decode teeEvidence.report for Automata PCCS lookup: {e}"))?;
            let daos = resolve_automata_pccs_daos(
                rpc_url,
                pcs_dao.as_deref(),
                pck_dao.as_deref(),
                fmspc_tcb_dao.as_deref(),
                enclave_identity_dao.as_deref(),
            )
            .await
            .map_err(|e| format!("resolve Automata {chain} PCCS DAO set: {e}"))?;
            let collateral = automata_dcap_quote_collateral(rpc_url, daos, &quote)
                .await
                .map_err(|e| format!("fetch GCP TDX DCAP collateral from Automata {chain}: {e}"))?;
            serde_json::to_value(collateral)
                .map_err(|e| format!("serialize Automata {chain} DCAP collateral: {e}"))?
        }
    };
    let mut object = response.collateral.as_object().cloned().unwrap_or_default();
    object.insert("gcpTdxDcap".to_string(), collateral);
    response.collateral = serde_json::Value::Object(object);
    Ok(())
}

async fn resolve_azure_maa_trust(
    response: &TlsAttestationResponse,
    config: &AzureMaaTrustConfig,
    trust_anchors: &mut TrustAnchors,
) -> Result<Vec<AzureMaaTrustKey>, String> {
    if !is_azure_maa_response(response) {
        return Ok(Vec::new());
    }
    if !trust_anchors.azure_maa_keys.is_empty() {
        let binding = response
            .ak_binding
            .as_ref()
            .ok_or_else(|| "Azure response is missing akBinding".to_string())?;
        return select_azure_maa_manual_trust_key(binding, &trust_anchors.azure_maa_keys)
            .map(|key| vec![key]);
    }
    let AzureMaaTrustSource::OnchainRegistry {
        rpc_url,
        session_registry,
    } = &config.source
    else {
        return Ok(Vec::new());
    };

    let jwt = extract_azure_maa_jwt_info(response)?;
    let kid_hash = keccak256(jwt.kid.as_bytes());
    let expected_issuer_hash = keccak256(jwt.issuer.as_bytes());
    let ak_collateral_verifier = resolve_ak_collateral_verifier(rpc_url, session_registry).await?;
    let maa_key_registry = resolve_maa_key_registry(rpc_url, &ak_collateral_verifier).await?;
    let entry = resolve_maa_signing_key(rpc_url, &maa_key_registry, kid_hash).await?;
    if entry.pkcs1_pubkey.is_empty() {
        return Err(format!(
            "MaaKeyRegistry {maa_key_registry} has no signing key for kid hash 0x{}",
            hex::encode(kid_hash)
        ));
    }
    if entry.revoked {
        return Err(format!(
            "MaaKeyRegistry {maa_key_registry} signing key for kid hash 0x{} is revoked",
            hex::encode(kid_hash)
        ));
    }
    if entry.issuer_hash != expected_issuer_hash {
        return Err(format!(
            "MaaKeyRegistry {maa_key_registry} issuer hash mismatch for kid hash 0x{}: JWT issuer {} hashes to 0x{}, registry has 0x{}",
            hex::encode(kid_hash),
            jwt.issuer,
            hex::encode(expected_issuer_hash),
            hex::encode(entry.issuer_hash)
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock is before Unix epoch: {e}"))?
        .as_secs();
    if entry.not_after < now {
        return Err(format!(
            "MaaKeyRegistry {maa_key_registry} signing key for kid hash 0x{} expired at Unix time {} (now {now})",
            hex::encode(kid_hash),
            entry.not_after
        ));
    }

    trust_anchors
        .azure_maa_keys
        .push(entry.pkcs1_pubkey.clone());
    Ok(vec![AzureMaaTrustKey {
        kid: jwt.kid,
        issuer: jwt.issuer,
        not_after: entry.not_after,
        public_key: entry.pkcs1_pubkey,
    }])
}

pub(crate) async fn resolve_committed_session_azure_maa_key(
    binding: &AkBinding,
    config: &AzureMaaTrustConfig,
    manual_keys: &[Vec<u8>],
) -> Result<AzureMaaTrustKey, CloudError> {
    if !manual_keys.is_empty() {
        return select_azure_maa_manual_trust_key(binding, manual_keys).map_err(|detail| {
            committed_session_maa_error("committed_session_maa_signature_invalid", detail)
        });
    }
    let AzureMaaTrustSource::OnchainRegistry {
        rpc_url,
        session_registry,
    } = &config.source
    else {
        return Err(committed_session_maa_error(
            "committed_session_maa_key_not_registered",
            "no MaaKeyRegistry trust source is configured",
        ));
    };

    let jwt = extract_azure_maa_jwt_info_from_binding(binding).map_err(|detail| {
        committed_session_maa_error("committed_session_maa_signature_invalid", detail)
    })?;
    let kid_hash = keccak256(jwt.kid.as_bytes());
    let ak_collateral_verifier = resolve_ak_collateral_verifier(rpc_url, session_registry)
        .await
        .map_err(|detail| {
            committed_session_maa_error("committed_session_maa_key_resolution_failed", detail)
        })?;
    let maa_key_registry = resolve_maa_key_registry(rpc_url, &ak_collateral_verifier)
        .await
        .map_err(|detail| {
            committed_session_maa_error("committed_session_maa_key_resolution_failed", detail)
        })?;
    let entry = resolve_maa_signing_key(rpc_url, &maa_key_registry, kid_hash)
        .await
        .map_err(|detail| {
            committed_session_maa_error("committed_session_maa_key_resolution_failed", detail)
        })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            committed_session_maa_error(
                "committed_session_maa_key_resolution_failed",
                format!("system clock is before Unix epoch: {error}"),
            )
        })?
        .as_secs();
    validate_committed_session_maa_entry(&jwt, &entry, now)?;

    let mut key =
        select_azure_maa_manual_trust_key(binding, std::slice::from_ref(&entry.pkcs1_pubkey))
            .map_err(|detail| {
                committed_session_maa_error("committed_session_maa_signature_invalid", detail)
            })?;
    key.not_after = entry.not_after;
    Ok(key)
}

fn validate_committed_session_maa_entry(
    jwt: &AzureMaaJwtInfo,
    entry: &MaaSigningKeyEntry,
    now: u64,
) -> Result<(), CloudError> {
    if entry.pkcs1_pubkey.is_empty() {
        return Err(committed_session_maa_error(
            "committed_session_maa_key_not_registered",
            format!("no signing key is registered for kid {}", jwt.kid),
        ));
    }
    if entry.revoked {
        return Err(committed_session_maa_error(
            "committed_session_maa_key_revoked",
            format!("signing key for kid {} is revoked", jwt.kid),
        ));
    }
    let expected_issuer_hash = keccak256(jwt.issuer.as_bytes());
    if entry.issuer_hash != expected_issuer_hash {
        return Err(committed_session_maa_error(
            "committed_session_maa_issuer_mismatch",
            format!(
                "JWT issuer {} hashes to 0x{}, registry has 0x{}",
                jwt.issuer,
                hex::encode(expected_issuer_hash),
                hex::encode(entry.issuer_hash)
            ),
        ));
    }
    if now > entry.not_after {
        return Err(committed_session_maa_error(
            "committed_session_maa_key_expired",
            format!(
                "signing key for kid {} expired at Unix time {} (now {now})",
                jwt.kid, entry.not_after
            ),
        ));
    }
    Ok(())
}

fn committed_session_maa_error(code: &str, detail: impl Into<String>) -> CloudError {
    CloudError::PortalSessionVerificationFailed {
        message: format!("{code}: {}", detail.into()),
    }
}

async fn fetch_azure_snp_cert_table(response: &TlsAttestationResponse) -> Result<Vec<u8>, String> {
    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "Azure SNP response is missing teeEvidence".to_string())?;
    let report = URL_SAFE_NO_PAD
        .decode(&evidence.report)
        .map_err(|error| format!("decode Azure SNP report: {error}"))?;
    let request = amd_snp_vcek_request(&report)?;
    let product = amd_kds_product(request.cpuid_family, request.cpuid_model)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("build AMD KDS client: {error}"))?;
    let chip_id = hex::encode(request.chip_id);
    let vcek_url = format!("https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}");
    let vcek = client
        .get(&vcek_url)
        .query(&[
            ("blSPL", request.bootloader),
            ("teeSPL", request.tee),
            ("snpSPL", request.snp),
            ("ucodeSPL", request.microcode),
        ])
        .send()
        .await
        .map_err(|error| format!("fetch AMD {product} VCEK: {error}"))?
        .error_for_status()
        .map_err(|error| format!("fetch AMD {product} VCEK: {error}"))?
        .bytes()
        .await
        .map_err(|error| format!("read AMD {product} VCEK: {error}"))?
        .to_vec();
    let chain_url = format!("https://kdsintf.amd.com/vcek/v1/{product}/cert_chain");
    let chain = client
        .get(&chain_url)
        .send()
        .await
        .map_err(|error| format!("fetch AMD {product} certificate chain: {error}"))?
        .error_for_status()
        .map_err(|error| format!("fetch AMD {product} certificate chain: {error}"))?
        .bytes()
        .await
        .map_err(|error| format!("read AMD {product} certificate chain: {error}"))?;
    let certs = parse_pem_certificates(&chain)?;
    let [ask, ark] = certs.as_slice() else {
        return Err(format!(
            "AMD {product} certificate chain contains {} certificates, expected ASK then ARK",
            certs.len()
        ));
    };
    amd_snp_vcek_cert_table(ark, ask, &vcek)
}

fn amd_kds_product(family: u8, model: u8) -> Result<&'static str, String> {
    match (family, model) {
        (0x19, 0x00..=0x0f) => Ok("Milan"),
        (0x19, 0x10..=0x1f) => Ok("Genoa"),
        _ => Err(format!(
            "unsupported AMD SNP CPUID family 0x{family:02x}, model 0x{model:02x} for KDS lookup"
        )),
    }
}

fn parse_pem_certificates(input: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(input)
        .map_err(|error| format!("AMD certificate chain is not UTF-8 PEM: {error}"))?;
    let mut remaining = text;
    let mut certs = Vec::new();
    while let Some(begin) = remaining.find(BEGIN) {
        let body = &remaining[begin + BEGIN.len()..];
        let end = body
            .find(END)
            .ok_or_else(|| "AMD certificate chain has an unterminated PEM block".to_string())?;
        let encoded = body[..end].lines().map(str::trim).collect::<String>();
        let der = STANDARD
            .decode(encoded)
            .map_err(|error| format!("decode AMD certificate PEM: {error}"))?;
        certs.push(der);
        remaining = &body[end + END.len()..];
    }
    if certs.is_empty() {
        return Err("AMD certificate chain has no PEM certificates".to_string());
    }
    Ok(certs)
}

async fn resolve_chain_trust_anchors(
    response: &TlsAttestationResponse,
    config: &AzureMaaTrustConfig,
    trust_anchors: &mut TrustAnchors,
    azure_snp_cert_table: Option<&[u8]>,
) -> Result<(), String> {
    let AzureMaaTrustSource::OnchainRegistry {
        rpc_url,
        session_registry,
    } = &config.source
    else {
        return Ok(());
    };
    let ak_collateral_verifier = resolve_ak_collateral_verifier(rpc_url, session_registry).await?;

    if response.platform.cloud.eq_ignore_ascii_case("gcp")
        && trust_anchors.gcp_roots.is_empty()
        && trust_anchors.gcp_root_hashes.is_empty()
    {
        let root = extract_gcp_ak_root_cert(response)?;
        let root_hash = keccak256(&root);
        let tpm_attestation = resolve_tpm_attestation(rpc_url, &ak_collateral_verifier).await?;
        if !resolve_verified_ca(rpc_url, &tpm_attestation, root_hash).await? {
            return Err(format!(
                "TpmAttestation {tpm_attestation} does not trust GCP AK root keccak256(root_der)=0x{}",
                hex::encode(root_hash)
            ));
        }
        trust_anchors.gcp_root_hashes.push(root_hash);
    }

    if response.platform.tee.eq_ignore_ascii_case("sev-snp")
        && trust_anchors.amd_ark_roots.is_empty()
        && trust_anchors.amd_ark_root_hashes.is_empty()
    {
        let ark = if response.platform.cloud.eq_ignore_ascii_case("gcp") {
            extract_snp_ark_cert(response)?
        } else if response.platform.cloud.eq_ignore_ascii_case("azure") {
            amd_snp_ark_from_cert_table(azure_snp_cert_table.ok_or_else(|| {
                "Azure SNP response is missing resolved AMD certificate table".to_string()
            })?)?
        } else {
            return Ok(());
        };
        let ark_hash: [u8; 32] = Sha256::digest(&ark).into();
        let tee_verifier = resolve_tee_verifier(rpc_url, session_registry).await?;
        let snp_attestation = resolve_snp_attestation(rpc_url, &tee_verifier).await?;
        if !resolve_snp_root_hash(rpc_url, &snp_attestation, ark_hash).await? {
            return Err(format!(
                "SnpAttestation {snp_attestation} does not trust AMD ARK sha256(ark_der)=0x{}",
                hex::encode(ark_hash)
            ));
        }
        trust_anchors.amd_ark_root_hashes.push(ark_hash);
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct AzureMaaJwtInfo {
    kid: String,
    issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MaaSigningKeyEntry {
    pkcs1_pubkey: Vec<u8>,
    issuer_hash: [u8; 32],
    not_after: u64,
    revoked: bool,
}

async fn resolve_ak_collateral_verifier(
    rpc_url: &str,
    session_registry: &str,
) -> Result<String, String> {
    let calldata = encode_no_arg_call("akCollateralVerifier()");
    let result = eth_call_bytes(
        rpc_url,
        session_registry,
        &calldata,
        "SessionRegistry.akCollateralVerifier",
    )
    .await?;
    decode_address_return(&result, "SessionRegistry.akCollateralVerifier")
}

async fn resolve_maa_key_registry(
    rpc_url: &str,
    ak_collateral_verifier: &str,
) -> Result<String, String> {
    let calldata = encode_no_arg_call("maaKeyRegistry()");
    let result = eth_call_bytes(
        rpc_url,
        ak_collateral_verifier,
        &calldata,
        "AkCollateralVerifier.maaKeyRegistry",
    )
    .await?;
    decode_address_return(&result, "AkCollateralVerifier.maaKeyRegistry")
}

async fn resolve_maa_signing_key(
    rpc_url: &str,
    maa_key_registry: &str,
    kid_hash: [u8; 32],
) -> Result<MaaSigningKeyEntry, String> {
    let calldata = encode_bytes32_arg_call("getMaaSigningKey(bytes32)", kid_hash);
    let result = eth_call_bytes(
        rpc_url,
        maa_key_registry,
        &calldata,
        "MaaKeyRegistry.getMaaSigningKey",
    )
    .await?;
    decode_maa_signing_key_return(&result)
}

async fn resolve_tpm_attestation(
    rpc_url: &str,
    ak_collateral_verifier: &str,
) -> Result<String, String> {
    let calldata = encode_no_arg_call("tpmAttestation()");
    let result = eth_call_bytes(
        rpc_url,
        ak_collateral_verifier,
        &calldata,
        "AkCollateralVerifier.tpmAttestation",
    )
    .await?;
    decode_address_return(&result, "AkCollateralVerifier.tpmAttestation")
}

async fn resolve_tee_verifier(rpc_url: &str, session_registry: &str) -> Result<String, String> {
    let calldata = encode_no_arg_call("teeVerifier()");
    let result = eth_call_bytes(
        rpc_url,
        session_registry,
        &calldata,
        "SessionRegistry.teeVerifier",
    )
    .await?;
    decode_address_return(&result, "SessionRegistry.teeVerifier")
}

async fn resolve_snp_attestation(rpc_url: &str, tee_verifier: &str) -> Result<String, String> {
    let calldata = encode_no_arg_call("snpAttestation()");
    let result = eth_call_bytes(
        rpc_url,
        tee_verifier,
        &calldata,
        "TeeVerifier.snpAttestation",
    )
    .await?;
    decode_address_return(&result, "TeeVerifier.snpAttestation")
}

async fn resolve_verified_ca(
    rpc_url: &str,
    tpm_attestation: &str,
    root_hash: [u8; 32],
) -> Result<bool, String> {
    let calldata = encode_bytes32_arg_call("verifiedCA(bytes32)", root_hash);
    let result = eth_call_bytes(
        rpc_url,
        tpm_attestation,
        &calldata,
        "TpmAttestation.verifiedCA",
    )
    .await?;
    if result.len() != 32 {
        return Err(format!(
            "TpmAttestation.verifiedCA return has invalid length: got {}, need 32",
            result.len()
        ));
    }
    abi_word_bool(&result)
}

async fn resolve_snp_root_hash(
    rpc_url: &str,
    snp_attestation: &str,
    ark_hash: [u8; 32],
) -> Result<bool, String> {
    for processor_model in 0..8u64 {
        let calldata = encode_uint_arg_call("rootCerts(uint8)", processor_model);
        let result = eth_call_bytes(
            rpc_url,
            snp_attestation,
            &calldata,
            "SnpAttestation.rootCerts",
        )
        .await?;
        if result.len() != 32 {
            return Err(format!(
                "SnpAttestation.rootCerts return has invalid length: got {}, need 32",
                result.len()
            ));
        }
        if result.as_slice() == ark_hash {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn eth_call_bytes(
    rpc_url: &str,
    contract: &str,
    calldata: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {
                "to": contract,
                "data": format!("0x{}", hex::encode(calldata)),
                "value": "0x0"
            },
            "latest"
        ]
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("build {label} RPC client: {e}"))?;
    let response: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("call {label} at {rpc_url}: {e}"))?
        .json()
        .await
        .map_err(|e| format!("decode {label} RPC response from {rpc_url}: {e}"))?;
    if let Some(error) = response.get("error") {
        return Err(format!("{label} RPC error from {rpc_url}: {error}"));
    }
    let result = response
        .get("result")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("{label} RPC response missing result: {response}"))?;
    decode_hex_result(result, label)
}

fn extract_azure_maa_jwt_info(
    response: &TlsAttestationResponse,
) -> Result<AzureMaaJwtInfo, String> {
    let binding = response
        .ak_binding
        .as_ref()
        .ok_or_else(|| "Azure response is missing akBinding".to_string())?;
    extract_azure_maa_jwt_info_from_binding(binding)
}

fn extract_azure_maa_jwt_info_from_binding(binding: &AkBinding) -> Result<AzureMaaJwtInfo, String> {
    if !binding.kind.eq_ignore_ascii_case("azure-maa-jwt") {
        return Err(format!(
            "Azure response akBinding kind is {}, expected azure-maa-jwt",
            binding.kind
        ));
    }
    let binding_bytes = URL_SAFE_NO_PAD
        .decode(&binding.data)
        .map_err(|e| format!("decode Azure MAA akBinding data: {e}"))?;
    let binding_json: serde_json::Value = serde_json::from_slice(&binding_bytes)
        .map_err(|e| format!("parse Azure MAA akBinding JSON: {e}"))?;
    let jwt = binding_json
        .get("jwt")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Azure MAA akBinding JSON is missing non-empty jwt".to_string())?;

    let mut parts = jwt.split('.');
    let header = parts
        .next()
        .ok_or_else(|| "Azure MAA JWT is missing header".to_string())?;
    let claims = parts
        .next()
        .ok_or_else(|| "Azure MAA JWT is missing claims".to_string())?;
    let signature = parts
        .next()
        .ok_or_else(|| "Azure MAA JWT is missing signature".to_string())?;
    if parts.next().is_some() || signature.is_empty() {
        return Err("Azure MAA JWT must have exactly three non-empty parts".to_string());
    }

    let header_json = decode_jwt_json(header, "Azure MAA JWT header")?;
    let claims_json = decode_jwt_json(claims, "Azure MAA JWT claims")?;
    let kid = header_json
        .get("kid")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Azure MAA JWT header is missing non-empty kid".to_string())?;
    let issuer = claims_json
        .get("iss")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Azure MAA JWT claims are missing non-empty iss".to_string())?;

    Ok(AzureMaaJwtInfo {
        kid: kid.to_string(),
        issuer: issuer.to_string(),
    })
}

fn extract_gcp_ak_root_cert(response: &TlsAttestationResponse) -> Result<Vec<u8>, String> {
    let binding = response
        .ak_binding
        .as_ref()
        .ok_or_else(|| "GCP response is missing akBinding".to_string())?;
    if !binding.kind.eq_ignore_ascii_case("gcp-cert-chain") {
        return Err(format!(
            "GCP response akBinding kind is {}, expected gcp-cert-chain",
            binding.kind
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(&binding.data)
        .map_err(|e| format!("decode GCP AK cert-chain binding: {e}"))?;
    let encoded_chain: Vec<String> = serde_json::from_slice(&raw)
        .map_err(|e| format!("parse GCP AK cert-chain binding JSON: {e}"))?;
    let mut chain = Vec::with_capacity(encoded_chain.len());
    for (index, encoded) in encoded_chain.iter().enumerate() {
        chain.push(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|e| format!("decode GCP AK cert-chain certificate {index}: {e}"))?,
        );
    }
    chain
        .pop()
        .ok_or_else(|| "GCP AK cert-chain binding is empty".to_string())
}

fn extract_snp_ark_cert(response: &TlsAttestationResponse) -> Result<Vec<u8>, String> {
    const SNP_CERT_TABLE_ARK_GUID: [u8; 16] = [
        0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0,
        0xae,
    ];

    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "GCP SNP response is missing teeEvidence".to_string())?;
    let auxiliary = evidence
        .auxiliary
        .as_ref()
        .ok_or_else(|| "GCP SNP response is missing teeEvidence.auxiliary".to_string())?;
    let auxblob = URL_SAFE_NO_PAD
        .decode(auxiliary)
        .map_err(|e| format!("decode GCP SNP auxiliary cert table: {e}"))?;
    let mut offset = 0usize;
    while offset + 24 <= auxblob.len() {
        let guid_bytes = &auxblob[offset..offset + 16];
        if guid_bytes.iter().all(|byte| *byte == 0) {
            break;
        }
        let cert_offset = u32::from_le_bytes(
            auxblob[offset + 16..offset + 20]
                .try_into()
                .expect("slice length"),
        ) as usize;
        let cert_len = u32::from_le_bytes(
            auxblob[offset + 20..offset + 24]
                .try_into()
                .expect("slice length"),
        ) as usize;
        let cert_end = cert_offset
            .checked_add(cert_len)
            .ok_or_else(|| "SNP cert table entry overflows usize".to_string())?;
        if cert_end > auxblob.len() {
            return Err(format!(
                "SNP cert table entry extends past auxblob: offset={cert_offset} len={cert_len} auxblob={}",
                auxblob.len()
            ));
        }
        if guid_bytes == SNP_CERT_TABLE_ARK_GUID {
            return Ok(auxblob[cert_offset..cert_end].to_vec());
        }
        offset += 24;
    }
    Err("GCP SNP auxiliary cert table is missing ARK certificate".to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AutomataPccsDaos {
    pcs_dao: String,
    pck_dao: String,
    fmspc_tcb_dao: String,
    enclave_identity_dao: String,
}

async fn resolve_automata_pccs_daos(
    rpc_url: &str,
    pcs_dao: Option<&str>,
    pck_dao: Option<&str>,
    fmspc_tcb_dao: Option<&str>,
    enclave_identity_dao: Option<&str>,
) -> Result<AutomataPccsDaos, String> {
    let standard_tcb_eval = if fmspc_tcb_dao.is_none() || enclave_identity_dao.is_none() {
        Some(
            automata_get_standard_tcb_eval(
                rpc_url,
                DEFAULT_TDX_DCAP_AUTOMATA_TCB_EVAL_DAO,
                AUTOMATA_TCB_ID_TDX,
            )
            .await?,
        )
    } else {
        None
    };

    let fmspc_tcb_dao = match fmspc_tcb_dao {
        Some(value) => value.to_string(),
        None => {
            let tcb_eval = standard_tcb_eval.expect("standard TCB eval resolved above");
            automata_default_dao_for_eval(
                DEFAULT_TDX_DCAP_AUTOMATA_FMSPC_TCB_DAOS_BY_EVAL,
                tcb_eval,
                "FMSPC TCB",
            )?
            .to_string()
        }
    };
    let enclave_identity_dao = match enclave_identity_dao {
        Some(value) => value.to_string(),
        None => {
            let tcb_eval = standard_tcb_eval.expect("standard TCB eval resolved above");
            automata_default_dao_for_eval(
                DEFAULT_TDX_DCAP_AUTOMATA_ENCLAVE_IDENTITY_DAOS_BY_EVAL,
                tcb_eval,
                "enclave identity",
            )?
            .to_string()
        }
    };

    Ok(AutomataPccsDaos {
        pcs_dao: pcs_dao
            .unwrap_or(DEFAULT_TDX_DCAP_AUTOMATA_PCS_DAO)
            .to_string(),
        pck_dao: pck_dao
            .unwrap_or(DEFAULT_TDX_DCAP_AUTOMATA_PCK_DAO)
            .to_string(),
        fmspc_tcb_dao,
        enclave_identity_dao,
    })
}

fn automata_default_dao_for_eval<'a>(
    daos: &'a [(u64, &'a str)],
    tcb_eval: u64,
    label: &str,
) -> Result<&'a str, String> {
    daos.iter()
        .find_map(|(eval, addr)| (*eval == tcb_eval).then_some(*addr))
        .ok_or_else(|| {
            format!(
                "no default Automata {label} DAO for standard TDX TCB evaluation number {tcb_eval}"
            )
        })
}

async fn automata_dcap_quote_collateral(
    rpc_url: &str,
    daos: AutomataPccsDaos,
    quote: &[u8],
) -> Result<dcap_qvl::QuoteCollateralV3, String> {
    let parsed = Quote::parse(quote).map_err(|e| format!("parse TDX quote: {e:#}"))?;
    let quote_pck_chain = dcap_qvl::intel::extract_cert_chain(&parsed)
        .map_err(|e| format!("extract PCK certificate chain from quote: {e:#}"))?;
    let pck_ca = dcap_qvl::intel::quote_ca(&parsed)
        .map_err(|e| format!("determine quote PCK CA type: {e:#}"))?;
    let pck_ca_id = match pck_ca {
        PckCa::Processor => AUTOMATA_PCS_CA_PROCESSOR,
        PckCa::Platform => AUTOMATA_PCS_CA_PLATFORM,
    };
    let fmspc =
        dcap_qvl::intel::quote_fmspc(&parsed).map_err(|e| format!("extract quote FMSPC: {e:#}"))?;
    let fmspc = hex::encode_upper(fmspc);

    let (root_ca_cert, root_ca_crl) =
        automata_get_certificate_by_id(rpc_url, &daos.pcs_dao, AUTOMATA_PCS_CA_ROOT).await?;
    let (pck_ca_cert, pck_crl) =
        automata_get_certificate_by_id(rpc_url, &daos.pcs_dao, pck_ca_id).await?;
    let pck_certificate_chain = if quote_pck_chain.len() > 1 {
        pem_chain_from_der(&quote_pck_chain)?
    } else {
        let (intermediate, root) =
            automata_get_pck_cert_chain(rpc_url, &daos.pck_dao, pck_ca_id).await?;
        let mut full_chain = quote_pck_chain;
        full_chain.push(intermediate);
        full_chain.push(root);
        pem_chain_from_der(&full_chain)?
    };

    let (tcb_info, tcb_info_signature) = automata_get_tcb_info(
        rpc_url,
        &daos.fmspc_tcb_dao,
        AUTOMATA_TCB_ID_TDX,
        &fmspc,
        DEFAULT_TDX_DCAP_AUTOMATA_TCB_INFO_VERSION,
    )
    .await?;
    if tcb_info.is_empty() || tcb_info_signature.is_empty() {
        return Err(format!(
            "Automata FMSPC TCB DAO {} returned empty TDX TCB info for FMSPC {fmspc} version {}",
            daos.fmspc_tcb_dao, DEFAULT_TDX_DCAP_AUTOMATA_TCB_INFO_VERSION
        ));
    }
    let (tcb_signing_cert, tcb_root_cert) =
        automata_get_tcb_issuer_chain(rpc_url, &daos.fmspc_tcb_dao).await?;
    let (qe_identity, qe_identity_signature) = automata_get_enclave_identity(
        rpc_url,
        &daos.enclave_identity_dao,
        AUTOMATA_ENCLAVE_ID_TD_QE,
        DEFAULT_TDX_DCAP_AUTOMATA_TD_QE_IDENTITY_VERSION,
    )
    .await?;
    if qe_identity.is_empty() || qe_identity_signature.is_empty() {
        return Err(format!(
            "Automata enclave identity DAO {} returned empty TD_QE identity version {}",
            daos.enclave_identity_dao, DEFAULT_TDX_DCAP_AUTOMATA_TD_QE_IDENTITY_VERSION
        ));
    }
    let (qe_signing_cert, qe_root_cert) =
        automata_get_enclave_identity_issuer_chain(rpc_url, &daos.enclave_identity_dao).await?;

    Ok(dcap_qvl::QuoteCollateralV3 {
        pck_crl_issuer_chain: pem_chain_from_der(&[pck_ca_cert, root_ca_cert.clone()])?,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain: pem_chain_from_der(&[tcb_signing_cert, tcb_root_cert])?,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain: pem_chain_from_der(&[qe_signing_cert, qe_root_cert])?,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: Some(pck_certificate_chain),
    })
}

fn encode_no_arg_call(signature: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&function_selector(signature));
    out
}

fn encode_bytes32_arg_call(signature: &str, arg: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&function_selector(signature));
    out.extend_from_slice(&arg);
    out
}

fn encode_uint_arg_call(signature: &str, arg: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&function_selector(signature));
    out.extend_from_slice(&abi_word_u64(arg));
    out
}

fn encode_two_uint_args_call(signature: &str, first: u64, second: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    out.extend_from_slice(&function_selector(signature));
    out.extend_from_slice(&abi_word_u64(first));
    out.extend_from_slice(&abi_word_u64(second));
    out
}

fn encode_get_tcb_info_call(tcb_type: u64, fmspc: &str, version: u64) -> Vec<u8> {
    let fmspc = fmspc.as_bytes();
    let mut out = Vec::with_capacity(4 + 96 + 32 + fmspc.len().div_ceil(32) * 32);
    out.extend_from_slice(&function_selector("getTcbInfo(uint256,string,uint256)"));
    out.extend_from_slice(&abi_word_u64(tcb_type));
    out.extend_from_slice(&abi_word_u64(96));
    out.extend_from_slice(&abi_word_u64(version));
    out.extend_from_slice(&abi_word_u64(fmspc.len() as u64));
    out.extend_from_slice(fmspc);
    let padding = (32 - (fmspc.len() % 32)) % 32;
    out.resize(out.len() + padding, 0);
    out
}

fn function_selector(signature: &str) -> [u8; 4] {
    let hash = Keccak256::digest(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

async fn automata_get_certificate_by_id(
    rpc_url: &str,
    pcs_dao: &str,
    ca: u64,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let calldata = encode_uint_arg_call("getCertificateById(uint8)", ca);
    let result = eth_call_bytes(rpc_url, pcs_dao, &calldata, "PcsDao.getCertificateById").await?;
    decode_two_bytes_return(&result, "PcsDao.getCertificateById")
}

async fn automata_get_pck_cert_chain(
    rpc_url: &str,
    pck_dao: &str,
    ca: u64,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let calldata = encode_uint_arg_call("getPckCertChain(uint8)", ca);
    let result = eth_call_bytes(rpc_url, pck_dao, &calldata, "PckDao.getPckCertChain").await?;
    decode_two_bytes_return(&result, "PckDao.getPckCertChain")
}

async fn automata_get_standard_tcb_eval(
    rpc_url: &str,
    tcb_eval_dao: &str,
    tcb_id: u64,
) -> Result<u64, String> {
    let calldata = encode_uint_arg_call("standard(uint8)", tcb_id);
    let result = eth_call_bytes(rpc_url, tcb_eval_dao, &calldata, "TcbEvalDao.standard").await?;
    decode_uint_return(&result, "TcbEvalDao.standard")
}

async fn automata_get_tcb_info(
    rpc_url: &str,
    fmspc_tcb_dao: &str,
    tcb_type: u64,
    fmspc: &str,
    version: u64,
) -> Result<(String, Vec<u8>), String> {
    let calldata = encode_get_tcb_info_call(tcb_type, fmspc, version);
    let result =
        eth_call_bytes(rpc_url, fmspc_tcb_dao, &calldata, "FmspcTcbDao.getTcbInfo").await?;
    decode_string_bytes_struct_return(&result, "FmspcTcbDao.getTcbInfo")
}

async fn automata_get_tcb_issuer_chain(
    rpc_url: &str,
    fmspc_tcb_dao: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let calldata = encode_no_arg_call("getTcbIssuerChain()");
    let result = eth_call_bytes(
        rpc_url,
        fmspc_tcb_dao,
        &calldata,
        "FmspcTcbDao.getTcbIssuerChain",
    )
    .await?;
    decode_two_bytes_return(&result, "FmspcTcbDao.getTcbIssuerChain")
}

async fn automata_get_enclave_identity(
    rpc_url: &str,
    enclave_identity_dao: &str,
    id: u64,
    version: u64,
) -> Result<(String, Vec<u8>), String> {
    let calldata = encode_two_uint_args_call("getEnclaveIdentity(uint256,uint256)", id, version);
    let result = eth_call_bytes(
        rpc_url,
        enclave_identity_dao,
        &calldata,
        "EnclaveIdentityDao.getEnclaveIdentity",
    )
    .await?;
    decode_string_bytes_struct_return(&result, "EnclaveIdentityDao.getEnclaveIdentity")
}

async fn automata_get_enclave_identity_issuer_chain(
    rpc_url: &str,
    enclave_identity_dao: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let calldata = encode_no_arg_call("getEnclaveIdentityIssuerChain()");
    let result = eth_call_bytes(
        rpc_url,
        enclave_identity_dao,
        &calldata,
        "EnclaveIdentityDao.getEnclaveIdentityIssuerChain",
    )
    .await?;
    decode_two_bytes_return(&result, "EnclaveIdentityDao.getEnclaveIdentityIssuerChain")
}

fn decode_two_bytes_return(bytes: &[u8], label: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    if bytes.len() < 64 {
        return Err(format!(
            "{label} return is too short: got {}, need at least 64",
            bytes.len()
        ));
    }
    let first_offset = abi_word_usize(&bytes[0..32])?;
    let second_offset = abi_word_usize(&bytes[32..64])?;
    Ok((
        abi_dynamic_bytes(bytes, first_offset, label)?.to_vec(),
        abi_dynamic_bytes(bytes, second_offset, label)?.to_vec(),
    ))
}

fn decode_uint_return(bytes: &[u8], label: &str) -> Result<u64, String> {
    if bytes.len() < 32 {
        return Err(format!(
            "{label} return is too short: got {}, need at least 32",
            bytes.len()
        ));
    }
    let value = abi_word_usize(&bytes[0..32])?;
    u64::try_from(value).map_err(|_| format!("{label} return does not fit u64: {value}"))
}

fn decode_string_bytes_struct_return(
    bytes: &[u8],
    label: &str,
) -> Result<(String, Vec<u8>), String> {
    if bytes.len() < 32 {
        return Err(format!(
            "{label} return is too short: got {}, need at least 32",
            bytes.len()
        ));
    }
    let tuple_offset = abi_word_usize(&bytes[0..32])?;
    if tuple_offset + 64 > bytes.len() {
        return Err(format!(
            "{label} tuple offset {tuple_offset} is out of bounds for {} bytes",
            bytes.len()
        ));
    }
    let tuple = &bytes[tuple_offset..];
    let string_offset = abi_word_usize(&tuple[0..32])?;
    let bytes_offset = abi_word_usize(&tuple[32..64])?;
    let string_start = tuple_offset + string_offset;
    let bytes_start = tuple_offset + bytes_offset;
    let raw_string = abi_dynamic_bytes(bytes, string_start, label)?;
    let string = String::from_utf8(raw_string.to_vec())
        .map_err(|e| format!("{label} string field is not valid UTF-8: {e}"))?;
    Ok((
        string,
        abi_dynamic_bytes(bytes, bytes_start, label)?.to_vec(),
    ))
}

fn abi_dynamic_bytes<'a>(bytes: &'a [u8], offset: usize, label: &str) -> Result<&'a [u8], String> {
    if offset + 32 > bytes.len() {
        return Err(format!(
            "{label} dynamic bytes offset {offset} is out of bounds for {} bytes",
            bytes.len()
        ));
    }
    let len = abi_word_usize(&bytes[offset..offset + 32])?;
    let start = offset + 32;
    let end = start
        .checked_add(len)
        .ok_or_else(|| format!("{label} dynamic bytes length overflows usize"))?;
    if end > bytes.len() {
        return Err(format!(
            "{label} dynamic bytes length {len} is out of bounds for {} bytes",
            bytes.len()
        ));
    }
    Ok(&bytes[start..end])
}

fn pem_chain_from_der(certs: &[Vec<u8>]) -> Result<String, String> {
    if certs.is_empty() {
        return Err("cannot build PEM chain from empty certificate list".to_string());
    }
    let mut out = String::new();
    for cert in certs {
        out.push_str(&pem_cert_from_der(cert));
    }
    Ok(out)
}

fn pem_cert_from_der(cert: &[u8]) -> String {
    let b64 = STANDARD.encode(cert);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn decode_address_return(bytes: &[u8], label: &str) -> Result<String, String> {
    if bytes.len() != 32 {
        return Err(format!(
            "{label} return has invalid ABI address length: got {}, need 32",
            bytes.len()
        ));
    }
    if bytes[..12].iter().any(|byte| *byte != 0) {
        return Err(format!("{label} return has non-zero address padding"));
    }
    let address = &bytes[12..32];
    if address.iter().all(|byte| *byte == 0) {
        return Err(format!("{label} returned the zero address"));
    }
    Ok(format!("0x{}", hex::encode(address)))
}

fn decode_maa_signing_key_return(bytes: &[u8]) -> Result<MaaSigningKeyEntry, String> {
    if bytes.len() < 32 {
        return Err(format!(
            "MaaKeyRegistry.getMaaSigningKey return is too short: got {}, need at least 32",
            bytes.len()
        ));
    }
    let tuple_offset = abi_word_usize(&bytes[0..32])?;
    if tuple_offset + 128 > bytes.len() {
        return Err(format!(
            "MaaKeyRegistry.getMaaSigningKey tuple offset {tuple_offset} is out of bounds for {} bytes",
            bytes.len()
        ));
    }
    let tuple = &bytes[tuple_offset..];
    let pkcs1_offset = abi_word_usize(&tuple[0..32])?;
    let mut issuer_hash = [0u8; 32];
    issuer_hash.copy_from_slice(&tuple[32..64]);
    let not_after = abi_word_to_u64(&tuple[64..96])?;
    let revoked = abi_word_bool(&tuple[96..128])?;
    if tuple_offset + pkcs1_offset + 32 > bytes.len() {
        return Err(format!(
            "MaaKeyRegistry.getMaaSigningKey pkcs1Pubkey offset {pkcs1_offset} is out of bounds for {} bytes",
            bytes.len()
        ));
    }
    let pkcs1_start = tuple_offset + pkcs1_offset;
    let pkcs1_len = abi_word_usize(&bytes[pkcs1_start..pkcs1_start + 32])?;
    let data_start = pkcs1_start + 32;
    let data_end = data_start + pkcs1_len;
    if data_end > bytes.len() {
        return Err(format!(
            "MaaKeyRegistry.getMaaSigningKey pkcs1Pubkey length {pkcs1_len} is out of bounds for {} bytes",
            bytes.len()
        ));
    }
    Ok(MaaSigningKeyEntry {
        pkcs1_pubkey: bytes[data_start..data_end].to_vec(),
        issuer_hash,
        not_after,
        revoked,
    })
}

fn decode_hex_result(result: &str, label: &str) -> Result<Vec<u8>, String> {
    let raw_hex = result.strip_prefix("0x").unwrap_or(result);
    hex::decode(raw_hex).map_err(|e| format!("decode {label} hex: {e}"))
}

fn decode_jwt_json(segment: &str, label: &str) -> Result<serde_json::Value, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("decode {label}: {e}"))?;
    serde_json::from_slice(&raw).map_err(|e| format!("parse {label} JSON: {e}"))
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(input);
    digest.into()
}

fn abi_word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&value.to_be_bytes());
    word
}

fn abi_word_to_u64(word: &[u8]) -> Result<u64, String> {
    if word.len() != 32 {
        return Err("ABI uint word has invalid length".to_string());
    }
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err("ABI uint word is too large for u64".to_string());
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(value))
}

fn abi_word_bool(word: &[u8]) -> Result<bool, String> {
    if word.len() != 32 {
        return Err("ABI bool word has invalid length".to_string());
    }
    if word[..31].iter().any(|byte| *byte != 0) {
        return Err("ABI bool word has non-zero high bytes".to_string());
    }
    match word[31] {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(format!("ABI bool word has invalid value {other}")),
    }
}

fn abi_word_usize(word: &[u8]) -> Result<usize, String> {
    if word.len() != 32 {
        return Err("ABI uint word has invalid length".to_string());
    }
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err("ABI uint word is too large for this verifier".to_string());
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&word[24..32]);
    usize::try_from(u64::from_be_bytes(value))
        .map_err(|_| "ABI uint word does not fit in usize".to_string())
}

fn is_tdx(response: &TlsAttestationResponse) -> bool {
    response.platform.tee.eq_ignore_ascii_case("tdx")
}

fn is_azure_maa_response(response: &TlsAttestationResponse) -> bool {
    response.platform.cloud.eq_ignore_ascii_case("azure")
        && response
            .ak_binding
            .as_ref()
            .is_some_and(|binding| binding.kind.eq_ignore_ascii_case("azure-maa-jwt"))
}

fn is_zero_eth_address(value: &str) -> bool {
    let raw = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    raw.len() == 40 && raw.bytes().all(|byte| byte == b'0')
}

fn has_gcp_tdx_collateral(collateral: &serde_json::Value) -> bool {
    collateral
        .get("gcpTdxDcap")
        .is_some_and(|value| !value.is_null() && !value.as_object().is_some_and(|o| o.is_empty()))
}

fn tls_preverification_failure_report(
    response: &TlsAttestationResponse,
    live_hash: &str,
    check_name: &str,
    detail: String,
) -> VerificationReport {
    VerificationReport {
        checks: vec![VerificationCheck {
            name: check_name.to_string(),
            result: CheckResult::Fail,
            detail: Some(detail),
        }],
        evidence: EvidenceSummary {
            tls_cert_der: Some(response.tls_cert_der.clone()),
            live_tls_cert_sha256: Some(live_hash.to_string()),
            response_tls_cert_sha256: Some(response.tls_cert_sha256.clone()),
            nonce: Some(response.nonce.clone()),
            qualifying_data: Some(response.qualifying_data.clone()),
            cloud: Some(response.platform.cloud.clone()),
            tee: Some(response.platform.tee.clone()),
            machine_type: Some(response.platform.machine_type.clone()),
            tpm_ak_public: Some(response.tpm.ak_public.clone()),
            tpm_quote: Some(response.tpm.quote.clone()),
            tpm_signature: Some(response.tpm.signature.clone()),
            pcrs: response.tpm.pcrs.clone(),
            event_log_hashes: response.tpm.event_log_hashes.clone(),
            tee_evidence_kind: response
                .tee_evidence
                .as_ref()
                .map(|evidence| evidence.kind.clone()),
            tee_evidence_report: response
                .tee_evidence
                .as_ref()
                .map(|evidence| evidence.report.clone()),
            tee_evidence_auxiliary: response
                .tee_evidence
                .as_ref()
                .and_then(|evidence| evidence.auxiliary.clone()),
            ak_binding_kind: response
                .ak_binding
                .as_ref()
                .map(|binding| binding.kind.clone()),
            ak_binding_data: response
                .ak_binding
                .as_ref()
                .map(|binding| binding.data.clone()),
            collateral: response.collateral.clone(),
            ..EvidenceSummary::default()
        },
    }
}

fn handle_tls_attestation_failure(
    report: VerificationReport,
    live_peer_cert_der: Vec<u8>,
    trust_tls_cert_sha256: Option<&str>,
    report_path: Option<&Path>,
) -> Result<VerifiedPortalTls, CloudError> {
    let written_report_path = if let Some(path) = report_path {
        write_tls_attestation_report(&report, path)?;
        Some(path.to_path_buf())
    } else {
        None
    };
    let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
    let live_hash = format!("0x{}", hex::encode(live_sha));
    if trust_tls_cert_sha256 == Some(live_hash.as_str()) {
        let client = pinned_client(&live_peer_cert_der, Duration::from_secs(300))?;
        return Ok(VerifiedPortalTls {
            client,
            identity: VerifiedTlsIdentity {
                cert_der: live_peer_cert_der,
                cert_sha256: live_sha,
                base_image_id: None,
                platform_profile_id: None,
                variant_id: None,
            },
            manual_override: Some(TlsManualOverride {
                live_cert_sha256: live_hash,
                report,
                report_path: written_report_path,
            }),
            session_verification: None,
        });
    }
    let report_json = serde_json::to_string_pretty(&report)
        .unwrap_or_else(|_| "<failed to render report>".to_string());
    let report_location = written_report_path
        .as_ref()
        .map(|path| format!("\nfailure report: {}", path.display()))
        .unwrap_or_default();
    Err(CloudError::PortalTlsAttestationFailed {
        message: format!(
            "{report_json}{report_location}\nmanual override after inspection: --trust-tls-cert-sha256 {live_hash}"
        ),
    })
}

fn peer_cert_der(resp: &reqwest::Response) -> Result<Vec<u8>, CloudError> {
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .map(|der| der.to_vec())
        .ok_or_else(|| CloudError::PortalTlsAttestationFailed {
            message: "bootstrap connection did not expose a peer certificate".to_string(),
        })
}

fn endpoint_failure_report(status: u16, body: &str, live_hash: &str) -> VerificationReport {
    VerificationReport {
        checks: vec![atakit_attestation::VerificationCheck {
            name: "tls-attestation-endpoint".to_string(),
            result: atakit_attestation::CheckResult::Fail,
            detail: Some(format!("portal returned HTTP {status}: {body}")),
        }],
        evidence: atakit_attestation::EvidenceSummary {
            live_tls_cert_sha256: Some(live_hash.to_string()),
            ..atakit_attestation::EvidenceSummary::default()
        },
    }
}

pub fn tls_manual_override_message(verified: &VerifiedPortalTls) -> Option<String> {
    let override_info = verified.manual_override.as_ref()?;
    let report_json = serde_json::to_string_pretty(&override_info.report)
        .unwrap_or_else(|_| "<failed to render report>".to_string());
    Some(format!(
        "TLS attestation failed, but manual override accepted for live certificate {}.{}\n{}",
        override_info.live_cert_sha256,
        override_info
            .report_path
            .as_ref()
            .map(|path| format!("\nFailure report: {}", path.display()))
            .unwrap_or_default(),
        report_json
    ))
}

fn pinned_client(cert_der: &[u8], timeout: Duration) -> Result<reqwest::Client, CloudError> {
    let cert = reqwest::Certificate::from_der(cert_der).map_err(|e| {
        CloudError::PortalTlsAttestationFailed {
            message: format!("invalid attested TLS certificate: {e}"),
        }
    })?;
    reqwest::Client::builder()
        .add_root_certificate(cert)
        // Portal certs are issued for `atakit-portal`, while clients usually
        // connect by cloud IP. Cert validity is pinned by the attestation hash;
        // only hostname verification is relaxed here.
        .danger_accept_invalid_hostnames(true)
        .timeout(timeout)
        .build()
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })
}

/// Build the legacy portal client that accepts any self-signed TLS certificate.
///
/// This is intentionally explicit and should only be used by callers that have
/// surfaced an unsafe operator override. It performs no TLS attestation, no
/// certificate pinning, and no hostname validation.
pub fn unsafe_portal_client(timeout: Duration) -> Result<reqwest::Client, CloudError> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(timeout)
        .build()
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })
}

pub(crate) fn random_nonce() -> Result<[u8; 32], CloudError> {
    let mut nonce = [0u8; 32];
    let mut file = std::fs::File::open("/dev/urandom").map_err(|e| CloudError::IoPath {
        path: "/dev/urandom".into(),
        source: e,
    })?;
    file.read_exact(&mut nonce)
        .map_err(|e| CloudError::IoPath {
            path: "/dev/urandom".into(),
            source: e,
        })?;
    Ok(nonce)
}

/// Poll the portal status endpoint with exponential backoff.
pub async fn wait_for_portal(
    host: &str,
    status_port: u16,
    timeout_secs: u64,
) -> Result<(), CloudError> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })?;

    wait_for_portal_with_client(&client, host, status_port, timeout_secs).await
}

pub async fn wait_for_portal_with_client(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
    timeout_secs: u64,
) -> Result<(), CloudError> {
    let url = format!("https://{host}:{status_port}/status");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut interval = Duration::from_secs(2);
    let max_interval = Duration::from_secs(30);

    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("portal is ready at {host}:{status_port}");
                return Ok(());
            }
            Ok(resp) => {
                tracing::debug!("portal not ready yet (status {})", resp.status());
            }
            Err(e) => {
                tracing::debug!("portal not reachable: {e}");
            }
        }

        if tokio::time::Instant::now() + interval > deadline {
            return Err(CloudError::PortalTimeout {
                address: format!("{host}:{status_port}"),
                timeout_secs,
            });
        }

        tokio::time::sleep(interval).await;
        interval = (interval * 2).min(max_interval);
    }
}

/// Terminal state reached by the portal after `/init`.
#[derive(Debug, Clone)]
pub enum PortalTerminalState {
    /// Portal reached the terminal Running state: workload initialised
    /// and chain registration (when required) completed.
    Running,
    /// Portal reached terminal Failed; `detail` is the portal-reported reason.
    Failed { detail: String },
    /// Portal reached CleanHalt before Running — workload exited cleanly
    /// before becoming ready. Unexpected during deploy.
    CleanHalt { detail: String },
}

/// Poll the portal `/status` endpoint until it reaches a terminal state
/// (Running, Failed, or CleanHalt) or `timeout_secs` elapses.
///
/// `on_transition` fires once per observed `state` change with the new
/// state name, so callers can render progress. Library crates can't print
/// directly; the CLI passes a closure that writes to stderr.
pub async fn wait_for_portal_terminal(
    host: &str,
    status_port: u16,
    timeout_secs: u64,
    on_transition: impl FnMut(&str),
) -> Result<PortalTerminalState, CloudError> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })?;

    wait_for_portal_terminal_with_client(&client, host, status_port, timeout_secs, on_transition)
        .await
}

pub async fn wait_for_portal_terminal_with_client(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
    timeout_secs: u64,
    mut on_transition: impl FnMut(&str),
) -> Result<PortalTerminalState, CloudError> {
    let url = format!("https://{host}:{status_port}/status");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let interval = Duration::from_secs(2);
    let mut last_state: Option<String> = None;

    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        let state = body
                            .get("state")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_string();
                        let detail = body
                            .get("detail")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_string();
                        if last_state.as_deref() != Some(state.as_str()) && !state.is_empty() {
                            on_transition(&state);
                            last_state = Some(state.clone());
                        }
                        match state.as_str() {
                            "Running" => return Ok(PortalTerminalState::Running),
                            "Failed" => return Ok(PortalTerminalState::Failed { detail }),
                            "CleanHalt" => return Ok(PortalTerminalState::CleanHalt { detail }),
                            _ => {}
                        }
                    }
                    Err(e) => {
                        tracing::debug!("portal status JSON parse failed: {e}");
                    }
                }
            }
            Ok(resp) => {
                tracing::debug!("portal status not ready yet (HTTP {})", resp.status());
            }
            Err(e) => {
                tracing::debug!("portal status not reachable: {e}");
            }
        }

        if tokio::time::Instant::now() + interval > deadline {
            return Err(CloudError::PortalTimeout {
                address: format!("{host}:{status_port}"),
                timeout_secs,
            });
        }
        tokio::time::sleep(interval).await;
    }
}

/// POST /init to the portal with workload archive and configuration.
///
/// Always uses HTTPS. The portal serves a self-signed certificate,
/// so we always accept invalid certs for the init request.
pub async fn post_portal_init(
    host: &str,
    status_port: u16,
    init_port: u16,
    archive_path: &str,
    unmeasured_tar: Option<&[u8]>,
    init_config: &InitConfig,
) -> Result<(), CloudError> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })?;
    let progress = NullReporter;
    post_portal_init_with_client(
        &client,
        host,
        status_port,
        init_port,
        archive_path,
        unmeasured_tar,
        init_config,
        Duration::from_secs(300),
        &progress,
    )
    .await
}

// Keep transport, payload, timeout, and progress controls explicit for callers.
#[allow(clippy::too_many_arguments)]
pub async fn post_portal_init_with_client(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
    init_port: u16,
    archive_path: &str,
    unmeasured_tar: Option<&[u8]>,
    init_config: &InitConfig,
    upload_timeout: Duration,
    progress: &dyn ProgressReporter,
) -> Result<(), CloudError> {
    verify_portal_init_schema(client, host, status_port).await?;
    let url = format!("https://{host}:{init_port}/init");
    // Read archive file.
    let archive_bytes = tokio::fs::read(archive_path)
        .await
        .map_err(|e| CloudError::IoPath {
            path: archive_path.into(),
            source: e,
        })?;

    // Build config JSON.
    let config_json = build_portal_config_json(init_config);
    let config_bytes = config_json.to_string().into_bytes();
    let payload_bytes = archive_bytes.len() as u64
        + config_bytes.len() as u64
        + unmeasured_tar.map_or(0, |u| u.len() as u64);

    // Build multipart form.
    let mut form = reqwest::multipart::Form::new()
        .part(
            "atawl",
            reqwest::multipart::Part::bytes(archive_bytes)
                .file_name("archive.atawl")
                .mime_str("application/octet-stream")
                .map_err(|e| CloudError::Http {
                    message: e.to_string(),
                })?,
        )
        .part(
            "config",
            reqwest::multipart::Part::bytes(config_bytes)
                .file_name("config.json")
                .mime_str("application/json")
                .map_err(|e| CloudError::Http {
                    message: e.to_string(),
                })?,
        );

    if let Some(unmeasured) = unmeasured_tar {
        form = form.part(
            "unmeasured-data",
            reqwest::multipart::Part::bytes(unmeasured.to_vec())
                .file_name("unmeasured.tar.gz")
                .mime_str("application/octet-stream")
                .map_err(|e| CloudError::Http {
                    message: e.to_string(),
                })?,
        );
    }

    let boundary = form.boundary().to_string();
    let progress_handle: Arc<dyn ProgressHandle> = progress
        .create(
            &format!(
                "Uploading /init multipart payload ({} payload bytes)",
                payload_bytes
            ),
            0,
        )
        .into();
    let stream_progress = Arc::clone(&progress_handle);
    let body_stream = form.into_stream().inspect_ok(move |chunk| {
        stream_progress.inc(chunk.len() as u64);
    });

    let send_result = client
        .post(&url)
        .timeout(upload_timeout)
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(reqwest::Body::wrap_stream(body_stream))
        .send()
        .await;
    progress_handle.finish();

    let resp = send_result.map_err(|e| CloudError::PortalInitFailed {
        message: format!("request failed: {e}"),
    })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(CloudError::PortalInitFailed {
            message: format!("portal returned {status}: {body}"),
        });
    }

    tracing::info!("workload initialized on CVM at {host}:{init_port}");
    Ok(())
}

async fn verify_portal_init_schema(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
) -> Result<(), CloudError> {
    let url = format!("https://{host}:{status_port}/status");
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| CloudError::PortalInitFailed {
            message: format!("read portal init schema from {url}: {error}"),
        })?;
    let status = response
        .error_for_status()
        .map_err(|error| CloudError::PortalInitFailed {
            message: format!("read portal init schema from {url}: {error}"),
        })?
        .json::<serde_json::Value>()
        .await
        .map_err(|error| CloudError::PortalInitFailed {
            message: format!("parse portal status from {url}: {error}"),
        })?;
    validate_portal_init_schema(&status)
}

fn validate_portal_init_schema(status: &serde_json::Value) -> Result<(), CloudError> {
    let observed = status
        .get("init_schema_version")
        .and_then(|value| value.as_u64());
    if observed == Some(u64::from(INIT_SCHEMA_VERSION)) {
        return Ok(());
    }
    Err(CloudError::PortalInitFailed {
        message: format!(
            "portal does not support required init schema version {INIT_SCHEMA_VERSION}; observed {}",
            observed
                .map(|value| value.to_string())
                .unwrap_or_else(|| "no init_schema_version".to_string())
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use rsa::rand_core::OsRng;
    use rsa::RsaPrivateKey;
    use signature::SignatureEncoding;

    fn signed_maa_binding(kid: &str, issuer: &str) -> (AkBinding, Vec<u8>) {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public = private
            .to_public_key()
            .to_pkcs1_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"alg": "RS256", "kid": kid})
                .to_string()
                .as_bytes(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": issuer,
                "x-ms-attestation-type": "tdxvm",
                "x-ms-compliance-status": "azure-compliant-cvm"
            })
            .to_string()
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let signature = RsaSigningKey::<Sha256>::new(private).sign(signing_input.as_bytes());
        let jwt = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_vec())
        );
        let data = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"jwt": jwt, "hclVarData": ""})
                .to_string()
                .as_bytes(),
        );
        (
            AkBinding {
                kind: "azure-maa-jwt".into(),
                data,
            },
            public,
        )
    }

    fn sample_config() -> InitConfig {
        InitConfig {
            platform: "gcp".to_string(),
            chain: InitChainConfig {
                rpc_url: "https://rpc.example.com".to_string(),
                session_registry: "0xSESS".to_string(),
                workload_registry: "0xWORK".to_string(),
                base_image_registry: "0xBASE".to_string(),
                registration: None,
                chain_id: None,
                tee_backend: "auto".to_string(),
                prover: Some(InitProverConfig {
                    backend: "sp1".to_string(),
                    execution: "network".to_string(),
                    endpoint: "https://prover.example.com".to_string(),
                    credential: Some("prover-key".to_string()),
                    options: BTreeMap::new(),
                }),
            },
            owner_operations: atakit_config::OwnerOperationsConfig::default(),
            owner_key: InitKeyConfig {
                mode: "provisioned".to_string(),
                key_type: "es256k".to_string(),
                private_key: Some("0xOWNER".to_string()),
            },
            gas_wallet: InitKeyConfig {
                mode: "self_generated".to_string(),
                key_type: "es256k".to_string(),
                private_key: None,
            },
            prover_credential: Some(InitKeyConfig {
                mode: "provisioned".to_string(),
                key_type: "es256k".to_string(),
                private_key: Some("0xSP1".to_string()),
            }),
            disks: BTreeMap::new(),
        }
    }

    /// Build a declared-disk map: each `(name, &[methods])` becomes
    /// `name -> unlock_method`.
    fn declared(disks: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        disks
            .iter()
            .map(|(name, methods)| {
                (
                    name.to_string(),
                    methods.iter().map(|m| m.to_string()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn automata_pccs_abi_encoding_and_return_decoding() {
        let calldata = encode_uint_arg_call("getCertificateById(uint8)", 1);
        assert_eq!(
            &calldata[0..4],
            &function_selector("getCertificateById(uint8)")
        );
        assert_eq!(&calldata[4..36], &abi_word_u64(1));

        let mut returned = Vec::new();
        returned.extend_from_slice(&abi_word_u64(64));
        returned.extend_from_slice(&abi_word_u64(128));
        returned.extend_from_slice(&abi_word_u64(3));
        returned.extend_from_slice(&[0x11, 0x22, 0x33]);
        returned.extend_from_slice(&[0u8; 29]);
        returned.extend_from_slice(&abi_word_u64(2));
        returned.extend_from_slice(&[0x44, 0x55]);
        returned.extend_from_slice(&[0u8; 30]);

        let decoded = decode_two_bytes_return(&returned, "test").expect("decode tuple");
        assert_eq!(decoded.0, vec![0x11, 0x22, 0x33]);
        assert_eq!(decoded.1, vec![0x44, 0x55]);
    }

    #[test]
    fn automata_pccs_decodes_dynamic_string_bytes_struct() {
        let mut returned = Vec::new();
        returned.extend_from_slice(&abi_word_u64(32));
        returned.extend_from_slice(&abi_word_u64(64));
        returned.extend_from_slice(&abi_word_u64(128));
        returned.extend_from_slice(&abi_word_u64(5));
        returned.extend_from_slice(b"{json");
        returned.extend_from_slice(&[0u8; 27]);
        returned.extend_from_slice(&abi_word_u64(3));
        returned.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        returned.extend_from_slice(&[0u8; 29]);

        let decoded = decode_string_bytes_struct_return(&returned, "test").expect("decode struct");
        assert_eq!(decoded.0, "{json");
        assert_eq!(decoded.1, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn automata_pccs_default_config_defers_versioned_daos_to_tcb_eval() {
        let cfg = tdx_dcap_collateral_config(None, None, None, None).expect("collateral config");
        match cfg.source {
            TdxDcapCollateralSource::AutomataOnchainPccs {
                chain,
                rpc_url,
                pcs_dao,
                pck_dao,
                fmspc_tcb_dao,
                enclave_identity_dao,
            } => {
                assert_eq!(chain.as_deref(), Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN));
                assert_eq!(rpc_url.as_deref(), Some(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL));
                assert_eq!(pcs_dao.as_deref(), Some(DEFAULT_TDX_DCAP_AUTOMATA_PCS_DAO));
                assert_eq!(pck_dao.as_deref(), Some(DEFAULT_TDX_DCAP_AUTOMATA_PCK_DAO));
                assert!(fmspc_tcb_dao.is_none());
                assert!(enclave_identity_dao.is_none());
            }
            other => panic!("expected Automata on-chain PCCS, got {other:?}"),
        }
    }

    #[test]
    fn automata_pccs_eval_19_defaults_to_current_hoodi_versioned_daos() {
        assert_eq!(
            automata_default_dao_for_eval(
                DEFAULT_TDX_DCAP_AUTOMATA_FMSPC_TCB_DAOS_BY_EVAL,
                19,
                "FMSPC TCB",
            )
            .expect("fmspc dao"),
            "0x74A0b849030BC8afaAfFf8F46126E3c13E365C7b",
        );
        assert_eq!(
            automata_default_dao_for_eval(
                DEFAULT_TDX_DCAP_AUTOMATA_ENCLAVE_IDENTITY_DAOS_BY_EVAL,
                19,
                "enclave identity",
            )
            .expect("enclave identity dao"),
            "0x299c1ae8101aF3d3483793dAfFe8ea9E098D7E17",
        );
    }

    #[test]
    fn automata_pccs_decode_uint_return() {
        let returned = abi_word_u64(19);
        assert_eq!(decode_uint_return(&returned, "standard").unwrap(), 19);
        assert!(decode_uint_return(&returned[..31], "standard")
            .unwrap_err()
            .contains("too short"));
    }

    #[test]
    fn azure_maa_trust_config_uses_chain_when_registration_enabled() {
        let mut cfg = sample_config();
        cfg.chain.rpc_url = "https://rpc.example.com".to_string();
        cfg.chain.session_registry = "0x1111111111111111111111111111111111111111".to_string();

        let trust = azure_maa_trust_config_from_init_chain(&cfg.chain);
        match trust.source {
            AzureMaaTrustSource::OnchainRegistry {
                rpc_url,
                session_registry,
            } => {
                assert_eq!(rpc_url, "https://rpc.example.com");
                assert_eq!(
                    session_registry,
                    "0x1111111111111111111111111111111111111111"
                );
            }
            AzureMaaTrustSource::None => panic!("expected on-chain Azure MAA trust config"),
        }
    }

    #[test]
    fn azure_maa_trust_config_uses_chain_even_for_off_registration() {
        let mut cfg = sample_config();
        cfg.chain.registration = Some("off".to_string());
        cfg.chain.rpc_url = "https://rpc.example.com".to_string();
        cfg.chain.session_registry = "0x1111111111111111111111111111111111111111".to_string();

        let trust = azure_maa_trust_config_from_init_chain(&cfg.chain);
        match trust.source {
            AzureMaaTrustSource::OnchainRegistry {
                rpc_url,
                session_registry,
            } => {
                assert_eq!(rpc_url, "https://rpc.example.com");
                assert_eq!(
                    session_registry,
                    "0x1111111111111111111111111111111111111111"
                );
            }
            AzureMaaTrustSource::None => {
                panic!("expected on-chain trust config despite registration=off")
            }
        }
    }

    #[test]
    fn azure_maa_jwt_info_is_extracted_from_binding() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"kid-1"}"#);
        let claims = URL_SAFE_NO_PAD.encode(r#"{"iss":"https://issuer.example"}"#);
        let jwt = format!("{header}.{claims}.signature");
        let binding = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "jwt": jwt,
                "hclVarData": ""
            })
            .to_string(),
        );
        let response = TlsAttestationResponse {
            format: 1,
            nonce: String::new(),
            tls_cert_der: String::new(),
            tls_cert_sha256: String::new(),
            qualifying_data: String::new(),
            platform: atakit_attestation::PlatformEvidence {
                cloud: "azure".to_string(),
                tee: "tdx".to_string(),
                machine_type: String::new(),
            },
            tpm: atakit_attestation::TpmEvidence {
                ak_public: String::new(),
                quote: String::new(),
                signature: String::new(),
                pcrs: vec![],
                event_log_hashes: vec![],
            },
            tee_evidence: None,
            ak_binding: Some(atakit_attestation::AkBinding {
                kind: "azure-maa-jwt".to_string(),
                data: binding,
            }),
            collateral: serde_json::Value::Null,
        };

        let info = extract_azure_maa_jwt_info(&response).unwrap();
        assert_eq!(info.kid, "kid-1");
        assert_eq!(info.issuer, "https://issuer.example");
    }

    #[tokio::test]
    async fn committed_session_selects_its_own_manual_maa_key() {
        let (session_binding, session_key) =
            signed_maa_binding("session-key-a", "https://issuer.example");
        let (tls_binding, tls_key) = signed_maa_binding("tls-key-b", "https://issuer.example");
        let manual_keys = vec![tls_key.clone(), session_key.clone()];

        let fresh_tls = select_azure_maa_manual_trust_key(&tls_binding, &manual_keys).unwrap();
        assert_eq!(fresh_tls.kid, "tls-key-b");
        assert_eq!(fresh_tls.public_key, tls_key);

        let committed = resolve_committed_session_azure_maa_key(
            &session_binding,
            &AzureMaaTrustConfig::default(),
            &manual_keys,
        )
        .await
        .unwrap();
        assert_eq!(committed.kid, "session-key-a");
        assert_eq!(committed.public_key, session_key);
    }

    #[test]
    fn committed_session_registry_maa_failures_have_exact_codes() {
        let jwt = AzureMaaJwtInfo {
            kid: "session-key-a".into(),
            issuer: "https://issuer.example".into(),
        };
        let issuer_hash = keccak256(jwt.issuer.as_bytes());
        let valid = MaaSigningKeyEntry {
            pkcs1_pubkey: vec![1],
            issuer_hash,
            not_after: 200,
            revoked: false,
        };

        let mut entry = valid.clone();
        entry.pkcs1_pubkey.clear();
        assert!(validate_committed_session_maa_entry(&jwt, &entry, 100)
            .unwrap_err()
            .to_string()
            .contains("committed_session_maa_key_not_registered"));

        let mut entry = valid.clone();
        entry.revoked = true;
        assert!(validate_committed_session_maa_entry(&jwt, &entry, 100)
            .unwrap_err()
            .to_string()
            .contains("committed_session_maa_key_revoked"));

        let mut entry = valid.clone();
        entry.not_after = 99;
        assert!(validate_committed_session_maa_entry(&jwt, &entry, 100)
            .unwrap_err()
            .to_string()
            .contains("committed_session_maa_key_expired"));

        let mut entry = valid;
        entry.issuer_hash = [0x55; 32];
        assert!(validate_committed_session_maa_entry(&jwt, &entry, 100)
            .unwrap_err()
            .to_string()
            .contains("committed_session_maa_issuer_mismatch"));
    }

    #[tokio::test]
    async fn committed_session_rejects_invalid_manual_maa_signature() {
        let (session_binding, _) = signed_maa_binding("session-key-a", "https://issuer.example");
        let (_, wrong_key) = signed_maa_binding("tls-key-b", "https://issuer.example");

        let error = resolve_committed_session_azure_maa_key(
            &session_binding,
            &AzureMaaTrustConfig::default(),
            &[wrong_key],
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("committed_session_maa_signature_invalid"));
    }

    #[test]
    fn maa_signing_key_return_decodes_dynamic_struct() {
        let pkcs1 = vec![0x30, 0x82, 0x01, 0x0a];
        let issuer_hash = [0x42u8; 32];
        let mut returned = Vec::new();
        returned.extend_from_slice(&abi_word_u64(32));
        returned.extend_from_slice(&abi_word_u64(128));
        returned.extend_from_slice(&issuer_hash);
        returned.extend_from_slice(&abi_word_u64(1_811_611_165));
        returned.extend_from_slice(&abi_word_u64(0));
        returned.extend_from_slice(&abi_word_u64(pkcs1.len() as u64));
        returned.extend_from_slice(&pkcs1);
        returned.extend_from_slice(&[0; 28]);

        let decoded = decode_maa_signing_key_return(&returned).unwrap();
        assert_eq!(decoded.pkcs1_pubkey, pkcs1);
        assert_eq!(decoded.issuer_hash, issuer_hash);
        assert_eq!(decoded.not_after, 1_811_611_165);
        assert!(!decoded.revoked);
    }

    #[test]
    fn portal_config_json_shape() {
        let json = build_portal_config_json(&sample_config());

        assert_eq!(json["format"], INIT_SCHEMA_VERSION);
        assert_eq!(json["platform"]["declared"], "gcp");
        assert_eq!(json["chain"]["rpc_url"], "https://rpc.example.com");
        assert_eq!(json["chain"]["contracts"]["session_registry"], "0xSESS");
        assert_eq!(json["chain"]["contracts"]["workload_registry"], "0xWORK");
        assert_eq!(json["chain"]["contracts"]["base_image_registry"], "0xBASE");
        assert!(json["chain"].get("transaction_submitter").is_none());
        assert!(json["chain"].get("expire_offset").is_none());
        assert_eq!(json["owner_operations"]["op_expiry_seconds"], 300);
        assert_eq!(json["owner_operations"]["challenge_expiry_seconds"], 60);
        assert_eq!(json["owner_key"]["mode"], "provisioned");
        assert_eq!(json["owner_key"]["type"], "es256k");
        assert_eq!(json["owner_key"]["private_key"], "0xOWNER");
        assert_eq!(json["gas_wallet"]["mode"], "self_generated");
        assert_eq!(json["gas_wallet"]["type"], "es256k");
        assert!(json["gas_wallet"].get("private_key").is_none());
        assert_eq!(json["prover_credential"]["mode"], "provisioned");
        assert_eq!(json["prover_credential"]["type"], "es256k");
        assert_eq!(json["prover_credential"]["private_key"], "0xSP1");
        assert!(json.get("sp1_payer").is_none());
        assert_eq!(json["prover"]["backend"], "sp1");
        assert_eq!(json["prover"]["execution"], "network");

        // Optional chain fields remain absent when they are not configured.
        assert!(json["chain"].get("registration").is_none());
        assert!(json["chain"].get("chain_id").is_none());
        assert!(json["chain"].get("proving_strategy").is_none());

        // No disk passphrases → no `disks` key at all (pre-field JSON).
        assert!(json.get("disks").is_none());
    }

    #[test]
    fn portal_config_json_emits_disk_passphrases_when_present() {
        let mut cfg = sample_config();
        cfg.disks
            .insert("secrets".to_string(), "hunter2".to_string());
        cfg.disks
            .insert("appdata".to_string(), "correct horse".to_string());

        let json = build_portal_config_json(&cfg);
        assert_eq!(json["disks"]["secrets"]["passphrase"], "hunter2");
        assert_eq!(json["disks"]["appdata"]["passphrase"], "correct horse");
        // Exactly the per-disk passphrase object, nothing else.
        assert_eq!(json["disks"]["secrets"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn parse_disk_passphrases_accepts_declared_names() {
        let declared = declared(&[("secrets", &["passphrase"]), ("appdata", &["passphrase"])]);
        let raw = vec![
            "secrets=hunter2".to_string(),
            "appdata=correct horse".to_string(),
        ];
        let parsed = parse_disk_passphrases(&raw, &declared).unwrap();
        assert_eq!(parsed.get("secrets").map(String::as_str), Some("hunter2"));
        assert_eq!(
            parsed.get("appdata").map(String::as_str),
            Some("correct horse")
        );
    }

    #[test]
    fn parse_disk_passphrases_rejects_undeclared_disk() {
        let declared = declared(&[("data", &["tpm"])]);
        let err = parse_disk_passphrases(&["typo=x".to_string()], &declared).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("typo"), "got: {msg}");
        assert!(msg.contains("not declared"), "got: {msg}");
    }

    #[test]
    fn parse_disk_passphrases_rejects_orphan_passphrase() {
        // A passphrase for a disk that doesn't use passphrase unlock.
        let declared = declared(&[("data", &["tpm"])]);
        let err = parse_disk_passphrases(&["data=x".to_string()], &declared).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("data"), "got: {msg}");
        assert!(msg.contains("does not use passphrase"), "got: {msg}");
    }

    #[test]
    fn parse_disk_passphrases_rejects_missing_passphrase() {
        // A disk declares passphrase unlock but the operator supplied none.
        let declared = declared(&[("secrets", &["passphrase"])]);
        let err = parse_disk_passphrases(&[], &declared).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("secrets"), "got: {msg}");
        assert!(msg.contains("requires a passphrase"), "got: {msg}");
        assert!(
            msg.contains("--disk-passphrase secrets="),
            "expected the fix hint: {msg}"
        );
    }

    #[test]
    fn parse_disk_passphrases_accepts_tpm_passphrase_combo() {
        // tpm+passphrase disk: the passphrase keyslot must still be supplied.
        let declared = declared(&[("appdata", &["tpm", "passphrase"])]);
        let parsed = parse_disk_passphrases(&["appdata=x".to_string()], &declared).unwrap();
        assert_eq!(parsed.get("appdata").map(String::as_str), Some("x"));
    }

    #[test]
    fn parse_disk_passphrases_value_may_contain_equals() {
        let declared = declared(&[("secrets", &["passphrase"])]);
        let parsed = parse_disk_passphrases(&["secrets=a=b=c".to_string()], &declared).unwrap();
        assert_eq!(parsed.get("secrets").map(String::as_str), Some("a=b=c"));
    }

    #[test]
    fn parse_disk_passphrases_rejects_malformed_empty_and_duplicate() {
        let declared = declared(&[("secrets", &["passphrase"])]);
        // No '='.
        assert!(parse_disk_passphrases(&["secrets".to_string()], &declared).is_err());
        // Empty value.
        assert!(parse_disk_passphrases(&["secrets=".to_string()], &declared).is_err());
        // Empty name.
        assert!(parse_disk_passphrases(&["=x".to_string()], &declared).is_err());
        // Duplicate name.
        assert!(parse_disk_passphrases(
            &["secrets=a".to_string(), "secrets=b".to_string()],
            &declared
        )
        .is_err());
    }

    #[test]
    fn parse_disk_passphrases_empty_input_is_empty_map() {
        // No passphrase-requiring disks → empty input is valid.
        let declared = declared(&[("scratch", &["tpm"])]);
        assert!(parse_disk_passphrases(&[], &declared).unwrap().is_empty());
    }

    fn measurement_pack_json(name: &str, version: &str) -> String {
        format!(
            r#"{{"baseImage":{{"id":"0x{}","name":"{name}","version":"{version}"}},"profiles":[],"publishedAt":"2026-07-07T00:00:00Z","revision":1,"schema":"atakit.measurement-pack.v1"}}"#,
            "00".repeat(32)
        )
    }

    fn signed_measurement_pack(json: &str) -> (Vec<u8>, Vec<String>) {
        let signing_key = K256SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let signature: K256Signature = signing_key.sign(json.as_bytes());
        let publisher_key = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        (signature.to_bytes().to_vec(), vec![publisher_key])
    }

    fn write_signed_measurement_pack(pack_dir: &Path, name: &str, version: &str) -> Vec<String> {
        let json = measurement_pack_json(name, version);
        let (signature, publisher_keys) = signed_measurement_pack(&json);
        std::fs::create_dir_all(pack_dir).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.json"), json).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.sig"), signature).unwrap();
        publisher_keys
    }

    #[test]
    fn load_measurement_policy_accepts_json_and_signature() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("base-v1.measurements.json");
        let sig_path = dir.path().join("base-v1.measurements.sig");
        let json = measurement_pack_json("base", "v1");
        let (sig, publisher_keys) = signed_measurement_pack(&json);
        std::fs::write(&json_path, json).unwrap();
        std::fs::write(&sig_path, sig).unwrap();

        let policy =
            load_measurement_policy(Some(&json_path), Some("base:v1"), &publisher_keys, None)
                .unwrap()
                .expect("policy");

        assert_eq!(policy.pack.base_image.name, "base");
        assert_eq!(policy.pack.base_image.version, "v1");
        assert_eq!(policy.source, json_path.display().to_string());
    }

    #[test]
    fn load_measurement_policy_rejects_base_image_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let json = measurement_pack_json("base", "v1");
        let (sig, publisher_keys) = signed_measurement_pack(&json);
        std::fs::write(dir.path().join("measurement-pack.json"), json).unwrap();
        std::fs::write(dir.path().join("measurement-pack.sig"), sig).unwrap();

        let err = load_measurement_policy(Some(dir.path()), Some("base:v2"), &publisher_keys, None)
            .unwrap_err();
        assert!(
            err.to_string().contains("measurement pack is for base:v1"),
            "got: {err}"
        );
    }

    #[test]
    fn load_measurement_policy_finds_local_baseimage_pack() {
        let dir = tempfile::tempdir().unwrap();
        let json = measurement_pack_json("base/image", "v1");
        let (sig, publisher_keys) = signed_measurement_pack(&json);
        let pack_dir = dir
            .path()
            .join("baseimage")
            .join("measurements")
            .join(encode_image_ref_path_segment("base/image"))
            .join(encode_image_ref_path_segment("v1"));
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.json"), json).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.sig"), sig).unwrap();

        let policy = load_measurement_policy(
            None,
            Some("base/image:v1"),
            &publisher_keys,
            Some(dir.path()),
        )
        .unwrap()
        .expect("policy");

        assert_eq!(policy.pack.base_image.name, "base/image");
        assert_eq!(policy.source, format!("local:{}", pack_dir.display()));
    }

    #[test]
    fn load_measurement_policy_reports_missing_local_baseimage_pack() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            load_measurement_policy(None, Some("base:v1"), &[], Some(dir.path())).unwrap_err();
        assert!(
            err.to_string()
                .contains("baseimage/measurements/ref~base/ref~v1/measurement-pack.json"),
            "got: {err}"
        );
    }

    #[test]
    fn local_measurement_pack_exists_when_either_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let pack_dir = dir
            .path()
            .join("baseimage")
            .join("measurements")
            .join(encode_image_ref_path_segment("base"))
            .join(encode_image_ref_path_segment("v1"));
        std::fs::create_dir_all(&pack_dir).unwrap();
        assert!(!local_measurement_pack_exists(dir.path(), "base:v1").unwrap());

        std::fs::write(pack_dir.join("measurement-pack.json"), b"{}").unwrap();
        assert!(local_measurement_pack_exists(dir.path(), "base:v1").unwrap());

        std::fs::remove_file(pack_dir.join("measurement-pack.json")).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.sig"), b"signature").unwrap();
        assert!(local_measurement_pack_exists(dir.path(), "base:v1").unwrap());

        std::fs::write(pack_dir.join("measurement-pack.json"), b"{}").unwrap();
        assert!(local_measurement_pack_exists(dir.path(), "base:v1").unwrap());
    }

    #[test]
    fn local_measurement_pack_paths_do_not_collapse_distinct_refs() {
        let dir = tempfile::tempdir().unwrap();

        assert_ne!(
            local_measurement_pack_dir(dir.path(), "foo@bar", "v1"),
            local_measurement_pack_dir(dir.path(), "foo_bar", "v1")
        );
    }

    #[test]
    fn load_measurement_policy_reads_legacy_safe_path() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = legacy_local_measurement_pack_dir(dir.path(), "automata-linux", "v1");
        let keys = write_signed_measurement_pack(&legacy, "automata-linux", "v1");

        let policy =
            load_measurement_policy(None, Some("automata-linux:v1"), &keys, Some(dir.path()))
                .unwrap()
                .unwrap();
        assert_eq!(policy.source, format!("local:{}", legacy.display()));
    }

    #[test]
    fn load_measurement_policy_reads_legacy_sanitized_path() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = legacy_local_measurement_pack_dir(dir.path(), "foo@bar", "v1");
        let keys = write_signed_measurement_pack(&legacy, "foo@bar", "v1");

        let policy = load_measurement_policy(None, Some("foo@bar:v1"), &keys, Some(dir.path()))
            .unwrap()
            .unwrap();
        assert_eq!(policy.pack.base_image.name, "foo@bar");
    }

    #[test]
    fn load_measurement_policy_rejects_legacy_collision_identity_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = legacy_local_measurement_pack_dir(dir.path(), "foo@bar", "v1");
        let keys = write_signed_measurement_pack(&legacy, "foo_bar", "v1");

        let error =
            load_measurement_policy(None, Some("foo@bar:v1"), &keys, Some(dir.path())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("measurement pack is for foo_bar:v1, not foo@bar:v1"),
            "got: {error}"
        );
    }

    #[test]
    fn incomplete_legacy_pack_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = legacy_local_measurement_pack_dir(dir.path(), "base", "v1");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(
            legacy.join("measurement-pack.json"),
            measurement_pack_json("base", "v1"),
        )
        .unwrap();

        assert!(local_measurement_pack_exists(dir.path(), "base:v1").unwrap());
        let error =
            load_measurement_policy(None, Some("base:v1"), &[], Some(dir.path())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("baseimage/measurements/base/v1/measurement-pack.sig"),
            "got: {error}"
        );
    }

    #[test]
    fn new_pack_path_takes_priority_over_legacy_path() {
        let dir = tempfile::tempdir().unwrap();
        let new_path = local_measurement_pack_dir(dir.path(), "base", "v1");
        let legacy = legacy_local_measurement_pack_dir(dir.path(), "base", "v1");
        let keys = write_signed_measurement_pack(&new_path, "base", "v1");
        write_signed_measurement_pack(&legacy, "wrong", "v1");

        let policy = load_measurement_policy(None, Some("base:v1"), &keys, Some(dir.path()))
            .unwrap()
            .unwrap();
        assert_eq!(policy.source, format!("local:{}", new_path.display()));
    }

    #[test]
    fn incomplete_new_pack_does_not_fall_back_to_legacy_pack() {
        let dir = tempfile::tempdir().unwrap();
        let new_path = local_measurement_pack_dir(dir.path(), "base", "v1");
        let legacy = legacy_local_measurement_pack_dir(dir.path(), "base", "v1");
        std::fs::create_dir_all(&new_path).unwrap();
        std::fs::write(
            new_path.join("measurement-pack.json"),
            measurement_pack_json("base", "v1"),
        )
        .unwrap();
        let keys = write_signed_measurement_pack(&legacy, "base", "v1");

        let error =
            load_measurement_policy(None, Some("base:v1"), &keys, Some(dir.path())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ref~base/ref~v1/measurement-pack.sig"),
            "got: {error}"
        );
    }

    #[test]
    fn no_local_pack_artifacts_remain_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!local_measurement_pack_exists(dir.path(), "base:v1").unwrap());
    }

    #[test]
    fn load_measurement_policy_rejects_missing_publisher_key() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("base-v1.measurements.json");
        let sig_path = dir.path().join("base-v1.measurements.sig");
        let json = measurement_pack_json("base", "v1");
        let (sig, _) = signed_measurement_pack(&json);
        std::fs::write(&json_path, json).unwrap();
        std::fs::write(&sig_path, sig).unwrap();

        let err =
            load_measurement_policy(Some(&json_path), Some("base:v1"), &[], None).unwrap_err();

        assert!(
            err.to_string()
                .contains("no trusted measurement publisher keys"),
            "got: {err}"
        );
    }

    /// When the operator sets `registration` and/or `chain_id` in
    /// their `[chains.<name>]` TOML, those values appear verbatim in
    /// the /init JSON.
    #[test]
    fn portal_config_json_emits_registration_and_chain_id_when_set() {
        let mut cfg = sample_config();
        cfg.chain.registration = Some("off".to_string());
        cfg.chain.chain_id = Some(11155111);

        let json = build_portal_config_json(&cfg);
        assert_eq!(json["chain"]["registration"], "off");
        assert_eq!(json["chain"]["chain_id"], 11155111);
    }

    /// Each policy value round-trips correctly.
    #[test]
    fn portal_config_json_emits_each_registration_value() {
        for value in ["required", "optional", "off"] {
            let mut cfg = sample_config();
            cfg.chain.registration = Some(value.to_string());
            let json = build_portal_config_json(&cfg);
            assert_eq!(json["chain"]["registration"], value);
        }
    }

    #[test]
    fn latest_portal_schema_capability_is_required() {
        validate_portal_init_schema(&serde_json::json!({
            "init_schema_version": INIT_SCHEMA_VERSION
        }))
        .unwrap();

        for status in [
            serde_json::json!({}),
            serde_json::json!({"init_schema_version": 1}),
            serde_json::json!({"init_schema_version": INIT_SCHEMA_VERSION + 1}),
        ] {
            let error = validate_portal_init_schema(&status).unwrap_err();
            assert!(error.to_string().contains("required init schema version"));
        }
    }

    #[test]
    fn initialization_timeout_covers_proof_owner_operation_and_buffer() {
        assert_eq!(initialization_timeout_seconds(None, 300), 1_260);
    }

    #[test]
    fn explicit_initialization_timeout_overrides_calculated_default() {
        assert_eq!(initialization_timeout_seconds(Some(42), 300), 42);
    }

    #[test]
    fn selects_amd_kds_product_for_supported_cpuid() {
        assert_eq!(amd_kds_product(0x19, 0x01).unwrap(), "Milan");
        assert_eq!(amd_kds_product(0x19, 0x11).unwrap(), "Genoa");
        assert!(amd_kds_product(0x1a, 0x01).is_err());
    }

    #[test]
    fn parses_amd_kds_pem_chain() {
        let pem = b"-----BEGIN CERTIFICATE-----\nYXNr\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nYXJr\n-----END CERTIFICATE-----\n";

        assert_eq!(
            parse_pem_certificates(pem).unwrap(),
            vec![b"ask".to_vec(), b"ark".to_vec()]
        );
    }
}
