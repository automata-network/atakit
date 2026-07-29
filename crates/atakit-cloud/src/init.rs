use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use atakit_attestation::{
    amd_snp_kds_product, amd_snp_security_state, amd_snp_vcek_request,
    select_azure_maa_manual_trust_key, verify_measurement_pack, verify_tls_attestation,
    verify_tls_attestation_with_workload_attributes, AkBinding, AmdSnpVerificationCollateral,
    AzureMaaTrustKey, CheckResult, EvidenceSummary, IntelTdxDcapCollateral, MeasurementPolicy,
    TlsAttestationResponse, TrustAnchors, VerificationCheck, VerificationInputs,
    VerificationReport, VerifiedTlsIdentity,
};
use atakit_attestation_client::{
    AttestationClient, AttestationClientConfig, PortalSessionVerificationContext,
};
pub use atakit_attestation_client::{TlsManualOverride, VerifiedPortalTls};
use atakit_core::{NullReporter, ProgressHandle, ProgressReporter};
use atakit_image::encode_image_ref_path_segment;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};

use crate::error::CloudError;
use crate::tdx_dcap::{
    fetch_automata_collateral, fetch_http_collateral, parse_dcap_collateral_json,
    AutomataPccsOverrides,
};

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
const MAX_TLS_ATTESTATION_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PORTAL_ERROR_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_PORTAL_STATUS_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_AMD_COLLATERAL_BYTES: usize = 1024 * 1024;

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
pub struct IntelTdxDcapCollateralConfig {
    pub source: IntelTdxDcapCollateralSource,
}

#[derive(Debug, Clone, Default)]
pub enum IntelTdxDcapCollateralSource {
    /// Do not resolve collateral before verification. Intel TDX verification
    /// then fails closed. This is retained for internal callers; the CLI
    /// defaults to Automata on-chain PCCS.
    #[default]
    None,
    /// Load an `atakit.intel-tdx-dcap-collateral` version 1 JSON document
    /// from disk.
    File(PathBuf),
    /// Fetch Intel TDX DCAP collateral from a direct HTTP PCCS/PCS endpoint.
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
        read_strategy: TdxDcapAutomataReadStrategy,
    },
}

/// Selects how Automata on-chain PCCS contract reads are grouped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TdxDcapAutomataReadStrategy {
    /// Send independent `eth_call` requests concurrently.
    #[default]
    DirectConcurrent,
    /// Send the group through Multicall3.
    ///
    /// `None` uses Alloy's standard Multicall3 address. A failed batch falls
    /// back to direct concurrent calls in `pccs-reader-rs`.
    Multicall3 { address: Option<String> },
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
) -> Result<IntelTdxDcapCollateralConfig, CloudError> {
    tdx_dcap_collateral_config_with_read_strategy(
        collateral_file,
        pccs_url,
        automata_collateral_rpc_url,
        automata_pcs_dao,
        TdxDcapAutomataReadStrategy::DirectConcurrent,
    )
}

/// Build a verifier-side TDX DCAP collateral config with an explicit Automata
/// on-chain read strategy.
pub fn tdx_dcap_collateral_config_with_read_strategy(
    collateral_file: Option<PathBuf>,
    pccs_url: Option<String>,
    automata_collateral_rpc_url: Option<String>,
    automata_pcs_dao: Option<String>,
    automata_read_strategy: TdxDcapAutomataReadStrategy,
) -> Result<IntelTdxDcapCollateralConfig, CloudError> {
    let non_default_automata_strategy =
        automata_read_strategy != TdxDcapAutomataReadStrategy::DirectConcurrent;
    let selected = usize::from(collateral_file.is_some())
        + usize::from(pccs_url.is_some())
        + usize::from(
            automata_collateral_rpc_url.is_some()
                || automata_pcs_dao.is_some()
                || non_default_automata_strategy,
        );
    if selected > 1 {
        return Err(CloudError::Config {
            message: "choose only one TDX DCAP collateral source: --tdx-dcap-collateral, --tdx-dcap-pccs-url, or --tdx-dcap-automata-*".to_string(),
        });
    }
    let source = if let Some(path) = collateral_file {
        IntelTdxDcapCollateralSource::File(path)
    } else if let Some(url) = pccs_url {
        IntelTdxDcapCollateralSource::HttpPccs { url }
    } else if automata_collateral_rpc_url.is_some() || automata_pcs_dao.is_some() {
        IntelTdxDcapCollateralSource::AutomataOnchainPccs {
            chain: Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN.to_string()),
            rpc_url: automata_collateral_rpc_url,
            pcs_dao: automata_pcs_dao,
            pck_dao: None,
            fmspc_tcb_dao: None,
            enclave_identity_dao: None,
            read_strategy: automata_read_strategy,
        }
    } else {
        IntelTdxDcapCollateralSource::AutomataOnchainPccs {
            chain: Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN.to_string()),
            rpc_url: Some(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL.to_string()),
            pcs_dao: None,
            pck_dao: None,
            fmspc_tcb_dao: None,
            enclave_identity_dao: None,
            read_strategy: automata_read_strategy,
        }
    };
    Ok(IntelTdxDcapCollateralConfig { source })
}

/// Parse the CLI values for the Automata on-chain read strategy.
pub fn tdx_dcap_automata_read_strategy(
    strategy: &str,
    multicall3_address: Option<String>,
) -> Result<TdxDcapAutomataReadStrategy, CloudError> {
    match strategy {
        "direct-concurrent" if multicall3_address.is_none() => {
            Ok(TdxDcapAutomataReadStrategy::DirectConcurrent)
        }
        "direct-concurrent" => Err(CloudError::Config {
            message:
                "--tdx-dcap-automata-multicall3-address requires --tdx-dcap-automata-read-strategy multicall3"
                    .to_string(),
        }),
        "multicall3" => Ok(TdxDcapAutomataReadStrategy::Multicall3 {
            address: multicall3_address,
        }),
        value => Err(CloudError::Config {
            message: format!(
                "invalid --tdx-dcap-automata-read-strategy {value}; expected direct-concurrent or multicall3"
            ),
        }),
    }
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

pub fn load_tls_verification_trust(
    gcp_ak_root_certs: &[String],
    azure_maa_keys: &[String],
    amd_ark_root_certs: &[String],
    amd_snp_crls: &[String],
) -> Result<TlsVerificationTrust, CloudError> {
    Ok(TlsVerificationTrust {
        trust_anchors: TrustAnchors {
            gcp_roots: parse_hex_blobs(gcp_ak_root_certs, "--gcp-ak-root-cert")?,
            azure_maa_keys: parse_hex_blobs(azure_maa_keys, "--azure-maa-key")?,
            amd_ark_roots: parse_hex_blobs(amd_ark_root_certs, "--amd-ark-root-cert")?,
            ..TrustAnchors::default()
        },
        amd_snp_crls: parse_hex_blobs(amd_snp_crls, "--amd-snp-crl")?,
    })
}

/// Verifier-approved roots and verifier-resolved AMD SEV-SNP revocation data.
#[derive(Debug, Clone, Default)]
pub struct TlsVerificationTrust {
    pub trust_anchors: TrustAnchors,
    pub amd_snp_crls: Vec<Vec<u8>>,
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

async fn read_response_bytes_limited(
    response: reqwest::Response,
    maximum_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream
        .try_next()
        .await
        .map_err(|error| format!("read {label}: {error}"))?
    {
        append_response_chunk_limited(&mut body, &chunk, maximum_bytes, label)?;
    }
    Ok(body)
}

fn append_response_chunk_limited(
    body: &mut Vec<u8>,
    chunk: &[u8],
    maximum_bytes: usize,
    label: &str,
) -> Result<(), String> {
    let new_length = body
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| format!("{label} length overflow"))?;
    if new_length > maximum_bytes {
        return Err(format!("{label} exceeds the {maximum_bytes}-byte limit"));
    }
    body.extend_from_slice(chunk);
    Ok(())
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
    tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    trust_tls_cert_sha256: Option<&str>,
    report_path: Option<&Path>,
) -> Result<VerifiedPortalTls, CloudError> {
    bootstrap_portal_tls_with_trust_config(
        host,
        status_port,
        measurement_policy,
        None,
        TlsVerificationTrust {
            trust_anchors,
            amd_snp_crls: Vec::new(),
        },
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
    workload_attributes: Option<atakit_core::tee_attributes::AttributeRequirements>,
    tls_verification_trust: TlsVerificationTrust,
    azure_maa_trust: AzureMaaTrustConfig,
    tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    trust_tls_cert_sha256: Option<&str>,
    report_path: Option<&Path>,
) -> Result<VerifiedPortalTls, CloudError> {
    let TlsVerificationTrust {
        mut trust_anchors,
        amd_snp_crls,
    } = tls_verification_trust;
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
        let body = read_response_bytes_limited(
            resp,
            MAX_PORTAL_ERROR_RESPONSE_BYTES,
            "portal TLS attestation error response",
        )
        .await
        .map(|body| String::from_utf8_lossy(&body).into_owned())
        .unwrap_or_else(|error| format!("<could not read response body: {error}>"));
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

    let response_body = read_response_bytes_limited(
        resp,
        MAX_TLS_ATTESTATION_RESPONSE_BYTES,
        "portal TLS attestation response",
    )
    .await
    .map_err(|message| CloudError::PortalTlsAttestationFailed { message })?;
    let response =
        serde_json::from_slice::<TlsAttestationResponse>(&response_body).map_err(|e| {
            CloudError::PortalTlsAttestationFailed {
                message: format!("invalid response JSON: {e}"),
            }
        })?;
    // Manual keys remain available until the committed session evidence is
    // fetched. The key that verifies fresh TLS evidence may differ from the
    // key that signed the retained session MAA JWT.
    let manual_azure_maa_keys = trust_anchors.azure_maa_keys.clone();

    let intel_tdx_dcap_collateral =
        match resolve_tdx_dcap_collateral(&response, &tdx_dcap_collateral).await {
            Ok(collateral) => collateral,
            Err(detail) => {
                let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
                let live_hash = format!("0x{}", hex::encode(live_sha));
                let report = tls_preverification_failure_report(
                    &response,
                    &live_hash,
                    "tdx-dcap-collateral",
                    detail,
                );
                return handle_tls_attestation_failure(
                    report,
                    live_peer_cert_der,
                    trust_tls_cert_sha256,
                    report_path,
                );
            }
        };

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

    let amd_snp_collateral = match resolve_amd_snp_collateral(&response, amd_snp_crls).await {
        Ok(collateral) => collateral,
        Err(detail) => {
            let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
            let live_hash = format!("0x{}", hex::encode(live_sha));
            let report = tls_preverification_failure_report(
                &response,
                &live_hash,
                "amd-snp-collateral",
                detail,
            );
            return handle_tls_attestation_failure(
                report,
                live_peer_cert_der,
                trust_tls_cert_sha256,
                report_path,
            );
        }
    };

    if let Err(detail) = resolve_chain_trust_anchors(
        &response,
        &azure_maa_trust,
        &mut trust_anchors,
        amd_snp_collateral.as_ref(),
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

    let session_chain_client = session_attestation_client(&azure_maa_trust).await?;
    let session_verification =
        measurement_policy
            .clone()
            .map(|measurement_policy| PortalSessionVerificationContext {
                platform: response.platform.clone(),
                measurement_policy,
                trust_anchors: trust_anchors.clone(),
                chain_client: session_chain_client.clone(),
                manual_azure_maa_keys: manual_azure_maa_keys.clone(),
                amd_snp_collateral: amd_snp_collateral.clone(),
                intel_tdx_dcap_collateral: intel_tdx_dcap_collateral.clone(),
            });
    let verification_inputs = VerificationInputs {
        nonce,
        live_peer_cert_der: live_peer_cert_der.clone(),
        response,
        intel_tdx_dcap_collateral,
        amd_snp_collateral,
        measurement_policy,
        trust_anchors,
    };
    let verification = match workload_attributes.as_ref() {
        Some(attributes) => {
            verify_tls_attestation_with_workload_attributes(verification_inputs, attributes)
        }
        None => verify_tls_attestation(verification_inputs),
    };
    match verification {
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
    response: &TlsAttestationResponse,
    config: &IntelTdxDcapCollateralConfig,
) -> Result<Option<IntelTdxDcapCollateral>, String> {
    if !is_tdx(response) {
        return Ok(None);
    }
    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "TDX response is missing teeEvidence".to_string())?;
    let quote = URL_SAFE_NO_PAD
        .decode(&evidence.report)
        .map_err(|e| format!("decode teeEvidence.report for DCAP collateral lookup: {e}"))?;
    let collateral = match &config.source {
        IntelTdxDcapCollateralSource::None => return Ok(None),
        IntelTdxDcapCollateralSource::File(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("read TDX DCAP collateral file {}: {e}", path.display()))?;
            parse_dcap_collateral_json(&raw, &quote).map_err(|error| {
                format!("parse TDX DCAP collateral file {}: {error}", path.display())
            })?
        }
        IntelTdxDcapCollateralSource::HttpPccs { url } => fetch_http_collateral(url, &quote)
            .await
            .map_err(|e| format!("fetch TDX DCAP collateral from {url}: {e}"))?,
        IntelTdxDcapCollateralSource::AutomataOnchainPccs {
            chain,
            rpc_url,
            pcs_dao,
            pck_dao,
            fmspc_tcb_dao,
            enclave_identity_dao,
            read_strategy,
        } => {
            let chain = chain.as_deref().unwrap_or(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN);
            let rpc_url = rpc_url
                .as_deref()
                .unwrap_or(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL);
            tokio::time::timeout(
                Duration::from_secs(180),
                fetch_automata_collateral(
                    rpc_url,
                    chain,
                    AutomataPccsOverrides {
                        pcs_dao: pcs_dao.as_deref(),
                        pck_dao: pck_dao.as_deref(),
                        fmspc_tcb_dao: fmspc_tcb_dao.as_deref(),
                        enclave_identity_dao: enclave_identity_dao.as_deref(),
                    },
                    read_strategy,
                    &quote,
                ),
            )
            .await
            .map_err(|_| {
                format!(
                    "fetch TDX DCAP collateral from Automata {chain}: timed out after 180 seconds"
                )
            })?
            .map_err(|e| format!("fetch TDX DCAP collateral from Automata {chain}: {e}"))?
        }
    };
    Ok(Some(collateral))
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
    let client = connect_attestation_client(rpc_url, session_registry).await?;
    let key = client
        .resolve_azure_maa_signing_key(&jwt.kid, &jwt.issuer)
        .await
        .map_err(|error| error.to_string())?;
    trust_anchors.azure_maa_keys.push(key.public_key.clone());
    Ok(vec![key])
}

async fn resolve_amd_snp_collateral(
    response: &TlsAttestationResponse,
    configured_crls: Vec<Vec<u8>>,
) -> Result<Option<AmdSnpVerificationCollateral>, String> {
    if !response.platform.tee.eq_ignore_ascii_case("sev-snp") {
        return Ok(None);
    }
    let is_azure = response.platform.cloud.eq_ignore_ascii_case("azure");
    let is_gcp = response.platform.cloud.eq_ignore_ascii_case("gcp");
    if !is_azure && !is_gcp {
        return Ok(None);
    }
    let crls = resolve_amd_snp_crls(response, configured_crls).await?;
    if is_azure {
        return fetch_azure_snp_collateral(response, crls).await.map(Some);
    }
    if is_gcp {
        let evidence = response
            .tee_evidence
            .as_ref()
            .ok_or_else(|| "GCP SNP response is missing teeEvidence".to_string())?;
        let auxiliary = evidence
            .auxiliary
            .as_ref()
            .ok_or_else(|| "GCP SNP response is missing teeEvidence.auxiliary".to_string())?;
        let certificate_table = URL_SAFE_NO_PAD
            .decode(auxiliary)
            .map_err(|error| format!("decode GCP SNP auxiliary certificate table: {error}"))?;
        return AmdSnpVerificationCollateral::from_certificate_table(&certificate_table, crls)
            .map(Some)
            .map_err(|error| error.to_string());
    }
    unreachable!("supported AMD SEV-SNP cloud checked above")
}

async fn fetch_azure_snp_collateral(
    response: &TlsAttestationResponse,
    crls: Vec<Vec<u8>>,
) -> Result<AmdSnpVerificationCollateral, String> {
    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "Azure SNP response is missing teeEvidence".to_string())?;
    let report = URL_SAFE_NO_PAD
        .decode(&evidence.report)
        .map_err(|error| format!("decode Azure SNP report: {error}"))?;
    let request = amd_snp_vcek_request(&report)?;
    let product = amd_snp_kds_product(&report)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("build AMD KDS client: {error}"))?;
    let chip_id = hex::encode(request.chip_id);
    let vcek_url = format!("https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}");
    let vcek_response = client
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
        .map_err(|error| format!("fetch AMD {product} VCEK: {error}"))?;
    let vcek = read_response_bytes_limited(
        vcek_response,
        MAX_AMD_COLLATERAL_BYTES,
        &format!("AMD {product} VCEK"),
    )
    .await?;
    let chain_url = format!("https://kdsintf.amd.com/vcek/v1/{product}/cert_chain");
    let chain_response = client
        .get(&chain_url)
        .send()
        .await
        .map_err(|error| format!("fetch AMD {product} certificate chain: {error}"))?
        .error_for_status()
        .map_err(|error| format!("fetch AMD {product} certificate chain: {error}"))?;
    let chain = read_response_bytes_limited(
        chain_response,
        MAX_AMD_COLLATERAL_BYTES,
        &format!("AMD {product} certificate chain"),
    )
    .await?;
    let certs = parse_pem_certificates(&chain)?;
    let [ask, ark] = certs.as_slice() else {
        return Err(format!(
            "AMD {product} certificate chain contains {} certificates, expected ASK then ARK",
            certs.len()
        ));
    };
    Ok(AmdSnpVerificationCollateral::from_vcek_chain(
        ark.clone(),
        ask.clone(),
        vcek,
        crls,
    ))
}

async fn resolve_amd_snp_crls(
    response: &TlsAttestationResponse,
    configured_crls: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, String> {
    if !configured_crls.is_empty() {
        return Ok(configured_crls);
    }
    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "SNP response is missing teeEvidence".to_string())?;
    let report = URL_SAFE_NO_PAD
        .decode(&evidence.report)
        .map_err(|error| format!("decode SNP report for AMD CRL lookup: {error}"))?;
    let product = amd_snp_kds_product(&report)?;
    let url = format!("https://kdsintf.amd.com/vcek/v1/{product}/crl");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("build AMD KDS client: {error}"))?;
    let crl_response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("fetch AMD {product} certificate revocation list: {error}"))?
        .error_for_status()
        .map_err(|error| format!("fetch AMD {product} certificate revocation list: {error}"))?;
    let crl = read_response_bytes_limited(
        crl_response,
        MAX_AMD_COLLATERAL_BYTES,
        &format!("AMD {product} certificate revocation list"),
    )
    .await?;
    Ok(vec![crl])
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
    amd_snp_collateral: Option<&AmdSnpVerificationCollateral>,
) -> Result<(), String> {
    let AzureMaaTrustSource::OnchainRegistry {
        rpc_url,
        session_registry,
    } = &config.source
    else {
        return Ok(());
    };
    let client = connect_attestation_client(rpc_url, session_registry).await?;

    if response.platform.cloud.eq_ignore_ascii_case("gcp")
        && trust_anchors.gcp_roots.is_empty()
        && trust_anchors.gcp_root_hashes.is_empty()
    {
        let root = extract_gcp_ak_root_cert(response)?;
        let root_hash = client
            .resolve_gcp_ak_root(&root)
            .await
            .map_err(|error| error.to_string())?;
        trust_anchors.gcp_root_hashes.push(root_hash);
    }

    if response.platform.tee.eq_ignore_ascii_case("sev-snp")
        && trust_anchors.amd_ark_roots.is_empty()
        && trust_anchors.amd_ark_root_hashes.is_empty()
    {
        if !response.platform.cloud.eq_ignore_ascii_case("gcp")
            && !response.platform.cloud.eq_ignore_ascii_case("azure")
        {
            return Ok(());
        }
        let ark = amd_snp_collateral
            .ok_or_else(|| "SNP response is missing resolved AMD collateral".to_string())?
            .ark_der();
        let ark_hash = client
            .resolve_amd_ark_root(ark)
            .await
            .map_err(|error| error.to_string())?;
        trust_anchors.amd_ark_root_hashes.push(ark_hash);
    }

    if response.platform.tee.eq_ignore_ascii_case("sev-snp") {
        let evidence = response
            .tee_evidence
            .as_ref()
            .ok_or_else(|| "SNP response is missing teeEvidence".to_string())?;
        let report = URL_SAFE_NO_PAD
            .decode(&evidence.report)
            .map_err(|error| format!("decode SNP report for registry default lookup: {error}"))?;
        let state = amd_snp_security_state(&report)?;
        let policy = client
            .resolve_amd_snp_security_policy(state.cpuid)
            .await
            .map_err(|error| error.to_string())?;
        trust_anchors
            .amd_snp_security_policies
            .retain(|existing| existing.cpuid != state.cpuid);
        trust_anchors.amd_snp_security_policies.push(policy);
    }

    Ok(())
}

async fn connect_attestation_client(
    rpc_url: &str,
    session_registry: &str,
) -> Result<AttestationClient, String> {
    AttestationClient::connect(AttestationClientConfig {
        rpc_url: rpc_url.to_string(),
        session_registry: session_registry.to_string(),
        expected_chain_id: None,
        expected_base_image_registry: None,
        expected_workload_registry: None,
    })
    .await
    .map_err(|error| error.to_string())
}

async fn session_attestation_client(
    config: &AzureMaaTrustConfig,
) -> Result<Option<AttestationClient>, CloudError> {
    let AzureMaaTrustSource::OnchainRegistry {
        rpc_url,
        session_registry,
    } = &config.source
    else {
        return Ok(None);
    };
    connect_attestation_client(rpc_url, session_registry)
        .await
        .map(Some)
        .map_err(|message| CloudError::PortalTlsAttestationFailed { message })
}

#[derive(Debug, Clone)]
struct AzureMaaJwtInfo {
    kid: String,
    issuer: String,
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

fn decode_jwt_json(segment: &str, label: &str) -> Result<serde_json::Value, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("decode {label}: {e}"))?;
    serde_json::from_slice(&raw).map_err(|e| format!("parse {label} JSON: {e}"))
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
                match read_response_bytes_limited(
                    resp,
                    MAX_PORTAL_STATUS_RESPONSE_BYTES,
                    "portal status response",
                )
                .await
                .and_then(|body| {
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .map_err(|error| format!("parse portal status response: {error}"))
                }) {
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
    let archive_bytes = std::fs::read(archive_path).map_err(|source| CloudError::IoPath {
        path: archive_path.into(),
        source,
    })?;
    let archive_sha256: [u8; 32] = Sha256::digest(&archive_bytes).into();
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
        &archive_sha256,
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
    expected_archive_sha256: &[u8; 32],
    unmeasured_tar: Option<&[u8]>,
    init_config: &InitConfig,
    upload_timeout: Duration,
    progress: &dyn ProgressReporter,
) -> Result<(), CloudError> {
    let archive_bytes =
        read_validated_workload_archive(archive_path, expected_archive_sha256).await?;
    verify_portal_init_schema(client, host, status_port).await?;
    let url = format!("https://{host}:{init_port}/init");

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
        let body = read_response_bytes_limited(
            resp,
            MAX_PORTAL_ERROR_RESPONSE_BYTES,
            "portal init error response",
        )
        .await
        .map(|body| String::from_utf8_lossy(&body).into_owned())
        .unwrap_or_else(|error| format!("<could not read response body: {error}>"));
        return Err(CloudError::PortalInitFailed {
            message: format!("portal returned {status}: {body}"),
        });
    }

    tracing::info!("workload initialized on CVM at {host}:{init_port}");
    Ok(())
}

async fn read_validated_workload_archive(
    archive_path: &str,
    expected_archive_sha256: &[u8; 32],
) -> Result<Vec<u8>, CloudError> {
    let archive_bytes =
        tokio::fs::read(archive_path)
            .await
            .map_err(|source| CloudError::IoPath {
                path: archive_path.into(),
                source,
            })?;
    let actual_archive_sha256: [u8; 32] = Sha256::digest(&archive_bytes).into();
    if actual_archive_sha256 != *expected_archive_sha256 {
        return Err(CloudError::WorkloadArchiveChanged {
            path: archive_path.into(),
            expected: hex::encode(expected_archive_sha256),
            actual: hex::encode(actual_archive_sha256),
        });
    }
    Ok(archive_bytes)
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
    let response = response
        .error_for_status()
        .map_err(|error| CloudError::PortalInitFailed {
            message: format!("read portal init schema from {url}: {error}"),
        })?;
    let body = read_response_bytes_limited(
        response,
        MAX_PORTAL_STATUS_RESPONSE_BYTES,
        "portal init schema response",
    )
    .await
    .map_err(|message| CloudError::PortalInitFailed {
        message: format!("read portal init schema from {url}: {message}"),
    })?;
    let status = serde_json::from_slice::<serde_json::Value>(&body).map_err(|error| {
        CloudError::PortalInitFailed {
            message: format!("parse portal status from {url}: {error}"),
        }
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
    fn automata_pccs_default_config_defers_versioned_daos_to_tcb_eval() {
        let cfg = tdx_dcap_collateral_config(None, None, None, None).expect("collateral config");
        match cfg.source {
            IntelTdxDcapCollateralSource::AutomataOnchainPccs {
                chain,
                rpc_url,
                pcs_dao,
                pck_dao,
                fmspc_tcb_dao,
                enclave_identity_dao,
                read_strategy,
            } => {
                assert_eq!(chain.as_deref(), Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN));
                assert_eq!(rpc_url.as_deref(), Some(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL));
                assert!(pcs_dao.is_none());
                assert!(pck_dao.is_none());
                assert!(fmspc_tcb_dao.is_none());
                assert!(enclave_identity_dao.is_none());
                assert_eq!(read_strategy, TdxDcapAutomataReadStrategy::DirectConcurrent);
            }
            other => panic!("expected Automata on-chain PCCS, got {other:?}"),
        }
    }

    #[test]
    fn automata_pccs_multicall3_strategy_preserves_an_address_override() {
        let strategy = tdx_dcap_automata_read_strategy(
            "multicall3",
            Some("0x1111111111111111111111111111111111111111".to_string()),
        )
        .expect("read strategy");
        assert_eq!(
            strategy,
            TdxDcapAutomataReadStrategy::Multicall3 {
                address: Some("0x1111111111111111111111111111111111111111".to_string())
            }
        );
    }

    #[test]
    fn automata_pccs_rejects_multicall3_address_with_direct_reads() {
        let error = tdx_dcap_automata_read_strategy(
            "direct-concurrent",
            Some("0x1111111111111111111111111111111111111111".to_string()),
        )
        .expect_err("address requires multicall3");
        assert!(error.to_string().contains("requires"));
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

    #[test]
    fn azure_snp_verification_collateral_stays_separate_from_portal_collateral() {
        let response = TlsAttestationResponse {
            format: 1,
            nonce: String::new(),
            tls_cert_der: String::new(),
            tls_cert_sha256: String::new(),
            qualifying_data: String::new(),
            platform: atakit_attestation::PlatformEvidence {
                cloud: "azure".to_string(),
                tee: "sev-snp".to_string(),
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
            ak_binding: None,
            collateral: serde_json::json!({
                "existing": true
            }),
        };

        let collateral = AmdSnpVerificationCollateral::from_vcek_chain(
            b"ark".to_vec(),
            b"ask".to_vec(),
            b"vcek".to_vec(),
            vec![b"crl".to_vec()],
        );

        assert_eq!(response.collateral["existing"], true);
        assert!(response.collateral.get("azureSnpCertTable").is_none());
        assert_eq!(collateral.ark_der(), b"ark");
        assert_eq!(collateral.crls_der(), &[b"crl".to_vec()]);
    }

    #[test]
    fn tls_verification_trust_keeps_amd_crls_separate_from_trust_anchors() {
        let trust =
            load_tls_verification_trust(&[], &[], &["aabb".to_string()], &["ccdd".to_string()])
                .expect("TLS verification trust");

        assert_eq!(trust.trust_anchors.amd_ark_roots, vec![vec![0xaa, 0xbb]]);
        assert_eq!(trust.amd_snp_crls, vec![vec![0xcc, 0xdd]]);
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

    #[tokio::test]
    async fn workload_archive_must_match_the_policy_validated_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("workload.atawl");
        tokio::fs::write(&archive_path, b"validated archive")
            .await
            .unwrap();
        let expected: [u8; 32] = Sha256::digest(b"validated archive").into();

        let bytes = read_validated_workload_archive(archive_path.to_str().unwrap(), &expected)
            .await
            .unwrap();
        assert_eq!(bytes, b"validated archive");

        tokio::fs::write(&archive_path, b"replacement archive")
            .await
            .unwrap();
        let error = read_validated_workload_archive(archive_path.to_str().unwrap(), &expected)
            .await
            .unwrap_err();
        assert!(matches!(error, CloudError::WorkloadArchiveChanged { .. }));
        assert!(error
            .to_string()
            .contains("workload archive changed after policy validation"));
    }

    #[test]
    fn explicit_initialization_timeout_overrides_calculated_default() {
        assert_eq!(initialization_timeout_seconds(Some(42), 300), 42);
    }

    #[test]
    fn selects_amd_kds_product_for_supported_cpuid() {
        let mut report = vec![0u8; 0x4a0];
        report[0x188] = 0x19;
        report[0x189] = 0x01;
        assert_eq!(amd_snp_kds_product(&report).unwrap(), "Milan");
        report[0x189] = 0x11;
        assert_eq!(amd_snp_kds_product(&report).unwrap(), "Genoa");
        report[0x188] = 0x1a;
        assert!(amd_snp_kds_product(&report).is_err());
    }

    #[test]
    fn response_body_limit_rejects_the_first_excess_byte() {
        let mut body = Vec::new();
        append_response_chunk_limited(&mut body, b"1234", 4, "test response").unwrap();
        let error = append_response_chunk_limited(&mut body, b"5", 4, "test response").unwrap_err();
        assert_eq!(body, b"1234");
        assert!(error.contains("4-byte limit"), "{error}");
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
