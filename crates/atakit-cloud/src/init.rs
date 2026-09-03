//! Workload deployment: the `POST /init` upload and portal lifecycle waiting.
//!
//! Portal TLS attestation collection, trust-input loading, and collateral
//! resolution moved to `atakit-attestation-client` on 2026-08-08 so that a
//! consumer of the verification workflow no longer receives `aws/`, `azure/`,
//! `gcp/`, `qemu/`, and disk-image handling with it. Every moved name is
//! re-exported below, so `atakit cloud verify-session`, `atakit cloud deploy`,
//! and `atakit cloud session status` are unchanged.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use atakit_core::{NullReporter, ProgressHandle, ProgressReporter};
use futures_util::TryStreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::error::CloudError;
use crate::pcr_policy::ResolvedPcrPolicyConfig;
use atakit_attestation::MeasurementPolicy;

pub use atakit_attestation_client::{
    bootstrap_portal_tls, cloud_tls_attestation_report_path, load_measurement_policy,
    load_tls_verification_trust, local_measurement_pack_exists,
    read_untrusted_portal_base_image_id, required_trust_inputs, tdx_dcap_automata_read_strategy,
    tdx_dcap_collateral_config, tdx_dcap_collateral_config_with_read_strategy,
    tls_manual_override_message, unsatisfied_trust_inputs, workload_tls_attestation_report_path,
    write_tls_attestation_report, AzureMaaTrustConfig, AzureMaaTrustSource, ChainBaseImage,
    ChainTrustSource, CollateralRequest, ExplicitTrustSource, IntelTdxDcapCollateralConfig,
    IntelTdxDcapCollateralSource, PortalTlsVerificationMode, PortalVerificationError,
    RequiredTrustInput, TdxDcapAutomataReadStrategy, TlsManualOverride, TlsVerificationTrust,
    TlsVerificationTrustFiles, TrustAnchorsBuilder, TrustInputSource, TrustProvenance, TrustSource,
    VerifiedPortalTls,
};

pub const ATAWL_SOURCE_CONTENT_TYPE: &str = "application/vnd.atakit.atawl-source+json";
const ATAWL_UPLOAD_SIZE_HEADER: &str = "atakit-archive-size";
const ATAWL_UPLOAD_SHA256_HEADER: &str = "atakit-archive-sha256";
const ATAWL_TRANSFER_TIMEOUT_HEADER: &str = "atakit-atawl-transfer-timeout-seconds";
const INIT_TIMEOUT_HEADER: &str = "atakit-init-timeout-seconds";
const INIT_TIMEOUT_MODE: &str = "portal-enforced-non-transfer-v1";
const MAX_ATAWL_SOURCE_SIZE: usize = 16 * 1024;

/// The portal may need the full five-minute container teardown budget after
/// the initialization deadline. Keep the HTTP request alive long enough for
/// that cleanup and the final state update to finish.
const PORTAL_INIT_CLEANUP_GRACE: Duration = Duration::from_secs(6 * 60);

#[derive(Debug, Clone, Serialize)]
pub struct RemoteAtawlSource {
    pub format: u32,
    pub uri: String,
    pub archive_sha256: String,
    pub archive_size_bytes: u64,
    pub workload_id: String,
}

/// Choose one authority for portal TLS verification.
///
/// Every command that verifies a portal goes through here, so this is where the
/// exclusive rule is enforced for all of them rather than in one command. A
/// configured chain means the registry supplies the trust anchors *and* the
/// base-image measurement policy; pinned files or an operator-supplied
/// measurement policy alongside it are refused rather than silently unused.
///
/// `portal_reported_base_image_id` is the untrusted identifier from
/// `GET /status`, used only to select which registry record is read.
pub async fn portal_tls_mode_for_init_chain(
    chain: &InitChainConfig,
    trust: TlsVerificationTrust,
    tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    explicit_measurement_policy: Option<MeasurementPolicy>,
    portal_reported_base_image_id: Option<[u8; 32]>,
) -> Result<PortalTlsVerificationMode, CloudError> {
    if atakit_attestation_client::chain_coordinates_configured(
        &chain.rpc_url,
        &chain.session_registry,
    ) {
        let mut conflicting: Vec<&str> = trust.sources.keys().map(String::as_str).collect();
        if explicit_measurement_policy.is_some() {
            conflicting.push("--measurements");
        }
        if !conflicting.is_empty() {
            return Err(CloudError::Config {
                message: format!(
                    "a configured chain resolves every trust input from the registry, so {} \
                     cannot also be supplied; drop them, or verify explicitly without a chain",
                    conflicting.join(", ")
                ),
            });
        }
        let base_image_id = portal_reported_base_image_id.ok_or_else(|| CloudError::Config {
            message: "normal portal TLS attestation requires the untrusted base_image_id from \
                      GET /status"
                .to_string(),
        })?;
        return Ok(PortalTlsVerificationMode::Chain {
            source: ChainTrustSource::connect(
                &chain.rpc_url,
                &chain.session_registry,
                tdx_dcap_collateral,
            )
            .await?,
            base_image: ChainBaseImage::PortalReported(base_image_id),
        });
    }
    let measurement_policy = explicit_measurement_policy.ok_or_else(|| CloudError::Config {
        message: "explicit verification needs a base-image measurement policy; supply \
                  --measurements, or select a chain"
            .to_string(),
    })?;
    Ok(PortalTlsVerificationMode::Explicit {
        source: ExplicitTrustSource::new(trust, tdx_dcap_collateral)?,
        measurement_policy: Box::new(measurement_policy),
    })
}

/// Build verifier-side Automata on-chain trust config from the chain section of
/// the `/init` payload.
///
/// The configuration type stays here because `InitChainConfig` is the `/init`
/// payload shape and belongs to deployment; the resolution behaviour lives in
/// `atakit-attestation-client`.
pub fn azure_maa_trust_config_from_init_chain(chain: &InitChainConfig) -> AzureMaaTrustConfig {
    atakit_attestation_client::azure_maa_trust_config_from_chain(
        &chain.rpc_url,
        &chain.session_registry,
    )
}

pub const INIT_SCHEMA_VERSION: u32 = 3;
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

const MAX_PORTAL_ERROR_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_PORTAL_STATUS_RESPONSE_BYTES: usize = 64 * 1024;

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
    pub pcr_policy: Option<ResolvedPcrPolicyConfig>,
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
    if let Some(policy) = &config.pcr_policy {
        portal_config["pcr_policy"] = serde_json::to_value(policy)
            .expect("ResolvedPcrPolicyConfig serialization cannot fail");
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

/// One initialization deadline for every non-ATAWL-transfer part of `/init`.
///
/// The portal reports the measured transfer duration. Adding only that duration
/// to the request-start deadline prevents pre-transfer work, later `/init` work,
/// or the wait for `Running` from borrowing unused ATAWL transfer time.
#[derive(Debug, Clone, Copy)]
pub struct PortalInitDeadline {
    deadline: tokio::time::Instant,
    timeout: Duration,
}

impl PortalInitDeadline {
    fn starting_at(
        started_at: tokio::time::Instant,
        timeout: Duration,
    ) -> Result<Self, CloudError> {
        let deadline = started_at
            .checked_add(timeout)
            .ok_or_else(|| CloudError::Config {
                message: "initialization timeout is too large".to_string(),
            })?;
        Ok(Self { deadline, timeout })
    }

    fn starting_now(timeout: Duration) -> Result<Self, CloudError> {
        Self::starting_at(tokio::time::Instant::now(), timeout)
    }

    fn from_request_timing(
        request_started_at: tokio::time::Instant,
        transfer_duration: Duration,
        timeout: Duration,
    ) -> Result<Self, CloudError> {
        let deadline = request_started_at
            .checked_add(timeout)
            .and_then(|deadline| deadline.checked_add(transfer_duration))
            .ok_or_else(|| CloudError::Config {
                message: "initialization timeout plus ATAWL transfer duration is too large"
                    .to_string(),
            })?;
        Ok(Self { deadline, timeout })
    }
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
    on_transition: impl FnMut(&str),
) -> Result<PortalTerminalState, CloudError> {
    wait_for_portal_terminal_until_with_client(
        client,
        host,
        status_port,
        PortalInitDeadline::starting_now(Duration::from_secs(timeout_secs))?,
        on_transition,
    )
    .await
}

/// Poll until the portal reaches a terminal state, without restarting the
/// initialization timeout consumed by `POST /init`.
pub async fn wait_for_portal_terminal_until_with_client(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
    init_deadline: PortalInitDeadline,
    mut on_transition: impl FnMut(&str),
) -> Result<PortalTerminalState, CloudError> {
    let url = format!("https://{host}:{status_port}/status");
    let interval = Duration::from_secs(2);
    let mut last_state: Option<String> = None;

    loop {
        let timeout_error = || CloudError::PortalTimeout {
            address: format!("{host}:{status_port}"),
            timeout_secs: init_deadline.timeout.as_secs(),
        };
        if tokio::time::Instant::now() >= init_deadline.deadline {
            return Err(timeout_error());
        }

        let response = tokio::time::timeout_at(init_deadline.deadline, client.get(&url).send())
            .await
            .map_err(|_| timeout_error())?;
        match response {
            Ok(resp) if resp.status().is_success() => {
                let body = tokio::time::timeout_at(
                    init_deadline.deadline,
                    read_response_bytes_limited(
                        resp,
                        MAX_PORTAL_STATUS_RESPONSE_BYTES,
                        "portal status response",
                    ),
                )
                .await
                .map_err(|_| timeout_error())?;
                match body.and_then(|body| {
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

        tokio::time::sleep_until(
            (tokio::time::Instant::now() + interval).min(init_deadline.deadline),
        )
        .await;
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
    let archive_sha256 = hash_workload_archive(archive_path).await?;
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
        Duration::from_secs(300),
        &progress,
    )
    .await
    .map(|_| ())
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
    atawl_transfer_timeout: Duration,
    init_timeout: Duration,
    progress: &dyn ProgressReporter,
) -> Result<PortalInitDeadline, CloudError> {
    let (archive_file, archive_size) =
        open_validated_workload_archive(archive_path, expected_archive_sha256).await?;
    verify_portal_init_schema(client, host, status_port).await?;
    let mut archive_headers = reqwest::header::HeaderMap::new();
    archive_headers.insert(
        reqwest::header::HeaderName::from_static(ATAWL_UPLOAD_SIZE_HEADER),
        reqwest::header::HeaderValue::from_str(&archive_size.to_string()).map_err(|error| {
            CloudError::Http {
                message: error.to_string(),
            }
        })?,
    );
    archive_headers.insert(
        reqwest::header::HeaderName::from_static(ATAWL_UPLOAD_SHA256_HEADER),
        reqwest::header::HeaderValue::from_str(&format!(
            "0x{}",
            hex::encode(expected_archive_sha256)
        ))
        .map_err(|error| CloudError::Http {
            message: error.to_string(),
        })?,
    );
    let atawl_part = reqwest::multipart::Part::stream_with_length(archive_file, archive_size)
        .file_name("archive.atawl")
        .mime_str("application/octet-stream")
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })?
        .headers(archive_headers);
    submit_portal_init(
        client,
        host,
        status_port,
        init_port,
        atawl_part,
        archive_size,
        "Uploading ATAWL",
        unmeasured_tar,
        init_config,
        atawl_transfer_timeout,
        init_timeout,
        progress,
        "upload",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn post_portal_init_remote_with_client(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
    init_port: u16,
    source: &RemoteAtawlSource,
    unmeasured_tar: Option<&[u8]>,
    init_config: &InitConfig,
    atawl_transfer_timeout: Duration,
    init_timeout: Duration,
    progress: &dyn ProgressReporter,
) -> Result<PortalInitDeadline, CloudError> {
    validate_remote_atawl_source(source)?;
    let descriptor = serde_json::to_vec(source).map_err(|error| CloudError::Http {
        message: format!("serialize remote ATAWL source: {error}"),
    })?;
    validate_remote_atawl_descriptor_size(&descriptor)?;
    verify_portal_remote_atawl_support(client, host, status_port).await?;
    if reqwest::Url::parse(&source.uri).is_ok_and(|uri| uri.scheme() == "http") {
        tracing::warn!("remote ATAWL uses HTTP; archive confidentiality is not protected");
    }
    let atawl_part = reqwest::multipart::Part::bytes(descriptor)
        .file_name("atawl-source.json")
        .mime_str(ATAWL_SOURCE_CONTENT_TYPE)
        .map_err(|error| CloudError::Http {
            message: error.to_string(),
        })?;
    submit_portal_init(
        client,
        host,
        status_port,
        init_port,
        atawl_part,
        source.archive_size_bytes,
        "Portal downloading ATAWL",
        unmeasured_tar,
        init_config,
        atawl_transfer_timeout,
        init_timeout,
        progress,
        "download",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn submit_portal_init(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
    init_port: u16,
    atawl_part: reqwest::multipart::Part,
    atawl_size: u64,
    progress_message: &str,
    unmeasured_tar: Option<&[u8]>,
    init_config: &InitConfig,
    atawl_transfer_timeout: Duration,
    init_timeout: Duration,
    progress: &dyn ProgressReporter,
    method: &'static str,
) -> Result<PortalInitDeadline, CloudError> {
    let url = format!("https://{host}:{init_port}/init");
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let transfer_timeout_header = atawl_transfer_timeout_header_value(atawl_transfer_timeout)?;
    let init_timeout_header = init_timeout_header_value(init_timeout)?;
    tracing::info!(%transfer_id, method, "starting portal ATAWL transfer");

    let config_bytes = build_portal_config_json(init_config)
        .to_string()
        .into_bytes();
    let mut form = reqwest::multipart::Form::new()
        .part("atawl", atawl_part)
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
    // This is only a safety cap while the response is unavailable. The portal
    // enforces the non-transfer budget, and its response supplies the measured
    // transfer duration used to construct the exact client-side deadline.
    let request_timeout =
        maximum_portal_init_request_timeout(atawl_transfer_timeout, init_timeout)?;
    let request_started_at = tokio::time::Instant::now();
    let maximum_request_deadline =
        request_started_at
            .checked_add(request_timeout)
            .ok_or_else(|| CloudError::Config {
                message: "portal initialization request timeout is too large".to_string(),
            })?;
    let progress_label = format!("{progress_message} [{transfer_id}]");
    let progress_handle: Arc<dyn ProgressHandle> =
        progress.create(&progress_label, atawl_size).into();
    let poll_task = tokio::spawn(poll_atawl_transfer_progress(
        client.clone(),
        host.to_string(),
        status_port,
        transfer_id.clone(),
        Arc::clone(&progress_handle),
    ));
    let send_result = client
        .post(&url)
        .timeout(request_timeout)
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Atakit-Transfer-Id", &transfer_id)
        .header(ATAWL_TRANSFER_TIMEOUT_HEADER, transfer_timeout_header)
        .header(INIT_TIMEOUT_HEADER, init_timeout_header)
        .body(reqwest::Body::wrap_stream(form.into_stream()))
        .send()
        .await;
    poll_task.abort();
    progress_handle.finish();

    let resp = send_result.map_err(|e| CloudError::PortalInitFailed {
        message: format!("request failed: {e}"),
    })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_result = tokio::time::timeout_at(
            maximum_request_deadline,
            read_response_bytes_limited(
                resp,
                MAX_PORTAL_ERROR_RESPONSE_BYTES,
                "portal init error response",
            ),
        )
        .await
        .map_err(|_| CloudError::PortalTimeout {
            address: format!("{host}:{init_port}"),
            timeout_secs: request_timeout.as_secs(),
        })?;
        if body_result
            .as_ref()
            .is_ok_and(|body| is_initialization_timeout_response(body))
        {
            return Err(CloudError::PortalTimeout {
                address: format!("{host}:{init_port}"),
                timeout_secs: init_timeout.as_secs(),
            });
        }
        let body = body_result
            .map(|body| String::from_utf8_lossy(&body).into_owned())
            .unwrap_or_else(|error| format!("<could not read response body: {error}>"));
        return Err(CloudError::PortalInitFailed {
            message: format!("portal returned {status}: {body}"),
        });
    }

    let response_body = tokio::time::timeout_at(
        maximum_request_deadline,
        read_response_bytes_limited(
            resp,
            MAX_PORTAL_STATUS_RESPONSE_BYTES,
            "portal init response",
        ),
    )
    .await
    .map_err(|_| CloudError::PortalTimeout {
        address: format!("{host}:{init_port}"),
        timeout_secs: request_timeout.as_secs(),
    })?
    .map_err(|message| CloudError::PortalInitFailed { message })?;
    let response: serde_json::Value =
        serde_json::from_slice(&response_body).map_err(|error| CloudError::PortalInitFailed {
            message: format!("parse portal init response: {error}"),
        })?;
    let transfer_duration_ms = response
        .get("atawl_transfer_duration_ms")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| CloudError::PortalInitFailed {
            message: "portal init response omitted atawl_transfer_duration_ms".to_string(),
        })?;
    let init_deadline = PortalInitDeadline::from_request_timing(
        request_started_at,
        Duration::from_millis(transfer_duration_ms),
        init_timeout,
    )?;
    if tokio::time::Instant::now() >= init_deadline.deadline {
        return Err(CloudError::PortalTimeout {
            address: format!("{host}:{init_port}"),
            timeout_secs: init_timeout.as_secs(),
        });
    }
    match response.get("transfer_id").and_then(|value| value.as_str()) {
        Some(returned) if returned != transfer_id => {
            return Err(CloudError::PortalInitFailed {
                message: "portal init response returned a different transfer_id".to_string(),
            })
        }
        None if method == "download" => {
            return Err(CloudError::PortalInitFailed {
                message: "portal init response omitted transfer_id".to_string(),
            })
        }
        Some(_) | None => {}
    }

    tracing::info!("workload initialized on CVM at {host}:{init_port}");
    Ok(init_deadline)
}

fn maximum_portal_init_request_timeout(
    atawl_transfer_timeout: Duration,
    init_timeout: Duration,
) -> Result<Duration, CloudError> {
    atawl_transfer_timeout
        .checked_add(init_timeout)
        .and_then(|timeout| timeout.checked_add(PORTAL_INIT_CLEANUP_GRACE))
        .ok_or_else(|| CloudError::Config {
            message:
                "ATAWL transfer timeout plus initialization timeout and cleanup grace is too large"
                    .to_string(),
        })
}

fn atawl_transfer_timeout_header_value(
    timeout: Duration,
) -> Result<reqwest::header::HeaderValue, CloudError> {
    if timeout.is_zero() || timeout.subsec_nanos() != 0 {
        return Err(CloudError::Config {
            message: "ATAWL transfer timeout must be a positive whole number of seconds"
                .to_string(),
        });
    }
    reqwest::header::HeaderValue::from_str(&timeout.as_secs().to_string()).map_err(|error| {
        CloudError::Config {
            message: format!("invalid ATAWL transfer timeout: {error}"),
        }
    })
}

fn init_timeout_header_value(
    timeout: Duration,
) -> Result<reqwest::header::HeaderValue, CloudError> {
    if timeout.is_zero() || timeout.subsec_nanos() != 0 {
        return Err(CloudError::Config {
            message: "initialization timeout must be a positive whole number of seconds"
                .to_string(),
        });
    }
    reqwest::header::HeaderValue::from_str(&timeout.as_secs().to_string()).map_err(|error| {
        CloudError::Config {
            message: format!("invalid initialization timeout: {error}"),
        }
    })
}

fn is_initialization_timeout_response(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|value| {
        value.get("code").and_then(|code| code.as_str()) == Some("initialization_timeout")
    })
}

fn validate_remote_atawl_descriptor_size(descriptor: &[u8]) -> Result<(), CloudError> {
    if descriptor.len() <= MAX_ATAWL_SOURCE_SIZE {
        return Ok(());
    }
    Err(CloudError::Config {
        message: format!(
            "remote ATAWL source descriptor is {} bytes; the protocol limit is {MAX_ATAWL_SOURCE_SIZE} bytes",
            descriptor.len()
        ),
    })
}

async fn open_validated_workload_archive(
    archive_path: &str,
    expected_archive_sha256: &[u8; 32],
) -> Result<(tokio::fs::File, u64), CloudError> {
    let mut archive_file = tokio::fs::File::open(archive_path)
        .await
        .map_err(|source| CloudError::IoPath {
            path: archive_path.into(),
            source,
        })?;
    let archive_size = archive_file
        .metadata()
        .await
        .map_err(|source| CloudError::IoPath {
            path: archive_path.into(),
            source,
        })?
        .len();
    let actual_archive_sha256 = hash_open_file(&mut archive_file, archive_path).await?;
    if actual_archive_sha256 != *expected_archive_sha256 {
        return Err(CloudError::WorkloadArchiveChanged {
            path: archive_path.into(),
            expected: hex::encode(expected_archive_sha256),
            actual: hex::encode(actual_archive_sha256),
        });
    }
    archive_file
        .rewind()
        .await
        .map_err(|source| CloudError::IoPath {
            path: archive_path.into(),
            source,
        })?;
    Ok((archive_file, archive_size))
}

async fn hash_workload_archive(archive_path: &str) -> Result<[u8; 32], CloudError> {
    let mut archive_file = tokio::fs::File::open(archive_path)
        .await
        .map_err(|source| CloudError::IoPath {
            path: archive_path.into(),
            source,
        })?;
    hash_open_file(&mut archive_file, archive_path).await
}

async fn hash_open_file(
    archive_file: &mut tokio::fs::File,
    archive_path: &str,
) -> Result<[u8; 32], CloudError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = archive_file
            .read(&mut buffer)
            .await
            .map_err(|source| CloudError::IoPath {
                path: archive_path.into(),
                source,
            })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

pub fn validate_remote_atawl_source(source: &RemoteAtawlSource) -> Result<(), CloudError> {
    if source.format != 1 {
        return Err(CloudError::Config {
            message: "remote ATAWL source format must be 1".to_string(),
        });
    }
    if source.archive_size_bytes == 0 {
        return Err(CloudError::Config {
            message: "remote ATAWL archive_size_bytes must be greater than zero".to_string(),
        });
    }
    validate_remote_bytes32("archive_sha256", &source.archive_sha256)?;
    validate_remote_bytes32("workload_id", &source.workload_id)?;
    let uri = reqwest::Url::parse(&source.uri).map_err(|_| CloudError::Config {
        message: "remote ATAWL URI is invalid".to_string(),
    })?;
    if !matches!(uri.scheme(), "http" | "https")
        || uri.host().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
    {
        return Err(CloudError::Config {
            message: "remote ATAWL URI must be HTTP or HTTPS, contain a host, and omit credentials and fragments".to_string(),
        });
    }
    Ok(())
}

fn validate_remote_bytes32(name: &str, value: &str) -> Result<(), CloudError> {
    let valid = value
        .strip_prefix("0x")
        .and_then(|value| hex::decode(value).ok())
        .is_some_and(|bytes| bytes.len() == 32);
    if valid {
        Ok(())
    } else {
        Err(CloudError::Config {
            message: format!("remote ATAWL {name} must be a 0x-prefixed bytes32 value"),
        })
    }
}

async fn poll_atawl_transfer_progress(
    client: reqwest::Client,
    host: String,
    status_port: u16,
    transfer_id: String,
    progress: Arc<dyn ProgressHandle>,
) -> tokio::time::Instant {
    let url = format!("https://{host}:{status_port}/status");
    let mut last_received = 0_u64;
    let mut observed = false;
    loop {
        if let Ok(response) = client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            if response.status().is_success() {
                if let Ok(body) = read_response_bytes_limited(
                    response,
                    MAX_PORTAL_STATUS_RESPONSE_BYTES,
                    "portal transfer status response",
                )
                .await
                {
                    if let Ok(status) = serde_json::from_slice::<serde_json::Value>(&body) {
                        let transfer = status.get("atawl_transfer");
                        let matches = transfer
                            .and_then(|transfer| transfer.get("transfer_id"))
                            .and_then(|value| value.as_str())
                            == Some(transfer_id.as_str());
                        if matches {
                            observed = true;
                            let received = transfer
                                .and_then(|transfer| transfer.get("bytes_received"))
                                .and_then(|value| value.as_u64())
                                .unwrap_or(last_received);
                            if received > last_received {
                                progress.inc(received - last_received);
                                last_received = received;
                            }
                        } else if atawl_transfer_has_finished(&status, observed) {
                            progress.finish();
                            return tokio::time::Instant::now();
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn atawl_transfer_has_finished(status: &serde_json::Value, observed: bool) -> bool {
    if observed {
        return true;
    }

    let state = status.get("state").and_then(|value| value.as_str());
    if matches!(state, Some("Failed" | "Running" | "CleanHalt")) {
        return true;
    }

    // A local archive can finish between two 500 ms status polls. The portal
    // publishes `atawl_received` immediately after it renames the completed
    // archive. Later phases also prove that either transfer method has ended.
    let step = status.get("step").and_then(|value| value.as_str());
    matches!(step, Some("atawl_received"))
        || (state == Some("Initializing")
            && !matches!(step, None | Some("receive" | "atawl_transfer")))
        || matches!(state, Some("InitializingWorkload" | "Registering"))
}

async fn verify_portal_init_schema(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
) -> Result<(), CloudError> {
    let status = read_portal_status(client, host, status_port).await?;
    validate_portal_init_schema(&status)
}

async fn verify_portal_remote_atawl_support(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
) -> Result<(), CloudError> {
    let status = read_portal_status(client, host, status_port).await?;
    validate_portal_init_schema(&status)?;
    let supported = status
        .get("atawl_part_content_types")
        .and_then(|value| value.as_array())
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(ATAWL_SOURCE_CONTENT_TYPE))
        });
    if supported {
        Ok(())
    } else {
        Err(CloudError::PortalInitFailed {
            message: "portal does not advertise remote ATAWL source support".to_string(),
        })
    }
}

async fn read_portal_status(
    client: &reqwest::Client,
    host: &str,
    status_port: u16,
) -> Result<serde_json::Value, CloudError> {
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
    serde_json::from_slice::<serde_json::Value>(&body).map_err(|error| {
        CloudError::PortalInitFailed {
            message: format!("parse portal status from {url}: {error}"),
        }
    })
}

fn validate_portal_init_schema(status: &serde_json::Value) -> Result<(), CloudError> {
    let observed = status
        .get("init_schema_version")
        .and_then(|value| value.as_u64());
    if observed != Some(u64::from(INIT_SCHEMA_VERSION)) {
        return Err(CloudError::PortalInitFailed {
            message: format!(
                "portal does not support required init schema version {INIT_SCHEMA_VERSION}; observed {}",
                observed
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "no init_schema_version".to_string())
            ),
        });
    }
    let timeout_mode = status
        .get("init_timeout_mode")
        .and_then(|value| value.as_str());
    if timeout_mode != Some(INIT_TIMEOUT_MODE) {
        return Err(CloudError::PortalInitFailed {
            message: format!(
                "portal does not support required initialization timeout mode {INIT_TIMEOUT_MODE}"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            pcr_policy: None,
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
            "init_schema_version": INIT_SCHEMA_VERSION,
            "init_timeout_mode": INIT_TIMEOUT_MODE
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

        let error = validate_portal_init_schema(&serde_json::json!({
            "init_schema_version": INIT_SCHEMA_VERSION
        }))
        .unwrap_err();
        assert!(error.to_string().contains("initialization timeout mode"));
    }

    #[test]
    fn initialization_timeout_covers_proof_owner_operation_and_buffer() {
        assert_eq!(initialization_timeout_seconds(None, 300), 1_260);
    }

    #[test]
    fn one_initialization_deadline_excludes_only_measured_transfer_time() {
        let request_started = tokio::time::Instant::now();
        let deadline = PortalInitDeadline::from_request_timing(
            request_started,
            Duration::from_secs(20),
            Duration::from_secs(60),
        )
        .unwrap();

        assert_eq!(
            deadline
                .deadline
                .saturating_duration_since(request_started + Duration::from_secs(35)),
            Duration::from_secs(45)
        );
        assert_eq!(deadline.timeout, Duration::from_secs(60));
    }

    #[test]
    fn portal_init_request_timeout_includes_cleanup_grace() {
        assert_eq!(
            maximum_portal_init_request_timeout(Duration::from_secs(20), Duration::from_secs(60),)
                .unwrap(),
            Duration::from_secs(20 + 60 + 6 * 60),
        );
    }

    #[test]
    fn transfer_completion_survives_a_missed_progress_sample() {
        assert!(!atawl_transfer_has_finished(
            &serde_json::json!({"state": "Initializing", "step": "receive"}),
            false,
        ));
        assert!(atawl_transfer_has_finished(
            &serde_json::json!({"state": "Initializing", "step": "atawl_received"}),
            false,
        ));
        assert!(atawl_transfer_has_finished(
            &serde_json::json!({"state": "Initializing", "step": "extract"}),
            false,
        ));
        assert!(atawl_transfer_has_finished(
            &serde_json::json!({"state": "Initializing", "step": "receive"}),
            true,
        ));
    }

    #[test]
    fn remote_atawl_source_validation_accepts_http_and_rejects_credentials() {
        let source = RemoteAtawlSource {
            format: 1,
            uri: "http://10.0.0.5/workload.atawl".into(),
            archive_sha256: format!("0x{}", "11".repeat(32)),
            archive_size_bytes: 123,
            workload_id: format!("0x{}", "22".repeat(32)),
        };
        assert!(validate_remote_atawl_source(&source).is_ok());

        let mut invalid = source;
        invalid.uri = "https://user:pass@repo/workload.atawl".into();
        assert!(validate_remote_atawl_source(&invalid).is_err());
    }

    fn remote_source_with_descriptor_size(size: usize) -> RemoteAtawlSource {
        let mut source = RemoteAtawlSource {
            format: 1,
            uri: "https://repo.example/".into(),
            archive_sha256: format!("0x{}", "11".repeat(32)),
            archive_size_bytes: 123,
            workload_id: format!("0x{}", "22".repeat(32)),
        };
        let base_size = serde_json::to_vec(&source).unwrap().len();
        assert!(base_size <= size);
        source.uri.push_str(&"a".repeat(size - base_size));
        assert_eq!(serde_json::to_vec(&source).unwrap().len(), size);
        source
    }

    #[test]
    fn remote_descriptor_exactly_at_the_protocol_limit_is_accepted() {
        let source = remote_source_with_descriptor_size(MAX_ATAWL_SOURCE_SIZE);
        let descriptor = serde_json::to_vec(&source).unwrap();
        validate_remote_atawl_descriptor_size(&descriptor).unwrap();
    }

    #[tokio::test]
    async fn oversized_remote_descriptor_is_rejected_before_http_submission() {
        let source = remote_source_with_descriptor_size(MAX_ATAWL_SOURCE_SIZE + 1);
        let descriptor = serde_json::to_vec(&source).unwrap();
        let error = validate_remote_atawl_descriptor_size(&descriptor).unwrap_err();
        assert!(matches!(error, CloudError::Config { .. }));
        assert!(error.to_string().contains("16384 bytes"));

        let error = post_portal_init_remote_with_client(
            &reqwest::Client::new(),
            "127.0.0.1",
            9,
            9,
            &source,
            None,
            &sample_config(),
            Duration::from_secs(47),
            Duration::from_secs(47),
            &NullReporter,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CloudError::Config { .. }));
        assert!(error.to_string().contains("16384 bytes"));
    }

    #[test]
    fn local_and_remote_init_share_the_same_transfer_timeout_header() {
        let value = atawl_transfer_timeout_header_value(Duration::from_secs(47)).unwrap();
        assert_eq!(value, "47");
        let init_value = init_timeout_header_value(Duration::from_secs(91)).unwrap();
        assert_eq!(init_value, "91");
    }

    #[test]
    fn portal_initialization_timeout_keeps_the_client_timeout_error() {
        assert!(is_initialization_timeout_response(
            br#"{"code":"initialization_timeout"}"#
        ));
        assert!(!is_initialization_timeout_response(
            br#"{"code":"atawl_transfer_timeout"}"#
        ));
    }

    #[test]
    fn remote_capability_requires_the_descriptor_media_type() {
        let supported = serde_json::json!({
            "init_schema_version": INIT_SCHEMA_VERSION,
            "init_timeout_mode": INIT_TIMEOUT_MODE,
            "atawl_part_content_types": [
                "application/octet-stream",
                ATAWL_SOURCE_CONTENT_TYPE
            ]
        });
        assert_eq!(
            supported["atawl_part_content_types"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|value| value.as_str() == Some(ATAWL_SOURCE_CONTENT_TYPE))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn workload_archive_must_match_the_policy_validated_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("workload.atawl");
        tokio::fs::write(&archive_path, b"validated archive")
            .await
            .unwrap();
        let expected: [u8; 32] = Sha256::digest(b"validated archive").into();

        let (mut file, size) =
            open_validated_workload_archive(archive_path.to_str().unwrap(), &expected)
                .await
                .unwrap();
        assert_eq!(size, b"validated archive".len() as u64);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"validated archive");

        tokio::fs::write(&archive_path, b"replacement archive")
            .await
            .unwrap();
        let error = open_validated_workload_archive(archive_path.to_str().unwrap(), &expected)
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
    fn response_body_limit_rejects_the_first_excess_byte() {
        let mut body = Vec::new();
        append_response_chunk_limited(&mut body, b"1234", 4, "test response").unwrap();
        let error = append_response_chunk_limited(&mut body, b"5", 4, "test response").unwrap_err();
        assert_eq!(body, b"1234");
        assert!(error.contains("4-byte limit"), "{error}");
    }
}

#[cfg(test)]
mod portal_tls_mode_tests {
    use super::*;

    const ZERO: &str = "0x0000000000000000000000000000000000000000";

    fn init_chain(rpc_url: &str, session_registry: &str) -> InitChainConfig {
        InitChainConfig {
            rpc_url: rpc_url.to_string(),
            session_registry: session_registry.to_string(),
            workload_registry: ZERO.to_string(),
            base_image_registry: ZERO.to_string(),
            registration: None,
            chain_id: None,
            tee_backend: "auto".to_string(),
            prover: None,
        }
    }

    fn chain() -> InitChainConfig {
        init_chain(
            "https://rpc.example.invalid",
            "0x1111111111111111111111111111111111111111",
        )
    }

    /// A configured chain is the authority for the measurement policy too, so
    /// an operator-supplied one alongside it is refused rather than ignored.
    ///
    /// This is checked before any connection, so the unreachable RPC endpoint
    /// above never matters — if it did, the check would be running too late.
    #[tokio::test]
    async fn a_chain_refuses_an_operator_supplied_measurement_policy() {
        let policy = MeasurementPolicy {
            source: "test".to_string(),
            pack: atakit_attestation::MeasurementPack {
                schema: atakit_attestation::BASE_IMAGE_MEASUREMENT_PACK_SCHEMA.to_string(),
                revision: 1,
                published_at: 0,
                subject: atakit_attestation::Subject {
                    publisher: "0x00".to_string(),
                    name: "n".to_string(),
                    version: "v".to_string(),
                    id: "0x00".to_string(),
                    uri: None,
                    archive_sha256: None,
                },
                measurements: serde_json::json!({ "profiles": [] }),
            },
        };

        let error = portal_tls_mode_for_init_chain(
            &chain(),
            TlsVerificationTrust::default(),
            IntelTdxDcapCollateralConfig::default(),
            Some(policy),
            Some([0x11; 32]),
        )
        .await
        .expect_err("--measurements alongside a chain must be refused");
        let message = error.to_string();
        assert!(message.contains("--measurements"), "got {message}");
    }

    /// Pinned trust files are refused for the same reason, and both are named
    /// together so an operator fixes one invocation rather than two.
    #[tokio::test]
    async fn a_chain_refuses_pinned_trust_files() {
        let mut trust = TlsVerificationTrust::default();
        trust.sources.insert(
            "--gcp-ak-root-cert".to_string(),
            vec!["/tmp/root.pem".to_string()],
        );

        let error = portal_tls_mode_for_init_chain(
            &chain(),
            trust,
            IntelTdxDcapCollateralConfig::default(),
            None,
            Some([0x11; 32]),
        )
        .await
        .expect_err("pinned files alongside a chain must be refused");
        assert!(
            error.to_string().contains("--gcp-ak-root-cert"),
            "got {error}"
        );
    }

    /// Without a chain the operator is the authority, so a measurement policy
    /// is required rather than optional.
    #[tokio::test]
    async fn explicit_mode_requires_a_measurement_policy() {
        let error = portal_tls_mode_for_init_chain(
            &init_chain("", ZERO),
            TlsVerificationTrust::default(),
            IntelTdxDcapCollateralConfig::default(),
            None,
            None,
        )
        .await
        .expect_err("explicit verification needs a policy");
        assert!(error.to_string().contains("--measurements"), "got {error}");
    }
}
