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
use sha2::{Digest, Sha256};

use crate::error::CloudError;
use crate::pcr_policy::ResolvedPcrPolicyConfig;

pub use atakit_attestation_client::{
    bootstrap_portal_tls, bootstrap_portal_tls_with_trust_config,
    cloud_tls_attestation_report_path, load_measurement_policy, load_tls_verification_trust,
    local_measurement_pack_exists, read_untrusted_portal_base_image_id, required_trust_inputs,
    tdx_dcap_automata_read_strategy, tdx_dcap_collateral_config,
    tdx_dcap_collateral_config_with_read_strategy, tls_manual_override_message,
    unsatisfied_trust_inputs, workload_tls_attestation_report_path, write_tls_attestation_report,
    AzureMaaTrustConfig, AzureMaaTrustSource, IntelTdxDcapCollateralConfig,
    IntelTdxDcapCollateralSource, PortalVerificationError, RequiredTrustInput,
    TdxDcapAutomataReadStrategy, TlsManualOverride, TlsVerificationTrust, VerifiedPortalTls,
};

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
    fn response_body_limit_rejects_the_first_excess_byte() {
        let mut body = Vec::new();
        append_response_chunk_limited(&mut body, b"1234", 4, "test response").unwrap();
        let error = append_response_chunk_limited(&mut body, b"5", 4, "test response").unwrap_err();
        assert_eq!(body, b"1234");
        assert!(error.contains("4-byte limit"), "{error}");
    }
}
