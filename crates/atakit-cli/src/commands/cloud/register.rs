use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_ext::core::primitives::{Address, Bytes, B256, U256};
use alloy_ext::ext::{NetworkProvider, ProviderEx};
use alloy_ext::network::TransactionBuilder;
use alloy_ext::rpc::types::TransactionRequest;
use alloy_ext::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use atakit_attestation::{
    chain_submission_request_binding_digest, recoverable_es256k_signature_matches,
};
use atakit_cloud::cli::RegisterArgs;
use atakit_cloud::init::{self, PortalTerminalState};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_config::TransactionSubmitter;
use atakit_config::{KeyMode, KeyType};
use atakit_core::Env;
use automata_tee_workload_measurement::session_registry::SessionRegistry;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};

use super::{
    init_chain_from_config, portal_endpoints, resolve_instance, resolve_tls_measurement_policy,
};
use crate::config::{ChainConfig, Config};

#[derive(Debug, Deserialize)]
struct SessionResponse {
    session_id: String,
    session_key: SessionKey,
    chain_id: u64,
    registry: String,
    chain_submission_available: bool,
}

#[derive(Debug, Deserialize)]
struct SessionKey {
    key_type: String,
    bytes: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ChainSubmission {
    chain_id: u64,
    to: String,
    value: String,
    data: String,
    session_id: String,
    op_expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct RequestBinding {
    challenge: String,
    #[serde(default)]
    signing_session_id: Option<String>,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct ChainSubmissionResponse {
    chain_submission: ChainSubmission,
    request_binding: RequestBinding,
}

#[derive(Debug, Deserialize)]
struct LifecycleStatusResponse {
    state: String,
    session_id: Option<String>,
    error_code: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum LifecycleWaitDecision {
    Proceed,
    Wait,
    Candidate(B256),
}

#[derive(Debug)]
pub(crate) enum RegistrationResult {
    LocalFallback { session_id: B256 },
    AlreadyActive { session_id: B256 },
    Submitted { session_id: B256, tx_hash: B256 },
}

pub async fn run(args: RegisterArgs, env: &Env, config: &Config) -> Result<()> {
    let (target_name, instance_name) =
        resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;
    let state = DeployState::load(&env.data_dir, &target_name, &instance_name)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    match &state.status {
        DeployStatus::Deployed { ip } if !ip.is_empty() => {}
        DeployStatus::Deployed { .. } => {
            bail!("deployment {target_name}/{instance_name} has no external IP")
        }
        _ => bail!("deployment {target_name}/{instance_name} is not deployed"),
    }
    let (portal_host, status_port, _) = portal_endpoints(&state)?;
    let target = config
        .cloud
        .targets
        .get(&target_name)
        .ok_or_else(|| anyhow::anyhow!("target '{target_name}' not found in config"))?;
    if target.registration.as_deref() == Some("off") {
        bail!("target '{target_name}' has registration = \"off\"");
    }

    let chain_name = args
        .chain
        .as_deref()
        .or_else(|| (!state.init_env.chain.is_empty()).then_some(state.init_env.chain.as_str()))
        .or(target.chain.as_deref())
        .ok_or_else(|| anyhow::anyhow!("chain is required for session registration"))?;
    let chain = config
        .chains
        .get(chain_name)
        .ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in [chains]"))?;
    if chain.transaction_submitter != TransactionSubmitter::AtakitCli {
        bail!(
            "chain '{chain_name}' uses transaction_submitter = \"atakit-portal\"; atakit-portal owns transaction submission"
        );
    }
    let prover = chain
        .prover
        .as_ref()
        .and_then(|name| config.provers.get(name));
    let init_chain =
        init_chain_from_config(chain_name, chain, target.registration.as_deref(), prover).await?;

    let gas_wallet_name = args
        .gas_wallet
        .as_deref()
        .or_else(|| {
            (!state.init_env.gas_wallet.is_empty()).then_some(state.init_env.gas_wallet.as_str())
        })
        .or(target.gas_wallet.as_deref())
        .ok_or_else(|| anyhow::anyhow!("gas wallet is required for session registration"))?;
    let signer = gas_wallet_signer(config, gas_wallet_name)?;

    eprint!("  Wait for CVM portal... ");
    init::wait_for_portal(&portal_host, status_port, args.timeout)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    eprintln!("{}", "done".green());

    eprint!("  Verify portal TLS... ");
    let portal_client = if args.unsafe_skip_tls_attestation {
        eprintln!("{}", "unsafe bypass".yellow());
        super::warn_unsafe_skip_tls_attestation();
        init::unsafe_portal_client(Duration::from_secs(args.timeout))
            .map_err(|error| anyhow::anyhow!("{error}"))?
    } else {
        let measurement_policy = resolve_tls_measurement_policy(
            args.measurements.as_deref(),
            args.base_image.as_deref(),
            &args.measurement_publisher_key,
            &env.data_dir,
            &init_chain,
        )
        .await?;
        let trust_anchors = init::load_tls_trust_anchors(
            &args.gcp_ak_root_cert,
            &args.azure_maa_key,
            &args.amd_ark_root_cert,
        )
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        let collateral = init::tdx_dcap_collateral_config(
            args.tdx_dcap_collateral.clone(),
            args.tdx_dcap_pccs_url.clone(),
            args.tdx_dcap_automata_collateral_rpc_url.clone(),
            args.tdx_dcap_automata_pcs_dao.clone(),
        )
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        let verified = init::bootstrap_portal_tls_with_trust_config(
            &portal_host,
            status_port,
            measurement_policy,
            trust_anchors,
            init::azure_maa_trust_config_from_init_chain(&init_chain),
            collateral,
            args.trust_tls_cert_sha256.as_deref(),
            Some(&init::cloud_tls_attestation_report_path(
                &env.data_dir,
                &target_name,
                &instance_name,
            )),
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        if let Some(message) = init::tls_manual_override_message(&verified) {
            eprintln!("{}", "overridden".yellow());
            eprintln!("{message}");
        } else {
            eprintln!("{}", "done".green());
        }
        verified.client
    };

    eprint!("  Submit session transaction... ");
    let result = submit_prepared_registration(
        &portal_client,
        &portal_host,
        status_port,
        chain,
        signer,
        args.timeout,
        args.wait_for_successor,
    )
    .await?;
    match result {
        RegistrationResult::LocalFallback { session_id } => {
            eprintln!("{}", "local fallback; no transaction".yellow());
            eprintln!("  Session: {session_id}");
        }
        RegistrationResult::AlreadyActive { session_id } => {
            eprintln!("{}", "already active".green());
            eprintln!("  Session: {session_id}");
        }
        RegistrationResult::Submitted {
            session_id,
            tx_hash,
        } => {
            eprintln!("{}", "confirmed".green());
            eprintln!("  Session: {session_id}");
            eprintln!("  Tx:      {tx_hash}");
        }
    }

    match init::wait_for_portal_terminal_with_client(
        &portal_client,
        &portal_host,
        status_port,
        args.timeout,
        |state| eprintln!("  Portal state: {state}"),
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?
    {
        PortalTerminalState::Running => {
            eprintln!(
                "{}",
                "Session transaction confirmed; workload is running."
                    .green()
                    .bold()
            );
            Ok(())
        }
        PortalTerminalState::Failed { detail } | PortalTerminalState::CleanHalt { detail } => {
            bail!("portal did not reach Running: {detail}")
        }
    }
}

pub(crate) fn gas_wallet_signer(
    config: &Config,
    gas_wallet_name: &str,
) -> Result<PrivateKeySigner> {
    let gas_wallet = config
        .keys
        .get(gas_wallet_name)
        .ok_or_else(|| anyhow::anyhow!("key '{gas_wallet_name}' not found in [keys]"))?;
    if gas_wallet.key_type != KeyType::Es256k {
        bail!("gas wallet '{gas_wallet_name}' must have type es256k");
    }
    if gas_wallet.mode != KeyMode::Provisioned {
        bail!(
            "gas wallet '{gas_wallet_name}' must be provisioned so the operator can sign the transaction"
        );
    }
    let private_key = gas_wallet.resolve(gas_wallet_name)?;
    parse_gas_wallet_private_key(gas_wallet_name, &private_key)
}

pub(crate) fn parse_gas_wallet_private_key(
    gas_wallet_name: &str,
    private_key: &str,
) -> Result<PrivateKeySigner> {
    private_key
        .trim()
        .strip_prefix("0x")
        .unwrap_or(private_key.trim())
        .parse()
        .with_context(|| format!("invalid gas wallet private key '{gas_wallet_name}'"))
}

pub(crate) async fn submit_prepared_registration(
    portal_client: &reqwest::Client,
    portal_host: &str,
    status_port: u16,
    chain: &ChainConfig,
    signer: PrivateKeySigner,
    timeout_secs: u64,
    wait_for_successor: bool,
) -> Result<RegistrationResult> {
    let base_url = format!("https://{portal_host}:{status_port}");
    let session_url = format!("{base_url}/session");
    let lifecycle_session_id = wait_for_lifecycle_candidate(
        portal_client,
        &base_url,
        Duration::from_secs(timeout_secs),
        wait_for_successor,
    )
    .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let session: SessionResponse = loop {
        let response = portal_client
            .get(&session_url)
            .send()
            .await
            .context("fetch portal session")?;
        if response.status().is_success() {
            break response.json().await.context("decode portal session")?;
        }
        if response.status() != reqwest::StatusCode::NOT_FOUND
            && response.status() != reqwest::StatusCode::CONFLICT
            && !response.status().is_server_error()
        {
            response
                .error_for_status()
                .context("portal session is unavailable")?;
        }
        if tokio::time::Instant::now() + Duration::from_secs(2) > deadline {
            bail!("portal did not prepare a session within {timeout_secs} seconds");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    if !session.chain_submission_available {
        let session_id = session
            .session_id
            .parse()
            .context("portal returned an invalid local session id")?;
        return Ok(RegistrationResult::LocalFallback { session_id });
    }

    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let challenge_text = URL_SAFE_NO_PAD.encode(challenge);
    let response: ChainSubmissionResponse = portal_client
        .get(format!("{base_url}/chain-submission"))
        .query(&[("challenge", challenge_text.as_str())])
        .send()
        .await
        .context("fetch portal chain submission")?
        .error_for_status()
        .context("portal chain submission is unavailable")?
        .json()
        .await
        .context("decode portal chain submission")?;

    let verified = verify_chain_submission(
        &session,
        &response,
        challenge,
        &challenge_text,
        &chain.session_registry,
    )?;
    if let Some(expected_session_id) = lifecycle_session_id {
        if verified.session_id != expected_session_id {
            bail!(
                "portal chain submission session {} does not match pending lifecycle session {}",
                verified.session_id,
                expected_session_id
            );
        }
    }
    let receipt_timeout = Duration::from_secs(timeout_secs);
    let provider = NetworkProvider::with_http(
        &chain.rpc_url,
        Some(Duration::from_secs(1)),
        Some(receipt_timeout),
        100,
    )
    .await
    .context("connect to chain RPC")?;
    if provider.chain_id() != verified.chain_id {
        bail!(
            "RPC chain ID {} does not match portal chain ID {}",
            provider.chain_id(),
            verified.chain_id
        );
    }
    let registry = SessionRegistry::new(verified.to, provider.clone());
    if registry
        .is_session_active(verified.session_id)
        .await
        .context("check whether session is already active")?
    {
        wait_for_portal_session_commit(
            portal_client,
            &session_url,
            verified.session_id,
            Duration::from_secs(timeout_secs),
        )
        .await?;
        return Ok(RegistrationResult::AlreadyActive {
            session_id: verified.session_id,
        });
    }

    let wallet_provider = provider.with_signer(signer);
    let tx = TransactionRequest::default()
        .with_to(verified.to)
        .with_value(U256::ZERO)
        .with_input(Bytes::from(verified.data));
    let mut pending = wallet_provider
        .send_transaction_ex(tx)
        .await
        .context("broadcast session transaction")?;
    let tx_hash = pending.tx_hash();
    let receipt = pending
        .get_receipt()
        .await
        .context("wait for session transaction receipt")?;
    if !receipt.status() {
        bail!("session transaction {tx_hash} reverted");
    }
    wait_for_portal_session_commit(
        portal_client,
        &session_url,
        verified.session_id,
        Duration::from_secs(timeout_secs),
    )
    .await?;
    Ok(RegistrationResult::Submitted {
        session_id: verified.session_id,
        tx_hash,
    })
}

async fn wait_for_lifecycle_candidate(
    portal_client: &reqwest::Client,
    base_url: &str,
    timeout: Duration,
    wait_for_successor: bool,
) -> Result<Option<B256>> {
    let status_url = format!("{base_url}/session/status");
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let response = portal_client
            .get(&status_url)
            .send()
            .await
            .context("fetch portal lifecycle status")?
            .error_for_status()
            .context("portal lifecycle status is unavailable")?;
        let status: LifecycleStatusResponse = response
            .json()
            .await
            .context("decode portal lifecycle status")?;
        match lifecycle_wait_decision(&status, wait_for_successor)? {
            LifecycleWaitDecision::Proceed => return Ok(None),
            LifecycleWaitDecision::Candidate(session_id) => return Ok(Some(session_id)),
            LifecycleWaitDecision::Wait => {}
        }
        if tokio::time::Instant::now() + Duration::from_secs(2) > deadline {
            bail!(
                "portal did not prepare a lifecycle successor within {} seconds",
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn lifecycle_wait_decision(
    status: &LifecycleStatusResponse,
    wait_for_successor: bool,
) -> Result<LifecycleWaitDecision> {
    match status.state.as_str() {
        "idle" | "completed" if wait_for_successor => Ok(LifecycleWaitDecision::Wait),
        "idle" | "completed" => Ok(LifecycleWaitDecision::Proceed),
        "waiting" => Ok(LifecycleWaitDecision::Wait),
        "running" => status
            .session_id
            .as_deref()
            .map(|session_id| {
                parse_b256(session_id, "pending lifecycle session ID")
                    .map(LifecycleWaitDecision::Candidate)
            })
            .unwrap_or(Ok(LifecycleWaitDecision::Wait)),
        "failed" => bail!(
            "portal lifecycle request failed: {}",
            status.error_code.as_deref().unwrap_or("unknown error")
        ),
        state => bail!("portal returned unknown lifecycle state '{state}'"),
    }
}

async fn wait_for_portal_session_commit(
    portal_client: &reqwest::Client,
    session_url: &str,
    expected_session_id: B256,
    timeout: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let response = portal_client
            .get(session_url)
            .send()
            .await
            .context("fetch portal session after transaction confirmation")?;
        if response.status().is_success() {
            let session: SessionResponse = response
                .json()
                .await
                .context("decode portal session after transaction confirmation")?;
            if parse_b256(&session.session_id, "committed portal session ID")?
                == expected_session_id
            {
                return Ok(());
            }
        } else if !response.status().is_server_error() {
            response
                .error_for_status()
                .context("portal session commit check failed")?;
        }
        if tokio::time::Instant::now() + Duration::from_secs(1) > deadline {
            bail!(
                "portal did not commit confirmed session {expected_session_id} within {} seconds",
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[derive(Debug)]
struct VerifiedSubmission {
    chain_id: u64,
    to: Address,
    data: Vec<u8>,
    session_id: B256,
}

fn verify_chain_submission(
    session: &SessionResponse,
    response: &ChainSubmissionResponse,
    challenge: [u8; 32],
    challenge_text: &str,
    configured_registry: &str,
) -> Result<VerifiedSubmission> {
    let submission = &response.chain_submission;
    if response.request_binding.challenge != challenge_text {
        bail!("portal returned a request binding for a different challenge");
    }
    let current_session_id = parse_b256(&session.session_id, "current session ID")?;
    let signing_session_id = response
        .request_binding
        .signing_session_id
        .as_deref()
        .map(|value| parse_b256(value, "request-binding signing session ID"))
        .transpose()?
        .unwrap_or(current_session_id);
    if signing_session_id != current_session_id {
        bail!("chain submission was not signed by the current session");
    }
    if submission.chain_id != session.chain_id {
        bail!("chain submission chain ID differs from the current session");
    }
    let to: Address = submission.to.parse().context("invalid submission target")?;
    let session_registry: Address = session
        .registry
        .parse()
        .context("invalid session registry")?;
    let configured_registry: Address = configured_registry
        .parse()
        .context("invalid configured session registry")?;
    if to != session_registry || to != configured_registry {
        bail!("chain submission target differs from the attested and configured registry");
    }
    if submission.value != "0x0" {
        bail!("chain submission must have zero value");
    }
    let session_id = parse_b256(&submission.session_id, "submission session ID")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    if submission.op_expires_at <= now {
        bail!("chain submission authorization has expired");
    }
    if !session.session_key.key_type.eq_ignore_ascii_case("ES256K") {
        bail!("portal session key is not ES256K");
    }
    let public_key = parse_hex(&session.session_key.bytes, "session public key")?;
    let signature = parse_hex(
        &response.request_binding.signature,
        "request binding signature",
    )?;
    let canonical = canonical_submission(submission)?;
    let digest = chain_submission_request_binding_digest(challenge, &canonical);
    if !recoverable_es256k_signature_matches(&public_key, digest, &signature) {
        bail!("portal chain submission request binding signature is invalid");
    }
    let data = parse_hex(&submission.data, "chain submission data")?;
    if data.is_empty() {
        bail!("chain submission data is empty");
    }
    Ok(VerifiedSubmission {
        chain_id: submission.chain_id,
        to,
        data,
        session_id,
    })
}

fn canonical_submission(submission: &ChainSubmission) -> Result<Vec<u8>> {
    let mut value = BTreeMap::new();
    value.insert("chain_id", serde_json::json!(submission.chain_id));
    value.insert("data", serde_json::json!(submission.data));
    value.insert("op_expires_at", serde_json::json!(submission.op_expires_at));
    value.insert("session_id", serde_json::json!(submission.session_id));
    value.insert("to", serde_json::json!(submission.to));
    value.insert("value", serde_json::json!(submission.value));
    serde_json::to_vec(&value).context("canonicalize chain submission")
}

fn parse_hex(value: &str, field: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("invalid {field} hex"))
}

fn parse_b256(value: &str, field: &str) -> Result<B256> {
    let bytes = parse_hex(value, field)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must be 32 bytes"))?;
    Ok(B256::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    #[test]
    fn lifecycle_status_waits_for_the_announced_successor() {
        let waiting = LifecycleStatusResponse {
            state: "running".into(),
            session_id: None,
            error_code: None,
        };
        assert_eq!(
            lifecycle_wait_decision(&waiting, false).unwrap(),
            LifecycleWaitDecision::Wait
        );

        let candidate = LifecycleStatusResponse {
            state: "running".into(),
            session_id: Some(format!("0x{}", "42".repeat(32))),
            error_code: None,
        };
        assert_eq!(
            lifecycle_wait_decision(&candidate, false).unwrap(),
            LifecycleWaitDecision::Candidate(B256::repeat_byte(0x42))
        );

        let idle = LifecycleStatusResponse {
            state: "idle".into(),
            session_id: None,
            error_code: None,
        };
        assert_eq!(
            lifecycle_wait_decision(&idle, false).unwrap(),
            LifecycleWaitDecision::Proceed
        );
        assert_eq!(
            lifecycle_wait_decision(&idle, true).unwrap(),
            LifecycleWaitDecision::Wait
        );
    }

    #[test]
    fn lifecycle_failure_is_not_reported_as_already_active() {
        let failed = LifecycleStatusResponse {
            state: "failed".into(),
            session_id: None,
            error_code: Some("proof_failed".into()),
        };
        assert!(lifecycle_wait_decision(&failed, false)
            .unwrap_err()
            .to_string()
            .contains("proof_failed"));
    }

    #[test]
    fn verifies_challenge_bound_submission_and_rejects_mutation() {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let challenge = [0x42; 32];
        let challenge_text = URL_SAFE_NO_PAD.encode(challenge);
        let registry = "0x1111111111111111111111111111111111111111";
        let active_session_id = format!("0x{}", "22".repeat(32));
        let candidate_session_id = format!("0x{}", "33".repeat(32));
        let submission = ChainSubmission {
            chain_id: 31337,
            to: registry.to_string(),
            value: "0x0".to_string(),
            data: "0x1234".to_string(),
            session_id: candidate_session_id,
            op_expires_at: u64::MAX,
        };
        let digest = chain_submission_request_binding_digest(
            challenge,
            &canonical_submission(&submission).unwrap(),
        );
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&digest)
            .expect("sign binding");
        let mut signature = signature.to_bytes().to_vec();
        signature.push(27 + recovery_id.to_byte());
        let session = SessionResponse {
            session_id: active_session_id.clone(),
            session_key: SessionKey {
                key_type: "ES256K".to_string(),
                bytes: format!("0x{}", hex::encode(public_key.as_bytes())),
            },
            chain_id: 31337,
            registry: registry.to_string(),
            chain_submission_available: true,
        };
        let mut response = ChainSubmissionResponse {
            chain_submission: submission,
            request_binding: RequestBinding {
                challenge: challenge_text.clone(),
                signing_session_id: Some(active_session_id),
                signature: format!("0x{}", hex::encode(signature)),
            },
        };

        verify_chain_submission(&session, &response, challenge, &challenge_text, registry)
            .expect("valid submission");
        response.chain_submission.data = "0x5678".to_string();
        assert!(
            verify_chain_submission(&session, &response, challenge, &challenge_text, registry)
                .unwrap_err()
                .to_string()
                .contains("signature is invalid")
        );
    }
}
