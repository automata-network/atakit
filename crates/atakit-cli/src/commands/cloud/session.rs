use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_ext::core::primitives::{Address, B256};
use alloy_ext::ext::NetworkProvider;
use anyhow::{bail, Context, Result};
use atakit_attestation::BindingMode;
use atakit_cloud::cli::{SessionMutationArgs, SessionRecoverArgs, SessionStatusArgs};
use atakit_cloud::session_lifecycle::{
    decode_hex_32, lifecycle_operation_window_seconds, lifecycle_wait_timeout_seconds,
    AuthorizeOutcome, LifecycleClient, LifecycleOperation, LifecycleStatus, PrepareOutcome,
};
use atakit_core::Env;
use automata_tee_workload_measurement::stubs::SessionRegistry::SessionRegistryInstance;
use chrono::Utc;
use k256::ecdsa::SigningKey;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};

use super::session_access::{resolve_verified_session_access, VerifiedCloudSessionAccess};
use crate::config::{Config, KeyMode, KeyType};

const REPORT_SCHEMA: &str = "atakit.session-lifecycle-report.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleReport {
    schema: String,
    operation: String,
    request_hash: String,
    state: String,
    predecessor_session_id: Option<String>,
    successor_session_id: Option<String>,
    error_code: Option<String>,
    transaction_hash: Option<String>,
    current_session_matches: Option<bool>,
    chain_active: Option<bool>,
    portal_state: Option<String>,
    created_at: Option<u64>,
    started_at: Option<u64>,
    completed_at: Option<u64>,
    updated_at: String,
}

impl LifecycleReport {
    fn from_status(
        operation: LifecycleOperation,
        predecessor_session_id: Option<String>,
        status: &LifecycleStatus,
    ) -> Result<Self> {
        let request_hash = status
            .request_hash
            .clone()
            .ok_or_else(|| anyhow::anyhow!("lifecycle status has no request_hash"))?;
        Ok(Self {
            schema: REPORT_SCHEMA.into(),
            operation: operation.path().into(),
            request_hash,
            state: status.state.clone(),
            predecessor_session_id,
            successor_session_id: status.session_id.clone(),
            error_code: status.error_code.clone(),
            transaction_hash: None,
            current_session_matches: None,
            chain_active: None,
            portal_state: None,
            created_at: status.created_at,
            started_at: status.started_at,
            completed_at: status.completed_at,
            updated_at: Utc::now().to_rfc3339(),
        })
    }

    fn update_status(&mut self, status: &LifecycleStatus) {
        self.state = status.state.clone();
        self.successor_session_id = status.session_id.clone();
        self.error_code = status.error_code.clone();
        self.created_at = status.created_at;
        self.started_at = status.started_at;
        self.completed_at = status.completed_at;
        self.updated_at = Utc::now().to_rfc3339();
    }
}

pub async fn run_new(args: SessionMutationArgs, env: &Env, config: &Config) -> Result<()> {
    run_mutation(LifecycleOperation::New, args, None, env, config).await
}

pub async fn run_rotate_key(args: SessionMutationArgs, env: &Env, config: &Config) -> Result<()> {
    run_mutation(LifecycleOperation::RotateKey, args, None, env, config).await
}

pub async fn run_renew(args: SessionMutationArgs, env: &Env, config: &Config) -> Result<()> {
    run_mutation(LifecycleOperation::Renew, args, None, env, config).await
}

pub async fn run_recover(args: SessionRecoverArgs, env: &Env, config: &Config) -> Result<()> {
    let old_session_id = decode_hex_32(&args.old_session_id, "old_session_id")
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    run_mutation(
        LifecycleOperation::Recover,
        args.mutation,
        Some(old_session_id),
        env,
        config,
    )
    .await
}

async fn run_mutation(
    operation: LifecycleOperation,
    args: SessionMutationArgs,
    recover_session_id: Option<[u8; 32]>,
    env: &Env,
    config: &Config,
) -> Result<()> {
    eprint!("Verify portal TLS... ");
    let access = resolve_verified_session_access(
        &args.instance,
        args.target.as_deref(),
        &args.verification,
        env,
        config,
    )
    .await?;
    eprintln!("{}", "done".green());

    eprint!("Verify current session... ");
    let predecessor = access.verify_current_session().await?;
    eprintln!("{}", "done".green());
    require_predecessor_binding(operation, predecessor.binding_mode)?;

    let old_session_id = match operation {
        LifecycleOperation::New => None,
        LifecycleOperation::RotateKey | LifecycleOperation::Renew => Some(predecessor.session_id),
        LifecycleOperation::Recover => recover_session_id,
    };
    let predecessor_text = Some(hex0x(match operation {
        LifecycleOperation::Recover => old_session_id.expect("recover session id"),
        _ => predecessor.session_id,
    }));
    let owner_key = resolve_owner_key(&args, &access, config)?;
    let expiry_seconds = lifecycle_operation_window_seconds(
        args.op_expiry_seconds,
        config.owner_operations.op_expiry_seconds,
    );
    if expiry_seconds == 0 {
        bail!("--op-expiry-seconds must be greater than zero");
    }
    let op_expires_at = now_unix()?
        .checked_add(expiry_seconds)
        .ok_or_else(|| anyhow::anyhow!("operation expiry overflows u64"))?;
    let timeout = Duration::from_secs(lifecycle_wait_timeout_seconds(args.timeout, expiry_seconds));
    if timeout.is_zero() {
        bail!("--timeout must be greater than zero");
    }

    let client = LifecycleClient::new(&access.verified_tls, &access.host, access.status_port);
    eprint!("Prepare {} request... ", operation.path());
    let prepared = client
        .prepare(operation, op_expires_at, old_session_id, &owner_key)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    eprintln!("{}", "done".green());

    let (request_hash, mut status, prepared_request) = match prepared {
        PrepareOutcome::Waiting(prepared) => {
            let status = LifecycleStatus {
                request_hash: Some(prepared.request_hash.clone()),
                command: Some(operation.status_name().into()),
                state: "waiting".into(),
                session_id: None,
                error_code: None,
                created_at: None,
                started_at: None,
                completed_at: None,
            };
            (prepared.request_hash.clone(), status, Some(prepared))
        }
        PrepareOutcome::Existing(status) => {
            let request_hash = status
                .request_hash
                .clone()
                .ok_or_else(|| anyhow::anyhow!("existing lifecycle request has no hash"))?;
            (request_hash, status, None)
        }
    };
    let report_path = lifecycle_report_path(
        &env.data_dir,
        &access.target_name,
        &access.instance_name,
        &request_hash,
    );
    let mut report = LifecycleReport::from_status(operation, predecessor_text, &status)?;
    write_report(&report_path, &report)?;
    println!("Request:   {request_hash}");
    println!("Report:    {}", report_path.display());
    let operation_deadline = tokio::time::Instant::now() + timeout;

    if let Some(prepared) = prepared_request {
        eprint!("Authorize request... ");
        loop {
            match client
                .authorize(&prepared, &owner_key)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?
            {
                AuthorizeOutcome::Started(started) => {
                    status = started;
                    report.update_status(&status);
                    write_report(&report_path, &report)?;
                    eprintln!("{}", "done".green());
                    break;
                }
                AuthorizeOutcome::Busy => {
                    if tokio::time::Instant::now() >= operation_deadline {
                        eprintln!("{}", "timed out".yellow());
                        bail_with_status_command(
                            &access,
                            &request_hash,
                            "authorization wait timed out",
                        )?;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    if !status.is_terminal() {
        let remaining = operation_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail_with_status_command(&access, &request_hash, "operation wait timed out")?;
        }
        status = match client
            .wait_for_request(&request_hash, remaining, |observed| {
                eprintln!("  state: {}", observed.state);
            })
            .await
        {
            Ok(status) => status,
            Err(error) => {
                report.state = "observation_timed_out".into();
                report.error_code = Some(error.to_string());
                report.updated_at = Utc::now().to_rfc3339();
                write_report(&report_path, &report)?;
                bail_with_status_command(&access, &request_hash, &error.to_string())?;
                unreachable!()
            }
        };
    }
    report.update_status(&status);
    write_report(&report_path, &report)?;
    if status.state == "failed" {
        bail!(
            "portal lifecycle request {request_hash} failed: {}",
            status.error_code.as_deref().unwrap_or("unknown error")
        );
    }

    finalize_completed(
        operation,
        &access,
        config,
        &status,
        &report_path,
        &mut report,
    )
    .await?;
    print_completed(operation, &report, &report_path);
    Ok(())
}

pub async fn run_status(args: SessionStatusArgs, env: &Env, config: &Config) -> Result<()> {
    eprint!("Verify portal TLS... ");
    let access = resolve_verified_session_access(
        &args.instance,
        args.target.as_deref(),
        &args.verification,
        env,
        config,
    )
    .await?;
    eprintln!("{}", "done".green());
    let client = LifecycleClient::new(&access.verified_tls, &access.host, access.status_port);
    let mut status = match args.request_hash.as_deref() {
        Some(request_hash) => client.request_status(request_hash).await,
        None => client.selected_status().await,
    }
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    if args.wait && !status.is_terminal() {
        let request_hash = status
            .request_hash
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the portal has no lifecycle request to wait for"))?;
        if status.state == "waiting" {
            bail!(
                "request {request_hash} is waiting for owner authorization; rerun the matching lifecycle command"
            );
        }
        status = client
            .wait_for_request(
                &request_hash,
                Duration::from_secs(args.timeout),
                |observed| {
                    eprintln!("  state: {}", observed.state);
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }

    print_status(&status);
    if status.state == "failed" {
        bail!(
            "portal lifecycle request failed: {}",
            status.error_code.as_deref().unwrap_or("unknown error")
        );
    }
    if status.state == "completed" {
        let operation = parse_operation(status.command.as_deref())?;
        let request_hash = status
            .request_hash
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("completed status has no request hash"))?;
        let report_path = lifecycle_report_path(
            &env.data_dir,
            &access.target_name,
            &access.instance_name,
            request_hash,
        );
        let mut report = read_report(&report_path).unwrap_or_else(|_| LifecycleReport {
            schema: REPORT_SCHEMA.into(),
            operation: operation.path().into(),
            request_hash: request_hash.into(),
            state: status.state.clone(),
            predecessor_session_id: None,
            successor_session_id: status.session_id.clone(),
            error_code: status.error_code.clone(),
            transaction_hash: None,
            current_session_matches: None,
            chain_active: None,
            portal_state: None,
            created_at: status.created_at,
            started_at: status.started_at,
            completed_at: status.completed_at,
            updated_at: Utc::now().to_rfc3339(),
        });
        report.update_status(&status);
        finalize_completed(
            operation,
            &access,
            config,
            &status,
            &report_path,
            &mut report,
        )
        .await?;
        print_completed(operation, &report, &report_path);
    }
    Ok(())
}

async fn finalize_completed(
    operation: LifecycleOperation,
    access: &VerifiedCloudSessionAccess,
    config: &Config,
    status: &LifecycleStatus,
    report_path: &Path,
    report: &mut LifecycleReport,
) -> Result<()> {
    let expected_session = status.session_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!("completed lifecycle request has no successor session_id")
    })?;
    let expected_session_bytes = decode_hex_32(expected_session, "session_id")
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    eprint!("Verify successor session... ");
    let successor = match access.verify_current_session().await {
        Ok(successor) => successor,
        Err(error) => {
            persist_report(report_path, report)?;
            return Err(error.context("verify completed lifecycle successor session"));
        }
    };
    report.current_session_matches = Some(successor.session_id == expected_session_bytes);
    if let Err(error) = require_matching_successor(
        operation,
        expected_session,
        expected_session_bytes,
        successor.session_id,
    ) {
        eprintln!("{}", "current session advanced".yellow());
        persist_report(report_path, report)?;
        return Err(error);
    } else {
        eprintln!("{}", "done".green());
    }

    if successor_requires_chain_check(successor.binding_mode) {
        let chain_name = access
            .chain_name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("chain-bound successor has no configured chain"))?;
        eprint!("Confirm isSessionActive... ");
        let active = match is_session_active(chain_name, expected_session_bytes, config).await {
            Ok(active) => active,
            Err(error) => {
                persist_report(report_path, report)?;
                return Err(error);
            }
        };
        report.chain_active = Some(active);
        if active {
            eprintln!("{}", "active".green());
        } else {
            eprintln!("{}", "inactive".yellow());
            persist_report(report_path, report)?;
            return require_active_successor(expected_session, active);
        }
    }

    let client = LifecycleClient::new(&access.verified_tls, &access.host, access.status_port);
    let portal_status = match client.portal_status().await {
        Ok(status) => status,
        Err(error) => {
            persist_report(report_path, report)?;
            return Err(anyhow::anyhow!("{error}"));
        }
    };
    report.portal_state = Some(portal_status.state);
    if portal_status.chain.session_id.as_deref() == Some(expected_session) {
        report.transaction_hash = portal_status.chain.tx_hash;
    }
    persist_report(report_path, report)
}

fn require_predecessor_binding(
    operation: LifecycleOperation,
    binding_mode: BindingMode,
) -> Result<()> {
    if operation.requires_old_session() && binding_mode != BindingMode::Chain {
        bail!(
            "atakit cloud session {} requires a chain-bound current session",
            operation.path()
        );
    }
    Ok(())
}

fn successor_requires_chain_check(binding_mode: BindingMode) -> bool {
    binding_mode == BindingMode::Chain
}

fn require_matching_successor(
    operation: LifecycleOperation,
    expected_session: &str,
    expected_session_bytes: [u8; 32],
    current_session_bytes: [u8; 32],
) -> Result<()> {
    if current_session_bytes != expected_session_bytes {
        bail!(
            "portal completed {} with successor {}, but current verified session is {}",
            operation.path(),
            expected_session,
            hex0x(current_session_bytes)
        );
    }
    Ok(())
}

fn require_active_successor(expected_session: &str, active: bool) -> Result<()> {
    if !active {
        bail!("isSessionActive({expected_session}) returned false");
    }
    Ok(())
}

fn resolve_owner_key(
    args: &SessionMutationArgs,
    access: &VerifiedCloudSessionAccess,
    config: &Config,
) -> Result<SigningKey> {
    let target = config
        .cloud
        .targets
        .get(&access.target_name)
        .ok_or_else(|| anyhow::anyhow!("target '{}' not found in config", access.target_name))?;
    let key_name = args
        .owner_key
        .as_deref()
        .or((!access.state.init_env.owner_key.is_empty())
            .then_some(access.state.init_env.owner_key.as_str()))
        .or(target.owner_key.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "owner key required: use --owner-key or configure the deployment target"
            )
        })?;
    let key_spec = config
        .keys
        .get(key_name)
        .ok_or_else(|| anyhow::anyhow!("key '{key_name}' not found in [keys]"))?;
    if key_spec.key_type != KeyType::Es256k {
        bail!(
            "key '{key_name}' has type {}; session lifecycle commands require es256k",
            key_spec.key_type
        );
    }
    if key_spec.mode != KeyMode::Provisioned {
        bail!(
            "key '{key_name}' has mode = \"{}\"; session lifecycle commands require a provisioned owner key",
            key_spec.mode
        );
    }
    let private_key = key_spec
        .resolve(key_name)
        .map_err(|error| anyhow::anyhow!("resolve owner key '{key_name}': {error}"))?;
    let private_key = private_key
        .trim()
        .strip_prefix("0x")
        .unwrap_or(private_key.trim());
    let private_key = hex::decode(private_key)
        .with_context(|| format!("owner key '{key_name}' is not valid hex"))?;
    SigningKey::from_slice(&private_key)
        .with_context(|| format!("owner key '{key_name}' is not a valid ES256K private key"))
}

async fn is_session_active(
    chain_name: &str,
    session_id: [u8; 32],
    config: &Config,
) -> Result<bool> {
    let chain = config
        .chains
        .get(chain_name)
        .ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in [chains]"))?;
    let registry_address: Address = chain
        .session_registry
        .parse()
        .with_context(|| format!("invalid session_registry in chain '{chain_name}'"))?;
    let provider = NetworkProvider::with_http(
        &chain.rpc_url,
        Some(Duration::from_secs(1)),
        Some(Duration::from_secs(37)),
        100,
    )
    .await
    .with_context(|| format!("connect to rpc_url for chain '{chain_name}'"))?;
    SessionRegistryInstance::new(registry_address, provider)
        .isSessionActive(B256::from(session_id))
        .call()
        .await
        .with_context(|| format!("call isSessionActive on chain '{chain_name}'"))
}

fn lifecycle_report_path(
    data_dir: &Path,
    target_name: &str,
    instance_name: &str,
    request_hash: &str,
) -> PathBuf {
    data_dir
        .join("cloud")
        .join("deployments")
        .join(target_name)
        .join(format!("{instance_name}.session-lifecycle"))
        .join(format!("{request_hash}.json"))
}

fn write_report(path: &Path, report: &LifecycleReport) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("report path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create lifecycle report directory {}", parent.display()))?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(report)?)
        .with_context(|| format!("write lifecycle report {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("replace lifecycle report {}", path.display()))
}

fn persist_report(path: &Path, report: &mut LifecycleReport) -> Result<()> {
    report.updated_at = Utc::now().to_rfc3339();
    write_report(path, report)
}

fn read_report(path: &Path) -> Result<LifecycleReport> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read lifecycle report {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse lifecycle report {}", path.display()))
}

fn print_status(status: &LifecycleStatus) {
    println!(
        "Request:   {}",
        status.request_hash.as_deref().unwrap_or("-")
    );
    println!("Operation: {}", status.command.as_deref().unwrap_or("-"));
    println!("State:     {}", status.state);
    println!("Session:   {}", status.session_id.as_deref().unwrap_or("-"));
    println!("Error:     {}", status.error_code.as_deref().unwrap_or("-"));
}

fn print_completed(operation: LifecycleOperation, report: &LifecycleReport, path: &Path) {
    println!();
    println!(
        "{}",
        "==> Session lifecycle operation completed".green().bold()
    );
    println!("    Operation:   {}", operation.path());
    println!("    Request:     {}", report.request_hash);
    println!(
        "    Successor:   {}",
        report.successor_session_id.as_deref().unwrap_or("-")
    );
    println!(
        "    Transaction: {}",
        report.transaction_hash.as_deref().unwrap_or("-")
    );
    println!("    Report:      {}", path.display());
}

fn bail_with_status_command(
    access: &VerifiedCloudSessionAccess,
    request_hash: &str,
    detail: &str,
) -> Result<()> {
    bail!(
        "{detail}\ncontinue observation with:\n  atakit cloud session status {}/{} --request-hash {} --wait",
        access.target_name,
        access.instance_name,
        request_hash
    )
}

fn parse_operation(value: Option<&str>) -> Result<LifecycleOperation> {
    match value {
        Some("new") => Ok(LifecycleOperation::New),
        Some("rotate_key") => Ok(LifecycleOperation::RotateKey),
        Some("renew") => Ok(LifecycleOperation::Renew),
        Some("recover") => Ok(LifecycleOperation::Recover),
        Some(value) => bail!("unknown portal lifecycle command {value:?}"),
        None => bail!("lifecycle status has no command"),
    }
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before the Unix epoch")?
        .as_secs())
}

fn hex0x(value: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn report_path_is_scoped_to_target_instance_and_request() {
        let path = lifecycle_report_path(Path::new("/data"), "gcp-target", "example", "0x1234");
        assert_eq!(
            path,
            Path::new("/data/cloud/deployments/gcp-target/example.session-lifecycle/0x1234.json")
        );
    }

    #[test]
    fn portal_operation_names_are_strict() {
        assert_eq!(
            parse_operation(Some("rotate_key")).unwrap(),
            LifecycleOperation::RotateKey
        );
        assert!(parse_operation(Some("rotate-key")).is_err());
        assert!(parse_operation(None).is_err());
    }

    #[test]
    fn report_json_never_contains_owner_signatures_or_challenges() {
        let status = LifecycleStatus {
            request_hash: Some(hex0x([0x11; 32])),
            command: Some("new".into()),
            state: "running".into(),
            session_id: None,
            error_code: None,
            created_at: Some(1),
            started_at: Some(2),
            completed_at: None,
        };
        let report = LifecycleReport::from_status(LifecycleOperation::New, None, &status).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("signature"));
        assert!(!json.contains("challenge"));
        assert!(!json.contains("private"));
    }

    #[test]
    fn exact_current_and_active_successor_passes_completion_checks() {
        let expected = [0x22; 32];
        let expected_text = hex0x(expected);
        require_matching_successor(
            LifecycleOperation::Renew,
            &expected_text,
            expected,
            expected,
        )
        .unwrap();
        require_active_successor(&expected_text, true).unwrap();
    }

    #[test]
    fn advanced_current_session_fails_completion_check() {
        let expected = [0x22; 32];
        let current = [0x33; 32];
        let error = require_matching_successor(
            LifecycleOperation::RotateKey,
            &hex0x(expected),
            expected,
            current,
        )
        .unwrap_err();
        let detail = error.to_string();
        assert!(detail.contains("current verified session"));
        assert!(detail.contains(&hex0x(current)));
    }

    #[test]
    fn inactive_successor_fails_completion_check() {
        let expected = hex0x([0x44; 32]);
        let error = require_active_successor(&expected, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("isSessionActive({expected}) returned false")
        );
    }

    #[test]
    fn failed_successor_checks_are_persisted_in_report() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.json");
        let status = LifecycleStatus {
            request_hash: Some(hex0x([0x11; 32])),
            command: Some("renew".into()),
            state: "completed".into(),
            session_id: Some(hex0x([0x22; 32])),
            error_code: None,
            created_at: Some(1),
            started_at: Some(2),
            completed_at: Some(3),
        };
        let mut report =
            LifecycleReport::from_status(LifecycleOperation::Renew, None, &status).unwrap();
        report.current_session_matches = Some(false);
        report.chain_active = Some(false);
        persist_report(&path, &mut report).unwrap();

        let saved = read_report(&path).unwrap();
        assert_eq!(saved.current_session_matches, Some(false));
        assert_eq!(saved.chain_active, Some(false));
    }

    #[test]
    fn successor_chain_check_follows_verified_binding() {
        assert!(successor_requires_chain_check(BindingMode::Chain));
        assert!(!successor_requires_chain_check(BindingMode::Local));
    }

    #[test]
    fn existing_session_operations_reject_local_predecessors() {
        for operation in [
            LifecycleOperation::RotateKey,
            LifecycleOperation::Renew,
            LifecycleOperation::Recover,
        ] {
            assert!(require_predecessor_binding(operation, BindingMode::Local).is_err());
            require_predecessor_binding(operation, BindingMode::Chain).unwrap();
        }
        require_predecessor_binding(LifecycleOperation::New, BindingMode::Local).unwrap();
    }
}
