use std::{
    collections::BTreeMap,
    future::Future,
    time::{Duration, Instant},
};

mod export;
pub(super) mod observations;

use anyhow::{bail, Context, Result};
use atakit_cloud::{
    cli::DiagnoseArgs,
    diagnose::{expected_vm_id, observe_vm, DiagnosticRunner},
    init, resume, DeployState,
};
use atakit_core::Env;
use serde_json::Value;

use super::session_access::{self, VerifiedPortalAccess};
use crate::config::Config;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Pass,
    Fail,
    Reported,
    NotChecked,
}

#[derive(Debug)]
pub(super) struct Check {
    pub name: String,
    pub outcome: Outcome,
    pub detail: String,
}

#[derive(Debug, Default)]
pub(super) struct Report {
    pub checks: Vec<Check>,
    pub status: Option<Value>,
    pub host: Option<String>,
    pub session: Option<atakit_attestation::VerifiedSession>,
    pub chain_name: Option<String>,
    pub durations_ms: BTreeMap<&'static str, u64>,
    measurement_comparisons: Vec<atakit_attestation::PcrMeasurementComparison>,
    next: Vec<String>,
}

impl Report {
    fn add(&mut self, name: &str, outcome: Outcome, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            outcome,
            detail: detail.into(),
        });
    }
    pub(super) fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.outcome == Outcome::Fail)
    }
    fn skip_portal(&mut self, reason: &str) {
        for check in [
            "Portal claims",
            "Portal TLS",
            "Initialization",
            "Disks",
            "Registration",
            "Session",
        ] {
            self.add(check, Outcome::NotChecked, reason);
        }
    }
    fn finish(self) -> Result<()> {
        for check in &self.checks {
            let label = match check.outcome {
                Outcome::Pass => "PASS",
                Outcome::Fail => "FAIL",
                Outcome::Reported => "REPORTED",
                Outcome::NotChecked => "NOT CHECKED",
            };
            println!(
                "{label:<12} {:<20} {}",
                check.name,
                display_text(&check.detail)
            );
        }
        for next in &self.next {
            println!("Next action: {}", display_text(next));
        }
        if self.failed() {
            bail!("diagnostics found failed checks");
        }
        Ok(())
    }
}

// Status details are free-form. Bound output, strip terminal controls, and avoid
// printing credential-bearing URLs from nested network errors.
pub(super) fn display_text(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            if word.contains("://") {
                "[URL omitted]".into()
            } else {
                word.chars().filter(|c| !c.is_control()).collect::<String>()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(1024)
        .collect()
}

async fn bounded<T>(seconds: u64, operation: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(seconds), operation)
        .await
        .map_err(|_| anyhow::anyhow!("check timed out after {seconds}s"))?
}

pub async fn run(args: DiagnoseArgs, env: &Env, config: &Config) -> Result<()> {
    let started_at = chrono::Utc::now();
    let started = Instant::now();
    let output = args.report.clone();
    let log_output = args.log_report.clone();
    let logs = args.workload_log.clone();
    let seconds = args.check_timeout;
    if let Some(path) = &output {
        export::validate_destination(path)?;
    }
    if let Some(path) = &log_output {
        export::validate_destination(path)?;
        if output
            .as_ref()
            .is_some_and(|report| export::same_destination(report, path))
        {
            bail!("--report and --log-report must name separate files");
        }
    }
    let loaded =
        DeployState::load_for_diagnose(&env.data_dir, &args.instance, args.target.as_deref());
    let (state, mut report) = match loaded {
        Ok(state) => {
            println!("Diagnosing {}/{}", state.target_name, state.instance_name);
            let report = match collect(args, state.clone(), env, config, true).await {
                Ok(report) => report,
                Err(error) => {
                    let mut report = Report::default();
                    report.add("Diagnostic collection", Outcome::Fail, error.to_string());
                    report
                }
            };
            (Some(state), report)
        }
        Err(error) => {
            let mut report = Report::default();
            report.add("Saved deployment", Outcome::Fail, error.to_string());
            report.skip_portal("saved deployment unavailable");
            (None, report)
        }
    };
    if let Some(path) = &log_output {
        match timed(
            &mut report,
            "Workload log export",
            seconds,
            export::write_logs(&logs, path),
        )
        .await
        {
            Ok(()) => {
                report.add(
                    "Workload log export",
                    Outcome::Pass,
                    "selected local logs exported separately; contents are not redacted",
                );
                eprintln!("Workload log export: {}", path.display());
            }
            Err(error) => report.add("Workload log export", Outcome::Fail, error.to_string()),
        }
    }
    if let Some(path) = &output {
        let value = export::document(state.as_ref(), &report, started_at, started.elapsed());
        export::write_new(path, &serde_json::to_vec_pretty(&value)?)?;
        eprintln!("Diagnostic report: {}", path.display());
    }
    report.finish()
}

async fn timed<T>(
    report: &mut Report,
    name: &'static str,
    seconds: u64,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    let started = Instant::now();
    let result = bounded(seconds, operation).await;
    report.durations_ms.insert(
        name,
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
    result
}

/// Collect fresh observations without printing or persisting a report.
pub(super) async fn collect(
    mut args: DiagnoseArgs,
    state: DeployState,
    env: &Env,
    config: &Config,
    progress: bool,
) -> Result<Report> {
    let mut report = Report::default();
    report.add(
        "Saved deployment",
        Outcome::Pass,
        "record loaded; saved state is not a live observation",
    );
    if progress {
        eprintln!("Checking cloud VM...");
    }
    let vm = match timed(&mut report, "Cloud VM", args.check_timeout, async {
        observe_vm(&state, &DiagnosticRunner)
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(vm) => vm,
        Err(error) => {
            let detail = match error.downcast_ref::<atakit_cloud::CloudError>() {
                Some(atakit_cloud::CloudError::CommandFailed { .. }) => "cloud CLI query failed; verify cloud login, permissions, and the saved VM reference".into(),
                _ => error.to_string(),
            };
            report.add("Cloud VM", Outcome::Fail, detail);
            report.skip_portal("current VM address could not be established");
            return Ok(report);
        }
    };
    report.add(
        "Cloud VM",
        Outcome::Pass,
        format!("{}; power state: {}", vm.id, vm.power_state),
    );
    match compare_vm_id(expected_vm_id(&state), &vm.id) {
        Outcome::Fail => {
            report.add(
                "VM identity",
                Outcome::Fail,
                "unique instance ID differs from saved deployment",
            );
            report.skip_portal("VM identity mismatch");
            report
                .next
                .push("Verify the saved VM reference; the VM may have been replaced.".into());
            return Ok(report);
        }
        Outcome::NotChecked => report.add(
            "VM identity",
            Outcome::NotChecked,
            "no saved unique instance ID; cloud lookup alone does not establish the original VM",
        ),
        _ => report.add(
            "VM identity",
            Outcome::Pass,
            "matches saved unique instance ID",
        ),
    }
    let Some(host) = vm.address else {
        report.add(
            "Public address",
            Outcome::Fail,
            "cloud VM has no public address",
        );
        report.skip_portal("no current public address");
        return Ok(report);
    };
    report.add("Public address", Outcome::Pass, host.clone());
    report.host = Some(host.clone());
    let port = state.portal_ports.status;
    if let Err(error) = timed(
        &mut report,
        "Portal connection",
        args.check_timeout,
        async {
            tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .context("portal TCP connection failed")?;
            Ok(())
        },
    )
    .await
    {
        report.add("Portal connection", Outcome::Fail, error.to_string());
        report.skip_portal("portal TCP connection failed");
        report.next.push("Check the VM power state, portal process, and network rules; this check does not identify which caused the failure.".into());
        return Ok(report);
    }
    report.add(
        "Portal connection",
        Outcome::Pass,
        format!("TCP {port} reachable; identity not yet verified"),
    );
    let untrusted_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(args.check_timeout))
        .build()?;
    let untrusted = timed(&mut report, "Portal claims", args.check_timeout, async {
        init::read_portal_status(&untrusted_client, &host, port)
            .await
            .map_err(anyhow::Error::from)
    })
    .await;
    match &untrusted {
        Ok(status) => report.add("Portal claims", Outcome::Reported, claims(status, false)),
        Err(error) => report.add("Portal claims", Outcome::NotChecked, error.to_string()),
    }
    let target = config.cloud.targets.get(&state.target_name);
    // Resolve trust from operator configuration only. Portal chain/registry
    // claims are never inputs to this selection.
    let chain_name = args
        .verification
        .chain
        .clone()
        .or_else(|| (!state.init_env.chain.is_empty()).then(|| state.init_env.chain.clone()))
        .or_else(|| target.and_then(|t| t.chain.clone()));
    let recorded_registration = state
        .initialization
        .as_ref()
        .and_then(|record| resume::load_inputs(&env.data_dir, record).ok())
        .map(|inputs| {
            inputs
                .config
                .chain
                .registration
                .unwrap_or_else(|| "required".into())
        });
    let registration = recorded_registration
        .clone()
        .or_else(|| target.and_then(|t| t.registration.clone()));
    let saved_base_image = state.base_image_ref.as_deref().filter(|s| !s.is_empty());
    if args.verification.base_image.is_none() {
        args.verification.base_image = saved_base_image.map(str::to_string);
    }
    let init_chain = timed(&mut report, "Verification trust", args.check_timeout, async {
        match chain_name.as_deref() {
            Some(name) => {
                let chain = config
                    .chains
                    .get(name)
                    .context("selected chain is missing from configuration")?;
                if args.verification.measurements.is_some() || chain.base_image_registry.is_some() {
                    Ok(
                        session_access::verification_chain_without_registry_derivation(
                            chain,
                            registration.as_deref(),
                        ),
                    )
                } else {
                    super::init_chain_from_config(name, chain, registration.as_deref(), None).await
                }
            }
            None if args.verification.measurements.is_some()
                || registration.as_deref() == Some("off") =>
            {
                Ok(super::synthesize_off_init_chain())
            }
            None => {
                bail!("no configured trust source; provide --chain or explicit verification inputs")
            }
        }
    })
    .await;
    let init_chain = match init_chain {
        Ok(chain) => chain,
        Err(error) => {
            report.add("Verification trust", Outcome::Fail, error.to_string());
            for name in [
                "Portal TLS",
                "Initialization",
                "Disks",
                "Registration",
                "Session",
            ] {
                report.add(
                    name,
                    Outcome::NotChecked,
                    "trusted verification inputs unavailable",
                );
            }
            report.next.push("Select a configured --chain or supply the explicit trust options from cloud verify-session.".into());
            return Ok(report);
        }
    };
    report.add(
        "Verification trust",
        Outcome::Pass,
        chain_name.as_deref().unwrap_or("explicit trust inputs"),
    );
    if progress {
        eprintln!("Verifying portal TLS...");
    }
    let verified = match timed(
        &mut report,
        "Portal TLS",
        args.check_timeout,
        session_access::verify_portal_tls_with_report(
            &host,
            port,
            &args.verification,
            env,
            &init_chain,
            None,
        ),
    )
    .await
    {
        Ok(verified) => verified,
        Err(error) => {
            report.measurement_comparisons = export::tls_comparisons(&error);
            report.add("Portal TLS", Outcome::Fail, error.to_string());
            for name in ["Initialization", "Disks", "Registration", "Session"] {
                report.add(
                    name,
                    Outcome::NotChecked,
                    "portal TLS attestation did not pass",
                );
            }
            report.next.push(
                "Inspect the attestation error and trusted image policy before using this portal."
                    .into(),
            );
            return Ok(report);
        }
    };
    report.add(
        "Portal TLS",
        Outcome::Pass,
        "attestation verified; subsequent status uses the verified connection",
    );
    let status = match timed(&mut report, "Verified status", args.check_timeout, async {
        init::read_portal_status(verified.client(), &host, port)
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(status) => status,
        Err(error) => {
            report.add("Verified status", Outcome::Fail, error.to_string());
            for name in ["Initialization", "Disks", "Registration", "Session"] {
                report.add(name, Outcome::NotChecked, "verified status unavailable");
            }
            return Ok(report);
        }
    };
    report.add(
        "Verified portal claims",
        Outcome::Reported,
        claims(&status, true),
    );
    report.status = Some(status.clone());
    compare_claims(&mut report, &state, config, &status);
    compare_value(
        &mut report,
        "Saved registration",
        recorded_registration.as_deref(),
        status["chain"]["registration"].as_str(),
        false,
    );
    inspect_status(
        &mut report,
        &state,
        &status,
        &hex::encode(verified.identity().cert_sha256),
    );
    if report.failed() {
        report.add(
            "Session",
            Outcome::NotChecked,
            "deployment comparison or portal state check failed",
        );
        return Ok(report);
    }
    if state.workload_name.is_empty() || state.workload_version.is_empty() {
        report.add("Session", Outcome::NotChecked, "no saved expected workload");
        return Ok(report);
    }
    if status["state"] != "Running"
        && status["chain"]["session_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .is_none()
    {
        report.add(
            "Session",
            Outcome::NotChecked,
            "portal has not reported an available session",
        );
        return Ok(report);
    }
    if progress {
        eprintln!("Verifying current session...");
    }
    report.chain_name = chain_name.clone();
    let access = VerifiedPortalAccess {
        target_name: state.target_name.clone(),
        instance_name: state.instance_name.clone(),
        state,
        host,
        status_port: port,
        chain_name,
        verified_tls: verified,
        registration,
    };
    match timed(&mut report, "Session", args.check_timeout, async {
        session_access::resolve_verified_session_access(access, &args.verification, config)
            .await?
            .verify_current_session()
            .await
    })
    .await
    {
        Ok(session) => {
            report.session = Some(session.clone());
            report.add(
                "Session",
                Outcome::Pass,
                format!(
                    "0x{}; {:?}; {} verification checks",
                    hex::encode(session.session_id),
                    session.binding_mode,
                    session.checks.len()
                ),
            );
        }
        Err(error) => report.add("Session", Outcome::Fail, error.to_string()),
    }
    Ok(report)
}

fn compare_vm_id(expected: Option<&str>, actual: &str) -> Outcome {
    match expected {
        Some(expected) if expected != actual => Outcome::Fail,
        Some(_) => Outcome::Pass,
        None => Outcome::NotChecked,
    }
}

fn claims(status: &Value, verified: bool) -> String {
    format!(
        "{}: image={}; chain ID={}; registry={}",
        if verified {
            "from verified portal"
        } else {
            "UNVERIFIED"
        },
        status["base_image_ref"].as_str().unwrap_or("not reported"),
        status["chain"]["chain_id"]
            .as_u64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "not reported".into()),
        status["chain"]["registry_address"]
            .as_str()
            .unwrap_or("not reported")
    )
}

fn compare_claims(report: &mut Report, state: &DeployState, config: &Config, status: &Value) {
    compare_value(
        report,
        "Saved image",
        state.base_image_ref.as_deref(),
        status["base_image_ref"].as_str(),
        false,
    );
    let saved_chain = config.chains.get(&state.init_env.chain);
    compare_value(
        report,
        "Saved chain ID",
        saved_chain
            .and_then(|c| c.chain_id)
            .map(|n| n.to_string())
            .as_deref(),
        status["chain"]["chain_id"]
            .as_u64()
            .map(|n| n.to_string())
            .as_deref(),
        false,
    );
    compare_value(
        report,
        "Saved registry",
        saved_chain.map(|c| c.session_registry.as_str()),
        status["chain"]["registry_address"].as_str(),
        true,
    );
}

fn compare_value(
    report: &mut Report,
    label: &str,
    expected: Option<&str>,
    reported: Option<&str>,
    hex: bool,
) {
    match (
        expected.filter(|s| !s.is_empty()),
        reported.filter(|s| !s.is_empty()),
    ) {
        (Some(a), Some(b)) if a == b || (hex && a.eq_ignore_ascii_case(b)) => report.add(
            label,
            Outcome::Pass,
            "portal claim matches saved expectation",
        ),
        (Some(_), Some(_)) => report.add(
            label,
            Outcome::Fail,
            "portal claim differs from saved expectation",
        ),
        (None, _) => report.add(label, Outcome::NotChecked, "no saved expectation available"),
        (_, None) => report.add(
            label,
            Outcome::NotChecked,
            "portal has not reported this value",
        ),
    }
}

fn inspect_status(report: &mut Report, state: &DeployState, status: &Value, certificate: &str) {
    let phase = status["state"].as_str().unwrap_or("missing");
    if !matches!(
        phase,
        "AwaitingInit"
            | "Initializing"
            | "InitializingWorkload"
            | "AwaitingDiskUnlock"
            | "Registering"
            | "Running"
            | "Failed"
            | "CleanHalt"
    ) {
        report.add(
            "Initialization",
            Outcome::Fail,
            "portal returned an unknown or missing state",
        );
    } else {
        report.add(
            "Portal state",
            if matches!(phase, "Failed" | "CleanHalt") {
                Outcome::Fail
            } else {
                Outcome::Reported
            },
            format!(
                "{phase}; {}",
                status["detail"].as_str().unwrap_or("no failure detail")
            ),
        );
        match &state.initialization {
            Some(_) if phase == "Running" && status["init_auth"].is_null() => {
                // A restored workload can retain its TLS certificate without
                // retaining the original /init authentication status. Current
                // session verification still runs independently below.
                report.add("Initialization", Outcome::NotChecked,
                    "running portal does not report the original initialization identity; cannot correlate the old request");
            }
            Some(record)
                if record
                    .tls_sha256
                    .as_deref()
                    .is_some_and(|saved| saved != certificate) =>
            {
                report.add("Initialization", Outcome::NotChecked,
                    "portal certificate differs from the saved initialization; cannot correlate the old request across a restart");
            }
            Some(record) => match resume::action(record, certificate, status) {
                Ok(action) => {
                    report.add(
                        "Initialization",
                        if matches!(action, resume::ResumeAction::Failed(_)) { Outcome::Fail } else { Outcome::Pass },
                        match &action {
                            resume::ResumeAction::Submit => "initialization identity matches; recorded request has not been accepted",
                            resume::ResumeAction::Failed(_) => "portal reports terminal initialization failure",
                            _ => "accepted request matches saved initialization identity",
                        },
                    );
                    if state.provisioning_complete
                        && expected_vm_id(state).is_some()
                        && matches!(
                            action,
                            resume::ResumeAction::Submit | resume::ResumeAction::Wait
                        )
                    {
                        report.next.push(format!("Inspect or continue the recorded request with atakit cloud resume {} --target {}", shell_escape::escape(state.instance_name.clone().into()), shell_escape::escape(state.target_name.clone().into())));
                    }
                }
                Err(error) => report.add("Initialization", Outcome::Fail, error.to_string()),
            },
            None => report.add(
                "Initialization",
                Outcome::NotChecked,
                "no saved initialization request to compare",
            ),
        }
    }
    match status["disks"].as_object() {
        Some(disks) => {
            report.add(
                "Disks",
                Outcome::Reported,
                format!("{} disk entries", disks.len()),
            );
            for (name, disk) in disks {
                let disk_state = disk["state"].as_str().unwrap_or("unknown");
                report.add(
                    &format!("Disk {}", display_text(name)),
                    Outcome::Reported,
                    disk_state,
                );
                if disk_state == "awaiting_passphrase"
                    && !report.failed()
                    && !state.workload_name.is_empty()
                    && !state.workload_version.is_empty()
                    && matches!(
                        state.status,
                        atakit_cloud::DeployStatus::Deployed { .. }
                            | atakit_cloud::DeployStatus::Deploying { .. }
                    )
                {
                    // The actual unlock command validates credentials and disk authority.
                    report.next.push(format!(
                        "atakit cloud disk unlock {} --target {} --disk {}",
                        shell_escape::escape(state.instance_name.clone().into()),
                        shell_escape::escape(state.target_name.clone().into()),
                        shell_escape::escape(name.clone().into())
                    ));
                }
            }
        }
        None => report.add("Disks", Outcome::NotChecked, "portal omitted disk status"),
    }
    let chain_status = status["chain"]["status"].as_str().unwrap_or("not reported");
    report.add(
        "Registration",
        if chain_status == "failed" {
            Outcome::Fail
        } else {
            Outcome::Reported
        },
        format!(
            "{chain_status}; {}",
            status["chain"]["detail"]
                .as_str()
                .unwrap_or("no failure detail")
        ),
    );
}

#[cfg(test)]
mod tests;
