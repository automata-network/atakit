use std::{io::Write, path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use atakit_attestation::{PcrMeasurementComparison, VerificationReport};
use atakit_attestation_client::PortalVerificationError;
use atakit_cloud::{DeployState, DeployStatus};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::{Outcome, Report};

pub(super) fn validate_destination(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!("output already exists: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect report destination"),
    }
    if !parent(path).is_dir() {
        bail!(
            "output directory does not exist: {}",
            parent(path).display()
        );
    }
    Ok(())
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(super) fn same_destination(a: &Path, b: &Path) -> bool {
    a == b
        || (a.file_name() == b.file_name()
            && std::fs::canonicalize(parent(a)).ok() == std::fs::canonicalize(parent(b)).ok())
}

/// Publish a complete owner-readable file, without replacing any existing file or symlink.
pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(parent(path)).context("create report output")?;
    atakit_core::restrict_to_owner(file.path())?;
    file.write_all(bytes).context("write report output")?;
    file.as_file().sync_all().context("flush report output")?;
    file.persist_noclobber(path)
        .map_err(|e| e.error)
        .context("publish report output without overwriting an existing file")?;
    Ok(())
}

pub(super) fn document(
    state: Option<&DeployState>,
    report: &Report,
    started: DateTime<Utc>,
    elapsed: Duration,
) -> Value {
    let checks: Vec<_> = report.checks.iter().map(|check| {
        let code = check_code(&check.name);
        json!({"check":code, "outcome":outcome(&check.outcome),
            "error": if check.outcome == Outcome::Fail { Some(format!("{code}_failed")) } else { None },
            "duration_ms": report.durations_ms.get(check.name.as_str())})
    }).collect();
    let operations: Vec<_> = report
        .durations_ms
        .iter()
        .map(|(name, elapsed)| json!({"check":check_code(name),"duration_ms":elapsed}))
        .collect();
    let versions = state.map(|s| {
        json!({
            "base_image": public_reference(s.base_image_ref.as_deref()),
            "provider_image": public_reference(Some(&s.image_ref)),
            "workload": {"name": public_reference(Some(&s.workload_name)),
                "version": public_reference(Some(&s.workload_version))}
        })
    });
    let saved = state.map(|s| {
        let (phase, step, total) = match &s.status {
            DeployStatus::Deploying { step, total } => ("deploying", Some(*step), Some(*total)),
            DeployStatus::Deployed { .. } => ("deployed", None, None),
            DeployStatus::Failed { .. } => ("failed", None, None),
            DeployStatus::Destroying => ("destroying", None, None),
            DeployStatus::Destroyed => ("destroyed", None, None),
        };
        json!({"instance":public_reference(Some(&s.instance_name)),
            "target":public_reference(Some(&s.target_name)), "platform":s.platform,
            "state":phase,"step":step,"total_steps":total,
            "initialization_phase":s.initialization.as_ref().map(|i| &i.phase),
            "created_at":s.created_at,"updated_at":s.updated_at})
    });
    let portal = report.status.as_ref().map(|status| json!({
        "source":"attested_portal", "state": enum_value(&status["state"], &[
            "AwaitingInit","Initializing","InitializingWorkload","AwaitingDiskUnlock",
            "Registering","Running","Failed","CleanHalt"]),
        "base_image": public_reference(status["base_image_ref"].as_str()),
        "chain_id":status["chain"]["chain_id"].as_u64(),
        "registry":fixed_hex(status["chain"]["registry_address"].as_str(),20),
        "registration":enum_value(&status["chain"]["status"], &["off","pending","ready","submitted","verified","failed"]),
        "startup_checks":super::observations::startup(&status["startup_checks"]),
        "readiness":super::observations::readiness(&status["readiness"]),
        "storage":super::observations::storage(&status["storage"]),
        "disks":status["disks"].as_object().map(|disks| disks.values().map(|d|
            enum_value(&d["state"], &["awaiting_passphrase","unlocked","locked","failed","pending","ready"]))
            .collect::<Vec<_>>())
    }));
    let session = report.session.as_ref().map(|s| {
        json!({
            "id":format!("0x{}",hex::encode(s.session_id)),"binding":s.binding_mode,
            "chain_id":s.binding_chain_id,"registry":format!("0x{}",hex::encode(s.binding_registry))
        })
    });
    json!({"schema":"atakit.cloud-diagnostics.v1", "cli_version":env!("CARGO_PKG_VERSION"),
        "started_at":started,"completed_at":Utc::now(),"duration_ms":millis(elapsed),
        "failed":report.failed(), "versions":versions,"saved":saved,"portal":portal,
        "session":session,"checks":checks,"operations":operations,
        "independent_verification":{
            "portal_tls":report.checks.iter().find(|c| c.name == "Portal TLS").map(|c| outcome(&c.outcome)),
            "session":report.checks.iter().find(|c| c.name == "Session").map(|c| outcome(&c.outcome))},
        "measurements":{"source":"tls_verifier_failure_report",
            "availability":if report.measurement_comparisons.is_empty(){"NOT REPORTED"}else{"REPORTED"},
            "attestation_passed":report.checks.iter().find(|c| c.name == "Portal TLS")
                .and_then(|c| match c.outcome {Outcome::Pass=>Some(true),Outcome::Fail=>Some(false),_=>None}),
            "comparisons":report.measurement_comparisons.iter().filter_map(public_comparison).collect::<Vec<_>>()},
        "workload_logs_included":false})
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn outcome(value: &Outcome) -> &'static str {
    match value {
        Outcome::Pass => "PASS",
        Outcome::Fail => "FAIL",
        Outcome::Reported => "REPORTED",
        Outcome::NotChecked => "NOT CHECKED",
    }
}

fn check_code(name: &str) -> &'static str {
    match name {
        "Saved deployment" => "saved_deployment",
        "Cloud VM" => "cloud_vm",
        "VM identity" => "vm_identity",
        "Public address" => "public_address",
        "Portal connection" => "portal_connection",
        "Portal claims" => "portal_claims",
        "Verification trust" => "verification_trust",
        "Portal TLS" => "portal_tls",
        "Verified status" => "verified_status",
        "Verified portal claims" => "verified_portal_claims",
        "Saved image" => "saved_image",
        "Saved chain ID" => "saved_chain_id",
        "Saved registry" => "saved_registry",
        "Saved registration" => "saved_registration",
        "Portal state" => "portal_state",
        "Initialization" => "initialization",
        "Disks" => "disks",
        "Registration" => "registration",
        "Session" => "session",
        "Workload log export" => "workload_log_export",
        _ if name.starts_with("Disk ") => "disk",
        _ => "diagnostic_collection",
    }
}

pub(super) fn public_reference(value: Option<&str>) -> Option<&str> {
    value.filter(|v| {
        !v.is_empty()
            && v.len() <= 512
            && !v.contains("://")
            && v.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-:/".contains(&c))
    })
}

pub(super) fn enum_value<'a>(value: &'a Value, allowed: &[&str]) -> Option<&'a str> {
    value.as_str().filter(|v| allowed.contains(v))
}

pub(super) fn fixed_hex(value: Option<&str>, bytes: usize) -> Option<String> {
    let value = value?.strip_prefix("0x").unwrap_or(value?);
    (value.len() == bytes * 2 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("0x{}", value.to_ascii_lowercase()))
}

fn public_comparison(c: &PcrMeasurementComparison) -> Option<Value> {
    let bytes = match c.bank.as_str() {
        "sha256" => 32,
        "sha384" => 48,
        _ => return None,
    };
    if c.pcr_index > 23 {
        return None;
    }
    let observed = fixed_hex(Some(&c.observed), bytes)?;
    let expected = match &c.expected {
        Some(v) => Some(fixed_hex(Some(v), bytes)?),
        None => None,
    };
    Some(
        json!({"bank":c.bank,"pcr_index":c.pcr_index,"expected":expected,
        "observed":observed,"matched":c.matched}),
    )
}

/// The TLS error carries one verifier JSON document followed by a CLI hint.
/// Read only that document, then select numeric PCR fields. Never export its
/// error strings, certificates, JWTs, collateral, or other evidence.
pub(super) fn tls_comparisons(error: &anyhow::Error) -> Vec<PcrMeasurementComparison> {
    let Some(PortalVerificationError::PortalTlsAttestationFailed { message }) =
        error.downcast_ref()
    else {
        return vec![];
    };
    let Some(Ok(report)) = serde_json::Deserializer::from_str(message)
        .into_iter::<VerificationReport>()
        .next()
    else {
        return vec![];
    };
    report
        .evidence
        .measurement_comparisons
        .into_iter()
        .filter(|c| public_comparison(c).is_some())
        .collect()
}

/// Logs have a separate explicit input and output. Never add these bytes to the
/// public diagnostic document or print them to the terminal.
pub(super) async fn write_logs(paths: &[std::path::PathBuf], output: &Path) -> Result<()> {
    use base64::Engine;
    use std::os::unix::fs::OpenOptionsExt;
    use tokio::io::AsyncReadExt;
    const MAX_BYTES: usize = 10 * 1024 * 1024;
    let mut remaining = MAX_BYTES;
    let mut entries = Vec::new();
    for path in paths {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .context("open selected local workload log")?;
        if !file.metadata()?.is_file() {
            bail!("selected workload log must be a regular file");
        }
        let file = tokio::fs::File::from_std(file);
        let mut bytes = Vec::new();
        file.take(remaining as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .context("read selected workload log")?;
        if bytes.len() > remaining {
            bail!("selected workload logs exceed the 10 MiB export limit");
        }
        remaining -= bytes.len();
        entries.push(
            json!({"name":path.file_name().map(|n| n.to_string_lossy()),"bytes":bytes.len(),
            "content_base64":base64::engine::general_purpose::STANDARD.encode(&bytes)}),
        );
    }
    write_new(
        output,
        &serde_json::to_vec_pretty(&json!({"schema":"atakit.workload-log-export.v1",
        "source":"operator_supplied_local_files", "redacted":false,"files":entries}))?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_success_cannot_override_failed_independent_verification() {
        let mut report = Report::default();
        report.add("Portal TLS", Outcome::Pass, "verified");
        report.add("Session", Outcome::Fail, "SECRET");
        report.status = Some(
            json!({"startup_checks":{"status":"passed","stage":"complete","detail":"SECRET"},
            "readiness":{"web":{"state":"ready","attempts":2}},
            "storage":{"sampled_at_ms":123,"entries":[],"error":"SECRET"}}),
        );
        let result = document(None, &report, Utc::now(), Duration::ZERO);
        assert_eq!(result["portal"]["startup_checks"]["status"], "passed");
        assert_eq!(result["independent_verification"]["session"], "FAIL");
        assert_eq!(result["failed"], true);
        assert_eq!(result["portal"]["readiness"][0]["attempts"], 2);
        assert!(!result.to_string().contains("SECRET"));
        report.status = Some(json!({"state":"Running"}));
        let legacy = document(None, &report, Utc::now(), Duration::ZERO);
        assert!(legacy["portal"]["storage"].is_null());
        assert!(legacy["portal"]["startup_checks"].is_null());
        assert!(legacy["portal"]["readiness"].is_null());
    }

    #[test]
    fn public_document_omits_raw_errors_urls_and_arbitrary_portal_fields() {
        let mut report = Report::default();
        report.add(
            "Portal TLS",
            Outcome::Fail,
            "SECRET key=abc https://user:pass@host/?token=SECRET",
        );
        report.add("Disk SECRET", Outcome::Reported, "SECRET");
        report.durations_ms.insert("Portal TLS", 15);
        report.status = Some(json!({"state":"Running","detail":"SECRET", "step":"SECRET",
            "base_image_ref":"https://SECRET", "env":{"PRIVATE_KEY":"SECRET"},
            "chain":{"registry_address":"SECRET", "status":"failed", "detail":"SECRET"},
            "disks":{"SECRET":{"state":"SECRET", "passphrase":"SECRET"}}}));
        let value = document(None, &report, Utc::now(), Duration::from_millis(20));
        assert!(!value.to_string().contains("SECRET"));
        assert!(!value.to_string().contains("pass@host"));
        assert_eq!(value["checks"][0]["error"], "portal_tls_failed");
        assert_eq!(value["checks"][0]["duration_ms"], 15);
        assert_eq!(value["duration_ms"], 20);
        assert_eq!(value["failed"], true);
    }

    #[test]
    fn only_typed_tls_failures_supply_valid_numeric_comparisons() {
        let comparison = PcrMeasurementComparison {
            bank: "sha256".into(),
            pcr_index: 0,
            expected: Some(format!("0x{}", "11".repeat(32))),
            observed: format!("0x{}", "22".repeat(32)),
            matched: false,
        };
        let mut report = VerificationReport {
            checks: vec![],
            evidence: Default::default(),
        };
        report
            .evidence
            .measurement_comparisons
            .push(comparison.clone());
        report.evidence.tee_evidence_auxiliary = Some("SECRET".into());
        let message = format!(
            "{}\nmanual override after inspection: SECRET",
            serde_json::to_string(&report).unwrap()
        );
        let error = anyhow::Error::from(PortalVerificationError::PortalTlsAttestationFailed {
            message: message.clone(),
        });
        let comparisons = tls_comparisons(&error);
        assert_eq!(comparisons.len(), 1);
        assert_eq!(comparisons[0].expected, comparison.expected);
        assert!(!serde_json::to_string(&comparisons)
            .unwrap()
            .contains("SECRET"));
        assert!(tls_comparisons(&anyhow::anyhow!(message)).is_empty());
        assert!(tls_comparisons(&anyhow::Error::from(
            PortalVerificationError::PortalTlsAttestationFailed {
                message: "portal returned an HTTP error: SECRET".into()
            }
        ))
        .is_empty());
        for (bank, index, observed) in [
            ("sha256", 0, "SECRET".into()),
            ("sha256", 24, comparison.observed.clone()),
            ("SECRET", 0, comparison.observed.clone()),
        ] {
            let mut invalid = comparison.clone();
            invalid.bank = bank.into();
            invalid.pcr_index = index;
            invalid.observed = observed;
            assert!(public_comparison(&invalid).is_none());
        }
    }

    #[test]
    fn output_is_private_complete_and_cannot_replace_a_file_or_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("report.json");
        write_new(&path, br#"{"complete":true}"#).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_new(&path, b"overwrite").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"complete":true}"#);
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(validate_destination(&link).is_err());
        assert!(write_new(&link, b"overwrite").is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
        assert!(same_destination(&path, &root.path().join("./report.json")));
    }

    #[tokio::test]
    async fn opted_in_logs_remain_separate_and_failed_exports_leave_no_partial_file() {
        use base64::Engine;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("web.log");
        std::fs::write(&source, b"SECRET\0\xff").unwrap();
        let output = root.path().join("logs.json");
        write_logs(std::slice::from_ref(&source), &output)
            .await
            .unwrap();
        let logs: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(logs["files"][0]["content_base64"].as_str().unwrap())
                .unwrap(),
            b"SECRET\0\xff"
        );
        assert_eq!(logs["redacted"], false);
        let report = document(None, &Report::default(), Utc::now(), Duration::ZERO);
        assert_eq!(report["workload_logs_included"], false);
        assert!(!report.to_string().contains("SECRET"));
        let link = root.path().join("link.log");
        symlink(&source, &link).unwrap();
        let failed = root.path().join("failed.json");
        assert!(write_logs(&[link], &failed).await.is_err());
        assert!(!failed.exists());
        let file = std::fs::File::create(&source).unwrap();
        file.set_len(10 * 1024 * 1024 + 1).unwrap();
        assert!(write_logs(&[source], &failed).await.is_err());
        assert!(!failed.exists());
    }
}
