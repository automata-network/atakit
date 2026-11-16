use super::*;
use atakit_cloud::{DeployStatus, NewDeployParams, PersistedInitEnv, PlatformKind, PortalPorts};
use serde_json::json;

fn state() -> DeployState {
    let mut state = DeployState::new(NewDeployParams {
        instance_name: "vm".into(),
        target_name: "target".into(),
        provider_name: "provider".into(),
        platform: PlatformKind::Azure,
        workload_publisher: format!("0x{}", "11".repeat(32)),
        workload_name: "workload".into(),
        workload_version: "v1".into(),
        image_ref: "image:v1".into(),
        base_image_ref: Some("image:v1".into()),
        archive_path: "private-archive".into(),
        archive_hash: String::new(),
        init_env: PersistedInitEnv::default(),
        portal_ports: PortalPorts::default(),
        total_steps: 1,
    });
    state.status = DeployStatus::Deployed {
        ip: "192.0.2.1".into(),
    };
    state
}

#[test]
fn read_only_load_accepts_failed_and_image_only_records_without_changing_them() {
    let root = tempfile::tempdir().unwrap();
    let mut state = state();
    state.status = DeployStatus::Failed {
        step: "init".into(),
        message: "failed".into(),
    };
    state.workload_name.clear();
    state.workload_version.clear();
    state.save(root.path()).unwrap();
    let path = root.path().join("cloud/deployments/target/vm.state.json");
    let before = std::fs::read(&path).unwrap();
    let loaded = DeployState::load_for_diagnose(root.path(), "vm", None).unwrap();
    assert!(matches!(loaded.status, DeployStatus::Failed { .. }));
    assert!(loaded.workload_name.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
}

#[test]
fn missing_records_do_not_create_directories_and_ambiguous_names_fail() {
    let root = tempfile::tempdir().unwrap();
    assert!(DeployState::load_for_diagnose(root.path(), "vm", None).is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    let mut state = state();
    state.save(root.path()).unwrap();
    state.target_name = "another".into();
    state.save(root.path()).unwrap();
    assert!(DeployState::load_for_diagnose(root.path(), "vm", None).is_err());
    assert!(DeployState::load_for_diagnose(root.path(), "target/vm", Some("another")).is_err());
    assert!(DeployState::load_for_diagnose(root.path(), "../vm", None).is_err());
    assert_eq!(
        DeployState::load_for_diagnose(root.path(), "target/vm", None)
            .unwrap()
            .target_name,
        "target"
    );
}

#[test]
fn vm_identity_mismatch_blocks_portal_checks() {
    assert_eq!(compare_vm_id(Some("old"), "new"), Outcome::Fail);
    assert_eq!(compare_vm_id(Some("same"), "same"), Outcome::Pass);
    assert_eq!(compare_vm_id(None, "new"), Outcome::NotChecked);
    let mut report = Report::default();
    report.skip_portal("VM identity mismatch");
    assert_eq!(report.checks.len(), 6);
    assert!(report
        .checks
        .iter()
        .all(|c| c.outcome == Outcome::NotChecked));
}

#[test]
fn portal_claims_do_not_become_saved_expectations() {
    let mut state = state();
    state.base_image_ref = None;
    let config = Config::default();
    let status = json!({"base_image_ref":"untrusted/image:v1","chain":{"chain_id":31337,"registry_address":"0xdeadbeef"}});
    let mut report = Report::default();
    compare_claims(&mut report, &state, &config, &status);
    assert!(report
        .checks
        .iter()
        .all(|c| c.outcome == Outcome::NotChecked));
    assert!(claims(&status, false).starts_with("UNVERIFIED"));
    assert!(claims(&status, false).contains("31337"));
    assert!(config.chains.is_empty());
}

#[test]
fn claimed_image_and_registry_mismatches_fail_but_absence_is_not_checked() {
    let mut report = Report::default();
    compare_value(
        &mut report,
        "image",
        Some("image:v1"),
        Some("image:v2"),
        false,
    );
    compare_value(
        &mut report,
        "registry",
        Some("0xAbCd"),
        Some("0xabcd"),
        true,
    );
    compare_value(&mut report, "chain", Some("1"), None, false);
    assert_eq!(report.checks[0].outcome, Outcome::Fail);
    assert_eq!(report.checks[1].outcome, Outcome::Pass);
    assert_eq!(report.checks[2].outcome, Outcome::NotChecked);
}

#[test]
fn disk_unlock_is_reported_without_exposing_private_status_fields() {
    let mut report = Report::default();
    let status = json!({"state":"AwaitingDiskUnlock", "disks":{"data":{"state":"awaiting_passphrase", "passphrase":"SECRET"}}, "chain":{"status":"pending"}});
    inspect_status(&mut report, &state(), &status, "cert");
    assert!(!report.failed());
    assert_eq!(
        report.next,
        vec!["atakit cloud disk unlock vm --target target --disk data"]
    );
    assert!(!format!("{report:?}").contains("SECRET"));
    assert!(report
        .checks
        .iter()
        .any(|c| c.name == "Initialization" && c.outcome == Outcome::NotChecked));
}

#[test]
fn failed_registration_and_terminal_or_unknown_portal_states_are_failures() {
    for status in [
        json!({"state":"Running","chain":{"status":"failed","detail":"transaction reverted"}}),
        json!({"state":"Failed","detail":"prover failed"}),
        json!({"state":"CleanHalt"}),
        json!({"state":"new-state"}),
    ] {
        let mut report = Report::default();
        inspect_status(&mut report, &state(), &status, "cert");
        assert!(report.failed());
    }
}

#[test]
fn mismatched_initialization_identity_blocks_recovery_suggestions() {
    let mut state = state();
    state.initialization = Some(resume::Initialization {
        transfer_id: "transfer".into(),
        phase: resume::InitializationPhase::MayHaveBeenSent,
        bootstrap: None,
        inputs_sha256: String::new(),
        tls_sha256: Some("cert".into()),
        submitted_config_sha256: None,
    });
    let mut report = Report::default();
    inspect_status(
        &mut report,
        &state,
        &json!({"state":"AwaitingDiskUnlock", "disks":{"data":{"state":"awaiting_passphrase"}}}),
        "cert",
    );
    assert!(report.failed());
    assert!(report.next.is_empty());
}

#[tokio::test]
async fn diagnostic_timeout_is_bounded() {
    let result = bounded(0, std::future::pending::<Result<()>>()).await;
    assert!(result.unwrap_err().to_string().contains("timed out"));
}

#[test]
fn restored_running_workload_without_init_identity_allows_session_diagnosis() {
    let mut state = state();
    state.initialization = Some(resume::Initialization {
        transfer_id: "old-transfer".into(),
        phase: resume::InitializationPhase::MayHaveBeenSent,
        bootstrap: None,
        inputs_sha256: String::new(),
        tls_sha256: Some("same-cert".into()),
        submitted_config_sha256: None,
    });
    for status in [
        json!({"state":"Running","disks":{},"chain":{"status":"verified"}}),
        json!({"state":"Running","init_auth":null,"disks":{},"chain":{"status":"verified"}}),
    ] {
        let mut report = Report::default();
        inspect_status(&mut report, &state, &status, "same-cert");
        assert!(!report.failed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "Initialization" && c.outcome == Outcome::NotChecked));
        assert!(report.next.is_empty());
    }
    // A reported identity must still be checked, even for a running workload.
    let mut report = Report::default();
    inspect_status(
        &mut report,
        &state,
        &json!({"state":"Running","init_auth":{"deployment_id":"different"}}),
        "same-cert",
    );
    assert!(report.failed());
    assert!(report.next.is_empty());
}

#[test]
fn changed_boot_certificate_does_not_block_current_session_diagnosis() {
    let mut state = state();
    state.initialization = Some(resume::Initialization {
        transfer_id: "old-transfer".into(),
        phase: resume::InitializationPhase::VerifiedComplete,
        bootstrap: None,
        inputs_sha256: String::new(),
        tls_sha256: Some("old-cert".into()),
        submitted_config_sha256: None,
    });
    let mut report = Report::default();
    inspect_status(
        &mut report,
        &state,
        &json!({"state":"Running","init_auth":{"deployment_id":"old-boot"},"disks":{},"chain":{"status":"verified"}}),
        "new-cert",
    );
    assert!(!report.failed());
    assert!(report
        .checks
        .iter()
        .any(|c| c.name == "Initialization" && c.outcome == Outcome::NotChecked));
    assert!(report.next.is_empty());
}

#[test]
fn display_bounds_text_and_omits_credential_bearing_urls() {
    let value = display_text("error https://user:secret@example.test?key=SECRET \x1b[31mfailed");
    assert!(!value.contains("SECRET"));
    assert!(!value.contains("secret"));
    assert!(!value.contains('\x1b'));
    assert!(display_text(&"x".repeat(4096)).len() <= 1024);
}
