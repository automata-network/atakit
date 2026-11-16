#![cfg(unix)]

use atakit_cloud::{
    AwsResources, DeployState, DeployStatus, NewDeployParams, PersistedInitEnv, PlatformKind,
    PortalPorts,
};
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, process::Command};

fn run_fixture(response: &str, exit_code: u8, observed_id: &str) -> (std::process::Output, String) {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    let data = root.path().join("data");
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(config.join("config.toml"), "").unwrap();
    let calls = root.path().join("calls");
    let executable = bin.join("aws");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nprintf '%s\\n' {}\nexit {exit_code}\n",
            shell_escape::escape(calls.display().to_string().into()),
            shell_escape::escape(response.into())
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut state = DeployState::new(NewDeployParams {
        instance_name: "vm".into(),
        target_name: "target".into(),
        provider_name: "aws".into(),
        platform: PlatformKind::Aws,
        workload_publisher: String::new(),
        workload_name: String::new(),
        workload_version: String::new(),
        image_ref: "image:v1".into(),
        base_image_ref: None,
        archive_path: "SECRET_ARCHIVE".into(),
        archive_hash: String::new(),
        init_env: PersistedInitEnv::default(),
        portal_ports: PortalPorts::default(),
        total_steps: 1,
    });
    state.status = DeployStatus::Failed {
        step: "init".into(),
        message: "SECRET_SAVED_ERROR".into(),
    };
    state.cloud_instance_id = Some(observed_id.into());
    state.resources.aws = Some(AwsResources {
        instance: Some("i-saved".into()),
        region: "region".into(),
        ..Default::default()
    });
    state.save(&data).unwrap();
    let path = data.join("cloud/deployments/target/vm.state.json");
    let before = std::fs::read(&path).unwrap();
    let report_path = root.path().join("diagnostics.json");
    let result = Command::new(env!("CARGO_BIN_EXE_atakit"))
        .args([
            "cloud",
            "diagnose",
            "vm",
            "--target",
            "target",
            "--check-timeout",
            "1",
        ])
        .arg("--report")
        .arg(&report_path)
        .env("PATH", &bin)
        .env("ATAKIT_CONFIG_DIR", &config)
        .env("ATAKIT_DATA_DIR", &data)
        .env("ATAKIT_CACHE_DIR", root.path().join("cache"))
        .output()
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.contains("SECRET"));
    let report_text = std::fs::read_to_string(&report_path).unwrap();
    assert!(!report_text.contains("SECRET"));
    let report: serde_json::Value = serde_json::from_str(&report_text).unwrap();
    assert_eq!(report["schema"], "atakit.cloud-diagnostics.v1");
    assert_eq!(report["failed"], true);
    assert_eq!(report["saved"]["state"], "failed");
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["outcome"] == "FAIL"));
    assert!(report["operations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["check"] == "cloud_vm" && c["duration_ms"].is_u64()));
    (result, std::fs::read_to_string(calls).unwrap())
}

#[test]
fn diagnose_failed_image_only_vm_without_mutating_saved_state() {
    let response = json!({"Reservations":[{"Instances":[{"InstanceId":"i-saved","State":{"Name":"stopped"}}]}]}).to_string();
    let (result, calls) = run_fixture(&response, 0, "i-saved");
    let text = String::from_utf8_lossy(&result.stdout);
    assert!(!result.status.success());
    assert!(text.contains("power state: stopped"));
    assert!(text.contains("no public address"));
    assert!(text.contains("NOT CHECKED"));
    assert_eq!(
        calls.trim(),
        "ec2 describe-instances --region region --instance-ids i-saved --output json"
    );
}

#[test]
fn diagnose_replaced_vm_stops_before_portal_access() {
    let response = json!({"Reservations":[{"Instances":[{"InstanceId":"i-new","State":{"Name":"running"},"PublicIpAddress":"127.0.0.1"}]}]}).to_string();
    let (result, calls) = run_fixture(&response, 0, "i-saved");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("unique instance ID differs"));
    assert_eq!(calls.lines().count(), 1);
}

#[test]
fn diagnose_cloud_failure_does_not_print_raw_provider_output() {
    let (result, calls) = run_fixture("SECRET_PROVIDER_RESPONSE", 1, "i-saved");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("cloud CLI query failed"));
    assert_eq!(calls.lines().count(), 1);
}

#[test]
fn diagnose_exports_missing_state_failure() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(config.join("config.toml"), "").unwrap();
    let report = root.path().join("report.json");
    let result = Command::new(env!("CARGO_BIN_EXE_atakit"))
        .args(["cloud", "diagnose", "missing", "--report"])
        .arg(&report)
        .env("ATAKIT_CONFIG_DIR", config)
        .env("ATAKIT_DATA_DIR", root.path().join("data"))
        .env("ATAKIT_CACHE_DIR", root.path().join("cache"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert!(value["saved"].is_null());
    assert_eq!(value["checks"][0]["error"], "saved_deployment_failed");
}
