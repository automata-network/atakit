use atakit_cloud::state::{DeployState, NewDeployParams, PersistedInitEnv, PortalPorts};
use atakit_cloud::PlatformKind;
use serde_json::Value;
use std::process::Command;
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        std::fs::create_dir(root.path().join("config")).unwrap();
        std::fs::write(root.path().join("config/config.toml"), "").unwrap();
        Self { root }
    }

    fn save(&self, instance: &str, mode: Option<bool>) {
        let mut state = DeployState::new(NewDeployParams {
            instance_name: instance.into(),
            target_name: "local".into(),
            workload_publisher: "publisher".into(),
            workload_name: "service".into(),
            workload_version: "v1".into(),
            provider_name: "qemu".into(),
            platform: PlatformKind::Qemu,
            image_ref: "linux:v1".into(),
            base_image_ref: None,
            archive_path: "SECRET_ARCHIVE_PATH".into(),
            archive_hash: "hash".into(),
            init_env: PersistedInitEnv::default(),
            portal_ports: PortalPorts::default(),
            total_steps: 1,
        });
        state.init_auth_required = mode;
        if mode == Some(true) {
            state.init_auth_key_file = Some("SECRET_CREDENTIAL_PATH".into());
        }
        state.init_env.owner_key = "SECRET_KEY_REFERENCE".into();
        state.save(&self.root.path().join("data")).unwrap();
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_atakit"))
            .args(args)
            .env("ATAKIT_CONFIG_DIR", self.root.path().join("config"))
            .env("ATAKIT_DATA_DIR", self.root.path().join("data"))
            .env("ATAKIT_CACHE_DIR", self.root.path().join("cache"))
            .output()
            .unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("SECRET"));
        assert!(!text.contains('\u{1b}'));
        serde_json::from_str(&text).unwrap()
    }
}

#[test]
fn list_json_handles_empty_filtered_and_all_modes() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.json(&["cloud", "list", "--json"])["deployments"],
        serde_json::json!([])
    );
    for (instance, mode) in [
        ("signed", Some(true)),
        ("unsigned", Some(false)),
        ("legacy", None),
    ] {
        fixture.save(instance, mode);
    }
    let list = fixture.json(&["cloud", "list", "--json"]);
    assert_eq!(list["format"], 1);
    let entries = list["deployments"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    for (name, mode) in [
        ("signed", "authenticated"),
        ("unsigned", "unsigned"),
        ("legacy", "unknown"),
    ] {
        assert_eq!(
            entries.iter().find(|e| e["instance"] == name).unwrap()["init_mode"],
            mode
        );
    }
    assert_eq!(
        fixture.json(&["cloud", "list", "--json", "--target", "missing"])["deployments"],
        serde_json::json!([])
    );
    let text = fixture.run(&["cloud", "list"]);
    let stderr = String::from_utf8_lossy(&text.stderr);
    assert!(stderr.contains("Init mode (saved)"));
    assert!(stderr.contains("authenticated"));
    assert!(stderr.contains("unsigned"));
    assert!(stderr.contains("unknown (not recorded)"));
}

#[test]
fn status_json_separates_saved_data_from_unavailable_live_data() {
    let fixture = Fixture::new();
    fixture.save("signed", Some(true));
    let saved = fixture.json(&["cloud", "status", "local/signed", "--json"]);
    assert_eq!(saved["saved"]["init_mode"], "authenticated");
    assert!(saved["live"].is_null());
    let live = fixture.json(&["cloud", "status", "local/signed", "--live", "--json"]);
    assert_eq!(live["saved"], saved["saved"]);
    assert_eq!(live["live"]["portal"]["verified"], false);
    assert!(live["live"]["portal"]["state"].is_null());
    assert_eq!(
        live["live"]["portal"]["error"],
        "no portal address available"
    );
    assert!(live["live"]["provider_error"].is_string());
}

#[cfg(unix)]
#[test]
fn status_watch_emits_fresh_json_after_failure_and_stops_on_ctrl_c() {
    use std::{
        io::{BufRead, BufReader},
        process::Stdio,
        time::{Duration, Instant},
    };
    let fixture = Fixture::new();
    fixture.save("signed", Some(true));
    let path = fixture
        .root
        .path()
        .join("data/cloud/deployments/local/signed.state.json");
    let before = std::fs::read(&path).unwrap();
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_atakit"))
            .args([
                "cloud",
                "status",
                "local/signed",
                "--live",
                "--verify",
                "--watch",
                "--interval",
                "1",
                "--json",
            ])
            .env("ATAKIT_CONFIG_DIR", fixture.root.path().join("config"))
            .env("ATAKIT_DATA_DIR", fixture.root.path().join("data"))
            .env("ATAKIT_CACHE_DIR", fixture.root.path().join("cache"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let first: Value =
        serde_json::from_str(&receiver.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
    assert_eq!(first["live"]["failed"], true);
    assert_eq!(first["live"]["portal"]["verified"], false);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    // A failed refresh must report that its saved input is now unavailable.
    std::fs::remove_file(&path).unwrap();
    let second: Value =
        serde_json::from_str(&receiver.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
    assert!(second["saved"].is_null());
    assert!(second["live"].is_null());
    assert!(second["error"].is_string());
    assert_ne!(first["observed_at"], second["observed_at"]);
    assert!(Command::new("kill")
        .args(["-INT", &child.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "watch did not stop on Ctrl+C");
        std::thread::sleep(Duration::from_millis(20));
    }
    reader.join().unwrap();
}

#[cfg(unix)]
#[test]
fn status_watch_ctrl_c_cancels_an_in_progress_cloud_query() {
    use std::{
        os::unix::fs::PermissionsExt,
        process::Stdio,
        time::{Duration, Instant},
    };
    let fixture = Fixture::new();
    fixture.save("signed", Some(true));
    let data = fixture.root.path().join("data");
    let mut state = DeployState::load_for_diagnose(&data, "local/signed", None).unwrap();
    state.platform = PlatformKind::Aws;
    state.cloud_instance_id = Some("i-saved".into());
    state.resources.aws = Some(atakit_cloud::AwsResources {
        instance: Some("i-saved".into()),
        region: "region".into(),
        ..Default::default()
    });
    state.save(&data).unwrap();
    let path = data.join("cloud/deployments/local/signed.state.json");
    let before = std::fs::read(&path).unwrap();
    let bin = fixture.root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let pid_file = fixture.root.path().join("provider-pid");
    std::fs::write(
        bin.join("aws"),
        format!(
            "#!/bin/sh\necho $$ > {}\nexec /bin/sleep 30\n",
            shell_escape::escape(pid_file.display().to_string().into())
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("aws"), std::fs::Permissions::from_mode(0o700)).unwrap();
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_atakit"))
            .args([
                "cloud",
                "status",
                "local/signed",
                "--live",
                "--verify",
                "--watch",
            ])
            .env("PATH", &bin)
            .env("ATAKIT_CONFIG_DIR", fixture.root.path().join("config"))
            .env("ATAKIT_DATA_DIR", &data)
            .env("ATAKIT_CACHE_DIR", fixture.root.path().join("cache"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pid_file.exists() {
        assert!(Instant::now() < deadline, "cloud query did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    assert!(Command::new("kill")
        .args(["-INT", &child.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "watch did not cancel its check");
        std::thread::sleep(Duration::from_millis(20));
    }
    let process = std::path::PathBuf::from(format!("/proc/{}", pid.trim()));
    while process.exists() {
        assert!(Instant::now() < deadline, "cloud query survived Ctrl+C");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
