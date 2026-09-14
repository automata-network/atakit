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
