use std::process::Command;

#[test]
fn status_lists_all_chains_without_a_runtime_or_target() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("config.toml"),
        r#"
[publish]
chain = "hoodi"
[chains.hoodi]
rpc_url = "http://127.0.0.1:1"
session_registry = "0x1111111111111111111111111111111111111111"
[chains.local]
rpc_url = "http://127.0.0.1:2"
session_registry = "0x2222222222222222222222222222222222222222"
chain_id = 31337
"#,
    )
    .unwrap();
    let runtime = root.path().join("runtime");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_atakit"))
            .args(["emulator", "status", "--json", "--runtime-dir"])
            .arg(&runtime)
            .env("ATAKIT_CONFIG_DIR", root.path())
            .env("ATAKIT_DATA_DIR", root.path().join("data"))
            .env("ATAKIT_CACHE_DIR", root.path().join("cache"))
            .output()
            .unwrap()
    };
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["state"], "stopped");
    assert_eq!(value["default_chain"], "hoodi");
    assert_eq!(value["chains"].as_object().unwrap().len(), 2);
    assert_eq!(value["chains"]["local"]["chain_id"], 31337);
    assert_eq!(value["chains"]["hoodi"]["rpc_url"], "http://127.0.0.1:1");
    assert!(value["chains"]["hoodi"]["base_image_registry"].is_null());
    assert!(!runtime.exists());
    // Corrupt runtime records must not be disguised as a stopped emulator.
    std::fs::create_dir(&runtime).unwrap();
    std::fs::write(runtime.join("endpoints.json"), "broken").unwrap();
    assert!(!run().status.success());
}

#[test]
fn status_preserves_live_endpoints_and_marks_stale_endpoints_stopped() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("config.toml"), "").unwrap();
    let runtime = root.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let endpoint = serde_json::json!({
        "environment_id":"fixture", "upstream_rpc_url":"http://localhost:8545",
        "anchor_number":42, "anchor_hash":"0xabc", "rpc_url":"http://localhost:8546",
        "chain_id":31337, "session_registry":"0x1", "workload_registry":"0x2",
        "base_image_registry":"0x3", "state":"ready", "workloads":{
            "guardian": {
                "version":"v0.2.1", "config_file":"/missing/atakit-workload.toml",
                "workload_dir":"/missing", "portal_socket":"/missing/portal.sock",
                "owner_fingerprint":null, "publisher_fingerprint":"0x123",
                "workload_id":null, "session_id":null, "state":"initializing",
                "error":null, "env":{}
            }
        }
    });
    std::fs::write(runtime.join("endpoints.json"), endpoint.to_string()).unwrap();
    let listener = UnixListener::bind(runtime.join("control.sock")).unwrap();
    let expected = endpoint.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&request).unwrap()["operation"],
            "status"
        );
        writeln!(stream, "{endpoint}").unwrap();
    });
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_atakit"))
            .args(["emulator", "status", "--runtime-dir"])
            .arg(&runtime)
            .env("ATAKIT_CONFIG_DIR", root.path())
            .env("ATAKIT_DATA_DIR", root.path().join("data"))
            .env("ATAKIT_CACHE_DIR", root.path().join("cache"))
            .output()
            .unwrap()
    };
    let output = run();
    server.join().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for (key, field) in expected.as_object().unwrap() {
        assert_eq!(&value[key], field);
    }
    assert_eq!(value["chains"], serde_json::json!({}));
    let stopped = run();
    assert!(stopped.status.success());
    let value: serde_json::Value = serde_json::from_slice(&stopped.stdout).unwrap();
    assert_eq!(value["state"], "stopped");
    assert!(value.get("rpc_url").is_none());
}
