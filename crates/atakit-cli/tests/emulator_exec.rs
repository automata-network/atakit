use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    process::Command,
};

#[test]
fn exec_preserves_external_environment_and_warns_without_exposing_values() {
    for overrides in [false, true] {
        let root = tempfile::tempdir_in("/private/tmp")
            .or_else(|_| tempfile::tempdir())
            .unwrap();
        std::fs::write(root.path().join("config.toml"), "").unwrap();
        let runtime = root.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        let endpoint = serde_json::json!({
            "environment_id":"test", "upstream_rpc_url":"http://localhost:8545",
            "anchor_number":1, "anchor_hash":"0x00", "rpc_url":"http://localhost:8546",
            "chain_id":31337, "session_registry":"0x1", "workload_registry":"0x2",
            "base_image_registry":"0x3", "state":"ready",
            "workloads":{"validator":{
                "config_file":root.path().join("atakit-workload.toml"),
                "workload_dir":root.path(), "portal_socket":runtime.join("portal.sock"),
                "publisher_fingerprint":"0x00", "state":"ready",
                "env":{"VALIDATOR_PORT":"9001", "TEST_SECRET":"configured-secret",
                    "TEST_EMPTY":"default", "TEST_SAME":"same", "EMULATOR_ROOTFS":"/runtime/root"}
            }}
        });
        std::fs::write(runtime.join("endpoints.json"), endpoint.to_string()).unwrap();
        let listener = UnixListener::bind(runtime.join("control.sock")).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            writeln!(stream, "{endpoint}").unwrap();
        });
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_atakit"));
        cmd.env_clear()
            .env("HOME", root.path())
            .env("ATAKIT_CONFIG_DIR", root.path())
            .env("ATAKIT_DATA_DIR", root.path().join("data"))
            .env("ATAKIT_CACHE_DIR", root.path().join("cache"))
            .env("TEST_INHERITED", "inherited")
            .env("TEST_SAME", "same")
            .args(["emulator", "exec", "--runtime-dir"])
            .arg(&runtime)
            .args(["--workload", "validator", "--", "/bin/sh", "-c",
                "printf '%s\\n' \"$VALIDATOR_PORT\" \"$TEST_SECRET\" \"$TEST_EMPTY\" \"$TEST_SAME\" \"$EMULATOR_ROOTFS\" \"$TEST_INHERITED\""]);
        if overrides {
            cmd.env("VALIDATOR_PORT", "9002")
                .env("TEST_SECRET", "external-secret")
                .env("TEST_EMPTY", "")
                .env("EMULATOR_ROOTFS", "/external/root");
        }
        let output = cmd.output().unwrap();
        server.join().unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{stderr}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            if overrides {
                "9002\nexternal-secret\n\nsame\n/external/root\ninherited\n"
            } else {
                "9001\nconfigured-secret\ndefault\nsame\n/runtime/root\ninherited\n"
            }
        );
        for name in [
            "VALIDATOR_PORT",
            "TEST_SECRET",
            "TEST_EMPTY",
            "EMULATOR_ROOTFS",
        ] {
            assert_eq!(stderr.contains(name), overrides, "{stderr}");
        }
        for hidden in [
            "configured-secret",
            "external-secret",
            "TEST_SAME",
            "TEST_INHERITED",
        ] {
            assert!(!stderr.contains(hidden), "{stderr}");
        }
    }
}
