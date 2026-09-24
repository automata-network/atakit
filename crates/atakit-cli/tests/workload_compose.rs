use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_atakit"));
    command
        .args(["emulator", "workload-compose"])
        .current_dir(root)
        .env("ATAKIT_CONFIG_DIR", root)
        .env_remove("ATAKIT_CONTAINER_ENGINE")
        .env("ATAKIT_DATA_DIR", root.join("data"))
        .env("ATAKIT_CACHE_DIR", root.join("cache"))
        .env("PATH", root.join("bin"));
    command
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    std::fs::write(
        root.path().join("config.toml"),
        "[build]\ncontainer_engine = 'docker'\n",
    )
    .unwrap();
    std::fs::create_dir(root.path().join("bin")).unwrap();
    let docker = root.path().join("bin/docker");
    std::fs::write(&docker, "#!/bin/sh\nprintf '%s\\n' \"$@\" > docker-args\nprintf 'docker output\\n'\nprintf 'docker error\\n' >&2\nexit 37\n").unwrap();
    std::fs::set_permissions(docker, std::fs::Permissions::from_mode(0o755)).unwrap();
    root
}

#[test]
fn stopped_runtime_forwards_arguments_output_and_exit_code() {
    let root = fixture();
    let runtime = root.path().join(".atakit-emulator");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::create_dir(runtime.join("app")).unwrap();
    let compose = runtime.join("app/compose.yaml");
    std::fs::write(&compose, "services: {}\n").unwrap();
    for (args, forwarded) in [
        (vec!["down", "--volumes"], vec!["down", "--volumes"]),
        (
            vec!["log", "-f", "--tail", "100"],
            vec!["logs", "-f", "--tail", "100"],
        ),
        (
            vec!["exec", "app", "sh", "-c", "echo hello world", "--help"],
            vec!["exec", "app", "sh", "-c", "echo hello world", "--help"],
        ),
    ] {
        let output = command(root.path())
            .args(["--workload", "app"])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(37),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"docker output\n");
        assert!(String::from_utf8_lossy(&output.stderr).contains("docker error"));
        let mut expected = format!("compose\n-f\n{}\n", compose.display());
        for arg in forwarded {
            expected.push_str(&format!("{arg}\n"));
        }
        assert_eq!(
            std::fs::read_to_string(root.path().join("docker-args")).unwrap(),
            expected
        );
        assert_eq!(std::fs::read_to_string(&compose).unwrap(), "services: {}\n");
    }
}

#[test]
fn missing_compose_explains_how_to_generate_it() {
    let root = fixture();
    let output = command(root.path()).arg("down").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("workload-compose up"));
    assert!(!root.path().join("docker-args").exists());
}

#[test]
fn up_never_runs_docker_when_regeneration_fails_even_with_an_old_file() {
    let root = fixture();
    let runtime = root.path().join(".atakit-emulator");
    std::fs::create_dir_all(runtime.join("app")).unwrap();
    std::fs::write(runtime.join("app/compose.yaml"), "services: {}\n").unwrap();
    let output = command(root.path())
        .args(["--workload", "app", "up", "-d", "--build"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!root.path().join("docker-args").exists());
}

#[test]
fn up_regenerates_before_docker_and_honors_selection_and_output() {
    use atakit_emulator::endpoints::{EndpointInfo, WorkloadEndpoint};
    use std::{
        collections::BTreeMap,
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixListener,
    };
    let root = fixture();
    let runtime = root.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let config = root.path().join("atakit-workload.toml");
    std::fs::write(&config, "format=7\n[workload]\nname='app'\nversion='1'\nbase-image-mode='whitelist'\nimage={build='new-source'}\natakit-portal=false\n").unwrap();
    let workload = WorkloadEndpoint {
        version: Some("1".into()),
        config_file: config,
        workload_dir: root.path().into(),
        portal_socket: root.path().join("unused.sock"),
        owner_fingerprint: None,
        publisher_fingerprint: String::new(),
        workload_id: None,
        session_id: None,
        state: "ready".into(),
        error: None,
        env: BTreeMap::from([(
            "EMULATOR_ROOTFS".into(),
            root.path().join("root").display().to_string(),
        )]),
    };
    let endpoints = EndpointInfo {
        environment_id: "test".into(),
        upstream_rpc_url: "http://localhost:8545".into(),
        anchor_number: 0,
        anchor_hash: "0x00".into(),
        rpc_url: "http://127.0.0.1:8546".into(),
        chain_id: 31337,
        session_registry: String::new(),
        workload_registry: String::new(),
        base_image_registry: String::new(),
        state: "ready".into(),
        workloads: BTreeMap::from([("app".into(), workload.clone()), ("other".into(), workload)]),
    };
    std::fs::write(
        runtime.join("endpoints.json"),
        serde_json::to_vec(&endpoints).unwrap(),
    )
    .unwrap();
    let listener = UnixListener::bind(runtime.join("control.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();

    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("fixture did not receive a request: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert!(request.contains("status"));
        writeln!(stream, "{}", serde_json::to_string(&endpoints).unwrap()).unwrap();
    });
    let output_path = root.path().join("custom.yaml");
    std::fs::write(&output_path, "stale file").unwrap();
    std::fs::write(
        root.path().join("bin/docker"),
        "#!/bin/sh\n/bin/cat \"$3\"\nprintf '%s\\n' \"$@\" > docker-args\n",
    )
    .unwrap();
    let output = command(root.path())
        .arg("--runtime-dir")
        .arg(&runtime)
        .args([
            "--workload",
            "app",
            "--portal-transport",
            "native",
            "--output",
        ])
        .arg(&output_path)
        .args(["up", "-d", "--build"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = String::from_utf8(output.stdout).unwrap();
    assert!(document.contains("new-source"));
    assert!(!document.contains("stale file"));
    assert!(!document.contains("other:"));
    assert_eq!(document, std::fs::read_to_string(&output_path).unwrap());
    assert_eq!(
        std::fs::read_to_string(root.path().join("docker-args")).unwrap(),
        format!("compose\n-f\n{}\nup\n-d\n--build\n", output_path.display())
    );
}

#[test]
fn compose_uses_configured_engine_and_existing_auto_detection_order() {
    for (configured, available, expected) in [
        ("docker", vec!["docker", "podman"], "docker"),
        ("podman", vec!["docker", "podman"], "podman"),
        ("auto", vec!["docker", "podman"], "podman"),
        ("auto", vec!["docker"], "docker"),
        ("podman", vec!["docker"], ""),
        ("auto", vec![], ""),
    ] {
        let root = fixture();
        std::fs::remove_file(root.path().join("bin/docker")).unwrap();
        std::fs::write(
            root.path().join("config.toml"),
            format!("[build]\ncontainer_engine = '{configured}'\n"),
        )
        .unwrap();
        let runtime = root.path().join(".atakit-emulator");
        std::fs::create_dir_all(runtime.join("app")).unwrap();
        std::fs::write(runtime.join("app/compose.yaml"), "services: {}\n").unwrap();
        for engine in available {
            let path = root.path().join("bin").join(engine);
            std::fs::write(&path, format!("#!/bin/sh\nif [ \"$1\" = --version ]; then exit 0; fi\nprintf '{engine}\\n'\nprintf '%s\\n' \"$@\" > engine-args\n")).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let output = command(root.path())
            .args(["--workload", "app", "logs", "--tail", "5"])
            .output()
            .unwrap();
        if expected.is_empty() {
            assert!(
                !output.status.success(),
                "{configured} unexpectedly succeeded"
            );
            assert!(!root.path().join("engine-args").exists());
        } else {
            assert!(
                output.status.success(),
                "{configured}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("{expected}\n")
            );
            assert_eq!(
                std::fs::read_to_string(root.path().join("engine-args")).unwrap(),
                format!(
                    "compose\n-f\n{}\nlogs\n--tail\n5\n",
                    runtime.join("app/compose.yaml").display()
                )
            );
        }
    }
}

#[test]
fn compose_help_comes_from_selected_engine_without_runtime_files() {
    for engine in ["docker", "podman"] {
        let root = fixture();
        std::fs::write(
            root.path().join("config.toml"),
            format!("[build]\ncontainer_engine='{engine}'\n"),
        )
        .unwrap();
        let binary = root.path().join("bin").join(engine);
        std::fs::write(&binary, "#!/bin/sh\nprintf '%s\\n' \"$@\" > help-args\nprintf 'Commands: up down logs provider-specific-command\\n'\n").unwrap();
        std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        for args in [vec![], vec!["--help"], vec!["-h"], vec!["up", "--help"]] {
            let output = command(root.path()).args(&args).output().unwrap();
            assert!(
                output.status.success(),
                "{:?}: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
            let help = String::from_utf8(output.stdout).unwrap();
            assert!(help.contains("provider-specific-command"));
            if args.len() < 2 {
                assert!(help.contains("--portal-transport"));
                assert!(help.contains("atakit emulator workload-compose"));
            }
            let expected = if args.len() == 2 {
                "compose\nup\n--help\n"
            } else {
                "compose\n--help\n"
            };
            assert_eq!(
                std::fs::read_to_string(root.path().join("help-args")).unwrap(),
                expected
            );
            assert!(!root.path().join(".atakit-emulator").exists());
        }
    }
}

#[test]
fn offline_compose_selects_each_workloads_own_file() {
    let root = fixture();
    let runtime = root.path().join(".atakit-emulator");
    for name in ["signer", "api"] {
        std::fs::create_dir_all(runtime.join(name)).unwrap();
        std::fs::write(runtime.join(name).join("compose.yaml"), "services: {}\n").unwrap();
    }
    for name in ["signer", "api"] {
        let output = command(root.path())
            .args(["--workload", name, "down"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(37),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("docker-args")).unwrap(),
            format!(
                "compose\n-f\n{}\ndown\n",
                runtime.join(name).join("compose.yaml").display()
            )
        );
    }
    let ambiguous = command(root.path()).arg("down").output().unwrap();
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("--workload"));
}

#[test]
fn stopped_single_workload_is_inferred_from_saved_endpoints_not_a_shared_file() {
    let root = fixture();
    let runtime = root.path().join(".atakit-emulator");
    std::fs::create_dir_all(runtime.join("app")).unwrap();
    let compose = runtime.join("app/compose.yaml");
    std::fs::write(&compose, "services: {}\n").unwrap();
    let endpoints = serde_json::json!({
        "environment_id":"fixture", "upstream_rpc_url":"http://localhost:8545",
        "anchor_number":0, "anchor_hash":"0x0", "rpc_url":"http://localhost:8546",
        "chain_id":31337, "session_registry":"", "workload_registry":"",
        "base_image_registry":"", "state":"ready", "workloads":{
            "app": {"config_file":"unused", "workload_dir":"unused", "portal_socket":"unused",
                "owner_fingerprint":null, "publisher_fingerprint":"", "workload_id":null,
                "session_id":null, "state":"ready", "error":null, "env":{}}
        }
    });
    std::fs::write(runtime.join("endpoints.json"), endpoints.to_string()).unwrap();
    let output = command(root.path()).arg("ps").output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("docker-args")).unwrap(),
        format!("compose\n-f\n{}\nps\n", compose.display())
    );
}
