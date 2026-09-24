use std::{fs, path::Path};

use atakit_emulator::{
    cli::{EmulatorCli, EmulatorCommand},
    config::resolve_up,
};
use clap::Parser;
use tempfile::TempDir;

fn temp_dir() -> TempDir {
    tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap()
}

fn workload(dir: &Path, file_name: &str, name: &str) -> std::path::PathBuf {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join(file_name);
    fs::write(
        &path,
        format!(
            "format = 7\n[workload]\nname = \"{name}\"\nversion = \"1.0.0\"\nbase-image-mode = \"locked\"\nimage = {{ build = \".\" }}\n"
        ),
    )
    .unwrap();
    path
}

fn up(args: &[&str]) -> atakit_emulator::cli::UpArgs {
    let cli =
        EmulatorCli::try_parse_from(std::iter::once("atakit-emulator").chain(args.iter().copied()))
            .unwrap();
    let EmulatorCommand::Up(args) = cli.command else {
        panic!("expected up")
    };
    args
}

#[test]
fn registry_override_is_not_supported() {
    assert!(EmulatorCli::try_parse_from([
        "atakit-emulator",
        "up",
        "--workload",
        "signer=.",
        "--chain",
        "hoodi",
        "--session-registry",
        "0x7575BceC155b272077C87aD3Ae5Ef54Cf9DC6601",
    ])
    .is_err());
}

#[test]
fn cli_defaults_and_explicit_false_are_resolved() {
    let temp = temp_dir();
    workload(
        &temp.path().join("signer"),
        "atakit-workload.toml",
        "signer",
    );
    fs::write(
        temp.path().join("emulator.toml"),
        "foreground = true\nfork-url = \"http://upstream:1234\"\nanvil-port = 9546\n[[workloads]]\nfile = \"signer\"\n",
    ).unwrap();

    let args = up(&["up", "--config", "emulator.toml", "--foreground=false"]);
    let resolved = resolve_up(&args, temp.path()).unwrap();
    assert!(!resolved.foreground);
    assert_eq!(resolved.fork_url, "http://upstream:1234");
    assert_eq!(resolved.anvil_port, 9546);
    assert_eq!(resolved.runtime_dir, temp.path().join(".atakit-emulator"));
    assert_eq!(
        resolved.workloads[0].output_socket,
        temp.path()
            .join(".atakit-emulator/signer/root/run/atakit-portal.sock")
    );
}

#[test]
fn cli_workloads_replace_file_entries_and_cli_paths_use_cwd() {
    let temp = temp_dir();
    let config_dir = temp.path().join("configuration");
    let cwd = temp.path().join("caller");
    workload(&config_dir.join("old"), "atakit-workload.toml", "old");
    workload(&cwd.join("new"), "custom.toml", "underlying");
    fs::create_dir_all(&cwd).unwrap();
    fs::write(
        config_dir.join("emulator.toml"),
        "owner-key = \"file-shared\"\n[[workloads]]\nfile = \"old\"\nname = \"old-alias\"\noutput-socket = \"old.sock\"\nowner-key = \"file-local\"\n",
    ).unwrap();

    let args = up(&[
        "up",
        "--config",
        "../configuration/emulator.toml",
        "--workload",
        "chosen=new/custom.toml",
    ]);
    let resolved = resolve_up(&args, &cwd).unwrap();
    assert_eq!(resolved.workloads.len(), 1);
    assert_eq!(resolved.workloads[0].name, "chosen");
    assert_eq!(
        resolved.workloads[0].config_file,
        cwd.join("new/custom.toml")
    );
    assert_eq!(
        resolved.workloads[0].owner_key.as_deref(),
        Some("file-shared")
    );
    assert_eq!(
        resolved.workloads[0].output_socket,
        cwd.join(".atakit-emulator/chosen/root/run/atakit-portal.sock")
    );
}

#[test]
fn named_overrides_bind_independently_of_argument_order() {
    let temp = temp_dir();
    workload(&temp.path().join("one"), "atakit-workload.toml", "one");
    workload(&temp.path().join("two"), "atakit-workload.toml", "two");
    let args = up(&[
        "up",
        "--workload",
        "first=one",
        "--workload",
        "second=two",
        "--output-socket",
        "second=second.sock",
        "--output-socket",
        "first=first.sock",
        "--owner-key",
        "shared",
        "--owner-key",
        "second=second-key",
    ]);
    let resolved = resolve_up(&args, temp.path()).unwrap();
    assert_eq!(
        resolved.workloads[0].output_socket,
        temp.path().join("first.sock")
    );
    assert_eq!(resolved.workloads[0].owner_key.as_deref(), Some("shared"));
    assert_eq!(
        resolved.workloads[1].output_socket,
        temp.path().join("second.sock")
    );
    assert_eq!(
        resolved.workloads[1].owner_key.as_deref(),
        Some("second-key")
    );
}

#[test]
fn rejects_ambiguous_or_conflicting_instances_and_overrides() {
    let temp = temp_dir();
    workload(&temp.path().join("one"), "atakit-workload.toml", "same");
    workload(&temp.path().join("two"), "atakit-workload.toml", "same");

    let duplicate_names = resolve_up(
        &up(&["up", "--workload", "one", "--workload", "two"]),
        temp.path(),
    )
    .unwrap_err();
    assert!(duplicate_names
        .to_string()
        .contains("duplicate workload name"));

    let ambiguous_socket = resolve_up(
        &up(&[
            "up",
            "--workload",
            "left=one",
            "--workload",
            "right=two",
            "--output-socket",
            "custom.sock",
        ]),
        temp.path(),
    )
    .unwrap_err();
    assert!(ambiguous_socket.to_string().contains("must include NAME="));

    let duplicate_socket = resolve_up(
        &up(&[
            "up",
            "--workload",
            "left=one",
            "--workload",
            "right=two",
            "--output-socket",
            "left=shared.sock",
            "--output-socket",
            "right=shared.sock",
        ]),
        temp.path(),
    )
    .unwrap_err();
    assert!(duplicate_socket.to_string().contains("output socket"));
}

#[test]
fn default_config_is_loaded_and_errors_name_the_selected_source() {
    let temp = temp_dir();
    workload(temp.path(), "atakit-workload.toml", "nearby");
    fs::write(
        temp.path().join("atakit-emulator.toml"),
        "[[workloads]]\nfile = \".\"\n",
    )
    .unwrap();
    let resolved = resolve_up(&up(&["up"]), temp.path()).unwrap();
    assert_eq!(resolved.workloads[0].name, "nearby");

    let bad = temp.path().join("bad.toml");
    fs::write(
        &bad,
        "session-registry = \"forbidden\"\n[[workloads]]\nfile = \".\"\n",
    )
    .unwrap();
    let error = resolve_up(&up(&["up", "--config", "bad.toml"]), temp.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("bad.toml"));
    assert!(error.contains("session-registry"));
}

#[test]
fn rejects_invalid_aliases_and_duplicate_overrides() {
    let temp = temp_dir();
    workload(temp.path(), "atakit-workload.toml", "valid");
    let traversal = resolve_up(&up(&["up", "--workload", "../bad=."]), temp.path()).unwrap_err();
    assert!(traversal.to_string().contains("invalid workload name"));

    let duplicate = resolve_up(
        &up(&[
            "up",
            "--workload",
            ".",
            "--output-socket",
            "one.sock",
            "--output-socket",
            "two.sock",
        ]),
        temp.path(),
    )
    .unwrap_err();
    assert!(duplicate
        .to_string()
        .contains("duplicate output socket override"));
}

#[test]
fn malformed_config_error_does_not_echo_owner_key() {
    let temp = temp_dir();
    let secret = "0x0123456789abcdef-private-owner-key";
    fs::write(
        temp.path().join("bad-secret.toml"),
        format!("owner-key = \"{secret}\" trailing\n[[workloads]]\nfile = \".\"\n"),
    )
    .unwrap();
    let error = resolve_up(&up(&["up", "--config", "bad-secret.toml"]), temp.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("bad-secret.toml"));
    assert!(error.contains("line") || error.contains("byte"));
    assert!(!error.contains(secret));
}

#[test]
fn empty_file_paths_are_rejected_without_discovery() {
    let temp = temp_dir();
    workload(temp.path(), "atakit-workload.toml", "example");
    for config in [
        "[[workloads]]\nfile=''",
        "runtime-dir=''\n[[workloads]]\nfile='atakit-workload.toml'",
    ] {
        fs::write(temp.path().join("emulator.toml"), config).unwrap();
        assert!(resolve_up(&up(&["up", "--config", "emulator.toml"]), temp.path()).is_err());
    }
}

#[test]
fn platform_selection_is_explicit_and_scoped_to_the_selected_workload_list() {
    let temp = temp_dir();
    workload(&temp.path().join("app"), "atakit-workload.toml", "app");
    fs::write(temp.path().join("emulator.toml"), "[[workloads]]\nfile='app'\nplatform-profile='gcp-tdx'\nmeasurement-variant='c3-standard-4'\n").unwrap();
    let args = up(&[
        "up",
        "--config",
        "emulator.toml",
        "--measurement-variant",
        "app=c3-standard-8",
    ]);
    let resolved = resolve_up(&args, temp.path()).unwrap();
    let value = serde_json::to_value(&resolved.workloads[0]).unwrap();
    assert_eq!(value["platform_profile"], "gcp-tdx");
    assert_eq!(value["measurement_variant"], "c3-standard-8");
    let args = up(&["up", "--config", "emulator.toml", "--workload", "app"]);
    let value =
        serde_json::to_value(&resolve_up(&args, temp.path()).unwrap().workloads[0]).unwrap();
    assert!(value["platform_profile"].is_null());
    assert!(value["measurement_variant"].is_null());
    let args = up(&[
        "up",
        "--workload",
        "app",
        "--platform-profile",
        "unknown=gcp-tdx",
    ]);
    assert!(resolve_up(&args, temp.path())
        .unwrap_err()
        .to_string()
        .contains("unknown workload"));
    fs::write(
        temp.path().join("emulator.toml"),
        "[[workloads]]\nfile='app'\nplatform-profile=''\n",
    )
    .unwrap();
    assert!(resolve_up(&up(&["up", "--config", "emulator.toml"]), temp.path()).is_err());
}

#[test]
fn compose_can_omit_the_single_instance_selector() {
    assert!(EmulatorCli::try_parse_from(["atakit-emulator", "workload-compose", "up"]).is_ok());
}

#[test]
fn target_from_cli_overrides_emulator_file() {
    let temp = temp_dir();
    workload(temp.path(), "atakit-workload.toml", "signer");
    fs::write(
        temp.path().join("emulator.toml"),
        "target = \"saved\"\n[[workloads]]\nfile = \".\"\n",
    )
    .unwrap();
    let from_file = resolve_up(&up(&["up", "--config", "emulator.toml"]), temp.path()).unwrap();
    assert_eq!(serde_json::to_value(from_file).unwrap()["target"], "saved");
    let from_cli = resolve_up(
        &up(&["up", "--config", "emulator.toml", "--target", "chosen"]),
        temp.path(),
    )
    .unwrap();
    assert_eq!(serde_json::to_value(from_cli).unwrap()["target"], "chosen");
}

#[test]
fn cli_accepts_target_for_multiple_workloads() {
    let temp = temp_dir();
    workload(&temp.path().join("a"), "atakit-workload.toml", "a");
    workload(&temp.path().join("b"), "atakit-workload.toml", "b");
    let args = up(&[
        "up",
        "--workload",
        "a",
        "--workload",
        "b",
        "--target",
        "dev",
    ]);
    let launch = resolve_up(&args, temp.path()).unwrap();
    assert_eq!(launch.workloads.len(), 2);
    assert_eq!(serde_json::to_value(launch).unwrap()["target"], "dev");
}

#[test]
fn ip_env_is_rejected_before_launch() {
    let temp = temp_dir();
    let file = workload(temp.path(), "atakit-workload.toml", "app");
    let original = fs::read_to_string(&file).unwrap();
    for config in [
        format!("{original}ip-env = true\n"),
        format!("{original}\n[dependencies.side]\nimage = 'example:1'\nip-env = true\n"),
    ] {
        fs::write(&file, config).unwrap();
        let error = resolve_up(&up(&["up", "--workload", "."]), temp.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("ip-env"), "{error}");
    }
}

#[test]
fn nested_workloads_use_the_invocation_directory_for_resources() {
    let temp = temp_dir();
    let cwd = temp.path().join("project");
    let config_dir = temp.path().join("configuration");
    workload(
        &cwd.join("container/guardian"),
        "atakit-workload.toml",
        "guardian",
    );
    workload(
        &cwd.join("container/validator"),
        "atakit-workload.toml",
        "validator",
    );
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(config_dir.join("emulator.toml"), "[[workloads]]\nfile='../project/container/guardian/atakit-workload.toml'\n[[workloads]]\nfile='../project/container/validator'\n").unwrap();
    fs::write(cwd.join("container/Dockerfile"), "FROM scratch\n").unwrap();
    for name in ["guardian", "validator"] {
        let path = cwd.join(format!("container/{name}/atakit-workload.toml"));
        let source = fs::read_to_string(&path).unwrap().replace(
            "image = { build = \".\" }",
            "image = { build = '.', containerfile = 'container/Dockerfile' }",
        );
        fs::write(path, source).unwrap();
    }

    for args in [
        up(&[
            "up",
            "--workload",
            "container/guardian/atakit-workload.toml",
        ]),
        up(&["up", "--workload", "container/guardian"]),
        up(&["up", "--config", "../configuration/emulator.toml"]),
    ] {
        let resolved = resolve_up(&args, &cwd).unwrap();
        for entry in &resolved.workloads {
            assert_eq!(entry.workload_dir, cwd);
            let endpoint: atakit_emulator::endpoints::EndpointInfo =
                serde_json::from_value(serde_json::json!({
                    "environment_id": "test", "upstream_rpc_url": "http://localhost:8545",
                    "anchor_number": 0, "anchor_hash": "0x00", "rpc_url": "http://localhost:8546",
                    "chain_id": 31337, "session_registry": "", "workload_registry": "",
                    "base_image_registry": "", "state": "ready",
                    "workloads": { (entry.name.clone()): {
                        "config_file": entry.config_file, "workload_dir": entry.workload_dir,
                        "portal_socket": entry.output_socket, "publisher_fingerprint": "",
                        "state": "ready", "env": {}
                    }}
                }))
                .unwrap();
            let compose = atakit_emulator::compose::project_with_transport(
                &endpoint,
                std::slice::from_ref(&entry.name),
                &serde_json::Map::new(),
                &resolved.runtime_dir,
                atakit_emulator::cli::PortalTransport::Native,
            )
            .unwrap();
            let build = &compose["services"][&entry.name]["build"];
            assert_eq!(build["context"], cwd.join(".").to_str().unwrap());
            assert_eq!(
                build["dockerfile"],
                cwd.join("container/Dockerfile").to_str().unwrap()
            );

            assert_eq!(
                fs::read_to_string(entry.workload_dir.join("container/Dockerfile")).unwrap(),
                "FROM scratch\n"
            );
            assert_eq!(
                entry.config_file,
                cwd.join(format!("container/{}/atakit-workload.toml", entry.name))
            );
        }
    }
}

#[test]
fn default_config_preserves_overrides_and_does_not_search_parent_directories() {
    let temp = temp_dir();
    workload(temp.path(), "atakit-workload.toml", "default");
    workload(&temp.path().join("child"), "atakit-workload.toml", "chosen");
    let default = temp.path().join("atakit-emulator.toml");
    fs::write(&default, "anvil-port=9546\n[[workloads]]\nfile='.'\n").unwrap();
    let resolved = resolve_up(
        &up(&["up", "--workload", "child", "--anvil-port", "9547"]),
        temp.path(),
    )
    .unwrap();
    assert_eq!(resolved.workloads[0].name, "chosen");
    assert_eq!(resolved.anvil_port, 9547);
    let resolved = resolve_up(&up(&["up", "--workload", "child"]), temp.path()).unwrap();
    assert_eq!(resolved.anvil_port, 9546);
    let child = temp.path().join("child");
    assert!(resolve_up(&up(&["up"]), &child)
        .unwrap_err()
        .to_string()
        .contains("at least one workload"));
    assert!(resolve_up(&up(&["up", "--workload", "."]), &child).is_ok());
    assert!(
        resolve_up(&up(&["up", "--config", "missing.toml"]), temp.path())
            .unwrap_err()
            .to_string()
            .contains("missing.toml")
    );
    fs::write(&default, "invalid = [").unwrap();
    assert!(resolve_up(&up(&["up", "--workload", "child"]), temp.path())
        .unwrap_err()
        .to_string()
        .contains("atakit-emulator.toml"));
    fs::write(
        temp.path().join("custom.toml"),
        "[[workloads]]\nfile='child'\n",
    )
    .unwrap();
    let resolved = resolve_up(&up(&["up", "--config", "custom.toml"]), temp.path()).unwrap();
    assert_eq!(resolved.workloads[0].name, "chosen");
}

#[test]
fn up_rejects_non_build_main_images_but_allows_registry_dependencies() {
    let temp = temp_dir();
    let path = workload(temp.path(), "atakit-workload.toml", "app");
    let source = fs::read_to_string(&path).unwrap();
    for image in ["'example:1'", "{ file = 'image.tar' }", "{ build = '' }"] {
        fs::write(&path, source.replace("{ build = \".\" }", image)).unwrap();
        let error = resolve_up(
            &up(&["up", "--workload", path.to_str().unwrap()]),
            temp.path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("workload.image"), "{error:#}");
        assert!(error.to_string().contains("build"), "{error:#}");
        assert!(!temp.path().join(".atakit-emulator").exists());
    }
    fs::write(
        &path,
        format!("{source}\n[dependencies.redis]\nimage = 'redis:7'\n"),
    )
    .unwrap();
    resolve_up(
        &up(&["up", "--workload", path.to_str().unwrap()]),
        temp.path(),
    )
    .unwrap();
}

#[test]
fn up_rejects_pulled_packages_before_parsing_toml() {
    let temp = temp_dir();
    let package = temp.path().join("app.atawl");
    fs::write(&package, [0xff, 0x00]).unwrap();
    let error = resolve_up(
        &up(&["up", "--workload", package.to_str().unwrap()]),
        temp.path(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("does not yet support .atawl"),
        "{error:#}"
    );
}
