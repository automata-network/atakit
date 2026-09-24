use atakit_emulator::cli::{EmulatorCli, EmulatorCommand};
use clap::Parser;

#[test]
fn stop_accepts_an_explicit_runtime() {
    assert!(
        EmulatorCli::try_parse_from(["emulator", "stop", "--runtime-dir", "/tmp/example"]).is_ok()
    );
}

#[test]
fn down_requires_explicit_flag_to_purge_data() {
    assert!(EmulatorCli::try_parse_from(["emulator", "down"]).is_ok());
    assert!(EmulatorCli::try_parse_from(["emulator", "down", "--purge-data"]).is_ok());
    assert!(EmulatorCli::try_parse_from(["emulator", "stop", "--purge-data"]).is_err());
}

#[test]
fn compose_defaults_to_native_and_accepts_explicit_bridge() {
    use atakit_emulator::cli::{EmulatorCli, EmulatorCommand, PortalTransport};
    use clap::Parser;
    for (args, expected) in [
        (
            vec!["atakit-emulator", "workload-compose"],
            PortalTransport::Native,
        ),
        (
            vec![
                "atakit-emulator",
                "workload-compose",
                "--portal-transport",
                "bridge",
            ],
            PortalTransport::Bridge,
        ),
    ] {
        let EmulatorCommand::WorkloadCompose(parsed) =
            EmulatorCli::try_parse_from(args).unwrap().command
        else {
            panic!("expected Compose");
        };
        assert_eq!(parsed.compose.portal_transport, expected);
    }
}

#[test]
fn workload_compose_accepts_docker_commands_and_flags() {
    for args in [
        vec!["up", "-d", "--build"],
        vec!["logs", "-f", "--tail", "100"],
        vec!["exec", "secure-signer", "sh", "-c", "echo hello world"],
        vec!["down", "--volumes"],
        vec!["log", "--help"],
    ] {
        let mut argv = vec![
            "emulator",
            "workload-compose",
            "--portal-transport",
            "native",
        ];
        argv.extend(args);
        assert!(EmulatorCli::try_parse_from(argv).is_ok());
    }
}

#[test]
fn compose_accepts_platform_before_forwarded_command() {
    let parsed = EmulatorCli::try_parse_from([
        "emulator",
        "workload-compose",
        "--workload",
        "guardian",
        "--platform",
        "linux/amd64",
        "up",
        "--build",
    ])
    .unwrap();
    let EmulatorCommand::WorkloadCompose(args) = parsed.command else {
        panic!()
    };
    assert_eq!(args.compose.platform.as_deref(), Some("linux/amd64"));
    assert_eq!(
        args.command,
        vec![std::ffi::OsString::from("up"), "--build".into()]
    );
}

#[test]
fn standalone_compose_is_not_a_command() {
    assert!(EmulatorCli::try_parse_from(["emulator", "compose"]).is_err());
}
