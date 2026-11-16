use super::*;
use crate::{
    AwsResources, AzureResources, CommandOutput, GcpResources, NewDeployParams, PersistedInitEnv,
};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;

struct Runner {
    replies: Mutex<VecDeque<Result<String, CloudError>>>,
    calls: Mutex<Vec<(String, Vec<String>)>>,
}

impl Runner {
    fn new(replies: Vec<Result<String, CloudError>>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().unwrap().clone()
    }

    fn finished(&self) {
        assert!(self.replies.lock().unwrap().is_empty());
    }
}

#[async_trait::async_trait]
impl CommandRunner for Runner {
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        self.calls
            .lock()
            .unwrap()
            .push((program.into(), args.iter().map(|s| s.to_string()).collect()));
        let stdout = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected command")?;
        Ok(CommandOutput {
            status: 0,
            stdout,
            stderr: String::new(),
        })
    }

    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<CommandOutput, CloudError> {
        panic!("unexpected streaming command")
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> &'a str {
    &args[args.iter().position(|s| s == name).unwrap() + 1]
}

fn aws(rules: Value) -> String {
    json!({"SecurityGroups": [{"GroupId": "sg-saved", "IpPermissions": rules}]}).to_string()
}

fn aws_rule(protocol: &str, start: u16, end: u16) -> Value {
    json!({"IpProtocol": protocol, "FromPort": start, "ToPort": end,
        "IpRanges": [{"CidrIp": "203.0.113.7/32"}]})
}

fn azure_rule(name: &str, protocol: &str, range: &str, priority: u16, access: &str) -> Value {
    json!({"name": name, "protocol": protocol, "destinationPortRange": range,
        "priority": priority, "direction": "Inbound", "access": access,
        "sourceAddressPrefix": "203.0.113.7/32"})
}

fn ports(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn aws_preserves_restricted_ranges_and_adds_only_missing_protocol() {
    let runner = Runner::new(vec![
        Ok(aws(json!([aws_rule("6", 5200, 5210)]))),
        Ok(String::new()),
    ]);
    crate::aws::firewall::update_ingress_rules(
        "region",
        "saved-group",
        &ports(&["5201/tcp", "5201/udp", "5201/udp"]),
        &runner,
    )
    .await
    .unwrap();
    let calls = runner.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        flag(&calls[0].1, "--filters"),
        "Name=group-name,Values=saved-group"
    );
    assert_eq!(flag(&calls[1].1, "--group-id"), "sg-saved");
    assert_eq!(flag(&calls[1].1, "--protocol"), "udp");
    assert_eq!(flag(&calls[1].1, "--port"), "5201");
    assert_eq!(flag(&calls[1].1, "--cidr"), "0.0.0.0/0");
    runner.finished();
}

#[tokio::test]
async fn aws_all_protocols_preserves_group_and_ipv6_sources() {
    let runner = Runner::new(vec![Ok(aws(json!([{
        "IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-office"}],
        "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/64"}]
    }])))]);
    crate::aws::firewall::update_ingress_rules("r", "g", &ports(&["80/tcp", "53/udp"]), &runner)
        .await
        .unwrap();
    assert_eq!(runner.calls().len(), 1);
}

#[tokio::test]
async fn aws_partial_failure_retry_skips_successful_addition() {
    let runner = Runner::new(vec![
        Ok(aws(json!([]))),
        Ok(String::new()),
        Err(error("denied")),
        Ok(aws(json!([aws_rule("tcp", 80, 80)]))),
        Ok(String::new()),
        Ok(aws(json!([
            aws_rule("tcp", 80, 80),
            aws_rule("udp", 53, 53)
        ]))),
    ]);
    let ports = ports(&["80/tcp", "53/udp"]);
    assert!(
        crate::aws::firewall::update_ingress_rules("r", "g", &ports, &runner)
            .await
            .is_err()
    );
    crate::aws::firewall::update_ingress_rules("r", "g", &ports, &runner)
        .await
        .unwrap();
    crate::aws::firewall::update_ingress_rules("r", "g", &ports, &runner)
        .await
        .unwrap();
    let calls = runner.calls();
    assert_eq!(calls.len(), 6);
    assert_eq!(flag(&calls[4].1, "--port"), "53");
    runner.finished();
}

#[tokio::test]
async fn azure_preserves_restrictions_and_does_not_overwrite_name_or_priority() {
    let mut restricted = azure_rule("office", "Tcp", "", 100, "Allow");
    restricted["destinationPortRanges"] = json!(["5200-5210", "443"]);
    let mut outbound = azure_rule("allow-53-udp", "Udp", "53", 301, "Allow");
    outbound["direction"] = json!("Outbound");
    let rules = json!([
        restricted,
        azure_rule("deny", "*", "*", 300, "Deny"),
        outbound
    ]);
    let runner = Runner::new(vec![Ok(rules.to_string()), Ok(String::new())]);
    crate::azure::firewall::update_nsg_rules(
        "sub",
        "rg",
        "saved-nsg",
        &ports(&["5201/tcp", "443/tcp", "53/udp", "53/udp"]),
        &runner,
    )
    .await
    .unwrap();
    let calls = runner.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(flag(&calls[0].1, "--query"), "securityRules");
    let args = &calls[1].1;
    assert_eq!(flag(args, "--name"), "allow-53-udp-1");
    assert_eq!(flag(args, "--priority"), "302");
    assert_eq!(flag(args, "--protocol"), "Udp");
    assert_eq!(flag(args, "--destination-port-ranges"), "53");
    assert_eq!(flag(args, "--source-address-prefixes"), "*");
    assert_eq!(flag(args, "--nsg-name"), "saved-nsg");
    runner.finished();
}

#[tokio::test]
async fn azure_custom_wildcard_allow_is_preserved() {
    let runner = Runner::new(vec![Ok(json!([azure_rule(
        "private-network",
        "*",
        "*",
        100,
        "Allow"
    )])
    .to_string())]);
    crate::azure::firewall::update_nsg_rules("s", "r", "n", &ports(&["80/tcp", "53/udp"]), &runner)
        .await
        .unwrap();
    assert_eq!(runner.calls().len(), 1);
}

#[tokio::test]
async fn azure_partial_failure_retry_and_repeat_are_idempotent() {
    let tcp = azure_rule("allow-80-tcp", "Tcp", "80", 100, "Allow");
    let udp = azure_rule("allow-53-udp", "Udp", "53", 101, "Allow");
    let runner = Runner::new(vec![
        Ok("[]".into()),
        Ok(String::new()),
        Err(error("denied")),
        Ok(json!([tcp.clone()]).to_string()),
        Ok(String::new()),
        Ok(json!([tcp, udp]).to_string()),
    ]);
    let ports = ports(&["80/tcp", "53/udp"]);
    assert!(
        crate::azure::firewall::update_nsg_rules("s", "r", "n", &ports, &runner)
            .await
            .is_err()
    );
    crate::azure::firewall::update_nsg_rules("s", "r", "n", &ports, &runner)
        .await
        .unwrap();
    crate::azure::firewall::update_nsg_rules("s", "r", "n", &ports, &runner)
        .await
        .unwrap();
    let calls = runner.calls();
    assert_eq!(calls.len(), 6);
    assert_eq!(flag(&calls[4].1, "--destination-port-ranges"), "53");
    assert_eq!(flag(&calls[4].1, "--priority"), "101");
    runner.finished();
}

#[tokio::test]
async fn azure_priority_exhaustion_fails_before_any_writes() {
    let runner = Runner::new(vec![Ok(json!([azure_rule(
        "last", "Tcp", "22", 4095, "Allow"
    )])
    .to_string())]);
    assert!(crate::azure::firewall::update_nsg_rules(
        "s",
        "r",
        "n",
        &ports(&["80/tcp", "53/udp"]),
        &runner
    )
    .await
    .is_err());
    assert_eq!(runner.calls().len(), 1);
}

#[tokio::test]
async fn missing_or_invalid_cloud_rules_never_trigger_writes() {
    for response in ["garbage", "null", "{}", "{\"SecurityGroups\":[]}",
        "{\"SecurityGroups\":[{\"GroupId\":\"a\",\"IpPermissions\":[]},{\"GroupId\":\"b\",\"IpPermissions\":[]}]}"] {
        let runner = Runner::new(vec![Ok(response.into())]);
        assert!(crate::aws::firewall::update_ingress_rules("r", "g", &ports(&["80/tcp"]), &runner).await.is_err());
        assert_eq!(runner.calls().len(), 1);
    }
    for response in ["garbage", "null", "{}", "[{}]"] {
        let runner = Runner::new(vec![Ok(response.into())]);
        assert!(crate::azure::firewall::update_nsg_rules(
            "s",
            "r",
            "n",
            &ports(&["80/tcp"]),
            &runner
        )
        .await
        .is_err());
        assert_eq!(runner.calls().len(), 1);
    }
}

#[tokio::test]
async fn malformed_existing_port_ranges_fail_without_opening_public_access() {
    let runner = Runner::new(vec![Ok(aws(json!([{"IpProtocol": "tcp"}])))]);
    assert!(
        crate::aws::firewall::update_ingress_rules("r", "g", &ports(&["80/tcp"]), &runner)
            .await
            .is_err()
    );
    assert_eq!(runner.calls().len(), 1);
    for range in ["", "bad", "90-80", "65536"] {
        let runner = Runner::new(vec![Ok(json!([azure_rule(
            "office", "Tcp", range, 100, "Allow"
        )])
        .to_string())]);
        assert!(crate::azure::firewall::update_nsg_rules(
            "s",
            "r",
            "n",
            &ports(&["80/tcp"]),
            &runner
        )
        .await
        .is_err());
        assert_eq!(runner.calls().len(), 1);
    }
}

fn state(platform: PlatformKind) -> DeployState {
    let mut state = DeployState::new(NewDeployParams {
        instance_name: "vm".into(),
        target_name: "target".into(),
        provider_name: "provider".into(),
        platform,
        workload_publisher: String::new(),
        workload_name: String::new(),
        workload_version: String::new(),
        image_ref: String::new(),
        base_image_ref: None,
        archive_path: String::new(),
        archive_hash: String::new(),
        init_env: PersistedInitEnv::default(),
        portal_ports: PortalPorts {
            status: 6024,
            init: 5024,
        },
        total_steps: 1,
    });
    state.resources.aws = Some(AwsResources {
        region: "region".into(),
        security_group: Some("group".into()),
        ..Default::default()
    });
    state.resources.azure = Some(AzureResources {
        subscription: "sub".into(),
        resource_group: Some("rg".into()),
        nsg: Some("nsg".into()),
        ..Default::default()
    });
    state.resources.gcp = Some(GcpResources {
        project: "project".into(),
        firewall_rule: Some("rule".into()),
        ..Default::default()
    });
    state
}

#[tokio::test]
async fn init_dispatch_uses_saved_resources_and_custom_portal_ports() {
    for platform in [PlatformKind::Gcp, PlatformKind::Aws, PlatformKind::Azure] {
        let replies = match platform {
            PlatformKind::Gcp => vec![Ok(String::new())],
            PlatformKind::Aws => vec![
                Ok(aws(json!([]))),
                Ok(String::new()),
                Ok(String::new()),
                Ok(String::new()),
            ],
            PlatformKind::Azure => vec![
                Ok("[]".into()),
                Ok(String::new()),
                Ok(String::new()),
                Ok(String::new()),
            ],
            _ => unreachable!(),
        };
        let runner = Runner::new(replies);
        update_for_init(
            &state(platform),
            &ports(&["1024/tcp", "2024/tcp", "80/tcp", "80/tcp"]),
            &runner,
        )
        .await
        .unwrap();
        let calls = runner.calls();
        match platform {
            PlatformKind::Gcp => {
                assert!(calls[0]
                    .1
                    .contains(&"--rules=tcp:6024,tcp:5024,tcp:80".into()));
                assert!(!calls[0].1.iter().any(|a| a.contains("source")));
            }
            PlatformKind::Aws | PlatformKind::Azure => {
                let name = if platform == PlatformKind::Aws {
                    "--port"
                } else {
                    "--destination-port-ranges"
                };
                let actual: Vec<_> = calls
                    .iter()
                    .skip(1)
                    .map(|(_, args)| flag(args, name))
                    .collect();
                assert_eq!(actual, vec!["6024", "5024", "80"]);
            }
            _ => unreachable!(),
        }
        runner.finished();
    }
}

#[tokio::test]
async fn init_update_propagates_read_and_write_failures() {
    for platform in [PlatformKind::Gcp, PlatformKind::Aws, PlatformKind::Azure] {
        let runner = Runner::new(vec![Err(error("provider unavailable"))]);
        assert!(
            update_for_init(&state(platform), &ports(&["80/tcp"]), &runner)
                .await
                .is_err()
        );
        runner.finished();
        if platform != PlatformKind::Gcp {
            let response = if platform == PlatformKind::Aws {
                aws(json!([]))
            } else {
                "[]".into()
            };
            let runner = Runner::new(vec![Ok(response), Err(error("write denied"))]);
            assert!(
                update_for_init(&state(platform), &ports(&["80/tcp"]), &runner)
                    .await
                    .is_err()
            );
            runner.finished();
        }
    }
}

#[tokio::test]
async fn missing_saved_resources_fail_and_qemu_does_not_call_cloud_commands() {
    for platform in [
        PlatformKind::Gcp,
        PlatformKind::Aws,
        PlatformKind::Azure,
        PlatformKind::Qemu,
    ] {
        let mut state = state(platform);
        state.resources = Default::default();
        let runner = Runner::new(vec![]);
        assert_eq!(
            update_for_init(&state, &ports(&["80/tcp"]), &runner)
                .await
                .is_ok(),
            platform == PlatformKind::Qemu
        );
        assert!(runner.calls().is_empty());
    }
}

#[test]
fn invalid_ports_are_rejected() {
    for entry in ["0/tcp", "65536/tcp", "80/icmp", "1-2/tcp", "--bad/tcp"] {
        assert!(parse_ports(&ports(&[entry])).is_err());
    }
}
