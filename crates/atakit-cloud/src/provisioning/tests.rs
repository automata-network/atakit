use super::*;
use crate::{resume::DeploymentRunner, CommandOutput, NewDeployParams, PlatformKind};
use std::{collections::VecDeque, sync::Mutex};

mod boot_recording;
mod disk_confirmation;
mod fast_disks;
mod preservation;

struct Runner {
    replies: Mutex<VecDeque<Result<Value, &'static str>>>,
    calls: Mutex<Vec<Vec<String>>>,
    token: Mutex<String>,
}
impl Runner {
    fn new(replies: Vec<Result<Value, &'static str>>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
            calls: Mutex::new(vec![]),
            token: Mutex::new(String::new()),
        }
    }
    fn reply(&self, args: Vec<String>) -> Result<Value, CloudError> {
        if let Some(token) = args
            .iter()
            .find_map(|a| a.split_once("requestId=").map(|(_, v)| v))
        {
            *self.token.lock().unwrap() = token.into();
        }
        self.calls.lock().unwrap().push(args);
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected provider call")
            .map_err(|message| {
                match message
                    .strip_prefix("HTTP ")
                    .and_then(|s| s.parse::<u16>().ok())
                {
                    Some(status) => CloudError::ProviderResponse {
                        provider: "test",
                        status,
                        code: "test".into(),
                        message: "rejected".into(),
                    },
                    None if message == "AWS auth" => CloudError::CommandFailed {
                        program: "aws".into(),
                        args: "ec2 create-volume".into(),
                        stderr: "(UnauthorizedOperation)".into(),
                        code: Some(1),
                    },
                    None if message == "AWS missing" || message == "GCP missing" => {
                        CloudError::CommandFailed {
                            program: if message == "AWS missing" {
                                "aws"
                            } else {
                                "gcloud"
                            }
                            .into(),
                            args: "describe instance".into(),
                            stderr: if message == "AWS missing" {
                                "InvalidInstanceID.NotFound"
                            } else {
                                "instance was not found"
                            }
                            .into(),
                            code: Some(1),
                        }
                    }
                    None if message == "Azure missing" => CloudError::CommandFailed {
                        program: "az".into(),
                        args: "resource show".into(),
                        stderr: "ResourceNotFound".into(),
                        code: Some(3),
                    },
                    None if message.starts_with("Azure stderr: ") => CloudError::CommandFailed {
                        program: "az".into(),
                        args: "resource show".into(),
                        stderr: message.strip_prefix("Azure stderr: ").unwrap().into(),
                        code: Some(3),
                    },
                    None => error(message),
                }
            })?;
        Ok(serde_json::from_str(
            &reply
                .to_string()
                .replace("$TOKEN", &self.token.lock().unwrap()),
        )
        .unwrap())
    }
}
#[async_trait::async_trait]
impl CommandRunner for Runner {
    async fn azure_api(
        &self,
        method: &str,
        url: &str,
        body: Option<&Value>,
        create_only: bool,
    ) -> Result<Value, CloudError> {
        self.reply(vec![
            "azure-api".into(),
            method.into(),
            url.into(),
            create_only.to_string(),
            body.unwrap_or(&Value::Null).to_string(),
        ])
    }
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        let v = self.reply(
            std::iter::once(program)
                .chain(args.iter().copied())
                .map(str::to_owned)
                .collect(),
        )?;
        Ok(CommandOutput {
            status: 0,
            stdout: v
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| v.to_string()),
            stderr: String::new(),
        })
    }
    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<CommandOutput, CloudError> {
        panic!("unexpected streaming call")
    }
    async fn gcp_api(
        &self,
        method: &str,
        url: &str,
        body: Option<&Value>,
    ) -> Result<Value, CloudError> {
        self.reply(vec![
            method.into(),
            url.into(),
            body.unwrap_or(&Value::Null).to_string(),
        ])
    }
}
fn fixture(platform: PlatformKind) -> (tempfile::TempDir, DeployState) {
    let dir = tempfile::tempdir().unwrap();
    let mut state = DeployState::new(NewDeployParams {
        instance_name: "vm".into(),
        target_name: "target".into(),
        provider_name: "provider".into(),
        platform,
        workload_publisher: "publisher".into(),
        workload_name: "app".into(),
        workload_version: "v1".into(),
        image_ref: "image".into(),
        base_image_ref: None,
        archive_path: String::new(),
        archive_hash: String::new(),
        init_env: Default::default(),
        portal_ports: Default::default(),
        total_steps: 1,
    });
    state.provisioning.started = true;
    state.resources.aws = Some(crate::AwsResources {
        region: "region".into(),
        ..Default::default()
    });
    state.resources.gcp = Some(crate::GcpResources {
        project: "project".into(),
        zone: "zone".into(),
        ..Default::default()
    });
    state.resources.azure = Some(crate::AzureResources {
        subscription: "sub".into(),
        resource_group: Some("group".into()),
        ..Default::default()
    });
    if platform != PlatformKind::Aws {
        state.resources.aws = None;
    }
    if platform != PlatformKind::Gcp {
        state.resources.gcp = None;
    }
    if platform != PlatformKind::Azure {
        state.resources.azure = None;
    }
    state.save(dir.path()).unwrap();
    (dir, state)
}
fn durable<'a>(dir: &'a tempfile::TempDir, runner: &'a dyn CommandRunner) -> DeploymentRunner<'a> {
    DeploymentRunner {
        runner,
        data_dir: dir.path(),
        target: "target",
        instance: "vm",
    }
}
fn aws_request() -> CreateRequest {
    CreateRequest::Aws {
        args: vec![
            "ec2".into(),
            "create-volume".into(),
            "--size".into(),
            "8".into(),
        ],
    }
}
fn spec(kind: &str) -> crate::DiskSpec {
    crate::DiskSpec {
        name: "vm-data".into(),
        device_name: "data".into(),
        index: 0,
        size_gb: 8,
        disk_type: kind.into(),
        performance: None,
    }
}
fn volume(id: &str) -> Value {
    json!({"VolumeId":id,"VolumeType":"gp3","Size":8,"AvailabilityZone":"zone","SnapshotId":"","Attachments":[]})
}
fn gcp_request() -> CreateRequest {
    CreateRequest::Gcp {
        project: "project".into(),
        zone: "zone".into(),
        collection: "disks".into(),
        body: json!({"name":"vm-data"}),
    }
}
fn operation() -> Value {
    json!({"name":"op","status":"DONE","operationType":"insert","clientOperationId":"$TOKEN","targetId":"123","targetLink":"https://compute.googleapis.com/compute/v1/projects/project/zones/zone/disks/vm-data"})
}

fn pending_gcp_vm(state: &mut DeployState) -> Value {
    let mut op = operation();
    op["clientOperationId"] = json!("saved-token");
    op["status"] = json!("RUNNING");
    op["targetLink"] =
        json!("https://compute.googleapis.com/compute/v1/projects/project/zones/zone/instances/vm");
    state.cleanup.started = true;
    state.provisioning.creations.insert(
        "instance".into(),
        Creation {
            outcome: CreationOutcome::Accepted,
            request: CreateRequest::Gcp {
                project: "project".into(),
                zone: "zone".into(),
                collection: "instances".into(),
                body: json!({"name":"vm"}),
            },
            token: "saved-token".into(),
            sent: true,
            receipt: Some(op.clone()),
            result: None,
        },
    );
    op
}

#[tokio::test]
async fn gcp_cleanup_refreshes_capacity_rejection_and_preserves_completed_cleanup() {
    let (dir, mut state) = fixture(PlatformKind::Gcp);
    let mut op = pending_gcp_vm(&mut state);
    state
        .cleanup
        .completed
        .insert("already-cleaned-disk".into());
    state.save(dir.path()).unwrap();
    op["status"] = json!("DONE");
    op["error"] = json!({"errors":[{"code":"ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS"}]});
    let runner = Runner::new(vec![Ok(op.clone()), Err("HTTP 404")]);
    crate::provisioning_cleanup::reconcile_records(dir.path(), &mut state, &runner)
        .await
        .unwrap();
    assert_eq!(
        state.provisioning.creations["instance"].outcome,
        CreationOutcome::Failed
    );
    assert_eq!(state.provisioning.creations["instance"].receipt, Some(op));
    assert!(!crate::provisioning_cleanup::has_unresolved(&state));
    assert!(state.cloud_instance_id.is_none());
    assert!(state.cleanup.completed.contains("already-cleaned-disk"));
    crate::provisioning_cleanup::reconcile_records(dir.path(), &mut state, &runner)
        .await
        .unwrap();
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|c| c[0] == "GET"));
    assert!(calls[0][1].ends_with("/operations/op"));
    assert!(calls[1][1].ends_with("/instances/vm"));
}

#[tokio::test]
async fn gcp_cleanup_does_not_resolve_pending_foreign_or_uncertain_operations() {
    for case in 0..8 {
        let (dir, mut state) = fixture(PlatformKind::Gcp);
        let mut op = pending_gcp_vm(&mut state);
        state.save(dir.path()).unwrap();
        if case != 0 {
            op["status"] = json!("DONE");
            op["error"] = json!({"errors":[{"code":"REJECTED"}]});
        }
        match case {
            1 => op["name"] = json!("another-operation"),
            2 => op["clientOperationId"] = json!("another-request"),
            3 => op["targetLink"] = json!("another-resource"),
            4 => op["operationType"] = json!("delete"),
            _ => {}
        }
        let replies = match case {
            5 => vec![Err("HTTP 403")],
            6 => vec![Ok(op), Err("HTTP 403")],
            7 => vec![Ok(op), Ok(json!({"id":"123","name":"vm"}))],
            _ => vec![Ok(op)],
        };
        let runner = Runner::new(replies);
        crate::provisioning_cleanup::reconcile_records(dir.path(), &mut state, &runner)
            .await
            .unwrap();
        assert!(
            crate::provisioning_cleanup::has_unresolved(&state),
            "case {case}"
        );
        assert!(state.cloud_instance_id.is_none());
        assert!(state.cleanup.remaining.contains_key("creation instance"));
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), if case >= 6 { 2 } else { 1 });
        assert!(calls.iter().all(|c| c[0] == "GET"));
    }
}

#[tokio::test]
async fn gcp_cleanup_refreshes_success_and_records_only_the_matching_instance() {
    for id in ["123", "replacement"] {
        let (dir, mut state) = fixture(PlatformKind::Gcp);
        let mut op = pending_gcp_vm(&mut state);
        state.save(dir.path()).unwrap();
        op["status"] = json!("DONE");
        let runner = Runner::new(vec![Ok(op), Ok(json!({"id":id,"name":"vm"}))]);
        crate::provisioning_cleanup::reconcile_records(dir.path(), &mut state, &runner)
            .await
            .unwrap();
        if id == "123" {
            assert_eq!(state.cloud_instance_id.as_deref(), Some("123"));
            assert!(!crate::provisioning_cleanup::has_unresolved(&state));
        } else {
            assert!(state.cloud_instance_id.is_none());
            assert!(crate::provisioning_cleanup::has_unresolved(&state));
        }
        assert!(runner.calls.lock().unwrap().iter().all(|c| c[0] == "GET"));
    }
}

#[tokio::test]
async fn gcp_create_records_terminal_rejection_without_authorizing_initialization() {
    let (dir, _) = fixture(PlatformKind::Gcp);
    let mut op = operation();
    op["error"] = json!({"errors":[{"code":"ZONE_RESOURCE_POOL_EXHAUSTED"}]});
    let runner = Runner::new(vec![Ok(op), Err("HTTP 404")]);
    assert!(matches!(
        durable(&dir, &runner)
            .create_resource("disk:data", &gcp_request())
            .await,
        Err(CloudError::CreationFailed { .. })
    ));
    let state = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        state.provisioning.creations["disk:data"].outcome,
        CreationOutcome::Failed
    );
    assert!(state.created_disks.is_empty());
    assert!(state.provisioning.creations["disk:data"].result.is_none());
}
fn azure_disk(unique: &str) -> Value {
    json!({"id":"/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/vm-data","name":"vm-data","sku":{"name":"StandardSSD_LRS"},"properties":{"uniqueId":unique,"diskSizeGB":8,"creationData":{"createOption":"Empty"}}})
}
fn azure_request() -> CreateRequest {
    CreateRequest::Azure {
        subscription: "sub".into(),
        group: "group".into(),
        template: json!({}),
    }
}
fn azure_deployment(disk: Value) -> Value {
    json!({"properties":{"provisioningState":"Succeeded","outputs":{"resource":{"value":disk}}}})
}
fn azure_operation(disk: Value) -> Value {
    json!([{"properties":{"provisioningState":"Succeeded","provisioningOperation":"Create","targetResource":{"id":disk["id"]},"response":{"content":disk}}}])
}

#[tokio::test]
async fn aws_lost_reply_retries_same_token_and_request_then_uses_cached_result() {
    let (dir, _) = fixture(PlatformKind::Aws);
    let runner = Runner::new(vec![Err("lost reply"), Ok(volume("vol-original"))]);
    let durable = durable(&dir, &runner);
    assert!(durable
        .create_resource("disk:data", &aws_request())
        .await
        .is_err());
    let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    let creation = &saved.provisioning.creations["disk:data"];
    assert!(creation.sent);
    assert!(creation.result.is_none());
    assert!(!saved.provisioning_complete);
    assert_eq!(
        durable
            .create_resource("disk:data", &aws_request())
            .await
            .unwrap()["VolumeId"],
        "vol-original"
    );
    durable
        .create_resource("disk:data", &aws_request())
        .await
        .unwrap();
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0].last().unwrap(), &creation.token);
}

#[tokio::test]
async fn changed_request_is_refused_without_a_second_provider_call() {
    let (dir, _) = fixture(PlatformKind::Aws);
    let runner = Runner::new(vec![Ok(volume("vol-original"))]);
    let durable = durable(&dir, &runner);
    durable
        .create_resource("disk:data", &aws_request())
        .await
        .unwrap();
    let changed = CreateRequest::Aws {
        args: vec![
            "ec2".into(),
            "create-volume".into(),
            "--size".into(),
            "16".into(),
        ],
    };
    assert!(durable
        .create_resource("disk:data", &changed)
        .await
        .unwrap_err()
        .to_string()
        .contains("request changed"));
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn aws_profile_applies_only_to_a_new_source_free_volume() {
    let (dir, _) = fixture(PlatformKind::Aws);
    let mut volume = volume("vol-original");
    volume["Iops"] = json!(6000);
    volume["Throughput"] = json!(250);
    let runner = Runner::new(vec![Ok(volume.clone()), Ok(json!({"Volumes":[volume]}))]);
    let mut disk = spec("gp3");
    disk.performance = Some(crate::disk_profiles::DiskPerformance {
        disk_type: "gp3".into(),
        iops: Some(6000),
        throughput_mibps: Some(250),
        ..Default::default()
    });
    crate::aws::disk::create("region", "zone", &disk, &durable(&dir, &runner))
        .await
        .unwrap();
    let calls = runner.calls.lock().unwrap();
    assert!(calls[0].windows(2).any(|w| w == ["--iops", "6000"]));
    assert!(calls[0].windows(2).any(|w| w == ["--throughput", "250"]));
    assert!(!calls[0].contains(&"--snapshot-id".into()));
    assert!(calls[1].contains(&"vol-original".into()));
    assert_eq!(calls.len(), 2);
}

#[tokio::test]
async fn aws_missing_confirmed_disk_is_never_recreated() {
    let (dir, _) = fixture(PlatformKind::Aws);
    let runner = Runner::new(vec![
        Ok(volume("vol-original")),
        Err("disk disappeared"),
        Err("disk disappeared"),
    ]);
    let durable = durable(&dir, &runner);
    for _ in 0..2 {
        assert!(
            crate::aws::disk::create("region", "zone", &spec("gp3"), &durable)
                .await
                .is_err()
        );
    }
    let state = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(state.created_disks["data"].observed.id, "vol-original");
    assert_eq!(state.resources.aws.unwrap().disks, vec!["vol-original"]);
    let calls = runner.calls.lock().unwrap();
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.iter().any(|s| s == "create-volume"))
            .count(),
        1
    );
}

#[tokio::test]
async fn aws_attachment_conflict_stops_without_adopting_or_detaching_disk() {
    let runner = Runner::new(vec![Ok(
        json!({"Reservations":[{"Instances":[{"InstanceId":"i-vm","BlockDeviceMappings":[{"DeviceName":"/dev/sdf","Ebs":{"VolumeId":"vol-foreign"}}]}]}]}),
    )]);
    let disk = crate::disk_inventory::CreatedDisk {
        specification: spec("gp3"),
        creation_verified: true,
        observed: crate::disk_inventory::aws_observation(&volume("vol-original")).unwrap(),
    };
    assert!(crate::aws::disk::attach("region", "i-vm", &disk, &runner)
        .await
        .unwrap_err()
        .to_string()
        .contains("different volume"));
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn gcp_lost_response_recovers_from_operation_and_checks_numeric_id() {
    let (dir, _) = fixture(PlatformKind::Gcp);
    let runner = Runner::new(vec![
        Err("lost reply"),
        Ok(json!({"items":[operation()]})),
        Ok(json!({"id":"123","name":"vm-data"})),
    ]);
    let durable = durable(&dir, &runner);
    assert!(durable
        .create_resource("disk:data", &gcp_request())
        .await
        .is_err());
    assert_eq!(
        durable
            .create_resource("disk:data", &gcp_request())
            .await
            .unwrap()["id"],
        "123"
    );
    durable
        .create_resource("disk:data", &gcp_request())
        .await
        .unwrap();
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0][0], "POST");
    assert!(calls[1..].iter().all(|c| c[0] == "GET"));
}

#[tokio::test]
async fn gcp_replacement_and_missing_operation_cannot_be_adopted() {
    for replies in [
        vec![Ok(operation()), Ok(json!({"id":"456"}))],
        vec![Err("lost reply"), Ok(json!({"items":[]}))],
    ] {
        let (dir, _) = fixture(PlatformKind::Gcp);
        let runner = Runner::new(replies);
        let durable = durable(&dir, &runner);
        assert!(durable
            .create_resource("disk:data", &gcp_request())
            .await
            .is_err());
        if !runner.replies.lock().unwrap().is_empty() {
            assert!(durable
                .create_resource("disk:data", &gcp_request())
                .await
                .is_err());
        }
        let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert!(saved.provisioning.creations["disk:data"].result.is_none());
        assert_eq!(
            runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c[0] == "POST")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn azure_lost_response_recovers_original_operation_without_repeating_put() {
    let (dir, _) = fixture(PlatformKind::Azure);
    let runner = Runner::new(vec![
        Err("lost reply"),
        Ok(azure_deployment(azure_disk("original"))),
        Ok(azure_operation(azure_disk("original"))),
    ]);
    let durable = durable(&dir, &runner);
    assert!(durable
        .create_resource("disk:data", &azure_request())
        .await
        .is_err());
    assert_eq!(
        durable
            .create_resource("disk:data", &azure_request())
            .await
            .unwrap()["properties"]["uniqueId"],
        "original"
    );
    durable
        .create_resource("disk:data", &azure_request())
        .await
        .unwrap();
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls.iter().filter(|c| c.contains(&"put".into())).count(),
        1
    );
}

#[tokio::test]
async fn azure_missing_deployment_does_not_submit_another_put() {
    let (dir, _) = fixture(PlatformKind::Azure);
    let runner = Runner::new(vec![Err("lost reply"), Err("DeploymentNotFound")]);
    let durable = durable(&dir, &runner);
    assert!(durable
        .create_resource("disk:data", &azure_request())
        .await
        .is_err());
    assert!(durable
        .create_resource("disk:data", &azure_request())
        .await
        .is_err());
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(!calls[1].contains(&"put".into()));
}

#[tokio::test]
async fn azure_standalone_disk_put_is_blocked_without_any_provider_call() {
    let (dir, _) = fixture(PlatformKind::Azure);
    let mut disk = azure_disk("original");
    disk["properties"]["creationData"]["createOption"] = json!("Copy");
    let runner = Runner::new(vec![
        Ok(json!({})),
        Ok(azure_deployment(disk.clone())),
        Ok(azure_operation(disk)),
    ]);
    assert!(crate::azure::disk::create_disk(
        "sub",
        "group",
        "region",
        &spec("StandardSSD_LRS"),
        &durable(&dir, &runner)
    )
    .await
    .is_err());
    let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert!(saved.created_disks.is_empty());
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[test]
fn azure_replacement_or_absent_original_response_cannot_be_adopted() {
    assert!(azure_creation_response(
        &azure_operation(azure_disk("original")),
        &azure_disk("replacement")
    )
    .is_err());
    let mut ops = azure_operation(azure_disk("original"));
    ops[0]["properties"]["response"] = Value::Null;
    assert!(azure_creation_response(&ops, &azure_disk("original")).is_err());
    assert!(azure_creation_response(&json!([]), &azure_disk("original")).is_err());
}

#[tokio::test]
async fn azure_existing_name_is_rejected_before_any_create_or_attach() {
    use crate::CloudProvider;
    let runner = Runner::new(vec![Ok(azure_disk("existing"))]);
    let provider = crate::azure::AzureProvider::new("sub".into(), "region".into());
    let step = DeployStep::CreateDisks {
        disks: vec![spec("StandardSSD_LRS")],
        resource_group: Some("group".into()),
    };
    assert!(provider.execute_step(&step, &runner, false).await.is_err());
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(&calls[0][..3], ["az", "disk", "show"]);
}

#[tokio::test]
async fn unresolved_creation_keeps_cleanup_state_and_does_not_issue_commands() {
    let (dir, _) = fixture(PlatformKind::Aws);
    let runner = Runner::new(vec![Err("lost reply")]);
    assert!(durable(&dir, &runner)
        .create_resource("disk:data", &aws_request())
        .await
        .is_err());
    let mut saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert!(crate::provisioning_cleanup::recover_records(&mut saved).is_ok());
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
}

#[test]
fn cleanup_recovers_saved_disk_result_before_callback() {
    let (_, mut state) = fixture(PlatformKind::Aws);
    state.provisioning.steps = vec![DeployStep::CreateDisks {
        disks: vec![spec("gp3")],
        resource_group: None,
    }];
    state.provisioning.creations.insert(
        "disk:data".into(),
        Creation {
            outcome: Default::default(),
            request: aws_request(),
            token: "token".into(),
            sent: true,
            receipt: None,
            result: Some(volume("vol-original")),
        },
    );
    crate::provisioning_cleanup::recover_records(&mut state).unwrap();
    assert_eq!(state.resources.aws.unwrap().disks, vec!["vol-original"]);
    assert!(!state.created_disks["data"].creation_verified);
}

#[tokio::test]
async fn cleanup_refuses_foreign_aws_attachment() {
    let (_, mut state) = fixture(PlatformKind::Aws);
    state.resources.aws.as_mut().unwrap().instance = Some("i-vm".into());
    state.cloud_instance_id = Some("i-vm".into());
    let runner = Runner::new(vec![
        Ok(
            json!({"Reservations":[{"Instances":[{"InstanceId":"i-vm","RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/sdf","Ebs":{"VolumeId":"vol-foreign","DeleteOnTermination":true}}]}]}]}),
        ),
        Err("cannot disable automatic disk deletion"),
    ]);
    assert!(crate::provisioning_cleanup::before_step(
        &state,
        &crate::DestroyStep::DeleteInstance {
            name: "i-vm".into()
        },
        false,
        &runner
    )
    .await
    .is_err());
    assert_eq!(runner.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn initialization_that_may_have_been_sent_blocks_all_creation_retries() {
    for platform in [PlatformKind::Aws, PlatformKind::Azure, PlatformKind::Gcp] {
        let (dir, mut state) = fixture(platform);
        state.initialization = Some(crate::resume::Initialization {
            transfer_id: "transfer".into(),
            phase: crate::resume::InitializationPhase::MayHaveBeenSent,
            bootstrap: None,
            inputs_sha256: String::new(),
            tls_sha256: None,
            submitted_config_sha256: None,
        });
        state.save(dir.path()).unwrap();
        let runner = Runner::new(vec![]);
        assert!(durable(&dir, &runner)
            .create_resource("disk:data", &aws_request())
            .await
            .is_err());
        assert!(runner.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn preserve_disks_confirms_aws_retention_before_termination() {
    let (_, mut state) = fixture(PlatformKind::Aws);
    let aws = state.resources.aws.as_mut().unwrap();
    aws.instance = Some("i-vm".into());
    state.cloud_instance_id = Some("i-vm".into());
    aws.disks = vec!["vol-original".into()];
    let vm = |delete| json!({"Reservations":[{"Instances":[{"InstanceId":"i-vm","RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/sdf","Ebs":{"VolumeId":"vol-original","DeleteOnTermination":delete}}]}]}]});
    let runner = Runner::new(vec![Ok(vm(true)), Ok(json!({})), Ok(vm(false))]);
    crate::provisioning_cleanup::before_step(
        &state,
        &crate::DestroyStep::DeleteInstance {
            name: "i-vm".into(),
        },
        true,
        &runner,
    )
    .await
    .unwrap();
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert!(calls[1].contains(&"modify-instance-attribute".into()));
    let mapping: Value = serde_json::from_str(calls[1].last().unwrap()).unwrap();
    assert_eq!(mapping[0]["Ebs"]["DeleteOnTermination"], false);
}

#[test]
fn azure_preserve_disks_does_not_delete_their_resource_group() {
    use crate::CloudProvider;
    let (_, mut state) = fixture(PlatformKind::Azure);
    state.resources.azure.as_mut().unwrap().disks = vec!["vm-data".into()];
    let provider = crate::azure::AzureProvider::new("sub".into(), "region".into());
    let plan = provider
        .plan_destroy(
            &state,
            &crate::DestroyOptions {
                preserve: vec!["disks".into()],
            },
        )
        .unwrap();
    assert!(!plan.steps.iter().any(|s| matches!(
        s,
        crate::DestroyStep::DeleteDisks { .. } | crate::DestroyStep::DeleteResourceGroup { .. }
    )));
}

/// Provider readbacks after a process was interrupted. Any unexpected create,
/// attach, resize, or delete is a test failure.
struct ExistingResources {
    calls: Mutex<Vec<Vec<String>>>,
}
impl ExistingResources {
    fn aws_vm() -> Value {
        json!({"Reservations":[{"Instances":[{"InstanceId":"i-vm","RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"vol-boot"}},{"DeviceName":"/dev/sdf","Ebs":{"VolumeId":"vol-original","DeleteOnTermination":true}}]}]}]})
    }
    fn gcp_disk(name: &str) -> Value {
        json!({"name":name,"id":if name=="vm-data"{"123"}else{"456"},"sizeGb":"8","type":"projects/project/zones/zone/diskTypes/pd-balanced"})
    }
    fn gcp_vm() -> Value {
        json!({"name":"vm","id":"789","networkInterfaces":[{"accessConfigs":[{"natIP":"192.0.2.1"}]}],"disks":[{"boot":true,"source":"https://compute.googleapis.com/compute/v1/projects/project/zones/zone/disks/vm-boot"},{"deviceName":"data","source":"https://compute.googleapis.com/compute/v1/projects/project/zones/zone/disks/vm-data"}]})
    }
    fn azure_vm() -> Value {
        json!({"name":"vm","vmId":"vm-unique","storageProfile":{"osDisk":{"managedDisk":{"id":"/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/vm-boot"}},"dataDisks":[{"name":"vm-data","createOption":"Empty","lun":0,"managedDisk":{"id":azure_disk("original")["id"]}}]}})
    }
}
#[async_trait::async_trait]
impl CommandRunner for ExistingResources {
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        self.calls
            .lock()
            .unwrap()
            .push(args.iter().map(|s| s.to_string()).collect());
        let value = match program {
            "aws" if args.contains(&"describe-instances") && args.contains(&"--query") => {
                json!("192.0.2.1")
            }
            "aws" if args.contains(&"describe-instances") => Self::aws_vm(),
            "aws" if args.contains(&"describe-subnets") => {
                json!({"Subnets":[{"SubnetId":"subnet","AvailabilityZone":"zone"}]})
            }
            "aws" if args.contains(&"describe-volumes") => {
                json!({"Volumes":[volume(if args.contains(&"vol-boot"){"vol-boot"}else{"vol-original"})]})
            }
            "aws" if args.contains(&"wait") => json!(""),
            "gcloud" if args.starts_with(&["compute", "instances", "describe"]) => {
                if args.contains(&"--format=value(id)") {
                    json!("789")
                } else {
                    Self::gcp_vm()
                }
            }
            "gcloud" if args.starts_with(&["compute", "disks", "describe"]) => {
                Self::gcp_disk(args[3])
            }
            "az" if args.starts_with(&["vm", "show"]) => {
                if args.contains(&"--query") {
                    json!("vm-unique")
                } else {
                    Self::azure_vm()
                }
            }
            "az" if args.starts_with(&["vm", "list-ip-addresses"]) => json!("192.0.2.1"),
            "az" if args.starts_with(&["disk", "show"]) => {
                let mut v = azure_disk("original");
                v["managedBy"] = json!("/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/vm");
                if args.contains(&"--ids") {
                    v["id"]=json!("/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/vm-boot");
                    v["properties"]["uniqueId"] = json!("boot-original");
                }
                v
            }
            _ => panic!("unexpected provider command {program} {args:?}"),
        };
        Ok(CommandOutput {
            status: 0,
            stdout: value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string()),
            stderr: String::new(),
        })
    }
    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<CommandOutput, CloudError> {
        panic!("unexpected command")
    }
}

#[tokio::test]
async fn saved_boot_disk_is_checked_when_vm_already_absent() {
    use crate::{
        disk_inventory::ObservedDisk, provisioning_cleanup as cleanup, CloudProvider, DestroyStep,
    };
    for platform in [PlatformKind::Aws, PlatformKind::Gcp] {
        let (_, mut state) = fixture(platform);
        let (id, name, absent, provider): (&str, &str, &str, Box<dyn CloudProvider>) = if platform
            == PlatformKind::Aws
        {
            state.cloud_instance_id = Some("i-vm".into());
            state.resources.aws.as_mut().unwrap().instance = Some("i-vm".into());
            (
                "vol-boot",
                "vol-boot",
                "AWS missing",
                Box::new(crate::aws::AwsProvider::new("region".into())),
            )
        } else {
            state.cloud_instance_id = Some("123".into());
            state.resources.gcp.as_mut().unwrap().instance = Some("vm".into());
            state.provisioning.creations.insert("instance".into(), Creation {
                    request: CreateRequest::Gcp { project: "project".into(), zone: "zone".into(), collection: "instances".into(), body: json!({"name":"vm"}) },
                    token: "original-request".into(), sent: true, receipt: None,
                    result: Some(json!({"id":"123","name":"vm","disks":[{"boot":true,"source":"projects/project/zones/zone/disks/vm-boot"}]})),
                    outcome: CreationOutcome::Succeeded,
                });
            (
                "456",
                "vm-boot",
                "GCP missing",
                Box::new(crate::gcp::GcpProvider::new(
                    "project".into(),
                    "zone".into(),
                )),
            )
        };
        state.created_boot_disk = Some(ObservedDisk {
            id: id.into(),
            disk_type: "type".into(),
            size_gb: 8,
            iops: None,
            throughput_mibps: None,
        });
        let before = serde_json::to_value(&state).unwrap();
        cleanup::record_attachments(&mut state, &Runner::new(vec![Err(absent)]))
            .await
            .unwrap();
        let mut plan = provider
            .plan_destroy(
                &state,
                &crate::DestroyOptions {
                    preserve: vec!["disks".into()],
                },
            )
            .unwrap();
        cleanup::add_boot_disk_step(&state, &mut plan.steps).unwrap();
        let boot_step = DestroyStep::DeleteDisks {
            names: vec![name.into()],
            resource_group: None,
        };
        assert!(
            plan.steps
                .iter()
                .any(|step| cleanup::step_key(step) == cleanup::step_key(&boot_step)),
            "{platform:?}: boot disk must remain in the cleanup plan without a live VM"
        );
        assert_eq!(
            serde_json::to_value(&state).unwrap(),
            before,
            "planning must not save another boot record"
        );
        assert!(state.cleanup.boot_disk.is_none());
        for (observed_id, accepted) in [(id, true), ("replacement", false)] {
            let response = if platform == PlatformKind::Aws {
                json!({"Volumes":[volume(observed_id)]})
            } else {
                json!({"id":observed_id,"name":name,"sizeGb":"8","type":"zones/zone/diskTypes/type"})
            };
            let runner = Runner::new(vec![Ok(response)]);
            let result = cleanup::before_step(&state, &boot_step, false, &runner).await;
            assert_eq!(result.is_ok(), accepted);
            if let Err(error) = result {
                assert!(error.to_string().contains("disk was replaced"));
            }
        }
    }
}

#[test]
fn unresolved_gcp_boot_reference_cannot_be_added_to_cleanup() {
    for invalid in 0..7 {
        let (_, mut state) = fixture(PlatformKind::Gcp);
        state.cloud_instance_id = Some("123".into());
        state.created_boot_disk = Some(crate::disk_inventory::ObservedDisk {
            id: "456".into(),
            disk_type: "pd-balanced".into(),
            size_gb: 8,
            iops: None,
            throughput_mibps: None,
        });
        let mut creation = Creation {
            request: CreateRequest::Gcp {
                project: "project".into(),
                zone: "zone".into(),
                collection: "instances".into(),
                body: json!({"name":"vm"}),
            },
            token: "original".into(),
            sent: true,
            receipt: None,
            result: Some(
                json!({"id":"123","disks":[{"boot":true,"source":"projects/project/zones/zone/disks/vm-boot"}]}),
            ),
            outcome: CreationOutcome::Succeeded,
        };
        match invalid {
            0 => creation.result = None,
            1 => creation.result.as_mut().unwrap()["disks"] = json!([]),
            2 => {
                creation.result.as_mut().unwrap()["disks"][0]["source"] =
                    json!("projects/other/zones/zone/disks/vm-boot")
            }
            3 => creation.result.as_mut().unwrap()["id"] = json!("another-vm"),
            4 => creation.sent = false,
            5 => {
                creation.result.as_mut().unwrap()["disks"] = json!([
                    {"boot":true,"source":"projects/project/zones/zone/disks/one"},
                    {"boot":true,"source":"projects/project/zones/zone/disks/two"}
                ])
            }
            _ => {}
        }
        if invalid != 6 {
            state
                .provisioning
                .creations
                .insert("instance".into(), creation);
        }
        let before = serde_json::to_value(&state).unwrap();
        let mut steps = vec![];
        assert!(
            crate::provisioning_cleanup::add_boot_disk_step(&state, &mut steps).is_err(),
            "case {invalid}"
        );
        assert!(steps.is_empty());
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
}

#[tokio::test]
async fn aws_data_disk_failure_keeps_boot_disk_owned_for_cleanup() {
    use crate::{provisioning_cleanup as cleanup, CloudProvider, DestroyStep};

    fn vm(auto_delete: bool) -> Value {
        json!({"Reservations":[{"Instances":[{
            "InstanceId":"i-vm", "RootDeviceName":"/dev/xvda",
            "BlockDeviceMappings":[{"DeviceName":"/dev/xvda",
                "Ebs":{"VolumeId":"vol-boot","DeleteOnTermination":auto_delete}}]
        }]}]})
    }
    struct SetupFailure {
        fail_attachment: bool,
    }
    #[async_trait::async_trait]
    impl CommandRunner for SetupFailure {
        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            assert_eq!(program, "aws");
            let value = match args[1] {
                "describe-instances" if args.contains(&"--query") => json!("192.0.2.1"),
                "describe-instances" => vm(true),
                "describe-volumes" => json!({"Volumes":[volume(
                    if args.contains(&"vol-boot") {"vol-boot"} else {"vol-original"}
                )]}),
                "describe-subnets" => {
                    json!({"Subnets":[{"SubnetId":"subnet","AvailabilityZone":"zone"}]})
                }
                "wait" => json!({}),
                "create-volume" if self.fail_attachment => volume("vol-original"),
                "create-volume" => {
                    return Err(CloudError::CommandFailed {
                        program: program.into(),
                        args: args.join(" "),
                        stderr: "(VolumeLimitExceeded)".into(),
                        code: Some(1),
                    })
                }
                "attach-volume" => return Err(error("attachment failed")),
                _ => panic!("unexpected provider command: {args:?}"),
            };
            Ok(CommandOutput {
                status: 0,
                stdout: value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
                stderr: String::new(),
            })
        }
        async fn run_stream(
            &self,
            _: &str,
            _: &[&str],
            _: bool,
        ) -> Result<CommandOutput, CloudError> {
            panic!("unexpected streaming call")
        }
    }

    for fail_attachment in [false, true] {
        let (dir, mut state) = fixture(PlatformKind::Aws);
        // Creation succeeded and its original response was saved before the
        // remaining VM setup. Exercise that setup through the real provider.
        state.provisioning.creations.insert(
            "instance".into(),
            Creation {
                request: CreateRequest::Aws {
                    args: [
                        "ec2",
                        "run-instances",
                        "--image-id",
                        "ami",
                        "--security-group-ids",
                        "sg",
                        "--subnet-id",
                        "subnet",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                },
                token: "original-request".into(),
                sent: true,
                receipt: None,
                result: Some(json!({"Instances":[{"InstanceId":"i-vm"}]})),
                outcome: CreationOutcome::Succeeded,
            },
        );
        let step = DeployStep::CreateInstanceAws {
            boot_disk_performance: None,
            instance_name: "vm".into(),
            instance_type: "m6a.large".into(),
            image_name: "image".into(),
            security_group: "group".into(),
            metadata: vec![],
            disks: vec![spec("gp3")],
            boot_disk_size_gb: Some(8),
            static_ip: None,
        };
        state.provisioning.steps = vec![step.clone()];
        state.save(dir.path()).unwrap();
        let runner = SetupFailure { fail_attachment };
        let provider = crate::aws::AwsProvider::new("region".into());
        let error = provider
            .execute_step(&step, &durable(&dir, &runner), false)
            .await
            .err()
            .expect("data disk setup must fail");
        assert!(
            error.to_string().contains(if fail_attachment {
                "attachment failed"
            } else {
                "VolumeLimitExceeded"
            }),
            "{error}"
        );
        let mut saved = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert_eq!(saved.cloud_instance_id.as_deref(), Some("i-vm"));
        assert_eq!(saved.created_boot_disk.as_ref().unwrap().id, "vol-boot");
        assert!(!saved.provisioning_complete);
        assert!(!cleanup::has_unresolved(&saved));

        cleanup::record_attachments(&mut saved, &Runner::new(vec![Ok(vm(true))]))
            .await
            .unwrap();
        assert!(saved.cleanup.retained_disks.is_empty());
        let mut plan = provider
            .plan_destroy(&saved, &crate::DestroyOptions { preserve: vec![] })
            .unwrap();
        cleanup::add_boot_disk_step(&saved, &mut plan.steps).unwrap();
        plan.steps = cleanup::separate_steps(plan.steps);
        let boot_step = DestroyStep::DeleteDisks {
            names: vec!["vol-boot".into()],
            resource_group: None,
        };
        assert_eq!(
            cleanup::step_key(&plan.steps[1]),
            cleanup::step_key(&boot_step)
        );

        // Saving the boot identity must not weaken the deletion identity check.
        let replaced = Runner::new(vec![Ok(json!({"Volumes":[volume("vol-replacement")]}))]);
        assert!(cleanup::before_step(&saved, &boot_step, false, &replaced)
            .await
            .unwrap_err()
            .to_string()
            .contains("disk was replaced"));
        assert_eq!(replaced.calls.lock().unwrap().len(), 1);

        let mut replies = vec![
            Ok(vm(true)),
            Ok(json!({})), // disable automatic deletion
            Ok(vm(false)),
            Ok(json!({})), // terminate VM
            Ok(json!({})), // instance-terminated waiter
        ];
        let mut expected_deleted = vec!["vol-boot"];
        if fail_attachment {
            expected_deleted.push("vol-original");
        }
        for id in &expected_deleted {
            replies.extend([
                Ok(json!({"Volumes":[volume(id)]})), // deletion guard
                Ok(json!({"Volumes":[volume(id)]})), // unattached-volume check
                Ok(json!({})),                       // volume-available waiter
                Ok(json!({})),                       // delete volume
            ]);
        }
        let runner = Runner::new(replies);
        for step in &plan.steps {
            cleanup::before_step(&saved, step, false, &runner)
                .await
                .unwrap();
            provider
                .execute_destroy_step(step, &runner, false)
                .await
                .unwrap();
            cleanup::completed(&mut saved, step);
        }
        cleanup::report_remaining(&mut saved, &[], &runner)
            .await
            .unwrap();
        assert!(saved.cleanup.remaining.is_empty());
        assert!(runner.replies.lock().unwrap().is_empty());
        let calls = runner.calls.lock().unwrap();
        let deleted: Vec<_> = calls
            .iter()
            .filter(|args| args.iter().any(|arg| arg == "delete-volume"))
            .map(|args| args.last().unwrap().as_str())
            .collect();
        assert_eq!(deleted, expected_deleted);
    }
}

#[tokio::test]
async fn all_providers_resume_saved_resources_and_second_resume_only_checks() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (dir, mut state) = fixture(platform);
        let saved = |request, result| Creation {
            outcome: Default::default(),
            request,
            token: "saved-token".into(),
            sent: true,
            receipt: None,
            result: Some(result),
        };
        let (provider, step, disk, instance_request, instance_result, disk_request, disk_result): (
            Box<dyn crate::CloudProvider>,
            _,
            _,
            _,
            _,
            _,
            _,
        ) = match platform {
            PlatformKind::Aws => {
                let disk = spec("gp3");
                (
                    Box::new(crate::aws::AwsProvider::new("region".into())),
                    DeployStep::CreateInstanceAws {
                        boot_disk_performance: None,
                        instance_name: "vm".into(),
                        instance_type: "m6a.large".into(),
                        image_name: "image".into(),
                        security_group: "group".into(),
                        metadata: vec![],
                        disks: vec![disk.clone()],
                        boot_disk_size_gb: None,
                        static_ip: None,
                    },
                    disk,
                    CreateRequest::Aws {
                        args: [
                            "ec2",
                            "run-instances",
                            "--image-id",
                            "ami",
                            "--security-group-ids",
                            "sg",
                            "--subnet-id",
                            "subnet",
                        ]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    },
                    json!({"Instances":[{"InstanceId":"i-vm"}]}),
                    CreateRequest::Aws {
                        args: [
                            "ec2",
                            "create-volume",
                            "--region",
                            "region",
                            "--availability-zone",
                            "zone",
                            "--volume-type",
                            "gp3",
                            "--size",
                            "8",
                            "--output",
                            "json",
                        ]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    },
                    volume("vol-original"),
                )
            }
            PlatformKind::Gcp => {
                let disk = spec("pd-balanced");
                (
                    Box::new(crate::gcp::GcpProvider::new(
                        "project".into(),
                        "zone".into(),
                    )),
                    DeployStep::CreateInstance {
                        boot_disk_performance: None,
                        instance_name: "vm".into(),
                        machine_type: "n2d-standard-2".into(),
                        zone: "zone".into(),
                        image: "image".into(),
                        cc_type: crate::CcType::SevSnp,
                        metadata: vec![],
                        disks: vec![disk.clone()],
                        boot_disk_size_gb: None,
                        static_ip: None,
                    },
                    disk,
                    CreateRequest::Gcp {
                        project: "project".into(),
                        zone: "zone".into(),
                        collection: "instances".into(),
                        body: json!({"name":"vm"}),
                    },
                    ExistingResources::gcp_vm(),
                    CreateRequest::Gcp {
                        project: "project".into(),
                        zone: "zone".into(),
                        collection: "disks".into(),
                        body: json!({"name":"vm-data","sizeGb":"8","type":"projects/project/zones/zone/diskTypes/pd-balanced"}),
                    },
                    ExistingResources::gcp_disk("vm-data"),
                )
            }
            PlatformKind::Azure => {
                let disk = spec("StandardSSD_LRS");
                (
                    Box::new(crate::azure::AzureProvider::new(
                        "sub".into(),
                        "region".into(),
                    )),
                    DeployStep::CreateInstanceAzure {
                        availability_zone: None,
                        instance_name: "vm".into(),
                        vm_size: "Standard_DC2as_v5".into(),
                        image_id: "image".into(),
                        image_ref: "image".into(),
                        cc_type: crate::CcType::SevSnp,
                        resource_group: "group".into(),
                        nsg: "group".into(),
                        metadata: vec![],
                        disks: vec![disk.clone()],
                        boot_disk_size_gb: None,
                        static_ip: None,
                        static_ip_resource_group: None,
                    },
                    disk,
                    CreateRequest::AzureVm {
                        subscription: "sub".into(),
                        group: "group".into(),
                        name: "vm".into(),
                        body: json!({"properties":{"storageProfile":{"dataDisks":[{"name":"vm-data","lun":0,"createOption":"Empty","diskSizeGB":8,"managedDisk":{"storageAccountType":"StandardSSD_LRS"}}]}}}),
                    },
                    json!({"id":"/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/vm","name":"vm","properties":{"vmId":"vm-unique"}}),
                    azure_request(),
                    azure_disk("original"),
                )
            }
            _ => unreachable!(),
        };
        let observed = match platform {
            PlatformKind::Aws => crate::disk_inventory::aws_observation(&disk_result),
            PlatformKind::Gcp => crate::disk_inventory::gcp_observation(&disk_result),
            _ => crate::disk_inventory::azure_observation(&disk_result),
        }
        .unwrap();
        state.created_disks.insert(
            "data".into(),
            crate::disk_inventory::CreatedDisk {
                specification: disk,
                observed,
                creation_verified: true,
            },
        );
        state.provisioning.steps = vec![step];
        state
            .provisioning
            .creations
            .insert("instance".into(), saved(instance_request, instance_result));
        state
            .provisioning
            .creations
            .insert("disk:data".into(), saved(disk_request, disk_result));
        state.save(dir.path()).unwrap();
        let runner = ExistingResources {
            calls: Mutex::new(vec![]),
        };
        resume(dir.path(), "target", "vm", provider.as_ref(), &runner)
            .await
            .unwrap();
        let loaded = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert!(loaded.provisioning_complete);
        assert_eq!(loaded.provisioning.next_step, 1);
        runner.calls.lock().unwrap().clear();
        resume(dir.path(), "target", "vm", provider.as_ref(), &runner)
            .await
            .unwrap();
        assert!(runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|args| !args.contains(&"wait".into())));
    }
}

#[tokio::test]
async fn definite_rejection_retries_but_transport_failure_does_not() {
    for status in [400, 401, 403, 404, 409, 412, 422, 429] {
        let (dir, _) = fixture(PlatformKind::Gcp);
        let rejected = CloudError::ProviderResponse {
            provider: "GCP",
            status,
            code: "DENIED".into(),
            message: "denied".into(),
        };
        assert!(matches!(
            rejected_response(rejected),
            CloudError::CreationRejected { .. }
        ));
        let runner = Runner::new(vec![
            Err("HTTP 403"),
            Ok(operation()),
            Ok(json!({"id":"123","name":"vm-data"})),
        ]);
        assert!(durable(&dir, &runner)
            .create_resource("disk:data", &gcp_request())
            .await
            .is_err());
        let first = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert_eq!(
            first.provisioning.creations["disk:data"].outcome,
            CreationOutcome::Rejected
        );
        assert!(!crate::provisioning_cleanup::has_unresolved(&first));
        durable(&dir, &runner)
            .create_resource("disk:data", &gcp_request())
            .await
            .unwrap();
        let second = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert_ne!(
            first.provisioning.creations["disk:data"].token,
            second.provisioning.creations["disk:data"].token
        );
        assert_eq!(
            second.provisioning.creations["disk:data"].outcome,
            CreationOutcome::Succeeded
        );
        assert!(!runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.iter().any(|arg| arg.contains("operations?filter"))));
    }
    for status in [408, 500, 502, 503, 504] {
        let e = CloudError::ProviderResponse {
            provider: "GCP",
            status,
            code: "UNKNOWN".into(),
            message: "unknown".into(),
        };
        assert!(!matches!(
            rejected_response(e),
            CloudError::CreationRejected { .. }
        ));
    }
}

#[test]
fn only_known_pre_request_auth_and_provider_rejections_allow_retry() {
    for (program, args, stderr, retry) in [
        ("gcloud", "auth print-access-token", "please login", true),
        ("az", "account get-access-token", "please login", true),
        ("aws", "ec2 create-volume", "(VolumeLimitExceeded)", true),
        ("aws", "ec2 run-instances", "(UnauthorizedOperation)", true),
        ("aws", "ec2 create-volume", "connection timed out", false),
        ("az", "rest", "(InvalidTemplate)", true),
        ("az", "rest", "(DeploymentFailed)", false),
    ] {
        let e = CloudError::CommandFailed {
            program: program.into(),
            args: args.into(),
            stderr: stderr.into(),
            code: Some(1),
        };
        assert_eq!(
            matches!(rejected_command(e), CloudError::CreationRejected { .. }),
            retry
        );
    }
}

fn vm_request() -> CreateRequest {
    CreateRequest::AzureVm {
        subscription: "sub".into(),
        group: "group".into(),
        name: "vm".into(),
        body: json!({"properties":{"storageProfile":{"dataDisks":[{"name":"vm-data","lun":0,"createOption":"Empty","diskSizeGB":8,"managedDisk":{"storageAccountType":"StandardSSD_LRS"}}]}}}),
    }
}
fn azure_vm_result() -> Value {
    json!({"id":"/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/vm","name":"vm","properties":{"vmId":"vm-unique","provisioningState":"Succeeded"}})
}

#[tokio::test]
async fn azure_vm_requires_conditional_create_and_never_repeats_a_lost_put() {
    let (dir, _) = fixture(PlatformKind::Azure);
    let runner = Runner::new(vec![Ok(azure_vm_result()), Ok(azure_vm_result())]);
    durable(&dir, &runner)
        .create_resource("instance", &vm_request())
        .await
        .unwrap();
    durable(&dir, &runner)
        .create_resource("instance", &vm_request())
        .await
        .unwrap();
    {
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(&calls[0][..2], ["azure-api", "PUT"]);
        assert_eq!(calls[0][3], "true");
    }
    let (dir, _) = fixture(PlatformKind::Azure);
    let runner = Runner::new(vec![Err("lost response")]);
    assert!(durable(&dir, &runner)
        .create_resource("instance", &vm_request())
        .await
        .is_err());
    assert!(durable(&dir, &runner)
        .create_resource("instance", &vm_request())
        .await
        .is_err());
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn azure_network_records_conditional_response_and_reuses_it_on_retry() {
    let (dir, _) = fixture(PlatformKind::Azure);
    let id =
        "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Network/networkInterfaces/nic";
    let request = CreateRequest::AzureNetwork {
        id: id.into(),
        api_version: "2024-05-01".into(),
        body: json!({"location":"eastus"}),
    };
    let response = json!({"id":id,"properties":{"resourceGuid":"original-nic","provisioningState":"Succeeded"}});
    let runner = Runner::new(vec![Ok(response.clone()), Err("poll failed"), Ok(response)]);
    assert!(durable(&dir, &runner)
        .create_resource("network:nic", &request)
        .await
        .is_err());
    let mut state = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        state.resources.azure.as_ref().unwrap().owned_resources[id].identity,
        "original-nic"
    );
    state
        .resources
        .azure
        .as_mut()
        .unwrap()
        .owned_resources
        .clear();
    crate::provisioning_cleanup::recover_records(&mut state).unwrap();
    assert_eq!(
        state.resources.azure.as_ref().unwrap().owned_resources[id].identity,
        "original-nic"
    );
    durable(&dir, &runner)
        .create_resource("network:nic", &request)
        .await
        .unwrap();
    durable(&dir, &runner)
        .create_resource("network:nic", &request)
        .await
        .unwrap();
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(&calls[0][..2], ["azure-api", "PUT"]);
    assert_eq!(calls[0][3], "true");
    assert!(calls[1..].iter().all(|call| call[1] == "GET"));
}

#[test]
fn azure_network_requires_created_status_not_successful_update() {
    assert!(require_azure_network_created(201).is_ok());
    for status in [200, 202, 204] {
        assert!(require_azure_network_created(status).is_err());
    }
}

#[tokio::test]
async fn standalone_azure_public_ip_put_is_blocked_before_any_provider_call() {
    let runner = Runner::new(vec![]);
    let url = "https://management.azure.com/subscriptions/sub/resourceGroups/group/providers/Microsoft.Network/publicIPAddresses/existing?api-version=2024-05-01";
    let result = azure_api(
        &runner,
        "PUT",
        url,
        Some(&json!({"location":"eastus"})),
        true,
    )
    .await;
    assert!(matches!(result, Err(CloudError::CreationRejected { .. })));
    assert!(runner.calls.lock().unwrap().is_empty());
}

fn vm_network_fixture() -> (CreateRequest, Value, Value, Value) {
    let prefix = "/subscriptions/sub/resourceGroups/group/providers";
    let vm_id = format!("{prefix}/Microsoft.Compute/virtualMachines/vm");
    let nic_id = format!("{prefix}/Microsoft.Network/networkInterfaces/allocated-nic");
    let ip_id = format!("{prefix}/Microsoft.Network/publicIPAddresses/allocated-ip");
    let subnet = format!("{prefix}/Microsoft.Network/virtualNetworks/vnet/subnets/default");
    let attachment = format!("{nic_id}/ipConfigurations/primary");
    let mut request = vm_request();
    let CreateRequest::AzureVm { body, .. } = &mut request else {
        unreachable!()
    };
    body["properties"]["networkProfile"] = json!({"networkInterfaceConfigurations":[{"name":"nic","properties":{"ipConfigurations":[{"name":"primary","properties":{"subnet":{"id":subnet},"publicIPAddressConfiguration":{"name":"ip","sku":{"name":"Standard"},"properties":{"deleteOption":"Detach","publicIPAllocationMethod":"Static"}}}}]}}]});
    let mut vm = azure_vm_result();
    vm["properties"]["networkProfile"] = json!({"networkInterfaces":[{"id":nic_id}]});
    let nic = json!({"id":nic_id,"properties":{"resourceGuid":"nic-original","virtualMachine":{"id":vm_id},"ipConfigurations":[{"name":"primary","id":attachment,"properties":{"subnet":{"id":subnet},"publicIPAddress":{"id":ip_id,"properties":{"deleteOption":"Detach"}}}}]}});
    let ip = json!({"id":ip_id,"sku":{"name":"Standard"},"properties":{"resourceGuid":"ip-original","ipConfiguration":{"id":attachment},"deleteOption":"Detach","publicIPAllocationMethod":"Static"}});
    (request, vm, nic, ip)
}

#[tokio::test]
async fn vm_created_network_records_identities_and_resume_never_recreates_it() {
    let (request, vm, nic, ip) = vm_network_fixture();
    let (dir, _) = fixture(PlatformKind::Azure);
    let runner = Runner::new(vec![
        Ok(vm.clone()),
        Ok(vm),
        Ok(nic.clone()),
        Ok(ip.clone()),
    ]);
    durable(&dir, &runner)
        .create_resource("instance", &request)
        .await
        .unwrap();
    durable(&dir, &runner)
        .create_resource("instance", &request)
        .await
        .unwrap();
    let state = DeployState::load(dir.path(), "target", "vm").unwrap();
    let owned = state.resources.azure.unwrap().owned_resources;
    assert_eq!(owned.len(), 2);
    assert_eq!(owned[nic["id"].as_str().unwrap()].identity, "nic-original");
    assert_eq!(owned[ip["id"].as_str().unwrap()].identity, "ip-original");
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0][1], "PUT");
    assert!(calls[1..].iter().all(|c| c[1] == "GET"));
}

#[tokio::test]
async fn vm_created_network_refuses_missing_provenance_or_changed_attachments() {
    for case in 0..4 {
        let (request, original, mut nic, mut ip) = vm_network_fixture();
        let mut current = original.clone();
        match case {
            0 => {
                current["properties"]["networkProfile"]["networkInterfaces"][0]["id"] =
                    json!("replacement")
            }
            1 => nic["properties"]["virtualMachine"]["id"] = json!("another-vm"),
            2 => ip["properties"]["ipConfiguration"]["id"] = json!("another-nic"),
            _ => {
                nic["properties"]["ipConfigurations"][0]["properties"]["publicIPAddress"]
                    ["properties"]["deleteOption"] = json!("Delete")
            }
        }
        let (dir, _) = fixture(PlatformKind::Azure);
        let runner = Runner::new(vec![Ok(original), Ok(current), Ok(nic), Ok(ip)]);
        assert!(durable(&dir, &runner)
            .create_resource("instance", &request)
            .await
            .is_err());
        let state = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert!(state.resources.azure.unwrap().owned_resources.is_empty());
        assert!(state.provisioning.creations["instance"].receipt.is_some());
    }
}

#[tokio::test]
async fn azure_cleanup_checks_stale_inventory_without_hiding_present_resources() {
    let id = "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/vm-data";
    for (reply, absent) in [
        (Err("Azure missing"), true),
        // Captured from a successful disk deletion followed by stale Azure
        // resource-list output and a direct resource-show absence check.
        (Err("Azure stderr: ERROR: (NotFound) Disk vm-data is not found.\nCode: NotFound\nMessage: Disk vm-data is not found."), true),
        (Err("Azure stderr: ERROR: (ResourceNotFound) Resource vm-data was not found.\nCode: ResourceNotFound"), true),
        (Err("Azure stderr: ERROR: (ResourceGroupNotFound) Resource group group could not be found."), true),
        (Err("Azure stderr: Code: NotFound\nMessage: Disk vm-data is not found."), true),
        (Ok(json!({"id":id})), false),
        (Err("Azure stderr: ERROR: (AuthorizationFailed) Access to vm-data denied.\nCode: AuthorizationFailed"), false),
        (Err("Azure stderr: ERROR: connection timed out"), false),
        (Err("Azure stderr: ERROR: (ResourceNotFoundException) Unexpected provider error."), false),
        // Text in the message must not override the primary error code.
        (Err("Azure stderr: ERROR: (AuthorizationFailed) ResourceNotFound is not an absence check.\nCode: NotFound"), false),
    ] {
        let (_, mut state) = fixture(PlatformKind::Azure);
        state.resources.azure.as_mut().unwrap().resource_group = Some("group".into());
        crate::provisioning_cleanup::completed(
            &mut state,
            &crate::DestroyStep::DeleteDisks {
                names: vec!["vm-data".into()],
                resource_group: Some("group".into()),
            },
        );
        let runner = Runner::new(vec![
            Ok(json!([{"id":id,"name":"vm-data"}])),
            reply,
        ]);
        crate::provisioning_cleanup::report_remaining(&mut state, &[], &runner)
            .await
            .unwrap();
        assert_eq!(state.cleanup.remaining.contains_key(id), !absent);
        assert_eq!(
            state.cleanup.remaining["resource group group"].starts_with("empty group"),
            absent
        );
        assert_eq!(runner.calls.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn azure_network_never_adopts_rejected_lost_or_replaced_resources() {
    let id =
        "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Network/networkInterfaces/nic";
    let request = CreateRequest::AzureNetwork {
        id: id.into(),
        api_version: "2024-05-01".into(),
        body: json!({"location":"eastus"}),
    };
    for failure in ["HTTP 412", "lost response"] {
        let (dir, _) = fixture(PlatformKind::Azure);
        let runner = Runner::new(vec![Err(failure)]);
        assert!(durable(&dir, &runner)
            .create_resource("network:nic", &request)
            .await
            .is_err());
        if failure == "lost response" {
            assert!(durable(&dir, &runner)
                .create_resource("network:nic", &request)
                .await
                .is_err());
        }
        let mut state = DeployState::load(dir.path(), "target", "vm").unwrap();
        crate::provisioning_cleanup::recover_records(&mut state).unwrap();
        assert!(state.resources.azure.unwrap().owned_resources.is_empty());
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }
    let (dir, _) = fixture(PlatformKind::Azure);
    let runner = Runner::new(vec![
        Ok(json!({"id":id,"properties":{"resourceGuid":"original"}})),
        Ok(
            json!({"id":id,"properties":{"resourceGuid":"replacement","provisioningState":"Succeeded"}}),
        ),
    ]);
    assert!(durable(&dir, &runner)
        .create_resource("network:nic", &request)
        .await
        .unwrap_err()
        .to_string()
        .contains("differs"));
    let state = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        state.resources.azure.unwrap().owned_resources[id].identity,
        "original"
    );
}

#[tokio::test]
async fn azure_vm_rejection_is_retryable_and_partial_vm_is_tracked() {
    let (dir, _) = fixture(PlatformKind::Azure);
    let runner = Runner::new(vec![
        Err("HTTP 412"),
        Ok(azure_vm_result()),
        Err("poll failed"),
    ]);
    assert!(durable(&dir, &runner)
        .create_resource("instance", &vm_request())
        .await
        .is_err());
    let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        saved.provisioning.creations["instance"].outcome,
        CreationOutcome::Rejected
    );
    assert!(durable(&dir, &runner)
        .create_resource("instance", &vm_request())
        .await
        .is_err());
    let mut saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    crate::provisioning_cleanup::recover_records(&mut saved).unwrap();
    assert_eq!(saved.cloud_instance_id.as_deref(), Some("vm-unique"));
    assert_eq!(
        saved.resources.azure.as_ref().unwrap().instance.as_deref(),
        Some("vm")
    );
    crate::provisioning_cleanup::completed(
        &mut saved,
        &crate::DestroyStep::DeleteInstance { name: "vm".into() },
    );
    assert!(!crate::provisioning_cleanup::has_unresolved(&saved));
}

#[tokio::test]
async fn cleanup_read_only_recovery_keeps_unknown_disk_independent_of_vm() {
    let (dir, mut state) = fixture(PlatformKind::Aws);
    state.provisioning.creations.insert(
        "disk:unknown".into(),
        Creation {
            request: aws_request(),
            token: "unknown".into(),
            sent: true,
            outcome: CreationOutcome::Unknown,
            receipt: None,
            result: None,
        },
    );
    state.resources.aws.as_mut().unwrap().instance = Some("i-vm".into());
    state.cloud_instance_id = Some("i-vm".into());
    state.save(dir.path()).unwrap();
    let runner = Runner::new(vec![]);
    crate::provisioning_cleanup::reconcile_records(dir.path(), &mut state, &runner)
        .await
        .unwrap();
    assert_eq!(state.cloud_instance_id.as_deref(), Some("i-vm"));
    assert!(state
        .cleanup
        .remaining
        .contains_key("creation disk:unknown"));
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn one_replaced_disk_does_not_block_checking_another_disk() {
    let (_, mut state) = fixture(PlatformKind::Gcp);
    for (name, id) in [("one", "1"), ("two", "2")] {
        let mut spec = spec("pd-balanced");
        spec.name = name.into();
        spec.device_name = name.into();
        state.created_disks.insert(
            name.into(),
            crate::disk_inventory::CreatedDisk {
                specification: spec,
                observed: crate::disk_inventory::gcp_observation(
                    &json!({"id":id,"sizeGb":"8","type":"pd-balanced"}),
                )
                .unwrap(),
                creation_verified: true,
            },
        );
    }
    let steps =
        crate::provisioning_cleanup::separate_steps(vec![crate::DestroyStep::DeleteDisks {
            names: vec!["one".into(), "two".into()],
            resource_group: None,
        }]);
    let runner = Runner::new(vec![
        Ok(json!({"id":"replacement","sizeGb":"8","type":"pd-balanced"})),
        Ok(json!({"id":"2","sizeGb":"8","type":"pd-balanced"})),
    ]);
    assert!(
        crate::provisioning_cleanup::before_step(&state, &steps[0], false, &runner)
            .await
            .is_err()
    );
    crate::provisioning_cleanup::before_step(&state, &steps[1], false, &runner)
        .await
        .unwrap();
    assert_eq!(runner.calls.lock().unwrap()[1][4], "two");
}

#[tokio::test]
async fn azure_group_containing_a_rejected_disk_is_never_deleted() {
    let (_, state) = fixture(PlatformKind::Azure);
    let provider = crate::azure::AzureProvider::new("sub".into(), "region".into());
    let plan = crate::CloudProvider::plan_destroy(
        &provider,
        &state,
        &crate::provider::DestroyOptions { preserve: vec![] },
    )
    .unwrap();
    assert!(!plan
        .steps
        .iter()
        .any(|s| matches!(s, crate::DestroyStep::DeleteResourceGroup { .. })));
    let runner = Runner::new(vec![]);
    assert!(crate::CloudProvider::execute_destroy_step(
        &provider,
        &crate::DestroyStep::DeleteResourceGroup {
            name: "group".into()
        },
        &runner,
        false
    )
    .await
    .is_err());
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cleanup_started_blocks_creation_without_any_cloud_call() {
    let (dir, mut state) = fixture(PlatformKind::Aws);
    state.cleanup.started = true;
    state.save(dir.path()).unwrap();
    let runner = Runner::new(vec![]);
    assert!(durable(&dir, &runner)
        .create_resource("disk:data", &aws_request())
        .await
        .is_err());
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn vm_shutdown_checks_identity_and_final_power_state_for_every_provider() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (_, mut state) = fixture(platform);
        state.cloud_instance_id = Some("original".into());
        let responses = match platform {
            PlatformKind::Aws => {
                state.resources.aws.as_mut().unwrap().instance = Some("original".into());
                vec![
                    Ok(
                        json!({"Reservations":[{"Instances":[{"InstanceId":"original","State":{"Name":"running"}}]}]}),
                    ),
                    Ok(json!({})),
                    Ok(json!({})),
                    Ok(
                        json!({"Reservations":[{"Instances":[{"InstanceId":"original","State":{"Name":"stopped"}}]}]}),
                    ),
                ]
            }
            PlatformKind::Gcp => {
                state.resources.gcp.as_mut().unwrap().instance = Some("vm".into());
                vec![
                    Ok(json!({"id":"original","status":"RUNNING"})),
                    Ok(json!({})),
                    Ok(json!({"id":"original","status":"TERMINATED"})),
                ]
            }
            PlatformKind::Azure => {
                state.resources.azure.as_mut().unwrap().instance = Some("vm".into());
                vec![
                    Ok(json!({"vmId":"original"})),
                    Ok(json!({})),
                    Ok(json!({"vmId":"original"})),
                    Ok(json!({"instanceView":{"statuses":[{"code":"PowerState/deallocated"}]}})),
                ]
            }
            _ => unreachable!(),
        };
        let runner = Runner::new(responses);
        let power = crate::provisioning_cleanup::stop_verified_vm(&state, &runner)
            .await
            .unwrap();
        assert!(matches!(
            power.as_str(),
            "stopped" | "TERMINATED (stopped)" | "deallocated"
        ));
        let wrong = match platform {
            PlatformKind::Aws => {
                json!({"Reservations":[{"Instances":[{"InstanceId":"replacement"}]}]})
            }
            PlatformKind::Gcp => json!({"id":"replacement"}),
            _ => json!({"vmId":"replacement"}),
        };
        let runner = Runner::new(vec![Ok(wrong)]);
        assert!(
            crate::provisioning_cleanup::stop_verified_vm(&state, &runner)
                .await
                .is_err()
        );
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn azure_powered_off_is_not_reported_as_deallocated() {
    let (_, mut state) = fixture(PlatformKind::Azure);
    state.cloud_instance_id = Some("original".into());
    state.resources.azure.as_mut().unwrap().instance = Some("vm".into());
    let runner = Runner::new(vec![
        Ok(json!({"vmId":"original"})),
        Ok(json!({})),
        Ok(json!({"vmId":"original"})),
        Ok(json!({"statuses":[{"code":"PowerState/stopped"}]})),
    ]);
    let e = crate::provisioning_cleanup::stop_verified_vm(&state, &runner)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("PowerState/stopped"));
    assert!(runner.calls.lock().unwrap()[1].contains(&"deallocate".into()));
}

#[tokio::test]
async fn gcp_preserves_only_persistent_disks_and_retries_partial_updates() {
    use crate::{provisioning_cleanup::before_step, CloudProvider, DestroyStep};
    let (_, mut state) = fixture(PlatformKind::Gcp);
    state.cloud_instance_id = Some("original".into());
    state.resources.gcp.as_mut().unwrap().instance = Some("vm".into());
    let vm = |boot_auto, data_auto| {
        json!({"id":"original","disks":[
            {"type":"PERSISTENT","boot":true,"deviceName":"boot","source":"disks/boot","autoDelete":boot_auto},
            {"type":"SCRATCH","boot":false,"deviceName":"local-ssd-0","autoDelete":true},
            {"type":"PERSISTENT","boot":false,"deviceName":"foreign","source":"disks/foreign","autoDelete":data_auto}
        ]})
    };
    let step = DestroyStep::DeleteInstance { name: "vm".into() };
    for preserve in [false, true] {
        let runner = Runner::new(vec![
            Ok(vm(true, true)),
            Ok(json!({})),
            Err("update denied"),
        ]);
        assert!(before_step(&state, &step, preserve, &runner).await.is_err());
        assert_eq!(runner.calls.lock().unwrap().len(), 3);
        assert!(runner.calls.lock().unwrap()[1].contains(&"boot".into()));
        assert!(runner.calls.lock().unwrap()[2].contains(&"foreign".into()));

        // The first disk update survived. Retry only updates the other disk.
        let runner = Runner::new(vec![
            Ok(vm(false, true)),
            Ok(json!({})),
            Ok(vm(false, false)),
            Ok(json!({})),
        ]);
        before_step(&state, &step, preserve, &runner).await.unwrap();
        crate::gcp::GcpProvider::new("project".into(), "zone".into())
            .execute_destroy_step(&step, &runner, false)
            .await
            .unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert!(
            calls[1].contains(&"foreign".into()) && calls[1].contains(&"--no-auto-delete".into())
        );
        assert!(calls[3].contains(&"delete".into()));
        assert!(!calls
            .iter()
            .flatten()
            .any(|arg| arg == "local-ssd-0" || arg.starts_with("--keep-disks")));
    }
    let runner = Runner::new(vec![
        Ok(vm(false, true)),
        Ok(json!({})),
        Ok(vm(false, true)),
    ]);
    assert!(before_step(&state, &step, false, &runner)
        .await
        .unwrap_err()
        .to_string()
        .contains("did not confirm"));
    let runner = Runner::new(vec![Ok(vm(false, false))]);
    before_step(&state, &step, false, &runner).await.unwrap();
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn gcp_cleanup_stop_discards_local_ssd_only_when_attached() {
    let (_, mut state) = fixture(PlatformKind::Gcp);
    state.cloud_instance_id = Some("original".into());
    state.resources.gcp.as_mut().unwrap().instance = Some("vm".into());
    for local in [false, true] {
        let vm = |status| json!({"id":"original","status":status,"disks":[{"type":if local {"SCRATCH"} else {"PERSISTENT"}}]});
        let runner = Runner::new(vec![Ok(vm("RUNNING")), Ok(json!({})), Ok(vm("TERMINATED"))]);
        crate::provisioning_cleanup::stop_verified_vm(&state, &runner)
            .await
            .unwrap();
        assert_eq!(
            runner.calls.lock().unwrap()[1].contains(&"--discard-local-ssd=true".into()),
            local
        );
        // A retry must not stop a VM already confirmed stopped.
        let runner = Runner::new(vec![Ok(vm("TERMINATED")), Ok(vm("TERMINATED"))]);
        crate::provisioning_cleanup::stop_verified_vm(&state, &runner)
            .await
            .unwrap();
        assert_eq!(runner.calls.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn azure_preserves_disks_before_vm_deletion() {
    let (_, mut state) = fixture(PlatformKind::Azure);
    state.cloud_instance_id = Some("original".into());
    state.resources.azure.as_mut().unwrap().instance = Some("vm".into());
    let step = crate::DestroyStep::DeleteInstance { name: "vm".into() };
    let vm = |option| json!({"vmId":"original","storageProfile":{"osDisk":{"deleteOption":option,"managedDisk":{"id":"boot"}},"dataDisks":[{"lun":0,"deleteOption":option,"managedDisk":{"id":"foreign"}}]},"networkProfile":{"networkInterfaces":[{"id":"nic","deleteOption":option}]}});
    let runner = Runner::new(vec![Ok(vm("Delete")), Ok(json!({})), Ok(vm("Detach"))]);
    crate::provisioning_cleanup::before_step(&state, &step, false, &runner)
        .await
        .unwrap();
    assert!(runner.calls.lock().unwrap()[1]
        .contains(&"storageProfile.dataDisks[0].deleteOption=Detach".into()));
    assert!(runner.calls.lock().unwrap()[1]
        .contains(&"networkProfile.networkInterfaces[0].deleteOption=Detach".into()));
    let runner = Runner::new(vec![Ok(vm("Delete")), Ok(json!({})), Ok(vm("Delete"))]);
    assert!(
        crate::provisioning_cleanup::before_step(&state, &step, false, &runner)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn azure_failed_deployment_records_created_network_resources() {
    let (dir, _) = fixture(PlatformKind::Azure);
    let id = "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Network/networkInterfaces/vm-nic";
    let request = CreateRequest::Azure {
        subscription: "sub".into(),
        group: "group".into(),
        template: json!({"resources":[{"type":"Microsoft.Network/networkInterfaces","name":"vm-nic","apiVersion":"2024-05-01"}]}),
    };
    let runner = Runner::new(vec![
        Ok(json!({})),
        Ok(json!({"properties":{"provisioningState":"Failed"}})),
        Ok(
            json!([{"properties":{"provisioningState":"Succeeded","provisioningOperation":"Create","statusCode":"Created","response":{"content":{"id":id,"properties":{"resourceGuid":"nic-original"}}}}}]),
        ),
    ]);
    assert!(durable(&dir, &runner)
        .create_resource("network:instance", &request)
        .await
        .is_err());
    let state = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        state.resources.azure.as_ref().unwrap().owned_resources[id].identity,
        "nic-original"
    );
    assert_eq!(
        state.provisioning.creations["network:instance"].outcome,
        CreationOutcome::Failed
    );
    assert!(!crate::provisioning_cleanup::has_unresolved(&state));
}

#[tokio::test]
async fn azure_vm_created_empty_disks_are_verified_but_attached_disks_are_refused() {
    for option in ["Empty", "Attach"] {
        let (dir, _) = fixture(PlatformKind::Azure);
        let runner = Runner::new(vec![Ok(azure_vm_result()), Ok(azure_vm_result())]);
        durable(&dir, &runner)
            .create_resource("instance", &vm_request())
            .await
            .unwrap();
        let vm = json!({"vmId":"vm-unique","storageProfile":{"dataDisks":[{"name":"vm-data","lun":0,"createOption":option,"managedDisk":{"id":azure_disk("disk-original")["id"]}}]}});
        let mut disk = azure_disk("disk-original");
        disk["managedBy"] = azure_vm_result()["id"].clone();
        let runner = Runner::new(vec![Ok(vm), Ok(disk)]);
        let result = crate::azure::disk::record_vm_created_disk(
            "sub",
            "group",
            "vm",
            &spec("StandardSSD_LRS"),
            &durable(&dir, &runner),
        )
        .await;
        let state = DeployState::load(dir.path(), "target", "vm").unwrap();
        if option == "Empty" {
            result.unwrap();
            assert!(state.created_disks["data"].creation_verified);
        } else {
            assert!(result.is_err());
            assert!(state.created_disks.is_empty());
            assert_eq!(runner.calls.lock().unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn azure_network_deletion_checks_identity_and_confirms_absence() {
    let resource = crate::provisioning_cleanup::AzureResource { id: "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Network/publicIPAddresses/ip".into(), api_version: "2024-05-01".into(), identity_field: "resourceGuid".into(), identity: "original".into() };
    let runner = Runner::new(vec![Ok(
        json!({"properties":{"resourceGuid":"replacement"}}),
    )]);
    assert!(
        crate::provisioning_cleanup::delete_azure_resource(&resource, &runner)
            .await
            .is_err()
    );
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
    let runner = Runner::new(vec![
        Ok(json!({"properties":{"resourceGuid":"original"}})),
        Ok(json!({})),
        Ok(json!({"properties":{"resourceGuid":"original"}})),
    ]);
    assert!(
        crate::provisioning_cleanup::delete_azure_resource(&resource, &runner)
            .await
            .unwrap_err()
            .to_string()
            .contains("still pending")
    );
}

#[tokio::test]
async fn aws_recovery_auth_failure_does_not_erase_original_uncertainty() {
    let (dir, _) = fixture(PlatformKind::Aws);
    let runner = Runner::new(vec![
        Err("lost response"),
        Err("AWS auth"),
        Ok(volume("vol-original")),
    ]);
    assert!(durable(&dir, &runner)
        .create_resource("disk:data", &aws_request())
        .await
        .is_err());
    let token = DeployState::load(dir.path(), "target", "vm")
        .unwrap()
        .provisioning
        .creations["disk:data"]
        .token
        .clone();
    assert!(durable(&dir, &runner)
        .create_resource("disk:data", &aws_request())
        .await
        .is_err());
    let state = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        state.provisioning.creations["disk:data"].outcome,
        CreationOutcome::Unknown
    );
    durable(&dir, &runner)
        .create_resource("disk:data", &aws_request())
        .await
        .unwrap();
    assert!(runner
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|c| c.last() == Some(&token)));
}

#[tokio::test]
async fn aws_image_cleanup_keeps_snapshot_ids_and_attempts_independent_snapshots() {
    let (dir, mut state) = fixture(PlatformKind::Aws);
    let runner = Runner::new(vec![
        Ok(
            json!({"Images":[{"Name":"image","ImageId":"ami-test","BlockDeviceMappings":[{"Ebs":{"SnapshotId":"snap-one"}},{"Ebs":{"SnapshotId":"snap-two"}}]}]}),
        ),
        Ok(json!({})),
        Err("snapshot one is in use"),
        Ok(json!({})),
    ]);
    let result =
        crate::provisioning_cleanup::delete_aws_image(&mut state, dir.path(), "image", &runner)
            .await;
    assert!(result.unwrap_err().to_string().contains("snap-one"));
    assert!(runner
        .calls
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .contains(&"snap-two".into()));
    let mut saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert!(saved.cleanup.image_removal.is_some());
    let runner = Runner::new(vec![Ok(json!({})), Ok(json!({})), Ok(json!({}))]);
    crate::provisioning_cleanup::delete_aws_image(&mut saved, dir.path(), "image", &runner)
        .await
        .unwrap();
    assert!(!runner
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.contains(&"describe-images".into())));
}

#[tokio::test]
async fn gcp_cleanup_recovers_unrecorded_boot_disk_after_read_failure_and_vm_deletion() {
    use crate::provisioning_cleanup as cleanup;
    let (dir, mut state) = fixture(PlatformKind::Gcp);
    state.cloud_instance_id = Some("123".into());
    state.resources.gcp.as_mut().unwrap().instance = Some("vm".into());
    state.provisioning.creations.insert("instance".into(), Creation {
        request: CreateRequest::Gcp { project: "project".into(), zone: "zone".into(), collection: "instances".into(), body: json!({"name":"vm"}) },
        token: "request".into(), sent: true, receipt: None,
        result: Some(json!({"id":"123","name":"vm","disks":[{"boot":true,"source":"projects/project/zones/zone/disks/vm-boot"}]})),
        outcome: CreationOutcome::Succeeded,
    });
    state
        .cleanup
        .retained_disks
        .insert("vm-boot".into(), "boot disk identity was not saved".into());
    cleanup::completed(
        &mut state,
        &crate::DestroyStep::DeleteInstance { name: "vm".into() },
    );
    state.save(dir.path()).unwrap();
    cleanup::reconcile_records(
        dir.path(),
        &mut state,
        &Runner::new(vec![Err("disk lookup unavailable")]),
    )
    .await
    .unwrap();
    assert!(state.created_boot_disk.is_none());
    assert!(state.cleanup.remaining["boot disk recovery"].contains("disk lookup unavailable"));
    assert!(state.cleanup.retained_disks.contains_key("vm-boot"));
    let runner = Runner::new(vec![Ok(
        json!({"id":"456","name":"vm-boot","sizeGb":"24","type":"zones/zone/diskTypes/pd-balanced"}),
    )]);
    cleanup::reconcile_records(dir.path(), &mut state, &runner)
        .await
        .unwrap();
    assert_eq!(state.created_boot_disk.as_ref().unwrap().id, "456");
    assert!(
        state.cleanup.boot_disk.is_none(),
        "do not add a duplicate boot record"
    );
    assert!(!state.cleanup.remaining.contains_key("boot disk recovery"));
    assert!(!state.cleanup.retained_disks.contains_key("vm-boot"));
    let saved =
        crate::DeployState::load(dir.path(), &state.target_name, &state.instance_name).unwrap();
    assert_eq!(saved.created_boot_disk.unwrap().id, "456");
    let mut steps = vec![];
    cleanup::add_boot_disk_step(&state, &mut steps).unwrap();
    assert!(
        matches!(&steps[..], [crate::DestroyStep::DeleteDisks { names, .. }] if names == &["vm-boot"])
    );
    // Once saved, retries must not adopt a different disk or reread its identity.
    cleanup::reconcile_records(dir.path(), &mut state, &Runner::new(vec![]))
        .await
        .unwrap();
    assert_eq!(state.created_boot_disk.unwrap().id, "456");
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn gcp_boot_recovery_checks_creation_scope_and_accepts_confirmed_absence() {
    use crate::provisioning_cleanup as cleanup;
    for invalid in [false, true] {
        let (dir, mut state) = fixture(PlatformKind::Gcp);
        state.cloud_instance_id = Some("123".into());
        state.provisioning.creations.insert("instance".into(), Creation {
            request: CreateRequest::Gcp { project: if invalid { "other" } else { "project" }.into(), zone: "zone".into(), collection: "instances".into(), body: json!({"name":"vm"}) },
            token: "request".into(), sent: true, receipt: None,
            result: Some(json!({"id":"123","name":"vm","disks":[{"boot":true,"source":"projects/project/zones/zone/disks/vm-boot"}]})),
            outcome: CreationOutcome::Succeeded,
        });
        state
            .cleanup
            .retained_disks
            .insert("vm-boot".into(), "boot disk identity was not saved".into());
        state.save(dir.path()).unwrap();
        let runner = Runner::new(if invalid {
            vec![]
        } else {
            vec![Err("GCP missing")]
        });
        cleanup::reconcile_records(dir.path(), &mut state, &runner)
            .await
            .unwrap();
        assert!(state.created_boot_disk.is_none());
        assert_eq!(
            state.cleanup.remaining.contains_key("boot disk recovery"),
            invalid
        );
        assert_eq!(
            state.cleanup.retained_disks.contains_key("vm-boot"),
            invalid
        );
        assert_eq!(runner.calls.lock().unwrap().len(), usize::from(!invalid));
    }
}
