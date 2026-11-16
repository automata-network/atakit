use super::*;
use crate::{CloudProvider, DeployStep};
use std::sync::atomic::{AtomicBool, Ordering};

struct BootRunner {
    resources: ExistingResources,
    fail_boot: AtomicBool,
    fail_later: AtomicBool,
    fail_data: AtomicBool,
    fail_wait: AtomicBool,
    replace_boot: AtomicBool,
    replace_vm: AtomicBool,
}

impl BootRunner {
    fn new() -> Self {
        Self {
            resources: ExistingResources {
                calls: Mutex::new(vec![]),
            },
            fail_boot: AtomicBool::new(false),
            fail_later: AtomicBool::new(false),
            fail_data: AtomicBool::new(false),
            fail_wait: AtomicBool::new(false),
            replace_boot: AtomicBool::new(false),
            replace_vm: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl CommandRunner for BootRunner {
    async fn gcp_api(
        &self,
        method: &str,
        url: &str,
        _: Option<&Value>,
    ) -> Result<Value, CloudError> {
        if method == "POST" {
            let token = url.split("requestId=").nth(1).unwrap();
            Ok(
                json!({"name":"operation","status":"DONE","operationType":"insert","clientOperationId":token,"targetId":"789","targetLink":"https://compute.googleapis.com/compute/v1/projects/project/zones/zone/instances/vm"}),
            )
        } else {
            Ok(ExistingResources::gcp_vm())
        }
    }
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        let boot_read = args.contains(&"describe-volumes")
            || args.starts_with(&["compute", "disks", "describe"])
            || (args.starts_with(&["disk", "show"]) && args.contains(&"--ids"));
        if args.contains(&"instance-running") && self.fail_wait.load(Ordering::SeqCst) {
            return Err(error("VM wait interrupted"));
        }
        if args.starts_with(&["disk", "show"])
            && args.contains(&"vm-data")
            && self.fail_data.load(Ordering::SeqCst)
        {
            return Err(error("data disk lookup unavailable"));
        }
        if boot_read && self.fail_boot.load(Ordering::SeqCst) {
            return Err(error("boot lookup unavailable"));
        }
        let later = (program == "aws" && args.contains(&"--query"))
            || args.starts_with(&["compute", "instances", "describe"])
            || args.starts_with(&["vm", "list-ip-addresses"]);
        if later && self.fail_later.load(Ordering::SeqCst) {
            return Err(error("IP lookup unavailable"));
        }
        let mut output = self.resources.run_capture(program, args).await?;
        if self.replace_vm.load(Ordering::SeqCst)
            && (args.starts_with(&["compute", "instances", "describe"])
                || args.starts_with(&["vm", "show"]))
        {
            let mut value: Value = serde_json::from_str(&output.stdout)?;
            value[if program == "gcloud" { "id" } else { "vmId" }] = "replacement".into();
            output.stdout = value.to_string();
        }
        if boot_read && self.replace_boot.load(Ordering::SeqCst) {
            let mut value: Value = serde_json::from_str(&output.stdout)?;
            match program {
                "aws" => value["Volumes"][0]["VolumeId"] = "replacement".into(),
                "gcloud" => value["id"] = "replacement".into(),
                "az" => value["properties"]["uniqueId"] = "replacement".into(),
                _ => unreachable!(),
            }
            output.stdout = value.to_string();
        }
        Ok(output)
    }
    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<CommandOutput, CloudError> {
        panic!("unexpected stream")
    }
}

fn setup(platform: PlatformKind) -> (tempfile::TempDir, Box<dyn CloudProvider>, DeployStep) {
    let (dir, mut state) = fixture(platform);
    let (provider, request, result, step): (Box<dyn CloudProvider>, _, _, _) = match platform {
        PlatformKind::Aws => (
            Box::new(crate::aws::AwsProvider::new("region".into())),
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
                .map(str::to_owned)
                .to_vec(),
            },
            json!({"Instances":[ExistingResources::aws_vm()["Reservations"][0]["Instances"][0]]}),
            DeployStep::CreateInstanceAws {
                instance_name: "vm".into(),
                instance_type: "m6a.large".into(),
                image_name: "image".into(),
                security_group: "group".into(),
                metadata: vec![],
                disks: vec![],
                boot_disk_size_gb: Some(8),
                boot_disk_performance: None,
                static_ip: None,
            },
        ),
        PlatformKind::Gcp => (
            Box::new(crate::gcp::GcpProvider::new(
                "project".into(),
                "zone".into(),
            )),
            CreateRequest::Gcp {
                project: "project".into(),
                zone: "zone".into(),
                collection: "instances".into(),
                body: json!({"name":"vm"}),
            },
            ExistingResources::gcp_vm(),
            DeployStep::CreateInstance {
                instance_name: "vm".into(),
                machine_type: "n2d-standard-2".into(),
                zone: "zone".into(),
                image: "image".into(),
                cc_type: crate::CcType::SevSnp,
                metadata: vec![],
                disks: vec![],
                boot_disk_size_gb: Some(8),
                boot_disk_performance: None,
                static_ip: None,
            },
        ),
        PlatformKind::Azure => (
            Box::new(crate::azure::AzureProvider::new(
                "sub".into(),
                "region".into(),
            )),
            CreateRequest::AzureVm {
                subscription: "sub".into(),
                group: "group".into(),
                name: "vm".into(),
                body: json!({}),
            },
            json!({"id":"/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/vm","properties":{"vmId":"vm-unique","storageProfile":ExistingResources::azure_vm()["storageProfile"]}}),
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
                disks: vec![],
                boot_disk_size_gb: Some(8),
                static_ip: None,
                static_ip_resource_group: None,
            },
        ),
        _ => unreachable!(),
    };
    state.provisioning.creations.insert(
        "instance".into(),
        Creation {
            request,
            result: Some(result),
            outcome: CreationOutcome::Succeeded,
            token: "original-request".into(),
            sent: true,
            receipt: None,
        },
    );
    state.provisioning.steps = vec![step.clone()];
    state.save(dir.path()).unwrap();
    (dir, provider, step)
}

#[tokio::test]
async fn boot_identity_survives_ip_failure_and_retry_uses_original_creation() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (dir, provider, step) = setup(platform);
        if platform == PlatformKind::Gcp {
            // Exercise a fresh GCP creation, whose response already verifies
            // the VM identity before the later CLI IP read can fail.
            let mut state = DeployState::load(dir.path(), "target", "vm").unwrap();
            let creation = state.provisioning.creations.get_mut("instance").unwrap();
            creation.result = None;
            creation.sent = false;
            creation.outcome = CreationOutcome::Unknown;
            state.save(dir.path()).unwrap();
        }
        let runner = BootRunner::new();
        runner.fail_later.store(true, Ordering::SeqCst);
        let error = provider
            .execute_step(&step, &durable(&dir, &runner), false)
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("IP lookup unavailable"),
            "{platform:?}: {error}"
        );
        let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
        let original = saved.created_boot_disk.unwrap();
        assert!(saved.cloud_instance_id.is_some());
        assert!(!saved.provisioning_complete);
        runner.fail_later.store(false, Ordering::SeqCst);
        for _ in 0..2 {
            provider
                .execute_step(&step, &durable(&dir, &runner), false)
                .await
                .unwrap();
            let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
            assert_eq!(saved.created_boot_disk.unwrap().id, original.id);
            assert_eq!(saved.provisioning.creations.len(), 1);
            assert_eq!(
                saved.provisioning.creations["instance"].token,
                "original-request"
            );
        }
        runner.replace_boot.store(true, Ordering::SeqCst);
        assert!(provider
            .execute_step(&step, &durable(&dir, &runner), false)
            .await
            .is_err());
        assert_eq!(
            DeployState::load(dir.path(), "target", "vm")
                .unwrap()
                .created_boot_disk
                .unwrap()
                .id,
            original.id
        );
    }
}

#[tokio::test]
async fn recovery_never_records_a_boot_disk_from_a_replacement_vm() {
    for platform in [PlatformKind::Gcp, PlatformKind::Azure] {
        let (dir, provider, step) = setup(platform);
        let runner = BootRunner::new();
        runner.replace_vm.store(true, Ordering::SeqCst);
        for _ in 0..2 {
            let failure = provider
                .execute_step(&step, &durable(&dir, &runner), false)
                .await
                .err()
                .unwrap();
            assert!(failure.to_string().contains("VM was replaced"));
            assert!(DeployState::load(dir.path(), "target", "vm")
                .unwrap()
                .created_boot_disk
                .is_none());
        }
        runner.replace_vm.store(false, Ordering::SeqCst);
        provider
            .execute_step(&step, &durable(&dir, &runner), false)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn failed_boot_lookup_keeps_vm_and_retry_finishes_without_recreation() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (dir, provider, step) = setup(platform);
        let runner = BootRunner::new();
        runner.fail_boot.store(true, Ordering::SeqCst);
        let error = provider
            .execute_step(&step, &durable(&dir, &runner), false)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("boot lookup unavailable"));
        let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert!(saved.cloud_instance_id.is_some());
        assert!(saved.created_boot_disk.is_none());
        assert!(!saved.provisioning_complete);
        runner.fail_boot.store(false, Ordering::SeqCst);
        provider
            .execute_step(&step, &durable(&dir, &runner), false)
            .await
            .unwrap();
        assert!(DeployState::load(dir.path(), "target", "vm")
            .unwrap()
            .created_boot_disk
            .is_some());
    }
}

#[tokio::test]
async fn rejected_boot_settings_keep_identity_without_granting_initialization() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (dir, provider, step) = setup(platform);
        let mut state = DeployState::load(dir.path(), "target", "vm").unwrap();
        state.disk_configuration.boot_size_gb = Some(64);
        state.save(dir.path()).unwrap();
        let runner = BootRunner::new();
        for _ in 0..2 {
            let error = provider
                .execute_step(&step, &durable(&dir, &runner), false)
                .await
                .err()
                .unwrap();
            assert!(
                error.to_string().contains("size differs"),
                "{platform:?}: {error}"
            );
            let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
            assert!(saved.created_boot_disk.is_some());
            assert!(!saved.provisioning_complete);
            assert!(saved.automatic_disk_setup.is_empty());
        }
    }
}

#[tokio::test]
async fn azure_data_lookup_failure_does_not_lose_the_boot_disk() {
    let (dir, provider, mut step) = setup(PlatformKind::Azure);
    let DeployStep::CreateInstanceAzure { disks, .. } = &mut step else {
        unreachable!()
    };
    disks.push(spec("StandardSSD_LRS"));
    let mut state = DeployState::load(dir.path(), "target", "vm").unwrap();
    let CreateRequest::AzureVm { body, .. } = &mut state
        .provisioning
        .creations
        .get_mut("instance")
        .unwrap()
        .request
    else {
        unreachable!()
    };
    body["properties"] = json!({"storageProfile":{"dataDisks":[{"name":"vm-data","lun":0,"createOption":"Empty","diskSizeGB":8,"managedDisk":{"storageAccountType":"StandardSSD_LRS"}}]}});
    state.provisioning.steps = vec![step.clone()];
    state.save(dir.path()).unwrap();
    let runner = BootRunner::new();
    runner.fail_data.store(true, Ordering::SeqCst);
    let failure = provider
        .execute_step(&step, &durable(&dir, &runner), false)
        .await
        .err()
        .unwrap();
    assert!(failure.to_string().contains("data disk lookup unavailable"));
    let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    let boot = saved.created_boot_disk.unwrap();
    assert!(!saved.provisioning_complete);
    assert!(saved.created_disks.is_empty());
    runner.fail_data.store(false, Ordering::SeqCst);
    for _ in 0..2 {
        provider
            .execute_step(&step, &durable(&dir, &runner), false)
            .await
            .unwrap();
        let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert_eq!(saved.created_boot_disk.unwrap().id, boot.id);
        assert!(saved.created_disks["data"].creation_verified);
    }
}

#[tokio::test]
async fn aws_original_boot_reference_is_recorded_before_waiting() {
    let (dir, provider, step) = setup(PlatformKind::Aws);
    let runner = BootRunner::new();
    runner.fail_wait.store(true, Ordering::SeqCst);
    let failure = provider
        .execute_step(&step, &durable(&dir, &runner), false)
        .await
        .err()
        .unwrap();
    assert!(failure.to_string().contains("VM wait interrupted"));
    assert_eq!(
        DeployState::load(dir.path(), "target", "vm")
            .unwrap()
            .created_boot_disk
            .unwrap()
            .id,
        "vol-boot"
    );
    runner.fail_wait.store(false, Ordering::SeqCst);
    provider
        .execute_step(&step, &durable(&dir, &runner), false)
        .await
        .unwrap();
}
