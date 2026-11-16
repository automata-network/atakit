use super::*;

#[tokio::test]
async fn aws_io2_creation_sends_iops_without_gp3_throughput() {
    let (dir, _) = fixture(PlatformKind::Aws);
    let mut volume = volume("vol-io2");
    volume["VolumeType"] = "io2".into();
    volume["Iops"] = 6000.into();
    let runner = Runner::new(vec![Ok(volume.clone()), Ok(json!({"Volumes":[volume]}))]);
    let mut disk = spec("io2");
    disk.performance = Some(crate::disk_profiles::DiskPerformance {
        disk_type: "io2".into(),
        iops: Some(6000),
        ..Default::default()
    });
    crate::aws::disk::create("region", "zone", &disk, &durable(&dir, &runner))
        .await
        .unwrap();
    let calls = runner.calls.lock().unwrap();
    assert!(calls[0].windows(2).any(|w| w == ["--volume-type", "io2"]));
    assert!(calls[0].windows(2).any(|w| w == ["--iops", "6000"]));
    assert!(!calls[0].contains(&"--throughput".into()));
}

fn fast_spec() -> crate::DiskSpec {
    let mut spec = spec("PremiumV2_LRS");
    spec.performance = Some(crate::disk_profiles::DiskPerformance {
        profile: Some("fast".into()),
        disk_type: spec.disk_type.clone(),
        iops: Some(4000),
        throughput_mibps: Some(250),
    });
    spec
}

fn disk(iops: u64, mbps: u64) -> Value {
    let mut value = azure_disk("disk-original");
    value["sku"]["name"] = "PremiumV2_LRS".into();
    value["managedBy"] = azure_vm_result()["id"].clone();
    value["properties"]["diskIOPSReadWrite"] = iops.into();
    value["properties"]["diskMBpsReadWrite"] = mbps.into();
    value["properties"]["provisioningState"] = "Succeeded".into();
    value
}

fn vm() -> Value {
    json!({"vmId":"vm-unique", "storageProfile":{"dataDisks":[{
        "name":"vm-data", "lun":0, "createOption":"Empty", "managedDisk":{"id":azure_disk("disk-original")["id"]}
    }]}})
}

async fn created_vm(dir: &tempfile::TempDir) {
    let mut request = vm_request();
    if let CreateRequest::AzureVm { body, .. } = &mut request {
        body["properties"]["storageProfile"]["dataDisks"][0]["managedDisk"]["storageAccountType"] =
            "PremiumV2_LRS".into();
    }
    let runner = Runner::new(vec![Ok(azure_vm_result()), Ok(azure_vm_result())]);
    durable(dir, &runner)
        .create_resource("instance", &request)
        .await
        .unwrap();
}

#[tokio::test]
async fn azure_tunes_only_new_owned_disks_and_never_retunes_verified_disks() {
    let (dir, _) = fixture(PlatformKind::Azure);
    created_vm(&dir).await;
    let runner = Runner::new(vec![
        Ok(vm()),
        Ok(disk(3000, 125)),
        Ok(json!({})),
        Ok(disk(4000, 263)),
    ]);
    crate::azure::disk::record_vm_created_disk(
        "sub",
        "group",
        "vm",
        &fast_spec(),
        &durable(&dir, &runner),
    )
    .await
    .unwrap();
    {
        let calls = runner.calls.lock().unwrap();
        assert_eq!(&calls[2][..2], &["azure-api", "PATCH"]);
        assert_eq!(
            serde_json::from_str::<Value>(&calls[2][4]).unwrap(),
            json!({"properties":{"diskIOPSReadWrite":4000,"diskMBpsReadWrite":263}})
        );
    }
    assert!(
        DeployState::load(dir.path(), "target", "vm")
            .unwrap()
            .created_disks["data"]
            .creation_verified
    );
    for (actual, success) in [(disk(4000, 263), true), (disk(3000, 125), false)] {
        let runner = Runner::new(vec![Ok(vm()), Ok(actual)]);
        assert_eq!(
            crate::azure::disk::record_vm_created_disk(
                "sub",
                "group",
                "vm",
                &fast_spec(),
                &durable(&dir, &runner)
            )
            .await
            .is_ok(),
            success
        );
        assert_eq!(runner.calls.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn azure_lost_performance_reply_recovers_by_reading_without_repeating_patch() {
    let (dir, _) = fixture(PlatformKind::Azure);
    created_vm(&dir).await;
    let runner = Runner::new(vec![Ok(vm()), Ok(disk(3000, 125)), Err("lost response")]);
    assert!(crate::azure::disk::record_vm_created_disk(
        "sub",
        "group",
        "vm",
        &fast_spec(),
        &durable(&dir, &runner)
    )
    .await
    .is_err());
    assert!(
        !DeployState::load(dir.path(), "target", "vm")
            .unwrap()
            .created_disks["data"]
            .creation_verified
    );
    let runner = Runner::new(vec![Ok(vm()), Ok(disk(4000, 263))]);
    crate::azure::disk::record_vm_created_disk(
        "sub",
        "group",
        "vm",
        &fast_spec(),
        &durable(&dir, &runner),
    )
    .await
    .unwrap();
    assert_eq!(runner.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn azure_refuses_to_tune_changed_identity_size_type_or_attachment() {
    for change in ["identity", "size", "type", "attachment", "source", "owner"] {
        let (dir, _) = fixture(PlatformKind::Azure);
        created_vm(&dir).await;
        let runner = Runner::new(vec![Ok(vm()), Ok(disk(3000, 125)), Err("lost response")]);
        assert!(crate::azure::disk::record_vm_created_disk(
            "sub",
            "group",
            "vm",
            &fast_spec(),
            &durable(&dir, &runner)
        )
        .await
        .is_err());
        let mut vm = vm();
        let mut value = disk(3000, 125);
        match change {
            "identity" => value["properties"]["uniqueId"] = "replacement".into(),
            "size" => value["properties"]["diskSizeGB"] = 16.into(),
            "type" => value["sku"]["name"] = "StandardSSD_LRS".into(),
            "attachment" => vm["storageProfile"]["dataDisks"][0]["createOption"] = "Attach".into(),
            "source" => value["properties"]["creationData"]["createOption"] = "Copy".into(),
            "owner" => value["managedBy"] = "other-vm".into(),
            _ => unreachable!(),
        }
        let runner = Runner::new(vec![Ok(vm), Ok(value)]);
        assert!(
            crate::azure::disk::record_vm_created_disk(
                "sub",
                "group",
                "vm",
                &fast_spec(),
                &durable(&dir, &runner)
            )
            .await
            .is_err(),
            "{change}"
        );
        assert!(runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| call[0] != "azure-api"));
    }
}

#[tokio::test]
async fn azure_disk_transport_rejects_creation_and_nonperformance_updates() {
    let runner = Runner::new(vec![]);
    let url = "https://management.azure.com/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/data?api-version=2024-03-02";
    for (method, body) in [
        ("PUT", json!({"properties":{}})),
        ("PATCH", json!({"properties":{"diskSizeGB":40}})),
        ("PATCH", json!({"properties":{"diskIOPSReadWrite":0}})),
    ] {
        assert!(
            super::super::azure_api(&runner, method, url, Some(&body), false)
                .await
                .is_err()
        );
    }
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn azure_pending_update_must_finish_even_when_target_values_are_visible() {
    let (dir, _) = fixture(PlatformKind::Azure);
    created_vm(&dir).await;
    let mut pending = disk(4000, 263);
    pending["properties"]["provisioningState"] = "Updating".into();
    let runner = Runner::new(vec![Ok(vm()), Ok(pending), Err("still unavailable")]);
    assert!(crate::azure::disk::record_vm_created_disk(
        "sub",
        "group",
        "vm",
        &fast_spec(),
        &durable(&dir, &runner)
    )
    .await
    .is_err());
    assert!(
        !DeployState::load(dir.path(), "target", "vm")
            .unwrap()
            .created_disks["data"]
            .creation_verified
    );
    assert!(runner
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|call| call[0] != "azure-api"));
}

#[tokio::test]
async fn azure_local_disks_require_original_vm_size_identity_and_managed_os() {
    let (dir, mut state) = fixture(PlatformKind::Azure);
    let mut request = vm_request();
    let properties = json!({"vmId":"vm-unique", "provisioningState":"Succeeded", "hardwareProfile":{"vmSize":"Standard_DC32eds_v6"},
        "securityProfile":{"securityType":"ConfidentialVM"}, "storageProfile":{"osDisk":{"createOption":"FromImage"}}});
    if let CreateRequest::AzureVm { body, .. } = &mut request {
        body["properties"] = properties.clone();
    }
    let mut original = azure_vm_result();
    original["properties"] = properties.clone();
    let runner = Runner::new(vec![Ok(original.clone()), Ok(original)]);
    durable(&dir, &runner)
        .create_resource("instance", &request)
        .await
        .unwrap();
    state.provisioning = DeployState::load(dir.path(), "target", "vm")
        .unwrap()
        .provisioning;
    state.cloud_instance_id = Some("vm-unique".into());
    state.resources.azure.as_mut().unwrap().instance = Some("vm".into());
    state.resources.azure.as_mut().unwrap().resource_group = Some("group".into());
    state.disk_configuration.vmtype = "Standard_DC32eds_v6".into();
    state.disk_configuration.disks.insert(
        "data".into(),
        crate::disk_profiles::DiskPerformance {
            disk_type: "local-ssd".into(),
            ..Default::default()
        },
    );
    crate::disk_inventory::verify_local_ssd(&state, &Runner::new(vec![Ok(properties.clone())]))
        .await
        .unwrap();
    for change in ["identity", "size", "security", "os"] {
        let mut current = properties.clone();
        match change {
            "identity" => current["vmId"] = "replacement".into(),
            "size" => current["hardwareProfile"]["vmSize"] = "Standard_DC32es_v6".into(),
            "security" => current["securityProfile"]["securityType"] = "TrustedLaunch".into(),
            "os" => {
                current["storageProfile"]["osDisk"]["diffDiskSettings"]["option"] = "Local".into()
            }
            _ => unreachable!(),
        }
        assert!(
            crate::disk_inventory::verify_local_ssd(&state, &Runner::new(vec![Ok(current)]))
                .await
                .is_err(),
            "{change}"
        );
    }
}

fn azure_inventory_fixture() -> (DeployState, Value, Value, Value) {
    let (_, mut state) = fixture(PlatformKind::Azure);
    state.cloud_instance_id = Some("vm-unique".into());
    let resources = state.resources.azure.as_mut().unwrap();
    resources.instance = Some("vm".into());
    resources.resource_group = Some("group".into());
    let mut boot = azure_disk("boot-original");
    boot["id"] =
        "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/boot".into();
    let data = disk(4000, 263);
    let mut vm = vm();
    vm["storageProfile"]["osDisk"] = json!({"managedDisk":{"id":boot["id"]}});
    vm["hardwareProfile"] = json!({"vmSize":"Standard_DC4eds_v6"});
    state.created_boot_disk = Some(crate::disk_inventory::azure_observation(&boot).unwrap());
    state.created_disks.insert(
        "data".into(),
        crate::disk_inventory::CreatedDisk {
            creation_verified: true,
            specification: fast_spec(),
            observed: crate::disk_inventory::azure_observation(&data).unwrap(),
        },
    );
    (state, vm, boot, data)
}

#[tokio::test]
async fn azure_initialization_disk_checks_do_not_need_the_vm_catalog() {
    for change in ["none", "boot", "data", "performance"] {
        let (state, vm, mut boot, mut data) = azure_inventory_fixture();
        match change {
            "boot" => boot["properties"]["uniqueId"] = "replaced".into(),
            "data" => data["properties"]["uniqueId"] = "replaced".into(),
            "performance" => data["properties"]["diskIOPSReadWrite"] = 3000.into(),
            _ => {}
        }
        let runner = Runner::new(vec![
            Ok(json!("vm-unique")),
            Ok(vm.clone()),
            Ok(boot),
            Ok(vm),
            Ok(data),
        ]);
        assert_eq!(
            crate::disk_inventory::verify_configuration(&state, &runner)
                .await
                .is_ok(),
            change == "none",
            "{change}"
        );
        assert!(runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| !call.iter().any(|arg| arg == "list-skus")));
    }
}

#[tokio::test]
async fn slow_azure_catalog_does_not_hide_verified_disk_status() {
    struct SlowCatalog(Runner);
    #[async_trait::async_trait]
    impl CommandRunner for SlowCatalog {
        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            if args.contains(&"list-skus") {
                return std::future::pending().await;
            }
            self.0.run_capture(program, args).await
        }
        async fn run_stream(
            &self,
            _: &str,
            _: &[&str],
            _: bool,
        ) -> Result<CommandOutput, CloudError> {
            panic!("disk status must not write")
        }
    }
    let (state, vm, boot, data) = azure_inventory_fixture();
    let runner = SlowCatalog(Runner::new(vec![
        Ok(json!("vm-unique")),
        Ok(vm.clone()),
        Ok(boot),
        Ok(vm.clone()),
        Ok(data),
        Ok(vm),
    ]));
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(6),
        crate::disk_inventory::status(&state, &runner),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(status["boot"]["id"], "boot-original");
    assert_eq!(status["disks"]["data"]["id"], "disk-original");
    assert_eq!(status["shared_vm_limits"]["status"], "not checked");
}
