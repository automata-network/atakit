use super::*;
use crate::provisioning_cleanup as cleanup;
use crate::DestroyStep;

async fn prepare_disk_confirmations(
    state: &mut DeployState,
    values: &[String],
    runner: &dyn CommandRunner,
) -> Result<Vec<String>, CloudError> {
    if values.is_empty() {
        let review = cleanup::inspect_unrecorded_disks(state, false, runner).await?;
        let mut messages = review.problems;
        messages.extend(
            review
                .pending
                .iter()
                .map(|(name, disk)| format!("{name}={}", disk.id)),
        );
        return Ok(messages);
    }
    let requested = values
        .iter()
        .map(|value| {
            let (name, id) = value.split_once('=').unwrap();
            let boot = state
                .cleanup
                .retained_disks
                .get(name)
                .is_some_and(|reason| reason.starts_with("boot disk identity was not saved"));
            (
                name.to_string(),
                cleanup::ConfirmedDisk {
                    id: id.into(),
                    boot,
                },
            )
        })
        .collect();
    cleanup::approve_disks(state, &requested, runner).await?;
    Ok(vec![])
}

fn setup(platform: PlatformKind) -> (tempfile::TempDir, DeployState, String, String) {
    let (dir, mut state) = fixture(platform);
    state.provisioning = Default::default();
    state.cloud_instance_id = Some("original".into());
    let name = if platform == PlatformKind::Aws {
        "vol-data"
    } else {
        "vm-data"
    }
    .to_string();
    let id = if platform == PlatformKind::Aws {
        "vol-data"
    } else {
        "123"
    }
    .to_string();
    match platform {
        PlatformKind::Gcp => {
            let r = state.resources.gcp.as_mut().unwrap();
            r.instance = Some("vm".into());
            r.disks = vec![name.clone()];
        }
        PlatformKind::Aws => {
            let r = state.resources.aws.as_mut().unwrap();
            r.instance = Some("original".into());
            r.disks = vec![name.clone()];
        }
        PlatformKind::Azure => {
            let r = state.resources.azure.as_mut().unwrap();
            r.instance = Some("vm".into());
            r.disks = vec![name.clone()];
        }
        _ => unreachable!(),
    }
    (dir, state, name, id)
}

fn disk(platform: PlatformKind, id: &str, owner: Option<&str>) -> Value {
    match platform {
        PlatformKind::Gcp => json!({"id":id,"users":owner.into_iter().collect::<Vec<_>>()}),
        PlatformKind::Aws => {
            json!({"Volumes":[{"VolumeId":id,"Attachments":owner.into_iter().map(|owner| json!({"InstanceId":owner})).collect::<Vec<_>>()}]})
        }
        PlatformKind::Azure => {
            json!({"uniqueId":id,"diskState":if owner.is_some(){"Attached"}else{"Unattached"},"managedBy":owner})
        }
        _ => unreachable!(),
    }
}

fn step(state: &DeployState, name: &str) -> DestroyStep {
    DestroyStep::DeleteDisks {
        names: vec![name.into()],
        resource_group: state
            .resources
            .azure
            .as_ref()
            .and_then(|r| r.resource_group.clone()),
    }
}

#[tokio::test]
async fn confirmation_is_cleanup_only_persists_and_rejects_changed_ids() {
    for platform in [PlatformKind::Gcp, PlatformKind::Aws, PlatformKind::Azure] {
        let (dir, mut state, name, id) = setup(platform);
        state.cleanup.retained_disks.insert(
            name.clone(),
            "attached disk has no creation record; retained".into(),
        );
        let runner = Runner::new(vec![Ok(disk(platform, &id, None))]);
        let guidance = prepare_disk_confirmations(&mut state, &[], &runner)
            .await
            .unwrap();
        assert!(guidance[0].contains(&format!("{name}={id}")));
        assert!(state.cleanup.confirmed_disks.is_empty());
        prepare_disk_confirmations(
            &mut state,
            &[format!("{name}={id}")],
            &Runner::new(vec![Ok(disk(platform, &id, None))]),
        )
        .await
        .unwrap();
        state.save(dir.path()).unwrap();
        let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert_eq!(saved.cleanup.confirmed_disks[&name].id, id);
        assert!(saved.cleanup.retained_disks.is_empty());
        assert!(saved.created_disks.is_empty());
        assert!(saved.created_boot_disk.is_none());
        assert!(saved.provisioning.creations.is_empty());
        assert!(cleanup::before_step(
            &saved,
            &step(&saved, &name),
            false,
            &Runner::new(vec![Ok(disk(platform, &id, None))])
        )
        .await
        .unwrap());
        assert!(cleanup::before_step(
            &saved,
            &step(&saved, &name),
            false,
            &Runner::new(vec![Ok(disk(platform, "replacement", None))])
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("refusing replacement"));
        assert!(prepare_disk_confirmations(
            &mut state,
            &[format!("{name}=replacement")],
            &Runner::new(vec![])
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("different approved ID"));
    }
}

#[tokio::test]
async fn confirmations_reject_stale_ids_foreign_attachments_and_changed_vms() {
    for platform in [PlatformKind::Gcp, PlatformKind::Aws, PlatformKind::Azure] {
        let (_, original, name, id) = setup(platform);
        let own = match platform {
            PlatformKind::Gcp => "https://www.googleapis.com/compute/v1/projects/project/zones/zone/instances/vm",
            PlatformKind::Aws => "original",
            _ => "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/vm",
        };
        for (observed_id, owner, vm) in [
            ("replacement", None, None),
            (id.as_str(), Some("foreign"), None),
            (id.as_str(), Some(own), Some("replacement")),
        ] {
            let mut state = original.clone();
            let mut replies = vec![Ok(disk(platform, observed_id, owner))];
            if let Some(vm) = vm {
                replies.push(Ok(match platform {
                    PlatformKind::Gcp => json!({"id":vm}),
                    PlatformKind::Aws => {
                        json!({"Reservations":[{"Instances":[{"InstanceId":vm}]}]})
                    }
                    _ => json!({"vmId":vm}),
                }));
            }
            let runner = Runner::new(replies);
            assert!(
                prepare_disk_confirmations(&mut state, &[format!("{name}={id}")], &runner)
                    .await
                    .is_err()
            );
            assert!(state.cleanup.confirmed_disks.is_empty());
            assert!(runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| !call.iter().any(|a| a == "delete")));
        }
    }
}

#[tokio::test]
async fn confirmation_allows_only_original_vm_and_requires_detachment_before_deletion() {
    let (_, mut state, name, id) = setup(PlatformKind::Gcp);
    let attached = disk(
        PlatformKind::Gcp,
        &id,
        Some("projects/project/zones/zone/instances/vm"),
    );
    prepare_disk_confirmations(
        &mut state,
        &[format!("{name}={id}")],
        &Runner::new(vec![Ok(attached.clone()), Ok(json!({"id":"original"}))]),
    )
    .await
    .unwrap();
    assert!(cleanup::before_step(
        &state,
        &step(&state, &name),
        false,
        &Runner::new(vec![Ok(attached)])
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("still attached"));
}

#[tokio::test]
async fn confirmation_is_scoped_and_cannot_override_creation_records() {
    let (_, mut state, name, id) = setup(PlatformKind::Gcp);
    assert!(
        prepare_disk_confirmations(&mut state, &["unknown=123".into()], &Runner::new(vec![]))
            .await
            .is_err()
    );
    state.cleanup.retained_disks.insert(
        "projects/foreign/zones/zone/disks/foreign".into(),
        "attached disk has no creation record".into(),
    );
    assert!(
        prepare_disk_confirmations(&mut state, &["foreign=123".into()], &Runner::new(vec![]))
            .await
            .is_err()
    );
    state.created_disks.insert(
        name.clone(),
        crate::disk_inventory::CreatedDisk {
            specification: crate::DiskSpec {
                name: name.clone(),
                device_name: "data".into(),
                index: 0,
                size_gb: 8,
                disk_type: "pd-balanced".into(),
                performance: None,
            },
            observed: crate::disk_inventory::ObservedDisk {
                id,
                disk_type: "pd-balanced".into(),
                size_gb: 8,
                iops: None,
                throughput_mibps: None,
            },
            creation_verified: true,
        },
    );
    assert!(prepare_disk_confirmations(
        &mut state,
        &[format!("{name}=replacement")],
        &Runner::new(vec![])
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("cannot be overridden"));
}

#[tokio::test]
async fn confirmation_batch_is_atomic_and_boot_cleanup_respects_data_preservation() {
    let (_, mut state, name, id) = setup(PlatformKind::Gcp);
    state.cleanup.retained_disks.insert(
        "vm".into(),
        "boot disk identity was not saved; retained".into(),
    );
    let values = ["vm=456".into(), format!("{name}={id}")];
    assert!(prepare_disk_confirmations(
        &mut state,
        &values,
        &Runner::new(vec![
            Ok(disk(PlatformKind::Gcp, "456", None)),
            Ok(disk(PlatformKind::Gcp, "replacement", None))
        ])
    )
    .await
    .is_err());
    assert!(state.cleanup.confirmed_disks.is_empty());
    prepare_disk_confirmations(
        &mut state,
        &values,
        &Runner::new(vec![
            Ok(disk(PlatformKind::Gcp, "456", None)),
            Ok(disk(PlatformKind::Gcp, &id, None)),
        ]),
    )
    .await
    .unwrap();
    let mut steps = vec![DestroyStep::DeleteInstance { name: "vm".into() }];
    cleanup::add_confirmed_disk_steps(&state, &mut steps, true);
    assert_eq!(steps.len(), 2);
    assert_eq!(
        cleanup::step_key(&steps[1]),
        cleanup::step_key(&step(&state, "vm"))
    );
    cleanup::report_remaining(&mut state, &["disks".into()], &Runner::new(vec![]))
        .await
        .unwrap();
    assert!(state.cleanup.remaining["disk vm-data"].starts_with("preserved"));
}

#[tokio::test]
async fn missing_disks_finish_without_name_based_deletion_and_read_errors_do_not_approve() {
    let (_, mut state, name, id) = setup(PlatformKind::Gcp);
    let runner = Runner::new(vec![Err("GCP missing")]);
    assert!(prepare_disk_confirmations(&mut state, &[], &runner)
        .await
        .unwrap()
        .is_empty());
    assert!(state
        .cleanup
        .completed
        .contains(&cleanup::step_key(&step(&state, &name))));
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
    state.cleanup.completed.clear();
    let guidance = prepare_disk_confirmations(
        &mut state,
        &[],
        &Runner::new(vec![Err("permission denied")]),
    )
    .await
    .unwrap();
    assert!(guidance[0].contains("permission denied"));
    assert!(state.cleanup.confirmed_disks.is_empty());
    prepare_disk_confirmations(
        &mut state,
        &[format!("{name}={id}")],
        &Runner::new(vec![Ok(disk(PlatformKind::Gcp, &id, None))]),
    )
    .await
    .unwrap();
    assert!(!cleanup::before_step(
        &state,
        &step(&state, &name),
        false,
        &Runner::new(vec![Err("GCP missing")])
    )
    .await
    .unwrap());
}

#[tokio::test]
async fn azure_confirmed_attachment_is_reported_as_preserved() {
    let (_, mut state, name, id) = setup(PlatformKind::Azure);
    state.resources.azure.as_mut().unwrap().disks.clear();
    let reference =
        "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/vm-data";
    state.cleanup.retained_disks.insert(
        reference.into(),
        "attached disk has no creation record; retained".into(),
    );
    prepare_disk_confirmations(
        &mut state,
        &[format!("{name}={id}")],
        &Runner::new(vec![Ok(disk(PlatformKind::Azure, &id, None))]),
    )
    .await
    .unwrap();
    cleanup::report_remaining(
        &mut state,
        &["disks".into()],
        &Runner::new(vec![Ok(
            json!([{"id":reference,"name":name,"type":"Microsoft.Compute/disks"}]),
        )]),
    )
    .await
    .unwrap();
    assert!(
        state.cleanup.remaining[reference].starts_with("preserved"),
        "{:?}",
        state.cleanup.remaining
    );
}
