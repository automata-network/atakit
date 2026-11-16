use super::*;
use crate::provisioning_cleanup::{completed, report_remaining, AzureResource};
use crate::DestroyStep;

const DISK_ID: &str =
    "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/vm-data";
const FIREWALL_ID: &str =
    "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Network/networkSecurityGroups/vm-fw";

fn setup(platform: PlatformKind) -> (tempfile::TempDir, DeployState, DestroyStep, DestroyStep) {
    let (dir, mut state) = fixture(platform);
    let disks = vec!["vm-data".into(), "vm-kept".into()];
    let firewall = match platform {
        PlatformKind::Aws => {
            let r = state.resources.aws.as_mut().unwrap();
            r.disks = disks;
            r.security_group = Some("vm-fw".into());
            DestroyStep::DeleteSecurityGroup {
                name: "vm-fw".into(),
            }
        }
        PlatformKind::Gcp => {
            let r = state.resources.gcp.as_mut().unwrap();
            r.disks = disks;
            r.firewall_rule = Some("vm-fw".into());
            DestroyStep::DeleteFirewall {
                name: "vm-fw".into(),
            }
        }
        PlatformKind::Azure => {
            let r = state.resources.azure.as_mut().unwrap();
            r.disks = disks;
            r.nsg = Some("vm-fw".into());
            let resource = AzureResource {
                id: FIREWALL_ID.into(),
                api_version: "2024-05-01".into(),
                identity_field: "resourceGuid".into(),
                identity: "original".into(),
            };
            r.owned_resources
                .insert(resource.id.clone(), resource.clone());
            DestroyStep::DeleteAzureResource { resource }
        }
        _ => unreachable!(),
    };
    let disk = DestroyStep::DeleteDisks {
        names: vec!["vm-data".into()],
        resource_group: if platform == PlatformKind::Azure {
            Some("group".into())
        } else {
            None
        },
    };
    (dir, state, disk, firewall)
}

fn inventory(platform: PlatformKind, deleted: bool) -> Runner {
    Runner::new(if platform == PlatformKind::Azure {
        let mut resources = vec![json!({
            "id":"/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/disks/vm-kept",
            "name":"vm-kept"
        })];
        if !deleted {
            resources.extend([
                json!({"id":DISK_ID,"name":"vm-data"}),
                json!({"id":FIREWALL_ID,"name":"vm-fw"}),
            ]);
        }
        vec![Ok(json!(resources))]
    } else {
        vec![]
    })
}

#[tokio::test]
async fn preservation_reports_exclude_completed_deletions_and_keep_remaining_resources() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (_dir, mut state, disk, firewall) = setup(platform);
        let flags = ["disks".into(), "firewall".into()];
        report_remaining(&mut state, &flags, &inventory(platform, false))
            .await
            .unwrap();
        for key in ["disk vm-data", "disk vm-kept", "firewall vm-fw"] {
            assert!(state.cleanup.remaining[key].starts_with("preserved"));
        }
        let resources = serde_json::to_value(&state.resources).unwrap();
        completed(&mut state, &disk);
        completed(&mut state, &firewall);
        let original_completed = state.cleanup.completed.clone();
        for _ in 0..2 {
            state.cleanup.remaining.clear(); // cloud destroy refreshes each report.
            let runner = inventory(platform, true);
            report_remaining(&mut state, &flags, &runner).await.unwrap();
            assert!(!state.cleanup.remaining.contains_key("disk vm-data"));
            assert!(!state.cleanup.remaining.contains_key("firewall vm-fw"));
            assert!(state.cleanup.remaining["disk vm-kept"].starts_with("preserved"));
            assert_eq!(state.cleanup.completed, original_completed);
            assert_eq!(serde_json::to_value(&state.resources).unwrap(), resources);
            assert_eq!(
                runner.calls.lock().unwrap().len(),
                usize::from(platform == PlatformKind::Azure),
                "completed records must not add provider lookups"
            );
        }
    }
}

#[tokio::test]
async fn unrelated_completed_deletions_do_not_hide_preserved_resources() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (_dir, mut state, mut disk, mut firewall) = setup(platform);
        if let DestroyStep::DeleteDisks { names, .. } = &mut disk {
            *names = vec!["another-disk".into()];
        }
        match &mut firewall {
            DestroyStep::DeleteSecurityGroup { name } | DestroyStep::DeleteFirewall { name } => {
                *name = "another-firewall".into();
            }
            DestroyStep::DeleteAzureResource { resource } => {
                resource.id = FIREWALL_ID.replace("/group/", "/another-group/");
            }
            _ => unreachable!(),
        }
        completed(&mut state, &disk);
        completed(&mut state, &firewall);
        report_remaining(
            &mut state,
            &["disks".into(), "firewall".into()],
            &inventory(platform, false),
        )
        .await
        .unwrap();
        for key in ["disk vm-data", "disk vm-kept", "firewall vm-fw"] {
            assert!(state.cleanup.remaining[key].starts_with("preserved"));
        }
    }
}

#[tokio::test]
async fn azure_completed_deletions_are_checked_when_inventory_still_lists_resources() {
    for (disk_reply, firewall_reply, absent) in [
        (Err("Azure missing"), Err("Azure missing"), true),
        (
            Ok(json!({"id":DISK_ID})),
            Ok(json!({"id":FIREWALL_ID})),
            false,
        ),
        (
            Err("Azure stderr: ERROR: (AuthorizationFailed) access denied"),
            Err("Azure stderr: ERROR: (AuthorizationFailed) access denied"),
            false,
        ),
    ] {
        let (_dir, mut state, disk, firewall) = setup(PlatformKind::Azure);
        completed(&mut state, &disk);
        completed(&mut state, &firewall);
        state.resources.azure.as_mut().unwrap().disks = vec!["vm-data".into()];
        let runner = Runner::new(vec![
            Ok(json!([{"id":DISK_ID,"name":"vm-data"},{"id":FIREWALL_ID,"name":"vm-fw"}])),
            disk_reply,
            firewall_reply,
        ]);
        report_remaining(&mut state, &["disks".into(), "firewall".into()], &runner)
            .await
            .unwrap();
        assert!(!state.cleanup.remaining.contains_key("disk vm-data"));
        assert!(!state.cleanup.remaining.contains_key("firewall vm-fw"));
        for id in [DISK_ID, FIREWALL_ID] {
            assert_eq!(state.cleanup.remaining.contains_key(id), !absent);
            if !absent {
                assert!(!state.cleanup.remaining[id].starts_with("preserved"));
            }
        }
        assert_eq!(
            state.cleanup.remaining["resource group group"].starts_with("empty group"),
            absent
        );
        assert_eq!(runner.calls.lock().unwrap().len(), 3);
    }
}
