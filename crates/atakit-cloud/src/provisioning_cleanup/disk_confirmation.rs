//! Explicit cleanup approval when an older deployment lacks disk creation IDs.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedDisk {
    pub id: String,
    pub boot: bool,
}

fn simple_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
}

fn gcp_path(value: &str) -> &str {
    value
        .strip_prefix("https://www.googleapis.com/compute/v1/")
        .or_else(|| value.strip_prefix("https://compute.googleapis.com/compute/v1/"))
        .unwrap_or(value)
}

/// Only use disk references within this deployment's saved provider scope.
fn disk_name(state: &DeployState, reference: &str) -> Option<String> {
    if simple_name(reference) {
        return Some(reference.into());
    }
    let name = match state.platform {
        PlatformKind::Gcp => {
            let g = state.resources.gcp.as_ref()?;
            gcp_path(reference)
                .strip_prefix(&format!("projects/{}/zones/{}/disks/", g.project, g.zone,))?
        }
        PlatformKind::Azure => {
            let a = state.resources.azure.as_ref()?;
            let prefix = format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/disks/",
                a.subscription,
                a.resource_group.as_ref()?
            );
            if !reference.get(..prefix.len())?.eq_ignore_ascii_case(&prefix) {
                return None;
            }
            &reference[prefix.len()..]
        }
        _ => return None,
    };
    simple_name(name).then(|| name.to_owned())
}

fn deletion(state: &DeployState, name: &str) -> DestroyStep {
    DestroyStep::DeleteDisks {
        names: vec![name.into()],
        resource_group: state
            .resources
            .azure
            .as_ref()
            .and_then(|a| a.resource_group.clone()),
    }
}

fn candidates(state: &DeployState) -> BTreeMap<String, bool> {
    let saved = match state.platform {
        PlatformKind::Gcp => state.resources.gcp.as_ref().map(|r| &r.disks),
        PlatformKind::Azure => state.resources.azure.as_ref().map(|r| &r.disks),
        PlatformKind::Aws => state.resources.aws.as_ref().map(|r| &r.disks),
        PlatformKind::Qemu => return BTreeMap::new(),
    };
    let mut result: BTreeMap<_, _> = saved
        .into_iter()
        .flatten()
        .filter_map(|name| disk_name(state, name).map(|name| (name, false)))
        .collect();
    for (reference, reason) in &state.cleanup.retained_disks {
        if let Some(name) = disk_name(state, reference) {
            let boot = reason.starts_with("boot disk identity was not saved");
            result
                .entry(name)
                .and_modify(|v| *v |= boot)
                .or_insert(boot);
        }
    }
    result.retain(|name, boot| {
        !state
            .cleanup
            .completed
            .contains(&step_key(&deletion(state, name)))
            && !state.cleanup.confirmed_disks.contains_key(name)
            && !state.created_disks.values().any(|d| {
                if state.platform == PlatformKind::Aws {
                    &d.observed.id == name
                } else {
                    &d.specification.name == name
                }
            })
            && !(*boot && state.created_boot_disk.is_some())
            && !state
                .cleanup
                .boot_disk
                .as_ref()
                .is_some_and(|d| &d.specification.name == name)
    });
    result
}

async fn read_disk(
    state: &DeployState,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<Value, CloudError> {
    match state.platform {
        PlatformKind::Gcp => {
            let g = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("missing GCP state"))?;
            let out = runner
                .run_capture(
                    "gcloud",
                    &[
                        "compute",
                        "disks",
                        "describe",
                        name,
                        "--project",
                        &g.project,
                        "--zone",
                        &g.zone,
                        "--format=json",
                    ],
                )
                .await?;
            Ok(serde_json::from_str(&out.stdout)?)
        }
        PlatformKind::Aws => {
            let a = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("missing AWS state"))?;
            disk_inventory::aws_volume(&a.region, name, runner).await
        }
        PlatformKind::Azure => {
            let a = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("missing Azure state"))?;
            crate::azure::disk::show(
                &a.subscription,
                a.resource_group
                    .as_deref()
                    .ok_or_else(|| error("missing Azure group"))?,
                name,
                runner,
            )
            .await
        }
        _ => Err(error(
            "disk confirmation is only supported for cloud deployments",
        )),
    }
}

fn disk_id(state: &DeployState, disk: &Value) -> Result<String, CloudError> {
    identity(match state.platform {
        PlatformKind::Gcp => &disk["id"],
        PlatformKind::Aws => &disk["VolumeId"],
        PlatformKind::Azure => &disk.get("properties").unwrap_or(disk)["uniqueId"],
        _ => return Err(error("not a cloud disk")),
    })
}

fn attachments(state: &DeployState, disk: &Value) -> Result<Vec<String>, CloudError> {
    let strings = |value: &Value| -> Result<Vec<String>, CloudError> {
        if value.is_null() {
            return Ok(vec![]);
        }
        value
            .as_array()
            .ok_or_else(|| error("invalid disk attachment list"))?
            .iter()
            .map(identity)
            .collect()
    };
    match state.platform {
        PlatformKind::Gcp => strings(&disk["users"]),
        PlatformKind::Aws => disk["Attachments"]
            .as_array()
            .ok_or_else(|| error("missing AWS volume attachment list"))?
            .iter()
            .map(|a| identity(&a["InstanceId"]))
            .collect(),
        PlatformKind::Azure => {
            let mut users = strings(&disk["managedByExtended"])?;
            if !disk["managedBy"].is_null() {
                users.push(identity(&disk["managedBy"])?);
            }
            // A disk in an attach/detach transition is not safe to delete.
            let props = disk.get("properties").unwrap_or(disk);
            if users.is_empty() && props["diskState"] != "Unattached" {
                return Err(error("Azure disk is not confirmed unattached"));
            }
            Ok(users)
        }
        _ => Err(error("not a cloud disk")),
    }
}

async fn check_attachments(
    state: &DeployState,
    disk: &Value,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let users = attachments(state, disk)?;
    if users.is_empty() {
        return Ok(());
    }
    let expected = match state.platform {
        PlatformKind::Gcp => {
            let g = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("missing GCP state"))?;
            format!(
                "projects/{}/zones/{}/instances/{}",
                g.project,
                g.zone,
                g.instance
                    .as_deref()
                    .ok_or_else(|| error("missing VM reference"))?
            )
        }
        PlatformKind::Aws => state
            .cloud_instance_id
            .clone()
            .ok_or_else(|| error("missing VM identity"))?,
        PlatformKind::Azure => {
            let a = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("missing Azure state"))?;
            format!("/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}",
                a.subscription, a.resource_group.as_deref().ok_or_else(|| error("missing Azure group"))?,
                a.instance.as_deref().ok_or_else(|| error("missing VM reference"))?)
        }
        _ => return Err(error("not a cloud VM")),
    };
    if users.iter().any(|user| match state.platform {
        PlatformKind::Gcp => gcp_path(user) != expected,
        PlatformKind::Azure => !user.eq_ignore_ascii_case(&expected),
        _ => user != &expected,
    }) {
        return Err(error("disk is attached to another VM; retained"));
    }
    verify_vm(state, &read_vm(state, runner).await?)
}

fn clear_retained(state: &mut DeployState, name: &str) {
    let references: Vec<_> = state
        .cleanup
        .retained_disks
        .keys()
        .filter(|reference| disk_name(state, reference).as_deref() == Some(name))
        .cloned()
        .collect();
    for reference in references {
        state.cleanup.retained_disks.remove(&reference);
        state.cleanup.remaining.remove(&reference);
    }
    state
        .cleanup
        .remaining
        .remove(&deletion(state, name).to_string());
}

/// A read-only proposal. These IDs are not permission to delete anything.
#[derive(Default)]
pub struct DiskReview {
    pub pending: BTreeMap<String, ConfirmedDisk>,
    pub problems: Vec<String>,
}

pub async fn inspect_unrecorded_disks(
    state: &mut DeployState,
    preserve_disks: bool,
    runner: &dyn CommandRunner,
) -> Result<DiskReview, CloudError> {
    let mut review = DiskReview::default();
    for (name, boot) in candidates(state) {
        if preserve_disks && !boot {
            continue;
        }
        match read_disk(state, &name, runner).await {
            Err(e) if missing(&e, state.platform) => {
                completed(state, &deletion(state, &name));
                clear_retained(state, &name);
            }
            Err(e) => review
                .problems
                .push(format!("{name}: could not inspect disk: {e}")),
            Ok(disk) => match disk_id(state, &disk) {
                Ok(id) => {
                    review.pending.insert(name, ConfirmedDisk { id, boot });
                }
                Err(e) => review
                    .problems
                    .push(format!("{name}: could not inspect disk identity: {e}")),
            },
        }
    }
    Ok(review)
}

/// Recheck the exact disks shown in the prompt. Commit the whole approval batch
/// to cleanup state only after all checks succeed. Never grant creation rights.
pub async fn approve_disks(
    state: &mut DeployState,
    requested: &BTreeMap<String, ConfirmedDisk>,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let pending = candidates(state);
    let mut staged = state.clone();
    for (name, expected) in requested {
        if let Some(previous) = state.cleanup.confirmed_disks.get(name) {
            if previous.id != expected.id || previous.boot != expected.boot {
                return Err(error(format!(
                    "disk {name} already has a different approved ID; refusing replacement"
                )));
            }
            continue;
        }
        if pending.get(name) != Some(&expected.boot) {
            return Err(error(format!("disk {name} is not an unrecorded disk in this deployment; existing creation identities cannot be overridden")));
        }
        let disk = match read_disk(state, name, runner).await {
            Err(e) if missing(&e, state.platform) => {
                completed(&mut staged, &deletion(state, name));
                clear_retained(&mut staged, name);
                continue;
            }
            other => other?,
        };
        if disk_id(state, &disk)? != expected.id {
            return Err(error(format!(
                "disk {name} ID changed since the cleanup prompt; refusing replacement"
            )));
        }
        check_attachments(state, &disk, runner).await?;
        staged
            .cleanup
            .confirmed_disks
            .insert(name.clone(), expected.clone());
        clear_retained(&mut staged, name);
    }
    *state = staged;
    Ok(())
}

/// One definition for both the per-disk report and Azure's group inventory.
pub(super) fn is_workload_disk(state: &DeployState, reference: &str) -> bool {
    let Some(name) = disk_name(state, reference) else {
        return false;
    };
    if let Some(disk) = state.cleanup.confirmed_disks.get(&name) {
        return !disk.boot;
    }
    if state
        .cleanup
        .boot_disk
        .as_ref()
        .is_some_and(|d| d.specification.name == name)
    {
        return false;
    }
    if let Some((_, reason)) = state
        .cleanup
        .retained_disks
        .iter()
        .find(|(r, _)| disk_name(state, r).as_ref() == Some(&name))
    {
        return !reason.starts_with("boot disk identity was not saved");
    }
    let saved = match state.platform {
        PlatformKind::Gcp => state.resources.gcp.as_ref().map(|r| &r.disks),
        PlatformKind::Azure => state.resources.azure.as_ref().map(|r| &r.disks),
        PlatformKind::Aws => state.resources.aws.as_ref().map(|r| &r.disks),
        PlatformKind::Qemu => None,
    };
    saved.is_some_and(|disks| disks.contains(&name))
}

pub fn add_confirmed_disk_steps(
    state: &DeployState,
    steps: &mut Vec<DestroyStep>,
    preserve_disks: bool,
) {
    let mut index = steps
        .iter()
        .position(|s| matches!(s, DestroyStep::DeleteInstance { .. }))
        .map(|i| i + 1)
        .unwrap_or(0);
    for (name, disk) in &state.cleanup.confirmed_disks {
        let step = deletion(state, name);
        if (preserve_disks && !disk.boot) || steps.iter().any(|s| step_key(s) == step_key(&step)) {
            continue;
        }
        steps.insert(index, step);
        index += 1;
    }
}

pub(super) async fn verify_before_delete(
    state: &DeployState,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    let expected = state
        .cleanup
        .confirmed_disks
        .get(name)
        .ok_or_else(|| error("missing disk approval"))?;
    let disk = match read_disk(state, name, runner).await {
        Err(e) if missing(&e, state.platform) => return Ok(false),
        other => other?,
    };
    if disk_id(state, &disk)? != expected.id {
        return Err(error(format!(
            "disk {name} ID differs from saved cleanup approval; refusing replacement"
        )));
    }
    if !attachments(state, &disk)?.is_empty() {
        return Err(error(format!(
            "disk {name} is still attached to a VM; retained"
        )));
    }
    Ok(true)
}
