//! Cleanup uses saved creation identities, including disks left unattached.
use crate::{
    disk_inventory,
    provisioning::{error, identity},
    CloudError, CommandRunner, DeployState, DeployStep, DestroyStep, PlatformKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

mod disk_confirmation;
pub use disk_confirmation::{
    add_confirmed_disk_steps, approve_disks, inspect_unrecorded_disks, ConfirmedDisk,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cleanup {
    pub started: bool,
    pub completed: BTreeSet<String>,
    pub remaining: BTreeMap<String, String>,
    pub vm_power: Option<String>,
    #[serde(default)]
    pub boot_disk: Option<disk_inventory::CreatedDisk>,
    #[serde(default)]
    pub resolved_creations: BTreeSet<String>,
    #[serde(default)]
    pub retained_disks: BTreeMap<String, String>,
    #[serde(default)]
    pub image_removal: Option<crate::image_removal::ImageRemoval>,
    /// Operator approval for cleanup, never evidence of fresh creation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub confirmed_disks: BTreeMap<String, ConfirmedDisk>,
}

/// Reuse the image-removal journal: deregistration can succeed even when a
/// backing snapshot cannot be removed. Save those IDs before deregistration.
pub async fn delete_aws_image(
    state: &mut DeployState,
    data_dir: &std::path::Path,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let _image_lock =
        crate::cloud_images::CloudImages::lock(data_dir, &state.image_ref, &state.provider_name)?;
    let aws = state
        .resources
        .aws
        .as_ref()
        .ok_or_else(|| error("missing AWS state"))?;
    let mut images = crate::cloud_images::CloudImages::load(data_dir)?;
    let tracked = images.get(&state.image_ref, &state.provider_name).cloned();
    let mut record = tracked.clone().unwrap_or(crate::cloud_images::CloudImage {
        platform: PlatformKind::Aws,
        cloud_name: name.into(),
        bucket: aws.bucket.clone(),
        gallery_rg: None,
        gallery: None,
        image_version: None,
        cc_types: vec![],
        uploaded_at: state.created_at,
        removal: None,
    });
    if record.cloud_name != name {
        return Err(error(
            "saved image name differs from the deployment image; retained",
        ));
    }
    record.removal = state.cleanup.image_removal.clone().or(record.removal);
    let config = crate::CloudProviderConfig {
        platform: PlatformKind::Aws,
        region: aws.region.clone(),
        project: None,
        subscription: None,
        uefi: None,
    };
    let plan = crate::image_removal::prepare(&record, &config, runner).await?;
    state.cleanup.image_removal = Some(plan.clone());
    state.save(data_dir)?;
    if tracked.is_some() {
        record.removal = Some(plan.clone());
        images.record(&state.image_ref, &state.provider_name, record);
        images.save(data_dir)?;
    }
    plan.execute(runner).await
}

pub fn has_unresolved(state: &DeployState) -> bool {
    state
        .provisioning
        .creations
        .iter()
        .any(|(key, c)| c.unresolved() && !state.cleanup.resolved_creations.contains(key))
}

pub fn completed(state: &mut DeployState, step: &DestroyStep) {
    state.cleanup.completed.insert(step_key(step));
    if matches!(step, DestroyStep::DeleteInstance { .. }) {
        state.cleanup.vm_power = Some("deleted".into());
        if state.cloud_instance_id.is_some() {
            state.cleanup.resolved_creations.insert("instance".into());
        }
    }
}

/// Resource names can be reused. Keep the provider's incarnation identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureResource {
    pub id: String,
    pub api_version: String,
    pub identity_field: String,
    pub identity: String,
}

pub fn step_key(step: &DestroyStep) -> String {
    serde_json::to_string(step).expect("destroy steps contain only serializable fields")
}

/// A batch must not let one failed disk skip all the remaining disks.
pub fn separate_steps(steps: Vec<DestroyStep>) -> Vec<DestroyStep> {
    steps
        .into_iter()
        .flat_map(|step| match step {
            DestroyStep::DeleteDisks {
                names,
                resource_group,
            } => names
                .into_iter()
                .map(|name| DestroyStep::DeleteDisks {
                    names: vec![name],
                    resource_group: resource_group.clone(),
                })
                .collect(),
            other => vec![other],
        })
        .collect()
}

/// Read provider receipts without resubmitting a create. Each request is
/// independent: an unknown disk must not prevent cleanup of a known VM.
pub async fn reconcile_records(
    data_dir: &std::path::Path,
    state: &mut DeployState,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    for (key, creation) in state.provisioning.creations.clone() {
        if !creation.unresolved() || state.cleanup.resolved_creations.contains(&key) {
            continue;
        }
        let durable = crate::resume::DeploymentRunner {
            runner,
            data_dir,
            target: &state.target_name,
            instance: &state.instance_name,
        };
        let result = crate::provisioning::reconcile(&durable, &key, &creation).await;
        *state = DeployState::load(data_dir, &state.target_name, &state.instance_name)?;
        match result {
            Ok(value) => {
                let record = state
                    .provisioning
                    .creations
                    .get_mut(&key)
                    .ok_or_else(|| error("creation record disappeared"))?;
                record.result = Some(value);
                record.outcome = crate::provisioning::CreationOutcome::Succeeded;
            }
            Err(e) => {
                if matches!(e, CloudError::CreationFailed { .. }) {
                    state
                        .provisioning
                        .creations
                        .get_mut(&key)
                        .ok_or_else(|| error("creation record disappeared"))?
                        .outcome = crate::provisioning::CreationOutcome::Failed;
                } else {
                    state
                        .cleanup
                        .remaining
                        .insert(format!("creation {key}"), e.to_string());
                }
            }
        }
        state.save(data_dir)?;
    }
    recover_records(state)?;
    if let Err(e) = recover_gcp_boot_disk(state, runner).await {
        state
            .cleanup
            .remaining
            .insert("boot disk recovery".into(), e.to_string());
    }
    state.save(data_dir)
}

/// Report observed group contents, including resources that Atakit cannot prove
/// it owns. A read failure is an incomplete inventory, never an empty group.
pub async fn report_remaining(
    state: &mut DeployState,
    preserve: &[String],
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    for (key, creation) in &state.provisioning.creations {
        if creation.unresolved() && !state.cleanup.resolved_creations.contains(key) {
            state
                .cleanup
                .remaining
                .entry(format!("creation {key}"))
                .or_insert_with(|| {
                    "creation outcome is unknown; resources may exist and incur charges".into()
                });
        } else {
            state.cleanup.remaining.remove(&format!("creation {key}"));
        }
    }
    for (name, reason) in state.cleanup.retained_disks.clone() {
        let result = match state.platform {
            PlatformKind::Aws => {
                let a = state
                    .resources
                    .aws
                    .as_ref()
                    .ok_or_else(|| error("missing AWS state"))?;
                disk_inventory::aws_volume(&a.region, &name, runner)
                    .await
                    .map(|_| ())
            }
            PlatformKind::Gcp => {
                let g = state
                    .resources
                    .gcp
                    .as_ref()
                    .ok_or_else(|| error("missing GCP state"))?;
                runner
                    .run_capture(
                        "gcloud",
                        &[
                            "compute",
                            "disks",
                            "describe",
                            &name,
                            "--project",
                            &g.project,
                            "--zone",
                            &g.zone,
                            "--format=json",
                        ],
                    )
                    .await
                    .map(|_| ())
            }
            // Azure resource list below provides a fresh inventory of the whole group.
            PlatformKind::Azure | PlatformKind::Qemu => continue,
        };
        match result {
            Err(e) if missing(&e, state.platform) => {
                state.cleanup.retained_disks.remove(&name);
            }
            Err(e) => {
                state
                    .cleanup
                    .remaining
                    .insert(name, format!("{reason}; could not verify existence: {e}"));
            }
            Ok(()) => {
                let reason = if preserve.iter().any(|p| p == "disks")
                    && disk_confirmation::is_workload_disk(state, &name)
                {
                    "preserved by --preserve disks; storage charges may continue".into()
                } else {
                    reason
                };
                state.cleanup.remaining.insert(name, reason);
            }
        }
    }
    for step in &state.provisioning.steps {
        let reserved = match step {
            DeployStep::CreateInstance { static_ip, .. }
            | DeployStep::CreateInstanceAws { static_ip, .. } => static_ip.clone(),
            DeployStep::CreateInstanceAzure {
                static_ip,
                static_ip_resource_group,
                ..
            } => static_ip.as_ref().map(|ip| {
                format!(
                    "{}/{ip}",
                    static_ip_resource_group
                        .as_deref()
                        .unwrap_or("unknown group")
                )
            }),
            _ => None,
        };
        if let Some(ip) = reserved {
            state.cleanup.remaining.insert(
                format!("reserved IP {ip}"),
                "preserved operator-supplied IP address; address charges may continue".into(),
            );
        }
    }
    let disks = match state.platform {
        PlatformKind::Aws => state.resources.aws.as_ref().map(|r| &r.disks),
        PlatformKind::Gcp => state.resources.gcp.as_ref().map(|r| &r.disks),
        PlatformKind::Azure => state.resources.azure.as_ref().map(|r| &r.disks),
        PlatformKind::Qemu => None,
    };
    if preserve.iter().any(|p| p == "disks") {
        for disk in disks.into_iter().flatten().chain(
            state
                .cleanup
                .confirmed_disks
                .iter()
                .filter(|(_, d)| !d.boot)
                .map(|(name, _)| name),
        ) {
            let deletion = DestroyStep::DeleteDisks {
                names: vec![disk.clone()],
                resource_group: state
                    .resources
                    .azure
                    .as_ref()
                    .and_then(|a| a.resource_group.clone()),
            };
            // Cleanup records each disk separately. A new preserve flag cannot
            // keep a disk whose deletion completed on an earlier attempt.
            if state.cleanup.completed.contains(&step_key(&deletion)) {
                state.cleanup.remaining.remove(&format!("disk {disk}"));
                continue;
            }
            state.cleanup.remaining.insert(
                format!("disk {disk}"),
                "preserved by --preserve disks; storage charges may continue".into(),
            );
        }
    }
    if preserve.iter().any(|p| p == "firewall") {
        let name = match state.platform {
            PlatformKind::Aws => state
                .resources
                .aws
                .as_ref()
                .and_then(|r| r.security_group.as_ref()),
            PlatformKind::Gcp => state
                .resources
                .gcp
                .as_ref()
                .and_then(|r| r.firewall_rule.as_ref()),
            PlatformKind::Azure => state.resources.azure.as_ref().and_then(|r| r.nsg.as_ref()),
            PlatformKind::Qemu => None,
        };
        if let Some(name) = name {
            if firewall_deletion_completed(state, name) {
                state.cleanup.remaining.remove(&format!("firewall {name}"));
            } else {
                state.cleanup.remaining.insert(
                    format!("firewall {name}"),
                    "preserved by --preserve firewall".into(),
                );
            }
        }
    }
    if let Some(a) = &state.resources.azure {
        if let Some(group) = &a.resource_group {
            let out = runner
                .run_capture(
                    "az",
                    &[
                        "resource",
                        "list",
                        "--subscription",
                        &a.subscription,
                        "--resource-group",
                        group,
                        "--output",
                        "json",
                    ],
                )
                .await?;
            let resources: Value = serde_json::from_str(&out.stdout)?;
            let resources = resources
                .as_array()
                .ok_or_else(|| error("invalid Azure resource inventory"))?;
            let mut present = 0;
            for resource in resources {
                let id = identity(&resource["id"])?;
                // Azure can briefly list a disk after its DELETE has
                // completed. Confirm each reported deleted resource directly.
                let deletion_completed = azure_resource_deletion_completed(&state.cleanup, &id);
                if deletion_completed {
                    match runner
                        .run_capture(
                            "az",
                            &["resource", "show", "--ids", &id, "--output", "json"],
                        )
                        .await
                    {
                        Err(e) if missing(&e, PlatformKind::Azure) => continue,
                        Err(e) => {
                            state.cleanup.remaining.insert(
                                id.clone(),
                                format!("listed after deletion; could not verify absence: {e}"),
                            );
                        }
                        Ok(_) => {}
                    }
                }
                present += 1;
                let name = resource["name"].as_str().unwrap_or("");
                let kept = !deletion_completed
                    && ((preserve.iter().any(|p| p == "disks")
                        && disk_confirmation::is_workload_disk(state, &id))
                        || (preserve.iter().any(|p| p == "firewall")
                            && a.nsg.as_deref() == Some(name)));
                state.cleanup.remaining.entry(id).or_insert_with(|| if kept {
                    "preserved by --preserve; charges may continue".into()
                } else { "still present; retained because deletion was not verified or ownership is unknown; charges may continue".into() });
            }
            state.cleanup.remaining.insert(
                format!("resource group {group}"),
                if present == 0 {
                    "empty group retained; Atakit does not cascade-delete resource groups".into()
                } else {
                    "group retained with the resources listed above".into()
                },
            );
        }
    }
    Ok(())
}

fn firewall_deletion_completed(state: &DeployState, name: &str) -> bool {
    let step = match state.platform {
        PlatformKind::Aws => DestroyStep::DeleteSecurityGroup { name: name.into() },
        PlatformKind::Gcp => DestroyStep::DeleteFirewall { name: name.into() },
        PlatformKind::Azure => {
            return state.resources.azure.as_ref().is_some_and(|a| {
                a.resource_group.as_ref().is_some_and(|group| {
                    let id = format!("/subscriptions/{}/resourceGroups/{group}/providers/Microsoft.Network/networkSecurityGroups/{name}", a.subscription);
                    azure_resource_deletion_completed(&state.cleanup, &id)
                })
            });
        }
        PlatformKind::Qemu => return false,
    };
    state.cleanup.completed.contains(&step_key(&step))
}

fn azure_resource_deletion_completed(cleanup: &Cleanup, id: &str) -> bool {
    let id_lower = id.to_ascii_lowercase();
    cleanup
        .completed
        .iter()
        .filter_map(|s| serde_json::from_str::<DestroyStep>(s).ok())
        .any(|step| match step {
            DestroyStep::DeleteInstance { name } => id_lower.ends_with(&format!(
                "/microsoft.compute/virtualmachines/{}",
                name.to_ascii_lowercase()
            )),
            DestroyStep::DeleteDisks { names, .. } => names.iter().any(|name| {
                id_lower.ends_with(&format!(
                    "/microsoft.compute/disks/{}",
                    name.to_ascii_lowercase()
                ))
            }),
            DestroyStep::DeleteAzureResource { resource } => resource.id.eq_ignore_ascii_case(id),
            _ => false,
        })
}

/// Record attachments before deleting the VM, since its attachment list then
/// disappears. Never turn an unverified attachment into an owned disk.
/// Return true only after reading and checking the attachment list. An absent
/// VM cannot resolve an earlier failed inventory.
pub async fn record_attachments(
    state: &mut DeployState,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    if state.cloud_instance_id.is_none() {
        return Ok(false);
    }
    let name = match state.platform {
        PlatformKind::Aws => state
            .resources
            .aws
            .as_ref()
            .and_then(|r| r.instance.as_ref()),
        PlatformKind::Gcp => state
            .resources
            .gcp
            .as_ref()
            .and_then(|r| r.instance.as_ref()),
        PlatformKind::Azure => state
            .resources
            .azure
            .as_ref()
            .and_then(|r| r.instance.as_ref()),
        PlatformKind::Qemu => None,
    };
    let Some(name) = name else { return Ok(false) };
    if state
        .cleanup
        .completed
        .contains(&step_key(&DestroyStep::DeleteInstance {
            name: name.clone(),
        }))
    {
        return Ok(false);
    }
    let vm = match read_vm(state, runner).await {
        Err(e) if missing(&e, state.platform) => return Ok(false),
        other => other?,
    };
    verify_vm(state, &vm)?;
    let mut boot_name = None;
    match state.platform {
        PlatformKind::Aws => {
            for disk in vm["BlockDeviceMappings"]
                .as_array()
                .ok_or_else(|| error("missing AWS disk list"))?
            {
                let id = identity(&disk["Ebs"]["VolumeId"])?;
                if disk["DeviceName"] == vm["RootDeviceName"] {
                    boot_name = Some(id);
                } else if !state.created_disks.values().any(|d| d.observed.id == id)
                    && !state.cleanup.confirmed_disks.contains_key(&id)
                {
                    state.cleanup.retained_disks.insert(id, "attached disk has no creation record; retained; storage charges may continue".into());
                }
            }
        }
        PlatformKind::Gcp => {
            for disk in vm["disks"]
                .as_array()
                .ok_or_else(|| error("missing GCP disk list"))?
            {
                if disk["type"] == "SCRATCH" {
                    continue;
                }
                let source = identity(&disk["source"])?;
                let name = source
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| error("invalid disk source"))?
                    .to_owned();
                if disk["boot"] == true {
                    boot_name = Some(name);
                } else if !state
                    .created_disks
                    .values()
                    .any(|d| d.specification.name == name)
                    && !state.cleanup.confirmed_disks.contains_key(&name)
                {
                    state.cleanup.retained_disks.insert(source, "attached disk has no creation record; retained; storage charges may continue".into());
                }
            }
        }
        PlatformKind::Azure => {
            let profile = &vm["storageProfile"];
            boot_name = profile["osDisk"]["name"].as_str().map(str::to_owned);
            for disk in profile["dataDisks"]
                .as_array()
                .ok_or_else(|| error("missing Azure disk list"))?
            {
                let id = identity(&disk["managedDisk"]["id"])?;
                if !state
                    .created_disks
                    .values()
                    .any(|d| disk["name"] == d.specification.name)
                    && !state
                        .cleanup
                        .confirmed_disks
                        .contains_key(disk["name"].as_str().unwrap_or(""))
                {
                    state
                        .cleanup
                        .retained_disks
                        .insert(id, "attached disk has no creation record; retained".into());
                }
            }
        }
        _ => {}
    }
    if let Some(name) = boot_name {
        if let Some(observed) = &state.created_boot_disk {
            state.cleanup.boot_disk = Some(disk_inventory::CreatedDisk {
                specification: crate::DiskSpec {
                    name,
                    device_name: "boot disk".into(),
                    index: 0,
                    size_gb: observed.size_gb,
                    disk_type: observed.disk_type.clone(),
                    performance: None,
                },
                observed: observed.clone(),
                creation_verified: false,
            });
        } else if !state
            .cleanup
            .confirmed_disks
            .get(&name)
            .is_some_and(|d| d.boot)
        {
            state.cleanup.retained_disks.insert(
                name,
                "boot disk identity was not saved; retained; storage charges may continue".into(),
            );
        }
    }
    Ok(true)
}

/// Check the saved GCP creation response before using its boot disk reference.
fn gcp_created_vm(state: &DeployState) -> Result<&Value, CloudError> {
    let gcp = state
        .resources
        .gcp
        .as_ref()
        .ok_or_else(|| error("missing GCP state"))?;
    let creation = state
        .provisioning
        .creations
        .get("instance")
        .ok_or_else(|| {
            error(format!(
                "boot disk {} has no saved VM creation response; retained",
                state
                    .created_boot_disk
                    .as_ref()
                    .map(|d| d.id.as_str())
                    .unwrap_or(&state.instance_name)
            ))
        })?;
    let crate::provisioning::CreateRequest::Gcp {
        project,
        zone,
        collection,
        ..
    } = &creation.request
    else {
        return Err(error(
            "boot disk has an invalid GCP VM creation record; retained",
        ));
    };
    if project != &gcp.project || zone != &gcp.zone || collection != "instances" || !creation.sent {
        return Err(error(
            "boot disk VM creation record does not match the deployment; retained",
        ));
    }
    let vm = creation.result.as_ref().ok_or_else(|| {
        error(format!(
            "boot disk {} has no saved VM creation response; retained",
            state
                .created_boot_disk
                .as_ref()
                .map(|d| d.id.as_str())
                .unwrap_or(&state.instance_name)
        ))
    })?;
    if state.cloud_instance_id.as_deref() != Some(identity(&vm["id"])?.as_str()) {
        return Err(error(
            "boot disk VM creation identity does not match the deployment; retained",
        ));
    }
    disk_inventory::gcp_boot_name(vm, &gcp.project, &gcp.zone)?;
    Ok(vm)
}

/// Creation can finish before its boot-disk callback runs. Recover the disk
/// through the saved VM creation response, including after the VM was deleted.
/// Reuse created_boot_disk and the existing reconciliation save.
async fn recover_gcp_boot_disk(
    state: &mut DeployState,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    if state.platform != PlatformKind::Gcp || state.created_boot_disk.is_some() {
        return Ok(());
    }
    if !state
        .provisioning
        .creations
        .get("instance")
        .is_some_and(|c| c.result.is_some())
    {
        return Ok(());
    }
    let vm = gcp_created_vm(state)?;
    let gcp = state
        .resources
        .gcp
        .as_ref()
        .ok_or_else(|| error("missing GCP state"))?;
    let name = disk_inventory::gcp_boot_name(vm, &gcp.project, &gcp.zone)?;
    match disk_inventory::gcp_boot_from_vm(&gcp.project, &gcp.zone, vm, runner).await {
        Ok(disk) => state.created_boot_disk = Some(disk),
        Err(e) if missing(&e, PlatformKind::Gcp) => {}
        Err(e) => return Err(e),
    }
    state.cleanup.retained_disks.remove(&name);
    state.cleanup.remaining.remove(&name);
    state.cleanup.remaining.remove("boot disk recovery");
    Ok(())
}

/// Derive the cleanup target from existing records, even when the VM is absent.
fn boot_disk_for_cleanup(
    state: &DeployState,
) -> Result<Option<disk_inventory::CreatedDisk>, CloudError> {
    if let Some(disk) = &state.cleanup.boot_disk {
        if state
            .created_boot_disk
            .as_ref()
            .is_some_and(|observed| observed.id != disk.observed.id)
        {
            return Err(error(
                "boot disk cleanup identity conflicts with the saved disk identity",
            ));
        }
        return Ok(Some(disk.clone()));
    }
    let Some(observed) = &state.created_boot_disk else {
        return Ok(None);
    };
    let name = match state.platform {
        PlatformKind::Aws => observed.id.clone(),
        PlatformKind::Gcp => {
            let vm = gcp_created_vm(state)?;
            let gcp = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("missing GCP state"))?;
            disk_inventory::gcp_boot_name(vm, &gcp.project, &gcp.zone)?
        }
        // Azure's group inventory reports disks that cannot be resolved from
        // an existing attachment record. QEMU uses its own cleanup path.
        _ => return Ok(None),
    };
    Ok(Some(disk_inventory::CreatedDisk {
        specification: crate::DiskSpec {
            name,
            device_name: "boot disk".into(),
            index: 0,
            size_gb: observed.size_gb,
            disk_type: observed.disk_type.clone(),
            performance: None,
        },
        observed: observed.clone(),
        creation_verified: false,
    }))
}

pub fn add_boot_disk_step(
    state: &DeployState,
    steps: &mut Vec<DestroyStep>,
) -> Result<(), CloudError> {
    if let Some(disk) = boot_disk_for_cleanup(state)? {
        let step = DestroyStep::DeleteDisks {
            names: vec![disk.specification.name.clone()],
            resource_group: state
                .resources
                .azure
                .as_ref()
                .and_then(|a| a.resource_group.clone()),
        };
        // The root disk is disposable, even when workload data disks are preserved.
        let index = steps
            .iter()
            .position(|s| matches!(s, DestroyStep::DeleteInstance { .. }))
            .map(|i| i + 1)
            .unwrap_or(0);
        steps.insert(index, step);
    }
    Ok(())
}

/// A result may have been saved immediately before a process interruption,
/// before the normal resource callbacks ran. Recover those references locally.
pub fn recover_records(state: &mut DeployState) -> Result<(), CloudError> {
    for (key, creation) in state.provisioning.creations.clone() {
        let mut recovered = state.clone();
        recovered.provisioning.creations = BTreeMap::from([(key.clone(), creation)]);
        match recover_record_results(&mut recovered) {
            Ok(()) => {
                state.resources = recovered.resources;
                state.cloud_instance_id = recovered.cloud_instance_id;
                state.created_disks = recovered.created_disks;
            }
            Err(e) => {
                state
                    .cleanup
                    .remaining
                    .insert(format!("invalid creation record {key}"), e.to_string());
            }
        }
    }
    Ok(())
}

fn recover_record_results(state: &mut DeployState) -> Result<(), CloudError> {
    for (key, creation) in state.provisioning.creations.clone() {
        if !creation.sent {
            continue;
        }
        let value = creation.result.or({
            if matches!(
                creation.request,
                crate::provisioning::CreateRequest::AzureVm { .. }
                    | crate::provisioning::CreateRequest::AzureNetwork { .. }
            ) {
                creation.receipt
            } else {
                None
            }
        });
        let Some(value) = value else { continue };
        if let crate::provisioning::CreateRequest::AzureNetwork {
            id, api_version, ..
        } = &creation.request
        {
            let record = crate::provisioning::azure_network_record(id, api_version, &value)?;
            let azure = state
                .resources
                .azure
                .as_mut()
                .ok_or_else(|| error("missing Azure state"))?;
            if azure
                .owned_resources
                .get(id)
                .is_some_and(|old| old.identity != record.identity)
            {
                return Err(error(
                    "creation result conflicts with saved Azure network identity",
                ));
            }
            azure.owned_resources.insert(id.clone(), record);
        } else if key == "instance" {
            let current = match state.platform {
                PlatformKind::Aws => identity(&value["Instances"][0]["InstanceId"])?,
                PlatformKind::Gcp => identity(&value["id"])?,
                PlatformKind::Azure => identity(&value["properties"]["vmId"])?,
                PlatformKind::Qemu => continue,
            };
            if state
                .cloud_instance_id
                .as_ref()
                .is_some_and(|old| old != &current)
            {
                return Err(error("creation result conflicts with saved VM identity"));
            }
            match state.platform {
                PlatformKind::Aws => {
                    let id = identity(&value["Instances"][0]["InstanceId"])?;
                    state
                        .resources
                        .aws
                        .as_mut()
                        .ok_or_else(|| error("missing AWS state"))?
                        .instance = Some(id.clone());
                    state.cloud_instance_id = Some(id);
                }
                PlatformKind::Gcp => {
                    state.cloud_instance_id = Some(identity(&value["id"])?);
                    state
                        .resources
                        .gcp
                        .as_mut()
                        .ok_or_else(|| error("missing GCP state"))?
                        .instance = Some(identity(&value["name"])?);
                }
                PlatformKind::Azure => {
                    state.cloud_instance_id = Some(identity(&value["properties"]["vmId"])?);
                    state
                        .resources
                        .azure
                        .as_mut()
                        .ok_or_else(|| error("missing Azure state"))?
                        .instance = Some(identity(&value["name"])?);
                }
                _ => {}
            }
        } else if let Some(logical) = key.strip_prefix("disk:") {
            let spec = state
                .provisioning
                .steps
                .iter()
                .flat_map(|step| match step {
                    DeployStep::CreateDisks { disks, .. }
                    | DeployStep::CreateInstanceAws { disks, .. }
                    | DeployStep::CreateInstanceAzure { disks, .. }
                    | DeployStep::CreateInstance { disks, .. } => disks.as_slice(),
                    _ => &[],
                })
                .find(|d| d.device_name == logical)
                .ok_or_else(|| error("missing saved disk specification"))?
                .clone();
            let observed = match state.platform {
                PlatformKind::Aws => disk_inventory::aws_observation(&value)?,
                PlatformKind::Gcp => disk_inventory::gcp_observation(&value)?,
                PlatformKind::Azure => disk_inventory::azure_observation(&value)?,
                _ => continue,
            };
            if state
                .created_disks
                .get(logical)
                .is_some_and(|d| d.observed.id != observed.id)
            {
                return Err(error("creation result conflicts with saved disk identity"));
            }
            let names = match state.platform {
                PlatformKind::Aws => {
                    &mut state
                        .resources
                        .aws
                        .as_mut()
                        .ok_or_else(|| error("missing AWS state"))?
                        .disks
                }
                PlatformKind::Gcp => {
                    &mut state
                        .resources
                        .gcp
                        .as_mut()
                        .ok_or_else(|| error("missing GCP state"))?
                        .disks
                }
                PlatformKind::Azure => {
                    &mut state
                        .resources
                        .azure
                        .as_mut()
                        .ok_or_else(|| error("missing Azure state"))?
                        .disks
                }
                _ => unreachable!(),
            };
            let name = if state.platform == PlatformKind::Aws {
                &observed.id
            } else {
                &spec.name
            };
            if !names.contains(name) {
                names.push(name.clone());
            }
            state
                .created_disks
                .entry(logical.into())
                .or_insert(disk_inventory::CreatedDisk {
                    specification: spec,
                    observed,
                    creation_verified: false,
                });
        }
    }
    Ok(())
}

pub fn missing(e: &CloudError, platform: PlatformKind) -> bool {
    let CloudError::CommandFailed { stderr, .. } = e else {
        return false;
    };
    match platform {
        PlatformKind::Aws => {
            stderr.contains("InvalidInstanceID.NotFound")
                || stderr.contains("InvalidVolume.NotFound")
        }
        PlatformKind::Gcp => stderr.contains("was not found"),
        PlatformKind::Azure => {
            // Azure disk reads can return NotFound after a successful delete
            // while resource-list still includes the disk. Match the error
            // code, not words in an authorization or transport error message.
            let code = stderr
                .lines()
                .find_map(|line| {
                    line.trim()
                        .strip_prefix("ERROR: (")?
                        .split_once(')')
                        .map(|(code, _)| code)
                })
                .or_else(|| {
                    stderr
                        .lines()
                        .find_map(|line| line.trim().strip_prefix("Code: ").map(str::trim))
                })
                .unwrap_or_else(|| stderr.trim());
            matches!(
                code,
                "NotFound" | "ResourceNotFound" | "ResourceGroupNotFound"
            )
        }
        _ => false,
    }
}

/// Run immediately before a destructive step. Missing resources are already
/// cleaned up; replacement resources and foreign attachments are never deleted.
/// Returns false when the resource is absent, so callers must skip deletion.
pub async fn before_step(
    state: &DeployState,
    step: &DestroyStep,
    _preserve_disks: bool,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    if let DestroyStep::DeleteResourceGroup { .. } = step {
        return Err(error("resource-group deletion can delete unrecorded resources; delete owned resources individually"));
    }
    if let DestroyStep::DeleteDisks { names, .. } = step {
        if names.len() != 1 {
            return Err(error("disk cleanup requires one disk per step"));
        }
        let mut present = false;
        for name in names {
            let matches_name = |disk: &disk_inventory::CreatedDisk| {
                if state.platform == PlatformKind::Aws {
                    &disk.observed.id == name
                } else {
                    &disk.specification.name == name
                }
            };
            let mut disk = state
                .created_disks
                .values()
                .find(|disk| matches_name(disk))
                .cloned();
            if disk.is_none() {
                disk = boot_disk_for_cleanup(state)?.filter(matches_name);
            }
            if disk.is_none() && state.cleanup.confirmed_disks.contains_key(name) {
                present |= disk_confirmation::verify_before_delete(state, name, runner).await?;
                continue;
            }
            let disk = disk.ok_or_else(|| {
                error(format!(
                    "disk {name} has no saved creation identity; retained"
                ))
            })?;
            let result = match state.platform {
                PlatformKind::Aws => {
                    let aws = state
                        .resources
                        .aws
                        .as_ref()
                        .ok_or_else(|| error("missing AWS state"))?;
                    disk_inventory::aws_volume(&aws.region, &disk.observed.id, runner)
                        .await
                        .and_then(|v| disk_inventory::aws_observation(&v))
                }
                PlatformKind::Gcp => {
                    let g = state
                        .resources
                        .gcp
                        .as_ref()
                        .ok_or_else(|| error("missing GCP state"))?;
                    runner
                        .run_capture(
                            "gcloud",
                            &[
                                "compute",
                                "disks",
                                "describe",
                                &disk.specification.name,
                                "--project",
                                &g.project,
                                "--zone",
                                &g.zone,
                                "--format=json",
                            ],
                        )
                        .await
                        .and_then(|o| Ok(serde_json::from_str::<Value>(&o.stdout)?))
                        .and_then(|v| disk_inventory::gcp_observation(&v))
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
                        &disk.specification.name,
                        runner,
                    )
                    .await
                    .and_then(|v| disk_inventory::azure_observation(&v))
                }
                _ => continue,
            };
            match result {
                Ok(actual) if actual.id == disk.observed.id => present = true,
                Err(e) if missing(&e, state.platform) => {}
                Err(e) => return Err(e),
                _ => return Err(error("refusing cleanup: a disk was replaced")),
            }
        }
        return Ok(present);
    }
    if let DestroyStep::DeleteInstance { name } = step {
        if let Some(reason) = state.cleanup.remaining.get("VM attachment inventory") {
            return Err(error(format!(
                "cannot delete VM before its attached disks are recorded: {reason}"
            )));
        }
        if state.cloud_instance_id.is_none() {
            return Err(error(
                "VM has no saved creation identity; refusing deletion",
            ));
        }
        if state.platform == PlatformKind::Aws {
            let a = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("missing AWS state"))?;
            let vm = match disk_inventory::aws_instance(&a.region, name, runner).await {
                Err(e) if missing(&e, state.platform) => return Ok(false),
                other => other?,
            };
            if vm["InstanceId"].as_str() != state.cloud_instance_id.as_deref() {
                return Err(error(
                    "AWS VM identity differs from the saved creation result",
                ));
            }
            let mappings = vm["BlockDeviceMappings"]
                .as_array()
                .ok_or_else(|| error("missing AWS disk list"))?;
            let mut updates = Vec::new();
            for m in mappings {
                let id = identity(&m["Ebs"]["VolumeId"])?;
                if m["Ebs"]["DeleteOnTermination"] != false {
                    updates.push(json!({"DeviceName":m["DeviceName"],"Ebs":{"VolumeId":id,"DeleteOnTermination":false}}));
                }
            }
            if !updates.is_empty() {
                runner
                    .run_capture(
                        "aws",
                        &[
                            "ec2",
                            "modify-instance-attribute",
                            "--region",
                            &a.region,
                            "--instance-id",
                            name,
                            "--block-device-mappings",
                            &serde_json::to_string(&updates)?,
                        ],
                    )
                    .await?;
                let current = disk_inventory::aws_instance(&a.region, name, runner).await?;
                if !current["BlockDeviceMappings"]
                    .as_array()
                    .is_some_and(|mappings| {
                        mappings
                            .iter()
                            .all(|m| m["Ebs"]["DeleteOnTermination"] == false)
                    })
                {
                    return Err(error(
                        "AWS still has an automatically deleted disk; refusing termination",
                    ));
                }
                for update in updates {
                    if !current["BlockDeviceMappings"].as_array().is_some_and(|m| {
                        m.iter().any(|v| {
                            v["DeviceName"] == update["DeviceName"]
                                && v["Ebs"]["VolumeId"] == update["Ebs"]["VolumeId"]
                                && v["Ebs"]["DeleteOnTermination"] == false
                        })
                    }) {
                        return Err(error(
                            "AWS did not confirm disk preservation; refusing termination",
                        ));
                    }
                }
            }
        } else {
            let vm = match read_vm(state, runner).await {
                Err(e) if missing(&e, state.platform) => return Ok(false),
                other => other?,
            };
            verify_vm(state, &vm)?;
            prevent_cascade(state, &vm, runner).await?;
        }
    }
    Ok(true)
}

async fn read_vm(state: &DeployState, runner: &dyn CommandRunner) -> Result<Value, CloudError> {
    let out = match state.platform {
        PlatformKind::Aws => {
            let a = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("missing AWS state"))?;
            return disk_inventory::aws_instance(
                &a.region,
                a.instance
                    .as_deref()
                    .ok_or_else(|| error("missing VM ID"))?,
                runner,
            )
            .await;
        }
        PlatformKind::Gcp => {
            let g = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("missing GCP state"))?;
            runner
                .run_capture(
                    "gcloud",
                    &[
                        "compute",
                        "instances",
                        "describe",
                        g.instance
                            .as_deref()
                            .ok_or_else(|| error("missing VM name"))?,
                        "--project",
                        &g.project,
                        "--zone",
                        &g.zone,
                        "--format=json",
                    ],
                )
                .await?
        }
        PlatformKind::Azure => {
            let a = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("missing Azure state"))?;
            runner
                .run_capture(
                    "az",
                    &[
                        "vm",
                        "show",
                        "--subscription",
                        &a.subscription,
                        "--resource-group",
                        a.resource_group
                            .as_deref()
                            .ok_or_else(|| error("missing Azure group"))?,
                        "--name",
                        a.instance
                            .as_deref()
                            .ok_or_else(|| error("missing VM name"))?,
                        "--output",
                        "json",
                    ],
                )
                .await?
        }
        PlatformKind::Qemu => return Err(error("not a cloud VM")),
    };
    Ok(serde_json::from_str(&out.stdout)?)
}

fn verify_vm(state: &DeployState, vm: &Value) -> Result<(), CloudError> {
    let value = match state.platform {
        PlatformKind::Aws => &vm["InstanceId"],
        PlatformKind::Gcp => &vm["id"],
        PlatformKind::Azure => &vm["vmId"],
        PlatformKind::Qemu => return Err(error("not a cloud VM")),
    };
    if Some(identity(value)?).as_ref() != state.cloud_instance_id.as_ref() {
        return Err(error("VM identity differs from the saved creation result; no deletion or power change is safe"));
    }
    Ok(())
}

async fn prevent_cascade(
    state: &DeployState,
    vm: &Value,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    // Preserve Persistent Disks individually: --keep-disks=all also attempts
    // to retain Local SSD, which GCP rejects. Local SSD must leave with its VM.
    if state.platform == PlatformKind::Gcp {
        let g = state
            .resources
            .gcp
            .as_ref()
            .ok_or_else(|| error("missing GCP state"))?;
        let name = g
            .instance
            .as_deref()
            .ok_or_else(|| error("missing VM name"))?;
        let disks = vm["disks"]
            .as_array()
            .ok_or_else(|| error("missing GCP disk list"))?;
        let mut changed = false;
        for disk in disks {
            match disk["type"].as_str() {
                Some("SCRATCH") => continue,
                Some("PERSISTENT") => {}
                _ => return Err(error("unknown GCP disk type; refusing VM deletion")),
            }
            if disk["autoDelete"] != false {
                let device = identity(&disk["deviceName"])?;
                runner
                    .run_capture(
                        "gcloud",
                        &[
                            "compute",
                            "instances",
                            "set-disk-auto-delete",
                            name,
                            "--project",
                            &g.project,
                            "--zone",
                            &g.zone,
                            "--device-name",
                            &device,
                            "--no-auto-delete",
                            "--quiet",
                        ],
                    )
                    .await?;
                changed = true;
            }
        }
        if changed {
            let current = read_vm(state, runner).await?;
            verify_vm(state, &current)?;
            let current_disks = current["disks"]
                .as_array()
                .ok_or_else(|| error("missing GCP disk list after update"))?;
            if !current_disks.iter().all(|disk| {
                disk["type"] == "SCRATCH"
                    || (disk["type"] == "PERSISTENT" && disk["autoDelete"] == false)
            }) || !disks
                .iter()
                .filter(|disk| disk["type"] == "PERSISTENT")
                .all(|old| {
                    current_disks.iter().any(|new| {
                        new["type"] == "PERSISTENT"
                            && new["source"] == old["source"]
                            && new["deviceName"] == old["deviceName"]
                            && new["autoDelete"] == false
                    })
                })
            {
                return Err(error(
                    "GCP did not confirm Persistent Disk preservation; refusing VM deletion",
                ));
            }
        }
        if disks.iter().any(|disk| disk["type"] == "SCRATCH") {
            tracing::warn!("GCP Local SSD contents will be discarded with the VM; --preserve disks only retains Persistent Disks");
        }
        return Ok(());
    }
    // Set and verify Detach on Azure disks and NICs.
    if state.platform != PlatformKind::Azure {
        return Ok(());
    }
    let a = state
        .resources
        .azure
        .as_ref()
        .ok_or_else(|| error("missing Azure state"))?;
    let group = a
        .resource_group
        .as_deref()
        .ok_or_else(|| error("missing Azure group"))?;
    let name = a
        .instance
        .as_deref()
        .ok_or_else(|| error("missing VM name"))?;
    let profile = vm
        .get("storageProfile")
        .ok_or_else(|| error("missing Azure storage profile"))?;
    let data = profile["dataDisks"]
        .as_array()
        .ok_or_else(|| error("missing Azure data disk list"))?;
    let nics = vm["networkProfile"]["networkInterfaces"]
        .as_array()
        .ok_or_else(|| error("missing Azure NIC list"))?;
    let mut settings = vec![];
    if profile["osDisk"]["deleteOption"] != "Detach" {
        settings.push("storageProfile.osDisk.deleteOption=Detach".to_string());
    }
    for (index, disk) in data.iter().enumerate() {
        if disk["deleteOption"] != "Detach" {
            settings.push(format!(
                "storageProfile.dataDisks[{index}].deleteOption=Detach"
            ));
        }
    }
    for (index, nic) in nics.iter().enumerate() {
        if nic["deleteOption"] != "Detach" && nic["properties"]["deleteOption"] != "Detach" {
            settings.push(format!(
                "networkProfile.networkInterfaces[{index}].deleteOption=Detach"
            ));
        }
    }
    if settings.is_empty() {
        return Ok(());
    }
    let mut args = vec![
        "vm",
        "update",
        "--subscription",
        &a.subscription,
        "--resource-group",
        group,
        "--name",
        name,
        "--set",
    ];
    args.extend(settings.iter().map(String::as_str));
    runner.run_capture("az", &args).await?;
    let current = read_vm(state, runner).await?;
    verify_vm(state, &current)?;
    let current_data = current["storageProfile"]["dataDisks"]
        .as_array()
        .ok_or_else(|| error("missing Azure data disk list after update"))?;
    let current_nics = current["networkProfile"]["networkInterfaces"]
        .as_array()
        .ok_or_else(|| error("missing Azure NIC list after update"))?;
    if current["storageProfile"]["osDisk"]["deleteOption"] != "Detach"
        || current["storageProfile"]["osDisk"]["managedDisk"]["id"]
            != profile["osDisk"]["managedDisk"]["id"]
        || current_data.len() != data.len()
        || current_nics.len() != nics.len()
        || !current_data.iter().zip(data).all(|(new, old)| {
            new["deleteOption"] == "Detach"
                && new["lun"] == old["lun"]
                && new["managedDisk"]["id"] == old["managedDisk"]["id"]
        })
        || !current_nics.iter().zip(nics).all(|(new, old)| {
            new["id"] == old["id"]
                && (new["deleteOption"] == "Detach"
                    || new["properties"]["deleteOption"] == "Detach")
        })
    {
        return Err(error(
            "Azure did not confirm attachment preservation; refusing VM deletion",
        ));
    }
    Ok(())
}

async fn verify_azure_resource(
    resource: &AzureResource,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let out = runner
        .run_capture(
            "az",
            &[
                "resource",
                "show",
                "--ids",
                &resource.id,
                "--api-version",
                &resource.api_version,
                "--output",
                "json",
            ],
        )
        .await?;
    let value: Value = serde_json::from_str(&out.stdout)?;
    if identity(&value["properties"][&resource.identity_field])? != resource.identity {
        return Err(error(format!(
            "Azure resource {} was replaced; retained",
            resource.id
        )));
    }
    Ok(())
}

pub async fn delete_azure_resource(
    resource: &AzureResource,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match verify_azure_resource(resource, runner).await {
        Err(e) if missing(&e, PlatformKind::Azure) => return Ok(()),
        other => other?,
    }
    runner
        .run_capture(
            "az",
            &[
                "resource",
                "delete",
                "--ids",
                &resource.id,
                "--api-version",
                &resource.api_version,
            ],
        )
        .await?;
    // A successful request can still be asynchronous. Do not discard its state
    // until a read confirms that the resource no longer exists.
    match verify_azure_resource(resource, runner).await {
        Err(e) if missing(&e, PlatformKind::Azure) => Ok(()),
        Err(e) => Err(e),
        Ok(()) => Err(error(format!(
            "Azure deletion of {} is still pending; retry cloud destroy",
            resource.id
        ))),
    }
}

/// Try to stop ordinary compute charges when safe VM deletion failed. A power
/// change always needs a matching immutable identity and a checked final state.
pub async fn stop_verified_vm(
    state: &DeployState,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let vm = match read_vm(state, runner).await {
        Err(e) if missing(&e, state.platform) => return Ok("absent".into()),
        other => other?,
    };
    verify_vm(state, &vm)?;
    match state.platform {
        PlatformKind::Aws => {
            let a = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("missing AWS state"))?;
            let id = a
                .instance
                .as_deref()
                .ok_or_else(|| error("missing VM ID"))?;
            if vm["State"]["Name"] == "terminated" {
                return Ok("terminated".into());
            }
            if vm["State"]["Name"] != "stopped" {
                runner
                    .run_capture(
                        "aws",
                        &[
                            "ec2",
                            "stop-instances",
                            "--region",
                            &a.region,
                            "--instance-ids",
                            id,
                        ],
                    )
                    .await?;
                runner
                    .run_capture(
                        "aws",
                        &[
                            "ec2",
                            "wait",
                            "instance-stopped",
                            "--region",
                            &a.region,
                            "--instance-ids",
                            id,
                        ],
                    )
                    .await?;
            }
            let current = read_vm(state, runner).await?;
            verify_vm(state, &current)?;
            if current["State"]["Name"] != "stopped" {
                return Err(error(format!(
                    "AWS VM power state: {}",
                    current["State"]["Name"]
                )));
            }
            Ok("stopped".into())
        }
        PlatformKind::Gcp => {
            let g = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("missing GCP state"))?;
            if vm["status"] != "TERMINATED" {
                let mut args = vec![
                    "compute",
                    "instances",
                    "stop",
                    g.instance
                        .as_deref()
                        .ok_or_else(|| error("missing VM name"))?,
                    "--project",
                    &g.project,
                    "--zone",
                    &g.zone,
                    "--quiet",
                ];
                if vm["disks"]
                    .as_array()
                    .is_some_and(|disks| disks.iter().any(|disk| disk["type"] == "SCRATCH"))
                {
                    tracing::warn!("Discarding GCP Local SSD contents while stopping the VM after failed cleanup");
                    args.push("--discard-local-ssd=true");
                }
                runner.run_capture("gcloud", &args).await?;
            }
            let current = read_vm(state, runner).await?;
            verify_vm(state, &current)?;
            if current["status"] != "TERMINATED" {
                return Err(error(format!("GCP VM power state: {}", current["status"])));
            }
            Ok("TERMINATED (stopped)".into())
        }
        PlatformKind::Azure => {
            let a = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("missing Azure state"))?;
            let name = a
                .instance
                .as_deref()
                .ok_or_else(|| error("missing VM name"))?;
            let group = a
                .resource_group
                .as_deref()
                .ok_or_else(|| error("missing Azure group"))?;
            runner
                .run_capture(
                    "az",
                    &[
                        "vm",
                        "deallocate",
                        "--subscription",
                        &a.subscription,
                        "--resource-group",
                        group,
                        "--name",
                        name,
                    ],
                )
                .await?;
            verify_vm(state, &read_vm(state, runner).await?)?;
            let out = runner
                .run_capture(
                    "az",
                    &[
                        "vm",
                        "get-instance-view",
                        "--subscription",
                        &a.subscription,
                        "--resource-group",
                        group,
                        "--name",
                        name,
                        "--output",
                        "json",
                    ],
                )
                .await?;
            let view: Value = serde_json::from_str(&out.stdout)?;
            let statuses = view
                .pointer("/instanceView/statuses")
                .or_else(|| view.get("statuses"));
            let power = statuses
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|s| s["code"].as_str())
                .find(|s| s.starts_with("PowerState/"))
                .unwrap_or("unknown");
            if power != "PowerState/deallocated" {
                return Err(error(format!("Azure VM power state: {power}")));
            }
            Ok("deallocated".into())
        }
        PlatformKind::Qemu => Err(error("not a cloud VM")),
    }
}
