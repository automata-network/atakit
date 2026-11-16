use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::DiskSpec;

/// Standalone Azure disk PUT updates existing disks and ignores If-None-Match.
/// New disks must be created by the create-only VM request.
pub async fn create_disk(
    _subscription: &str,
    _rg: &str,
    _region: &str,
    _spec: &DiskSpec,
    _runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    Err(CloudError::CreationRejected {
        message: "standalone Azure disk creation is unsafe; create data disks with the VM".into(),
    })
}

pub async fn record_vm_created_disk(
    subscription: &str,
    group: &str,
    vm_name: &str,
    spec: &DiskSpec,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    use crate::provisioning::{error, identity, CreateRequest};
    let saved = runner
        .recorded_creation("instance")
        .await?
        .ok_or_else(|| error("Azure VM creation request is missing"))?;
    let CreateRequest::AzureVm { body, .. } = &saved.request else {
        return Err(error(
            "Azure data disk has no create-only VM creation proof",
        ));
    };
    let original = saved
        .result
        .as_ref()
        .ok_or_else(|| error("Azure VM creation result is missing"))?;
    let expected_vm = identity(&original["properties"]["vmId"])?;
    let id = resource_id(subscription, group, &spec.name);
    let requested = body["properties"]["storageProfile"]["dataDisks"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["lun"] == spec.index && d["name"] == spec.name && d["createOption"] == "Empty")
        .ok_or_else(|| error("disk was not requested as a new empty VM disk"))?;
    if requested["diskSizeGB"] != spec.size_gb
        || requested["managedDisk"]["storageAccountType"] != spec.disk_type
    {
        return Err(error(
            "Azure disk specification differs from the saved VM creation request",
        ));
    }
    let out = runner
        .run_capture(
            "az",
            &[
                "vm",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                group,
                "--name",
                vm_name,
                "--output",
                "json",
            ],
        )
        .await?;
    let vm: serde_json::Value = serde_json::from_str(&out.stdout)?;
    if vm["vmId"] != expected_vm {
        return Err(error("Azure VM was replaced"));
    }
    // Attaching an existing disk changes createOption to Attach. Do not accept
    // a disk detached/replaced since the original VM creation.
    if !vm["storageProfile"]["dataDisks"]
        .as_array()
        .is_some_and(|disks| {
            disks.iter().any(|d| {
                d["lun"] == spec.index
                    && d["name"] == spec.name
                    && d["createOption"] == "Empty"
                    && d["managedDisk"]["id"]
                        .as_str()
                        .is_some_and(|v| v.eq_ignore_ascii_case(&id))
            })
        })
    {
        return Err(error(
            "Azure disk is not the Empty disk attached by VM creation",
        ));
    }
    let mut actual = show(subscription, group, &spec.name, runner).await?;
    let observed = crate::disk_inventory::azure_observation(&actual)?;
    verify_id(&actual, &id, &observed.id)?;
    let props = actual.get("properties").unwrap_or(&actual);
    if props["creationData"]["createOption"] != "Empty" {
        return Err(error("Azure disk was copied or restored"));
    }
    let vm_id = format!("/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Compute/virtualMachines/{vm_name}");
    if !actual["managedBy"]
        .as_str()
        .or_else(|| props["managedBy"].as_str())
        .is_some_and(|id| id.eq_ignore_ascii_case(&vm_id))
    {
        return Err(error("Azure disk is not owned by the recorded VM"));
    }
    if props["provisioningState"] == "Failed" {
        return Err(error("Azure disk provisioning failed"));
    }
    let previous = runner.recorded_disk(&spec.device_name).await?;
    if previous.as_ref().is_some_and(|old| {
        old.observed.id != observed.id
            || serde_json::to_value(&old.specification).ok() != serde_json::to_value(spec).ok()
    }) {
        return Err(error("Azure disk identity or saved specification changed"));
    }
    // A verified disk is no longer being provisioned. Resume must never retune
    // one after its performance was changed outside this creation attempt.
    if previous.as_ref().is_some_and(|old| old.creation_verified) {
        if props["provisioningState"] == "Updating" {
            return Err(error("Azure disk performance update is still pending"));
        }
        crate::disk_inventory::validate_azure(spec, &actual)?;
        return Ok(());
    }
    let mut record = crate::disk_inventory::CreatedDisk {
        specification: spec.clone(),
        observed,
        creation_verified: false,
    };
    runner.record_created_disk(&record).await?;
    let mut shape = spec.clone();
    shape.performance = None;
    crate::disk_inventory::validate(&shape, &record.observed)?;
    if matches!(spec.disk_type.as_str(), "PremiumV2_LRS" | "UltraSSD_LRS")
        && (crate::disk_inventory::validate_azure(spec, &actual).is_err()
            || props["provisioningState"] == "Updating")
    {
        let p = spec
            .performance
            .as_ref()
            .ok_or_else(|| error("missing Azure performance selection"))?;
        let mut properties = serde_json::Map::new();
        if let Some(iops) = p.iops {
            properties.insert("diskIOPSReadWrite".into(), iops.into());
        }
        if let Some(mibps) = p.throughput_mibps {
            properties.insert(
                "diskMBpsReadWrite".into(),
                crate::disk_profiles::azure_mbps(mibps)?.into(),
            );
        }
        // PATCH cannot create or replace a disk. Ownership and the immutable
        // uniqueId were checked above and are checked again after completion.
        let props = actual.get("properties").unwrap_or(&actual);
        if props["provisioningState"] != "Updating" {
            runner
                .azure_api(
                    "PATCH",
                    &format!("https://management.azure.com{id}?api-version=2024-03-02"),
                    Some(&serde_json::json!({"properties":properties})),
                    false,
                )
                .await?;
        }
        actual = tokio::time::timeout(std::time::Duration::from_secs(300), async {
            loop {
                let value = show(subscription, group, &spec.name, runner).await?;
                verify_id(&value, &id, &record.observed.id)?;
                let props = value.get("properties").unwrap_or(&value);
                if props["provisioningState"] == "Failed" {
                    return Err(error("Azure disk performance update failed"));
                }
                if props["provisioningState"] != "Updating"
                    && crate::disk_inventory::validate_azure(spec, &value).is_ok()
                {
                    return Ok(value);
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        })
        .await
        .map_err(|_| error("Azure disk performance update is still pending; use cloud resume"))??;
        record.observed = crate::disk_inventory::azure_observation(&actual)?;
    }
    crate::disk_inventory::validate_azure(spec, &actual)?;
    record.creation_verified = true;
    runner.record_created_disk(&record).await
}

pub fn resource_id(subscription: &str, group: &str, name: &str) -> String {
    format!("/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Compute/disks/{name}")
}

pub fn verify_id(
    value: &serde_json::Value,
    resource: &str,
    unique_id: &str,
) -> Result<(), CloudError> {
    let props = value.get("properties").unwrap_or(value);
    if !value["id"]
        .as_str()
        .is_some_and(|s| s.eq_ignore_ascii_case(resource))
        || props["uniqueId"] != unique_id
    {
        return Err(crate::provisioning::error(
            "Azure disk was replaced; its unique ID differs from the creation result",
        ));
    }
    Ok(())
}

pub async fn show(
    subscription: &str,
    group: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<serde_json::Value, CloudError> {
    let out = runner
        .run_capture(
            "az",
            &[
                "disk",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                group,
                "--name",
                name,
                "--output",
                "json",
            ],
        )
        .await?;
    Ok(serde_json::from_str(&out.stdout)?)
}

/// Check if a managed disk exists.
pub async fn check_disk_exists(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "disk",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
            ],
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(CloudError::CommandFailed { stderr, .. }) if stderr.contains("ResourceNotFound") => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Delete a managed disk.
pub async fn delete_disk(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "disk",
                "delete",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
                "--yes",
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("not found") || stderr.contains("NotFound") =>
        {
            tracing::debug!("disk '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("disk/{name}"),
            message: e.to_string(),
        }),
    }
}
