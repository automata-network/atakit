//! Provider observations and durable identities for disks created by this deploy.
use crate::{CloudError, CommandRunner, DeployState, DiskSpec, PlatformKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedDisk {
    pub id: String,
    pub disk_type: String,
    pub size_gb: u64,
    pub iops: Option<u64>,
    pub throughput_mibps: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedDisk {
    #[serde(default)]
    pub creation_verified: bool,
    pub specification: DiskSpec,
    pub observed: ObservedDisk,
}

fn error(message: impl Into<String>) -> CloudError {
    CloudError::DiskError {
        message: message.into(),
    }
}

fn number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

pub fn gcp_observation(value: &Value) -> Result<ObservedDisk, CloudError> {
    Ok(ObservedDisk {
        id: value["id"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| value["id"].as_u64().map(|id| id.to_string()))
            .filter(|id| !id.is_empty())
            .ok_or_else(|| error("GCP disk response has no unique ID"))?,
        disk_type: value["type"]
            .as_str()
            .and_then(|v| v.rsplit('/').next())
            .ok_or_else(|| error("GCP disk response has no type"))?
            .into(),
        size_gb: number(&value["sizeGb"]).ok_or_else(|| error("GCP disk response has no size"))?,
        iops: number(&value["provisionedIops"]),
        throughput_mibps: number(&value["provisionedThroughput"]),
    })
}

pub fn aws_observation(value: &Value) -> Result<ObservedDisk, CloudError> {
    Ok(ObservedDisk {
        id: value["VolumeId"]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| error("AWS volume response has no unique ID"))?
            .into(),
        disk_type: value["VolumeType"]
            .as_str()
            .ok_or_else(|| error("AWS volume response has no type"))?
            .into(),
        size_gb: number(&value["Size"]).ok_or_else(|| error("AWS volume response has no size"))?,
        iops: number(&value["Iops"]),
        throughput_mibps: number(&value["Throughput"]),
    })
}

pub fn azure_observation(value: &Value) -> Result<ObservedDisk, CloudError> {
    let props = value.get("properties").unwrap_or(value);
    Ok(ObservedDisk {
        id: crate::provisioning::identity(&props["uniqueId"])?,
        disk_type: value["sku"]["name"]
            .as_str()
            .ok_or_else(|| error("Azure disk has no SKU"))?
            .into(),
        size_gb: number(&props["diskSizeGB"])
            .or_else(|| number(&props["diskSizeGb"]))
            .ok_or_else(|| error("Azure disk has no size"))?,
        iops: number(&props["diskIOPSReadWrite"]).or_else(|| number(&props["diskIopsReadWrite"])),
        throughput_mibps: number(&props["diskMBpsReadWrite"])
            .or_else(|| number(&props["diskMbpsReadWrite"]))
            .and_then(|mbps| mbps.checked_mul(1_000_000))
            .map(|bytes| bytes / 1_048_576),
    })
}

pub fn validate(spec: &DiskSpec, actual: &ObservedDisk) -> Result<(), CloudError> {
    let performance_matches = spec.performance.as_ref().is_none_or(|requested| {
        requested.iops.is_none_or(|v| actual.iops == Some(v))
            && requested
                .throughput_mibps
                .is_none_or(|v| actual.throughput_mibps == Some(v))
    });
    if actual.disk_type != spec.disk_type || actual.size_gb != spec.size_gb || !performance_matches
    {
        return Err(error(format!(
            "disk {:?} ({}) differs from the saved creation settings; leaving it untouched",
            spec.device_name, actual.id
        )));
    }
    Ok(())
}

/// Retain an exact check of Azure's whole MB/s value before the display
/// conversion loses precision. No additional saved performance field is needed.
pub fn validate_azure(spec: &DiskSpec, value: &Value) -> Result<(), CloudError> {
    let props = value.get("properties").unwrap_or(value);
    if matches!(spec.disk_type.as_str(), "PremiumV2_LRS" | "UltraSSD_LRS")
        && props["provisioningState"] != "Succeeded"
    {
        return Err(error(
            "Azure disk performance provisioning has not succeeded",
        ));
    }
    validate(spec, &azure_observation(value)?)?;
    if let Some(mibps) = spec.performance.as_ref().and_then(|p| p.throughput_mibps) {
        let actual =
            number(&props["diskMBpsReadWrite"]).or_else(|| number(&props["diskMbpsReadWrite"]));
        if actual != Some(crate::disk_profiles::azure_mbps(mibps)?) {
            return Err(error(
                "Azure disk throughput differs from the saved creation settings",
            ));
        }
    }
    Ok(())
}

pub fn require_empty_source(value: &Value, fields: &[&str]) -> Result<(), CloudError> {
    if fields.iter().any(|field| {
        value
            .get(field)
            .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
    }) {
        return Err(error(
            "disk was restored from an existing source; automatic initialization is forbidden",
        ));
    }
    Ok(())
}

pub(crate) async fn aws_instance(
    region: &str,
    instance: &str,
    runner: &dyn CommandRunner,
) -> Result<Value, CloudError> {
    let out = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-instances",
                "--region",
                region,
                "--instance-ids",
                instance,
                "--output",
                "json",
            ],
        )
        .await?;
    let json: Value = serde_json::from_str(&out.stdout)?;
    let vm = &json["Reservations"][0]["Instances"][0];
    if vm["InstanceId"].as_str() != Some(instance) {
        return Err(error("AWS instance identity mismatch"));
    }
    Ok(vm.clone())
}

fn aws_attachment(vm: &Value, device: &str) -> Result<String, CloudError> {
    let mappings = vm["BlockDeviceMappings"]
        .as_array()
        .ok_or_else(|| error("AWS instance has no disk attachment list"))?;
    let entries: Vec<_> = mappings
        .iter()
        .filter(|v| v["DeviceName"].as_str() == Some(device))
        .collect();
    if entries.len() != 1 {
        return Err(error(format!("expected one AWS disk at {device}")));
    }
    entries[0]["Ebs"]["VolumeId"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| error("AWS attachment has no volume ID"))
}

pub(crate) async fn aws_volume(
    region: &str,
    id: &str,
    runner: &dyn CommandRunner,
) -> Result<Value, CloudError> {
    let out = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-volumes",
                "--region",
                region,
                "--volume-ids",
                id,
                "--output",
                "json",
            ],
        )
        .await?;
    let json: Value = serde_json::from_str(&out.stdout)?;
    let volumes = json["Volumes"]
        .as_array()
        .filter(|v| v.len() == 1)
        .ok_or_else(|| error("expected exactly one AWS volume"))?;
    Ok(volumes[0].clone())
}

/// Read actual attachments and compare unique disk IDs to saved create results.
pub async fn verify(
    state: &DeployState,
    runner: &dyn CommandRunner,
) -> Result<BTreeMap<String, ObservedDisk>, CloudError> {
    if state
        .created_disks
        .values()
        .any(|disk| !disk.creation_verified)
    {
        return Err(error(
            "disk creation verification did not complete; leaving all disks untouched",
        ));
    }
    let mut observations = BTreeMap::new();
    if state.created_disks.is_empty() {
        return Ok(observations);
    }
    match state.platform {
        PlatformKind::Aws => {
            let resources = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("missing AWS resources"))?;
            let instance = resources
                .instance
                .as_deref()
                .ok_or_else(|| error("missing AWS instance"))?;
            let vm = aws_instance(&resources.region, instance, runner).await?;
            for (name, record) in &state.created_disks {
                let device = format!(
                    "/dev/sd{}",
                    (b'f' + record.specification.index as u8) as char
                );
                let id = aws_attachment(&vm, &device)?;
                if id != record.observed.id {
                    return Err(error(format!(
                        "disk {name:?} was replaced; refusing initialization"
                    )));
                }
                let actual = aws_observation(&aws_volume(&resources.region, &id, runner).await?)?;
                validate(&record.specification, &actual)?;
                if actual.id != id {
                    return Err(error("AWS volume identity mismatch"));
                }
                observations.insert(name.clone(), actual);
            }
        }
        PlatformKind::Gcp => {
            let resources = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("missing GCP resources"))?;
            let instance = resources
                .instance
                .as_deref()
                .ok_or_else(|| error("missing GCP instance"))?;
            let out = runner
                .run_capture(
                    "gcloud",
                    &[
                        "compute",
                        "instances",
                        "describe",
                        instance,
                        "--project",
                        &resources.project,
                        "--zone",
                        &resources.zone,
                        "--format=json",
                    ],
                )
                .await?;
            let vm: Value = serde_json::from_str(&out.stdout)?;
            let attachments = vm["disks"]
                .as_array()
                .ok_or_else(|| error("GCP instance has no disk attachments"))?;
            for (name, record) in &state.created_disks {
                let spec = &record.specification;
                let matches: Vec<_> = attachments
                    .iter()
                    .filter(|v| v["deviceName"].as_str() == Some(name))
                    .collect();
                let expected_source = format!(
                    "projects/{}/zones/{}/disks/{}",
                    resources.project, resources.zone, spec.name
                );
                if matches.len() != 1
                    || !matches[0]["source"].as_str().is_some_and(|s| {
                        s == expected_source || s.ends_with(&format!("/{expected_source}"))
                    })
                {
                    return Err(error(format!("GCP disk {name:?} attachment changed")));
                }
                let out = runner
                    .run_capture(
                        "gcloud",
                        &[
                            "compute",
                            "disks",
                            "describe",
                            &spec.name,
                            "--project",
                            &resources.project,
                            "--zone",
                            &resources.zone,
                            "--format=json",
                        ],
                    )
                    .await?;
                let actual = gcp_observation(&serde_json::from_str(&out.stdout)?)?;
                if actual.id != record.observed.id {
                    return Err(error(format!(
                        "disk {name:?} was replaced; refusing initialization"
                    )));
                }
                validate(spec, &actual)?;
                observations.insert(name.clone(), actual);
            }
        }
        PlatformKind::Azure => {
            let r = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("missing Azure resources"))?;
            let group = r
                .resource_group
                .as_deref()
                .ok_or_else(|| error("missing Azure group"))?;
            let instance = r
                .instance
                .as_deref()
                .ok_or_else(|| error("missing Azure VM"))?;
            let out = runner
                .run_capture(
                    "az",
                    &[
                        "vm",
                        "show",
                        "--subscription",
                        &r.subscription,
                        "--resource-group",
                        group,
                        "--name",
                        instance,
                        "--output",
                        "json",
                    ],
                )
                .await?;
            let vm: Value = serde_json::from_str(&out.stdout)?;
            if vm["vmId"].as_str() != state.cloud_instance_id.as_deref() {
                return Err(error("Azure VM was replaced"));
            }
            let attachments = vm["storageProfile"]["dataDisks"]
                .as_array()
                .ok_or_else(|| error("missing Azure disk attachments"))?;
            for (name, record) in &state.created_disks {
                let resource = crate::azure::disk::resource_id(
                    &r.subscription,
                    group,
                    &record.specification.name,
                );
                let slot: Vec<_> = attachments
                    .iter()
                    .filter(|a| a["lun"].as_u64() == Some(record.specification.index as u64))
                    .collect();
                if slot.len() != 1
                    || !slot[0]["managedDisk"]["id"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(&resource))
                {
                    return Err(error(format!("Azure disk {name:?} attachment changed")));
                }
                let value = crate::azure::disk::show(
                    &r.subscription,
                    group,
                    &record.specification.name,
                    runner,
                )
                .await?;
                crate::azure::disk::verify_id(&value, &resource, &record.observed.id)?;
                let actual = azure_observation(&value)?;
                validate_azure(&record.specification, &value)?;
                observations.insert(name.clone(), actual);
            }
        }
        _ => {
            return Err(error(
                "recorded automatic disk initialization is unsupported on this provider",
            ))
        }
    }
    Ok(observations)
}

pub async fn aws_boot(
    region: &str,
    instance: &str,
    runner: &dyn CommandRunner,
) -> Result<ObservedDisk, CloudError> {
    let vm = aws_instance(region, instance, runner).await?;
    aws_boot_from_vm(region, &vm, runner).await
}

pub(crate) async fn aws_boot_from_vm(
    region: &str,
    vm: &Value,
    runner: &dyn CommandRunner,
) -> Result<ObservedDisk, CloudError> {
    let root = vm["RootDeviceName"]
        .as_str()
        .ok_or_else(|| error("AWS instance has no root device"))?;
    let id = aws_attachment(vm, root)?;
    let actual = aws_observation(&aws_volume(region, &id, runner).await?)?;
    if actual.id != id {
        return Err(error("AWS boot disk identity mismatch"));
    }
    Ok(actual)
}

pub async fn gcp_boot(
    project: &str,
    zone: &str,
    instance: &str,
    runner: &dyn CommandRunner,
) -> Result<ObservedDisk, CloudError> {
    let out = runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "instances",
                "describe",
                instance,
                "--project",
                project,
                "--zone",
                zone,
                "--format=json",
            ],
        )
        .await?;
    let vm: Value = serde_json::from_str(&out.stdout)?;
    gcp_boot_from_vm(project, zone, &vm, runner).await
}

pub(crate) async fn gcp_boot_from_vm(
    project: &str,
    zone: &str,
    vm: &Value,
    runner: &dyn CommandRunner,
) -> Result<ObservedDisk, CloudError> {
    let name = gcp_boot_name(vm, project, zone)?;
    let out = runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "disks",
                "describe",
                &name,
                "--project",
                project,
                "--zone",
                zone,
                "--format=json",
            ],
        )
        .await?;
    gcp_observation(&serde_json::from_str(&out.stdout)?)
}

/// Resolve a boot disk reference from either a live VM or its saved creation
/// response, without accepting a disk in a different project or zone.
pub(crate) fn gcp_boot_name(vm: &Value, project: &str, zone: &str) -> Result<String, CloudError> {
    let roots: Vec<_> = vm["disks"]
        .as_array()
        .ok_or_else(|| error("GCP instance has no disks"))?
        .iter()
        .filter(|d| d["boot"] == true)
        .collect();
    if roots.len() != 1 {
        return Err(error("expected exactly one GCP boot disk"));
    }
    let source = roots[0]["source"]
        .as_str()
        .ok_or_else(|| error("GCP boot disk has no source"))?;
    let name = source
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| error("invalid GCP boot disk source"))?;
    let suffix = format!("projects/{project}/zones/{zone}/disks/{name}");
    if source != suffix && !source.ends_with(&format!("/{suffix}")) {
        return Err(error(
            "GCP boot disk belongs to a different project or zone",
        ));
    }
    Ok(name.into())
}

pub fn validate_boot(state: &DeployState, actual: &ObservedDisk) -> Result<(), CloudError> {
    if state
        .created_boot_disk
        .as_ref()
        .is_some_and(|old| old.id != actual.id)
    {
        return Err(error(
            "boot disk identity changed; leaving the disk untouched",
        ));
    }
    if state
        .disk_configuration
        .boot_size_gb
        .is_some_and(|size| size != actual.size_gb)
    {
        return Err(error("boot disk size differs from saved creation settings"));
    }
    if let Some(p) = &state.disk_configuration.boot {
        validate(
            &DiskSpec {
                name: "boot".into(),
                device_name: "boot".into(),
                index: 0,
                size_gb: actual.size_gb,
                disk_type: p.disk_type.clone(),
                performance: Some(p.clone()),
            },
            actual,
        )?;
    }
    Ok(())
}

pub async fn azure_boot(
    subscription: &str,
    group: &str,
    instance: &str,
    runner: &dyn CommandRunner,
) -> Result<ObservedDisk, CloudError> {
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
                instance,
                "--output",
                "json",
            ],
        )
        .await?;
    let vm: Value = serde_json::from_str(&out.stdout)?;
    azure_boot_from_vm(&vm, runner).await
}

pub(crate) async fn azure_boot_from_vm(
    vm: &Value,
    runner: &dyn CommandRunner,
) -> Result<ObservedDisk, CloudError> {
    let id = vm["storageProfile"]["osDisk"]["managedDisk"]["id"]
        .as_str()
        .ok_or_else(|| error("Azure VM has no boot disk ID"))?;
    let out = runner
        .run_capture("az", &["disk", "show", "--ids", id, "--output", "json"])
        .await?;
    let value: Value = serde_json::from_str(&out.stdout)?;
    if !value["id"]
        .as_str()
        .is_some_and(|s| s.eq_ignore_ascii_case(id))
    {
        return Err(error("Azure boot disk identity mismatch"));
    }
    azure_observation(&value)
}

/// Status reads never change provider settings. Failure leaves all disks intact.
pub async fn verify_local_ssd(
    state: &DeployState,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let Some(local) = state.disk_configuration.local_ssd()? else {
        return Ok(());
    };
    if state.platform == PlatformKind::Azure {
        return verify_azure_local_ssd(state, runner).await;
    }
    if state.platform != PlatformKind::Gcp {
        return Err(error("Local SSD requires GCP"));
    }
    let g = state
        .resources
        .gcp
        .as_ref()
        .ok_or_else(|| error("missing GCP resources"))?;
    let name = g
        .instance
        .as_deref()
        .ok_or_else(|| error("missing GCP instance"))?;
    let created = state
        .provisioning
        .creations
        .get("instance")
        .and_then(|c| c.result.as_ref())
        .ok_or_else(|| error("Local SSD has no saved VM creation result"))?;
    let out = runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "instances",
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
    let vm: Value = serde_json::from_str(&out.stdout)?;
    if vm["id"].as_str() != state.cloud_instance_id.as_deref() || created["id"] != vm["id"] {
        return Err(error(
            "Local SSD VM identity differs from its creation result",
        ));
    }
    for value in [created, &vm] {
        let disks = value["disks"]
            .as_array()
            .ok_or_else(|| error("missing VM disk attachments"))?;
        let local_disks: Vec<_> = disks.iter().filter(|d| d["type"] == "SCRATCH").collect();
        if local_disks.len() != local.count as usize
            || (0..local.count).any(|i| {
                local_disks
                    .iter()
                    .filter(|d| {
                        d["deviceName"] == format!("local-ssd-{i}")
                            && d["interface"] == "NVME"
                            && d["diskSizeGb"] == "375"
                            && d["boot"] == false
                    })
                    .count()
                    != 1
            })
        {
            return Err(error(
                "Local SSD attachments differ from the selected VM's members",
            ));
        }
    }
    Ok(())
}

async fn verify_azure_local_ssd(
    state: &DeployState,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let resources = state
        .resources
        .azure
        .as_ref()
        .ok_or_else(|| error("missing Azure resources"))?;
    let group = resources
        .resource_group
        .as_deref()
        .ok_or_else(|| error("missing Azure group"))?;
    let instance = resources
        .instance
        .as_deref()
        .ok_or_else(|| error("missing Azure VM"))?;
    let creation = state
        .provisioning
        .creations
        .get("instance")
        .ok_or_else(|| error("local SSD has no VM creation request"))?;
    let crate::provisioning::CreateRequest::AzureVm { body, .. } = &creation.request else {
        return Err(error("local SSD requires an Azure VM creation request"));
    };
    let original = creation
        .result
        .as_ref()
        .ok_or_else(|| error("local SSD has no VM creation result"))?;
    let out = runner
        .run_capture(
            "az",
            &[
                "vm",
                "show",
                "--subscription",
                &resources.subscription,
                "--resource-group",
                group,
                "--name",
                instance,
                "--output",
                "json",
            ],
        )
        .await?;
    let current: Value = serde_json::from_str(&out.stdout)?;
    if state.cloud_instance_id.as_deref().is_none_or(str::is_empty)
        || current["vmId"].as_str() != state.cloud_instance_id.as_deref()
        || original["properties"]["vmId"] != current["vmId"]
    {
        return Err(error(
            "Azure local SSD VM identity differs from its creation result",
        ));
    }
    for value in [&body["properties"], &original["properties"], &current] {
        if value["hardwareProfile"]["vmSize"] != state.disk_configuration.vmtype
            || value["securityProfile"]["securityType"] != "ConfidentialVM"
            || value["storageProfile"]["osDisk"]["diffDiskSettings"]["option"] == "Local"
        {
            return Err(error(
                "Azure local SSD requires the original confidential VM size and a managed OS disk",
            ));
        }
    }
    Ok(())
}

/// Verify VM and disk identities and settings without optional catalog lookups.
/// Initialization uses these checks before granting disk creation permission.
pub async fn verify_configuration(
    state: &DeployState,
    runner: &dyn CommandRunner,
) -> Result<Value, CloudError> {
    crate::resume::verify_instance_identity(state, runner).await?;
    let boot = match state.platform {
        PlatformKind::Aws => {
            let r = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("missing AWS resources"))?;
            Some(
                aws_boot(
                    &r.region,
                    r.instance
                        .as_deref()
                        .ok_or_else(|| error("missing AWS instance"))?,
                    runner,
                )
                .await?,
            )
        }
        PlatformKind::Gcp => {
            let r = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("missing GCP resources"))?;
            Some(
                gcp_boot(
                    &r.project,
                    &r.zone,
                    r.instance
                        .as_deref()
                        .ok_or_else(|| error("missing GCP instance"))?,
                    runner,
                )
                .await?,
            )
        }
        PlatformKind::Azure => {
            let r = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("missing Azure resources"))?;
            Some(
                azure_boot(
                    &r.subscription,
                    r.resource_group
                        .as_deref()
                        .ok_or_else(|| error("missing Azure group"))?,
                    r.instance
                        .as_deref()
                        .ok_or_else(|| error("missing Azure VM"))?,
                    runner,
                )
                .await?,
            )
        }
        _ => None,
    };
    if let Some(boot) = &boot {
        validate_boot(state, boot)?;
    }
    let disks = verify(state, runner).await?;
    let local_ssd = state.disk_configuration.local_ssd()?;
    if local_ssd.is_some() {
        verify_local_ssd(state, runner).await?;
    }
    Ok(
        serde_json::json!({"source": "provider API", "boot": boot, "disks": disks, "local_ssd": local_ssd,
        "quota_and_capacity": "not reserved; provider admission decides availability"}),
    )
}

pub async fn status(state: &DeployState, runner: &dyn CommandRunner) -> Result<Value, CloudError> {
    let mut observation = verify_configuration(state, runner).await?;
    // Optional performance information must not hide verified disk observations
    // behind a slow regional catalog query.
    observation["shared_vm_limits"] = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        shared_limits(state, runner),
    )
    .await
    {
        Ok(Ok(limits)) => limits,
        Ok(Err(error)) => {
            serde_json::json!({"error":error.to_string(),"status":"not checked"})
        }
        Err(_) => {
            serde_json::json!({"error":"shared VM limit lookup timed out","status":"not checked"})
        }
    };
    Ok(observation)
}

async fn shared_limits(
    state: &DeployState,
    runner: &dyn CommandRunner,
) -> Result<Value, CloudError> {
    match state.platform {
        PlatformKind::Aws => {
            let r = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("missing AWS resources"))?;
            let vm = aws_instance(
                &r.region,
                r.instance
                    .as_deref()
                    .ok_or_else(|| error("missing AWS instance"))?,
                runner,
            )
            .await?;
            let vmtype = vm["InstanceType"]
                .as_str()
                .ok_or_else(|| error("missing current AWS instance type"))?;
            let out = runner
                .run_capture(
                    "aws",
                    &[
                        "ec2",
                        "describe-instance-types",
                        "--instance-types",
                        vmtype,
                        "--region",
                        &r.region,
                        "--output",
                        "json",
                    ],
                )
                .await?;
            let response: Value = serde_json::from_str(&out.stdout)?;
            let item = response["InstanceTypes"]
                .as_array()
                .and_then(|a| a.iter().find(|v| v["InstanceType"] == vmtype))
                .ok_or_else(|| error("AWS returned no matching instance type"))?;
            let limit = &item["EbsInfo"]["EbsOptimizedInfo"];
            Ok(
                serde_json::json!({"vmtype":vmtype,"source":"AWS describe-instance-types","maximum_iops":limit["MaximumIops"],
                "maximum_throughput_mibps":limit["MaximumThroughputInMBps"].as_f64().map(|v|v*1_000_000.0/1_048_576.0),
                "baseline_iops":limit["BaselineIops"],
                "baseline_throughput_mibps":limit["BaselineThroughputInMBps"].as_f64().map(|v|v*1_000_000.0/1_048_576.0)}),
            )
        }
        PlatformKind::Gcp => {
            let r = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("missing GCP resources"))?;
            let instance = r
                .instance
                .as_deref()
                .ok_or_else(|| error("missing GCP instance"))?;
            let out = runner
                .run_capture(
                    "gcloud",
                    &[
                        "compute",
                        "instances",
                        "describe",
                        instance,
                        "--project",
                        &r.project,
                        "--zone",
                        &r.zone,
                        "--format=json",
                    ],
                )
                .await?;
            let vm: Value = serde_json::from_str(&out.stdout)?;
            let vmtype = vm["machineType"]
                .as_str()
                .and_then(|v| v.rsplit('/').next())
                .ok_or_else(|| error("missing current GCP machine type"))?;
            Ok(
                match crate::disk_profiles::gcp_hyperdisk_vm_limits(vmtype) {
                    Some((iops, mibps)) => {
                        serde_json::json!({"vmtype":vmtype,"maximum_iops":iops,"maximum_throughput_mibps":mibps,"source":"GCP documented Hyperdisk VM limits"})
                    }
                    None => {
                        serde_json::json!({"vmtype":vmtype,"status":"not checked","detail":"shared performance limit unavailable for this machine family"})
                    }
                },
            )
        }
        PlatformKind::Azure => {
            use crate::azure::capabilities::{capability, catalog, find};
            let r = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("missing Azure resources"))?;
            let group = r
                .resource_group
                .as_deref()
                .ok_or_else(|| error("missing Azure group"))?;
            let name = r
                .instance
                .as_deref()
                .ok_or_else(|| error("missing Azure VM"))?;
            let out = runner
                .run_capture(
                    "az",
                    &[
                        "vm",
                        "show",
                        "--subscription",
                        &r.subscription,
                        "--resource-group",
                        group,
                        "--name",
                        name,
                        "--output",
                        "json",
                    ],
                )
                .await?;
            let vm: Value = serde_json::from_str(&out.stdout)?;
            let vmtype = vm["hardwareProfile"]["vmSize"]
                .as_str()
                .ok_or_else(|| error("missing current Azure VM size"))?;
            let provider = crate::CloudProviderConfig {
                platform: PlatformKind::Azure,
                subscription: Some(r.subscription.clone()),
                region: r.region.clone(),
                project: None,
                uefi: None,
            };
            let skus = catalog(&provider, "virtualMachines", runner).await?;
            let sku = find(&skus, vmtype)?;
            Ok(
                serde_json::json!({"vmtype": vmtype, "source":"Azure list-skus",
                "maximum_iops":capability(sku, "UncachedDiskIOPS").and_then(|s|s.parse::<u64>().ok()),
                "maximum_throughput_mibps":capability(sku, "UncachedDiskBytesPerSecond").and_then(|s|s.parse::<u64>().ok()).map(|v|v as f64 / 1_048_576.0)}),
            )
        }
        _ => Ok(Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CloudProvider, CommandOutput, NewDeployParams};
    use serde_json::json;
    use std::{collections::VecDeque, sync::Mutex};
    struct Runner {
        replies: Mutex<VecDeque<Value>>,
        calls: Mutex<Vec<Vec<String>>>,
        created: Mutex<Vec<CreatedDisk>>,
    }
    impl Runner {
        fn new(replies: Vec<Value>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                calls: Mutex::new(vec![]),
                created: Mutex::new(vec![]),
            }
        }
    }
    #[async_trait::async_trait]
    impl CommandRunner for Runner {
        async fn create_resource(
            &self,
            _: &str,
            request: &crate::provisioning::CreateRequest,
        ) -> Result<Value, CloudError> {
            self.calls
                .lock()
                .unwrap()
                .push(vec![serde_json::to_string(request).unwrap()]);
            Ok(self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("missing creation result"))
        }
        async fn run_capture(&self, _: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|s| s.to_string()).collect());
            Ok(CommandOutput {
                status: 0,
                stdout: self
                    .replies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected provider call")
                    .to_string(),
                stderr: String::new(),
            })
        }
        async fn run_stream(
            &self,
            _: &str,
            _: &[&str],
            _: bool,
        ) -> Result<CommandOutput, CloudError> {
            panic!("unexpected provider write")
        }
        async fn record_created_disk(&self, disk: &CreatedDisk) -> Result<(), CloudError> {
            self.created.lock().unwrap().push(disk.clone());
            Ok(())
        }
    }
    fn spec() -> DiskSpec {
        DiskSpec {
            name: "vm-database".into(),
            device_name: "database".into(),
            index: 0,
            size_gb: 2000,
            disk_type: "hyperdisk-balanced".into(),
            performance: Some(crate::disk_profiles::DiskPerformance {
                disk_type: "hyperdisk-balanced".into(),
                iops: Some(6000),
                throughput_mibps: Some(250),
                ..Default::default()
            }),
        }
    }
    fn gcp_disk(id: &str) -> Value {
        json!({"name":"vm-database","id":id,"type":"zones/zone/diskTypes/hyperdisk-balanced","sizeGb":"2000","provisionedIops":"6000","provisionedThroughput":"250"})
    }
    fn gcp_vm() -> Value {
        json!({"disks":[{"deviceName":"database","source":"https://www.googleapis.com/compute/v1/projects/project/zones/zone/disks/vm-database"}]})
    }
    fn state() -> DeployState {
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "vm".into(),
            target_name: "target".into(),
            provider_name: "provider".into(),
            platform: PlatformKind::Gcp,
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
        state.resources.gcp = Some(crate::GcpResources {
            project: "project".into(),
            zone: "zone".into(),
            instance: Some("vm".into()),
            ..Default::default()
        });
        state.created_disks.insert(
            "database".into(),
            CreatedDisk {
                creation_verified: true,
                specification: spec(),
                observed: gcp_observation(&gcp_disk("original")).unwrap(),
            },
        );
        state
    }
    #[tokio::test]
    async fn local_ssd_requires_original_vm_and_exact_members() {
        use crate::provisioning::{CreateRequest, Creation, CreationOutcome};
        let vm = json!({"id":"123", "disks":[
            {"type":"PERSISTENT", "boot":true},
            {"type":"SCRATCH", "deviceName":"local-ssd-0", "interface":"NVME", "diskSizeGb":"375", "boot":false},
            {"type":"SCRATCH", "deviceName":"local-ssd-1", "interface":"NVME", "diskSizeGb":"375", "boot":false}
        ]});
        let mut state = state();
        state.cloud_instance_id = Some("123".into());
        state.disk_configuration.vmtype = "c3-standard-8-lssd".into();
        state.disk_configuration.disks.insert(
            "database".into(),
            crate::disk_profiles::DiskPerformance {
                disk_type: "local-ssd".into(),
                ..Default::default()
            },
        );
        state.provisioning.creations.insert(
            "instance".into(),
            Creation {
                outcome: CreationOutcome::Succeeded,
                request: CreateRequest::Gcp {
                    project: "project".into(),
                    zone: "zone".into(),
                    collection: "instances".into(),
                    body: json!({}),
                },
                token: "token".into(),
                sent: true,
                receipt: None,
                result: Some(vm.clone()),
            },
        );
        verify_local_ssd(&state, &Runner::new(vec![vm.clone()]))
            .await
            .unwrap();
        let mut missing = vm.clone();
        missing["disks"].as_array_mut().unwrap().pop();
        let mut replaced = vm.clone();
        replaced["id"] = json!("456");
        let mut wrong_name = vm.clone();
        wrong_name["disks"][2]["deviceName"] = json!("local-ssd-0");
        let mut wrong_type = vm.clone();
        wrong_type["disks"][2]["type"] = json!("PERSISTENT");
        for invalid in [missing, replaced, wrong_name, wrong_type] {
            assert!(verify_local_ssd(&state, &Runner::new(vec![invalid]))
                .await
                .is_err());
        }
        state
            .provisioning
            .creations
            .get_mut("instance")
            .unwrap()
            .result = None;
        assert!(verify_local_ssd(&state, &Runner::new(vec![]))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn gcp_creation_records_identity_and_settings_before_allowing_initialization() {
        let runner = Runner::new(vec![gcp_disk("new"), gcp_disk("new")]);
        crate::gcp::disk::create_disk("project", "zone", &spec(), &runner)
            .await
            .unwrap();
        let created = runner.created.lock().unwrap();
        assert!(!created[0].creation_verified);
        assert!(created[1].creation_verified);
        assert_eq!(created[1].observed.id, "new");
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        let request: crate::provisioning::CreateRequest =
            serde_json::from_str(&calls[0][0]).unwrap();
        let crate::provisioning::CreateRequest::Gcp { body, .. } = request else {
            panic!("wrong provider")
        };
        assert_eq!(body["provisionedIops"], "6000");
        assert_eq!(body["provisionedThroughput"], "250");
        assert!(body["type"]
            .as_str()
            .unwrap()
            .ends_with("/hyperdisk-balanced"));
    }
    #[tokio::test]
    async fn restored_or_mismatched_creation_is_tracked_but_not_authorized() {
        for bad in ["sourceSnapshot", "provisionedIops"] {
            let mut value = gcp_disk("new");
            value[bad] = json!("unexpected");
            let runner = Runner::new(vec![value]);
            assert!(
                crate::gcp::disk::create_disk("project", "zone", &spec(), &runner)
                    .await
                    .is_err()
            );
            assert!(runner
                .created
                .lock()
                .unwrap()
                .iter()
                .all(|d| !d.creation_verified));
        }
    }
    #[tokio::test]
    async fn existing_gcp_disk_is_never_adopted_or_reformatted() {
        let runner = Runner::new(vec![gcp_disk("existing")]);
        let provider = crate::gcp::GcpProvider::new("project".into(), "zone".into());
        let step = crate::DeployStep::CreateDisks {
            disks: vec![spec()],
            resource_group: None,
        };
        assert!(provider.execute_step(&step, &runner, false).await.is_err());
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
        assert!(runner.created.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn replacement_reattachment_and_changed_settings_stop_resume_without_provider_writes() {
        let state = state();
        assert!(
            verify(&state, &Runner::new(vec![gcp_vm(), gcp_disk("original")]))
                .await
                .is_ok()
        );
        assert!(verify(
            &state,
            &Runner::new(vec![gcp_vm(), gcp_disk("replacement")])
        )
        .await
        .is_err());
        let mut vm = gcp_vm();
        vm["disks"][0]["source"] = json!("projects/other/zones/zone/disks/vm-database");
        assert!(verify(&state, &Runner::new(vec![vm])).await.is_err());
        let mut disk = gcp_disk("original");
        disk["provisionedIops"] = json!(9000);
        let runner = Runner::new(vec![gcp_vm(), disk]);
        assert!(verify(&state, &runner).await.is_err());
        assert!(runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|args| args.contains(&"describe".into())));
    }
    #[tokio::test]
    async fn aws_snapshot_volume_cannot_gain_automatic_initialization() {
        let runner = Runner::new(vec![
            json!({"VolumeId":"vol-restored","SnapshotId":"snap-old","VolumeType":"gp3","Size":2000,"AvailabilityZone":"zone"}),
        ]);
        let mut disk = spec();
        disk.disk_type = "gp3".into();
        disk.performance = None;
        assert!(crate::aws::disk::create("region", "zone", &disk, &runner)
            .await
            .is_err());
        let created = runner.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        assert!(!created[0].creation_verified);
    }
    #[tokio::test]
    async fn shared_limits_use_live_machine_type_and_convert_aws_units() {
        let mut state = state();
        state.disk_configuration.vmtype = "outdated-type".into();
        let gcp = Runner::new(vec![
            json!({"machineType":"projects/project/zones/zone/machineTypes/c3-standard-4"}),
        ]);
        let result = shared_limits(&state, &gcp).await.unwrap();
        assert_eq!(result["vmtype"], "c3-standard-4");
        assert_eq!(result["maximum_throughput_mibps"], 400);
        state.platform = PlatformKind::Aws;
        state.resources.aws = Some(crate::AwsResources {
            region: "region".into(),
            instance: Some("i-new".into()),
            ..Default::default()
        });
        let aws = Runner::new(vec![
            json!({"Reservations":[{"Instances":[{"InstanceId":"i-new","InstanceType":"m6a.xlarge"}]}]}),
            json!({"InstanceTypes":[{"InstanceType":"m6a.xlarge","EbsInfo":{"EbsOptimizedInfo":{"MaximumIops":40000,"MaximumThroughputInMBps":1000,"BaselineIops":6000,"BaselineThroughputInMBps":250}}}]}),
        ]);
        let result = shared_limits(&state, &aws).await.unwrap();
        assert_eq!(result["maximum_iops"], 40000);
        assert_eq!(
            result["maximum_throughput_mibps"].as_f64(),
            Some(1000.0 * 1_000_000.0 / 1_048_576.0)
        );
    }
}
