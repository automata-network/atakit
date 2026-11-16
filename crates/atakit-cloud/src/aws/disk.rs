use crate::{
    disk_inventory::{self, CreatedDisk},
    provisioning::{error, CreateRequest},
    CloudError, CommandRunner, DiskSpec,
};
use serde_json::{json, Value};

pub async fn create(
    region: &str,
    zone: &str,
    spec: &DiskSpec,
    runner: &dyn CommandRunner,
) -> Result<CreatedDisk, CloudError> {
    let mut args = vec![
        "ec2".into(),
        "create-volume".into(),
        "--region".into(),
        region.into(),
        "--availability-zone".into(),
        zone.into(),
        "--volume-type".into(),
        spec.disk_type.clone(),
        "--size".into(),
        spec.size_gb.to_string(),
        "--output".into(),
        "json".into(),
    ];
    if let Some(p) = &spec.performance {
        if let Some(v) = p.iops {
            args.extend(["--iops".into(), v.to_string()]);
        }
        if let Some(v) = p.throughput_mibps {
            args.extend(["--throughput".into(), v.to_string()]);
        }
    }
    let value = runner
        .create_resource(
            &format!("disk:{}", spec.device_name),
            &CreateRequest::Aws { args },
        )
        .await?;
    let observed = disk_inventory::aws_observation(&value)?;
    let mut record = CreatedDisk {
        creation_verified: false,
        specification: spec.clone(),
        observed,
    };
    runner.record_created_disk(&record).await?;
    disk_inventory::require_empty_source(&value, &["SnapshotId", "SourceVolumeId"])?;
    if value["AvailabilityZone"] != zone {
        return Err(error("AWS disk creation returned a different zone"));
    }
    disk_inventory::validate(spec, &record.observed)?;
    record.creation_verified = true;
    runner.record_created_disk(&record).await?;
    let current = disk_inventory::aws_volume(region, &record.observed.id, runner).await?;
    let actual = disk_inventory::aws_observation(&current)?;
    if actual.id != record.observed.id {
        return Err(error("AWS disk identity changed"));
    }
    disk_inventory::validate(spec, &actual)?;
    Ok(record)
}

pub async fn attach(
    region: &str,
    instance: &str,
    disk: &CreatedDisk,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let device = format!("/dev/sd{}", (b'f' + disk.specification.index as u8) as char);
    let vm = disk_inventory::aws_instance(region, instance, runner).await?;
    let mappings = vm["BlockDeviceMappings"]
        .as_array()
        .ok_or_else(|| error("missing AWS attachment list"))?;
    let slot: Vec<_> = mappings
        .iter()
        .filter(|m| m["DeviceName"] == device)
        .collect();
    if slot.len() > 1
        || slot
            .first()
            .is_some_and(|m| m["Ebs"]["VolumeId"] != disk.observed.id)
    {
        return Err(error(
            "AWS disk attachment is occupied by a different volume",
        ));
    }
    if slot.is_empty() {
        if mappings
            .iter()
            .any(|m| m["Ebs"]["VolumeId"] == disk.observed.id)
        {
            return Err(error("AWS disk is attached at a different device"));
        }
        let value = disk_inventory::aws_volume(region, &disk.observed.id, runner).await?;
        let actual = disk_inventory::aws_observation(&value)?;
        disk_inventory::validate(&disk.specification, &actual)?;
        if actual.id != disk.observed.id
            || value["Attachments"]
                .as_array()
                .is_none_or(|a| !a.is_empty())
        {
            return Err(error("AWS volume identity or attachment changed"));
        }
        runner
            .run_capture(
                "aws",
                &[
                    "ec2",
                    "wait",
                    "volume-available",
                    "--region",
                    region,
                    "--volume-ids",
                    &disk.observed.id,
                ],
            )
            .await?;
        runner
            .run_capture(
                "aws",
                &[
                    "ec2",
                    "attach-volume",
                    "--region",
                    region,
                    "--instance-id",
                    instance,
                    "--volume-id",
                    &disk.observed.id,
                    "--device",
                    &device,
                    "--output",
                    "json",
                ],
            )
            .await?;
    }
    runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "wait",
                "volume-in-use",
                "--region",
                region,
                "--volume-ids",
                &disk.observed.id,
            ],
        )
        .await?;
    // Separate attachments otherwise default to retaining the volume.
    let mapping = json!([{"DeviceName":device,"Ebs":{"VolumeId":disk.observed.id,"DeleteOnTermination":true}}]).to_string();
    let vm = disk_inventory::aws_instance(region, instance, runner).await?;
    let matches: Vec<_> = vm["BlockDeviceMappings"]
        .as_array()
        .ok_or_else(|| error("missing AWS attachments"))?
        .iter()
        .filter(|m| m["DeviceName"] == device && m["Ebs"]["VolumeId"] == disk.observed.id)
        .collect();
    if matches.len() != 1 {
        return Err(error("AWS attachment verification failed"));
    }
    if matches[0]["Ebs"]["DeleteOnTermination"] != true {
        runner
            .run_capture(
                "aws",
                &[
                    "ec2",
                    "modify-instance-attribute",
                    "--region",
                    region,
                    "--instance-id",
                    instance,
                    "--block-device-mappings",
                    &mapping,
                ],
            )
            .await?;
        let confirmed = disk_inventory::aws_instance(region, instance, runner).await?;
        if !confirmed["BlockDeviceMappings"]
            .as_array()
            .is_some_and(|m| {
                m.iter().any(|v| {
                    v["DeviceName"] == device
                        && v["Ebs"]["VolumeId"] == disk.observed.id
                        && v["Ebs"]["DeleteOnTermination"] == true
                })
            })
        {
            return Err(error(
                "AWS did not confirm DeleteOnTermination for the created disk",
            ));
        }
    }
    Ok(())
}

pub async fn delete(region: &str, id: &str, runner: &dyn CommandRunner) -> Result<(), CloudError> {
    // IDs, not names, are the deletion targets. A terminated instance may have
    // already removed this exact volume through DeleteOnTermination.
    match disk_inventory::aws_volume(region, id, runner).await {
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("InvalidVolume.NotFound") =>
        {
            return Ok(())
        }
        Err(e) => return Err(e),
        Ok(v) => {
            if v["VolumeId"] != id || v["Attachments"].as_array().is_none_or(|a| !a.is_empty()) {
                return Err(error(
                    "refusing to delete an attached or mismatched AWS disk",
                ));
            }
        }
    }
    runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "wait",
                "volume-available",
                "--region",
                region,
                "--volume-ids",
                id,
            ],
        )
        .await?;
    runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "delete-volume",
                "--region",
                region,
                "--volume-id",
                id,
            ],
        )
        .await?;
    Ok(())
}

pub async fn subnet_zone(
    region: &str,
    subnet: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let out = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-subnets",
                "--region",
                region,
                "--subnet-ids",
                subnet,
                "--output",
                "json",
            ],
        )
        .await?;
    let value: Value = serde_json::from_str(&out.stdout)?;
    if value["Subnets"][0]["SubnetId"] != subnet {
        return Err(error("AWS subnet identity mismatch"));
    }
    value["Subnets"][0]["AvailabilityZone"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| error("AWS subnet has no zone"))
}
