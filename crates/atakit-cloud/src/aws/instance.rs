use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::DiskSpec;

/// Find a subnet to launch into, preferring a default-for-AZ subnet so the
/// instance receives an auto-assigned public IP.
pub async fn find_subnet(region: &str, runner: &dyn CommandRunner) -> Result<String, CloudError> {
    let default = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-subnets",
                "--region",
                region,
                "--filters",
                "Name=default-for-az,Values=true",
                "--query",
                "Subnets[0].SubnetId",
                "--output",
                "text",
            ],
        )
        .await?;
    let id = default.stdout.trim();
    if !id.is_empty() && id != "None" {
        return Ok(id.to_string());
    }

    // Fall back to any subnet in the region.
    let any = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-subnets",
                "--region",
                region,
                "--query",
                "Subnets[0].SubnetId",
                "--output",
                "text",
            ],
        )
        .await?;
    let id = any.stdout.trim();
    if id.is_empty() || id == "None" {
        return Err(CloudError::InstanceError {
            message: format!("no subnet found in region '{region}'"),
        });
    }
    Ok(id.to_string())
}

/// Launch a SEV-SNP EC2 instance. Returns `(instance_id, public_ip)`.
#[allow(clippy::too_many_arguments)]
pub async fn create_instance(
    region: &str,
    name: &str,
    instance_type: &str,
    ami_id: &str,
    sg_id: &str,
    subnet_id: &str,
    metadata: &[(String, String)],
    disks: &[DiskSpec],
    boot_disk_size_gb: Option<u64>,
    runner: &dyn CommandRunner,
) -> Result<(String, String), CloudError> {
    // Block device mappings (JSON, to safely carry the nested Ebs object).
    let mut mappings = Vec::new();
    if let Some(gb) = boot_disk_size_gb {
        mappings.push(serde_json::json!({
            "DeviceName": "/dev/xvda",
            "Ebs": { "VolumeSize": gb, "DeleteOnTermination": true },
        }));
    }
    for disk in disks {
        // Map the manifest disk index to an EBS device letter (f, g, h...).
        let letter = (b'f' + disk.index as u8) as char;
        mappings.push(serde_json::json!({
            "DeviceName": format!("/dev/sd{letter}"),
            "Ebs": {
                "VolumeSize": disk.size_gb,
                "VolumeType": disk.disk_type,
                "DeleteOnTermination": true,
            },
        }));
    }

    // Instance tags: the Name tag plus metadata (AWS equivalent of GCP labels).
    let mut tags = vec![serde_json::json!({ "Key": "Name", "Value": name })];
    for (k, v) in metadata {
        tags.push(serde_json::json!({ "Key": k, "Value": v }));
    }
    let tag_spec =
        serde_json::to_string(&serde_json::json!([{ "ResourceType": "instance", "Tags": tags }]))?;

    let mut args: Vec<String> = vec![
        "ec2".into(),
        "run-instances".into(),
        "--region".into(),
        region.into(),
        "--image-id".into(),
        ami_id.into(),
        "--instance-type".into(),
        instance_type.into(),
        "--subnet-id".into(),
        subnet_id.into(),
        "--security-group-ids".into(),
        sg_id.into(),
        "--cpu-options".into(),
        "AmdSevSnp=enabled".into(),
        "--associate-public-ip-address".into(),
        "--tag-specifications".into(),
        tag_spec,
        "--output".into(),
        "json".into(),
    ];
    if !mappings.is_empty() {
        args.push("--block-device-mappings".into());
        args.push(serde_json::to_string(&mappings)?);
    }

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output =
        runner
            .run_capture("aws", &arg_refs)
            .await
            .map_err(|e| CloudError::InstanceError {
                message: format!("failed to create instance: {e}"),
            })?;

    let parsed: serde_json::Value = serde_json::from_str(&output.stdout)?;
    let instance_id = parsed
        .get("Instances")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|i| i.get("InstanceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| CloudError::InstanceError {
            message: "run-instances returned no InstanceId".to_string(),
        })?
        .to_string();

    runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "wait",
                "instance-running",
                "--region",
                region,
                "--instance-ids",
                &instance_id,
            ],
        )
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!("instance did not reach running state: {e}"),
        })?;

    let ip = get_instance_public_ip(region, &instance_id, runner)
        .await?
        .unwrap_or_default();
    if ip.is_empty() {
        tracing::warn!("could not determine public IP for instance {instance_id}");
    }
    Ok((instance_id, ip))
}

/// Get the public IP of an instance.
pub async fn get_instance_public_ip(
    region: &str,
    instance_id: &str,
    runner: &dyn CommandRunner,
) -> Result<Option<String>, CloudError> {
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-instances",
                "--region",
                region,
                "--instance-ids",
                instance_id,
                "--query",
                "Reservations[0].Instances[0].PublicIpAddress",
                "--output",
                "text",
            ],
        )
        .await?;
    let ip = output.stdout.trim();
    if ip.is_empty() || ip == "None" {
        Ok(None)
    } else {
        Ok(Some(ip.to_string()))
    }
}

/// Terminate an instance and wait for it to fully terminate, so dependent
/// resources (e.g. the security group) can be deleted afterwards.
pub async fn terminate_instance(
    region: &str,
    instance_id: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "terminate-instances",
                "--region",
                region,
                "--instance-ids",
                instance_id,
            ],
        )
        .await
    {
        Ok(_) => {}
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("InvalidInstanceID.NotFound") =>
        {
            tracing::debug!("instance '{instance_id}' already terminated");
            return Ok(());
        }
        Err(e) => {
            return Err(CloudError::DestroyFailed {
                resource: format!("instance/{instance_id}"),
                message: e.to_string(),
            });
        }
    }

    runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "wait",
                "instance-terminated",
                "--region",
                region,
                "--instance-ids",
                instance_id,
            ],
        )
        .await
        .map_err(|e| CloudError::DestroyFailed {
            resource: format!("instance/{instance_id}"),
            message: format!("instance did not terminate: {e}"),
        })?;
    Ok(())
}

/// Get console (serial) output for an instance.
pub async fn get_console_output(
    region: &str,
    instance_id: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "get-console-output",
                "--region",
                region,
                "--instance-id",
                instance_id,
                "--latest",
                "--query",
                "Output",
                "--output",
                "text",
            ],
        )
        .await?;
    Ok(output.stdout)
}
