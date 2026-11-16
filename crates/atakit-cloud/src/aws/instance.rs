use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::DiskSpec;

fn apply_disk_performance(
    ebs: &mut serde_json::Value,
    performance: &crate::disk_profiles::DiskPerformance,
) {
    ebs["VolumeType"] = performance.disk_type.clone().into();
    if let Some(iops) = performance.iops {
        ebs["Iops"] = iops.into();
    }
    if let Some(throughput) = performance.throughput_mibps {
        ebs["Throughput"] = throughput.into();
    }
}

pub(super) fn validate_static_ip_allocation_id(allocation_id: &str) -> Result<(), CloudError> {
    if !allocation_id
        .strip_prefix("eipalloc-")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(CloudError::Config {
            message: "AWS static_ip must be an Elastic IP allocation ID (eipalloc-...), not an IP address or name".into(),
        });
    }
    Ok(())
}

/// Resolve an operator-owned allocation before creating a VM. Do not take an
/// address from an existing instance, network interface, or NAT gateway.
async fn resolve_static_ip_address_for_instance(
    region: &str,
    allocation_id: &str,
    expected_instance: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    validate_static_ip_allocation_id(allocation_id)?;
    let error = |message| CloudError::InstanceError {
        message: format!("AWS static_ip '{allocation_id}' in region '{region}': {message}"),
    };
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-addresses",
                "--region",
                region,
                "--allocation-ids",
                allocation_id,
                "--output",
                "json",
            ],
        )
        .await
        .map_err(|e| error(format!("failed to look up Elastic IP: {e}")))?;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Address {
        allocation_id: String,
        public_ip: String,
        domain: String,
        association_id: Option<String>,
        instance_id: Option<String>,
        network_interface_id: Option<String>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Addresses {
        addresses: Vec<Address>,
    }
    let response: Addresses = serde_json::from_str(&output.stdout)
        .map_err(|e| error(format!("invalid describe-addresses response: {e}")))?;
    let [address] = response.addresses.as_slice() else {
        return Err(error("expected exactly one Elastic IP allocation".into()));
    };
    if address.allocation_id != allocation_id || address.domain != "vpc" {
        return Err(error(
            "response does not match the requested VPC Elastic IP allocation".into(),
        ));
    }
    if [
        &address.association_id,
        &address.instance_id,
        &address.network_interface_id,
    ]
    .iter()
    .any(|value| value.as_ref().is_some_and(|value| !value.is_empty()))
        && !(expected_instance.is_some() && address.instance_id.as_deref() == expected_instance)
    {
        return Err(error(
            "Elastic IP is already associated with another resource; choose an unassociated allocation".into(),
        ));
    }
    address
        .public_ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| error("Elastic IP did not return a valid public IPv4 address".into()))?;
    Ok(address.public_ip.clone())
}

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
    boot_disk_performance: Option<&crate::disk_profiles::DiskPerformance>,
    static_ip: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<(String, String), CloudError> {
    if !disks.is_empty() {
        return Err(crate::provisioning::error(
            "AWS workload disks must use explicit volume creation and attachment",
        ));
    }
    let saved = runner.recorded_creation("instance").await?;
    let previous_id = saved
        .as_ref()
        .and_then(|s| s.result.as_ref())
        .and_then(|v| v["Instances"][0]["InstanceId"].as_str());
    let static_ip_address = match static_ip {
        Some(allocation_id) => Some(
            resolve_static_ip_address_for_instance(region, allocation_id, previous_id, runner)
                .await?,
        ),
        None => None,
    };

    // Block device mappings (JSON, to safely carry the nested Ebs object).
    let mut mappings = Vec::new();
    if let Some(gb) = boot_disk_size_gb {
        mappings.push(serde_json::json!({
            "DeviceName": "/dev/xvda",
            "Ebs": { "VolumeSize": gb, "DeleteOnTermination": true },
        }));
    }
    if boot_disk_size_gb.is_some() {
        if let Some(performance) = boot_disk_performance {
            apply_disk_performance(&mut mappings[0]["Ebs"], performance);
        }
    }
    // Instance tags: the Name tag plus metadata (AWS equivalent of GCP labels).
    let mut tags = vec![serde_json::json!({ "Key": "Name", "Value": name })];
    for (k, v) in metadata {
        if k == "atakit-init-auth" {
            continue;
        }
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
        if static_ip.is_some() {
            "--no-associate-public-ip-address"
        } else {
            "--associate-public-ip-address"
        }
        .into(),
        "--tag-specifications".into(),
        tag_spec,
        "--output".into(),
        "json".into(),
    ];
    if let Some((_, bootstrap)) = metadata.iter().find(|(key, _)| key == "atakit-init-auth") {
        args.extend([
            "--user-data".into(),
            atakit_init_auth::encode_user_data(&serde_json::from_str(bootstrap)?)?,
            "--metadata-options".into(),
            "HttpEndpoint=enabled,HttpTokens=required".into(),
        ]);
    }
    if !mappings.is_empty() {
        args.push("--block-device-mappings".into());
        args.push(serde_json::to_string(&mappings)?);
    }

    let request = saved
        .map(|s| s.request)
        .unwrap_or(crate::provisioning::CreateRequest::Aws { args });
    let parsed = runner.create_resource("instance", &request).await?;
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
        .record_created_instance(&instance_id, "", false, Some(&instance_id))
        .await?;
    let original = &parsed["Instances"][0];
    let has_boot_reference = original["BlockDeviceMappings"]
        .as_array()
        .is_some_and(|disks| !disks.is_empty());
    if has_boot_reference {
        runner
            .record_boot_disk(
                &crate::disk_inventory::aws_boot_from_vm(region, original, runner).await?,
            )
            .await?;
    }
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

    // RunInstances can return before the root attachment is available. Read
    // it once running, before IP association or any workload disk work.
    if !has_boot_reference {
        runner
            .record_boot_disk(&crate::disk_inventory::aws_boot(region, &instance_id, runner).await?)
            .await?;
    }

    let ip = if let Some((allocation_id, ip)) = static_ip.zip(static_ip_address) {
        runner
            .run_capture(
                "aws",
                &[
                    "ec2",
                    "associate-address",
                    "--region",
                    region,
                    "--allocation-id",
                    allocation_id,
                    "--instance-id",
                    &instance_id,
                    // Also protect against another caller attaching the address
                    // after our lookup and before this request.
                    "--no-allow-reassociation",
                    "--output",
                    "json",
                ],
            )
            .await
            .map_err(|e| CloudError::InstanceError {
                message: format!(
                    "failed to associate Elastic IP '{allocation_id}' with instance '{instance_id}' in region '{region}': {e}"
                ),
            })?;
        // Persist the reserved address and finish provisioning only after the
        // attachment succeeds. Failures retain the instance for cloud destroy.
        runner
            .record_created_instance(&instance_id, &ip, true, Some(&instance_id))
            .await?;
        // Use the allocation lookup, avoiding a stale instance IP read after
        // association. Portal readiness will wait for the address to be usable.
        ip
    } else {
        get_instance_public_ip(region, &instance_id, runner)
            .await?
            .unwrap_or_default()
    };
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

/// Request an EC2 instance reboot, then require both current AWS instance
/// status checks to pass.
///
/// AWS can keep both status checks at `ok` throughout an operating-system
/// reboot. A status-check transition is therefore not proof that a reboot was
/// accepted or completed and must not be required here.
pub async fn reboot_instance(
    region: &str,
    instance_id: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "reboot-instances",
                "--region",
                region,
                "--instance-ids",
                instance_id,
            ],
        )
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!("failed to reboot instance '{instance_id}': {e}"),
        })?;

    runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "wait",
                "instance-status-ok",
                "--region",
                region,
                "--instance-ids",
                instance_id,
            ],
        )
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!(
                "instance '{instance_id}' did not pass AWS status checks after reboot: {e}"
            ),
        })?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::aws::AwsProvider;
    use crate::config::PlatformKind;
    use crate::exec::CommandOutput;
    use crate::plan::{DeployStep, DestroyStep};
    use crate::provider::{CloudProvider, DestroyOptions};
    use crate::resume::DeploymentRunner;
    use crate::state::{AwsResources, DeployState, NewDeployParams};

    const ALLOCATION: &str = "eipalloc-0123456789abcdef0";
    const ADDRESS: &str = r#"{"Addresses":[{"AllocationId":"eipalloc-0123456789abcdef0","PublicIp":"203.0.113.10","Domain":"vpc"}]}"#;

    #[tokio::test]
    async fn boot_profile_applies_only_to_new_instance_creation() {
        let runner = RecordingRunner::with_outputs(&[
            r#"{"Instances":[{"InstanceId":"i-new"}]}"#,
            "",
            r#"{"Reservations":[{"Instances":[{"InstanceId":"i-new","RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"vol-root"}}]}]}]}"#,
            r#"{"Volumes":[{"VolumeId":"vol-root","VolumeType":"gp3","Size":32}]}"#,
            "203.0.113.10",
        ]);
        let performance = crate::disk_profiles::DiskPerformance {
            profile: Some("fast".into()),
            disk_type: "gp3".into(),
            iops: Some(6000),
            throughput_mibps: Some(250),
        };
        create_instance(
            "region",
            "vm",
            "m6a.xlarge",
            "ami",
            "sg",
            "subnet",
            &[],
            &[],
            Some(32),
            Some(&performance),
            None,
            &runner,
        )
        .await
        .unwrap();
        let calls = runner.calls.lock().unwrap();
        let args = &calls[0].1;
        let pos = args
            .iter()
            .position(|v| v == "--block-device-mappings")
            .unwrap();
        let mappings: serde_json::Value = serde_json::from_str(&args[pos + 1]).unwrap();
        for entry in mappings.as_array().unwrap() {
            assert_eq!(entry["Ebs"]["VolumeType"], "gp3");
            assert_eq!(entry["Ebs"]["Iops"], 6000);
            assert_eq!(entry["Ebs"]["Throughput"], 250);
        }
        assert_eq!(mappings[0]["Ebs"]["VolumeSize"], 32);
        assert_eq!(mappings.as_array().unwrap().len(), 1);
        assert!(calls
            .iter()
            .all(|(_, args)| !args.iter().any(|v| v == "modify-volume")));
    }

    fn instance_step() -> DeployStep {
        DeployStep::CreateInstanceAws {
            boot_disk_performance: None,
            instance_name: "vm".into(),
            instance_type: "m6a.large".into(),
            image_name: "image".into(),
            security_group: "sg".into(),
            metadata: Vec::new(),
            disks: Vec::new(),
            boot_disk_size_gb: None,
            static_ip: Some(ALLOCATION.into()),
        }
    }

    fn saved_state() -> (tempfile::TempDir, DeployState) {
        let dir = tempfile::tempdir().unwrap();
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "vm".into(),
            target_name: "target".into(),
            provider_name: "aws-test".into(),
            platform: PlatformKind::Aws,
            workload_publisher: format!("0x{}", "11".repeat(32)),
            workload_name: "workload".into(),
            workload_version: "v1".into(),
            image_ref: "image:v1".into(),
            base_image_ref: None,
            archive_path: String::new(),
            archive_hash: String::new(),
            init_env: Default::default(),
            portal_ports: Default::default(),
            total_steps: 1,
        });
        state.resources.aws = Some(AwsResources {
            region: "us-east-2".into(),
            ..Default::default()
        });
        state.save(dir.path()).unwrap();
        (dir, state)
    }

    #[tokio::test]
    async fn static_ip_provider_step_attaches_and_records_reserved_address() {
        let provider = AwsProvider::new("us-east-2".into());
        let runner = RecordingRunner::with_outputs(&[
            "ami-123", // AMI lookup
            "sg-123",  // Security group lookup
            "subnet-123",
            ADDRESS,
            r#"{"Instances":[{"InstanceId":"i-123"}]}"#,
            "", // Instance running
            r#"{"Reservations":[{"Instances":[{"InstanceId":"i-123","RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"vol-root"}}]}]}]}"#,
            r#"{"Volumes":[{"VolumeId":"vol-root","VolumeType":"gp3","Size":32}]}"#,
            r#"{"AssociationId":"eipassoc-123"}"#,
        ]);
        let (dir, _) = saved_state();
        let recorded = DeploymentRunner {
            runner: &runner,
            data_dir: dir.path(),
            target: "target",
            instance: "vm",
        };
        let result = provider
            .execute_step(&instance_step(), &recorded, false)
            .await
            .unwrap();
        assert_eq!(
            result.resource_updates.external_ip.as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(result.resource_updates.instance.as_deref(), Some("i-123"));
        let state = DeployState::load(dir.path(), "target", "vm").unwrap();
        assert!(state.provisioning_complete);
        assert_eq!(state.cloud_instance_id.as_deref(), Some("i-123"));
        assert_eq!(
            state.resources.aws.as_ref().unwrap().external_ip.as_deref(),
            Some("203.0.113.10")
        );

        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 9);
        assert_eq!(
            calls[3].1,
            [
                "ec2",
                "describe-addresses",
                "--region",
                "us-east-2",
                "--allocation-ids",
                ALLOCATION,
                "--output",
                "json"
            ]
        );
        assert!(calls[4]
            .1
            .iter()
            .any(|a| a == "--no-associate-public-ip-address"));
        assert!(!calls[4]
            .1
            .iter()
            .any(|a| a == "--associate-public-ip-address"));
        assert_eq!(&calls[5].1[..3], ["ec2", "wait", "instance-running"]);
        assert_eq!(
            calls[8].1,
            [
                "ec2",
                "associate-address",
                "--region",
                "us-east-2",
                "--allocation-id",
                ALLOCATION,
                "--instance-id",
                "i-123",
                "--no-allow-reassociation",
                "--output",
                "json"
            ]
        );
    }

    #[tokio::test]
    async fn static_ip_rejects_unusable_allocations_before_creating_a_vm() {
        let address: serde_json::Value = serde_json::from_str(ADDRESS).unwrap();
        let mut cases = vec![serde_json::json!({"Addresses": []}), serde_json::json!({})];
        for (key, value) in [
            ("AssociationId", "eipassoc-123"),
            ("InstanceId", "i-other"),
            ("NetworkInterfaceId", "eni-nat"),
            ("Domain", "standard"),
            ("AllocationId", "eipalloc-00000000"),
            ("PublicIp", ""),
            ("PublicIp", "not-an-ip"),
            ("PublicIp", "2001:db8::1"),
        ] {
            let mut response = address.clone();
            response["Addresses"][0][key] = value.into();
            cases.push(response);
        }
        for missing in ["PublicIp", "AllocationId", "Domain"] {
            let mut response = address.clone();
            response["Addresses"][0]
                .as_object_mut()
                .unwrap()
                .remove(missing);
            cases.push(response);
        }
        cases.push(
            serde_json::json!({"Addresses": [address["Addresses"][0], address["Addresses"][0]]}),
        );
        for response in cases {
            let runner = RecordingRunner::with_outputs(&[&response.to_string()]);
            let err = create_instance(
                "us-east-2",
                "vm",
                "m6a.large",
                "ami",
                "sg",
                "subnet",
                &[],
                &[],
                None,
                None,
                Some(ALLOCATION),
                &runner,
            )
            .await
            .unwrap_err();
            assert!(err.to_string().contains(ALLOCATION), "{err}");
            assert_eq!(runner.calls.lock().unwrap().len(), 1, "{response}");
        }
    }

    #[tokio::test]
    async fn static_ip_lookup_failure_stops_before_vm_creation() {
        let runner =
            RecordingRunner::with_outputs(&[]).with_failure("InvalidAllocationID.NotFound");
        let err = create_instance(
            "us-east-2",
            "vm",
            "m6a.large",
            "ami",
            "sg",
            "subnet",
            &[],
            &[],
            None,
            None,
            Some(ALLOCATION),
            &runner,
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        for expected in [ALLOCATION, "us-east-2", "InvalidAllocationID.NotFound"] {
            assert!(message.contains(expected), "{message}");
        }
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn static_ip_failure_retains_incomplete_vm_for_destroy_without_releasing_address() {
        for failure in [
            "instance waiter failed",
            "Resource.AlreadyAssociated",
            "UnauthorizedOperation",
        ] {
            let mut outputs = vec![
                "ami-123",
                "sg-123",
                "subnet-123",
                ADDRESS,
                r#"{"Instances":[{"InstanceId":"i-123"}]}"#,
            ];
            if failure != "instance waiter failed" {
                outputs.extend(["", r#"{"Reservations":[{"Instances":[{"InstanceId":"i-123","RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"vol-root"}}]}]}]}"#, r#"{"Volumes":[{"VolumeId":"vol-root","VolumeType":"gp3","Size":32}]}"#]);
            }
            let runner = RecordingRunner::with_outputs(&outputs).with_failure(failure);
            let (dir, _) = saved_state();
            let recorded = DeploymentRunner {
                runner: &runner,
                data_dir: dir.path(),
                target: "target",
                instance: "vm",
            };
            let provider = AwsProvider::new("us-east-2".into());
            let err = provider
                .execute_step(&instance_step(), &recorded, false)
                .await
                .err()
                .unwrap();
            assert!(err.to_string().contains(failure), "{err}");
            let state = DeployState::load(dir.path(), "target", "vm").unwrap();
            assert!(!state.provisioning_complete);
            assert_eq!(state.cloud_instance_id.as_deref(), Some("i-123"));
            assert_eq!(
                state.resources.aws.as_ref().unwrap().instance.as_deref(),
                Some("i-123")
            );
            assert_eq!(state.resources.aws.as_ref().unwrap().external_ip, None);
            let plan = provider
                .plan_destroy(&state, &DestroyOptions { preserve: vec![] })
                .unwrap();
            assert!(
                matches!(plan.steps.as_slice(), [DestroyStep::DeleteInstance { name }] if name == "i-123")
            );
            // These are recorded commands only; this test never calls AWS.
            let cleanup = RecordingRunner::with_outputs(&["", ""]);
            provider
                .execute_destroy_step(&plan.steps[0], &cleanup, false)
                .await
                .unwrap();
            let calls = cleanup.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].1[1], "terminate-instances");
            assert_eq!(&calls[1].1[..3], ["ec2", "wait", "instance-terminated"]);
        }
    }

    #[tokio::test]
    async fn init_bootstrap_uses_user_data_and_requires_imdsv2() {
        let runner = RecordingRunner::with_outputs(&[
            r#"{"Instances":[{"InstanceId":"i-123"}]}"#,
            "",
            r#"{"Reservations":[{"Instances":[{"InstanceId":"i-123","RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"vol-root"}}]}]}]}"#,
            r#"{"Volumes":[{"VolumeId":"vol-root","VolumeType":"gp3","Size":32}]}"#,
            "203.0.113.30",
        ]);
        let public = r#"{"format":1,"scheme":"atakit-init-es256k-v1","public_key":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","deployment_id":"1111111111111111111111111111111111111111111111111111111111111111"}"#;
        create_instance(
            "region",
            "vm",
            "m6a.large",
            "ami",
            "sg",
            "subnet",
            &[("atakit-init-auth".into(), public.into())],
            &[],
            None,
            None,
            None,
            &runner,
        )
        .await
        .unwrap();
        let calls = runner.calls.lock().unwrap();
        let args = &calls[0].1;
        let index = args.iter().position(|arg| arg == "--user-data").unwrap();
        let decoded = atakit_init_auth::decode_user_data(&args[index + 1])
            .unwrap()
            .unwrap();
        assert_eq!(decoded, serde_json::from_str(public).unwrap());
        assert!(args
            .iter()
            .any(|arg| arg == "HttpEndpoint=enabled,HttpTokens=required"));
        let tags = args
            .iter()
            .position(|arg| arg == "--tag-specifications")
            .unwrap();
        assert!(!args[tags + 1].contains("atakit-init-auth"));
        assert!(args
            .iter()
            .any(|arg| arg == "--associate-public-ip-address"));
        assert!(!args
            .iter()
            .any(|arg| arg == "--no-associate-public-ip-address"));
        assert_eq!(calls.len(), 5);
    }

    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        outputs: Mutex<VecDeque<Result<String, &'static str>>>,
    }

    impl RecordingRunner {
        fn with_outputs(outputs: &[&str]) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                outputs: Mutex::new(
                    outputs
                        .iter()
                        .map(|output| Ok(output.to_string()))
                        .collect(),
                ),
            }
        }

        fn with_failure(mut self, message: &'static str) -> Self {
            self.outputs.get_mut().unwrap().push_back(Err(message));
            self
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for RecordingRunner {
        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            self.calls.lock().expect("calls lock").push((
                program.to_string(),
                args.iter().map(|arg| (*arg).to_string()).collect(),
            ));
            let stdout = self
                .outputs
                .lock()
                .expect("outputs lock")
                .pop_front()
                .expect("unexpected AWS command")
                .map_err(|message| CloudError::CommandFailed {
                    program: program.into(),
                    args: args.join(" "),
                    stderr: message.into(),
                    code: Some(1),
                })?;
            Ok(CommandOutput {
                status: 0,
                stdout,
                stderr: String::new(),
            })
        }

        async fn run_stream(
            &self,
            _program: &str,
            _args: &[&str],
            _verbose: bool,
        ) -> Result<CommandOutput, CloudError> {
            panic!("run_stream must not be called")
        }
    }

    #[tokio::test]
    async fn reboot_accepts_request_without_requiring_status_transition() {
        let runner = RecordingRunner::with_outputs(&["", ""]);
        reboot_instance("us-east-2", "i-0123456789abcdef0", &runner)
            .await
            .expect("reboot instance");

        let calls = runner.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "aws");
        assert_eq!(
            calls[0].1,
            [
                "ec2",
                "reboot-instances",
                "--region",
                "us-east-2",
                "--instance-ids",
                "i-0123456789abcdef0",
            ]
        );
        assert_eq!(calls[1].0, "aws");
        assert_eq!(
            calls[1].1,
            [
                "ec2",
                "wait",
                "instance-status-ok",
                "--region",
                "us-east-2",
                "--instance-ids",
                "i-0123456789abcdef0",
            ]
        );
    }
}
