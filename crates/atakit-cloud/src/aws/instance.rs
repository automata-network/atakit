use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::DiskSpec;

use std::time::Duration;

const REBOOT_TRANSITION_POLL_ATTEMPTS: usize = 60;
const REBOOT_TRANSITION_POLL_INTERVAL: Duration = Duration::from_secs(2);

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

async fn instance_status_checks(
    region: &str,
    instance_id: &str,
    runner: &dyn CommandRunner,
) -> Result<Vec<String>, CloudError> {
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-instance-status",
                "--region",
                region,
                "--instance-ids",
                instance_id,
                "--include-all-instances",
                "--query",
                "InstanceStatuses[0].[InstanceStatus.Status,SystemStatus.Status]",
                "--output",
                "text",
            ],
        )
        .await?;
    Ok(output
        .stdout
        .split_whitespace()
        .map(str::to_owned)
        .collect())
}

async fn wait_for_reboot_transition(
    region: &str,
    instance_id: &str,
    status_before_reboot: &[String],
    runner: &dyn CommandRunner,
    attempts: usize,
    interval: Duration,
) -> Result<(), CloudError> {
    for attempt in 0..attempts {
        let current = instance_status_checks(region, instance_id, runner)
            .await
            .map_err(|e| CloudError::InstanceError {
                message: format!(
                    "failed to observe AWS status checks for instance '{instance_id}' after reboot request: {e}"
                ),
            })?;
        if current != status_before_reboot {
            return Ok(());
        }
        if attempt + 1 < attempts {
            tokio::time::sleep(interval).await;
        }
    }

    Err(CloudError::InstanceError {
        message: format!(
            "AWS did not report a status-check transition for instance '{instance_id}' after reboot request"
        ),
    })
}

/// Reboot an EC2 instance, observe the reboot transition, and then wait for
/// both AWS instance status checks to pass again.
pub async fn reboot_instance(
    region: &str,
    instance_id: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let status_before_reboot = instance_status_checks(region, instance_id, runner)
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!(
                "failed to read AWS status checks for instance '{instance_id}' before reboot: {e}"
            ),
        })?;

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

    wait_for_reboot_transition(
        region,
        instance_id,
        &status_before_reboot,
        runner,
        REBOOT_TRANSITION_POLL_ATTEMPTS,
        REBOOT_TRANSITION_POLL_INTERVAL,
    )
    .await?;

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
    use crate::exec::CommandOutput;

    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        outputs: Mutex<VecDeque<String>>,
    }

    impl RecordingRunner {
        fn with_outputs(outputs: &[&str]) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                outputs: Mutex::new(outputs.iter().map(|output| output.to_string()).collect()),
            }
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
                .unwrap_or_default();
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
    async fn reboot_observes_transition_before_status_wait() {
        let runner = RecordingRunner::with_outputs(&["ok\tok\n", "", "initializing\tok\n", ""]);
        reboot_instance("us-east-2", "i-0123456789abcdef0", &runner)
            .await
            .expect("reboot instance");

        let calls = runner.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].0, "aws");
        assert_eq!(
            calls[0].1,
            [
                "ec2",
                "describe-instance-status",
                "--region",
                "us-east-2",
                "--instance-ids",
                "i-0123456789abcdef0",
                "--include-all-instances",
                "--query",
                "InstanceStatuses[0].[InstanceStatus.Status,SystemStatus.Status]",
                "--output",
                "text",
            ]
        );
        assert_eq!(calls[1].0, "aws");
        assert_eq!(
            calls[1].1,
            [
                "ec2",
                "reboot-instances",
                "--region",
                "us-east-2",
                "--instance-ids",
                "i-0123456789abcdef0",
            ]
        );
        assert_eq!(calls[2].0, "aws");
        assert_eq!(
            calls[2].1,
            [
                "ec2",
                "describe-instance-status",
                "--region",
                "us-east-2",
                "--instance-ids",
                "i-0123456789abcdef0",
                "--include-all-instances",
                "--query",
                "InstanceStatuses[0].[InstanceStatus.Status,SystemStatus.Status]",
                "--output",
                "text",
            ]
        );
        assert_eq!(calls[3].0, "aws");
        assert_eq!(
            calls[3].1,
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

    #[tokio::test]
    async fn reboot_transition_poll_rejects_unchanged_status() {
        let runner = RecordingRunner::with_outputs(&["ok\tok\n", "ok\tok\n"]);
        let status_before_reboot = vec!["ok".to_string(), "ok".to_string()];

        let error = wait_for_reboot_transition(
            "us-east-2",
            "i-0123456789abcdef0",
            &status_before_reboot,
            &runner,
            2,
            Duration::ZERO,
        )
        .await
        .expect_err("unchanged status must fail");

        assert!(error.to_string().contains(
            "AWS did not report a status-check transition for instance 'i-0123456789abcdef0'"
        ));
        assert_eq!(runner.calls.lock().expect("calls lock").len(), 2);
    }
}
