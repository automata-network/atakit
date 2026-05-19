use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Interval between `describe-import-snapshot-tasks` polls.
const IMPORT_POLL_SECS: u64 = 45;

/// Ensure the S3 bucket exists, creating it in `region` if needed.
pub async fn ensure_bucket(
    region: &str,
    bucket: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    // head-bucket succeeds only if the bucket exists and is accessible.
    if runner
        .run_capture("aws", &["s3api", "head-bucket", "--bucket", bucket])
        .await
        .is_ok()
    {
        return Ok(());
    }

    let location = format!("LocationConstraint={region}");
    let mut args = vec![
        "s3api",
        "create-bucket",
        "--bucket",
        bucket,
        "--region",
        region,
    ];
    // us-east-1 is the default location and rejects an explicit constraint.
    if region != "us-east-1" {
        args.push("--create-bucket-configuration");
        args.push(&location);
    }
    runner
        .run_capture("aws", &args)
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create S3 bucket: {e}"),
        })?;
    Ok(())
}

/// Upload the local VMDK to S3. Returns the S3 object key.
pub async fn upload_vmdk(
    bucket: &str,
    source_path: &str,
    runner: &dyn CommandRunner,
    verbose: bool,
) -> Result<String, CloudError> {
    let filename = std::path::Path::new(source_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("aws_disk.vmdk");
    let key = format!("vms/{filename}");
    let dest = format!("s3://{bucket}/{key}");
    runner
        .run_stream("aws", &["s3", "cp", source_path, &dest], verbose)
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to upload disk image: {e}"),
        })?;
    Ok(key)
}

/// Start an `import-snapshot` task for a VMDK in S3. Returns the task id.
pub async fn import_snapshot(
    region: &str,
    bucket: &str,
    key: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let container = serde_json::json!({
        "Description": "atakit CVM image",
        "Format": "vmdk",
        "UserBucket": { "S3Bucket": bucket, "S3Key": key },
    });
    // The disk-container spec is passed as a file:// reference to avoid
    // shell-quoting a JSON blob on the command line.
    let tmp = tempfile::Builder::new()
        .prefix("atakit-container")
        .suffix(".json")
        .tempfile()
        .map_err(CloudError::Io)?;
    std::fs::write(tmp.path(), serde_json::to_vec(&container)?).map_err(|e| {
        CloudError::IoPath {
            path: tmp.path().to_path_buf(),
            source: e,
        }
    })?;
    let disk_container = format!("file://{}", tmp.path().display());

    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "import-snapshot",
                "--region",
                region,
                "--description",
                "atakit CVM image",
                "--disk-container",
                &disk_container,
                "--output",
                "json",
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("import-snapshot failed: {e}"),
        })?;

    let parsed: serde_json::Value = serde_json::from_str(&output.stdout)?;
    parsed
        .get("ImportTaskId")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| CloudError::ImageUploadFailed {
            message: "import-snapshot returned no ImportTaskId".to_string(),
        })
}

/// Poll an import-snapshot task until it completes. Returns the snapshot id.
pub async fn wait_for_snapshot(
    region: &str,
    task_id: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    loop {
        let output = runner
            .run_capture(
                "aws",
                &[
                    "ec2",
                    "describe-import-snapshot-tasks",
                    "--region",
                    region,
                    "--import-task-ids",
                    task_id,
                    "--output",
                    "json",
                ],
            )
            .await
            .map_err(|e| CloudError::ImageUploadFailed {
                message: format!("failed to poll import task: {e}"),
            })?;

        let parsed: serde_json::Value = serde_json::from_str(&output.stdout)?;
        let detail = parsed
            .get("ImportSnapshotTasks")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|t| t.get("SnapshotTaskDetail"));
        let status = detail
            .and_then(|d| d.get("Status"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match status {
            "completed" => {
                let snapshot = detail
                    .and_then(|d| d.get("SnapshotId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if snapshot.is_empty() {
                    return Err(CloudError::ImageUploadFailed {
                        message: "import completed but no SnapshotId returned".to_string(),
                    });
                }
                return Ok(snapshot.to_string());
            }
            "deleted" | "deleting" => {
                let message = detail
                    .and_then(|d| d.get("StatusMessage"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error");
                return Err(CloudError::ImageUploadFailed {
                    message: format!("snapshot import failed: {message}"),
                });
            }
            _ => {
                let progress = detail
                    .and_then(|d| d.get("Progress"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0");
                tracing::info!("snapshot import: {status} ({progress}%)");
                tokio::time::sleep(std::time::Duration::from_secs(IMPORT_POLL_SECS)).await;
            }
        }
    }
}

/// Find the id of an AMI owned by this account with the given name.
pub async fn find_ami(
    region: &str,
    ami_name: &str,
    runner: &dyn CommandRunner,
) -> Result<Option<String>, CloudError> {
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-images",
                "--region",
                region,
                "--owners",
                "self",
                "--filters",
                &format!("Name=name,Values={ami_name}"),
                "--query",
                "Images[*].ImageId",
                "--output",
                "text",
            ],
        )
        .await?;
    Ok(output
        .stdout
        .split_whitespace()
        .find(|s| !s.is_empty() && *s != "None")
        .map(String::from))
}

/// Deregister every AMI with the given name and delete their backing
/// snapshots. Idempotent: a no-op when no matching AMI exists.
pub async fn deregister_ami_by_name(
    region: &str,
    ami_name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-images",
                "--region",
                region,
                "--owners",
                "self",
                "--filters",
                &format!("Name=name,Values={ami_name}"),
                "--query",
                "Images[*].ImageId",
                "--output",
                "text",
            ],
        )
        .await?;
    let ids: Vec<String> = output
        .stdout
        .split_whitespace()
        .filter(|s| !s.is_empty() && *s != "None")
        .map(String::from)
        .collect();
    for ami_id in ids {
        deregister_ami(region, &ami_id, runner).await?;
    }
    Ok(())
}

/// Deregister a single AMI by id and delete its backing snapshots.
async fn deregister_ami(
    region: &str,
    ami_id: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    // Collect snapshot ids before the AMI is deregistered.
    let snapshots: Vec<String> = match runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-images",
                "--region",
                region,
                "--image-ids",
                ami_id,
                "--query",
                "Images[0].BlockDeviceMappings[*].Ebs.SnapshotId",
                "--output",
                "text",
            ],
        )
        .await
    {
        Ok(o) => o
            .stdout
            .split_whitespace()
            .filter(|s| !s.is_empty() && *s != "None")
            .map(String::from)
            .collect(),
        Err(_) => Vec::new(),
    };

    match runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "deregister-image",
                "--region",
                region,
                "--image-id",
                ami_id,
            ],
        )
        .await
    {
        Ok(_) => {}
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("InvalidAMIID.NotFound") =>
        {
            tracing::debug!("AMI '{ami_id}' already deregistered");
        }
        Err(e) => {
            return Err(CloudError::DestroyFailed {
                resource: format!("ami/{ami_id}"),
                message: e.to_string(),
            });
        }
    }

    for snapshot in snapshots {
        delete_snapshot(region, &snapshot, runner).await?;
    }
    Ok(())
}

/// Delete an EBS snapshot. Idempotent.
async fn delete_snapshot(
    region: &str,
    snapshot_id: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "delete-snapshot",
                "--region",
                region,
                "--snapshot-id",
                snapshot_id,
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("InvalidSnapshot.NotFound") =>
        {
            tracing::debug!("snapshot '{snapshot_id}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("snapshot/{snapshot_id}"),
            message: e.to_string(),
        }),
    }
}

/// Register an imported snapshot as a Secure Boot, SEV-SNP-capable AMI.
///
/// The AMI's UEFI variables are seeded from `aws-uefi-blob.bin` (expected
/// under `certs_dir`) so Secure Boot is enabled with custom keys. atakit
/// requires Secure Boot on every CVM deploy — there is no soft fallback.
/// Returns the new AMI id.
pub async fn register_ami(
    region: &str,
    ami_name: &str,
    snapshot_id: &str,
    certs_dir: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let blob = std::path::Path::new(certs_dir).join("aws-uefi-blob.bin");
    if !blob.exists() {
        return Err(CloudError::ImageUploadFailed {
            message: format!(
                "AWS UEFI Secure Boot blob missing: expected '{}'. The base \
                 image archive (.atabi) must ship aws-uefi-blob.bin alongside \
                 secure_boot_certs/. atakit requires Secure Boot on every CVM deploy.",
                blob.display(),
            ),
        });
    }
    let uefi_data = format!("file://{}", blob.display());
    let block_mapping = format!(
        "DeviceName=/dev/xvda,Ebs={{SnapshotId={snapshot_id},DeleteOnTermination=true}}"
    );

    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "register-image",
                "--region",
                region,
                "--name",
                ami_name,
                "--root-device-name",
                "/dev/xvda",
                "--block-device-mappings",
                &block_mapping,
                "--architecture",
                "x86_64",
                "--virtualization-type",
                "hvm",
                "--ena-support",
                "--tpm-support",
                "v2.0",
                "--boot-mode",
                "uefi",
                "--uefi-data",
                &uefi_data,
                "--output",
                "json",
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to register AMI: {e}"),
        })?;

    let parsed: serde_json::Value = serde_json::from_str(&output.stdout)?;
    parsed
        .get("ImageId")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| CloudError::ImageUploadFailed {
            message: "register-image returned no ImageId".to_string(),
        })
}

/// Delete an S3 bucket and all of its contents. Idempotent.
pub async fn delete_bucket(bucket: &str, runner: &dyn CommandRunner) -> Result<(), CloudError> {
    match runner
        .run_capture("aws", &["s3", "rb", &format!("s3://{bucket}"), "--force"])
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("NoSuchBucket") || stderr.contains("does not exist") =>
        {
            tracing::debug!("bucket '{bucket}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("bucket/{bucket}"),
            message: e.to_string(),
        }),
    }
}
