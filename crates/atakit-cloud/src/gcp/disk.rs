use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::DiskSpec;

/// Create a persistent disk.
pub async fn create_disk(
    project: &str,
    zone: &str,
    spec: &DiskSpec,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let key = format!("disk:{}", spec.device_name);
    let mut body = serde_json::json!({"name":spec.name,"sizeGb":spec.size_gb.to_string(),
        "type":format!("projects/{project}/zones/{zone}/diskTypes/{}",spec.disk_type)});
    if let Some(p) = &spec.performance {
        if let Some(iops) = p.iops {
            body["provisionedIops"] = iops.to_string().into();
        }
        if let Some(throughput) = p.throughput_mibps {
            body["provisionedThroughput"] = throughput.to_string().into();
        }
    }
    let created = runner
        .create_resource(
            &key,
            &crate::provisioning::CreateRequest::Gcp {
                project: project.into(),
                zone: zone.into(),
                collection: "disks".into(),
                body,
            },
        )
        .await?;
    let value = &created;
    if value["name"].as_str() != Some(&spec.name) {
        return Err(crate::provisioning::error(
            "GCP create returned a different disk name",
        ));
    }
    let observed = crate::disk_inventory::gcp_observation(value)?;
    // Track the resource even if the returned settings fail verification.
    let mut record = crate::disk_inventory::CreatedDisk {
        creation_verified: false,
        specification: spec.clone(),
        observed: observed.clone(),
    };
    runner.record_created_disk(&record).await?;
    crate::disk_inventory::require_empty_source(
        value,
        &[
            "sourceImage",
            "sourceSnapshot",
            "sourceDisk",
            "sourceInstantSnapshot",
        ],
    )?;
    crate::disk_inventory::validate(spec, &observed)?;
    record.creation_verified = true;
    runner.record_created_disk(&record).await?;
    let live = runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "disks",
                "describe",
                &spec.name,
                "--project",
                project,
                "--zone",
                zone,
                "--format=json",
            ],
        )
        .await?;
    let actual = crate::disk_inventory::gcp_observation(&serde_json::from_str(&live.stdout)?)?;
    if actual.id != record.observed.id {
        return Err(crate::provisioning::error(
            "GCP disk was replaced; refusing attachment",
        ));
    }
    crate::disk_inventory::validate(spec, &actual)?;
    Ok(())
}

/// Check if a disk exists.
pub async fn check_disk_exists(
    project: &str,
    zone: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    match runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "disks",
                "describe",
                name,
                "--project",
                project,
                "--zone",
                zone,
                "--format=json",
            ],
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(CloudError::CommandFailed { stderr, .. }) if stderr.contains("was not found") => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Delete a persistent disk.
pub async fn delete_disk(
    project: &str,
    zone: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "disks",
                "delete",
                name,
                "--project",
                project,
                "--zone",
                zone,
                "--quiet",
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. }) if stderr.contains("was not found") => {
            tracing::debug!("disk '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("disk/{name}"),
            message: e.to_string(),
        }),
    }
}
