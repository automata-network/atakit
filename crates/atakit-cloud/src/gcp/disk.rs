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
    runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "disks",
                "create",
                &spec.name,
                "--project",
                project,
                "--zone",
                zone,
                &format!("--size={}GB", spec.size_gb),
                &format!("--type={}", spec.disk_type),
            ],
        )
        .await
        .map_err(|e| CloudError::DiskError {
            message: format!("failed to create disk '{}': {e}", spec.name),
        })?;

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
