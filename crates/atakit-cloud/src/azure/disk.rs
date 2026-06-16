use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::DiskSpec;

/// Create a managed disk.
pub async fn create_disk(
    subscription: &str,
    rg: &str,
    spec: &DiskSpec,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    runner
        .run_capture(
            "az",
            &[
                "disk",
                "create",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                &spec.name,
                "--size-gb",
                &spec.size_gb.to_string(),
                "--sku",
                "Premium_LRS",
            ],
        )
        .await
        .map_err(|e| CloudError::DiskError {
            message: format!("failed to create disk '{}': {e}", spec.name),
        })?;
    Ok(())
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
        Err(CloudError::CommandFailed { .. }) => Ok(false),
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
