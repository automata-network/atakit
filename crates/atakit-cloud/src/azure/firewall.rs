use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Create a Network Security Group.
pub async fn create_nsg(
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    runner
        .run_capture(
            "az",
            &[
                "network",
                "nsg",
                "create",
                "--resource-group",
                rg,
                "--name",
                name,
            ],
        )
        .await
        .map_err(|e| CloudError::FirewallError {
            message: format!("failed to create NSG: {e}"),
        })?;
    Ok(())
}

/// Add NSG rules for the given ports with incrementing priorities.
///
/// Each entry in `ports` is `"port/proto"` (e.g. `"1024/tcp"`, `"5353/udp"`).
pub async fn add_nsg_rules(
    rg: &str,
    nsg: &str,
    ports: &[String],
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    for (i, entry) in ports.iter().enumerate() {
        let (port, proto) = entry.split_once('/').unwrap_or((entry, "tcp"));
        let priority = 100 + (i as u32) * 10;
        let rule_name = format!("allow-{port}-{proto}");

        runner
            .run_capture(
                "az",
                &[
                    "network",
                    "nsg",
                    "rule",
                    "create",
                    "--resource-group",
                    rg,
                    "--nsg-name",
                    nsg,
                    "--name",
                    &rule_name,
                    "--priority",
                    &priority.to_string(),
                    "--protocol",
                    &capitalize_proto(proto),
                    "--destination-port-ranges",
                    port,
                    "--access",
                    "Allow",
                    "--direction",
                    "Inbound",
                ],
            )
            .await
            .map_err(|e| CloudError::FirewallError {
                message: format!("failed to create NSG rule '{rule_name}': {e}"),
            })?;
    }
    Ok(())
}

/// Check if an NSG exists.
pub async fn check_nsg_exists(
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "network",
                "nsg",
                "show",
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

/// Delete an NSG.
pub async fn delete_nsg(
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "network",
                "nsg",
                "delete",
                "--resource-group",
                rg,
                "--name",
                name,
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("not found") || stderr.contains("NotFound") =>
        {
            tracing::debug!("NSG '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("nsg/{name}"),
            message: e.to_string(),
        }),
    }
}

/// Capitalize protocol name for Azure CLI (e.g. "tcp" -> "Tcp").
fn capitalize_proto(proto: &str) -> String {
    let mut chars = proto.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
    }
}
