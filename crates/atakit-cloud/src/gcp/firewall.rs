use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Create a firewall rule allowing traffic on specified ports.
///
/// Each entry in `ports` is `"port/proto"` (e.g. `"1024/tcp"`, `"5353/udp"`).
/// Falls back to TCP if no protocol suffix is present.
pub async fn create_firewall(
    project: &str,
    rule_name: &str,
    ports: &[String],
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    // Build gcloud --rules value: "tcp:1024,tcp:3000,udp:5353"
    let rules: Vec<String> = ports
        .iter()
        .map(|p| {
            let (port, proto) = p.split_once('/').unwrap_or((p, "tcp"));
            format!("{proto}:{port}")
        })
        .collect();
    let allow = rules.join(",");
    runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "firewall-rules",
                "create",
                rule_name,
                "--project",
                project,
                "--direction=INGRESS",
                "--action=ALLOW",
                &format!("--rules={allow}"),
                "--source-ranges=0.0.0.0/0",
                &format!("--target-tags={rule_name}"),
            ],
        )
        .await
        .map_err(|e| CloudError::FirewallError {
            message: format!("failed to create firewall rule: {e}"),
        })?;

    Ok(())
}

/// Check if a firewall rule exists.
pub async fn check_firewall_exists(
    project: &str,
    rule_name: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    match runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "firewall-rules",
                "describe",
                rule_name,
                "--project",
                project,
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

/// Delete a firewall rule.
pub async fn delete_firewall(
    project: &str,
    rule_name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "firewall-rules",
                "delete",
                rule_name,
                "--project",
                project,
                "--quiet",
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. }) if stderr.contains("was not found") => {
            tracing::debug!("firewall rule '{rule_name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("firewall/{rule_name}"),
            message: e.to_string(),
        }),
    }
}
