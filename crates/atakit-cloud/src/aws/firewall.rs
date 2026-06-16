use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Look up the default VPC id for the region.
pub async fn default_vpc_id(
    region: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-vpcs",
                "--region",
                region,
                "--filters",
                "Name=isDefault,Values=true",
                "--query",
                "Vpcs[0].VpcId",
                "--output",
                "text",
            ],
        )
        .await?;
    let id = output.stdout.trim();
    if id.is_empty() || id == "None" {
        return Err(CloudError::FirewallError {
            message: format!("no default VPC found in region '{region}'"),
        });
    }
    Ok(id.to_string())
}

/// Find a security group id by name, if it exists.
pub async fn find_security_group(
    region: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<Option<String>, CloudError> {
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "describe-security-groups",
                "--region",
                region,
                "--filters",
                &format!("Name=group-name,Values={name}"),
                "--query",
                "SecurityGroups[0].GroupId",
                "--output",
                "text",
            ],
        )
        .await?;
    let id = output.stdout.trim();
    if id.is_empty() || id == "None" {
        Ok(None)
    } else {
        Ok(Some(id.to_string()))
    }
}

/// Create a security group in `vpc_id`, returning its id.
pub async fn create_security_group(
    region: &str,
    name: &str,
    vpc_id: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "create-security-group",
                "--region",
                region,
                "--group-name",
                name,
                "--description",
                "atakit SEV-SNP CVM security group",
                "--vpc-id",
                vpc_id,
                "--query",
                "GroupId",
                "--output",
                "text",
            ],
        )
        .await
        .map_err(|e| CloudError::FirewallError {
            message: format!("failed to create security group: {e}"),
        })?;
    Ok(output.stdout.trim().to_string())
}

/// Add ingress rules for the given `"port/proto"` entries (CIDR 0.0.0.0/0).
pub async fn add_ingress_rules(
    region: &str,
    sg_id: &str,
    ports: &[String],
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    for entry in ports {
        let (port, proto) = entry.split_once('/').unwrap_or((entry.as_str(), "tcp"));
        match runner
            .run_capture(
                "aws",
                &[
                    "ec2",
                    "authorize-security-group-ingress",
                    "--region",
                    region,
                    "--group-id",
                    sg_id,
                    "--protocol",
                    proto,
                    "--port",
                    port,
                    "--cidr",
                    "0.0.0.0/0",
                ],
            )
            .await
        {
            Ok(_) => {}
            Err(CloudError::CommandFailed { stderr, .. })
                if stderr.contains("InvalidPermission.Duplicate") => {}
            Err(e) => {
                return Err(CloudError::FirewallError {
                    message: format!("failed to add ingress rule for {entry}: {e}"),
                });
            }
        }
    }
    Ok(())
}

/// Delete a security group by name. Idempotent.
pub async fn delete_security_group(
    region: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let sg_id = match find_security_group(region, name, runner).await? {
        Some(id) => id,
        None => {
            tracing::debug!("security group '{name}' already deleted");
            return Ok(());
        }
    };
    match runner
        .run_capture(
            "aws",
            &[
                "ec2",
                "delete-security-group",
                "--region",
                region,
                "--group-id",
                &sg_id,
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("InvalidGroup.NotFound") =>
        {
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("security-group/{name}"),
            message: e.to_string(),
        }),
    }
}
