use crate::config::CcType;
use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Create an Azure CVM instance. Returns the external IP address.
///
/// Disks are attached separately via `attach_disk()` with explicit LUN
/// assignments, so they are not passed here.
#[allow(clippy::too_many_arguments)]
pub async fn create_instance(
    rg: &str,
    name: &str,
    vm_size: &str,
    image_id: &str,
    _cc_type: CcType,
    nsg: &str,
    metadata: &[(String, String)],
    boot_disk_size_gb: Option<u64>,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let mut args = vec![
        "vm",
        "create",
        "--resource-group",
        rg,
        "--name",
        name,
        "--size",
        vm_size,
        "--image",
        image_id,
        "--specialized",
        "--security-type",
        "ConfidentialVM",
        "--os-disk-security-encryption-type",
        "VMGuestStateOnly",
        "--enable-vtpm",
        "true",
        "--enable-secure-boot",
        "true",
        "--nsg",
        nsg,
        "--public-ip-sku",
        "Standard",
    ];

    let os_disk_size_str = boot_disk_size_gb.map(|gb| gb.to_string());
    if let Some(ref size) = os_disk_size_str {
        args.push("--os-disk-size-gb");
        args.push(size);
    }

    // Tags (Azure equivalent of GCP labels/metadata).
    let tags_str: Vec<String> = metadata
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let tags_flag;
    if !tags_str.is_empty() {
        tags_flag = tags_str.join(" ");
        args.push("--tags");
        args.push(&tags_flag);
    }

    args.push("--output");
    args.push("json");

    let output = runner
        .run_capture("az", &args)
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!("failed to create instance: {e}"),
        })?;

    // Parse the public IP from JSON output.
    let ip = parse_public_ip(&output.stdout).unwrap_or_default();
    if ip.is_empty() {
        tracing::warn!("could not determine public IP from instance creation output");
    }
    Ok(ip)
}

/// Attach a managed disk to an instance with a specific LUN.
pub async fn attach_disk(
    rg: &str,
    vm_name: &str,
    disk_name: &str,
    lun: u32,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    runner
        .run_capture(
            "az",
            &[
                "vm",
                "disk",
                "attach",
                "--resource-group",
                rg,
                "--vm-name",
                vm_name,
                "--name",
                disk_name,
                "--lun",
                &lun.to_string(),
            ],
        )
        .await
        .map_err(|e| CloudError::DiskError {
            message: format!("failed to attach disk '{disk_name}' at LUN {lun}: {e}"),
        })?;
    Ok(())
}

/// Get the public IP of a running instance.
pub async fn get_instance_ip(
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<Option<String>, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "vm",
                "list-ip-addresses",
                "--resource-group",
                rg,
                "--name",
                name,
                "--query",
                "[0].virtualMachine.network.publicIpAddresses[0].ipAddress",
                "-o",
                "tsv",
            ],
        )
        .await?;

    let ip = output.stdout.trim().to_string();
    if ip.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ip))
    }
}

/// Delete an instance.
pub async fn delete_instance(
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "vm",
                "delete",
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
            tracing::debug!("instance '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("instance/{name}"),
            message: e.to_string(),
        }),
    }
}

/// Get boot diagnostics log from an instance.
pub async fn get_boot_log(
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "vm",
                "boot-diagnostics",
                "get-boot-log",
                "--resource-group",
                rg,
                "--name",
                name,
            ],
        )
        .await?;
    Ok(output.stdout)
}

/// Delete a resource group and all resources within it.
pub async fn delete_resource_group(
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &["group", "delete", "--name", name, "--yes", "--no-wait"],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("not found") || stderr.contains("NotFound") =>
        {
            tracing::debug!("resource group '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("resource-group/{name}"),
            message: e.to_string(),
        }),
    }
}

/// Parse the public IP from `az vm create --output json`.
fn parse_public_ip(json_output: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(json_output).ok()?;
    // az vm create returns publicIpAddress at the top level.
    parsed
        .get("publicIpAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
