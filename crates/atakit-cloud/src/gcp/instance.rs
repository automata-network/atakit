use crate::config::CcType;
use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Create a GCE VM instance with a CVM-compatible configuration.
/// Returns the external IP address.
pub async fn create_instance(
    project: &str,
    zone: &str,
    name: &str,
    machine_type: &str,
    image: &str,
    cc_type: CcType,
    metadata: &[(String, String)],
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let cc_flag = format!("--confidential-compute-type={cc_type}");
    let machine_flag = format!("--machine-type={machine_type}");
    let image_flag = format!("--image={image}");
    let tags_flag = format!("--tags={name}-ingress");
    let cpu_flag = cc_type
        .min_cpu_platform()
        .map(|p| format!("--min-cpu-platform={p}"));
    // Use ^;^ as the delimiter so commas in values (e.g. "ports=1024,8000")
    // are not misinterpreted as key-value separators by gcloud.
    let metadata_flag = if !metadata.is_empty() {
        let pairs: Vec<String> = metadata.iter().map(|(k, v)| format!("{k}={v}")).collect();
        Some(format!("--metadata=^;^{}", pairs.join(";")))
    } else {
        None
    };

    let mut args = vec![
        "compute",
        "instances",
        "create",
        name,
        "--project",
        project,
        "--zone",
        zone,
        &machine_flag,
        &image_flag,
        "--image-project",
        project,
        "--network-interface=network-tier=PREMIUM,nic-type=GVNIC",
        &cc_flag,
        "--maintenance-policy=TERMINATE",
    ];
    if let Some(ref flag) = cpu_flag {
        args.push(flag);
    }
    if let Some(ref flag) = metadata_flag {
        args.push(flag);
    }
    args.push(&tags_flag);
    args.push("--format=json");

    let output = runner
        .run_capture("gcloud", &args)
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!("failed to create instance: {e}"),
        })?;

    // Parse the external IP from JSON output.
    let ip = parse_external_ip(&output.stdout).unwrap_or_default();
    if ip.is_empty() {
        tracing::warn!("could not determine external IP from instance creation output");
    }
    Ok(ip)
}

/// Check if an instance exists.
pub async fn check_instance_exists(
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
                "instances",
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

/// Get the external IP of a running instance.
pub async fn get_instance_ip(
    project: &str,
    zone: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<Option<String>, CloudError> {
    let output = runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "instances",
                "describe",
                name,
                "--project",
                project,
                "--zone",
                zone,
                "--format=get(networkInterfaces[0].accessConfigs[0].natIP)",
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
                "instances",
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
            tracing::debug!("instance '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("instance/{name}"),
            message: e.to_string(),
        }),
    }
}

/// Get serial port output from an instance.
pub async fn get_serial_output(
    project: &str,
    zone: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "instances",
                "get-serial-port-output",
                name,
                "--project",
                project,
                "--zone",
                zone,
            ],
        )
        .await?;

    Ok(output.stdout)
}

/// Parse the external IP from `gcloud compute instances create --format=json` output.
fn parse_external_ip(json_output: &str) -> Option<String> {
    // Output is a JSON array with one element.
    let parsed: serde_json::Value = serde_json::from_str(json_output).ok()?;
    let instances = parsed.as_array()?;
    let instance = instances.first()?;
    let interfaces = instance.get("networkInterfaces")?.as_array()?;
    let iface = interfaces.first()?;
    let access_configs = iface.get("accessConfigs")?.as_array()?;
    let config = access_configs.first()?;
    config.get("natIP")?.as_str().map(|s| s.to_string())
}
