use crate::config::CcType;
use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::DiskSpec;

/// Create a GCE VM instance with a CVM-compatible configuration.
/// Returns the external IP address.
#[allow(clippy::too_many_arguments)]
pub async fn create_instance(
    project: &str,
    zone: &str,
    name: &str,
    machine_type: &str,
    image: &str,
    cc_type: CcType,
    metadata: &[(String, String)],
    disks: &[DiskSpec],
    boot_disk_size_gb: Option<u64>,
    static_ip_address: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let cc_flag = format!("--confidential-compute-type={cc_type}");
    let machine_flag = format!("--machine-type={machine_type}");
    let image_flag = format!("--image={image}");
    let tags_flag = format!("--tags={name}-ingress");
    let boot_disk_flag = boot_disk_size_gb.map(|gb| format!("--boot-disk-size={gb}GB"));
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

    let network_interface_flag = match static_ip_address {
        Some(ip) => format!("--network-interface=network-tier=PREMIUM,nic-type=GVNIC,address={ip}"),
        None => "--network-interface=network-tier=PREMIUM,nic-type=GVNIC".to_string(),
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
        &network_interface_flag,
        &cc_flag,
        "--maintenance-policy=TERMINATE",
        // Shielded VM: required for the image's custom PK/KEK/db to take
        // effect at boot. Without these flags GCE provisions the VM with
        // SecureBoot=0x00 even when the image carries Secure Boot certs.
        "--shielded-secure-boot",
        "--shielded-vtpm",
        "--shielded-integrity-monitoring",
    ];
    if let Some(ref flag) = boot_disk_flag {
        args.push(flag);
    }
    if let Some(ref flag) = cpu_flag {
        args.push(flag);
    }
    if let Some(ref flag) = metadata_flag {
        args.push(flag);
    }
    args.push(&tags_flag);

    // Attach pre-created persistent disks.
    let disk_flags: Vec<String> = disks
        .iter()
        .map(|d| {
            format!(
                "--disk=name={},device-name={},auto-delete=no",
                d.name, d.device_name,
            )
        })
        .collect();
    for flag in &disk_flags {
        args.push(flag);
    }

    args.push("--format=json");

    let output =
        runner
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

/// Resolve an existing regional reserved address name to its IP address.
pub async fn resolve_static_ip_address(
    project: &str,
    zone: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let region = region_from_zone(zone).ok_or_else(|| CloudError::Config {
        message: format!("cannot derive GCP region from zone '{zone}' for static_ip '{name}'"),
    })?;
    let output = runner
        .run_capture(
            "gcloud",
            &[
                "compute",
                "addresses",
                "describe",
                name,
                "--region",
                &region,
                "--project",
                project,
                "--format=get(address)",
            ],
        )
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!("failed to resolve static IP '{name}' in region '{region}': {e}"),
        })?;
    let address = output.stdout.trim();
    if address.is_empty() {
        return Err(CloudError::InstanceError {
            message: format!("static IP '{name}' in region '{region}' did not return an address"),
        });
    }
    Ok(address.to_string())
}

fn region_from_zone(zone: &str) -> Option<String> {
    let (region, suffix) = zone.rsplit_once('-')?;
    if region.is_empty() || suffix.is_empty() {
        return None;
    }
    Some(region.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CommandOutput;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[tokio::test]
    async fn init_bootstrap_preserves_json_in_instance_metadata() {
        let runner = MockRunner::new(vec![output("203.0.113.30")]);
        let public = r#"{"format":1,"public_key":"public","deployment_id":"test"}"#;
        create_instance(
            "proj",
            "zone",
            "vm",
            "c3-standard-4",
            "img",
            CcType::Tdx,
            &[("atakit-init-auth".into(), public.into())],
            &[],
            None,
            None,
            &runner,
        )
        .await
        .unwrap();
        let calls = runner.calls();
        assert!(calls[0]
            .1
            .contains(&format!("--metadata=^;^atakit-init-auth={public}")));
    }

    struct MockRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        responses: Mutex<VecDeque<CommandOutput>>,
    }

    impl MockRunner {
        fn new(responses: Vec<CommandOutput>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for MockRunner {
        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|arg| (*arg).to_string()).collect(),
            ));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| CloudError::State {
                    message: "missing mock response".to_string(),
                })
        }

        async fn run_stream(
            &self,
            _program: &str,
            _args: &[&str],
            _verbose: bool,
        ) -> Result<CommandOutput, CloudError> {
            unimplemented!("streaming is not used by these tests")
        }
    }

    fn output(stdout: &str) -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[tokio::test]
    async fn static_ip_lookup_uses_regional_address_and_create_uses_resolved_ip() {
        let runner = MockRunner::new(vec![
            output("203.0.113.10\n"),
            output(r#"[{"networkInterfaces":[{"accessConfigs":[{"natIP":"203.0.113.10"}]}]}]"#),
        ]);

        let static_ip =
            resolve_static_ip_address("proj", "asia-southeast1-b", "reserved-ip", &runner)
                .await
                .unwrap();
        assert_eq!(static_ip, "203.0.113.10");

        let ip = create_instance(
            "proj",
            "asia-southeast1-b",
            "vm1",
            "c3-standard-4",
            "img1",
            CcType::Tdx,
            &[],
            &[],
            None,
            Some(&static_ip),
            &runner,
        )
        .await
        .unwrap();
        assert_eq!(ip, "203.0.113.10");

        let calls = runner.calls();
        assert_eq!(calls[0].0, "gcloud");
        assert_eq!(
            calls[0].1,
            vec![
                "compute",
                "addresses",
                "describe",
                "reserved-ip",
                "--region",
                "asia-southeast1",
                "--project",
                "proj",
                "--format=get(address)",
            ]
        );
        assert!(calls[1].1.contains(
            &"--network-interface=network-tier=PREMIUM,nic-type=GVNIC,address=203.0.113.10"
                .to_string()
        ));
    }

    #[tokio::test]
    async fn create_instance_without_static_ip_preserves_ephemeral_public_ip_args() {
        let runner = MockRunner::new(vec![output(
            r#"[{"networkInterfaces":[{"accessConfigs":[{"natIP":"198.51.100.20"}]}]}]"#,
        )]);

        create_instance(
            "proj",
            "us-central1-a",
            "vm1",
            "c3-standard-4",
            "img1",
            CcType::Tdx,
            &[],
            &[],
            None,
            None,
            &runner,
        )
        .await
        .unwrap();

        let calls = runner.calls();
        assert!(!calls[0].1.iter().any(|arg| arg.starts_with("--address=")));
        assert!(calls[0]
            .1
            .contains(&"--network-interface=network-tier=PREMIUM,nic-type=GVNIC".to_string()));
    }
}
