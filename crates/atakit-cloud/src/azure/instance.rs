use crate::config::CcType;
use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Create an Azure CVM instance. Returns the external IP address.
///
/// Disks are attached separately via `attach_disk()` with explicit LUN
/// assignments, so they are not passed here.
#[allow(clippy::too_many_arguments)]
pub async fn create_instance(
    subscription: &str,
    rg: &str,
    name: &str,
    vm_size: &str,
    image_id: &str,
    _cc_type: CcType,
    nsg: &str,
    metadata: &[(String, String)],
    boot_disk_size_gb: Option<u64>,
    static_public_ip_id: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let mut args = vec![
        "vm",
        "create",
        "--subscription",
        subscription,
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
        "--admin-username", // Do NOT remove! VM create will fail.
        "dummyuser",
        "--admin-password", // Do NOT remove! VM create will fail.
        "DummyPassword123",
    ];

    let os_disk_size_str = boot_disk_size_gb.map(|gb| gb.to_string());
    if let Some(ref size) = os_disk_size_str {
        args.push("--os-disk-size-gb");
        args.push(size);
    }
    if let Some(id) = static_public_ip_id {
        args.push("--public-ip-address");
        args.push(id);
    }

    // Tags (Azure equivalent of GCP labels/metadata).
    let tags_str: Vec<String> = metadata.iter().map(|(k, v)| format!("{k}={v}")).collect();
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

/// Resolve and validate an existing Azure Public IP resource.
pub async fn resolve_static_public_ip(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "network",
                "public-ip",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
                "--output",
                "json",
            ],
        )
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!(
                "failed to resolve Azure static IP '{name}' in resource group '{rg}': {e}"
            ),
        })?;
    let parsed: serde_json::Value = serde_json::from_str(&output.stdout)?;
    let allocation = parsed
        .get("publicIpAllocationMethod")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if allocation != "Static" {
        return Err(CloudError::InstanceError {
            message: format!(
                "Azure public IP '{name}' in resource group '{rg}' must use Static allocation"
            ),
        });
    }
    let sku = parsed
        .get("sku")
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if sku != "Standard" {
        return Err(CloudError::InstanceError {
            message: format!(
                "Azure public IP '{name}' in resource group '{rg}' must use Standard SKU"
            ),
        });
    }
    parsed
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .map(|id| id.to_string())
        .ok_or_else(|| CloudError::InstanceError {
            message: format!(
                "Azure public IP '{name}' in resource group '{rg}' did not return a resource ID"
            ),
        })
}

/// Attach a managed disk to an instance with a specific LUN.
pub async fn attach_disk(
    subscription: &str,
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
                "--subscription",
                subscription,
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
    subscription: &str,
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
                "--subscription",
                subscription,
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
    subscription: &str,
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
    subscription: &str,
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
                "--subscription",
                subscription,
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
    subscription: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "group",
                "delete",
                "--subscription",
                subscription,
                "--name",
                name,
                "--yes",
                "--no-wait",
            ],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CommandOutput;
    use std::collections::VecDeque;
    use std::sync::Mutex;

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
    async fn static_public_ip_is_validated_and_passed_to_vm_create() {
        let public_ip_id =
            "/subscriptions/sub/resourceGroups/network-rg/providers/Microsoft.Network/publicIPAddresses/portal-ip";
        let runner = MockRunner::new(vec![
            output(&format!(
                r#"{{
                    "id": "{public_ip_id}",
                    "publicIpAllocationMethod": "Static",
                    "sku": {{"name": "Standard"}}
                }}"#
            )),
            output(r#"{"publicIpAddress":"203.0.113.30"}"#),
        ]);

        let resolved = resolve_static_public_ip("sub", "network-rg", "portal-ip", &runner)
            .await
            .unwrap();
        assert_eq!(resolved, public_ip_id);

        create_instance(
            "sub",
            "deploy-rg",
            "vm1",
            "Standard_DC4as_v5",
            public_ip_id,
            CcType::SevSnp,
            "vm1-nsg",
            &[],
            None,
            Some(&resolved),
            &runner,
        )
        .await
        .unwrap();

        let calls = runner.calls();
        assert_eq!(
            calls[0].1,
            vec![
                "network",
                "public-ip",
                "show",
                "--subscription",
                "sub",
                "--resource-group",
                "network-rg",
                "--name",
                "portal-ip",
                "--output",
                "json",
            ]
        );
        assert!(calls[1].1.contains(&"--public-ip-address".to_string()));
        assert!(calls[1].1.contains(&public_ip_id.to_string()));
        assert!(calls[1].1.contains(&"--public-ip-sku".to_string()));
        assert!(calls[1].1.contains(&"Standard".to_string()));
    }

    #[tokio::test]
    async fn create_instance_without_static_ip_preserves_ephemeral_public_ip_args() {
        let runner = MockRunner::new(vec![output(r#"{"publicIpAddress":"198.51.100.40"}"#)]);

        create_instance(
            "sub",
            "deploy-rg",
            "vm1",
            "Standard_DC4as_v5",
            "image-id",
            CcType::SevSnp,
            "vm1-nsg",
            &[],
            None,
            None,
            &runner,
        )
        .await
        .unwrap();

        let calls = runner.calls();
        assert!(!calls[0].1.contains(&"--public-ip-address".to_string()));
        assert!(calls[0].1.contains(&"--public-ip-sku".to_string()));
        assert!(calls[0].1.contains(&"Standard".to_string()));
    }
}
