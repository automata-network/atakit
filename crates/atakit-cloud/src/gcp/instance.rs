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
    boot_disk_performance: Option<&crate::disk_profiles::DiskPerformance>,
    static_ip_address: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let mut boot =
        serde_json::json!({"sourceImage":format!("projects/{project}/global/images/{image}")});
    if let Some(size) = boot_disk_size_gb {
        boot["diskSizeGb"] = size.to_string().into();
    }
    if let Some(p) = boot_disk_performance {
        boot["diskType"] =
            format!("projects/{project}/zones/{zone}/diskTypes/{}", p.disk_type).into();
        if let Some(v) = p.iops {
            boot["provisionedIops"] = v.to_string().into();
        }
        if let Some(v) = p.throughput_mibps {
            boot["provisionedThroughput"] = v.to_string().into();
        }
    }
    let mut attached =
        vec![serde_json::json!({"boot":true,"autoDelete":true,"initializeParams":boot})];
    for disk in disks {
        attached.push(
            serde_json::json!({"boot":false,"autoDelete":false,"deviceName":disk.device_name,
            "source":format!("projects/{project}/zones/{zone}/disks/{}",disk.name)}),
        );
    }
    let mut access =
        serde_json::json!({"type":"ONE_TO_ONE_NAT","name":"External NAT","networkTier":"PREMIUM"});
    if let Some(ip) = static_ip_address {
        access["natIP"] = ip.into();
    }
    let mut body = serde_json::json!({"name":name,"machineType":format!("zones/{zone}/machineTypes/{machine_type}"),
        "confidentialInstanceConfig":{"enableConfidentialCompute":true,"confidentialInstanceType":cc_type.to_string()},
        "scheduling":{"onHostMaintenance":"TERMINATE"},
        "shieldedInstanceConfig":{"enableSecureBoot":true,"enableVtpm":true,"enableIntegrityMonitoring":true},
        "networkInterfaces":[{"network":format!("projects/{project}/global/networks/default"),"nicType":"GVNIC","accessConfigs":[access]}],
        "tags":{"items":[format!("{name}-ingress")]},"disks":attached,
        "metadata":{"items":metadata.iter().map(|(key,value)|serde_json::json!({"key":key,"value":value})).collect::<Vec<_>>()}});
    if let Some(cpu) = cc_type.min_cpu_platform() {
        body["minCpuPlatform"] = cpu.into();
    }
    let saved = runner.recorded_creation("instance").await?;
    let recovering = saved
        .as_ref()
        .is_some_and(|c| c.result.is_some() || c.receipt.is_some());
    let request = if let Some(saved) = saved {
        saved.request
    } else {
        // Preserve gcloud's existing default service-account behavior. Resolve
        // it once; retries use the original request even if project defaults change.
        let output = runner
            .run_capture(
                "gcloud",
                &[
                    "compute",
                    "project-info",
                    "describe",
                    "--project",
                    project,
                    "--format=json",
                ],
            )
            .await?;
        let defaults: serde_json::Value = serde_json::from_str(&output.stdout)?;
        if let Some(account) = defaults["defaultServiceAccount"]
            .as_str()
            .filter(|s| !s.is_empty())
        {
            body["serviceAccounts"] = serde_json::json!([{"email":account,"scopes":[
                "https://www.googleapis.com/auth/devstorage.read_only",
                "https://www.googleapis.com/auth/logging.write",
                "https://www.googleapis.com/auth/monitoring.write",
                "https://www.googleapis.com/auth/servicecontrol",
                "https://www.googleapis.com/auth/service.management.readonly",
                "https://www.googleapis.com/auth/pubsub",
                "https://www.googleapis.com/auth/trace.append"
            ]}]);
        }
        crate::provisioning::CreateRequest::Gcp {
            project: project.into(),
            zone: zone.into(),
            collection: "instances".into(),
            body,
        }
    };
    let value = runner.create_resource("instance", &request).await?;
    let identity = crate::provisioning::identity(&value["id"])?;
    // Save the creation identity before the IP/boot disk readbacks can fail.
    runner
        .record_created_instance(name, "", false, Some(&identity))
        .await?;
    // A saved result can outlive its VM. Check that VM before accepting a
    // previously unrecorded disk from its old boot source.
    let current = if recovering {
        let vm = read_created_vm(project, zone, name, &identity, runner).await?;
        if crate::disk_inventory::gcp_boot_name(&vm, project, zone)?
            != crate::disk_inventory::gcp_boot_name(&value, project, zone)?
        {
            return Err(crate::provisioning::error(
                "GCP boot attachment changed since VM creation",
            ));
        }
        Some(vm)
    } else {
        None
    };
    // The verified creation result already contains the boot source. Do not
    // make recording its identity depend on the later IP readback.
    runner
        .record_boot_disk(
            &crate::disk_inventory::gcp_boot_from_vm(project, zone, &value, runner).await?,
        )
        .await?;
    let live = match current {
        Some(vm) => vm,
        None => read_created_vm(project, zone, name, &identity, runner).await?,
    };
    let ip = live["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    runner
        .record_created_instance(name, &ip, true, Some(&identity))
        .await?;
    Ok(ip)
}

async fn read_created_vm(
    project: &str,
    zone: &str,
    name: &str,
    expected_identity: &str,
    runner: &dyn CommandRunner,
) -> Result<serde_json::Value, CloudError> {
    let out = runner
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
        .await?;
    let live: serde_json::Value = serde_json::from_str(&out.stdout)?;
    if crate::provisioning::identity(&live["id"])? != expected_identity {
        return Err(crate::provisioning::error("GCP VM was replaced"));
    }
    Ok(live)
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

/// Delete an instance after cleanup has disabled Persistent Disk auto-delete.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CommandOutput;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[tokio::test]
    async fn boot_profile_reaches_only_new_instance_creation() {
        let runner = MockRunner::new(vec![output(
            r#"{"id":"7","networkInterfaces":[{"accessConfigs":[{"natIP":"203.0.113.30"}]}]}"#,
        )]);
        let profile = crate::disk_profiles::DiskPerformance {
            disk_type: "hyperdisk-balanced".into(),
            iops: Some(6000),
            throughput_mibps: Some(250),
            ..Default::default()
        };
        create_instance(
            "project",
            "zone",
            "vm",
            "c4-standard-4",
            "image",
            CcType::Tdx,
            &[],
            &[],
            Some(32),
            Some(&profile),
            None,
            &runner,
        )
        .await
        .unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        let body = &runner.requests.lock().unwrap()[0];
        let boot = &body["disks"][0]["initializeParams"];
        assert!(boot["diskType"]
            .as_str()
            .unwrap()
            .ends_with("/hyperdisk-balanced"));
        assert_eq!(boot["provisionedIops"], "6000");
        assert_eq!(boot["provisionedThroughput"], "250");
        assert_eq!(boot["diskSizeGb"], "32");
        assert_eq!(
            body["serviceAccounts"][0]["email"],
            "default@project.iam.gserviceaccount.com"
        );
        assert_eq!(body["shieldedInstanceConfig"]["enableSecureBoot"], true);
        assert_eq!(
            body["confidentialInstanceConfig"]["confidentialInstanceType"],
            "TDX"
        );
    }

    #[tokio::test]
    async fn init_bootstrap_preserves_json_in_instance_metadata() {
        let runner = MockRunner::new(vec![output(
            r#"{"id":"7","networkInterfaces":[{"accessConfigs":[{"natIP":"203.0.113.30"}]}]}"#,
        )]);
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
            None,
            &runner,
        )
        .await
        .unwrap();
        assert_eq!(
            runner.requests.lock().unwrap()[0]["metadata"]["items"][0]["value"],
            public
        );
    }

    struct MockRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        responses: Mutex<VecDeque<CommandOutput>>,
        requests: Mutex<Vec<serde_json::Value>>,
    }

    impl MockRunner {
        fn new(responses: Vec<CommandOutput>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(vec![]),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for MockRunner {
        async fn create_resource(
            &self,
            _: &str,
            request: &crate::provisioning::CreateRequest,
        ) -> Result<serde_json::Value, CloudError> {
            let crate::provisioning::CreateRequest::Gcp {
                project,
                zone,
                body,
                ..
            } = request
            else {
                panic!("wrong provider")
            };
            self.requests.lock().unwrap().push(body.clone());
            Ok(
                serde_json::json!({"id":"7","disks":[{"boot":true,"source":format!("projects/{project}/zones/{zone}/disks/boot") }]}),
            )
        }
        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            if args.starts_with(&["compute", "project-info"]) {
                return Ok(output(
                    r#"{"defaultServiceAccount":"default@project.iam.gserviceaccount.com"}"#,
                ));
            }
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|arg| (*arg).to_string()).collect(),
            ));
            if args.starts_with(&["compute", "disks", "describe"]) {
                return Ok(output(r#"{"id":"8","type":"pd-balanced","sizeGb":"32"}"#));
            }
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
            output(
                r#"{"id":"7","networkInterfaces":[{"accessConfigs":[{"natIP":"203.0.113.10"}]}]}"#,
            ),
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
        assert_eq!(
            runner.requests.lock().unwrap()[0]["networkInterfaces"][0]["accessConfigs"][0]["natIP"],
            "203.0.113.10"
        );
    }

    #[tokio::test]
    async fn create_instance_without_static_ip_preserves_ephemeral_public_ip_args() {
        let runner = MockRunner::new(vec![output(
            r#"{"id":"7","networkInterfaces":[{"accessConfigs":[{"natIP":"198.51.100.20"}]}]}"#,
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
            None,
            &runner,
        )
        .await
        .unwrap();

        let requests = runner.requests.lock().unwrap();
        let nic = &requests[0]["networkInterfaces"][0];
        assert_eq!(nic["nicType"], "GVNIC");
        assert_eq!(nic["accessConfigs"][0]["networkTier"], "PREMIUM");
        assert!(nic["accessConfigs"][0].get("natIP").is_none());
    }
}
