pub mod deps;
pub mod destroy;
pub mod disk;
pub mod firewall;
pub mod image;
pub mod instance;

use std::collections::BTreeMap;

use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::naming::ResourceNames;
use crate::plan::*;
use crate::provider::{deployment_firewall_ports, CloudProvider, DeployOptions, DestroyOptions};
use crate::state::DeployState;

/// GCP cloud provider.
pub struct GcpProvider {
    pub project: String,
    pub zone: String,
}

impl GcpProvider {
    pub fn new(project: String, zone: String) -> Self {
        Self { project, zone }
    }

    /// Create from a deploy state's GCP resources.
    pub fn from_state(state: &DeployState) -> Result<Self, CloudError> {
        let gcp = state
            .resources
            .gcp
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "deployment has no GCP resources".to_string(),
            })?;
        Ok(Self {
            project: gcp.project.clone(),
            zone: gcp.zone.clone(),
        })
    }
}

fn apply_console_policy(metadata: &mut BTreeMap<String, String>, image_ref: &str) {
    // Instance metadata takes precedence over GCP project metadata.
    if !image_ref.ends_with("-debug") {
        metadata.retain(|key, _| {
            !key.eq_ignore_ascii_case("serial-port-enable")
                && !key.eq_ignore_ascii_case("serial-port-logging-enable")
        });
        metadata.insert("serial-port-enable".into(), "false".into());
        metadata.insert("serial-port-logging-enable".into(), "false".into());
    }
}

#[async_trait::async_trait]
impl CloudProvider for GcpProvider {
    fn check_deps(&self) -> Result<(), CloudError> {
        deps::check_gcloud()
    }

    async fn plan_deploy(&self, opts: &DeployOptions) -> Result<DeployPlan, CloudError> {
        let names = ResourceNames::for_gcp(&opts.instance_name, &opts.image_ref);
        let mut steps = vec![DeployStep::CheckDeps];

        // Image upload/verify.
        let image_source = opts
            .source_image_path
            .clone()
            .or_else(|| opts.target.metadata.get("image_path").cloned());
        steps.push(DeployStep::UploadImage {
            bucket: names.bucket.clone(),
            image_name: names.image.clone(),
            source_path: image_source,
            certs_dir: opts.source_image_certs_dir.clone(),
            cc_types: opts.cc_types.clone(),
            force: opts.force_image,
        });

        // Firewall - always open the cvm-agent ports (2024 portal/measurements,
        // 1024 workload init), plus workload ports. Skipping these breaks
        // `fetch-platform-measurements` and image-only deploys (gcloud
        // `--rules=` rejects an empty list).
        // workload_ports are already resolved "port/proto" strings from the manifest.
        let ports = deployment_firewall_ports(opts);
        steps.push(DeployStep::OpenPorts {
            firewall_rule: names.firewall.clone(),
            ports,
        });

        // Disks from the workload manifest.
        // C4 cannot attach Persistent Disk volumes. Use Hyperdisk Balanced
        // for its workload disks, as GCE already does for its boot disk.
        let disk_type = if opts.target.vmtype.starts_with("c4-standard-") {
            "hyperdisk-balanced"
        } else {
            "pd-balanced"
        };
        let mut disks = Vec::new();
        for (disk_name, index, size_gb) in &opts.workload_disks {
            disks.push(DiskSpec {
                performance: None,
                name: format!("{}-{disk_name}", names.instance),
                device_name: disk_name.clone(),
                index: *index,
                size_gb: *size_gb,
                disk_type: disk_type.to_string(),
            });
        }
        for disk in &mut disks {
            opts.disk_configuration.apply(disk);
        }
        disks.retain(|disk| disk.disk_type != "local-ssd");
        if !disks.is_empty() {
            steps.push(DeployStep::CreateDisks {
                disks: disks.clone(),
                resource_group: None,
            });
        }

        let mut instance_metadata = opts.metadata.clone();
        apply_console_policy(&mut instance_metadata, &opts.image_ref);
        let metadata: Vec<(String, String)> = instance_metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .chain(
                opts.init_auth
                    .iter()
                    .map(|value| ("atakit-init-auth".to_string(), value.clone())),
            )
            .collect();
        steps.push(DeployStep::CreateInstance {
            boot_disk_performance: opts.disk_configuration.boot.clone(),
            instance_name: names.instance.clone(),
            machine_type: opts.target.vmtype.clone(),
            zone: self.zone.clone(),
            image: names.image.clone(),
            cc_type: opts.target.resolved_cc_type(crate::PlatformKind::Gcp)?,
            metadata,
            disks,
            boot_disk_size_gb: opts.boot_disk_size_gb,
            static_ip: opts.static_ip.clone(),
        });

        if !opts.skip_init {
            // Wait for portal.
            steps.push(DeployStep::WaitForPortal {
                timeout_secs: crate::init::PORTAL_READINESS_TIMEOUT_SECONDS,
            });
            // Initialize workload.
            steps.push(DeployStep::InitializeWorkload {
                archive_path: opts.archive_path.clone(),
            });
        }

        Ok(DeployPlan { steps })
    }

    async fn execute_step(
        &self,
        step: &DeployStep,
        runner: &dyn CommandRunner,
        verbose: bool,
    ) -> Result<StepResult, CloudError> {
        let mut updates = ResourceUpdates::default();

        match step {
            DeployStep::CheckDeps => {
                self.check_deps()?;
            }

            DeployStep::UploadImage {
                bucket,
                image_name,
                source_path,
                certs_dir,
                cc_types,
                force,
            } => {
                let exists = image::check_image_exists(&self.project, image_name, runner).await?;
                if exists && *force {
                    tracing::info!("force: deleting existing image '{image_name}'");
                    image::delete_image(&self.project, image_name, runner).await?;
                    image::delete_bucket(bucket, runner).await.ok();
                } else if exists {
                    tracing::info!("image '{image_name}' already exists, skipping upload");
                }
                if !exists || *force {
                    if let Some(src) = source_path {
                        let certs =
                            certs_dir
                                .as_deref()
                                .ok_or_else(|| CloudError::ImageUploadFailed {
                                    message: format!(
                                        "cannot register GCE image '{image_name}': no \
                                     secure_boot_certs/ directory resolved for the \
                                     base image. atakit requires Secure Boot to be \
                                     enabled on every CVM deploy."
                                    ),
                                })?;
                        image::ensure_bucket(&self.project, bucket, &self.zone, runner).await?;
                        let gcs_uri = image::upload_image(bucket, src, runner, verbose).await?;
                        image::register_image(
                            &self.project,
                            image_name,
                            &gcs_uri,
                            cc_types,
                            certs,
                            runner,
                        )
                        .await?;
                        updates.bucket = Some(bucket.clone());
                    } else {
                        return Err(CloudError::ImageUploadFailed {
                            message: format!(
                                "GCE image '{image_name}' does not exist and no source file was provided"
                            ),
                        });
                    }
                }
                updates.image = Some(image_name.clone());
            }

            DeployStep::OpenPorts {
                firewall_rule,
                ports,
            } => {
                if firewall::check_firewall_exists(&self.project, firewall_rule, runner).await? {
                    tracing::info!("firewall rule '{firewall_rule}' already exists");
                } else {
                    firewall::create_firewall(&self.project, firewall_rule, ports, runner).await?;
                }
                updates.firewall_rule = Some(firewall_rule.clone());
            }

            DeployStep::CreateDisks { disks, .. } => {
                for spec in disks {
                    if !runner
                        .creation_recorded(&format!("disk:{}", spec.device_name))
                        .await?
                        && disk::check_disk_exists(&self.project, &self.zone, &spec.name, runner)
                            .await?
                    {
                        return Err(CloudError::DiskError {
                            message: format!("disk '{}' already exists; refusing to reuse or initialize an unowned disk", spec.name),
                        });
                    } else {
                        disk::create_disk(&self.project, &self.zone, spec, runner).await?;
                    }
                    updates.disks.push(spec.name.clone());
                }
            }

            DeployStep::CreateInstance {
                boot_disk_performance,
                instance_name,
                machine_type,
                zone,
                image,
                cc_type,
                metadata,
                disks,
                boot_disk_size_gb,
                static_ip,
            } => {
                for disk in disks {
                    disk::create_disk(&self.project, zone, disk, runner).await?;
                }
                let static_ip_address = if let Some(saved) =
                    runner.recorded_creation("instance").await?
                {
                    match saved.request {
                        crate::provisioning::CreateRequest::Gcp { body, .. } => body
                            ["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
                            .as_str()
                            .map(str::to_owned),
                        _ => None,
                    }
                } else {
                    match static_ip {
                        Some(name) => Some(
                            instance::resolve_static_ip_address(&self.project, zone, name, runner)
                                .await?,
                        ),
                        None => None,
                    }
                };
                let ip = instance::create_instance(
                    &self.project,
                    zone,
                    instance_name,
                    machine_type,
                    image,
                    *cc_type,
                    metadata,
                    disks,
                    *boot_disk_size_gb,
                    boot_disk_performance.as_ref(),
                    static_ip_address.as_deref(),
                    runner,
                )
                .await?;
                updates.instance = Some(instance_name.clone());
                updates.external_ip = Some(ip);
            }

            DeployStep::WaitForPortal { .. } => {
                // IP must be set from a previous step - caller passes it.
                // This will be handled by the CLI layer.
            }

            DeployStep::InitializeWorkload { .. } => {
                // Handled by the CLI layer (calls init::post_init).
            }

            // Azure / AWS / QEMU steps - should not be executed by GCP provider.
            DeployStep::CreateResourceGroup { .. }
            | DeployStep::UploadImageAzure { .. }
            | DeployStep::CreateInstanceAzure { .. }
            | DeployStep::UploadImageAws { .. }
            | DeployStep::CreateInstanceAws { .. }
            | DeployStep::StartLocalVm { .. } => {
                return Err(CloudError::State {
                    message: "non-GCP step executed by GCP provider".to_string(),
                });
            }
        }

        Ok(StepResult {
            resource_updates: updates,
        })
    }

    fn plan_destroy(
        &self,
        state: &DeployState,
        opts: &DestroyOptions,
    ) -> Result<DestroyPlan, CloudError> {
        let gcp = state
            .resources
            .gcp
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no GCP resources in state".to_string(),
            })?;

        let mut steps = Vec::new();

        // Delete instance first.
        if let Some(ref name) = gcp.instance {
            steps.push(DestroyStep::DeleteInstance { name: name.clone() });
        }

        // Delete disks (unless preserved).
        if !opts.preserve.contains(&"disks".to_string()) && !gcp.disks.is_empty() {
            steps.push(DestroyStep::DeleteDisks {
                names: gcp.disks.clone(),
                resource_group: None,
            });
        }

        // Delete firewall (unless preserved).
        if !opts.preserve.contains(&"firewall".to_string()) {
            if let Some(ref name) = gcp.firewall_rule {
                steps.push(DestroyStep::DeleteFirewall { name: name.clone() });
            }
        }

        // Delete image (unless preserved).
        if !opts.preserve.contains(&"image".to_string()) {
            if let Some(ref name) = gcp.image {
                steps.push(DestroyStep::DeleteImage { name: name.clone() });
            }
        }

        // Delete bucket (unless image preserved).
        if !opts.preserve.contains(&"image".to_string()) {
            if let Some(ref name) = gcp.bucket {
                steps.push(DestroyStep::DeleteBucket { name: name.clone() });
            }
        }

        Ok(DestroyPlan { steps })
    }

    async fn execute_destroy_step(
        &self,
        step: &DestroyStep,
        runner: &dyn CommandRunner,
        _verbose: bool,
    ) -> Result<(), CloudError> {
        match step {
            DestroyStep::DeleteInstance { name } => {
                instance::delete_instance(&self.project, &self.zone, name, runner).await
            }
            DestroyStep::DeleteDisks { names, .. } => {
                for name in names {
                    disk::delete_disk(&self.project, &self.zone, name, runner).await?;
                }
                Ok(())
            }
            DestroyStep::DeleteFirewall { name } => {
                firewall::delete_firewall(&self.project, name, runner).await
            }
            DestroyStep::DeleteImage { name } => {
                image::delete_image(&self.project, name, runner).await
            }
            DestroyStep::DeleteBucket { name } => image::delete_bucket(name, runner).await,

            // Azure / AWS / QEMU steps.
            DestroyStep::DeleteAzureResource { .. }
            | DestroyStep::DeleteResourceGroup { .. }
            | DestroyStep::DeleteImageVersion { .. }
            | DestroyStep::DeleteImageDefinition { .. }
            | DestroyStep::DeleteSecurityGroup { .. }
            | DestroyStep::DeleteAmi { .. }
            | DestroyStep::DeleteS3Bucket { .. }
            | DestroyStep::StopLocalVm { .. }
            | DestroyStep::RemoveLocalInstanceDir { .. } => Err(CloudError::State {
                message: "non-GCP destroy step executed by GCP provider".to_string(),
            }),
        }
    }

    async fn get_instance_ip(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<Option<String>, CloudError> {
        let instance_name = state
            .resources
            .gcp
            .as_ref()
            .and_then(|g| g.instance.as_ref())
            .ok_or_else(|| CloudError::State {
                message: "no instance in state".to_string(),
            })?;
        instance::get_instance_ip(&self.project, &self.zone, instance_name, runner).await
    }

    async fn get_serial_output(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<String, CloudError> {
        let instance_name = state
            .resources
            .gcp
            .as_ref()
            .and_then(|g| g.instance.as_ref())
            .ok_or_else(|| CloudError::State {
                message: "no instance in state".to_string(),
            })?;
        instance::get_serial_output(&self.project, &self.zone, instance_name, runner).await
    }

    fn ssh_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError> {
        let instance_name = state
            .resources
            .gcp
            .as_ref()
            .and_then(|g| g.instance.as_ref())
            .ok_or_else(|| CloudError::State {
                message: "no instance in state".to_string(),
            })?;
        Ok(vec![
            "gcloud".to_string(),
            "compute".to_string(),
            "ssh".to_string(),
            instance_name.clone(),
            "--project".to_string(),
            self.project.clone(),
            "--zone".to_string(),
            self.zone.clone(),
        ])
    }

    fn serial_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError> {
        let instance_name = state
            .resources
            .gcp
            .as_ref()
            .and_then(|g| g.instance.as_ref())
            .ok_or_else(|| CloudError::State {
                message: "no instance in state".to_string(),
            })?;
        Ok(vec![
            "gcloud".to_string(),
            "compute".to_string(),
            "connect-to-serial-port".to_string(),
            instance_name.clone(),
            "--project".to_string(),
            self.project.clone(),
            "--zone".to_string(),
            self.zone.clone(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn workload_disks_use_storage_supported_by_the_machine_type() {
        let provider = GcpProvider::new("project".into(), "europe-west4-a".into());
        for (machine, expected_type) in [
            ("c4-standard-8", "hyperdisk-balanced"),
            ("c3-standard-8", "pd-balanced"),
            ("n2d-standard-4", "pd-balanced"),
        ] {
            let target = serde_json::from_value(serde_json::json!({
                "provider": "gcp", "vmtype": machine
            }))
            .unwrap();
            let opts = DeployOptions {
                disk_configuration: Default::default(),
                init_auth: None,
                instance_name: "test-instance".into(),
                target_name: "test-target".into(),
                target,
                image_ref: "automata-linux:v0.3.5".into(),
                source_image_path: None,
                source_image_certs_dir: None,
                archive_path: "test.atawl".into(),
                archive_hash: String::new(),
                workload_name: "test-workload".into(),
                workload_version: "v0.0.1".into(),
                init_env: Default::default(),
                metadata: BTreeMap::new(),
                force_image: false,
                skip_init: true,
                cc_types: vec![],
                workload_ports: vec![],
                portal_ports: Default::default(),
                workload_disks: vec![("data".into(), 10, 10)],
                boot_disk_size_gb: None,
                static_ip: None,
                static_ip_resource_group: None,
            };
            let plan = provider.plan_deploy(&opts).await.unwrap();
            let mut checked_steps = 0;
            for step in &plan.steps {
                if let DeployStep::CreateDisks { disks, .. }
                | DeployStep::CreateInstance { disks, .. } = step
                {
                    assert_eq!(disks.len(), 1);
                    assert_eq!(disks[0].disk_type, expected_type, "{machine}");
                    assert_eq!(disks[0].device_name, "data");
                    assert_eq!(disks[0].size_gb, 10);
                    assert_eq!(disks[0].index, 10);
                    checked_steps += 1;
                }
            }
            assert_eq!(checked_steps, 2, "must create and attach the workload disk");
            let mut local_opts = opts;
            local_opts.target.vmtype = "c3-standard-8-lssd".into();
            local_opts.disk_configuration.disks.insert(
                "data".into(),
                crate::disk_profiles::DiskPerformance {
                    disk_type: "local-ssd".into(),
                    ..Default::default()
                },
            );
            let plan = provider.plan_deploy(&local_opts).await.unwrap();
            assert!(!plan
                .steps
                .iter()
                .any(|step| matches!(step, DeployStep::CreateDisks { .. })));
            assert!(plan.steps.iter().any(
                |step| matches!(step, DeployStep::CreateInstance { disks, .. } if disks.is_empty())
            ));
        }
    }

    #[test]
    fn release_image_overrides_serial_metadata_while_debug_image_keeps_it() {
        let mut release = BTreeMap::from([
            ("serial-port-enable".into(), "true".into()),
            ("serial-port-logging-enable".into(), "true".into()),
        ]);
        apply_console_policy(&mut release, "automata-linux:v0.3.5");
        assert_eq!(release.get("serial-port-enable").unwrap(), "false");
        assert_eq!(release.get("serial-port-logging-enable").unwrap(), "false");

        let mut debug = BTreeMap::from([("serial-port-enable".into(), "true".into())]);
        apply_console_policy(&mut debug, "automata-linux:v0.3.5-debug");
        assert_eq!(debug.get("serial-port-enable").unwrap(), "true");
    }
}
