pub mod deps;
pub mod destroy;
pub mod disk;
pub mod firewall;
pub mod image;
pub mod instance;

use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::naming::ResourceNames;
use crate::plan::*;
use crate::provider::{CloudProvider, DeployOptions, DestroyOptions};
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
            cc_type: opts.target.cc_type,
            force: opts.force_image,
        });

        // Firewall - always open agent port 1024 (tcp), plus workload ports.
        // Port format: "port/proto" (e.g. "1024/tcp", "5353/udp").
        // No protocol suffix in the workload config means both tcp and udp.
        let mut ports = vec!["1024/tcp".to_string()];
        for mapping in &opts.workload_ports {
            // Parse "host:container[/proto]" -> host port + optional proto.
            let (ports_part, proto) = match mapping.split_once('/') {
                Some((p, proto)) => (p, Some(proto)),
                None => (mapping.as_str(), None),
            };
            let host_port = ports_part.split(':').next().unwrap_or("").trim();
            if host_port.is_empty() {
                continue;
            }
            let protos: &[&str] = match proto {
                Some(p) => &[p],
                None => &["tcp", "udp"],
            };
            for p in protos {
                let entry = format!("{host_port}/{p}");
                if !ports.contains(&entry) {
                    ports.push(entry);
                }
            }
        }
        steps.push(DeployStep::OpenPorts {
            firewall_rule: names.firewall.clone(),
            ports,
        });

        // Disks from the workload manifest.
        let mut disks = Vec::new();
        for (disk_name, size_gb) in &opts.workload_disks {
            disks.push(DiskSpec {
                name: format!("{}-{disk_name}", names.instance),
                device_name: disk_name.clone(),
                size_gb: *size_gb,
                disk_type: "pd-balanced".to_string(),
            });
        }
        if !disks.is_empty() {
            steps.push(DeployStep::CreateDisks { disks: disks.clone() });
        }

        // Create instance.
        steps.push(DeployStep::CreateInstance {
            instance_name: names.instance.clone(),
            machine_type: opts.target.vmtype.clone(),
            zone: self.zone.clone(),
            image: names.image.clone(),
            cc_type: opts.target.cc_type,
            metadata: opts.metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            disks,
        });

        if !opts.skip_init {
            // Wait for agent.
            steps.push(DeployStep::WaitForAgent { timeout_secs: 300 });
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
                cc_type,
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
                        image::ensure_bucket(&self.project, bucket, &self.zone, runner).await?;
                        let gcs_uri =
                            image::upload_image(bucket, src, runner, verbose).await?;
                        image::register_image(&self.project, image_name, &gcs_uri, *cc_type, runner).await?;
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

            DeployStep::CreateDisks { disks } => {
                for spec in disks {
                    if disk::check_disk_exists(&self.project, &self.zone, &spec.name, runner)
                        .await?
                    {
                        tracing::info!("disk '{}' already exists", spec.name);
                    } else {
                        disk::create_disk(&self.project, &self.zone, spec, runner).await?;
                    }
                    updates.disks.push(spec.name.clone());
                }
            }

            DeployStep::CreateInstance {
                instance_name,
                machine_type,
                zone,
                image,
                cc_type,
                metadata,
                disks,
            } => {
                let ip = instance::create_instance(
                    &self.project,
                    zone,
                    instance_name,
                    machine_type,
                    image,
                    *cc_type,
                    metadata,
                    disks,
                    runner,
                )
                .await?;
                updates.instance = Some(instance_name.clone());
                updates.external_ip = Some(ip);
            }

            DeployStep::WaitForAgent { .. } => {
                // IP must be set from a previous step - caller passes it.
                // This will be handled by the CLI layer.
            }

            DeployStep::InitializeWorkload { .. } => {
                // Handled by the CLI layer (calls init::post_init).
            }

            // Azure steps - should not be executed by GCP provider.
            DeployStep::CreateResourceGroup { .. }
            | DeployStep::UploadImageAzure { .. }
            | DeployStep::CreateInstanceAzure { .. } => {
                return Err(CloudError::State {
                    message: "Azure step executed by GCP provider".to_string(),
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
            DestroyStep::DeleteDisks { names } => {
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

            // Azure steps.
            DestroyStep::DeleteResourceGroup { .. }
            | DestroyStep::DeleteImageVersion { .. } => {
                Err(CloudError::State {
                    message: "Azure destroy step executed by GCP provider".to_string(),
                })
            }
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
