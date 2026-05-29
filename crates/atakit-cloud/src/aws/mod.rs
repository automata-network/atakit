pub mod deps;
pub mod firewall;
pub mod image;
pub mod instance;

use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::naming::ResourceNames;
use crate::plan::*;
use crate::provider::{CloudProvider, DeployOptions, DestroyOptions};
use crate::state::DeployState;

/// AWS cloud provider.
pub struct AwsProvider {
    pub region: String,
}

impl AwsProvider {
    pub fn new(region: String) -> Self {
        Self { region }
    }

    /// Create from a deploy state's AWS resources.
    pub fn from_state(state: &DeployState) -> Result<Self, CloudError> {
        let aws = state
            .resources
            .aws
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "deployment has no AWS resources".to_string(),
            })?;
        Ok(Self {
            region: aws.region.clone(),
        })
    }
}

#[async_trait::async_trait]
impl CloudProvider for AwsProvider {
    fn check_deps(&self) -> Result<(), CloudError> {
        deps::check_aws()
    }

    async fn plan_deploy(&self, opts: &DeployOptions) -> Result<DeployPlan, CloudError> {
        let names = ResourceNames::for_aws(&opts.instance_name, &opts.image_ref);
        let mut steps = vec![DeployStep::CheckDeps];

        steps.push(DeployStep::UploadImageAws {
            bucket: names.bucket.clone(),
            image_name: names.image.clone(),
            source_path: opts.source_image_path.clone(),
            certs_dir: opts.source_image_certs_dir.clone(),
            force: opts.force_image,
        });

        // Firewall - workload_ports are already resolved "port/proto" strings.
        let mut ports = Vec::new();
        for entry in &opts.workload_ports {
            if !ports.contains(entry) {
                ports.push(entry.clone());
            }
        }
        steps.push(DeployStep::OpenPorts {
            firewall_rule: names.firewall.clone(),
            ports,
        });

        // Disks from the workload manifest. AWS creates EBS data volumes
        // inline with run-instances (DeleteOnTermination=true), so there is
        // no separate CreateDisks step.
        let mut disks = Vec::new();
        for (disk_name, index, size_gb) in &opts.workload_disks {
            disks.push(DiskSpec {
                name: format!("{}-{disk_name}", names.instance),
                device_name: disk_name.clone(),
                index: *index,
                size_gb: *size_gb,
                disk_type: "gp3".to_string(),
            });
        }

        steps.push(DeployStep::CreateInstanceAws {
            instance_name: names.instance.clone(),
            instance_type: opts.target.vmtype.clone(),
            image_name: names.image.clone(),
            security_group: names.firewall.clone(),
            metadata: opts
                .metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            disks,
            boot_disk_size_gb: opts.boot_disk_size_gb,
        });

        if !opts.skip_init {
            steps.push(DeployStep::WaitForPortal { timeout_secs: 300 });
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

            DeployStep::UploadImageAws {
                bucket,
                image_name,
                source_path,
                certs_dir,
                force,
            } => {
                let existing = image::find_ami(&self.region, image_name, runner).await?;
                if existing.is_some() && *force {
                    tracing::info!("force: deregistering existing AMI '{image_name}'");
                    image::deregister_ami_by_name(&self.region, image_name, runner).await?;
                    image::delete_bucket(bucket, runner).await.ok();
                } else if existing.is_some() {
                    tracing::info!("AMI '{image_name}' already exists, skipping upload");
                }

                if existing.is_none() || *force {
                    let src =
                        source_path
                            .as_deref()
                            .ok_or_else(|| CloudError::ImageUploadFailed {
                                message: format!(
                                "AMI '{image_name}' does not exist and no source file was provided"
                            ),
                            })?;
                    let certs =
                        certs_dir
                            .as_deref()
                            .ok_or_else(|| CloudError::ImageUploadFailed {
                                message: format!(
                                    "cannot register AMI '{image_name}': no secure-boot \
                                 directory resolved for the base image. atakit \
                                 requires Secure Boot on every CVM deploy."
                                ),
                            })?;

                    image::ensure_bucket(&self.region, bucket, runner).await?;
                    let key = image::upload_vmdk(bucket, src, runner, verbose).await?;
                    let task_id =
                        image::import_snapshot(&self.region, bucket, &key, runner).await?;
                    let snapshot_id =
                        image::wait_for_snapshot(&self.region, &task_id, runner).await?;
                    // Drop any stale same-name AMI before registering.
                    image::deregister_ami_by_name(&self.region, image_name, runner).await?;
                    let ami_id =
                        image::register_ami(&self.region, image_name, &snapshot_id, certs, runner)
                            .await?;
                    tracing::info!("registered AMI {ami_id}");
                    updates.bucket = Some(bucket.clone());
                    updates.snapshot = Some(snapshot_id);
                }
                updates.image = Some(image_name.clone());
            }

            DeployStep::OpenPorts {
                firewall_rule,
                ports,
            } => {
                match firewall::find_security_group(&self.region, firewall_rule, runner).await? {
                    Some(_) => {
                        tracing::info!("security group '{firewall_rule}' already exists");
                    }
                    None => {
                        let vpc = firewall::default_vpc_id(&self.region, runner).await?;
                        let sg_id = firewall::create_security_group(
                            &self.region,
                            firewall_rule,
                            &vpc,
                            runner,
                        )
                        .await?;
                        firewall::add_ingress_rules(&self.region, &sg_id, ports, runner).await?;
                    }
                }
                updates.firewall_rule = Some(firewall_rule.clone());
            }

            DeployStep::CreateInstanceAws {
                instance_name,
                instance_type,
                image_name,
                security_group,
                metadata,
                disks,
                boot_disk_size_gb,
            } => {
                let ami_id = image::find_ami(&self.region, image_name, runner)
                    .await?
                    .ok_or_else(|| CloudError::InstanceError {
                        message: format!("AMI '{image_name}' not found"),
                    })?;
                let sg_id = firewall::find_security_group(&self.region, security_group, runner)
                    .await?
                    .ok_or_else(|| CloudError::InstanceError {
                        message: format!("security group '{security_group}' not found"),
                    })?;
                let subnet = instance::find_subnet(&self.region, runner).await?;

                let (instance_id, ip) = instance::create_instance(
                    &self.region,
                    instance_name,
                    instance_type,
                    &ami_id,
                    &sg_id,
                    &subnet,
                    metadata,
                    disks,
                    *boot_disk_size_gb,
                    runner,
                )
                .await?;

                updates.instance = Some(instance_id);
                updates.external_ip = Some(ip);
            }

            DeployStep::WaitForPortal { .. } | DeployStep::InitializeWorkload { .. } => {
                // Handled by the CLI layer.
            }

            // GCP / Azure steps - should not be executed by the AWS provider.
            DeployStep::UploadImage { .. }
            | DeployStep::CreateInstance { .. }
            | DeployStep::CreateDisks { .. }
            | DeployStep::CreateResourceGroup { .. }
            | DeployStep::UploadImageAzure { .. }
            | DeployStep::CreateInstanceAzure { .. }
            | DeployStep::StartLocalVm { .. } => {
                return Err(CloudError::State {
                    message: "non-AWS step executed by AWS provider".to_string(),
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
        let aws = state
            .resources
            .aws
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no AWS resources in state".to_string(),
            })?;

        let mut steps = Vec::new();

        // Terminate the instance first; EBS data volumes auto-delete with it.
        if let Some(ref id) = aws.instance {
            steps.push(DestroyStep::DeleteInstance { name: id.clone() });
        }

        // Delete the security group (unless preserved).
        if !opts.preserve.contains(&"firewall".to_string()) {
            if let Some(ref sg) = aws.security_group {
                steps.push(DestroyStep::DeleteSecurityGroup { name: sg.clone() });
            }
        }

        // Delete the AMI + backing snapshots and the S3 bucket (unless preserved).
        if !opts.preserve.contains(&"image".to_string()) {
            if let Some(ref ami) = aws.ami {
                steps.push(DestroyStep::DeleteAmi { name: ami.clone() });
            }
            if let Some(ref bucket) = aws.bucket {
                steps.push(DestroyStep::DeleteS3Bucket {
                    name: bucket.clone(),
                });
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
                instance::terminate_instance(&self.region, name, runner).await
            }
            DestroyStep::DeleteSecurityGroup { name } => {
                firewall::delete_security_group(&self.region, name, runner).await
            }
            DestroyStep::DeleteAmi { name } => {
                image::deregister_ami_by_name(&self.region, name, runner).await
            }
            DestroyStep::DeleteS3Bucket { name } => image::delete_bucket(name, runner).await,

            // GCP / Azure / QEMU steps.
            DestroyStep::DeleteDisks { .. }
            | DestroyStep::DeleteFirewall { .. }
            | DestroyStep::DeleteImage { .. }
            | DestroyStep::DeleteBucket { .. }
            | DestroyStep::DeleteResourceGroup { .. }
            | DestroyStep::DeleteImageVersion { .. }
            | DestroyStep::DeleteImageDefinition { .. }
            | DestroyStep::StopLocalVm { .. }
            | DestroyStep::RemoveLocalInstanceDir { .. } => Err(CloudError::State {
                message: "non-AWS destroy step executed by AWS provider".to_string(),
            }),
        }
    }

    async fn get_instance_ip(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<Option<String>, CloudError> {
        let instance_id = state
            .resources
            .aws
            .as_ref()
            .and_then(|a| a.instance.as_ref())
            .ok_or_else(|| CloudError::State {
                message: "no instance in state".to_string(),
            })?;
        instance::get_instance_public_ip(&self.region, instance_id, runner).await
    }

    async fn get_serial_output(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<String, CloudError> {
        let instance_id = state
            .resources
            .aws
            .as_ref()
            .and_then(|a| a.instance.as_ref())
            .ok_or_else(|| CloudError::State {
                message: "no instance in state".to_string(),
            })?;
        instance::get_console_output(&self.region, instance_id, runner).await
    }

    fn ssh_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError> {
        let instance_id = state
            .resources
            .aws
            .as_ref()
            .and_then(|a| a.instance.as_ref())
            .ok_or_else(|| CloudError::State {
                message: "no instance in state".to_string(),
            })?;
        Ok(vec![
            "aws".to_string(),
            "ec2-instance-connect".to_string(),
            "ssh".to_string(),
            "--instance-id".to_string(),
            instance_id.clone(),
            "--region".to_string(),
            self.region.clone(),
        ])
    }

    fn serial_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError> {
        let instance_id = state
            .resources
            .aws
            .as_ref()
            .and_then(|a| a.instance.as_ref())
            .ok_or_else(|| CloudError::State {
                message: "no instance in state".to_string(),
            })?;
        Ok(vec![
            "aws".to_string(),
            "ec2".to_string(),
            "get-console-output".to_string(),
            "--region".to_string(),
            self.region.clone(),
            "--instance-id".to_string(),
            instance_id.clone(),
            "--latest".to_string(),
        ])
    }
}
