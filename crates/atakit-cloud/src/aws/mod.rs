pub mod deps;
pub mod disk;
pub mod firewall;
pub mod image;
pub mod instance;

use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::naming::ResourceNames;
use crate::plan::*;
use crate::provider::{deployment_firewall_ports, CloudProvider, DeployOptions, DestroyOptions};
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
        if let Some(allocation_id) = &opts.static_ip {
            instance::validate_static_ip_allocation_id(allocation_id)?;
        }
        let names = ResourceNames::for_aws(&opts.instance_name, &opts.image_ref);
        let mut steps = vec![DeployStep::CheckDeps];

        steps.push(DeployStep::UploadImageAws {
            bucket: names.bucket.clone(),
            image_name: names.image.clone(),
            source_path: opts.source_image_path.clone(),
            certs_dir: opts.source_image_certs_dir.clone(),
            force: opts.force_image,
        });

        // Firewall - always open the cvm-agent ports (2024 portal/measurements,
        // 1024 workload init), plus workload ports. Normal workload deploys
        // already get these from resolved manifest ports, but image-only
        // deploys have no manifest to inject them.
        let ports = deployment_firewall_ports(opts);
        steps.push(DeployStep::OpenPorts {
            firewall_rule: names.firewall.clone(),
            ports,
        });

        // CreateInstanceAws creates each workload volume separately, records
        // its returned ID, and attaches it with DeleteOnTermination=true.
        let mut disks = Vec::new();
        for (disk_name, index, size_gb) in &opts.workload_disks {
            disks.push(DiskSpec {
                performance: None,
                name: format!("{}-{disk_name}", names.instance),
                device_name: disk_name.clone(),
                index: *index,
                size_gb: *size_gb,
                disk_type: "gp3".to_string(),
            });
        }

        for disk in &mut disks {
            opts.disk_configuration.apply(disk);
        }
        steps.push(DeployStep::CreateInstanceAws {
            boot_disk_performance: opts.disk_configuration.boot.clone(),
            instance_name: names.instance.clone(),
            instance_type: opts.target.vmtype.clone(),
            image_name: names.image.clone(),
            security_group: names.firewall.clone(),
            metadata: opts
                .metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .chain(
                    opts.init_auth
                        .iter()
                        .map(|value| ("atakit-init-auth".to_string(), value.clone())),
                )
                .collect(),
            disks,
            boot_disk_size_gb: opts.boot_disk_size_gb,
            static_ip: opts.static_ip.clone(),
        });

        if !opts.skip_init {
            steps.push(DeployStep::WaitForPortal {
                timeout_secs: crate::init::PORTAL_READINESS_TIMEOUT_SECONDS,
            });
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
                boot_disk_performance,
                instance_name,
                instance_type,
                image_name,
                security_group,
                metadata,
                disks,
                boot_disk_size_gb,
                static_ip,
            } => {
                let (ami_id, sg_id, subnet) = if let Some(saved) =
                    runner.recorded_creation("instance").await?
                {
                    let crate::provisioning::CreateRequest::Aws { args } = saved.request else {
                        return Err(crate::provisioning::error("wrong AWS creation record"));
                    };
                    let get = |key: &str| {
                        args.windows(2)
                            .find(|a| a[0] == key)
                            .map(|a| a[1].clone())
                            .ok_or_else(|| {
                                crate::provisioning::error(format!("saved AWS request lacks {key}"))
                            })
                    };
                    (
                        get("--image-id")?,
                        get("--security-group-ids")?,
                        get("--subnet-id")?,
                    )
                } else {
                    let ami = image::find_ami(&self.region, image_name, runner)
                        .await?
                        .ok_or_else(|| crate::provisioning::error("AWS image not found"))?;
                    let group = firewall::find_security_group(&self.region, security_group, runner)
                        .await?
                        .ok_or_else(|| {
                            crate::provisioning::error("AWS security group not found")
                        })?;
                    (
                        ami,
                        group,
                        instance::find_subnet(&self.region, runner).await?,
                    )
                };

                let (instance_id, ip) = instance::create_instance(
                    &self.region,
                    instance_name,
                    instance_type,
                    &ami_id,
                    &sg_id,
                    &subnet,
                    metadata,
                    &[],
                    *boot_disk_size_gb,
                    boot_disk_performance.as_ref(),
                    static_ip.as_deref(),
                    runner,
                )
                .await?;

                if !disks.is_empty() {
                    let zone = disk::subnet_zone(&self.region, &subnet, runner).await?;
                    for spec in disks {
                        let disk = disk::create(&self.region, &zone, spec, runner).await?;
                        disk::attach(&self.region, &instance_id, &disk, runner).await?;
                    }
                }
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
        // AWS detaches its Elastic IP but keeps the operator-owned allocation.
        if let Some(ref id) = aws.instance {
            steps.push(DestroyStep::DeleteInstance { name: id.clone() });
        }
        if !opts.preserve.contains(&"disks".into()) && !aws.disks.is_empty() {
            steps.push(DestroyStep::DeleteDisks {
                names: aws.disks.clone(),
                resource_group: None,
            });
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
            DestroyStep::DeleteDisks { names, .. } => {
                for id in names {
                    disk::delete(&self.region, id, runner).await?;
                }
                Ok(())
            }
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
            DestroyStep::DeleteFirewall { .. }
            | DestroyStep::DeleteImage { .. }
            | DestroyStep::DeleteBucket { .. }
            | DestroyStep::DeleteAzureResource { .. }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CcType, CloudTarget};
    use crate::state::{PersistedInitEnv, PortalPorts};
    use std::collections::BTreeMap;

    fn test_target() -> CloudTarget {
        CloudTarget {
            availability_zone: None,
            boot_disk: Default::default(),
            disks: Default::default(),
            runtime: Default::default(),
            provider: "test-aws".to_string(),
            vmtype: "m6a.large".to_string(),
            uefi: None,
            image: Some("test-image:v1".to_string()),
            cc_type: Some(CcType::SevSnp),
            name: None,
            metadata: BTreeMap::new(),
            boot_disk_size: None,
            static_ip: None,
            static_ip_resource_group: None,
            chain: Some("testnet".to_string()),
            registration: None,
            owner_key: Some("owner".to_string()),
            gas_wallet: Some("gas".to_string()),
            prover_credential: None,
        }
    }

    fn test_deploy_opts() -> DeployOptions {
        DeployOptions {
            disk_configuration: Default::default(),
            init_auth: None,
            instance_name: "test-instance".to_string(),
            target_name: "test-target".to_string(),
            target: test_target(),
            image_ref: "test-image:v1".to_string(),
            source_image_path: Some("/tmp/disk.raw".to_string()),
            source_image_certs_dir: Some("/tmp/secure_boot_certs".to_string()),
            archive_path: String::new(),
            archive_hash: String::new(),
            workload_name: String::new(),
            workload_version: String::new(),
            init_env: PersistedInitEnv::default(),
            metadata: BTreeMap::new(),
            force_image: false,
            skip_init: true,
            cc_types: vec![CcType::SevSnp],
            workload_ports: Vec::new(),
            portal_ports: Default::default(),
            workload_disks: Vec::new(),
            boot_disk_size_gb: None,
            static_ip: None,
            static_ip_resource_group: None,
        }
    }

    #[tokio::test]
    async fn plan_deploy_opens_portal_ports_without_workload_ports() {
        let provider = AwsProvider::new("us-east-1".to_string());
        let plan = provider.plan_deploy(&test_deploy_opts()).await.unwrap();

        let ports = plan
            .steps
            .iter()
            .find_map(|step| match step {
                DeployStep::OpenPorts { ports, .. } => Some(ports),
                _ => None,
            })
            .expect("plan must contain OpenPorts");

        assert!(ports.contains(&"2024/tcp".to_string()));
        assert!(ports.contains(&"1024/tcp".to_string()));
    }

    #[tokio::test]
    async fn plan_deploy_uses_portal_port_overrides() {
        let provider = AwsProvider::new("us-east-1".to_string());
        let mut opts = test_deploy_opts();
        opts.portal_ports = PortalPorts {
            status: 6024,
            init: 5024,
        };
        opts.workload_ports = vec![
            "2024/tcp".to_string(),
            "1024/tcp".to_string(),
            "3000/tcp".to_string(),
        ];

        let plan = provider.plan_deploy(&opts).await.unwrap();

        let ports = plan
            .steps
            .iter()
            .find_map(|step| match step {
                DeployStep::OpenPorts { ports, .. } => Some(ports),
                _ => None,
            })
            .expect("plan must contain OpenPorts");

        assert!(ports.contains(&"6024/tcp".to_string()));
        assert!(ports.contains(&"5024/tcp".to_string()));
        assert!(ports.contains(&"3000/tcp".to_string()));
        assert!(!ports.contains(&"2024/tcp".to_string()));
        assert!(!ports.contains(&"1024/tcp".to_string()));
    }

    #[tokio::test]
    async fn plan_deploy_passes_static_ip_allocation_to_instance_creation() {
        let provider = AwsProvider::new("us-east-1".to_string());
        let mut opts = test_deploy_opts();
        opts.static_ip = Some("eipalloc-0123456789abcdef0".to_string());

        let plan = provider.plan_deploy(&opts).await.unwrap();
        let allocation = plan.steps.iter().find_map(|step| match step {
            DeployStep::CreateInstanceAws { static_ip, .. } => static_ip.as_deref(),
            _ => None,
        });
        assert_eq!(allocation, opts.static_ip.as_deref());
    }

    #[tokio::test]
    async fn plan_deploy_rejects_static_ip_values_that_are_not_allocation_ids() {
        let provider = AwsProvider::new("us-east-1".into());
        for invalid in ["", "203.0.113.10", "my-ip", "eipalloc-", "eipalloc-xyz"] {
            let mut opts = test_deploy_opts();
            opts.static_ip = Some(invalid.into());
            let err = provider.plan_deploy(&opts).await.err().expect(invalid);
            assert!(err.to_string().contains("Elastic IP allocation ID"));
        }
    }
}
