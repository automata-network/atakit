pub mod deps;
pub mod disk;
pub mod firewall;
pub mod image;
pub mod instance;

use std::path::Path;

use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::naming::AzureResourceNames;
use crate::plan::*;
use crate::provider::{deployment_firewall_ports, CloudProvider, DeployOptions, DestroyOptions};
use crate::state::DeployState;

/// Decompress a `.zst` file to a destination path.
fn decompress_zst(src: &Path, dest: &Path) -> Result<(), CloudError> {
    use std::io::{Read, Write};

    let file = std::fs::File::open(src).map_err(|e| CloudError::IoPath {
        path: src.to_path_buf(),
        source: e,
    })?;
    let mut decoder = zstd::Decoder::new(file).map_err(CloudError::Io)?;
    let mut out = std::fs::File::create(dest).map_err(|e| CloudError::IoPath {
        path: dest.to_path_buf(),
        source: e,
    })?;

    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = decoder.read(&mut buf).map_err(CloudError::Io)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n]).map_err(CloudError::Io)?;
    }
    out.flush().map_err(CloudError::Io)?;
    Ok(())
}

/// Azure cloud provider.
pub struct AzureProvider {
    pub subscription: String,
    pub region: String,
}

impl AzureProvider {
    pub fn new(subscription: String, region: String) -> Self {
        Self {
            subscription,
            region,
        }
    }

    /// Create from a deploy state's Azure resources.
    pub fn from_state(state: &DeployState) -> Result<Self, CloudError> {
        let az = state
            .resources
            .azure
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "deployment has no Azure resources".to_string(),
            })?;
        Ok(Self {
            subscription: az.subscription.clone(),
            region: az.region.clone(),
        })
    }
}

#[async_trait::async_trait]
impl CloudProvider for AzureProvider {
    fn check_deps(&self) -> Result<(), CloudError> {
        deps::check_az()
    }

    async fn plan_deploy(&self, opts: &DeployOptions) -> Result<DeployPlan, CloudError> {
        // Storage account, gallery, and image version are derived from
        // (region, image_ref) — shared across every deploy of the same image.
        // The first deploy uploads the VHD; subsequent deploys detect the
        // existing gallery image version and skip the upload.
        let names =
            AzureResourceNames::for_azure(&opts.instance_name, &opts.image_ref, &self.region);
        let mut steps = vec![DeployStep::CheckDeps];

        // Create deployment resource group.
        steps.push(DeployStep::CreateResourceGroup {
            name: names.resource_group.clone(),
            region: self.region.clone(),
        });

        // Image upload/verify (gallery lives in shared RG).
        steps.push(DeployStep::UploadImageAzure {
            resource_group: names.resource_group.clone(),
            storage_account: names.storage_account.clone(),
            gallery_rg: names.gallery_rg.clone(),
            gallery: names.gallery.clone(),
            image_definition: names.image_definition.clone(),
            image_version: names.image_version.clone(),
            source_path: opts.source_image_path.clone(),
            certs_dir: opts.source_image_certs_dir.clone(),
            cc_types: opts.cc_types.clone(),
            force: opts.force_image,
        });

        // Firewall - always open the cvm-agent ports (2024 portal/measurements,
        // 1024 workload init), plus workload ports. Skipping these breaks
        // `fetch-platform-measurements` and image-only deploys.
        // workload_ports are already resolved "port/proto" strings.
        let ports = deployment_firewall_ports(opts);
        steps.push(DeployStep::OpenPorts {
            firewall_rule: names.nsg.clone(),
            ports,
        });

        // Disks from the workload manifest.
        let mut disks = Vec::new();
        for (disk_name, index, size_gb) in &opts.workload_disks {
            disks.push(DiskSpec {
                name: format!("{}-{disk_name}", names.instance),
                device_name: disk_name.clone(),
                index: *index,
                size_gb: *size_gb,
                disk_type: "Premium_LRS".to_string(),
            });
        }
        if !disks.is_empty() {
            steps.push(DeployStep::CreateDisks {
                disks: disks.clone(),
                resource_group: Some(names.resource_group.clone()),
            });
        }

        // Create instance - image_id will be resolved during execution.
        steps.push(DeployStep::CreateInstanceAzure {
            instance_name: names.instance.clone(),
            vm_size: opts.target.vmtype.clone(),
            image_id: String::new(), // resolved at execution time
            image_ref: opts.image_ref.clone(),
            cc_type: opts.target.resolved_cc_type(crate::PlatformKind::Azure)?,
            resource_group: names.resource_group.clone(),
            nsg: names.nsg.clone(),
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

            DeployStep::CreateResourceGroup { name, region } => {
                image::ensure_resource_group(&self.subscription, name, region, runner).await?;
                updates.resource_group = Some(name.clone());
            }

            DeployStep::UploadImageAzure {
                resource_group: _,
                storage_account,
                gallery_rg,
                gallery,
                image_definition,
                image_version,
                source_path,
                certs_dir,
                cc_types: _,
                force,
            } => {
                // Ensure gallery RG exists (shared, survives destroy).
                image::ensure_resource_group(&self.subscription, gallery_rg, &self.region, runner)
                    .await?;

                let exists = image::check_image_version_exists(
                    &self.subscription,
                    gallery_rg,
                    gallery,
                    image_definition,
                    image_version,
                    runner,
                )
                .await?;

                if exists && *force {
                    tracing::info!("force: deleting existing image version");
                    image::delete_image_version(
                        &self.subscription,
                        gallery_rg,
                        gallery,
                        image_definition,
                        image_version,
                        runner,
                    )
                    .await?;
                } else if exists {
                    tracing::info!(
                        "image version '{image_definition}:{image_version}' already \
                         exists; verifying it is ready before reuse"
                    );
                    // Block on provisioningState. If a prior deploy was
                    // interrupted mid-replication the image may still be
                    // Creating/Updating; wait for it. If it's Failed, this
                    // errors with a pointer to --force-image.
                    image::wait_for_image_version_succeeded(
                        &self.subscription,
                        gallery_rg,
                        gallery,
                        image_definition,
                        image_version,
                        runner,
                    )
                    .await?;

                    let image_id = image::get_image_version_id(
                        &self.subscription,
                        gallery_rg,
                        gallery,
                        image_definition,
                        image_version,
                        runner,
                    )
                    .await?;
                    updates.gallery_rg = Some(gallery_rg.clone());
                    updates.gallery = Some(gallery.clone());
                    updates.image_definition = Some(image_definition.clone());
                    updates.image_version = Some(image_version.clone());
                    updates.image = Some(image_id);
                    updates.storage_account = Some(storage_account.clone());
                    return Ok(StepResult {
                        resource_updates: updates,
                    });
                }

                if !exists || *force {
                    if let Some(src) = source_path {
                        let certs =
                            certs_dir
                                .as_deref()
                                .ok_or_else(|| CloudError::ImageUploadFailed {
                                    message: format!(
                                        "cannot register Azure image version \
                                     '{image_definition}:{image_version}': no \
                                     secure_boot_certs/ directory resolved for \
                                     the base image. atakit requires Secure \
                                     Boot to be enabled on every CVM deploy."
                                    ),
                                })?;
                        if !exists {
                            image::delete_image_definition(
                                &self.subscription,
                                gallery_rg,
                                gallery,
                                image_definition,
                                runner,
                            )
                            .await?;
                        }

                        // Ensure storage infra. Storage account lives in the
                        // shared gallery RG, not the per-instance RG, so it
                        // survives `cloud destroy` and is reused by future
                        // deploys of the same image.
                        image::ensure_storage_account(
                            &self.subscription,
                            gallery_rg,
                            storage_account,
                            &self.region,
                            runner,
                        )
                        .await?;
                        image::ensure_storage_container(
                            &self.subscription,
                            storage_account,
                            "vhds",
                            runner,
                        )
                        .await?;

                        // Decompress .vhd.zst to a temp file for upload.
                        let (upload_path, _tmp_dir) = if src.ends_with(".zst") {
                            let tmp = tempfile::tempdir().map_err(CloudError::Io)?;
                            let decompressed = tmp.path().join("azure_disk.vhd");
                            decompress_zst(std::path::Path::new(src), &decompressed)?;
                            (decompressed.display().to_string(), Some(tmp))
                        } else {
                            (src.clone(), None)
                        };

                        let filename = std::path::Path::new(&upload_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("image.vhd");
                        image::upload_vhd(
                            &self.subscription,
                            storage_account,
                            "vhds",
                            filename,
                            &upload_path,
                            runner,
                            verbose,
                        )
                        .await?;

                        // Ensure gallery and image definition.
                        image::ensure_gallery(&self.subscription, gallery_rg, gallery, runner)
                            .await?;
                        image::ensure_image_definition(
                            &self.subscription,
                            gallery_rg,
                            gallery,
                            image_definition,
                            runner,
                        )
                        .await?;

                        // Get storage account ID for image version creation.
                        // The account now lives in the shared gallery RG.
                        let sa_id = image::get_storage_account_id(
                            &self.subscription,
                            storage_account,
                            gallery_rg,
                            runner,
                        )
                        .await?;

                        // Plain blob URL. The gallery service authenticates
                        // through Azure RBAC on --os-vhd-storage-account
                        // (sa_id); passing a SAS-wrapped URL here is rejected
                        // by `az sig image-version create` as an invalid blob
                        // URI.
                        let blob_url = format!(
                            "https://{storage_account}.blob.core.windows.net/vhds/{filename}"
                        );

                        // Create image version.
                        let image_id = image::create_image_version(
                            &self.subscription,
                            &self.region,
                            gallery_rg,
                            gallery,
                            image_definition,
                            image_version,
                            &sa_id,
                            &blob_url,
                            certs,
                            runner,
                        )
                        .await?;

                        updates.image = Some(image_id);
                        updates.storage_account = Some(storage_account.clone());
                    } else {
                        return Err(CloudError::ImageUploadFailed {
                            message: format!(
                                "image version '{image_definition}:{image_version}' does not exist and no source file was provided"
                            ),
                        });
                    }
                }

                updates.gallery_rg = Some(gallery_rg.clone());
                updates.gallery = Some(gallery.clone());
                updates.image_definition = Some(image_definition.clone());
                updates.image_version = Some(image_version.clone());
            }

            DeployStep::OpenPorts {
                firewall_rule,
                ports,
            } => {
                // The firewall_rule IS the NSG name. Derive the RG from
                // the naming convention: {instance}-nsg -> {instance}-rg.
                let rg_name = format!(
                    "{}-rg",
                    firewall_rule.strip_suffix("-nsg").unwrap_or(firewall_rule)
                );

                if firewall::check_nsg_exists(&self.subscription, &rg_name, firewall_rule, runner)
                    .await?
                {
                    tracing::info!("NSG '{firewall_rule}' already exists");
                } else {
                    firewall::create_nsg(&self.subscription, &rg_name, firewall_rule, runner)
                        .await?;
                    firewall::add_nsg_rules(
                        &self.subscription,
                        &rg_name,
                        firewall_rule,
                        ports,
                        runner,
                    )
                    .await?;
                }
                updates.nsg = Some(firewall_rule.clone());
                updates.firewall_rule = Some(firewall_rule.clone());
            }

            DeployStep::CreateDisks {
                disks,
                resource_group,
            } => {
                let rg_name = resource_group.as_deref().ok_or_else(|| CloudError::State {
                    message: "Azure CreateDisks step is missing its resource group".to_string(),
                })?;

                for spec in disks {
                    if disk::check_disk_exists(&self.subscription, rg_name, &spec.name, runner)
                        .await?
                    {
                        tracing::info!("disk '{}' already exists", spec.name);
                    } else {
                        disk::create_disk(&self.subscription, rg_name, spec, runner).await?;
                    }
                    updates.disks.push(spec.name.clone());
                }
            }

            DeployStep::CreateInstanceAzure {
                instance_name,
                vm_size,
                image_id: _,
                image_ref,
                cc_type,
                resource_group,
                nsg,
                metadata,
                disks,
                boot_disk_size_gb,
            } => {
                // The image_id in the step is empty at plan time. Look up the
                // gallery image version ID using the image_ref for naming.
                let names = AzureResourceNames::for_azure(instance_name, image_ref, &self.region);
                let image_id = image::get_image_version_id(
                    &self.subscription,
                    &names.gallery_rg,
                    &names.gallery,
                    &names.image_definition,
                    &names.image_version,
                    runner,
                )
                .await
                .unwrap_or_default();

                let ip = instance::create_instance(
                    &self.subscription,
                    resource_group,
                    instance_name,
                    vm_size,
                    &image_id,
                    *cc_type,
                    nsg,
                    metadata,
                    *boot_disk_size_gb,
                    runner,
                )
                .await?;

                // Attach disks with explicit LUN assignments after VM creation.
                for disk in disks {
                    instance::attach_disk(
                        &self.subscription,
                        resource_group,
                        instance_name,
                        &disk.name,
                        disk.index,
                        runner,
                    )
                    .await?;
                }

                updates.instance = Some(instance_name.clone());
                updates.external_ip = Some(ip);
            }

            DeployStep::WaitForPortal { .. } => {
                // Handled by CLI layer.
            }

            DeployStep::InitializeWorkload { .. } => {
                // Handled by CLI layer.
            }

            // GCP / AWS / QEMU steps - should not be executed by Azure provider.
            DeployStep::UploadImage { .. }
            | DeployStep::CreateInstance { .. }
            | DeployStep::UploadImageAws { .. }
            | DeployStep::CreateInstanceAws { .. }
            | DeployStep::StartLocalVm { .. } => {
                return Err(CloudError::State {
                    message: "non-Azure step executed by Azure provider".to_string(),
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
        let az = state
            .resources
            .azure
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no Azure resources in state".to_string(),
            })?;

        let mut steps = Vec::new();

        // Delete instance first.
        if let Some(ref name) = az.instance {
            steps.push(DestroyStep::DeleteInstance { name: name.clone() });
        }

        // Delete disks (unless preserved).
        if !opts.preserve.contains(&"disks".to_string()) && !az.disks.is_empty() {
            steps.push(DestroyStep::DeleteDisks {
                names: az.disks.clone(),
                resource_group: az.resource_group.clone(),
            });
        }

        // The NSG lives in {instance}-rg, which is deleted below — cascade handles it.

        // The gallery image version + definition + storage account are shared
        // across every deploy of the same (region, image_ref). Do NOT delete
        // them on per-instance destroy — sibling instances may still depend on
        // them, and the next deploy of the same image reuses the upload.
        // Use `atakit image rm` to clean up shared image artifacts. Azure
        // therefore ignores both the default-preserved `image` token and the
        // CLI's `--clean-image` opt-in.
        let _ = &opts.preserve; // intentionally unused: image is always preserved on destroy

        // Delete the deployment resource group (per-instance: VM, disks, NSG).
        // The shared storage account lives in the gallery RG and is untouched.
        if let Some(ref name) = az.resource_group {
            steps.push(DestroyStep::DeleteResourceGroup { name: name.clone() });
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
                let rg = format!("{name}-rg");
                instance::delete_instance(&self.subscription, &rg, name, runner).await
            }
            DestroyStep::DeleteDisks {
                names,
                resource_group,
            } => {
                let rg = resource_group.as_deref().ok_or_else(|| CloudError::State {
                    message: "Azure DeleteDisks step is missing its resource group".to_string(),
                })?;
                for name in names {
                    disk::delete_disk(&self.subscription, rg, name, runner).await?;
                }
                Ok(())
            }
            DestroyStep::DeleteImageVersion {
                gallery_rg,
                gallery,
                image_definition,
                image_version,
            } => {
                image::delete_image_version(
                    &self.subscription,
                    gallery_rg,
                    gallery,
                    image_definition,
                    image_version,
                    runner,
                )
                .await
            }
            DestroyStep::DeleteImageDefinition {
                gallery_rg,
                gallery,
                image_definition,
            } => {
                image::delete_image_definition(
                    &self.subscription,
                    gallery_rg,
                    gallery,
                    image_definition,
                    runner,
                )
                .await
            }
            DestroyStep::DeleteResourceGroup { name } => {
                instance::delete_resource_group(&self.subscription, name, runner).await
            }
            // GCP / AWS / QEMU steps.
            DestroyStep::DeleteImage { .. }
            | DestroyStep::DeleteBucket { .. }
            | DestroyStep::DeleteFirewall { .. }
            | DestroyStep::DeleteSecurityGroup { .. }
            | DestroyStep::DeleteAmi { .. }
            | DestroyStep::DeleteS3Bucket { .. }
            | DestroyStep::StopLocalVm { .. }
            | DestroyStep::RemoveLocalInstanceDir { .. } => Err(CloudError::State {
                message: "non-Azure destroy step executed by Azure provider".to_string(),
            }),
        }
    }

    async fn get_instance_ip(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<Option<String>, CloudError> {
        let az = state
            .resources
            .azure
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no Azure resources in state".to_string(),
            })?;
        let instance_name = az.instance.as_ref().ok_or_else(|| CloudError::State {
            message: "no instance in state".to_string(),
        })?;
        let rg = az
            .resource_group
            .as_deref()
            .ok_or_else(|| CloudError::State {
                message: "no resource group in state".to_string(),
            })?;
        instance::get_instance_ip(&self.subscription, rg, instance_name, runner).await
    }

    async fn get_serial_output(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<String, CloudError> {
        let az = state
            .resources
            .azure
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no Azure resources in state".to_string(),
            })?;
        let instance_name = az.instance.as_ref().ok_or_else(|| CloudError::State {
            message: "no instance in state".to_string(),
        })?;
        let rg = az
            .resource_group
            .as_deref()
            .ok_or_else(|| CloudError::State {
                message: "no resource group in state".to_string(),
            })?;
        instance::get_boot_log(&self.subscription, rg, instance_name, runner).await
    }

    fn ssh_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError> {
        let az = state
            .resources
            .azure
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no Azure resources in state".to_string(),
            })?;
        let instance_name = az.instance.as_ref().ok_or_else(|| CloudError::State {
            message: "no instance in state".to_string(),
        })?;
        let rg = az
            .resource_group
            .as_deref()
            .ok_or_else(|| CloudError::State {
                message: "no resource group in state".to_string(),
            })?;
        Ok(vec![
            "az".to_string(),
            "ssh".to_string(),
            "vm".to_string(),
            "--subscription".to_string(),
            self.subscription.clone(),
            "--name".to_string(),
            instance_name.clone(),
            "--resource-group".to_string(),
            rg.to_string(),
        ])
    }

    fn serial_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError> {
        let az = state
            .resources
            .azure
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no Azure resources in state".to_string(),
            })?;
        let instance_name = az.instance.as_ref().ok_or_else(|| CloudError::State {
            message: "no instance in state".to_string(),
        })?;
        let rg = az
            .resource_group
            .as_deref()
            .ok_or_else(|| CloudError::State {
                message: "no resource group in state".to_string(),
            })?;
        Ok(vec![
            "az".to_string(),
            "serial-console".to_string(),
            "connect".to_string(),
            "--subscription".to_string(),
            self.subscription.clone(),
            "--name".to_string(),
            instance_name.clone(),
            "--resource-group".to_string(),
            rg.to_string(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CcType, CloudTarget};
    use crate::provider::{CloudProvider, DeployOptions};
    use crate::state::PersistedInitEnv;
    use std::collections::BTreeMap;

    fn test_target() -> CloudTarget {
        CloudTarget {
            provider: "test-azure".to_string(),
            vmtype: "Standard_DC4as_v5".into(),
            uefi: None,
            image: Some("test-image:v1".to_string()),
            cc_type: None,
            name: None,
            metadata: BTreeMap::new(),
            boot_disk_size: None,
            chain: Some("testnet".to_string()),
            registration: None,
            owner_key: Some("owner".to_string()),
            gas_wallet: Some("gas".to_string()),
            sp1_payer: None,
        }
    }

    fn test_deploy_opts(image_ref: &str) -> DeployOptions {
        DeployOptions {
            instance_name: "test-instance".into(),
            target_name: "test-target".into(),
            target: test_target(),
            image_ref: image_ref.into(),
            source_image_path: Some("/tmp/disk.vhd".into()),
            source_image_certs_dir: Some("/tmp/secure_boot_certs".into()),
            archive_path: "/tmp/test.atawl".into(),
            archive_hash: "abc123".into(),
            workload_name: "test-workload".into(),
            workload_version: "v0.0.1".into(),
            init_env: PersistedInitEnv::default(),
            metadata: BTreeMap::new(),
            force_image: false,
            skip_init: true,
            cc_types: vec![CcType::SevSnp],
            workload_ports: vec![],
            portal_ports: Default::default(),
            workload_disks: vec![],
            boot_disk_size_gb: None,
        }
    }

    #[tokio::test]
    async fn plan_deploy_carries_image_ref_to_create_instance_step() {
        let provider = AzureProvider::new("sub-123".into(), "eastus".into());
        let opts = test_deploy_opts("automata-linux:v0.1.6");

        let plan = provider.plan_deploy(&opts).await.unwrap();

        // Find the CreateInstanceAzure step and verify image_ref is populated.
        let create_step = plan
            .steps
            .iter()
            .find(|s| matches!(s, DeployStep::CreateInstanceAzure { .. }));
        assert!(
            create_step.is_some(),
            "plan must contain CreateInstanceAzure"
        );

        if let DeployStep::CreateInstanceAzure { image_ref, .. } = create_step.unwrap() {
            assert_eq!(image_ref, "automata-linux:v0.1.6");
        } else {
            unreachable!();
        }
    }

    #[tokio::test]
    async fn plan_deploy_disks_carry_the_created_resource_group() {
        // Regression: disk steps used to re-derive the RG from the disk name
        // via rsplit_once('-'), which broke when the instance name and disk
        // name both contained hyphens (e.g. instance
        // "multi-container-example-azure-tdx" + disk "shared-data" produced
        // a bogus "...-shared-rg" instead of "...-rg"). The RG must now match
        // the one the CreateResourceGroup step actually creates.
        let provider = AzureProvider::new("sub-123".into(), "eastus".into());
        let mut opts = test_deploy_opts("test-baseimage:v0.0.5");
        opts.instance_name = "multi-container-example-azure-tdx".into();
        opts.workload_disks = vec![("shared-data".to_string(), 10, 10)];

        let plan = provider.plan_deploy(&opts).await.unwrap();

        let created_rg = plan.steps.iter().find_map(|s| match s {
            DeployStep::CreateResourceGroup { name, .. } => Some(name.clone()),
            _ => None,
        });
        let disk_rg = plan.steps.iter().find_map(|s| match s {
            DeployStep::CreateDisks { resource_group, .. } => Some(resource_group.clone()),
            _ => None,
        });

        let created_rg = created_rg.expect("plan must create a resource group");
        let disk_rg = disk_rg
            .expect("plan must contain CreateDisks")
            .expect("Azure CreateDisks must carry a resource group");
        assert_eq!(
            disk_rg, created_rg,
            "disk RG must match the resource group that is actually created"
        );
    }

    #[tokio::test]
    async fn plan_deploy_image_ref_not_empty() {
        // Regression: before the fix, image_ref was absent from the step,
        // causing AzureResourceNames::for_azure to be called with "" and
        // producing an empty image_definition.
        let provider = AzureProvider::new("sub-123".into(), "eastus".into());
        let opts = test_deploy_opts("debug-linux:v0.2.0");

        let plan = provider.plan_deploy(&opts).await.unwrap();

        for step in &plan.steps {
            if let DeployStep::CreateInstanceAzure { image_ref, .. } = step {
                assert!(
                    !image_ref.is_empty(),
                    "image_ref in CreateInstanceAzure must not be empty"
                );
            }
        }
    }
}
