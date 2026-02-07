use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::info;

use super::CloudPlatform;
use crate::config::{self, Config};
use crate::types::PlatformConfig;

pub(crate) struct Azure {
    vm_name: String,
    vm_type: String,
    region: String,
    resource_group: String,
    storage_account: String,
    container_name: String,
    /// Path to the workload tar.gz artifact.
    tar_path: PathBuf,
    quiet: bool,
    /// Path to the additional-data source directory (for individual blob uploads).
    additional_data_dir: PathBuf,
}

impl Azure {
    pub(crate) fn new(
        deployment_name: &str,
        platform_config: &PlatformConfig,
        tar_path: &Path,
        quiet: bool,
        additional_data_dir: &Path,
    ) -> Result<Self> {
        let vm_type = platform_config
            .vmtype
            .as_deref()
            .unwrap_or("Standard_DC2es_v6")
            .to_string();
        let region = platform_config
            .region
            .as_deref()
            .unwrap_or("East US")
            .to_string();

        let resource_group = format!("{}_Rg", deployment_name);
        let suffix = config::random_suffix(4);
        let storage_account = {
            let mut name: String = config::sanitize_name(deployment_name)
                .chars()
                .take(20)
                .collect();
            name.push_str(&suffix);
            while name.len() < 3 {
                name.push('0');
            }
            name
        };

        info!(
            platform = "Azure",
            vm_name = deployment_name,
            vm_type = %vm_type,
            region = %region,
            resource_group = %resource_group,
            storage_account = %storage_account,
            workload = %tar_path.display(),
            "Deployment configuration"
        );

        Ok(Self {
            vm_name: deployment_name.to_string(),
            vm_type,
            region,
            resource_group,
            storage_account,
            container_name: "workloads".to_string(),
            tar_path: tar_path.to_path_buf(),
            quiet,
            additional_data_dir: additional_data_dir.to_path_buf(),
        })
    }
}

impl CloudPlatform for Azure {
    fn name(&self) -> &str {
        "azure"
    }

    fn setup_network(&mut self) -> Result<()> {
        Ok(())
    }

    fn ensure_data_disk(&mut self) -> Result<()> {
        Ok(())
    }

    fn disk_filename(&self) -> &str {
        "azure_disk.vhd"
    }

    fn check_deps(&self, cfg: &Config) -> Result<()> {
        cfg.run_script_default("check_csp_deps.sh", &["azure"])
            .context("check deps")
    }

    fn prepare_image(&mut self, _cfg: &Config) -> Result<()> {
        // 1. Create resource group.
        info!("Creating resource group");
        super::run_cmd(
            "az",
            &[
                "group",
                "create",
                "--name",
                &self.resource_group,
                "--location",
                &self.region,
            ],
            self.quiet,
        )?;

        // 2. Create storage account.
        info!("Creating storage account");
        super::run_cmd(
            "az",
            &[
                "storage",
                "account",
                "create",
                "--name",
                &self.storage_account,
                "--resource-group",
                &self.resource_group,
                "--location",
                &self.region,
                "--sku",
                "Standard_LRS",
            ],
            self.quiet,
        )?;

        // 3. Create blob container.
        super::run_cmd(
            "az",
            &[
                "storage",
                "container",
                "create",
                "--name",
                &self.container_name,
                "--account-name",
                &self.storage_account,
            ],
            self.quiet,
        )?;

        // 4. Upload workload tar.gz.
        info!("Uploading workload to blob storage");
        let tar_filename = self
            .tar_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        super::run_cmd(
            "az",
            &[
                "storage",
                "blob",
                "upload",
                "--account-name",
                &self.storage_account,
                "--container-name",
                &self.container_name,
                "--name",
                &tar_filename,
                "--file",
                &self.tar_path.to_string_lossy(),
            ],
            self.quiet,
        )?;

        Ok(())
    }

    fn attach_additional_data_disk(&mut self, img_path: Option<&Path>) -> Result<()> {
        // Upload the FAT image as a single blob.
        if let Some(img) = img_path {
            info!("Uploading additional-data image to blob storage");
            super::run_cmd(
                "az",
                &[
                    "storage",
                    "blob",
                    "upload",
                    "--account-name",
                    &self.storage_account,
                    "--container-name",
                    &self.container_name,
                    "--name",
                    "additional-data.img",
                    "--file",
                    &img.to_string_lossy(),
                    "--overwrite",
                ],
                self.quiet,
            )?;
        }

        // Also upload individual files for backward compatibility
        // (CVM agent downloads blobs individually).
        let dir = &self.additional_data_dir;
        if !dir.is_dir() {
            return Ok(());
        }

        info!("Uploading individual additional-data files");
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                super::run_cmd(
                    "az",
                    &[
                        "storage",
                        "blob",
                        "upload",
                        "--account-name",
                        &self.storage_account,
                        "--container-name",
                        &self.container_name,
                        "--name",
                        &format!("additional-data/{}", name),
                        "--file",
                        &entry.path().to_string_lossy(),
                        "--overwrite",
                    ],
                    self.quiet,
                )?;
            }
        }

        Ok(())
    }

    fn launch(&self) -> Result<()> {
        info!("Creating CVM instance");
        super::run_cmd(
            "az",
            &[
                "vm",
                "create",
                "--resource-group",
                &self.resource_group,
                "--name",
                &self.vm_name,
                "--size",
                &self.vm_type,
                "--location",
                &self.region,
                "--security-type",
                "ConfidentialVM",
            ],
            self.quiet,
        )?;

        Ok(())
    }

    fn post_launch(&self) -> Result<()> {
        info!(vm_name = %self.vm_name, "Azure deployment complete");
        Ok(())
    }
}
