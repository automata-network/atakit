use std::path::Path;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tracing::info;

use crate::cmd;
use crate::{CloudProvider, Compute, DiskFormat, ImageManager, InstanceInfo, Logs, Metadata};

// ── Configuration ─────────────────────────────────────────────────

/// Configuration for creating an [`Azure`] provider instance.
pub struct AzureConfig {
    pub vm_name: String,
    pub vm_type: Option<String>,
    pub region: Option<String>,
    pub resource_group: Option<String>,
    pub storage_account: Option<String>,
    pub container_name: Option<String>,
    /// Run without confirmation prompts.
    pub quiet: bool,
}

// ── Provider ──────────────────────────────────────────────────────

pub struct Azure {
    vm_name: String,
    vm_type: String,
    region: String,
    resource_group: String,
    storage_account: String,
    container_name: String,
    quiet: bool,
}

impl Azure {
    pub async fn new(config: AzureConfig) -> Result<Self> {
        let vm_type = config.vm_type.unwrap_or_else(|| "Standard_DC2es_v6".into());
        let region = config.region.unwrap_or_else(|| "East US".into());
        let resource_group = config
            .resource_group
            .unwrap_or_else(|| format!("{}_Rg", config.vm_name));

        let suffix = cmd::random_suffix(4);

        let storage_account = match config.storage_account {
            Some(s) => s,
            None => {
                // Try to find an existing storage account in the resource group.
                let existing = cmd::try_capture(
                    "az",
                    &[
                        "storage",
                        "account",
                        "list",
                        "--resource-group",
                        &resource_group,
                        "--query",
                        "[0].name",
                        "--output",
                        "tsv",
                    ],
                )
                .await;
                match existing {
                    Some(name) => {
                        info!(storage_account = %name, "Found existing storage account");
                        name
                    }
                    None => {
                        let mut name: String = cmd::sanitize_name(&config.vm_name)
                            .chars()
                            .take(20)
                            .collect();
                        name.push_str(&suffix);
                        while name.len() < 3 {
                            name.push('0');
                        }
                        name
                    }
                }
            }
        };

        let container_name = config.container_name.unwrap_or_else(|| "workloads".into());

        info!(
            platform = "Azure",
            vm_name = %config.vm_name,
            vm_type = %vm_type,
            region = %region,
            resource_group = %resource_group,
            storage_account = %storage_account,
            "Configuration"
        );

        Ok(Self {
            vm_name: config.vm_name,
            vm_type,
            region,
            resource_group,
            storage_account,
            container_name,
            quiet: config.quiet,
        })
    }
}

// ── CloudProvider ─────────────────────────────────────────────────

#[async_trait]
impl CloudProvider for Azure {
    fn name(&self) -> &str {
        "azure"
    }

    fn disk_format(&self) -> DiskFormat {
        DiskFormat::Vhd
    }

    async fn check_deps(&self) -> Result<()> {
        if !cmd::command_exists("az").await {
            bail!(
                "Azure CLI (az) not found. Install it from https://aka.ms/InstallAzureCLIDeb"
            );
        }
        Ok(())
    }
}

// ── ImageManager ──────────────────────────────────────────────────

#[async_trait]
impl ImageManager for Azure {
    async fn upload_image(&mut self, disk_path: &Path, version: Option<&str>, force: bool) -> Result<()> {
        // Use versioned blob name if version provided.
        let blob_name = match version {
            Some(v) => format!("{}-{}.vhd", self.vm_name, v),
            None => disk_path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "disk.vhd".into()),
        };

        // 1. Create resource group.
        info!("Creating resource group");
        cmd::run_cmd(
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
        )
        .await?;

        // 2. Create storage account.
        info!("Creating storage account");
        cmd::run_cmd(
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
        )
        .await?;

        // 3. Create blob container.
        cmd::run_cmd(
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
        )
        .await?;

        // 4. Check if blob already exists with this version.
        if !force && version.is_some() && self.image_exists(version).await {
            info!(blob = %blob_name, "Image already exists, skipping upload");
            return Ok(());
        }

        // 5. Upload disk image (uses --overwrite, so force just skips the check).
        info!(blob = %blob_name, "Uploading disk image to blob storage");
        cmd::run_cmd(
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
                &blob_name,
                "--file",
                &disk_path.to_string_lossy(),
                "--overwrite",
            ],
            self.quiet,
        )
        .await?;

        Ok(())
    }

    async fn image_exists(&self, version: Option<&str>) -> bool {
        let blob_name = match version {
            Some(v) => format!("{}-{}.vhd", self.vm_name, v),
            None => return false,
        };

        cmd::run_cmd_silent(
            "az",
            &[
                "storage",
                "blob",
                "exists",
                "--account-name",
                &self.storage_account,
                "--container-name",
                &self.container_name,
                "--name",
                &blob_name,
                "--query",
                "exists",
                "--output",
                "tsv",
            ],
        )
        .await
    }

    async fn delete_image(&mut self, _version: Option<&str>) -> Result<()> {
        // Deleting the resource group removes all associated resources.
        info!("Deleting resource group (and all contained resources)");
        unimplemented!("Azure does not support deleting individual images, must delete entire resource group");
    }
}

// ── Compute ───────────────────────────────────────────────────────

#[async_trait]
impl Compute for Azure {
    async fn create_instance(&mut self, metadata: &Metadata) -> Result<InstanceInfo> {
        let mut args: Vec<String> = vec![
            "vm".into(),
            "create".into(),
            "--resource-group".into(),
            self.resource_group.clone(),
            "--name".into(),
            self.vm_name.clone(),
            "--size".into(),
            self.vm_type.clone(),
            "--location".into(),
            self.region.clone(),
            "--security-type".into(),
            "ConfidentialVM".into(),
        ];

        // Metadata as --tags key=value.
        if !metadata.is_empty() {
            args.push("--tags".into());
            for (key, value) in metadata {
                args.push(format!("{key}={value}"));
            }
        }

        info!("Creating CVM instance");
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        cmd::run_cmd("az", &arg_refs, self.quiet).await?;

        self.instance_info(&self.vm_name.clone()).await
    }

    async fn destroy_instance(&mut self, _name: &str) -> Result<()> {
        // Azure destroys by resource group, not individual VM name.
        info!("Deleting resource group");
        cmd::run_cmd(
            "az",
            &[
                "group",
                "delete",
                "--name",
                &self.resource_group,
                "--yes",
                "--no-wait",
            ],
            self.quiet,
        )
        .await?;
        Ok(())
    }

    async fn instance_info(&self, name: &str) -> Result<InstanceInfo> {
        let ip = cmd::try_capture(
            "az",
            &[
                "vm",
                "show",
                "--resource-group",
                &self.resource_group,
                "--name",
                name,
                "--show-details",
                "--query",
                "publicIps",
                "--output",
                "tsv",
            ],
        )
        .await;

        Ok(InstanceInfo {
            name: name.to_string(),
            public_ip: ip,
        })
    }
}

// ── Logs ──────────────────────────────────────────────────────────

#[async_trait]
impl Logs for Azure {
    async fn serial_logs(&self, name: &str) -> Result<String> {
        let output = cmd::try_capture(
            "az",
            &[
                "vm",
                "boot-diagnostics",
                "get-boot-log",
                "--resource-group",
                &self.resource_group,
                "--name",
                name,
            ],
        )
        .await;

        match output {
            Some(logs) => Ok(logs),
            None => bail!("Failed to retrieve boot diagnostics for VM '{name}'"),
        }
    }
}
