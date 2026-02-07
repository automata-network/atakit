use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use tracing::{info, warn};

use crate::config::{self, Config};

#[derive(Args)]
pub struct DeployAzure {
    #[arg(long = "vm_name", alias = "vm-name", default_value = "cvm-test")]
    pub vm_name: String,

    #[arg(long = "vm_type", alias = "vm-type", default_value = "Standard_DC2es_v6")]
    pub vm_type: String,

    #[arg(long, default_value = "East US")]
    pub region: String,

    #[arg(long = "resource_group", alias = "resource-group")]
    pub resource_group: Option<String>,

    #[arg(long = "storage_account", alias = "storage-account")]
    pub storage_account: Option<String>,

    #[arg(long = "gallery_name", alias = "gallery-name")]
    pub gallery_name: Option<String>,

    #[arg(long = "additional_ports", alias = "additional-ports")]
    pub additional_ports: Option<String>,

    #[arg(long = "add-workload", num_args = 0..=1, default_missing_value = "./workload")]
    pub add_workload: Option<PathBuf>,

    #[arg(long = "attach-disk")]
    pub attach_disk: Option<String>,

    #[arg(long = "disk-size")]
    pub disk_size: Option<String>,
}

impl DeployAzure {
    pub fn run(self, cfg: &Config) -> Result<()> {
        let workload_dir = super::resolve_workload_dir(&self.add_workload, cfg)?;
        let ports = self.additional_ports.as_deref().unwrap_or("");
        let attach_disk = self.attach_disk.as_deref().unwrap_or("");
        let disk_size = self.disk_size.as_deref().unwrap_or("");
        let artifact_dir_str = cfg.artifact_dir.to_string_lossy().to_string();

        cfg.run_script("check_csp_deps.sh", &["azure"], &workload_dir)?;

        let resource_group = self
            .resource_group
            .unwrap_or_else(|| format!("{}_Rg", self.vm_name));

        let suffix = config::random_suffix(4);

        let storage_account = match self.storage_account {
            Some(s) => s,
            None => {
                let existing = config::try_capture(
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
                );
                match existing {
                    Some(name) => {
                        info!(storage_account = %name, "Found existing storage account");
                        name
                    }
                    None => {
                        let mut name: String =
                            config::sanitize_name(&self.vm_name).chars().take(20).collect();
                        name.push_str(&suffix);
                        while name.len() < 3 {
                            name.push('0');
                        }
                        name
                    }
                }
            }
        };

        let gallery_name = match self.gallery_name {
            Some(g) => g,
            None => {
                let existing = config::try_capture(
                    "az",
                    &[
                        "sig",
                        "list",
                        "--resource-group",
                        &resource_group,
                        "--query",
                        "[0].name",
                        "--output",
                        "tsv",
                    ],
                );
                match existing {
                    Some(name) => {
                        info!(gallery = %name, "Found existing shared image gallery");
                        name
                    }
                    None => {
                        let sanitized: String = self
                            .vm_name
                            .to_lowercase()
                            .chars()
                            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
                            .collect();
                        let trimmed = sanitized
                            .trim_start_matches(|c: char| c == '_' || c == '.')
                            .trim_end_matches(|c: char| c == '_' || c == '.');
                        let base: String = trimmed.chars().take(80).collect();
                        format!("{}{}", base, suffix)
                    }
                }
            }
        };

        let mut region = self.region;
        if let Some(location) = config::try_capture(
            "az",
            &[
                "group",
                "show",
                "--name",
                &resource_group,
                "--query",
                "location",
                "--output",
                "tsv",
            ],
        ) {
            let query = format!("[?name=='{}'].displayName", location);
            if let Some(friendly) = config::try_capture(
                "az",
                &[
                    "account",
                    "list-locations",
                    "--query",
                    &query,
                    "--output",
                    "tsv",
                ],
            ) {
                if friendly != region {
                    warn!(from = %region, to = %friendly, "Resource group region mismatch, updating");
                    region = friendly;
                }
            }
        }

        cfg.run_script(
            "check_options.sh",
            &["azure", &self.vm_type, &region],
            &workload_dir,
        )?;

        cfg.run_script("get_disk_image.sh", &["azure"], &workload_dir)?;

        info!(workload_dir = %workload_dir.display(), "Adding workload");
        cfg.run_script("update_disk.sh", &["azure_disk.vhd"], &workload_dir)?;

        cfg.run_script(
            "generate_api_token.sh",
            &["azure_disk.vhd", "azure", &self.vm_name],
            &workload_dir,
        )?;

        info!(
            platform = "Azure",
            vm_name = %self.vm_name,
            resource_group = %resource_group,
            region = %region,
            vm_type = %self.vm_type,
            additional_ports = %ports,
            storage_account = %storage_account,
            gallery = %gallery_name,
            attach_disk = %if attach_disk.is_empty() { "none" } else { attach_disk },
            disk_size = %if disk_size.is_empty() { "default" } else { disk_size },
            "Deployment configuration"
        );

        cfg.run_script(
            "make_azure_vm.sh",
            &[
                &self.vm_name,
                &resource_group,
                &self.vm_type,
                ports,
                &storage_account,
                &gallery_name,
                &region,
                attach_disk,
                disk_size,
                &artifact_dir_str,
            ],
            &workload_dir,
        )?;

        cfg.run_script(
            "get_golden_measurements.sh",
            &["azure", &self.vm_name],
            &workload_dir,
        )?;

        info!(vm_name = %self.vm_name, "Deployment complete");
        Ok(())
    }
}
