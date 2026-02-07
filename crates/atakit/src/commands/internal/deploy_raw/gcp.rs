use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use tracing::info;

use crate::config::{self, Config};

#[derive(Args)]
pub struct DeployGcp {
    #[arg(long = "vm_name", alias = "vm-name", default_value = "cvm-test")]
    pub vm_name: String,

    #[arg(long = "project_id", alias = "project-id")]
    pub project_id: Option<String>,

    #[arg(long)]
    pub bucket: Option<String>,

    #[arg(long, default_value = "asia-southeast1-b")]
    pub region: String,

    #[arg(long = "vm_type", alias = "vm-type", default_value = "c3-standard-4")]
    pub vm_type: String,

    #[arg(long = "additional_ports", alias = "additional-ports")]
    pub additional_ports: Option<String>,

    #[arg(long)]
    pub ip: Option<String>,

    #[arg(long = "add-workload", num_args = 0..=1, default_missing_value = "./workload")]
    pub add_workload: Option<PathBuf>,

    #[arg(long = "attach-disk")]
    pub attach_disk: Option<String>,

    #[arg(long = "disk-size")]
    pub disk_size: Option<String>,
}

impl DeployGcp {
    pub fn run(self, cfg: &Config) -> Result<()> {
        let workload_dir = super::resolve_workload_dir(&self.add_workload, cfg)?;
        let bucket = super::resolve_bucket(cfg, &self.bucket, "gcp", &self.vm_name);
        let ports = self.additional_ports.as_deref().unwrap_or("");
        let ip = self.ip.as_deref().unwrap_or("");
        let attach_disk = self.attach_disk.as_deref().unwrap_or("");
        let disk_size = self.disk_size.as_deref().unwrap_or("");
        let artifact_dir_str = cfg.artifact_dir.to_string_lossy().to_string();

        cfg.run_script(
            "check_options.sh",
            &["gcp", &self.vm_type, &self.region],
            &workload_dir,
        )?;

        cfg.run_script("get_disk_image.sh", &["gcp"], &workload_dir)?;

        info!(workload_dir = %workload_dir.display(), "Adding workload");
        cfg.run_script("update_disk.sh", &["gcp_disk.tar.gz"], &workload_dir)?;

        cfg.run_script("check_csp_deps.sh", &["gcp"], &workload_dir)?;

        let project_id = match &self.project_id {
            Some(id) => id.clone(),
            None => {
                let id = config::try_capture("gcloud", &["config", "get-value", "project"]);
                match id {
                    Some(id) => {
                        info!(project_id = %id, "Using default gcloud project");
                        id
                    }
                    None => {
                        bail!(
                            "PROJECT_ID not provided and no default found in gcloud config.\n\
                             To fix run: gcloud init --console-only --no-launch-browser"
                        );
                    }
                }
            }
        };

        cfg.run_script(
            "generate_api_token.sh",
            &["gcp_disk.tar.gz", "gcp", &self.vm_name],
            &workload_dir,
        )?;

        info!(
            platform = "GCP",
            vm_name = %self.vm_name,
            region = %self.region,
            project_id = %project_id,
            vm_type = %self.vm_type,
            bucket = %bucket,
            additional_ports = %ports,
            attach_disk = %if attach_disk.is_empty() { "none" } else { attach_disk },
            disk_size = %if disk_size.is_empty() { "default" } else { disk_size },
            "Deployment configuration"
        );

        cfg.run_script(
            "make_gcp_vm.sh",
            &[
                &self.vm_name,
                &self.region,
                &project_id,
                &self.vm_type,
                &bucket,
                ports,
                ip,
                attach_disk,
                disk_size,
                &artifact_dir_str,
            ],
            &workload_dir,
        )?;

        cfg.run_script(
            "get_golden_measurements.sh",
            &["gcp", &self.vm_name],
            &workload_dir,
        )?;

        info!(vm_name = %self.vm_name, "Deployment complete");
        Ok(())
    }
}
