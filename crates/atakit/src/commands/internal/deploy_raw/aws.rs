use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use tracing::info;

use crate::Config;

#[derive(Args)]
pub struct DeployAws {
    #[arg(long = "vm_name", alias = "vm-name", default_value = "cvm-test")]
    pub vm_name: String,

    #[arg(long)]
    pub bucket: Option<String>,

    #[arg(long, default_value = "us-east-2")]
    pub region: String,

    #[arg(long = "vm_type", alias = "vm-type", default_value = "m6a.large")]
    pub vm_type: String,

    #[arg(long = "additional_ports", alias = "additional-ports")]
    pub additional_ports: Option<String>,

    #[arg(long)]
    pub eip: Option<String>,

    #[arg(long = "add-workload", num_args = 0..=1, default_missing_value = "./workload")]
    pub add_workload: Option<PathBuf>,

    #[arg(long = "attach-disk")]
    pub attach_disk: Option<String>,

    #[arg(long = "disk-size")]
    pub disk_size: Option<String>,
}

impl DeployAws {
    pub fn run(self, cfg: &Config) -> Result<()> {
        let workload_dir = super::resolve_workload_dir(&self.add_workload, cfg)?;
        let bucket = super::resolve_bucket(cfg, &self.bucket, "aws", &self.vm_name);
        let ports = self.additional_ports.as_deref().unwrap_or("");
        let eip = self.eip.as_deref().unwrap_or("");
        let attach_disk = self.attach_disk.as_deref().unwrap_or("");
        let disk_size = self.disk_size.as_deref().unwrap_or("");
        let artifact_dir_str = cfg.artifact_dir.to_string_lossy().to_string();

        cfg.run_script(
            "check_options.sh",
            &["aws", &self.vm_type, &self.region],
            &workload_dir,
        )?;

        cfg.run_script("get_disk_image.sh", &["aws"], &workload_dir)?;

        info!(workload_dir = %workload_dir.display(), "Adding workload");
        cfg.run_script("update_disk.sh", &["aws_disk.vmdk"], &workload_dir)?;

        cfg.run_script("check_csp_deps.sh", &["aws"], &workload_dir)?;

        cfg.run_script(
            "generate_api_token.sh",
            &["aws_disk.vmdk", "aws", &self.vm_name],
            &workload_dir,
        )?;

        info!(
            platform = "AWS",
            vm_name = %self.vm_name,
            region = %self.region,
            vm_type = %self.vm_type,
            bucket = %bucket,
            eip = %eip,
            additional_ports = %ports,
            attach_disk = %if attach_disk.is_empty() { "none" } else { attach_disk },
            disk_size = %if disk_size.is_empty() { "default" } else { disk_size },
            "Deployment configuration"
        );

        cfg.run_script(
            "make_aws_vm.sh",
            &[
                &self.vm_name,
                &self.region,
                &self.vm_type,
                &bucket,
                ports,
                eip,
                attach_disk,
                disk_size,
                &artifact_dir_str,
            ],
            &workload_dir,
        )?;

        cfg.run_script(
            "get_golden_measurements.sh",
            &["aws", &self.vm_name],
            &workload_dir,
        )?;

        info!(vm_name = %self.vm_name, "Deployment complete");
        Ok(())
    }
}
