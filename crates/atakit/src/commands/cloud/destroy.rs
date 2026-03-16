use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use tracing::info;

use csp::{
    CloudResource, CloudResourceConfig, CloudResourceManager, DataDiskConfig, PortRule, Preserve,
    Protocol,
};

use crate::env::Env;

use crate::commands::deploy::config::{self, DeploymentConfig, PortDef, ProviderKind};

/// Destroy a deployed CVM instance and its associated cloud resources.
///
/// TARGET can be:
///   - A path to a deployment.json file
///   - A deployment name defined in atakit.json
#[derive(Args)]
pub struct Destroy {
    /// Deployment name from atakit.json, or path to deployment.json
    pub target: String,

    /// Platform (gcp, azure).
    /// Required when the atakit.json deployment has multiple platforms.
    #[arg(long)]
    pub platform: Option<String>,

    /// Skip confirmation prompts
    #[arg(long)]
    pub quiet: bool,

    /// Also delete the cloud disk image (preserved by default)
    #[arg(long)]
    pub delete_image: bool,

    /// Resources to preserve (comma-separated): firewall, disks, public-ip
    #[arg(long, value_delimiter = ',')]
    pub preserve: Vec<String>,
}

impl Destroy {
    pub async fn run(self, env: &Env) -> Result<()> {
        let deploy_config = self.load_config(env)?;
        let port_rules = build_port_rules(&deploy_config.ports);
        let data_disks = build_data_disks(&deploy_config.disks);
        let mut preserve = parse_preserve(&self.preserve);

        // Preserve the image by default — it's expensive to re-upload.
        if !self.delete_image && !preserve.contains(&Preserve::Image) {
            preserve.push(Preserve::Image);
        }

        // Use the config's image reference — matches what upload_image targets.
        let image_version = Some(deploy_config.image.to_string());

        let store = env.instance_store();

        let resource = self
            .build_resource(&deploy_config, env, &port_rules)
            .await?;

        let rc = CloudResourceConfig {
            name: deploy_config.name.clone(),
            image_path: PathBuf::new(), // unused for destroy
            image_version,
            force_upload_image: false,
            port_rules,
            data_disks,
            metadata: vec![],
            preserve,
        };

        let mut manager = CloudResourceManager::new(resource, rc);
        manager.destroy().await?;

        // Remove instance record.
        let platform = match deploy_config.provider {
            ProviderKind::Gcp => "gcp",
            ProviderKind::Azure => "azure",
            ProviderKind::Qemu => "qemu",
        };
        if store.delete(platform, &deploy_config.name)? {
            info!(name = %deploy_config.name, "Instance record removed");
        }

        println!();
        println!("  Destroyed: {}", deploy_config.name);

        Ok(())
    }

    /// Load a DeploymentConfig from a file or atakit.json (no image download).
    fn load_config(&self, env: &Env) -> Result<DeploymentConfig> {
        let target = &self.target;

        if target.ends_with(".json") || Path::new(target).is_file() {
            let path = Path::new(target);
            info!(file = %path.display(), "Loading deployment config from file");
            return config::load_from_file(path);
        }

        let atakit_config = env.config()?;
        let project_dir = env.config_dir()?.to_path_buf();

        info!(
            deployment = %target,
            config = %project_dir.display(),
            "Resolving deployment from atakit.json"
        );

        config::config_from_atakit_json(
            &atakit_config,
            target,
            self.platform.as_deref(),
            &project_dir,
        )
    }

    /// Construct the provider from config (mirrors runner.rs logic).
    async fn build_resource(
        &self,
        config: &DeploymentConfig,
        env: &Env,
        port_rules: &[PortRule],
    ) -> Result<CloudResource> {
        match config.provider {
            ProviderKind::Gcp => {
                let opts = config.gcp.as_ref().cloned().unwrap_or_default();
                let gcp_config = csp::gcp::GcpConfig {
                    vm_name: config.name.clone(),
                    vm_type: config.vm_type.clone(),
                    zone: opts.zone,
                    project_id: opts.project_id,
                    bucket_name: opts.bucket_name,
                    image_name: opts.image_name,
                    secure_boot_dir: None,
                    quiet: self.quiet,
                    port_rules: port_rules.to_vec(),
                    data_disks: vec![],
                };
                Ok(CloudResource::Gcp(csp::gcp::Gcp::new(gcp_config).await?))
            }
            ProviderKind::Azure => {
                let opts = config.azure.as_ref().cloned().unwrap_or_default();
                let azure_config = csp::azure::AzureConfig {
                    vm_name: config.name.clone(),
                    vm_type: config.vm_type.clone(),
                    region: opts.region,
                    resource_group: opts.resource_group,
                    storage_account: opts.storage_account,
                    container_name: opts.container_name,
                    secure_boot_dir: None,
                    port_rules: port_rules.to_vec(),
                    data_disks: vec![],
                    gallery_name: opts.gallery_name,
                    quiet: self.quiet,
                };
                Ok(CloudResource::Azure(
                    csp::azure::Azure::new(azure_config).await?,
                ))
            }
            ProviderKind::Qemu => {
                let opts = config.qemu.as_ref().cloned().unwrap_or_default();
                let instance_dir = opts
                    .instance_dir
                    .unwrap_or_else(|| env.qemu_disk_dir(&config.name));
                let ovmf_path = match opts.ovmf_path {
                    Some(p) => p,
                    None => env.ensure_ovmf()?,
                };
                let qemu_config = csp::qemu::QemuConfig {
                    vm_name: config.name.clone(),
                    instance_dir,
                    ovmf_path,
                    disk_tar_gz: PathBuf::new(),
                    quiet: self.quiet,
                    port_rules: port_rules.to_vec(),
                };
                Ok(CloudResource::Qemu(csp::qemu::Qemu::new(qemu_config)?))
            }
        }
    }
}

// ── Converters ───────────────────────────────────────────────────

fn build_port_rules(ports: &[PortDef]) -> Vec<PortRule> {
    ports
        .iter()
        .map(|p| PortRule {
            port: p.port,
            protocol: match p.protocol.as_str() {
                "udp" => Protocol::Udp,
                _ => Protocol::Tcp,
            },
        })
        .collect()
}

fn build_data_disks(disks: &[config::DiskDef]) -> Vec<DataDiskConfig> {
    disks
        .iter()
        .map(|d| DataDiskConfig {
            name: d.name.clone(),
            size: d.size.clone(),
        })
        .collect()
}

fn parse_preserve(values: &[String]) -> Vec<Preserve> {
    values
        .iter()
        .filter_map(|s| match s.as_str() {
            "image" => Some(Preserve::Image),
            "firewall" => Some(Preserve::Firewall),
            "disks" => Some(Preserve::Disks),
            "public-ip" => Some(Preserve::PublicIp),
            _ => None,
        })
        .collect()
}
