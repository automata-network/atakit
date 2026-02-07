mod azure;
mod fat_image;
pub(crate) mod gcp;
mod qemu;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use clap::Args;
use flate2::read::GzDecoder;
use tar::Archive;
use tracing::{debug, info, warn};

use indexmap::IndexMap;
use serde::Deserialize;

use crate::types::{AtakitConfig, DiskDef};
use crate::Config;

/// Minimal docker-compose representation for port/volume extraction.
#[derive(Debug, Deserialize)]
struct DockerCompose {
    #[serde(default)]
    services: IndexMap<String, ComposeServiceMinimal>,
}

#[derive(Debug, Deserialize)]
struct ComposeServiceMinimal {
    #[serde(default)]
    volumes: Vec<String>,
    #[serde(default)]
    ports: Vec<String>,
}

/// Deploy workloads to cloud platforms using atakit.json configuration.
#[derive(Args)]
pub struct Deploy {
    /// Comma-separated platforms to deploy to (e.g., "gcp,azure")
    #[arg(long, value_delimiter = ',')]
    pub platforms: Vec<String>,

    /// Skip confirmation prompts before running commands
    #[arg(long)]
    pub quiet: bool,

    /// Skip disk image building (workload injection + API token generation)
    /// and go directly to cloud platform deployment.
    /// Assumes the disk image is already prepared.
    #[arg(long)]
    pub no_build: bool,

    /// Path to additional-data directory (default: ./additional-data/)
    #[arg(long)]
    pub additional_data: Option<PathBuf>,

    /// Deployment names from atakit.json (deploys all if omitted)
    pub deployments: Vec<String>,
}

#[allow(dead_code)]
pub(crate) trait CloudPlatform {
    fn name(&self) -> &str;
    fn disk_filename(&self) -> &str;
    fn check_deps(&self, cfg: &Config) -> Result<()>;
    /// Prepare the platform disk image (upload to cloud / extract locally).
    fn prepare_image(&mut self, cfg: &Config) -> Result<()>;
    /// Attach a pre-built FAT image containing additional-data files.
    /// `img_path` is `None` when there is no additional-data to inject.
    fn attach_additional_data_disk(&mut self, img_path: Option<&Path>) -> Result<()>;
    /// Configure network / firewall rules before VM launch.
    fn setup_network(&mut self) -> Result<()>;
    /// Create or attach the data disk if configured.
    fn ensure_data_disk(&mut self) -> Result<()>;
    /// Launch the VM instance (may block for local platforms).
    fn launch(&self) -> Result<()>;
    /// Post-launch actions (save artifacts, retrieve IP, cleanup).
    fn post_launch(&self) -> Result<()>;
}

fn run_cloud_deploy(
    p: &mut dyn CloudPlatform,
    cfg: &Config,
    additional_data_img: Option<&Path>,
) -> Result<()> {
    p.check_deps(cfg)?;
    p.prepare_image(cfg)?;
    p.attach_additional_data_disk(additional_data_img)?;
    p.setup_network()?;
    p.ensure_data_disk()?;
    p.launch()?;
    p.post_launch()?;
    Ok(())
}

/// Run a command with optional confirmation prompt.
pub(super) fn run_cmd(program: &str, args: &[&str], quiet: bool) -> Result<()> {
    let full_cmd = format!("{} {}", program, args.join(" "));
    println!();
    println!("  > {}", full_cmd);

    if !quiet {
        print!("  Proceed? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            bail!("Aborted: {}", full_cmd);
        }
    }

    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("Failed to run {}", full_cmd))?;
    if !status.success() {
        bail!("{} failed with status {}", full_cmd, status);
    }
    Ok(())
}

/// Run a command silently without prompting. Returns true on success.
pub(super) fn run_cmd_silent(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

impl Deploy {
    pub fn run(self, config: &Config) -> Result<()> {
        let atakit_config = AtakitConfig::load()?;
        let project_dir = std::env::current_dir()?;
        let artifact_dir = project_dir.join("ata_artifacts");
        let additional_data_dir = self
            .additional_data
            .clone()
            .unwrap_or_else(|| project_dir.join("additional-data"));

        let deployment_names: Vec<String> = if self.deployments.is_empty() {
            atakit_config.deployment.keys().cloned().collect()
        } else {
            self.deployments.clone()
        };

        if deployment_names.is_empty() {
            bail!("No deployments defined in atakit.json");
        }

        for dep_name in &deployment_names {
            let dep_def = atakit_config.deployment.get(dep_name).ok_or_else(|| {
                anyhow::anyhow!(
                    "Deployment '{}' not found in atakit.json. Available: {}",
                    dep_name,
                    atakit_config
                        .deployment
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;

            let target_platforms: Vec<&String> = if self.platforms.is_empty() {
                dep_def.platforms.keys().collect()
            } else {
                self.platforms.iter().collect()
            };

            if target_platforms.is_empty() {
                warn!(deployment = %dep_name, "No matching platforms, skipping");
                continue;
            }

            let workload_name = dep_def.workload.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Deployment '{}' is missing the 'workload' field in atakit.json",
                    dep_name
                )
            })?;

            if !atakit_config
                .workloads
                .iter()
                .any(|w| w.name == workload_name)
            {
                let available: Vec<&str> = atakit_config
                    .workloads
                    .iter()
                    .map(|w| w.name.as_str())
                    .collect();
                bail!(
                    "Deployment '{}' references workload '{}' which is not defined in atakit.json. Available workloads: [{}]",
                    dep_name,
                    workload_name,
                    available.join(", ")
                );
            }

            let tar_path = artifact_dir.join(format!("{}.tar.gz", workload_name));
            if !self.no_build && !tar_path.exists() {
                bail!(
                    "Workload artifact '{}' not found. Run `atakit build-workload` first.",
                    tar_path.display()
                );
            }

            // Extract port mappings from docker-compose for firewall rules.
            let compose_ports = extract_compose_ports(&atakit_config, workload_name, &project_dir);

            // Resolve data disks: if the compose file uses named volumes,
            // find matching disk definitions by name from atakit.json.
            let volume_names =
                extract_compose_named_volumes(&atakit_config, workload_name, &project_dir)?;
            let disk_defs: Vec<&DiskDef> = volume_names
                .iter()
                .filter_map(|vol| atakit_config.disks.iter().find(|d| d.name == *vol))
                .collect();

            // Build additional-data FAT image (shared across platforms for this deployment).
            let deploy_dir = artifact_dir.join("deploy").join(dep_name);
            std::fs::create_dir_all(&deploy_dir)?;
            let img_path = deploy_dir.join("additional-data.img");
            let additional_data_img =
                fat_image::create_additional_data_image(&additional_data_dir, &img_path)?;

            for platform in target_platforms {
                info!(deployment = %dep_name, platform = %platform, "Deploying");

                if self.no_build {
                    let disk_file = disk_filename(platform.as_str())?;
                    let disk_path = config.disk_dir.join(disk_file);
                    if !disk_path.exists() {
                        bail!(
                            "Disk image '{}' not found. Build the image first or remove --no-build.",
                            disk_path.display()
                        );
                    }
                    info!("--no-build: skipping disk image build, using existing disk");
                } else {
                    debug!(tar_path = %tar_path.display(), config = ?config, "Using workload artifact");

                    prepare_disk_image(config, platform.as_str(), &tar_path)?;

                    let disk_file = disk_filename(platform.as_str())?;
                    info!("Generating API token");
                    config.run_script_default(
                        "generate_api_token.sh",
                        &[disk_file, script_csp(platform.as_str()), dep_name],
                    )?;
                }

                match platform.as_str() {
                    "gcp" => {
                        let platform_config = &dep_def.platforms[platform.as_str()];
                        let mut gcp = gcp::Gcp::new(
                            dep_name,
                            platform_config,
                            config,
                            self.quiet,
                            &compose_ports,
                            &disk_defs,
                        )?;
                        run_cloud_deploy(&mut gcp, config, additional_data_img.as_deref())?;
                    }
                    "gcp_qemu" => {
                        let mut q = qemu::Qemu::new(
                            dep_name,
                            config,
                            true,
                            &compose_ports,
                            &disk_defs,
                        )?;
                        run_cloud_deploy(&mut q, config, additional_data_img.as_deref())?;
                    }
                    "azure" => {
                        let platform_config = &dep_def.platforms[platform.as_str()];
                        let mut az = azure::Azure::new(
                            dep_name,
                            platform_config,
                            &tar_path,
                            self.quiet,
                            &additional_data_dir,
                        )?;
                        run_cloud_deploy(&mut az, config, additional_data_img.as_deref())?;
                    }
                    other => bail!("Unsupported platform: {}", other),
                }

                // Skip golden measurements for gcp_qemu — the VM has already
                // exited by the time QEMU returns, so there is nothing to measure.
                if !platform.contains("_qemu") {
                    info!("Collecting golden measurements");
                    config.run_script_default(
                        "get_golden_measurements.sh",
                        &[platform.as_str(), dep_name],
                    )?;
                }
            }
        }

        info!("Deployment complete");
        Ok(())
    }
}

fn disk_filename(platform: &str) -> Result<&str> {
    match platform {
        "gcp" | "gcp_qemu" => Ok("gcp_disk.tar.gz"),
        "azure" => Ok("azure_disk.vhd"),
        "aws" => Ok("aws_disk.vmdk"),
        other => bail!("Unknown platform: {}", other),
    }
}

/// Map platform names to the cloud-specific prefix used by shell scripts.
/// `gcp_qemu` reuses GCP disk preparation, so scripts see `"gcp"`.
fn script_csp(platform: &str) -> &str {
    match platform {
        "gcp_qemu" => "gcp",
        other => other,
    }
}

fn prepare_disk_image(config: &Config, platform: &str, tar_path: &Path) -> Result<()> {
    let disk_file = disk_filename(platform)?;
    let disk_path = config.disk_dir.join(disk_file);

    if !disk_path.exists() {
        info!(disk = %disk_file, "Disk image not found, downloading");
        config.run_script_default("get_disk_image.sh", &[script_csp(platform)])?;
        if !disk_path.exists() {
            bail!(
                "Disk image '{}' still not found in {} after download",
                disk_file,
                config.disk_dir.display()
            );
        }
    }

    let workload_dir = config.disk_dir.join("workload");
    std::fs::create_dir_all(&workload_dir).context("Failed to create workload directory")?;

    // Extract workload tar.gz into workload directory.
    info!(
        workload = %tar_path.display(),
        dest = %workload_dir.display(),
        "Extracting workload archive"
    );
    let tar_file = std::fs::File::open(tar_path)
        .with_context(|| format!("Failed to open {}", tar_path.display()))?;
    let decoder = GzDecoder::new(tar_file);
    let mut archive = Archive::new(decoder);
    archive
        .unpack(&workload_dir)
        .with_context(|| format!("Failed to extract {}", tar_path.display()))?;

    // Call update_disk.sh to inject workload into disk image.
    info!(disk = %disk_file, "Updating disk image with workload");
    let result = config.run_script("update_disk.sh", &[disk_file], &workload_dir);

    // Clean up workload directory regardless of success.
    if let Err(e) = std::fs::remove_dir_all(&workload_dir) {
        warn!(error = %e, "Failed to clean up workload directory");
    }

    result?;
    Ok(())
}

/// Extract port mappings from the docker-compose file associated with a workload.
///
/// Returns `(service_name, port_string)` tuples. On any error (file not found,
/// parse failure), returns an empty vec so deployment can still proceed with
/// default firewall ports.
fn extract_compose_ports(
    atakit_config: &AtakitConfig,
    workload_name: &str,
    project_dir: &Path,
) -> Vec<(String, String)> {
    let wl_def = match atakit_config
        .workloads
        .iter()
        .find(|w| w.name == workload_name)
    {
        Some(w) => w,
        None => return vec![],
    };
    let compose_path = project_dir.join(&wl_def.docker_compose);
    let content = match std::fs::read_to_string(&compose_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let compose: DockerCompose = match serde_yaml::from_str(&content) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    compose
        .services
        .iter()
        .flat_map(|(name, svc)| svc.ports.iter().map(move |p| (name.clone(), p.clone())))
        .collect()
}

/// Extract all named volumes from the docker-compose file for a workload.
///
/// Returns the deduplicated list of named volume names. On any error,
/// returns an empty vec so deployment can still proceed.
fn extract_compose_named_volumes(
    atakit_config: &AtakitConfig,
    workload_name: &str,
    project_dir: &Path,
) -> Result<Vec<String>> {
    let wl_def = atakit_config
        .workloads
        .iter()
        .find(|w| w.name == workload_name)
        .with_context(|| format!("Workload '{}' not found in atakit.json", workload_name))?;
    let compose_path = project_dir.join(&wl_def.docker_compose);
    let content = std::fs::read_to_string(&compose_path)
        .with_context(|| format!("Failed to read {}", compose_path.display()))?;
    let compose: DockerCompose = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", compose_path.display()))?;
    let mut named_volumes: Vec<String> = Vec::new();
    for svc in compose.services.values() {
        for vol in &svc.volumes {
            let parts: Vec<&str> = vol.splitn(3, ':').collect();
            if parts.len() < 2 {
                continue;
            }
            let host = parts[0];
            if !(host.starts_with('.') || host.starts_with('/') || host.starts_with('~')) {
                if !named_volumes.contains(&host.to_string()) {
                    named_volumes.push(host.to_string());
                }
            }
        }
    }
    Ok(named_volumes)
}
