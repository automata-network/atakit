use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use automata_linux_release::{ImageStore, Platform};
use serde::{Deserialize, Serialize};
use tracing::info;
use workload_compose::ComposeSummary;

use crate::types::{AtakitConfig, DeploymentDef, PlatformConfig};

// ── Core deployment configuration ────────────────────────────────

/// Deployment configuration (serializable to/from JSON).
///
/// Loaded from a standalone JSON file or assembled from atakit.json.
/// The `image` specifies which automata-linux release to use;
/// the actual image path is resolved at runtime via `ImageStore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub name: String,
    pub provider: ProviderKind,
    /// Relative path to the workload package (e.g., "workload.tar.gz").
    /// Resolved relative to the deployment.json file's directory.
    pub workload: String,
    /// Release tag for automata-linux disk images (e.g., "v0.5.0").
    /// If omitted, the latest local release is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<DiskDef>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp: Option<GcpOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<AzureOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu: Option<QemuOptions>,
}

/// Resolved paths from ImageStore (for the runner).
#[derive(Debug)]
pub struct ResolvedPaths {
    pub image: PathBuf,
    pub secure_boot_dir: Option<PathBuf>,
    /// The release version tag (e.g., "v0.5.0") for image naming.
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Gcp,
    Azure,
    Qemu,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortDef {
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskDef {
    pub name: String,
    pub size: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GcpOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AzureOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct QemuOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ovmf_path: Option<PathBuf>,
}

// ── Loading ──────────────────────────────────────────────────────

/// Load a DeploymentConfig from a standalone JSON file.
pub fn load_from_file(path: &Path) -> Result<DeploymentConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))
}

/// Resolve image paths for a DeploymentConfig using ImageStore.
///
/// If the image is not found locally, it will be automatically downloaded.
/// `image_version_override` overrides the config's image version tag.
pub async fn resolve_deployment(
    config: &DeploymentConfig,
    store: &ImageStore,
    image_version_override: Option<&str>,
) -> Result<ResolvedPaths> {
    let platform = provider_to_platform(&config.provider);

    // CLI override takes precedence over config.
    let image_version = image_version_override.or(config.image.as_deref());
    let (image_path, resolved_tag) = resolve_image(store, platform, image_version).await?;

    // Get secure boot dir if available (GCP only).
    let secure_boot_dir = resolved_tag.as_ref().and_then(|tag| {
        let dir = store.certs_dir(tag);
        dir.exists().then_some(dir)
    });

    info!(
        deployment = %config.name,
        image = resolved_tag.as_deref().unwrap_or("(latest)"),
        path = %image_path.display(),
        "Resolved deployment"
    );

    Ok(ResolvedPaths {
        image: image_path,
        secure_boot_dir,
        version: resolved_tag,
    })
}

/// Resolve a deployment by name from atakit.json.
///
/// `platform_override` selects the platform when a deployment has multiple.
/// `image_version_override` overrides the config's image version tag.
/// `image_dir` is the ImageStore base directory for automata-linux releases.
/// `config_dir` is the directory containing atakit.json.
pub async fn resolve_from_atakit_json(
    atakit_config: &AtakitConfig,
    deployment_name: &str,
    platform_override: Option<&str>,
    image_version_override: Option<&str>,
    image_dir: &Path,
    config_dir: &Path,
) -> Result<(DeploymentConfig, ResolvedPaths)> {
    let deploy_def = atakit_config
        .deployment
        .get(deployment_name)
        .with_context(|| {
            let available: Vec<&str> = atakit_config
                .deployment
                .keys()
                .map(|k| k.as_str())
                .collect();
            format!(
                "Deployment '{}' not found in atakit.json. Available: {}",
                deployment_name,
                if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                }
            )
        })?;

    let (platform_name, platform_config) = resolve_platform(deploy_def, platform_override)?;

    let provider = match platform_name.as_str() {
        "gcp" => ProviderKind::Gcp,
        "azure" => ProviderKind::Azure,
        "qemu" => ProviderKind::Qemu,
        other => bail!("Unsupported provider '{other}'. Supported: gcp, azure, qemu"),
    };

    // Extract ports and disks from workload's docker-compose if available.
    let (ports, volume_names) = extract_workload_info(atakit_config, deploy_def, config_dir)?;

    // Match named volumes to disk definitions in atakit.json.
    let disks = resolve_disks(atakit_config, &volume_names);

    // Build the config (without resolved image).
    let config = DeploymentConfig {
        name: deployment_name.to_string(),
        provider,
        workload: "workload.tar.gz".to_string(),
        image: deploy_def.image.clone(),
        vm_type: platform_config.vmtype.clone(),
        quiet: None,
        ports,
        disks,
        metadata: HashMap::new(),
        gcp: build_gcp_options_simple(&platform_name, platform_config),
        azure: build_azure_options(&platform_name, platform_config),
        qemu: None,
    };

    // Resolve to get the actual image path (auto-downloads if needed).
    let store = ImageStore::new(image_dir).with_token_from_env();
    let paths = resolve_deployment(&config, &store, image_version_override).await?;
    Ok((config, paths))
}

// ── Helpers ──────────────────────────────────────────────────────

fn resolve_platform<'a>(
    deploy_def: &'a DeploymentDef,
    platform_override: Option<&str>,
) -> Result<(String, &'a PlatformConfig)> {
    if deploy_def.platforms.is_empty() {
        bail!("Deployment has no platforms defined");
    }

    match platform_override {
        Some(name) => {
            let config = deploy_def.platforms.get(name).with_context(|| {
                let available: Vec<&str> =
                    deploy_def.platforms.keys().map(|k| k.as_str()).collect();
                format!(
                    "Platform '{}' not found. Available: {}",
                    name,
                    available.join(", ")
                )
            })?;
            Ok((name.to_string(), config))
        }
        None => {
            if deploy_def.platforms.len() > 1 {
                let available: Vec<&str> =
                    deploy_def.platforms.keys().map(|k| k.as_str()).collect();
                bail!(
                    "Multiple platforms defined ({}). Use --platform to select one.",
                    available.join(", ")
                );
            }
            let (name, config) = deploy_def.platforms.iter().next().unwrap();
            Ok((name.clone(), config))
        }
    }
}

/// Map ProviderKind to automata-linux-release Platform.
fn provider_to_platform(provider: &ProviderKind) -> Platform {
    match provider {
        ProviderKind::Gcp | ProviderKind::Qemu => Platform::Gcp,
        ProviderKind::Azure => Platform::Azure,
    }
}

/// Resolve disk image path using ImageStore.
///
/// If the image is not found locally, it will be automatically downloaded.
/// Returns the image path and optionally the release tag used.
async fn resolve_image(
    store: &ImageStore,
    platform: Platform,
    image: Option<&str>,
) -> Result<(PathBuf, Option<String>)> {
    // If a specific release tag is requested, use that.
    if let Some(tag) = image {
        let path = store.image_path(tag, platform);
        if path.exists() {
            info!(tag, %platform, "Using local disk image");
            return Ok((path, Some(tag.to_string())));
        }

        // Not found locally, download it.
        info!(tag, %platform, "Disk image not found locally, downloading...");
        let paths = store.download(tag, &[platform]).await?;
        if let Some(path) = paths.into_iter().next() {
            return Ok((path, Some(tag.to_string())));
        }
        bail!("Failed to download disk image for release {tag}");
    }

    // No specific tag requested, check local images first.
    let local_tags = store.list_local()?;
    for tag in local_tags.iter().rev() {
        let path = store.image_path(tag, platform);
        if path.exists() {
            info!(tag, %platform, "Using local disk image");
            return Ok((path, Some(tag.clone())));
        }
    }

    // No local images, find and download the latest release with disk images.
    info!(%platform, "No local images found, fetching latest release...");
    let release = store.client().find_latest_image_release().await?;
    let tag = &release.tag_name;

    info!(tag, %platform, "Downloading disk image...");
    let paths = store.download(tag, &[platform]).await?;
    if let Some(path) = paths.into_iter().next() {
        return Ok((path, Some(tag.clone())));
    }

    bail!("Failed to download disk image for latest release {tag}");
}

/// Extract port and volume information from the workload's docker-compose.
fn extract_workload_info(
    atakit_config: &AtakitConfig,
    deploy_def: &DeploymentDef,
    config_dir: &Path,
) -> Result<(Vec<PortDef>, Vec<String>)> {
    let workload_name = match &deploy_def.workload {
        Some(name) => name,
        None => return Ok((Vec::new(), Vec::new())),
    };

    let wl_def = atakit_config
        .workloads
        .iter()
        .find(|w| &w.name == workload_name)
        .with_context(|| {
            format!(
                "Workload '{workload_name}' referenced in deployment but not found in workloads[]"
            )
        })?;

    let compose_path = config_dir.join(&wl_def.docker_compose);
    let content = match std::fs::read_to_string(&compose_path) {
        Ok(c) => c,
        Err(_) => {
            info!(path = %compose_path.display(), "Docker-compose not found, skipping port/volume extraction");
            return Ok((Vec::new(), Vec::new()));
        }
    };

    let compose = workload_compose::from_yaml_str(&content)
        .with_context(|| format!("Failed to parse {}", compose_path.display()))?;

    let mut ports = Vec::new();
    let mut volume_names = Vec::new();

    for (_service_name, service) in &compose.services {
        for port in &service.ports {
            if let Some(host_port) = port.host_port {
                ports.push(PortDef {
                    port: host_port,
                    protocol: port.protocol.clone(),
                });
            }
        }

        for vol in &service.volumes {
            if let workload_compose::WorkloadVolumeMount::Named { name, .. } = vol {
                if !volume_names.contains(name) {
                    volume_names.push(name.clone());
                }
            }
        }
    }

    Ok((ports, volume_names))
}

/// Match named volumes from docker-compose to disk definitions in atakit.json.
fn resolve_disks(atakit_config: &AtakitConfig, volume_names: &[String]) -> Vec<DiskDef> {
    volume_names
        .iter()
        .filter_map(|vol_name| {
            atakit_config
                .disks
                .iter()
                .find(|d| d.name == *vol_name)
                .map(|d| DiskDef {
                    name: d.name.clone(),
                    size: d.size.clone(),
                })
        })
        .collect()
}

fn build_gcp_options_simple(
    platform_name: &str,
    platform_config: &PlatformConfig,
) -> Option<GcpOptions> {
    if platform_name != "gcp" {
        return None;
    }
    Some(GcpOptions {
        zone: platform_config.region.clone(),
        project_id: platform_config.project.clone(),
        ..Default::default()
    })
}

fn build_azure_options(
    platform_name: &str,
    platform_config: &PlatformConfig,
) -> Option<AzureOptions> {
    if platform_name != "azure" {
        return None;
    }
    Some(AzureOptions {
        region: platform_config.region.clone(),
        ..Default::default()
    })
}

// ── Build from deployment definition (for build-workload) ────────

/// Build a deployment config from an atakit.json deployment definition.
///
/// Used by build-workload to generate deployment.json files for each
/// (deployment, platform) pair.
pub fn build_from_deployment(
    deployment_name: &str,
    deploy_def: &DeploymentDef,
    platform_name: &str,
    platform_config: &PlatformConfig,
    summary: &ComposeSummary,
    atakit_config: &AtakitConfig,
) -> Result<DeploymentConfig> {
    let provider = match platform_name {
        "gcp" => ProviderKind::Gcp,
        "azure" => ProviderKind::Azure,
        "qemu" => ProviderKind::Qemu,
        other => bail!("Unsupported platform '{other}'. Supported: gcp, azure, qemu"),
    };

    // Extract ports from compose summary.
    let ports: Vec<PortDef> = summary
        .ports
        .iter()
        .filter_map(|sp| {
            sp.port.host_port.map(|hp| PortDef {
                port: hp,
                protocol: sp.port.protocol.clone(),
            })
        })
        .collect();

    // Match named volumes to disk definitions.
    let disks: Vec<DiskDef> = summary
        .named_volumes
        .iter()
        .filter_map(|vol| {
            atakit_config
                .disks
                .iter()
                .find(|d| d.name == *vol)
                .map(|d| DiskDef {
                    name: d.name.clone(),
                    size: d.size.clone(),
                })
        })
        .collect();

    Ok(DeploymentConfig {
        name: deployment_name.to_string(),
        provider: provider.clone(),
        workload: "workload.tar.gz".to_string(),
        image: deploy_def.image.clone(),
        vm_type: platform_config.vmtype.clone(),
        quiet: None,
        ports,
        disks,
        metadata: HashMap::new(),
        gcp: build_gcp_options_simple(platform_name, platform_config),
        azure: build_azure_options(platform_name, platform_config),
        qemu: if matches!(provider, ProviderKind::Qemu) {
            Some(QemuOptions::default())
        } else {
            None
        },
    })
}

/// Serialize a deployment config to JSON.
pub fn to_json(config: &DeploymentConfig) -> Result<String> {
    serde_json::to_string_pretty(config).context("Failed to serialize deployment config")
}
