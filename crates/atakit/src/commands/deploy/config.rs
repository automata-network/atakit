use std::collections::HashMap;
use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result, bail};
use automata_linux_release::{ImageRef, ImageStore, Platform};
use serde::{Deserialize, Serialize};
use tracing::info;
use workload_compose::ComposeAnalysis;

use crate::types::{AtakitConfig, DeploymentDef, PlatformConfig, WorkloadDef};

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
    pub workload_path: String,
    // Optional image reference (e.g., "tee-base-image:v1") to override the config value.
    pub workload: ImageRef,
    /// Release tag for automata-linux disk images (e.g., "automata-linux:v0.5.0").
    /// If omitted, the latest local release is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_type: Option<String>,
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
    /// Agent environment configuration for session registry
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_env: Option<AgentEnvConfig>,
    /// Additional data files that need to be provided at deploy time
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_data_files: Vec<PathBuf>,
}

/// Resolved paths from ImageStore (for the runner).
#[derive(Debug)]
pub struct ResolvedPaths {
    pub image: PathBuf,
    pub secure_boot_dir: Option<PathBuf>,
    pub image_ref: Option<ImageRef>,
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

impl PortDef {
    pub fn tcp(port: u16) -> Self {
        PortDef {
            port,
            protocol: "tcp".to_string(),
        }
    }
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

/// Agent environment configuration for session registry.
/// Can be specified in deployment config or via CLI arguments.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AgentEnvConfig {
    /// Private key for relay operations (hex encoded)
    pub relay_private_key: B256,
    /// RPC URL for blockchain connection
    pub rpc_url: String,
    /// Session registry contract address
    pub session_registry: Address,
    /// Owner private key for session registration (hex encoded)
    pub owner_private_key: B256,
    /// Session expiration offset in seconds (default: 3600)
    pub expire_offset: u64,
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
    repo: &str,
    image_ref_override: Option<&ImageRef>,
) -> Result<ResolvedPaths> {
    let platform = provider_to_platform(&config.provider);

    // CLI override takes precedence over config.
    let image_ref = image_ref_override.or(config.image.as_ref());
    let (image_path, resolved_image_ref) = resolve_image(store, platform, repo, image_ref).await?;

    // Get secure boot dir if available (GCP only).
    let secure_boot_dir = resolved_image_ref.as_ref().and_then(|image_ref| {
        let dir = store.certs_dir(image_ref);
        dir.exists().then_some(dir)
    });

    info!(
        deployment = %config.name,
        image = resolved_image_ref.as_ref().map(|r| r.to_string()).unwrap_or("(latest)".to_string()),
        path = %image_path.display(),
        "Resolved deployment"
    );

    Ok(ResolvedPaths {
        image: image_path,
        secure_boot_dir,
        image_ref: resolved_image_ref,
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
    image_repo: &str,
    deployment_name: &str,
    platform_override: Option<&str>,
    image_ref_override: Option<&ImageRef>,
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

    // Find the workload definition.
    let wl_def = find_workload_def(atakit_config, &deploy_def.workload)?;

    // Analyze workload compose file.
    let analysis = workload_compose::analyze(config_dir, &wl_def.docker_compose)?;

    // Extract project name from config directory.
    let project_name = config_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("atakit");

    // Build the config using shared logic.
    let config = build_from_deployment(
        deployment_name,
        deploy_def,
        wl_def,
        &platform_name,
        platform_config,
        &analysis,
        atakit_config,
        project_name,
    )?;

    // Resolve to get the actual image path (auto-downloads if needed).
    let store = ImageStore::new(image_dir).with_token_from_env();
    let paths = resolve_deployment(&config, &store, image_repo, image_ref_override).await?;
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

/// Find a workload definition by name in the atakit config.
fn find_workload_def<'a>(
    atakit_config: &'a AtakitConfig,
    workload_name: &str,
) -> Result<&'a WorkloadDef> {
    atakit_config
        .workloads
        .iter()
        .find(|w| w.name == workload_name)
        .with_context(|| format!("Workload '{}' not found in atakit.json workloads[]", workload_name))
}

/// Resolve disk image path using ImageStore.
///
/// If the image is not found locally, it will be automatically downloaded.
/// Returns the image path and optionally the release tag used.
async fn resolve_image(
    store: &ImageStore,
    platform: Platform,
    repo: &str,
    image: Option<&ImageRef>,
) -> Result<(PathBuf, Option<ImageRef>)> {
    // If a specific release tag is requested, use that.
    if let Some(image_ref) = image {
        let path = store.image_path(image_ref, platform);
        if path.exists() {
            info!(image_ref = ?image_ref, %platform, "Using local disk image");
            return Ok((path, Some(image_ref.clone())));
        }

        // Not found locally, download it.
        info!(%image_ref, %platform, "Disk image not found locally, downloading...");
        let paths = store.download(image_ref, &[platform]).await?;
        if let Some(path) = paths.into_iter().next() {
            return Ok((path, Some(image_ref.clone())));
        }
        bail!(
            "Failed to download disk image for release {}",
            image_ref.tag
        );
    }

    // No specific tag requested, check local images first.
    let local_tags = store.list_local()?;
    for image_ref in local_tags.iter().rev() {
        let path = store.image_path(image_ref, platform);
        if path.exists() {
            info!(%image_ref, %platform, "Using local disk image");
            return Ok((path, Some(image_ref.clone())));
        }
    }

    // No local images, find and download the latest release with disk images.
    info!(%platform, "No local images found, fetching latest release...");
    let release = store.client().find_latest_image_release(repo).await?;
    let image_ref = ImageRef::new(repo, release.tag_name);

    info!(%image_ref, %platform, "Downloading disk image...");
    let paths = store.download(&image_ref, &[platform]).await?;
    if let Some(path) = paths.into_iter().next() {
        return Ok((path, Some(image_ref.clone())));
    }

    bail!("Failed to download disk image for latest release {image_ref}");
}


fn build_gcp_options_simple(
    platform_name: &str,
    platform_config: &PlatformConfig,
    project_name: &str,
) -> Option<GcpOptions> {
    if platform_name != "gcp" {
        return None;
    }
    Some(GcpOptions {
        zone: platform_config.region.clone(),
        project_id: platform_config.project.clone(),
        bucket_name: Some(sanitize_bucket_name(project_name)),
        ..Default::default()
    })
}

/// Sanitize a string to be a valid GCS bucket name.
/// GCS bucket names must be 3-63 chars, lowercase, start with letter, contain only a-z, 0-9, hyphens.
fn sanitize_bucket_name(name: &str) -> String {
    let sanitized: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    // Remove leading/trailing hyphens and collapse multiple hyphens
    let sanitized: String = sanitized
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    // Ensure it starts with a letter
    let sanitized = if sanitized
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(true)
    {
        format!("ata-{}", sanitized)
    } else {
        sanitized
    };
    // Truncate to 63 chars max
    sanitized.chars().take(63).collect()
}

fn build_azure_options(
    platform_name: &str,
    platform_config: &PlatformConfig,
    project_name: &str,
) -> Option<AzureOptions> {
    if platform_name != "azure" {
        return None;
    }
    Some(AzureOptions {
        region: platform_config.region.clone(),
        storage_account: Some(sanitize_azure_storage_name(project_name)),
        container_name: Some(sanitize_bucket_name(project_name)),
        ..Default::default()
    })
}

/// Sanitize a string to be a valid Azure storage account name.
/// Azure storage names must be 3-24 chars, lowercase letters and numbers only (no hyphens).
fn sanitize_azure_storage_name(name: &str) -> String {
    let sanitized: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    // Ensure it starts with a letter
    let sanitized = if sanitized
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(true)
    {
        format!("ata{}", sanitized)
    } else {
        sanitized
    };
    // Ensure minimum length of 3 and max of 24
    let sanitized = if sanitized.len() < 3 {
        format!("{}atakit", sanitized)
    } else {
        sanitized
    };
    sanitized.chars().take(24).collect()
}

// ── Build from deployment definition (for build-workload) ────────

/// Build a deployment config from an atakit.json deployment definition.
///
/// Used by build-workload to generate deployment.json files for each
/// (deployment, platform) pair.
pub fn build_from_deployment(
    deployment_name: &str,
    deploy_def: &DeploymentDef,
    wl_def: &WorkloadDef,
    platform_name: &str,
    platform_config: &PlatformConfig,
    summary: &ComposeAnalysis,
    atakit_config: &AtakitConfig,
    project_name: &str,
) -> Result<DeploymentConfig> {
    let provider = match platform_name {
        "gcp" => ProviderKind::Gcp,
        "azure" => ProviderKind::Azure,
        "qemu" => ProviderKind::Qemu,
        other => bail!("Unsupported platform '{other}'. Supported: gcp, azure, qemu"),
    };

    // Extract ports from compose summary.
    let ports: Vec<PortDef> = summary.summary
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
    let disks: Vec<DiskDef> = summary.summary
        .named_volumes
        .iter()
        .filter_map(|(_, vol)| {
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
        workload: ImageRef::new(&wl_def.name, &wl_def.version),
        workload_path: format!("{}-{}.tar.gz", wl_def.name, wl_def.version),
        image: deploy_def.image.clone(),
        vm_type: platform_config.vmtype.clone(),
        ports,
        disks,
        metadata: HashMap::new(),
        gcp: build_gcp_options_simple(platform_name, platform_config, project_name),
        azure: build_azure_options(platform_name, platform_config, project_name),
        qemu: if matches!(provider, ProviderKind::Qemu) {
            Some(QemuOptions::default())
        } else {
            None
        },
        agent_env: None,
        additional_data_files: summary
            .additional_data_files
            .iter()
            .map(|(_, original)| original.clone())
            .collect(),
    })
}

/// Serialize a deployment config to JSON.
pub fn to_json(config: &DeploymentConfig) -> Result<String> {
    serde_json::to_string_pretty(config).context("Failed to serialize deployment config")
}
