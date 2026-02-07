use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use cvm_agent::{CvmAgentPolicy, DiskInput, ImageVerifyPolicy, PortInput};

use workload_compose::ImageKind;

use crate::types::{AtakitConfig, DockerImageEntry, WorkloadDef, WorkloadManifest};

use super::analyze::ComposeAnalysis;
use super::ImageMode;

// ---------------------------------------------------------------------------
// Docker Compose serde types (for YAML round-trip rewriting)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct DockerCompose {
    #[serde(default)]
    services: IndexMap<String, ComposeService>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    volumes: Option<IndexMap<String, serde_yaml::Value>>,
    /// Preserves unknown top-level keys (e.g. `version`, `networks`, `configs`).
    #[serde(flatten)]
    extra: IndexMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ComposeService {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    build: Option<serde_yaml::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    volumes: Vec<String>,
    #[serde(default, skip_serializing_if = "EnvFileEntry::is_none")]
    env_file: EnvFileEntry,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<String>,
    /// Preserves unknown service-level keys (e.g. `environment`, `depends_on`, `restart`).
    #[serde(flatten)]
    extra: IndexMap<String, serde_yaml::Value>,
}

/// `env_file` can be a single string or a list of strings.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(untagged)]
enum EnvFileEntry {
    #[default]
    None,
    Single(String),
    Multiple(Vec<String>),
}

impl EnvFileEntry {
    fn is_none(&self) -> bool {
        matches!(self, EnvFileEntry::None)
    }

    fn to_paths(&self) -> Vec<String> {
        match self {
            EnvFileEntry::None => vec![],
            EnvFileEntry::Single(s) => vec![s.clone()],
            EnvFileEntry::Multiple(v) => v.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Package creation
// ---------------------------------------------------------------------------

/// Create a tar.gz workload package.
///
/// When `image_mode` is `Pull`, Docker images are not built or packaged; the
/// manifest will only record the image tags for runtime pulling.
///
/// `package_name` is the output file name (without extension), e.g., "my-deployment-gcp".
/// `image_version` is the automata-linux disk image version to embed in the manifest.
pub fn create_package(
    package_name: &str,
    wl_def: &WorkloadDef,
    analysis: &ComposeAnalysis,
    project_dir: &Path,
    artifact_dir: &Path,
    atakit_config: &AtakitConfig,
    image_mode: ImageMode,
    image_version: Option<&str>,
) -> Result<()> {
    let output_path = artifact_dir.join(format!("{}.tar.gz", package_name));
    let file = fs::File::create(&output_path)
        .with_context(|| format!("Failed to create {}", output_path.display()))?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = tar::Builder::new(enc);
    tar.mode(tar::HeaderMode::Deterministic);

    let prefix = ".";

    // 1. Rewrite docker-compose paths to match archive layout, then add.
    let compose_abs = project_dir.join(&analysis.compose_path);
    let compose_content = fs::read_to_string(&compose_abs)
        .with_context(|| format!("Failed to read {}", compose_abs.display()))?;
    // Match each named volume to its DiskDef in atakit.json.
    let disk_mappings: Vec<(&str, &crate::types::DiskDef, String)> = analysis
        .summary
        .named_volumes
        .iter()
        .filter_map(|vol| {
            atakit_config
                .disks
                .iter()
                .find(|d| d.name == *vol)
                .map(|d| (vol.as_str(), d, format!("/data/volumes/{}", d.name)))
        })
        .collect();
    let volume_mounts: Vec<(&str, &str)> = disk_mappings
        .iter()
        .map(|(vol, _, mp)| (*vol, mp.as_str()))
        .collect();
    let rewritten = rewrite_compose(&compose_content, &volume_mounts)?;
    let rewritten_bytes = rewritten.as_bytes();

    let mut header = tar::Header::new_gnu();
    header.set_size(rewritten_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(
        &mut header,
        format!("{}/docker-compose.yml", prefix),
        rewritten_bytes,
    )
    .context("Failed to add docker-compose.yml")?;

    // Directory containing the compose file, relative to the project root.
    let compose_parent = compose_abs.parent().unwrap_or(project_dir);
    let compose_rel_dir = compose_parent
        .strip_prefix(project_dir)
        .unwrap_or(Path::new(""));

    // 2. Add measured files.
    for rel in &analysis.measured_files {
        let abs = project_dir.join(rel);
        if !abs.exists() {
            warn!(path = %rel.display(), "Measured file not found, skipping");
            continue;
        }
        let compose_rel = rel.strip_prefix(compose_rel_dir).unwrap_or(rel);
        let archive_name = format!("{}/{}", prefix, compose_rel.display());
        if abs.is_file() {
            tar.append_path_with_name(&abs, &archive_name)
                .with_context(|| format!("Failed to add {}", rel.display()))?;
        }
    }

    // 3. Add additional-data files under secrets/ directory.
    for rel in &analysis.additional_data_files {
        let abs = project_dir.join(rel);
        if !abs.exists() {
            warn!(path = %rel.display(), "Additional data file not found, skipping");
            continue;
        }
        let compose_rel = rel.strip_prefix(compose_rel_dir).unwrap_or(rel);
        let archive_name = format!("{}/secrets/{}", prefix, compose_rel.display());
        if abs.is_file() {
            tar.append_path_with_name(&abs, &archive_name)
                .with_context(|| format!("Failed to add {}", rel.display()))?;
        }
    }

    // 4. Add CVM agent config files.
    let port_inputs: Vec<PortInput> = analysis
        .summary
        .ports
        .iter()
        .filter_map(|sp| {
            sp.port.host_port.map(|hp| PortInput {
                service: sp.service.clone(),
                host_port: hp,
                protocol: sp.port.protocol.clone(),
            })
        })
        .collect();
    let mut policy = CvmAgentPolicy::default().with_ports(&port_inputs);
    for (_, disk, mount_point) in &disk_mappings {
        policy = policy.with_disk(DiskInput {
            serial: disk.name.clone(),
            mount_point: mount_point.clone(),
            encryption_enabled: disk
                .encryption
                .as_ref()
                .map(|e| e.enable)
                .unwrap_or(false),
            encryption_key_security: disk
                .encryption
                .as_ref()
                .map(|e| e.encryption_key_security.clone())
                .unwrap_or_else(|| "standard".to_string()),
        });
    }
    let policy_json = serde_json::to_string_pretty(&policy)?;
    add_static_file(
        &mut tar,
        &format!("{}/config/cvm_agent/cvm_agent_policy.json", prefix),
        policy_json.as_bytes(),
    )?;
    let verify_json = serde_json::to_string_pretty(&ImageVerifyPolicy::default())?;
    add_static_file(
        &mut tar,
        &format!(
            "{}/config/cvm_agent/sample_image_verify_policy.json",
            prefix
        ),
        verify_json.as_bytes(),
    )?;

    // 5. Handle Docker images.
    let mut manifest_images: Vec<DockerImageEntry> = Vec::new();

    for img in &analysis.summary.images {
        match &img.kind {
            ImageKind::Build { tag } => {
                let image_tag = tag.clone();
                if matches!(image_mode, ImageMode::Pull) {
                    // Skip build/save, just record the tag for runtime pulling.
                    let resolved_tag = resolve_image_short_name(&image_tag);
                    info!(service = %img.service, tag = %resolved_tag, "Skipping image build (--image-mode=pull)");
                    manifest_images.push(DockerImageEntry {
                        service: img.service.clone(),
                        image_tag: Some(resolved_tag),
                        image_tar: None,
                    });
                } else {
                    build_and_save_image(
                        &img.service,
                        &image_tag,
                        &compose_abs,
                        artifact_dir,
                        &wl_def.name,
                        &mut tar,
                        &mut manifest_images,
                    )?;
                }
            }
            ImageKind::BuildUntagged => {
                let image_tag = format!("{}_{}", wl_def.name, img.service);
                if matches!(image_mode, ImageMode::Pull) {
                    let resolved_tag = resolve_image_short_name(&image_tag);
                    info!(service = %img.service, tag = %resolved_tag, "Skipping image build (--image-mode=pull)");
                    manifest_images.push(DockerImageEntry {
                        service: img.service.clone(),
                        image_tag: Some(resolved_tag),
                        image_tar: None,
                    });
                } else {
                    build_and_save_image(
                        &img.service,
                        &image_tag,
                        &compose_abs,
                        artifact_dir,
                        &wl_def.name,
                        &mut tar,
                        &mut manifest_images,
                    )?;
                }
            }
            ImageKind::Pull { tag } => {
                manifest_images.push(DockerImageEntry {
                    service: img.service.clone(),
                    image_tag: Some(tag.clone()),
                    image_tar: None,
                });
            }
        }
    }

    // 6. Create and add manifest.json.
    let manifest = WorkloadManifest {
        name: package_name.to_string(),
        docker_compose: "docker-compose.yml".to_string(),
        image: image_version.map(|s| s.to_string()),
        measured_files: analysis
            .measured_files
            .iter()
            .map(|p| {
                p.strip_prefix(compose_rel_dir)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect(),
        additional_data_files: analysis
            .additional_data_files
            .iter()
            .map(|p| {
                let cr = p.strip_prefix(compose_rel_dir).unwrap_or(p);
                format!("secrets/{}", cr.to_string_lossy())
            })
            .collect(),
        docker_images: manifest_images,
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    let manifest_bytes = manifest_json.as_bytes();

    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(
        &mut header,
        format!("{}/manifest.json", prefix),
        manifest_bytes,
    )
    .context("Failed to add manifest.json")?;

    // 7. Finalize the archive.
    let enc = tar.into_inner().context("Failed to finalize tar archive")?;
    enc.finish().context("Failed to finish gzip compression")?;

    Ok(())
}

/// Rewrite docker-compose file paths so they match the archive layout.
fn rewrite_compose(content: &str, volume_mounts: &[(&str, &str)]) -> Result<String> {
    let mut compose: DockerCompose =
        serde_yaml::from_str(content).context("Failed to parse docker-compose for rewriting")?;

    // Remove top-level `volumes:` section when named volumes are present --
    // the CVM agent manages the data disk mounts directly.
    if !volume_mounts.is_empty() {
        compose.volumes = None;
    }

    for (_name, service) in compose.services.iter_mut() {
        // Rewrite env_file paths.
        let paths = service.env_file.to_paths();
        if !paths.is_empty() {
            let rewritten: Vec<String> = paths.iter().map(|p| rewrite_file_path(p)).collect();
            service.env_file = match rewritten.len() {
                1 => EnvFileEntry::Single(rewritten.into_iter().next().unwrap()),
                _ => EnvFileEntry::Multiple(rewritten),
            };
        }

        // Remove build directive -- images are pre-built as tars.
        service.build = None;

        // Resolve image short names to fully qualified references.
        if let Some(ref img) = service.image {
            service.image = Some(resolve_image_short_name(img));
        }

        // Rewrite volume bind-mount host paths and named volumes.
        service.volumes = service
            .volumes
            .iter()
            .map(|v| rewrite_volume_path(v, volume_mounts))
            .collect();
    }

    serde_yaml::to_string(&compose).context("Failed to serialize rewritten compose")
}

/// Map a compose-relative file path to its archive location.
fn rewrite_file_path(raw: &str) -> String {
    let clean = raw.strip_prefix("./").unwrap_or(raw);
    if clean.contains("additional-data/") || clean.starts_with("additional-data") {
        format!("./secrets/{}", clean)
    } else {
        format!("./{}", clean)
    }
}

/// Rewrite the host portion of a volume bind-mount to its archive location,
/// or replace a named volume with the disk mount point from atakit.json.
fn rewrite_volume_path(vol: &str, volume_mounts: &[(&str, &str)]) -> String {
    let parts: Vec<&str> = vol.splitn(3, ':').collect();
    if parts.len() < 2 {
        return vol.to_string();
    }
    let host = parts[0];
    if !(host.starts_with('.') || host.starts_with('/') || host.starts_with('~')) {
        // Named volume -- replace with disk mount point if it matches any mapping.
        if let Some((_, mp)) = volume_mounts.iter().find(|(nv, _)| *nv == host) {
            let mut result = mp.to_string();
            result.push(':');
            result.push_str(parts[1]);
            if parts.len() > 2 {
                result.push(':');
                result.push_str(parts[2]);
            }
            return result;
        }
        return vol.to_string();
    }
    let new_host = rewrite_file_path(host);
    let mut result = new_host;
    result.push(':');
    result.push_str(parts[1]);
    if parts.len() > 2 {
        result.push(':');
        result.push_str(parts[2]);
    }
    result
}

/// Add a static file to the tar archive with deterministic headers.
fn add_static_file<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    archive_path: &str,
    content: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(&mut header, archive_path, content)
        .with_context(|| format!("Failed to add {}", archive_path))
}

/// Build a Docker image via docker compose, save it as a tar, and add to archive.
fn build_and_save_image<W: std::io::Write>(
    service: &str,
    image_tag: &str,
    compose_abs: &Path,
    artifact_dir: &Path,
    workload_name: &str,
    tar: &mut tar::Builder<W>,
    manifest_images: &mut Vec<DockerImageEntry>,
) -> Result<()> {
    let resolved_tag = resolve_image_short_name(image_tag);

    // Build the image via docker compose.
    info!(service, "Building Docker image");
    let status = Command::new("docker")
        .env("DOCKER_DEFAULT_PLATFORM", "linux/amd64")
        .args(["compose", "-f"])
        .arg(compose_abs)
        .args(["build", service])
        .status()
        .context("Failed to run docker compose build")?;
    if !status.success() {
        bail!("docker compose build failed for service '{service}'");
    }

    // Tag with the fully qualified name so docker save embeds it.
    if resolved_tag != image_tag {
        let status = Command::new("docker")
            .args(["tag", image_tag, &resolved_tag])
            .status()
            .context("Failed to run docker tag")?;
        if !status.success() {
            bail!("docker tag failed: {image_tag} -> {resolved_tag}");
        }
    }

    // Save the image to a temporary tar.
    let image_tar_name = format!("{service}.tar");
    let image_tar_path = artifact_dir.join(&image_tar_name);
    info!(tag = %resolved_tag, "Saving Docker image");
    let status = Command::new("docker")
        .args(["save", "--platform", "linux/amd64", "-o"])
        .arg(&image_tar_path)
        .arg(&resolved_tag)
        .status()
        .context("Failed to run docker save")?;
    if !status.success() {
        bail!("docker save failed for image '{resolved_tag}'");
    }

    // Add the image tar to the archive root as {workload}-image.tar.
    let archive_name = format!("{workload_name}-image.tar");
    tar.append_path_with_name(&image_tar_path, &archive_name)
        .with_context(|| format!("Failed to add image tar: {archive_name}"))?;

    // Clean up the temporary tar.
    let _ = std::fs::remove_file(&image_tar_path);

    manifest_images.push(DockerImageEntry {
        service: service.to_string(),
        image_tag: Some(resolved_tag),
        image_tar: Some(archive_name),
    });

    Ok(())
}

/// Resolve a Docker image short name to a fully qualified reference.
fn resolve_image_short_name(image: &str) -> String {
    if image.is_empty() {
        return image.to_string();
    }

    match image.find('/') {
        None => {
            // No `/` -- official library image (e.g. `nginx`, `nginx:latest`).
            format!("docker.io/library/{}", image)
        }
        Some(slash_pos) => {
            let first = &image[..slash_pos];
            if first.contains('.') || first.contains(':') || first == "localhost" {
                // First component looks like a registry hostname.
                image.to_string()
            } else {
                // Namespace without registry (e.g. `user/image:tag`).
                format!("docker.io/{}", image)
            }
        }
    }
}
