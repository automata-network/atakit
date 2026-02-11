use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use automata_linux_release::ImageRef;
use flate2::Compression;
use flate2::write::GzEncoder;
use tracing::{info, warn};

use cvm_agent::{CvmAgentPolicy, DiskInput, ImageVerifyPolicy, PortInput};

use workload_compose::{
    ComposeAnalysis, DockerImageEntry, ImageKind, WorkloadManifest, resolve_image_short_name,
    to_yaml,
};

use crate::types::{AtakitConfig, WorkloadDef};

use super::ImageMode;

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
    image_ref: Option<ImageRef>,
) -> Result<()> {
    let output_path = artifact_dir.join(format!("{}.tar.gz", package_name));
    let file = fs::File::create(&output_path)
        .with_context(|| format!("Failed to create {}", output_path.display()))?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = tar::Builder::new(enc);
    tar.mode(tar::HeaderMode::Deterministic);
    let image_ref = image_ref.unwrap_or(wl_def.image.clone());

    let prefix = ".";

    // 1. Serialize docker-compose from validated WorkloadCompose (normalized output).
    let compose_abs = project_dir.join(&analysis.compose_path);
    // Match each named volume to its DiskDef in atakit.json.
    let disk_mappings: Vec<(&str, &str, &crate::types::DiskDef, String)> = analysis
        .summary
        .named_volumes
        .iter()
        .filter_map(|(service, vol)| {
            atakit_config
                .disks
                .iter()
                .find(|d| d.name == *vol)
                .map(|d| {
                    (
                        service.as_str(),
                        vol.as_str(),
                        d,
                        format!("/data/volumes/{}", d.name),
                    )
                })
        })
        .collect();
    let rewritten = to_yaml(&analysis.compose).context("Failed to serialize docker-compose")?;
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

    // 2. Add measured files.
    for (real, compose_rel) in &analysis.measured_files {
        let abs = project_dir.join(real);
        if !abs.exists() {
            warn!(path = %compose_rel.display(), "Measured file not found, skipping");
            continue;
        }
        if let Some(file_name) = compose_rel.file_name() {
            if let Some(file_name) = file_name.to_str() {
                if file_name == "cvm-agent.sock" {
                    info!(path = %compose_rel.display(), "Skipping cvm-agent sock file");
                    continue;
                }
            }
        }
        let archive_name = format!("{}/{}", prefix, compose_rel.display());
        if abs.is_file() {
            tar.append_path_with_name(&abs, &archive_name)
                .with_context(|| format!("Failed to add {}", compose_rel.display()))?;
        }
    }

    // 3. Add additional-data files under additional-data/ directory.
    // for (compose, compose_rel) in &analysis.additional_data_files {
    //     // skip the additional data
    //     let abs = project_dir.join(compose);
    //     if !abs.exists() {
    //         warn!(path = %compose.display(), "Additional data file not found, skipping");
    //         continue;
    //     }
    //     let archive_name = format!("{}/{}", prefix, compose_rel.display());
    //     if abs.is_file() {
    //         tar.append_path_with_name(&abs, &archive_name)
    //             .with_context(|| format!("Failed to add {}", compose_rel.display()))?;
    //     }
    // }

    let agent_socket_targets = analysis
        .summary
        .referenced_files
        .iter()
        .filter(|f| f.path == "./cvm-agent.sock")
        .map(|n| n.service.clone())
        .collect::<Vec<_>>();

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
    policy.workload_config.services.agent_socket_targets = agent_socket_targets.clone();
    for (service, _, disk, mount_point) in &disk_mappings {
        policy = policy.with_disk(DiskInput {
            serial: disk.name.clone(),
            service: service.to_string(),
            mount_point: mount_point.clone(),
            encryption_enabled: disk.encryption.as_ref().map(|e| e.enable).unwrap_or(false),
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
                        image_tag: resolved_tag,
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
                        image_tag: resolved_tag,
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
                    image_tag: tag.clone(),
                    image_tar: None,
                });
            }
        }
    }

    // 6. Create and add manifest.json.

    let manifest = WorkloadManifest {
        name: ImageRef::new(&wl_def.name, &wl_def.version),
        docker_compose: "docker-compose.yml".to_string(),
        image: image_ref.clone(),
        measured_files: analysis
            .measured_files
            .iter()
            .map(|(_, original)| original.to_string_lossy().into_owned())
            .collect(),
        additional_data_files: analysis
            .additional_data_files
            .iter()
            .map(|(_, original)| original.to_string_lossy().into_owned())
            .collect(),
        docker_images: manifest_images,
        enable_cvm_agent: agent_socket_targets,
        atakit_version: env!("CARGO_PKG_VERSION").to_string(),
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
        image_tag: resolved_tag,
        image_tar: Some(archive_name),
    });

    Ok(())
}
