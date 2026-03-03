use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use tracing::info;

use crate::{Compose, ContainerEngine};

pub struct Podman;
pub struct PodmanCompose;

impl Compose for PodmanCompose {
    fn build(&self, compose_file: &Path, service: &str, platform: Option<&str>) -> Result<()> {
        if let Some(p) = platform {
            check_podman_arch(p)?;
        }

        info!(service, "Building image via podman compose");
        let mut cmd = Command::new("podman");
        // Use env var instead of --platform flag because podman compose may
        // delegate to docker-compose v1 which doesn't support --platform.
        if let Some(p) = platform {
            cmd.env("DOCKER_DEFAULT_PLATFORM", p);
        }
        cmd.args(["compose", "-f"])
            .arg(compose_file)
            .args(["build", service]);

        let status = cmd
            .status()
            .context("Failed to run podman compose build")?;
        if !status.success() {
            bail!("podman compose build failed for service '{service}'");
        }
        Ok(())
    }
}

/// Check that the podman host architecture matches the target platform.
fn check_podman_arch(platform: &str) -> Result<()> {
    let target_arch = platform
        .split('/')
        .nth(1)
        .context("Invalid platform format, expected 'os/arch'")?;

    let output = Command::new("podman")
        .args(["info", "--format", "{{.Host.Arch}}"])
        .stderr(Stdio::null())
        .output()
        .context("Failed to run podman info")?;
    if !output.status.success() {
        bail!("podman info failed");
    }

    let host_arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if host_arch != target_arch {
        bail!(
            "Podman host architecture '{host_arch}' does not match target platform '{platform}'. \
             Cross-platform builds are not supported with podman. \
             Switch to docker with: atakit config default-container-engine docker"
        );
    }
    Ok(())
}

impl ContainerEngine for Podman {
    type Compose = PodmanCompose;

    fn name(&self) -> &str {
        "podman"
    }

    fn compose(&self) -> PodmanCompose {
        PodmanCompose
    }

    fn tag(&self, source: &str, target: &str) -> Result<()> {
        let status = Command::new("podman")
            .args(["tag", source, target])
            .status()
            .context("Failed to run podman tag")?;
        if !status.success() {
            bail!("podman tag failed: {source} -> {target}");
        }
        Ok(())
    }

    fn save(&self, image: &str, output: &Path, _platform: &str) -> Result<()> {
        // Podman doesn't need --platform for save; the image is already
        // built for the target platform.
        info!(tag = %image, "Saving image via podman save");
        let status = Command::new("podman")
            .args(["save", "--format", "oci-archive", "-o"])
            .arg(output)
            .arg(image)
            .status()
            .context("Failed to run podman save")?;
        if !status.success() {
            bail!("podman save failed for image '{image}'");
        }
        Ok(())
    }

    fn pull(&self, image: &str, platform: &str) -> Result<()> {
        info!(tag = %image, "Pulling image via podman pull");
        let status = Command::new("podman")
            .args(["pull", "--platform", platform])
            .arg(image)
            .status()
            .context("Failed to run podman pull")?;
        if !status.success() {
            bail!("podman pull failed for image '{image}'");
        }
        Ok(())
    }

    fn image_exists(&self, image: &str) -> bool {
        Command::new("podman")
            .args(["image", "inspect", image])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}
