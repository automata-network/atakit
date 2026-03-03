use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use tracing::info;

use crate::{Compose, ContainerEngine};

pub struct Docker;
pub struct DockerCompose;

impl Compose for DockerCompose {
    fn build(&self, compose_file: &Path, service: &str, platform: Option<&str>) -> Result<()> {
        info!(service, "Building image via docker compose");
        let mut cmd = Command::new("docker");
        if let Some(p) = platform {
            cmd.env("DOCKER_DEFAULT_PLATFORM", p);
        }

        let status = cmd
            .args(["compose", "-f"])
            .arg(compose_file)
            .args(["build", service])
            .status()
            .context("Failed to run docker compose build")?;
        if !status.success() {
            bail!("docker compose build failed for service '{service}'");
        }
        Ok(())
    }
}

impl ContainerEngine for Docker {
    type Compose = DockerCompose;

    fn name(&self) -> &str {
        "docker"
    }

    fn compose(&self) -> DockerCompose {
        DockerCompose
    }

    fn tag(&self, source: &str, target: &str) -> Result<()> {
        let status = Command::new("docker")
            .args(["tag", source, target])
            .status()
            .context("Failed to run docker tag")?;
        if !status.success() {
            bail!("docker tag failed: {source} -> {target}");
        }
        Ok(())
    }

    fn save(&self, image: &str, output: &Path, platform: &str) -> Result<()> {
        info!(tag = %image, "Saving image via docker save");
        let status = Command::new("docker")
            .args(["save", "--platform", platform, "-o"])
            .arg(output)
            .arg(image)
            .status()
            .context("Failed to run docker save")?;
        if !status.success() {
            bail!("docker save failed for image '{image}'");
        }
        Ok(())
    }

    fn pull(&self, image: &str, platform: &str) -> Result<()> {
        info!(tag = %image, "Pulling image via docker pull");
        let status = Command::new("docker")
            .args(["pull", "--platform", platform])
            .arg(image)
            .status()
            .context("Failed to run docker pull")?;
        if !status.success() {
            bail!("docker pull failed for image '{image}'");
        }
        Ok(())
    }

    fn image_exists(&self, image: &str) -> bool {
        Command::new("docker")
            .args(["image", "inspect", image])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}
