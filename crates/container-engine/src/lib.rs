mod docker;
mod podman;

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Result, bail};

pub use docker::{Docker, DockerCompose};
pub use podman::{Podman, PodmanCompose};

pub trait Compose {
    fn build(&self, compose_file: &Path, service: &str, platform: Option<&str>) -> Result<()>;
}

pub trait ContainerEngine {
    type Compose: Compose;
    fn name(&self) -> &str;
    fn compose(&self) -> Self::Compose;
    fn tag(&self, source: &str, target: &str) -> Result<()>;
    fn save(&self, image: &str, output: &Path, platform: &str) -> Result<()>;
    fn pull(&self, image: &str, platform: &str) -> Result<()>;
    fn image_exists(&self, image: &str) -> bool;
}

pub enum ContainerRuntime {
    Docker(Docker),
    Podman(Podman),
}

pub enum ComposeRuntime {
    Docker(DockerCompose),
    Podman(PodmanCompose),
}

impl Compose for ComposeRuntime {
    fn build(&self, compose_file: &Path, service: &str, platform: Option<&str>) -> Result<()> {
        match self {
            Self::Docker(d) => d.build(compose_file, service, platform),
            Self::Podman(p) => p.build(compose_file, service, platform),
        }
    }
}

impl ContainerEngine for ContainerRuntime {
    type Compose = ComposeRuntime;

    fn name(&self) -> &str {
        match self {
            Self::Docker(d) => d.name(),
            Self::Podman(p) => p.name(),
        }
    }

    fn compose(&self) -> ComposeRuntime {
        match self {
            Self::Docker(_) => ComposeRuntime::Docker(DockerCompose),
            Self::Podman(_) => ComposeRuntime::Podman(PodmanCompose),
        }
    }

    fn tag(&self, source: &str, target: &str) -> Result<()> {
        match self {
            Self::Docker(d) => d.tag(source, target),
            Self::Podman(p) => p.tag(source, target),
        }
    }

    fn save(&self, image: &str, output: &Path, platform: &str) -> Result<()> {
        match self {
            Self::Docker(d) => d.save(image, output, platform),
            Self::Podman(p) => p.save(image, output, platform),
        }
    }

    fn pull(&self, image: &str, platform: &str) -> Result<()> {
        match self {
            Self::Docker(d) => d.pull(image, platform),
            Self::Podman(p) => p.pull(image, platform),
        }
    }

    fn image_exists(&self, image: &str) -> bool {
        match self {
            Self::Docker(d) => d.image_exists(image),
            Self::Podman(p) => p.image_exists(image),
        }
    }
}

/// Detect an available container engine.
///
/// Priority: `CONTAINER_ENGINE` env var > `prefer` argument > auto-detect (docker then podman).
pub fn detect(prefer: Option<&str>) -> Result<ContainerRuntime> {
    if let Ok(engine) = std::env::var("CONTAINER_ENGINE") {
        return match engine.as_str() {
            "docker" => Ok(ContainerRuntime::Docker(Docker)),
            "podman" => Ok(ContainerRuntime::Podman(Podman)),
            other => bail!("Unsupported CONTAINER_ENGINE: {other}"),
        };
    }

    if let Some(engine) = prefer {
        return match engine {
            "docker" => Ok(ContainerRuntime::Docker(Docker)),
            "podman" => Ok(ContainerRuntime::Podman(Podman)),
            other => bail!("Unsupported container engine preference: {other}"),
        };
    }

    if is_available("docker") {
        return Ok(ContainerRuntime::Docker(Docker));
    }
    if is_available("podman") {
        return Ok(ContainerRuntime::Podman(Podman));
    }

    bail!("No container engine found. Install docker or podman.")
}

fn is_available(binary: &str) -> bool {
    Command::new(binary)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
