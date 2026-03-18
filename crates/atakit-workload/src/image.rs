use std::collections::BTreeMap;
use std::path::Path;

use tokio::process::Command;

use crate::WorkloadError;

/// Supported container engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerEngine {
    Docker,
    Podman,
}

impl ContainerEngine {
    /// Detect an available container engine. Tries podman first, then docker.
    pub async fn detect() -> Result<Self, WorkloadError> {
        if command_exists("podman").await {
            Ok(ContainerEngine::Podman)
        } else if command_exists("docker").await {
            Ok(ContainerEngine::Docker)
        } else {
            Err(WorkloadError::NoContainerEngine)
        }
    }

    /// Parse from a CLI string ("docker" or "podman").
    pub fn from_str_opt(s: &str) -> Result<Self, WorkloadError> {
        match s {
            "docker" => Ok(ContainerEngine::Docker),
            "podman" => Ok(ContainerEngine::Podman),
            _ => Err(WorkloadError::Validation(format!(
                "unknown container engine: {s:?} (expected \"docker\" or \"podman\")"
            ))),
        }
    }

    fn bin(&self) -> &'static str {
        match self {
            ContainerEngine::Docker => "docker",
            ContainerEngine::Podman => "podman",
        }
    }

    /// Build a container image from a build context.
    pub async fn build_image(
        &self,
        context: &Path,
        containerfile: Option<&str>,
        tag: &str,
        args: &BTreeMap<String, String>,
    ) -> Result<(), WorkloadError> {
        let mut cmd = Command::new(self.bin());
        cmd.arg("build").arg("-t").arg(tag);

        if let Some(cf) = containerfile {
            cmd.arg("-f").arg(cf);
        }

        for (k, v) in args {
            cmd.arg("--build-arg").arg(format!("{k}={v}"));
        }

        cmd.arg(context);

        run_command_streaming(&mut cmd, &format!("{} build", self.bin())).await
    }

    /// Pull an image from a registry.
    pub async fn pull_image(&self, reference: &str) -> Result<(), WorkloadError> {
        let mut cmd = Command::new(self.bin());
        cmd.arg("pull").arg(reference);
        run_command(&mut cmd, &format!("{} pull", self.bin())).await
    }

    /// Save (export) an image to an OCI tar archive.
    pub async fn save_image(
        &self,
        reference: &str,
        dest: &Path,
    ) -> Result<(), WorkloadError> {
        let mut cmd = Command::new(self.bin());
        cmd.arg("save").arg("-o").arg(dest).arg(reference);
        run_command(&mut cmd, &format!("{} save", self.bin())).await
    }
}

impl std::fmt::Display for ContainerEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.bin())
    }
}

async fn command_exists(name: &str) -> bool {
    use std::process::Stdio;
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn run_command(cmd: &mut Command, label: &str) -> Result<(), WorkloadError> {
    let output = cmd.output().await.map_err(WorkloadError::Io)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(WorkloadError::ContainerCommand {
            command: label.to_string(),
            stderr,
        });
    }
    Ok(())
}

/// Run a command with stdout/stderr inherited so the user sees build output in real time.
async fn run_command_streaming(cmd: &mut Command, label: &str) -> Result<(), WorkloadError> {
    use std::process::Stdio;
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .map_err(WorkloadError::Io)?;
    if !status.success() {
        return Err(WorkloadError::ContainerCommand {
            command: label.to_string(),
            stderr: format!("exited with {status}"),
        });
    }
    Ok(())
}
