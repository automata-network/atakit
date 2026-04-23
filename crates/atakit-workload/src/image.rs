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
    ///
    /// Built reproducibly: `SOURCE_DATE_EPOCH=0` normalises file/config
    /// timestamps, and engine-specific flags rewrite layer timestamps and
    /// strip build provenance so the same inputs produce byte-identical
    /// images.
    ///
    /// Note for Docker: `rewrite-timestamp=true` conflicts with the daemon's
    /// unpack-on-load path, so we build to a tarball first and then
    /// `docker load` it.
    pub async fn build_image(
        &self,
        context: &Path,
        containerfile: Option<&str>,
        tag: &str,
        args: &BTreeMap<String, String>,
        verbose: bool,
    ) -> Result<(), WorkloadError> {
        match self {
            ContainerEngine::Docker => {
                let tar = tempfile::Builder::new()
                    .prefix("atakit-reproducible-build-")
                    .suffix(".tar")
                    .tempfile()
                    .map_err(WorkloadError::Io)?;

                let mut cmd = Command::new(self.bin());
                cmd.arg("buildx")
                    .arg("build")
                    .arg("--provenance=false")
                    .arg("--output")
                    .arg(format!(
                        "type=docker,name={tag},dest={},rewrite-timestamp=true",
                        tar.path().display()
                    ))
                    .arg("--build-arg")
                    .arg("SOURCE_DATE_EPOCH=0")
                    .env("SOURCE_DATE_EPOCH", "0");

                if let Some(cf) = containerfile {
                    cmd.arg("-f").arg(context.join(cf));
                }
                for (k, v) in args {
                    cmd.arg("--build-arg").arg(format!("{k}={v}"));
                }
                cmd.arg(context);

                run_command_streaming(&mut cmd, "docker buildx build", verbose).await?;

                let mut load = Command::new(self.bin());
                load.arg("load").arg("-i").arg(tar.path());
                run_command_streaming(&mut load, "docker load", verbose).await
            }
            ContainerEngine::Podman => {
                let mut cmd = Command::new(self.bin());
                cmd.arg("build")
                    .arg("-t")
                    .arg(tag)
                    .arg("--timestamp")
                    .arg("0");

                if let Some(cf) = containerfile {
                    cmd.arg("-f").arg(context.join(cf));
                }
                for (k, v) in args {
                    cmd.arg("--build-arg").arg(format!("{k}={v}"));
                }
                cmd.arg(context);

                run_command_streaming(&mut cmd, "podman build", verbose).await
            }
        }
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

/// Run a command, optionally streaming stdout/stderr to the terminal.
///
/// When `verbose` is false, output is captured and discarded on success. On
/// failure the captured stderr is included in the error.
async fn run_command_streaming(
    cmd: &mut Command,
    label: &str,
    verbose: bool,
) -> Result<(), WorkloadError> {
    use std::process::Stdio;

    if verbose {
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
    } else {
        let output = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(WorkloadError::Io)?;
        if !output.status.success() {
            // Cap stderr to avoid unbounded memory usage from verbose container tools
            const MAX_STDERR: usize = 8192;
            let raw = &output.stderr;
            let stderr = if raw.len() > MAX_STDERR {
                let truncated = String::from_utf8_lossy(&raw[raw.len() - MAX_STDERR..]);
                format!("... ({} bytes truncated)\n{truncated}", raw.len() - MAX_STDERR)
            } else {
                String::from_utf8_lossy(raw).to_string()
            };
            return Err(WorkloadError::ContainerCommand {
                command: label.to_string(),
                stderr,
            });
        }
    }
    Ok(())
}
