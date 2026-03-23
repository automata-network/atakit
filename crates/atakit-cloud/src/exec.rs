use crate::error::CloudError;

/// Output from a completed command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Trait for executing shell commands (gcloud, gsutil, az).
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run a command and capture stdout + stderr.
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError>;

    /// Run a command, optionally streaming output to stderr.
    async fn run_stream(
        &self,
        program: &str,
        args: &[&str],
        verbose: bool,
    ) -> Result<CommandOutput, CloudError>;
}

/// Real process-based command runner using tokio.
pub struct ProcessRunner;

#[async_trait::async_trait]
impl CommandRunner for ProcessRunner {
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        tracing::debug!(program, ?args, "running command");
        let output = tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CloudError::CommandNotFound {
                        program: program.to_string(),
                    }
                } else {
                    CloudError::Io(e)
                }
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let status = output.status.code().unwrap_or(-1);

        tracing::debug!(status, "command completed");

        if !output.status.success() {
            return Err(CloudError::CommandFailed {
                program: program.to_string(),
                args: args.join(" "),
                stderr: stderr.trim().to_string(),
                code: output.status.code(),
            });
        }

        Ok(CommandOutput {
            status,
            stdout,
            stderr,
        })
    }

    async fn run_stream(
        &self,
        program: &str,
        args: &[&str],
        verbose: bool,
    ) -> Result<CommandOutput, CloudError> {
        tracing::debug!(program, ?args, verbose, "running command (stream)");
        let stdio = if verbose {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::piped()
        };

        let child = tokio::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(stdio)
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CloudError::CommandNotFound {
                        program: program.to_string(),
                    }
                } else {
                    CloudError::Io(e)
                }
            })?;

        let output = child.wait_with_output().await.map_err(CloudError::Io)?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let status = output.status.code().unwrap_or(-1);

        if !output.status.success() {
            return Err(CloudError::CommandFailed {
                program: program.to_string(),
                args: args.join(" "),
                stderr: stderr.trim().to_string(),
                code: output.status.code(),
            });
        }

        Ok(CommandOutput {
            status,
            stdout,
            stderr,
        })
    }
}
