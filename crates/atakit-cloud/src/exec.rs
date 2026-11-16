use crate::error::CloudError;

/// Output from a completed command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Trait for executing shell commands (gcloud, az).
// async_trait generates a must_use future that Clippy already treats as must_use.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    async fn create_resource(
        &self,
        key: &str,
        request: &crate::provisioning::CreateRequest,
    ) -> Result<serde_json::Value, CloudError> {
        let creation = crate::provisioning::Creation {
            outcome: Default::default(),
            request: request.clone(),
            token: uuid::Uuid::new_v4().to_string(),
            sent: false,
            receipt: None,
            result: None,
        };
        crate::provisioning::execute(self, key, &creation, false).await
    }
    async fn creation_recorded(&self, _key: &str) -> Result<bool, CloudError> {
        Ok(false)
    }
    async fn recorded_creation(
        &self,
        _key: &str,
    ) -> Result<Option<crate::provisioning::Creation>, CloudError> {
        Ok(None)
    }
    async fn record_creation_receipt(
        &self,
        _key: &str,
        _receipt: &serde_json::Value,
    ) -> Result<(), CloudError> {
        Ok(())
    }
    async fn gcp_api(
        &self,
        _method: &str,
        _url: &str,
        _body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, CloudError> {
        Err(crate::provisioning::error(
            "runner does not implement GCP API transport",
        ))
    }
    async fn azure_api(
        &self,
        _method: &str,
        _url: &str,
        _body: Option<&serde_json::Value>,
        _create_only: bool,
    ) -> Result<serde_json::Value, CloudError> {
        Err(crate::provisioning::error(
            "runner does not implement Azure API transport",
        ))
    }
    async fn record_boot_disk(
        &self,
        _disk: &crate::disk_inventory::ObservedDisk,
    ) -> Result<(), CloudError> {
        Ok(())
    }
    async fn record_azure_resource(
        &self,
        _resource: &crate::provisioning_cleanup::AzureResource,
    ) -> Result<(), CloudError> {
        Ok(())
    }
    /// Read the saved disk record before resuming its provisioning.
    async fn recorded_disk(
        &self,
        _name: &str,
    ) -> Result<Option<crate::disk_inventory::CreatedDisk>, CloudError> {
        Ok(None)
    }
    /// Record each fresh disk before a later provisioning step can fail.
    async fn record_created_disk(
        &self,
        _disk: &crate::disk_inventory::CreatedDisk,
    ) -> Result<(), CloudError> {
        Ok(())
    }
    /// Persist VM creation before any later waiter or disk attachment can fail.
    async fn record_created_instance(
        &self,
        _instance: &str,
        _ip: &str,
        _complete: bool,
        _identity: Option<&str>,
    ) -> Result<(), CloudError> {
        Ok(())
    }
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
#[derive(Default)]
pub struct ProcessRunner {
    /// When true, print each command to stderr before executing.
    pub verbose: bool,
}

impl ProcessRunner {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }
}

#[async_trait::async_trait]
impl CommandRunner for ProcessRunner {
    async fn azure_api(
        &self,
        method: &str,
        url: &str,
        body: Option<&serde_json::Value>,
        create_only: bool,
    ) -> Result<serde_json::Value, CloudError> {
        crate::provisioning::azure_api(self, method, url, body, create_only).await
    }
    async fn gcp_api(
        &self,
        method: &str,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, CloudError> {
        crate::provisioning::gcp_api(self, method, url, body).await
    }
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        tracing::debug!(program, ?args, "running command");
        if self.verbose {
            eprintln!("  $ {} {}", program, shell_join(args));
        }
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
        if self.verbose {
            eprintln!("  $ {} {}", program, shell_join(args));
        }
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

/// Join args for display, quoting any that contain spaces or special chars.
fn shell_join(args: &[&str]) -> String {
    args.iter()
        .map(|a| {
            if a.contains(' ') || a.contains(';') || a.contains('\'') || a.is_empty() {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                (*a).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
