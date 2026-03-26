use crate::error::CloudError;

/// Check that `az` CLI is installed and on PATH.
pub fn check_az() -> Result<(), CloudError> {
    match std::process::Command::new("az")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err(CloudError::DependencyMissing {
            tool: "az".to_string(),
            install_hint: "install the Azure CLI: https://learn.microsoft.com/cli/azure/install-azure-cli"
                .to_string(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(CloudError::DependencyMissing {
                tool: "az".to_string(),
                install_hint:
                    "install the Azure CLI: https://learn.microsoft.com/cli/azure/install-azure-cli"
                        .to_string(),
            })
        }
        Err(e) => Err(CloudError::Io(e)),
    }
}
