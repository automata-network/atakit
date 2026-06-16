use crate::error::CloudError;

const INSTALL_HINT: &str =
    "install the AWS CLI v2: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html";

/// Check that the `aws` CLI is installed and on PATH.
pub fn check_aws() -> Result<(), CloudError> {
    match std::process::Command::new("aws")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err(CloudError::DependencyMissing {
            tool: "aws".to_string(),
            install_hint: INSTALL_HINT.to_string(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(CloudError::DependencyMissing {
            tool: "aws".to_string(),
            install_hint: INSTALL_HINT.to_string(),
        }),
        Err(e) => Err(CloudError::Io(e)),
    }
}
