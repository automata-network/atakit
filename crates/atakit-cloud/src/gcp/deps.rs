use crate::error::CloudError;

/// Check that `gcloud` is installed and on PATH.
pub fn check_gcloud() -> Result<(), CloudError> {
    match std::process::Command::new("gcloud")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err(CloudError::DependencyMissing {
            tool: "gcloud".to_string(),
            install_hint: "install the Google Cloud SDK: https://cloud.google.com/sdk/docs/install"
                .to_string(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(CloudError::DependencyMissing {
                tool: "gcloud".to_string(),
                install_hint:
                    "install the Google Cloud SDK: https://cloud.google.com/sdk/docs/install"
                        .to_string(),
            })
        }
        Err(e) => Err(CloudError::Io(e)),
    }
}
