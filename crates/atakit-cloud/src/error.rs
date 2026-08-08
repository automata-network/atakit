use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("config error: {message}")]
    Config { message: String },

    #[error("target not found: {name}")]
    TargetNotFound { name: String },

    #[error("state error: {message}")]
    State { message: String },

    #[error("deployment not found: {instance}")]
    StateNotFound { instance: String },

    #[error("ambiguous instance '{instance}', matches: {}", matches.join(", "))]
    AmbiguousInstance {
        instance: String,
        matches: Vec<String>,
    },

    #[error("deployment already exists: {instance}")]
    AlreadyExists { instance: String },

    #[error("{program} failed (exit {code:?}): {stderr}")]
    CommandFailed {
        program: String,
        args: String,
        stderr: String,
        code: Option<i32>,
    },

    #[error("{program} not found on PATH")]
    CommandNotFound { program: String },

    #[error("missing dependency: {tool} ({install_hint})")]
    DependencyMissing { tool: String, install_hint: String },

    #[error("image upload failed: {message}")]
    ImageUploadFailed { message: String },

    #[error("firewall error: {message}")]
    FirewallError { message: String },

    #[error("disk error: {message}")]
    DiskError { message: String },

    #[error("invalid --disk-passphrase: {message}")]
    InvalidDiskPassphrase { message: String },

    #[error("instance error: {message}")]
    InstanceError { message: String },

    #[error("portal at {address} did not respond within {timeout_secs}s")]
    PortalTimeout { address: String, timeout_secs: u64 },

    #[error("portal initialization failed: {message}")]
    PortalInitFailed { message: String },

    #[error("portal TLS attestation failed: {message}")]
    PortalTlsAttestationFailed { message: String },

    #[error("portal session verification failed: {message}")]
    PortalSessionVerificationFailed { message: String },

    #[error("portal session lifecycle failed: {message}")]
    PortalSessionLifecycleFailed { message: String },

    #[error("deploy failed at step '{step}': {message}")]
    DeployFailed { step: String, message: String },

    #[error("destroy failed for resource '{resource}': {message}")]
    DestroyFailed { resource: String, message: String },

    #[error("invalid name '{name}': {message}")]
    InvalidName { name: String, message: String },

    #[error("archive not found: {path}")]
    ArchiveNotFound { path: String },

    #[error(
        "workload archive changed after policy validation: {path} \
         (expected SHA-256 {expected}, got {actual}); restart initialization"
    )]
    WorkloadArchiveChanged {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("workload error: {message}")]
    WorkloadError { message: String },

    #[error("HTTP error: {message}")]
    Http { message: String },

    #[error("I/O error: {path}")]
    IoPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Verification errors raised by `atakit-attestation-client` re-enter this
/// vocabulary unchanged.
///
/// Each variant maps onto the `CloudError` variant carrying the identical
/// message, so relocating that code did not change what any `atakit cloud`
/// command prints. Wrapping instead of mapping would have.
impl From<atakit_attestation_client::PortalVerificationError> for CloudError {
    fn from(error: atakit_attestation_client::PortalVerificationError) -> Self {
        use atakit_attestation_client::PortalVerificationError as Source;
        match error {
            Source::Config { message } => CloudError::Config { message },
            Source::Http { message } => CloudError::Http { message },
            Source::PortalTlsAttestationFailed { message } => {
                CloudError::PortalTlsAttestationFailed { message }
            }
            Source::PortalSessionVerificationFailed { message } => {
                CloudError::PortalSessionVerificationFailed { message }
            }
            Source::IoPath { path, source } => CloudError::IoPath { path, source },
            Source::Json(source) => CloudError::Json(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CloudError;

    /// The conversion must preserve the rendered message exactly. A caller that
    /// formats the error sees no difference between the pre-relocation and
    /// post-relocation build.
    #[test]
    fn verification_errors_convert_without_changing_their_message() {
        use atakit_attestation_client::PortalVerificationError as Source;

        for source in [
            Source::Config {
                message: "bad input".to_string(),
            },
            Source::Http {
                message: "connection reset".to_string(),
            },
            Source::PortalTlsAttestationFailed {
                message: "quote mismatch".to_string(),
            },
            Source::PortalSessionVerificationFailed {
                message: "invalid session evidence".to_string(),
            },
            Source::IoPath {
                path: "/dev/urandom".into(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
        ] {
            let expected = source.to_string();
            assert_eq!(CloudError::from(source).to_string(), expected);
        }
    }

    #[test]
    fn portal_session_verification_error_keeps_message_field() {
        let error = CloudError::PortalSessionVerificationFailed {
            message: "invalid session evidence".to_string(),
        };

        assert_eq!(
            error.to_string(),
            "portal session verification failed: invalid session evidence"
        );
    }
}
