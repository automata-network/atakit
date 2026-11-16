//! Errors raised by portal TLS attestation collection, trust-input loading,
//! and the complete verification workflow.
//!
//! These responsibilities moved out of `atakit-cloud`, whose `CloudError` also
//! covers cloud provider, disk-image, and deployment failures that this crate
//! cannot produce. `atakit-cloud` converts back through
//! `From<PortalVerificationError>`, and each variant maps onto the `CloudError`
//! variant with the identical message, so command output is unchanged.

use std::path::PathBuf;

use atakit_attestation::SessionVerificationFailure;

#[derive(Debug, thiserror::Error)]
pub enum PortalVerificationError {
    #[error("config error: {message}")]
    Config { message: String },

    #[error("HTTP error: {message}")]
    Http { message: String },

    #[error("portal TLS attestation failed: {message}")]
    PortalTlsAttestationFailed { message: String },

    #[error("portal session verification failed: {message}")]
    PortalSessionVerificationFailed { message: String },

    #[error("portal session verification failed: {failure:?}")]
    SessionVerification {
        failure: Box<SessionVerificationFailure>,
    },

    #[error("I/O error: {path}")]
    IoPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::PortalVerificationError;

    /// The rendered text must match the `CloudError` variant each one converts
    /// into, because `atakit cloud deploy`, `init`, and `verify-session` print
    /// these strings.
    #[test]
    fn messages_match_the_cloud_error_variants_they_convert_into() {
        assert_eq!(
            PortalVerificationError::Config {
                message: "bad input".to_string()
            }
            .to_string(),
            "config error: bad input"
        );
        assert_eq!(
            PortalVerificationError::Http {
                message: "connection reset".to_string()
            }
            .to_string(),
            "HTTP error: connection reset"
        );
        assert_eq!(
            PortalVerificationError::PortalTlsAttestationFailed {
                message: "quote mismatch".to_string()
            }
            .to_string(),
            "portal TLS attestation failed: quote mismatch"
        );
        assert_eq!(
            PortalVerificationError::PortalSessionVerificationFailed {
                message: "invalid session evidence".to_string()
            }
            .to_string(),
            "portal session verification failed: invalid session evidence"
        );
        assert_eq!(
            PortalVerificationError::IoPath {
                path: "/dev/urandom".into(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            }
            .to_string(),
            "I/O error: /dev/urandom"
        );
    }
}
