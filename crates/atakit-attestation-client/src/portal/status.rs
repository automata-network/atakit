//! The portal's pre-attestation `GET /status` claim.
//!
//! This lives with verification rather than with deployment because its only
//! use is choosing which trusted measurement policy to load before portal TLS
//! attestation runs. The value itself is never trusted.

use std::time::Duration;

use crate::error::PortalVerificationError;
use crate::http::read_response_bytes_limited;

const MAX_PORTAL_STATUS_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, serde::Deserialize)]
struct PortalBaseImageClaim {
    base_image_id: Option<String>,
}

/// Read the portal's pre-TLS base-image claim from `GET /status`.
///
/// This value is not trusted. Callers may use it only as the lookup key for a
/// trusted measurement policy. The later TLS attestation check must prove that
/// the measured platform satisfies the policy returned for this exact ID.
pub async fn read_untrusted_portal_base_image_id(
    host: &str,
    status_port: u16,
) -> Result<[u8; 32], PortalVerificationError> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| PortalVerificationError::Http {
            message: error.to_string(),
        })?;
    let url = format!("https://{host}:{status_port}/status");
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(
            |error| PortalVerificationError::PortalTlsAttestationFailed {
                message: format!("read untrusted base_image_id from {url}: {error}"),
            },
        )?
        .error_for_status()
        .map_err(
            |error| PortalVerificationError::PortalTlsAttestationFailed {
                message: format!("read untrusted base_image_id from {url}: {error}"),
            },
        )?;
    let body = read_response_bytes_limited(
        response,
        MAX_PORTAL_STATUS_RESPONSE_BYTES,
        "portal status response",
    )
    .await
    .map_err(
        |message| PortalVerificationError::PortalTlsAttestationFailed {
            message: format!("read untrusted base_image_id from {url}: {message}"),
        },
    )?;
    let claim: PortalBaseImageClaim = serde_json::from_slice(&body).map_err(|error| {
        PortalVerificationError::PortalTlsAttestationFailed {
            message: format!("parse untrusted base_image_id from {url}: {error}"),
        }
    })?;
    parse_untrusted_portal_base_image_id(claim.base_image_id.as_deref())
}

fn parse_untrusted_portal_base_image_id(
    value: Option<&str>,
) -> Result<[u8; 32], PortalVerificationError> {
    let value = value.ok_or_else(|| PortalVerificationError::PortalTlsAttestationFailed {
        message: "GET /status did not return base_image_id".to_string(),
    })?;
    let raw = value.strip_prefix("0x").ok_or_else(|| {
        PortalVerificationError::PortalTlsAttestationFailed {
            message: "GET /status base_image_id must use 0x-prefixed hexadecimal".to_string(),
        }
    })?;
    let decoded =
        hex::decode(raw).map_err(
            |error| PortalVerificationError::PortalTlsAttestationFailed {
                message: format!("GET /status base_image_id is invalid hexadecimal: {error}"),
            },
        )?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        PortalVerificationError::PortalTlsAttestationFailed {
            message: format!(
                "GET /status base_image_id must contain exactly 32 bytes, got {}",
                decoded.len()
            ),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_untrusted_portal_base_image_id_strictly() {
        let value = format!("0x{}", "ab".repeat(32));
        assert_eq!(
            parse_untrusted_portal_base_image_id(Some(&value)).unwrap(),
            [0xab; 32]
        );

        for invalid in [None, Some("ab"), Some("0x11"), Some("0xzzzz")] {
            assert!(parse_untrusted_portal_base_image_id(invalid).is_err());
        }
    }
}
