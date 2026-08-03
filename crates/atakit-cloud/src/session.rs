//! Complete cloud portal and current-session verification workflow.

use std::path::PathBuf;

use atakit_attestation::{BindingMode, MeasurementPolicy, TrustedSessionBinding, VerifiedSession};
pub use atakit_attestation_client::session::*;
use atakit_attestation_client::AttestationClient;

use crate::error::CloudError;
use crate::init::{
    bootstrap_portal_tls_with_trust_config, AzureMaaTrustConfig, IntelTdxDcapCollateralConfig,
    TlsVerificationTrust,
};

/// Source of the trusted workload policy used for current-session
/// verification.
#[derive(Debug, Clone)]
pub enum SessionWorkloadPolicySource {
    /// Resolve the exact registered `WorkloadSpec` after verified portal TLS
    /// selects the base-image ID.
    Registry {
        client: AttestationClient,
        workload: String,
    },
    /// Use a caller-supplied typed workload policy. An optional chain binding
    /// still comes from verifier-selected coordinates, never portal evidence.
    Explicit {
        policy: TrustedWorkloadSessionPolicy,
        trusted_binding: Option<TrustedSessionBinding>,
    },
}

/// Complete inputs for portal TLS and current-session verification.
#[derive(Debug, Clone)]
pub struct PortalSessionVerificationRequest {
    pub host: String,
    pub status_port: u16,
    pub measurement_policy: MeasurementPolicy,
    pub tls_verification_trust: TlsVerificationTrust,
    pub azure_maa_trust: AzureMaaTrustConfig,
    pub tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    pub report_path: Option<PathBuf>,
    pub workload_policy: SessionWorkloadPolicySource,
    pub required_binding: Option<BindingMode>,
}

/// Verified portal TLS identity and the current session verified through that
/// pinned connection.
#[derive(Debug, Clone)]
pub struct VerifiedPortalSession {
    pub portal_tls: VerifiedPortalTls,
    pub session: VerifiedSession,
}

/// Verify portal TLS through the concrete cloud integration, then verify a
/// fresh challenge-bound current-session evidence bundle through the pinned
/// TLS connection.
pub async fn verify_portal_session(
    request: PortalSessionVerificationRequest,
) -> Result<VerifiedPortalSession, CloudError> {
    let PortalSessionVerificationRequest {
        host,
        status_port,
        measurement_policy,
        tls_verification_trust,
        azure_maa_trust,
        tdx_dcap_collateral,
        report_path,
        workload_policy,
        required_binding,
    } = request;

    let portal_tls = bootstrap_portal_tls_with_trust_config(
        &host,
        status_port,
        Some(measurement_policy),
        None,
        tls_verification_trust,
        azure_maa_trust,
        tdx_dcap_collateral,
        None,
        report_path.as_deref(),
    )
    .await?;

    let session = match workload_policy {
        SessionWorkloadPolicySource::Registry { client, workload } => {
            client
                .verify_current_session(
                    &portal_tls,
                    &host,
                    status_port,
                    &workload,
                    required_binding,
                )
                .await
        }
        SessionWorkloadPolicySource::Explicit {
            policy,
            trusted_binding,
        } => {
            verify_current_session(
                &portal_tls,
                &host,
                status_port,
                policy,
                required_binding,
                trusted_binding,
            )
            .await
        }
    }
    .map_err(|error| CloudError::PortalSessionVerificationFailed {
        message: error.to_string(),
    })?;

    Ok(VerifiedPortalSession {
        portal_tls,
        session,
    })
}
