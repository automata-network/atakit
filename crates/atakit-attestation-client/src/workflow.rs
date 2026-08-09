//! Complete portal TLS and current-session verification workflow.

use std::path::PathBuf;

use atakit_attestation::{BindingMode, MeasurementPolicy, VerifiedSession};
use atakit_cvm_types::AppRef;

use crate::chain::TrustedWorkloadSessionPolicy;
use crate::error::PortalVerificationError;
use crate::pack::workload::packed_workload_policy;
use crate::portal::session::{verify_current_session, VerifiedPortalTls};
use crate::portal::tls::bootstrap_portal_tls;
use crate::trust::source::TrustSource;

/// Where the trusted session policy comes from.
///
/// The `Explicit` variant no longer carries a `trusted_binding`. Operator
/// supplied policy combined with a chain-derived `chain_id` and
/// `SessionRegistry` address is mixed trust even though both values are
/// well-formed, so the field is gone and the binding lives only on
/// `ChainTrustSource`, reachable only in chain mode.
#[derive(Debug, Clone)]
pub enum SessionWorkloadPolicySource {
    /// Resolve the registered `WorkloadSpec` through the chain source's own
    /// client, after verified portal TLS selects the base-image ID.
    Registry { workload: String },
    /// Use an operator-supplied typed workload policy.
    Explicit {
        policy: TrustedWorkloadSessionPolicy,
    },
    /// Resolve the workload policy from the configured `workload-trust` pack,
    /// after verified portal TLS selects the base-image ID.
    ///
    /// Carries the reference rather than a resolved policy because the pack
    /// must be shown to answer for the workload the caller asked about. Handing
    /// in a policy would have made that the caller's job, and a caller that
    /// skipped it would get a pack answering for a workload nobody requested.
    Pack { workload: AppRef },
}

/// Complete inputs for portal TLS and current-session verification.
#[derive(Debug, Clone)]
pub struct PortalSessionVerificationRequest {
    pub host: String,
    pub status_port: u16,
    pub measurement_policy: MeasurementPolicy,
    pub trust_source: TrustSource,
    pub workload_policy: SessionWorkloadPolicySource,
    pub report_path: Option<PathBuf>,
    pub required_binding: Option<BindingMode>,
}

/// Verified portal TLS identity and the current session verified through that
/// pinned connection.
#[derive(Debug, Clone)]
pub struct VerifiedPortalSession {
    pub portal_tls: VerifiedPortalTls,
    pub session: VerifiedSession,
}

/// Verify portal TLS, then verify a fresh challenge-bound current-session
/// evidence bundle through the pinned TLS connection.
pub async fn verify_portal_session(
    request: PortalSessionVerificationRequest,
) -> Result<VerifiedPortalSession, PortalVerificationError> {
    let PortalSessionVerificationRequest {
        host,
        status_port,
        measurement_policy,
        trust_source,
        workload_policy,
        report_path,
        required_binding,
    } = request;

    // One authority per verification. A policy from one source paired with
    // anchors from another is the mixed trust the exclusive rule forbids, so
    // the mismatch is refused before the portal is contacted.
    match (&trust_source, &workload_policy) {
        (TrustSource::Chain(_), SessionWorkloadPolicySource::Registry { .. })
        | (TrustSource::Explicit(_), SessionWorkloadPolicySource::Explicit { .. })
        | (TrustSource::Packs(_), SessionWorkloadPolicySource::Pack { .. }) => {}
        (TrustSource::Chain(_), SessionWorkloadPolicySource::Explicit { .. }) => {
            return Err(PortalVerificationError::Config {
                message: "chain trust mode resolves the registered workload policy from the \
                          chain; remove --trusted-workload-pcr23-sha256 and \
                          --trusted-workload-pcr23-sha384, or drop --chain to verify explicitly"
                    .to_string(),
            })
        }
        (TrustSource::Explicit(_), SessionWorkloadPolicySource::Registry { .. }) => {
            return Err(PortalVerificationError::Config {
                message: "explicit trust mode has no chain to resolve a registered workload \
                          policy from; supply --trusted-workload-pcr23-sha256 and \
                          --trusted-workload-pcr23-sha384"
                    .to_string(),
            })
        }
        (TrustSource::Packs(_), _) => {
            return Err(PortalVerificationError::Config {
                message: "trust-pack mode resolves the workload policy from the configured \
                          workload-trust pack; name the workload instead of supplying a policy \
                          or a registry lookup"
                    .to_string(),
            })
        }
        (_, SessionWorkloadPolicySource::Pack { .. }) => {
            return Err(PortalVerificationError::Config {
                message: "a workload-trust pack supplies the workload policy only in trust-pack \
                          mode; taking policy from a pack while resolving anchors elsewhere is \
                          the mixed trust the exclusive-source rule forbids"
                    .to_string(),
            })
        }
    }

    let portal_tls = bootstrap_portal_tls(
        &host,
        status_port,
        Some(measurement_policy),
        None,
        &trust_source,
        None,
        report_path.as_deref(),
    )
    .await?;

    let session = match (&trust_source, &workload_policy) {
        (TrustSource::Chain(source), SessionWorkloadPolicySource::Registry { workload }) => {
            source
                .client()
                .verify_current_session(&portal_tls, &host, status_port, workload, required_binding)
                .await
        }
        (TrustSource::Explicit(_), SessionWorkloadPolicySource::Explicit { policy }) => {
            verify_current_session(
                &portal_tls,
                &host,
                status_port,
                policy.clone(),
                required_binding,
            )
            .await
        }
        (TrustSource::Packs(source), SessionWorkloadPolicySource::Pack { workload }) => {
            // Resolved after portal TLS, because the pack's workload spec is
            // checked against the base image TLS actually selected rather than
            // one the caller declared.
            let base_image_id = portal_tls.identity.base_image_id.ok_or_else(|| {
                PortalVerificationError::PortalTlsAttestationFailed {
                    message: "verified portal TLS identity has no base-image ID".to_string(),
                }
            })?;
            let policy = packed_workload_policy(source.workload_pack()?, workload, base_image_id)?;
            verify_current_session(&portal_tls, &host, status_port, policy, required_binding).await
        }
        _ => unreachable!("the mode pairing is checked above"),
    }
    .map_err(
        |error| PortalVerificationError::PortalSessionVerificationFailed {
            message: error.to_string(),
        },
    )?;

    Ok(VerifiedPortalSession {
        portal_tls,
        session,
    })
}
