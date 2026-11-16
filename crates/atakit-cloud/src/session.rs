//! Complete portal TLS and current-session verification workflow.
//!
//! Relocated to `atakit_attestation_client::workflow`. Retained
//! here as a re-export so `atakit cloud verify-session` is unchanged.

pub use atakit_attestation_client::session::*;
pub use atakit_attestation_client::workflow::{
    verify_portal_session, PortalSessionVerificationRequest, SessionVerificationMode,
    VerifiedPortalSession,
};
