//! Read-only retrieval of trusted inputs for atakit attestation verification.
//!
//! [`AttestationClient`] reads verifier-selected contract state. It never
//! signs or submits a transaction. The caller selects the RPC endpoint and
//! `SessionRegistry`; portal evidence cannot select either value.
//!
//! Modules follow the pipeline this crate implements:
//!
//! - [`chain`] obtains trusted inputs from verifier-selected registry state.
//! - [`portal`] talks to the portal under verification.

pub mod chain;
pub mod portal;

pub use chain::{
    AttestationClient, AttestationClientConfig, AttestationClientError, ChainVerificationContext,
    TrustedWorkloadSessionPolicy,
};
pub use portal::session::{
    verify_current_session, PortalSessionVerificationContext, TlsManualOverride, VerifiedPortalTls,
};

/// Retained for callers that referenced the pre-module path.
pub use portal::session;
