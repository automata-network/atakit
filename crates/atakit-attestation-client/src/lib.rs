//! The complete atakit attestation verification workflow.
//!
//! [`AttestationClient`] reads verifier-selected contract state. It never
//! signs or submits a transaction. The caller selects the RPC endpoint and
//! `SessionRegistry`; portal evidence cannot select either value.
//!
//! Modules follow the pipeline this crate implements:
//!
//! - [`chain`] obtains trusted inputs from verifier-selected registry state.
//! - [`collateral`] resolves vendor-signed material for the presented evidence.
//! - [`trust`] loads verifier-supplied inputs and states what each platform
//!   requires.
//! - [`portal`] talks to the portal under verification.
//! - [`workflow`] runs the complete portal TLS and current-session order.
//!
//! Portal TLS collection lives here as of 2026-08-08, reversing the boundary
//! set in `atakit-ng` pull request 58. The platform branching it performs is
//! attestation logic, not cloud deployment: it uses no cloud provider SDK, no
//! credentials, and no deployment module. See this crate's README.

pub mod chain;
pub mod collateral;
pub mod error;
mod http;
pub mod pack;
pub mod portal;
#[cfg(test)]
mod test_support;
pub mod trust;
pub mod workflow;

pub use chain::{
    AttestationClient, AttestationClientConfig, AttestationClientError, ChainVerificationContext,
    TrustedWorkloadSessionPolicy,
};
pub use error::PortalVerificationError;
// `PortalSessionVerificationContext` and `SessionAuthority` are deliberately
// not exported. They record what was verified; a caller able to construct or
// mutate one could replace the authority after portal TLS established it, which
// defeats every check that follows. `VerifiedPortalTls::authority_kind` is the
// read-only view callers need.
pub use portal::session::{
    verify_current_session, SessionAuthorityKind, SessionWorkloadSelector, TlsManualOverride,
    VerifiedPortalTls,
};

/// Retained for callers that referenced the pre-module path.
pub use portal::session;

pub use collateral::intel_tdx::{
    tdx_dcap_automata_read_strategy, tdx_dcap_collateral_config,
    tdx_dcap_collateral_config_with_read_strategy, IntelTdxDcapCollateralConfig,
    IntelTdxDcapCollateralSource, TdxDcapAutomataReadStrategy,
};
// The raw conversions are deliberately not exported. They take a `TrustPack`
// and perform no validity check, because they are pure conversions; exporting
// them would give a caller a way to use an expired pack's contents without
// passing any of the boundaries that check the window. The public surface is
// `PackTrustSource` and the two verification modes, all of which check.
pub use pack::read::{read_trust_pack, read_trust_pack_file, TrustPack, TrustPackReadOptions};
pub use pack::write::TrustPackBuilder;
pub use pack::{ArchiveLimits, TrustPackError, TrustPackIndex, TrustPackKind};
pub use portal::status::read_untrusted_portal_base_image_id;
pub use portal::tls::{
    bootstrap_portal_tls, tls_manual_override_message, ChainBaseImage, PortalTlsVerificationMode,
};
pub use trust::builder::TrustAnchorsBuilder;
pub use trust::files::{
    azure_maa_trust_config_from_chain, chain_coordinates_configured, load_tls_verification_trust,
    AzureMaaTrustConfig, AzureMaaTrustSource, TlsVerificationTrust,
};
pub use trust::measurement::{
    cloud_tls_attestation_report_path, load_measurement_policy, local_measurement_pack_exists,
    workload_tls_attestation_report_path, write_tls_attestation_report,
};
pub use trust::request::{AzureMaaJwtInfo, CollateralRequest};
pub use trust::requirements::{
    required_trust_inputs, required_trust_inputs_for_request, unsatisfied_trust_inputs,
    RequiredTrustInput,
};
pub use trust::source::{
    ChainTrustSource, ExplicitTrustSource, PackTrustSource, TrustInputSource, TrustProvenance,
    TrustSource,
};
pub use workflow::{
    verify_portal_session, PortalSessionVerificationRequest, SessionVerificationMode,
    VerifiedPortalSession,
};
