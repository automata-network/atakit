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
pub mod portal;
pub mod trust;
pub mod workflow;

pub use chain::{
    AttestationClient, AttestationClientConfig, AttestationClientError, ChainVerificationContext,
    TrustedWorkloadSessionPolicy,
};
pub use error::PortalVerificationError;
pub use portal::session::{
    verify_current_session, PortalSessionVerificationContext, TlsManualOverride, VerifiedPortalTls,
};

/// Retained for callers that referenced the pre-module path.
pub use portal::session;

pub use collateral::intel_tdx::{
    tdx_dcap_automata_read_strategy, tdx_dcap_collateral_config,
    tdx_dcap_collateral_config_with_read_strategy, IntelTdxDcapCollateralConfig,
    IntelTdxDcapCollateralSource, TdxDcapAutomataReadStrategy,
};
pub use portal::status::read_untrusted_portal_base_image_id;
pub use portal::tls::{
    bootstrap_portal_tls, bootstrap_portal_tls_with_trust_config, tls_manual_override_message,
};
pub use trust::files::{
    azure_maa_trust_config_from_chain, load_tls_verification_trust, AzureMaaTrustConfig,
    AzureMaaTrustSource, TlsVerificationTrust,
};
pub use trust::measurement::{
    cloud_tls_attestation_report_path, load_measurement_policy, local_measurement_pack_exists,
    workload_tls_attestation_report_path, write_tls_attestation_report,
};
pub use trust::requirements::{
    required_trust_inputs, unsatisfied_trust_inputs, RequiredTrustInput,
};
pub use workflow::{
    verify_portal_session, PortalSessionVerificationRequest, SessionWorkloadPolicySource,
    VerifiedPortalSession,
};
