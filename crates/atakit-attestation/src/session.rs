//! Shared application-session verification primitives.
//!
//! Provider-specific TEE, AK, TPM, and PCR verification lives in the
//! provider-neutral verification core shared with TLS. This module owns the session-specific wire types,
//! deterministic derivations, PCR policy evaluation, request binding, and
//! explicit caller-supplied trust contract.
//!
//! This API verifies the cryptographic and policy validity of the presented
//! current session. Owner transaction authorization, lifecycle-operation
//! authorization, and registry state are separate concerns and are neither
//! required nor inferred here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use signature::{hazmat::PrehashVerifier, Verifier};

const SESSION_DOMAIN: &str = "CVM_SESSION_V1";
const KEY_DOMAIN: &str = "KEY_RESOLVER_V1";
const SESSION_NONCE_DOMAIN: &str = "CVM_SESSION_REG_NONCE_V1";
const DELEGATION_DOMAIN: &str = "CVM_SESSION_KEY_DELEGATION";
const EVIDENCE_BINDING_DOMAIN: &str = "ATAKIT_PORTAL_SESSION_REQUEST_BINDING_EVIDENCE_BUNDLE_V1";
const CHAIN_SUBMISSION_BINDING_DOMAIN: &str =
    "ATAKIT_PORTAL_SESSION_REQUEST_BINDING_CHAIN_SUBMISSION_V1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvidenceBundle {
    pub format: u8,
    pub binding: SessionBinding,
    pub platform: SessionPlatform,
    pub tee_evidence: RawEvidence,
    pub ak_evidence: AkEvidence,
    pub tpm_quote: TpmQuoteEvidence,
    pub tpm_certify: TpmCertifyEvidence,
    pub pcr_values: Vec<SessionPcrValue>,
    pub event_log_hashes: Vec<SessionEventHashes>,
    pub session_key: SessionPublicKey,
    pub session_key_delegation: SessionKeyDelegation,
    pub session_id: String,
    pub policy: SessionPolicy,
    pub owner: SessionOwner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBinding {
    pub mode: BindingMode,
    pub chain_id: u64,
    pub registry: String,
    pub owner_nonce: String,
    pub qualifying_data: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingMode {
    Chain,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPlatform {
    pub cloud: String,
    pub attestation_mode: SessionAttestationMode,
    pub tee: String,
    pub machine_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAttestationMode {
    Hardware,
    Emulation,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvidence {
    pub kind: String,
    pub report: String,
    pub auxiliary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkEvidence {
    pub kind: String,
    pub ak_public: String,
    pub collateral: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuoteEvidence {
    pub tpm2b_attest: String,
    pub tpm_signature: String,
    pub signature_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmCertifyEvidence {
    pub tpm2b_attest: String,
    pub tpm_signature: String,
    pub tpmt_public: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPcrValue {
    pub index: u8,
    pub sha256: String,
    pub sha384: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEventHashes {
    pub pcr_index: u8,
    pub sha256: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPublicKey {
    pub type_id: u8,
    pub bytes: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeyDelegation {
    pub tpm_signing_key: SessionPublicKey,
    pub digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    pub workload_id: String,
    pub base_image_id: String,
    pub platform_profile_id: String,
    pub measurement_variant_id: String,
    pub pcr_specs: Vec<SessionPcrPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPcrPolicy {
    pub pcr_index: u8,
    pub verify_type: SessionPcrVerifyType,
    pub match_data: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionPcrVerifyType {
    Static,
    DynamicSubset,
    DynamicSubsequence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOwner {
    pub fingerprint: String,
    /// Optional on-chain transaction projection. It remains request-bound as
    /// part of the bundle JSON but is not an offline session-validity input.
    pub contract_authorization: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequestBinding {
    pub challenge: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct SessionVerificationInputs {
    /// Exact JSON value signed by the portal. The verifier parses its trusted
    /// fields from this same value, so request binding cannot cover different
    /// bytes from the evidence being verified.
    pub bundle: serde_json::Value,
    pub request_binding: SessionRequestBinding,
    /// Exact challenge generated by the verifier for this request.
    ///
    /// Verifying only the challenge echoed by the portal would accept a
    /// replayed bundle and its old, otherwise-valid signature.
    pub expected_challenge: [u8; 32],
    pub trust: SessionTrust,
}

#[derive(Debug, Clone)]
pub struct SessionTrust {
    pub platform: SessionPlatformTrust,
    pub policy: TrustedSessionPolicy,
    /// Chain coordinates selected by the verifier. Portal evidence never
    /// selects these values. Local-bound sessions do not use them.
    pub binding: Option<TrustedSessionBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedSessionBinding {
    pub chain_id: u64,
    pub registry: [u8; 20],
}

#[derive(Debug, Clone, Default)]
pub struct CertificateTrust {
    /// Exact trusted DER certificates.
    pub certificates: Vec<Vec<u8>>,
    /// Keccak-256 hashes of trusted DER certificates.
    pub keccak256_hashes: Vec<[u8; 32]>,
}

/// Provider-specific trust input. The caller resolves and supplies these
/// values; the verifier never fetches or silently substitutes trust material.
#[derive(Debug, Clone)]
pub enum SessionPlatformTrust {
    GcpTdx {
        gcp_ak_roots: CertificateTrust,
        dcap_collateral: serde_json::Value,
    },
    GcpSnp {
        gcp_ak_roots: CertificateTrust,
        amd_ark_roots: CertificateTrust,
    },
    AzureTdx {
        maa_signing_keys: Vec<AzureMaaTrustKey>,
        dcap_collateral: serde_json::Value,
    },
    AzureSnp {
        maa_signing_keys: Vec<AzureMaaTrustKey>,
        amd_ark_roots: CertificateTrust,
        /// AMD SNP ARK/ASK/VCEK or VLEK certificate table for this report.
        snp_cert_table: Vec<u8>,
    },
    AwsSnp {
        aws_nitro_roots: CertificateTrust,
        amd_ark_roots: CertificateTrust,
    },
}

#[derive(Debug, Clone)]
pub struct AzureMaaTrustKey {
    pub kid: String,
    pub issuer: String,
    pub not_after: u64,
    /// PKCS#1 DER or a supported RSA public-key encoding.
    pub public_key: Vec<u8>,
}

/// Policy selected by the verifier's caller. The policy projection in the
/// evidence bundle is untrusted; its IDs and any non-empty PCR projection must
/// match this value.
#[derive(Debug, Clone)]
pub struct TrustedSessionPolicy {
    pub workload_id: [u8; 32],
    pub base_image_id: [u8; 32],
    pub platform_profile_id: [u8; 32],
    pub measurement_variant_id: [u8; 32],
    pub pcr_specs: Vec<SessionPcrPolicy>,
    pub effective_attributes: Vec<SessionAttribute>,
    pub attribute_requirements: Vec<SessionAttributeRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAttribute {
    pub key: [u8; 32],
    pub value: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAttributeRequirement {
    pub key: [u8; 32],
    /// Empty means any value is accepted, matching the contract.
    pub allowed_values: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSession {
    pub session_id: [u8; 32],
    pub session_key_fingerprint: [u8; 32],
    pub binding_mode: BindingMode,
    pub binding_chain_id: u64,
    pub binding_registry: [u8; 20],
    pub attestation_mode: SessionAttestationMode,
    pub checks: Vec<SessionVerificationCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionVerificationCheck {
    pub name: String,
    pub valid: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionVerificationFailure {
    pub checks: Vec<SessionVerificationCheck>,
    pub errors: Vec<String>,
}

/// Verify a production session against explicit provider trust and policy.
/// Development emulation evidence is never accepted by this entry point.
pub fn verify_session_bundle(
    inputs: SessionVerificationInputs,
) -> std::result::Result<VerifiedSession, SessionVerificationFailure> {
    let mut checks = Vec::new();
    let mut errors = Vec::new();
    let bundle: SessionEvidenceBundle = match serde_json::from_value(inputs.bundle.clone()) {
        Ok(bundle) => bundle,
        Err(error) => {
            record(
                &mut checks,
                &mut errors,
                "bundle-json",
                false,
                &format!("invalid session evidence bundle: {error}"),
            );
            return Err(SessionVerificationFailure { checks, errors });
        }
    };
    let bundle = &bundle;

    record(
        &mut checks,
        &mut errors,
        "format",
        bundle.format == 1,
        "expected format 1",
    );
    verify_production_evidence_kind(bundle, &mut checks, &mut errors);
    verify_key_types(bundle, &mut checks, &mut errors);
    let session_id = decode_hex_32(&bundle.session_id, "session_id", &mut errors);
    let session_key = decode_hex(&bundle.session_key.bytes, "session_key.bytes", &mut errors);
    let session_key_fingerprint = session_key
        .as_ref()
        .map(|bytes| compute_key_fingerprint(bundle.session_key.type_id, bytes));
    if let (Some(actual), Some(expected)) = (
        session_key_fingerprint,
        decode_hex_32(
            &bundle.session_key.fingerprint,
            "session_key.fingerprint",
            &mut errors,
        ),
    ) {
        record(
            &mut checks,
            &mut errors,
            "session-key-fingerprint",
            actual == expected,
            "session key fingerprint mismatch",
        );
    }

    let tpm_signature = decode_b64(
        &bundle.tpm_quote.tpm_signature,
        "tpm_quote.tpm_signature",
        &mut errors,
    );
    let tee_report = decode_b64(
        &bundle.tee_evidence.report,
        "tee_evidence.report",
        &mut errors,
    );
    let tee_hash = tee_report
        .as_ref()
        .map(|report| <[u8; 32]>::from(Keccak256::digest(report)));
    if let (Some(signature), Some(tee_hash), Some(expected_id)) =
        (tpm_signature.as_ref(), tee_hash, session_id)
    {
        let signature_hash: [u8; 32] = Keccak256::digest(signature).into();
        let actual_id = compute_session_id(signature_hash, tee_hash);
        record(
            &mut checks,
            &mut errors,
            "session-id",
            actual_id == expected_id,
            "session ID does not match the Quote signature and TEE report hash",
        );
    }

    verify_platform_attestation(bundle, &inputs.trust.platform, &mut checks, &mut errors);
    verify_raw_quote(bundle, &mut checks, &mut errors);
    verify_quote_projection(bundle, &mut checks, &mut errors);
    verify_raw_certify(bundle, &mut checks, &mut errors);
    verify_delegation(bundle, &mut checks, &mut errors);

    let binding_registry = verify_binding(
        bundle,
        inputs.trust.binding.as_ref(),
        &mut checks,
        &mut errors,
    );
    verify_policies(bundle, &inputs.trust.policy, &mut checks, &mut errors);
    verify_request_binding(
        bundle,
        &inputs.bundle,
        &inputs.request_binding,
        inputs.expected_challenge,
        &mut checks,
        &mut errors,
    );

    if errors.is_empty() {
        Ok(VerifiedSession {
            session_id: session_id.expect("validated session id"),
            session_key_fingerprint: session_key_fingerprint.expect("validated session key"),
            binding_mode: bundle.binding.mode,
            binding_chain_id: bundle.binding.chain_id,
            binding_registry: binding_registry.expect("validated binding registry"),
            attestation_mode: SessionAttestationMode::Hardware,
            checks,
        })
    } else {
        Err(SessionVerificationFailure { checks, errors })
    }
}

fn verify_key_types(
    bundle: &SessionEvidenceBundle,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    record(
        checks,
        errors,
        "session-key-type",
        bundle.session_key.type_id == 3,
        "session request binding requires an ES256K session key (type_id 3)",
    );
    record(
        checks,
        errors,
        "tpm-signing-key-type",
        bundle.session_key_delegation.tpm_signing_key.type_id == 2,
        "certified TPM signing key must be ES256 (type_id 2)",
    );
}

fn verify_production_evidence_kind(
    bundle: &SessionEvidenceBundle,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    record(
        checks,
        errors,
        "attestation-mode",
        bundle.platform.attestation_mode == SessionAttestationMode::Hardware,
        "production session verification requires attestation_mode=hardware",
    );
    let production = bundle.tee_evidence.kind != "emulation"
        && bundle.ak_evidence.kind != "emulation"
        && bundle.platform.tee != "emulation"
        && bundle.platform.tee != "none"
        && bundle.session_key_delegation.tpm_signing_key.type_id != 0;
    record(
        checks,
        errors,
        "production-evidence",
        production,
        "development emulation evidence is not accepted by the production session verifier",
    );
}

fn verify_platform_attestation(
    bundle: &SessionEvidenceBundle,
    trust: &SessionPlatformTrust,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    match trust {
        SessionPlatformTrust::GcpTdx {
            gcp_ak_roots,
            dcap_collateral,
        } => {
            if !require_platform(bundle, "gcp", "tdx", checks, errors) {
                return;
            }
            verify_gcp_platform(
                bundle,
                gcp_ak_roots,
                None,
                Some(dcap_collateral),
                checks,
                errors,
            );
        }
        SessionPlatformTrust::GcpSnp {
            gcp_ak_roots,
            amd_ark_roots,
        } => {
            if !require_platform(bundle, "gcp", "sev-snp", checks, errors) {
                return;
            }
            verify_gcp_platform(
                bundle,
                gcp_ak_roots,
                Some(amd_ark_roots),
                None,
                checks,
                errors,
            );
        }
        SessionPlatformTrust::AzureTdx {
            maa_signing_keys,
            dcap_collateral,
        } => {
            if !require_platform(bundle, "azure", "tdx", checks, errors) {
                return;
            }
            verify_azure_platform(
                bundle,
                maa_signing_keys,
                None,
                Some(dcap_collateral),
                checks,
                errors,
            );
        }
        SessionPlatformTrust::AzureSnp {
            maa_signing_keys,
            amd_ark_roots,
            snp_cert_table,
        } => {
            if !require_platform(bundle, "azure", "sev-snp", checks, errors) {
                return;
            }
            verify_azure_platform(
                bundle,
                maa_signing_keys,
                Some((amd_ark_roots, snp_cert_table.as_slice())),
                None,
                checks,
                errors,
            );
        }
        SessionPlatformTrust::AwsSnp { .. } => record(
            checks,
            errors,
            "platform-attestation",
            false,
            "AWS session-bundle verification is unsupported until Nitro attestation and raw SNP evidence are verified as one chain",
        ),
    }
}

fn require_platform(
    bundle: &SessionEvidenceBundle,
    cloud: &str,
    tee: &str,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) -> bool {
    let valid = bundle.platform.cloud == cloud && bundle.platform.tee == tee;
    record(
        checks,
        errors,
        "platform-trust-selection",
        valid,
        &format!(
            "selected trust requires cloud={cloud}, tee={tee}; bundle has cloud={}, tee={}",
            bundle.platform.cloud, bundle.platform.tee
        ),
    );
    valid
}

fn verify_gcp_platform(
    bundle: &SessionEvidenceBundle,
    gcp_ak_roots: &CertificateTrust,
    amd_ark_roots: Option<&CertificateTrust>,
    dcap_collateral: Option<&serde_json::Value>,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    if bundle.ak_evidence.kind != "gcp_cert_chain" {
        record(
            checks,
            errors,
            "gcp-ak-cert-chain",
            false,
            "GCP session verification requires ak_evidence.kind=gcp_cert_chain",
        );
        return;
    }
    let collateral = decode_b64(
        &bundle.ak_evidence.collateral,
        "ak_evidence.collateral",
        errors,
    );
    let ak_public = decode_b64(
        &bundle.ak_evidence.ak_public,
        "ak_evidence.ak_public",
        errors,
    );
    let quote = decode_b64(
        &bundle.tpm_quote.tpm2b_attest,
        "tpm_quote.tpm2b_attest",
        errors,
    );
    let quote_signature = decode_b64(
        &bundle.tpm_quote.tpm_signature,
        "tpm_quote.tpm_signature",
        errors,
    );
    let (Some(collateral), Some(ak_public), Some(quote), Some(quote_signature)) =
        (collateral, ak_public, quote, quote_signature)
    else {
        return;
    };
    let chain = match decode_abi_bytes_array(&collateral) {
        Ok(chain) => chain,
        Err(detail) => {
            record(checks, errors, "gcp-ak-cert-chain", false, &detail);
            return;
        }
    };

    let mut report = super::VerificationReport {
        checks: Vec::new(),
        evidence: super::EvidenceSummary::default(),
    };
    let mut core_errors = Vec::new();
    super::verification_core::verify_gcp_ak_cert_chain_der(
        &mut report,
        &mut core_errors,
        &chain,
        &ak_public,
        &gcp_ak_roots.certificates,
        &gcp_ak_roots.keccak256_hashes,
    );
    super::verification_core::verify_tpm_quote_signature(
        &mut report,
        &mut core_errors,
        &ak_public,
        &quote,
        &quote_signature,
    );

    let tee_evidence = super::TeeEvidence {
        kind: bundle.tee_evidence.kind.clone(),
        report: bundle.tee_evidence.report.clone(),
        auxiliary: bundle.tee_evidence.auxiliary.clone(),
    };
    let pcrs = bundle
        .pcr_values
        .iter()
        .map(|pcr| super::PcrEvidence {
            index: pcr.index,
            sha256: Some(pcr.sha256.clone()),
            sha384: pcr.sha384.clone(),
        })
        .collect::<Vec<_>>();
    super::verification_core::verify_gcp_tee_vtpm_binding(
        &mut report,
        &mut core_errors,
        Some(&tee_evidence),
        &bundle.platform.tee,
        &pcrs,
    );
    match (amd_ark_roots, dcap_collateral) {
        (Some(amd), None) => super::verification_core::verify_gcp_snp_vendor_report(
            &mut report,
            &mut core_errors,
            Some(&tee_evidence),
            &amd.certificates,
            &amd.keccak256_hashes,
        ),
        (None, Some(dcap)) => super::verification_core::verify_gcp_tdx_vendor_report(
            &mut report,
            &mut core_errors,
            Some(&tee_evidence),
            dcap,
        ),
        _ => record(
            checks,
            errors,
            "platform-attestation",
            false,
            "GCP trust input is inconsistent with the selected TEE",
        ),
    }
    import_core_checks(report, checks, errors);
}

fn verify_azure_platform(
    bundle: &SessionEvidenceBundle,
    maa_signing_keys: &[AzureMaaTrustKey],
    snp_trust: Option<(&CertificateTrust, &[u8])>,
    dcap_collateral: Option<&serde_json::Value>,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let Some(binding) = azure_ak_binding(bundle, errors) else {
        return;
    };
    let quote = decode_b64(
        &bundle.tpm_quote.tpm2b_attest,
        "tpm_quote.tpm2b_attest",
        errors,
    );
    let quote_signature = decode_b64(
        &bundle.tpm_quote.tpm_signature,
        "tpm_quote.tpm_signature",
        errors,
    );
    let (Some(quote), Some(quote_signature)) = (quote, quote_signature) else {
        return;
    };
    let tee_evidence = super::TeeEvidence {
        kind: bundle.tee_evidence.kind.clone(),
        report: bundle.tee_evidence.report.clone(),
        auxiliary: bundle.tee_evidence.auxiliary.clone(),
    };
    let mut report = super::VerificationReport {
        checks: Vec::new(),
        evidence: super::EvidenceSummary::default(),
    };
    let mut core_errors = Vec::new();
    super::verification_core::verify_azure_maa_session_binding(
        &mut report,
        &mut core_errors,
        &binding,
        maa_signing_keys,
        &bundle.platform.tee,
    );
    super::verification_core::verify_azure_hclak_quote_signature(
        &mut report,
        &mut core_errors,
        &binding,
        &quote,
        &quote_signature,
    );
    super::verification_core::verify_azure_tee_var_data_binding(
        &mut report,
        &mut core_errors,
        &tee_evidence,
        &bundle.platform.tee,
    );
    match (snp_trust, dcap_collateral) {
        (Some((amd, cert_table)), None) => {
            let vendor_evidence = super::TeeEvidence {
                auxiliary: Some(URL_SAFE_NO_PAD.encode(cert_table)),
                ..tee_evidence
            };
            super::verification_core::verify_gcp_snp_vendor_report(
                &mut report,
                &mut core_errors,
                Some(&vendor_evidence),
                &amd.certificates,
                &amd.keccak256_hashes,
            );
        }
        (None, Some(dcap)) => super::verification_core::verify_gcp_tdx_vendor_report(
            &mut report,
            &mut core_errors,
            Some(&tee_evidence),
            dcap,
        ),
        _ => record(
            checks,
            errors,
            "platform-attestation",
            false,
            "Azure trust input is inconsistent with the selected TEE",
        ),
    }
    import_core_checks(report, checks, errors);
}

fn azure_ak_binding(
    bundle: &SessionEvidenceBundle,
    errors: &mut Vec<String>,
) -> Option<super::AkBinding> {
    if bundle.ak_evidence.kind != "azure_maa_jwt" {
        errors.push(
            "azure-maa-jwt: Azure session verification requires ak_evidence.kind=azure_maa_jwt"
                .into(),
        );
        return None;
    }
    let collateral = decode_b64(
        &bundle.ak_evidence.collateral,
        "ak_evidence.collateral",
        errors,
    )?;
    let (jwt, hcl_var_data) = match decode_abi_bytes_pair(&collateral) {
        Ok(pair) => pair,
        Err(detail) => {
            errors.push(format!("azure-maa-jwt: {detail}"));
            return None;
        }
    };
    let jwt = match String::from_utf8(jwt) {
        Ok(jwt) => jwt,
        Err(error) => {
            errors.push(format!("azure-maa-jwt: JWT is not UTF-8: {error}"));
            return None;
        }
    };
    if let Some(auxiliary) = bundle.tee_evidence.auxiliary.as_deref() {
        let projected = decode_b64(auxiliary, "tee_evidence.auxiliary", errors)?;
        if projected != hcl_var_data {
            errors.push(
                "azure-maa-jwt: collateral HCL var_data differs from tee_evidence.auxiliary".into(),
            );
            return None;
        }
    } else {
        errors.push("azure-maa-jwt: tee_evidence.auxiliary is missing HCL var_data".into());
        return None;
    }
    let data = serde_json::to_vec(&serde_json::json!({
        "jwt": jwt,
        "hclVarData": URL_SAFE_NO_PAD.encode(&hcl_var_data),
    }))
    .expect("Azure binding JSON serialization cannot fail");
    Some(super::AkBinding {
        kind: "azure-maa-jwt".into(),
        data: URL_SAFE_NO_PAD.encode(data),
    })
}

/// Project the retained Azure MAA JWT and HCL data from a committed session
/// evidence bundle. Callers use this before selecting the exact historical
/// MAA signing key for session verification.
pub fn azure_maa_binding_from_session_bundle(
    bundle: &SessionEvidenceBundle,
) -> Result<super::AkBinding, String> {
    let mut errors = Vec::new();
    azure_ak_binding(bundle, &mut errors).ok_or_else(|| {
        if errors.is_empty() {
            "committed session has no Azure MAA binding".to_string()
        } else {
            errors.join("; ")
        }
    })
}

fn import_core_checks(
    report: super::VerificationReport,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    for check in report.checks {
        record(
            checks,
            errors,
            &check.name,
            check.result == super::CheckResult::Pass,
            check
                .detail
                .as_deref()
                .unwrap_or("shared verifier skipped a required check"),
        );
    }
}

fn decode_abi_bytes_array(encoded: &[u8]) -> std::result::Result<Vec<Vec<u8>>, String> {
    let array_start = abi_usize(encoded, 0, "bytes[] offset")?;
    if array_start != 32 {
        return Err(format!(
            "GCP AK collateral is not canonical abi.encode(bytes[]): array offset is {array_start}, expected 32"
        ));
    }
    let count = abi_usize(encoded, array_start, "bytes[] length")?;
    let heads_start = array_start
        .checked_add(32)
        .ok_or_else(|| "bytes[] head offset overflow".to_string())?;
    let heads_len = count
        .checked_mul(32)
        .ok_or_else(|| "bytes[] head length overflow".to_string())?;
    let mut cursor = heads_start
        .checked_add(heads_len)
        .ok_or_else(|| "bytes[] data offset overflow".to_string())?;
    if cursor > encoded.len() {
        return Err("GCP AK collateral bytes[] head is truncated".into());
    }

    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let head = heads_start + index * 32;
        let relative = abi_usize(encoded, head, "bytes[] element offset")?;
        let expected_relative = cursor - heads_start;
        if relative != expected_relative {
            return Err(format!(
                "GCP AK collateral bytes[] element {index} has non-canonical offset {relative}, expected {expected_relative}"
            ));
        }
        let length = abi_usize(encoded, cursor, "bytes element length")?;
        let data_start = cursor
            .checked_add(32)
            .ok_or_else(|| "bytes element data offset overflow".to_string())?;
        let data_end = data_start
            .checked_add(length)
            .ok_or_else(|| "bytes element length overflow".to_string())?;
        let value = encoded
            .get(data_start..data_end)
            .ok_or_else(|| format!("GCP AK collateral bytes[] element {index} is truncated"))?;
        values.push(value.to_vec());
        let padded = length
            .checked_add(31)
            .ok_or_else(|| "bytes element padding overflow".to_string())?
            / 32
            * 32;
        cursor = data_start
            .checked_add(padded)
            .ok_or_else(|| "bytes element end overflow".to_string())?;
        if cursor > encoded.len() {
            return Err(format!(
                "GCP AK collateral bytes[] element {index} padding is truncated"
            ));
        }
    }
    if cursor != encoded.len() {
        return Err("GCP AK collateral has trailing bytes after bytes[]".into());
    }
    Ok(values)
}

fn decode_abi_bytes_pair(encoded: &[u8]) -> std::result::Result<(Vec<u8>, Vec<u8>), String> {
    let first_offset = abi_usize(encoded, 0, "first bytes offset")?;
    let second_offset = abi_usize(encoded, 32, "second bytes offset")?;
    if first_offset != 64 {
        return Err(format!(
            "non-canonical abi.encode(bytes,bytes): first offset is {first_offset}, expected 64"
        ));
    }
    let first_length = abi_usize(encoded, first_offset, "first bytes length")?;
    let first_start = first_offset + 32;
    let first_end = first_start
        .checked_add(first_length)
        .ok_or_else(|| "first bytes length overflow".to_string())?;
    let first_padded_end = first_start
        .checked_add(first_length.div_ceil(32) * 32)
        .ok_or_else(|| "first bytes padding overflow".to_string())?;
    if second_offset != first_padded_end {
        return Err(format!(
            "non-canonical abi.encode(bytes,bytes): second offset is {second_offset}, expected {first_padded_end}"
        ));
    }
    let first = encoded
        .get(first_start..first_end)
        .ok_or_else(|| "first bytes value is truncated".to_string())?
        .to_vec();
    let second_length = abi_usize(encoded, second_offset, "second bytes length")?;
    let second_start = second_offset + 32;
    let second_end = second_start
        .checked_add(second_length)
        .ok_or_else(|| "second bytes length overflow".to_string())?;
    let canonical_end = second_start
        .checked_add(second_length.div_ceil(32) * 32)
        .ok_or_else(|| "second bytes padding overflow".to_string())?;
    if canonical_end != encoded.len() {
        return Err("abi.encode(bytes,bytes) is truncated or has trailing bytes".into());
    }
    let second = encoded
        .get(second_start..second_end)
        .ok_or_else(|| "second bytes value is truncated".to_string())?
        .to_vec();
    Ok((first, second))
}

fn abi_usize(encoded: &[u8], offset: usize, field: &str) -> std::result::Result<usize, String> {
    let word = encoded
        .get(offset..offset.saturating_add(32))
        .ok_or_else(|| format!("{field} is truncated"))?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(format!("{field} exceeds 64 bits"));
    }
    let value = u64::from_be_bytes(word[24..].try_into().expect("word slice length"));
    usize::try_from(value).map_err(|_| format!("{field} exceeds usize"))
}

fn verify_raw_quote(
    bundle: &SessionEvidenceBundle,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let quote = decode_b64(
        &bundle.tpm_quote.tpm2b_attest,
        "tpm_quote.tpm2b_attest",
        errors,
    );
    let signature = decode_b64(
        &bundle.tpm_quote.tpm_signature,
        "tpm_quote.tpm_signature",
        errors,
    );
    let qualifying = decode_hex_32(
        &bundle.binding.qualifying_data,
        "binding.qualifying_data",
        errors,
    );
    let supplied_signature_hash = decode_hex_32(
        &bundle.tpm_quote.signature_hash,
        "tpm_quote.signature_hash",
        errors,
    );
    if let (Some(signature), Some(supplied)) = (signature.as_ref(), supplied_signature_hash) {
        let actual: [u8; 32] = Keccak256::digest(signature).into();
        record(
            checks,
            errors,
            "tpm-signature-hash",
            actual == supplied,
            "TPM Quote signature hash mismatch",
        );
    }
    let (Some(quote), Some(_signature), Some(qualifying)) = (quote, signature, qualifying) else {
        return;
    };
    let pcrs = bundle
        .pcr_values
        .iter()
        .map(|pcr| super::PcrEvidence {
            index: pcr.index,
            sha256: Some(pcr.sha256.clone()),
            sha384: pcr.sha384.clone(),
        })
        .collect::<Vec<_>>();
    let mut report = super::VerificationReport {
        checks: Vec::new(),
        evidence: super::EvidenceSummary::default(),
    };
    let mut quote_errors = Vec::new();
    super::verification_core::verify_tpm_quote(
        &mut report,
        &mut quote_errors,
        &quote,
        &qualifying,
        &pcrs,
    );
    for check in report.checks {
        let valid = check.result == super::CheckResult::Pass;
        record(
            checks,
            errors,
            &check.name,
            valid,
            check.detail.as_deref().unwrap_or(""),
        );
    }
}

fn verify_quote_projection(
    bundle: &SessionEvidenceBundle,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let pcr_indices = bundle
        .pcr_values
        .iter()
        .map(|pcr| pcr.index)
        .collect::<Vec<_>>();
    let event_indices = bundle
        .event_log_hashes
        .iter()
        .map(|events| events.pcr_index)
        .collect::<Vec<_>>();
    record(
        checks,
        errors,
        "event-log-pcr-projection",
        event_indices == pcr_indices,
        "event_log_hashes must contain exactly one entry for every quoted PCR, in Quote order",
    );
    record(
        checks,
        errors,
        "pcr-bank-projection",
        bundle.pcr_values.iter().all(|pcr| pcr.sha384.is_none()),
        "session Quote projection currently supports only the SHA-256 PCR bank",
    );
}

fn verify_raw_certify(
    bundle: &SessionEvidenceBundle,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let attest = decode_b64(
        &bundle.tpm_certify.tpm2b_attest,
        "tpm_certify.tpm2b_attest",
        errors,
    );
    let signature = decode_b64(
        &bundle.tpm_certify.tpm_signature,
        "tpm_certify.tpm_signature",
        errors,
    );
    let tpmt_public = decode_b64(
        &bundle.tpm_certify.tpmt_public,
        "tpm_certify.tpmt_public",
        errors,
    );
    let ak_public = decode_b64(
        &bundle.ak_evidence.ak_public,
        "ak_evidence.ak_public",
        errors,
    );
    let (Some(attest), Some(signature), Some(tpmt_public)) = (attest, signature, tpmt_public)
    else {
        return;
    };
    let body = match super::verification_core::tpm2b_attest_body(&attest) {
        Ok(body) => body,
        Err(detail) => {
            record(checks, errors, "tpm-certify-structure", false, &detail);
            return;
        }
    };
    let certified_name = match parse_certified_name(body) {
        Ok(name) => {
            record(checks, errors, "tpm-certify-structure", true, "");
            name
        }
        Err(detail) => {
            record(checks, errors, "tpm-certify-structure", false, &detail);
            return;
        }
    };
    let expected_name = match tpmt_public_name(&tpmt_public) {
        Ok(name) => name,
        Err(detail) => {
            record(checks, errors, "tpm-certify-name", false, &detail);
            return;
        }
    };
    record(
        checks,
        errors,
        "tpm-certify-name",
        certified_name == expected_name,
        "TPM Certify name does not bind the supplied TPMT_PUBLIC",
    );
    verify_tpmt_public_attributes(&tpmt_public, checks, errors);

    verify_certified_delegation_key(
        &tpmt_public,
        &bundle.session_key_delegation.tpm_signing_key.bytes,
        checks,
        errors,
    );

    if bundle.ak_evidence.kind == "azure_maa_jwt" {
        let Some(binding) = azure_ak_binding(bundle, errors) else {
            return;
        };
        let mut report = super::VerificationReport {
            checks: Vec::new(),
            evidence: super::EvidenceSummary::default(),
        };
        let mut core_errors = Vec::new();
        super::verification_core::verify_azure_hclak_certify_signature(
            &mut report,
            &mut core_errors,
            &binding,
            &attest,
            &signature,
        );
        import_core_checks(report, checks, errors);
    } else {
        let Some(ak_public) = ak_public else {
            return;
        };
        let valid = super::verification_core::parse_tpmt_public_ecc_p256(&ak_public)
            .ok()
            .zip(super::verification_core::parse_tpmt_signature_ecdsa_sha256(&signature).ok())
            .is_some_and(|(key, signature)| key.verify(body, &signature).is_ok());
        record(
            checks,
            errors,
            "tpm-certify-signature",
            valid,
            "TPM Certify signature did not verify under the AK",
        );
    }
}

fn verify_certified_delegation_key(
    tpmt_public: &[u8],
    delegation_key_hex: &str,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let certified_key = match super::verification_core::parse_tpmt_public_ecc_p256(tpmt_public) {
        Ok(key) => key,
        Err(detail) => {
            record(
                checks,
                errors,
                "tpm-certify-public-key",
                false,
                &format!("certified TPMT_PUBLIC is not an ECC P-256 key: {detail}"),
            );
            return;
        }
    };
    let Some(delegation_key) = decode_hex(
        delegation_key_hex,
        "session_key_delegation.tpm_signing_key.bytes",
        errors,
    ) else {
        record(
            checks,
            errors,
            "tpm-certify-public-key",
            false,
            "delegation signing key is malformed",
        );
        return;
    };
    let projected = certified_key.to_encoded_point(false);
    record(
        checks,
        errors,
        "tpm-certify-public-key",
        projected.as_bytes() == delegation_key,
        "certified TPMT_PUBLIC differs from the delegation signing key",
    );
}

fn verify_tpmt_public_attributes(
    tpmt_public: &[u8],
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    const REQUIRED_SET: u32 = 0x0004_0072;
    const REQUIRED_CLEAR: u32 = 0xfffb_fb8d;
    let Some(bytes) = tpmt_public.get(4..8) else {
        record(
            checks,
            errors,
            "tpm-certify-object-attributes",
            false,
            "TPMT_PUBLIC is too short for objectAttributes",
        );
        return;
    };
    let attributes = u32::from_be_bytes(bytes.try_into().expect("attribute slice length"));
    let required_present = attributes & REQUIRED_SET == REQUIRED_SET;
    let forbidden_clear = attributes & REQUIRED_CLEAR == 0;
    record(
        checks,
        errors,
        "tpm-certify-object-attributes",
        required_present && forbidden_clear,
        &format!(
            "TPMT_PUBLIC objectAttributes 0x{attributes:08x} must set 0x{REQUIRED_SET:08x} and clear 0x{REQUIRED_CLEAR:08x}"
        ),
    );
}

fn parse_certified_name(body: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut reader = super::verification_core::ByteReader::new(body);
    if reader.read_u32("certify.magic")? != 0xff54_4347 {
        return Err("TPM Certify magic is invalid".into());
    }
    if reader.read_u16("certify.type")? != 0x8017 {
        return Err("TPMS_ATTEST is not a Certify attestation".into());
    }
    reader.read_tpm2b("certify.qualifiedSigner")?;
    reader.read_tpm2b("certify.extraData")?;
    reader.read_exact("certify.clockInfo", 17)?;
    reader.read_exact("certify.firmwareVersion", 8)?;
    let name = reader.read_tpm2b("certify.name")?.to_vec();
    reader.read_tpm2b("certify.qualifiedName")?;
    if !reader.is_empty() {
        return Err(format!(
            "TPM Certify has {} trailing bytes",
            reader.remaining()
        ));
    }
    Ok(name)
}

fn tpmt_public_name(tpmt_public: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if tpmt_public.len() < 4 {
        return Err("TPMT_PUBLIC is too short for type and nameAlg".into());
    }
    let name_alg = u16::from_be_bytes([tpmt_public[2], tpmt_public[3]]);
    if name_alg != 0x000b {
        return Err(format!(
            "TPMT_PUBLIC nameAlg 0x{name_alg:04x} is not SHA-256"
        ));
    }
    let mut name = Vec::with_capacity(34);
    name.extend_from_slice(&name_alg.to_be_bytes());
    name.extend_from_slice(&Sha256::digest(tpmt_public));
    Ok(name)
}

fn verify_delegation(
    bundle: &SessionEvidenceBundle,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let signing_key = decode_hex(
        &bundle.session_key_delegation.tpm_signing_key.bytes,
        "session_key_delegation.tpm_signing_key.bytes",
        errors,
    );
    let signing_fingerprint = decode_hex_32(
        &bundle.session_key_delegation.tpm_signing_key.fingerprint,
        "session_key_delegation.tpm_signing_key.fingerprint",
        errors,
    );
    if let (Some(key), Some(expected)) = (signing_key.as_ref(), signing_fingerprint) {
        let actual =
            compute_key_fingerprint(bundle.session_key_delegation.tpm_signing_key.type_id, key);
        record(
            checks,
            errors,
            "tpm-signing-key-fingerprint",
            actual == expected,
            "certified TPM signing-key fingerprint mismatch",
        );
    }
    let supplied_digest = decode_hex_32(
        &bundle.session_key_delegation.digest,
        "session_key_delegation.digest",
        errors,
    );
    let registry = decode_address(&bundle.binding.registry, "binding.registry", errors);
    let base_image = decode_hex_32(&bundle.policy.base_image_id, "policy.base_image_id", errors);
    let workload = decode_hex_32(&bundle.policy.workload_id, "policy.workload_id", errors);
    let session = decode_hex_32(&bundle.session_id, "session_id", errors);
    let session_key_fp = decode_hex_32(
        &bundle.session_key.fingerprint,
        "session_key.fingerprint",
        errors,
    );
    if let (
        Some(supplied),
        Some(registry),
        Some(base_image),
        Some(workload),
        Some(session),
        Some(session_key_fp),
    ) = (
        supplied_digest,
        registry,
        base_image,
        workload,
        session,
        session_key_fp,
    ) {
        let expected = delegation_digest(
            bundle.binding.chain_id,
            registry,
            base_image,
            workload,
            session,
            session_key_fp,
        );
        record(
            checks,
            errors,
            "session-key-delegation-digest",
            expected == supplied,
            "session-key delegation digest mismatch",
        );
        let signature = decode_hex(
            &bundle.session_key_delegation.signature,
            "session_key_delegation.signature",
            errors,
        );
        if let (Some(key), Some(signature)) = (signing_key, signature) {
            let valid = P256VerifyingKey::from_sec1_bytes(&key)
                .ok()
                .zip(P256Signature::from_der(&signature).ok())
                .is_some_and(|(key, signature)| key.verify_prehash(&expected, &signature).is_ok());
            record(
                checks,
                errors,
                "session-key-delegation-signature",
                valid,
                "session-key delegation signature mismatch",
            );
        }
    }
}

fn delegation_digest(
    chain_id: u64,
    registry: [u8; 20],
    base_image: [u8; 32],
    workload: [u8; 32],
    session: [u8; 32],
    session_key_fingerprint: [u8; 32],
) -> [u8; 32] {
    let mut encoded = [0u8; 224];
    encoded[..32].copy_from_slice(&keccak(DELEGATION_DOMAIN.as_bytes()));
    encoded[56..64].copy_from_slice(&chain_id.to_be_bytes());
    encoded[76..96].copy_from_slice(&registry);
    encoded[96..128].copy_from_slice(&base_image);
    encoded[128..160].copy_from_slice(&workload);
    encoded[160..192].copy_from_slice(&session);
    encoded[192..].copy_from_slice(&session_key_fingerprint);
    keccak(&encoded)
}

pub fn evaluate_session_pcr_policy(
    policy: &SessionPcrPolicy,
    measured_value: [u8; 32],
    measured_events: &[[u8; 32]],
) -> std::result::Result<(), String> {
    super::verification_core::evaluate_pcr_policy(policy, measured_value, measured_events)
}
fn verify_binding(
    bundle: &SessionEvidenceBundle,
    trusted: Option<&TrustedSessionBinding>,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) -> Option<[u8; 20]> {
    let registry = decode_address(&bundle.binding.registry, "binding.registry", errors);
    let owner = decode_hex_32(&bundle.owner.fingerprint, "owner.fingerprint", errors);
    let nonce = decode_hex_32(&bundle.binding.owner_nonce, "binding.owner_nonce", errors);
    let qualifying = decode_hex_32(
        &bundle.binding.qualifying_data,
        "binding.qualifying_data",
        errors,
    );
    if let (Some(registry), Some(owner), Some(nonce), Some(qualifying)) =
        (registry, owner, nonce, qualifying)
    {
        let expected =
            compute_session_qualifying_data(bundle.binding.chain_id, registry, owner, nonce);
        record(
            checks,
            errors,
            "binding-qualifying-data",
            expected == qualifying,
            "qualifying data mismatch",
        );
        let zero_registry = registry == [0u8; 20];
        let shape = match bundle.binding.mode {
            BindingMode::Chain => bundle.binding.chain_id != 0 && !zero_registry,
            BindingMode::Local => bundle.binding.chain_id == 0 && zero_registry,
        };
        record(
            checks,
            errors,
            "binding-mode",
            shape,
            "binding mode does not match chain ID and registry",
        );
        verify_trusted_binding(
            bundle.binding.mode,
            bundle.binding.chain_id,
            registry,
            trusted,
            checks,
            errors,
        );
    }
    registry
}

fn verify_trusted_binding(
    mode: BindingMode,
    chain_id: u64,
    registry: [u8; 20],
    trusted: Option<&TrustedSessionBinding>,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let Some(trusted) = trusted.filter(|_| mode == BindingMode::Chain) else {
        return;
    };
    record(
        checks,
        errors,
        "trusted-binding-chain-id",
        chain_id == trusted.chain_id,
        "authenticated session chain ID differs from the verifier-selected chain",
    );
    record(
        checks,
        errors,
        "trusted-binding-registry",
        registry == trusted.registry,
        "authenticated session registry differs from the verifier-selected SessionRegistry",
    );
}

fn verify_policies(
    bundle: &SessionEvidenceBundle,
    trusted: &TrustedSessionPolicy,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    verify_policy_id(
        "workload-id",
        &bundle.policy.workload_id,
        trusted.workload_id,
        checks,
        errors,
    );
    verify_policy_id(
        "base-image-id",
        &bundle.policy.base_image_id,
        trusted.base_image_id,
        checks,
        errors,
    );
    verify_policy_id(
        "platform-profile-id",
        &bundle.policy.platform_profile_id,
        trusted.platform_profile_id,
        checks,
        errors,
    );
    verify_policy_id(
        "measurement-variant-id",
        &bundle.policy.measurement_variant_id,
        trusted.measurement_variant_id,
        checks,
        errors,
    );
    record(
        checks,
        errors,
        "trusted-pcr-policy-projection",
        bundle.policy.pcr_specs.is_empty() || bundle.policy.pcr_specs == trusted.pcr_specs,
        "non-empty bundle PCR policy projection differs from the caller-supplied trusted policy",
    );
    if trusted.pcr_specs.is_empty() {
        record(
            checks,
            errors,
            "trusted-pcr-policy",
            false,
            "caller-supplied trusted PCR policy is empty",
        );
        return;
    }

    for policy in &trusted.pcr_specs {
        let name = format!("pcr-policy-{}", policy.pcr_index);
        let Some(value) = bundle
            .pcr_values
            .iter()
            .find(|value| value.index == policy.pcr_index)
        else {
            record(checks, errors, &name, false, "PCR value is absent");
            continue;
        };
        let Some(measured) = decode_hex_32(&value.sha256, "pcr_values.sha256", errors) else {
            continue;
        };
        let events = bundle
            .event_log_hashes
            .iter()
            .find(|events| events.pcr_index == policy.pcr_index)
            .map(|events| {
                events
                    .sha256
                    .iter()
                    .map(|event| decode_hex_array(event))
                    .collect::<std::result::Result<Vec<_>, _>>()
            })
            .transpose();
        match events {
            Ok(events) => match evaluate_session_pcr_policy(
                policy,
                measured,
                events.as_deref().unwrap_or_default(),
            ) {
                Ok(()) => record(checks, errors, &name, true, ""),
                Err(detail) => record(checks, errors, &name, false, &detail),
            },
            Err(detail) => record(checks, errors, &name, false, &detail),
        }
    }
    verify_attribute_policy(trusted, checks, errors);
}

fn verify_attribute_policy(
    trusted: &TrustedSessionPolicy,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let attributes_unique = trusted
        .effective_attributes
        .iter()
        .enumerate()
        .all(|(index, item)| {
            !trusted.effective_attributes[index + 1..]
                .iter()
                .any(|other| other.key == item.key)
        });
    record(
        checks,
        errors,
        "trusted-effective-attribute-keys",
        attributes_unique,
        "caller-supplied effective attributes contain duplicate keys",
    );
    let requirements_unique =
        trusted
            .attribute_requirements
            .iter()
            .enumerate()
            .all(|(index, item)| {
                !trusted.attribute_requirements[index + 1..]
                    .iter()
                    .any(|other| other.key == item.key)
            });
    record(
        checks,
        errors,
        "trusted-attribute-requirement-keys",
        requirements_unique,
        "caller-supplied attribute requirements contain duplicate keys",
    );
    for (index, requirement) in trusted.attribute_requirements.iter().enumerate() {
        let name = format!("attribute-requirement-{index}");
        let Some(attribute) = trusted
            .effective_attributes
            .iter()
            .find(|attribute| attribute.key == requirement.key)
        else {
            record(
                checks,
                errors,
                &name,
                false,
                &format!(
                    "required attribute 0x{} is absent",
                    hex::encode(requirement.key)
                ),
            );
            continue;
        };
        let valid = requirement.allowed_values.is_empty()
            || requirement.allowed_values.contains(&attribute.value);
        record(
            checks,
            errors,
            &name,
            valid,
            &format!(
                "attribute 0x{} value 0x{} is not allowed",
                hex::encode(requirement.key),
                hex::encode(attribute.value)
            ),
        );
    }
}

fn verify_policy_id(
    name: &str,
    bundle_value: &str,
    trusted_value: [u8; 32],
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let Some(bundle_value) = decode_hex_32(bundle_value, "policy identifier", errors) else {
        return;
    };
    record(
        checks,
        errors,
        name,
        bundle_value == trusted_value,
        "bundle policy identifier differs from the caller-supplied trusted policy",
    );
}

fn verify_request_binding(
    bundle: &SessionEvidenceBundle,
    signed_bundle: &serde_json::Value,
    binding: &SessionRequestBinding,
    expected_challenge: [u8; 32],
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let challenge = decode_b64(&binding.challenge, "request_binding.challenge", errors)
        .and_then(|bytes| bytes.try_into().ok());
    if let Some(challenge) = challenge {
        record(
            checks,
            errors,
            "request-challenge",
            challenge == expected_challenge,
            "response challenge differs from the verifier-generated challenge",
        );
    }
    let public_key = decode_hex(&bundle.session_key.bytes, "session_key.bytes", errors);
    let signature = decode_hex(&binding.signature, "request_binding.signature", errors);
    let canonical = serde_json_canonicalizer::to_vec(signed_bundle);
    match (challenge, public_key, signature, canonical) {
        (Some(challenge), Some(public_key), Some(signature), Ok(canonical)) => {
            let digest = request_binding_digest(EVIDENCE_BINDING_DOMAIN, challenge, &canonical);
            let valid = recoverable_es256k_signature_matches(&public_key, digest, &signature);
            record(
                checks,
                errors,
                "request-binding",
                valid,
                "request-binding signature mismatch",
            );
        }
        (_, _, _, Err(error)) => record(
            checks,
            errors,
            "request-binding",
            false,
            &format!("JCS canonicalization: {error}"),
        ),
        _ => record(
            checks,
            errors,
            "request-binding",
            false,
            "request binding input is malformed",
        ),
    }
}

pub fn request_binding_digest(domain: &str, challenge: [u8; 32], jcs: &[u8]) -> [u8; 32] {
    let mut encoded = [0u8; 96];
    encoded[..32].copy_from_slice(&keccak(domain.as_bytes()));
    encoded[32..64].copy_from_slice(&challenge);
    encoded[64..].copy_from_slice(&Sha256::digest(jcs));
    Sha256::digest(encoded).into()
}

pub fn chain_submission_request_binding_digest(challenge: [u8; 32], jcs: &[u8]) -> [u8; 32] {
    request_binding_digest(CHAIN_SUBMISSION_BINDING_DOMAIN, challenge, jcs)
}

pub fn compute_session_id(tpm_signature_hash: [u8; 32], tee_hash: [u8; 32]) -> [u8; 32] {
    let mut encoded = [0u8; 96];
    encoded[..32].copy_from_slice(&keccak(SESSION_DOMAIN.as_bytes()));
    encoded[32..64].copy_from_slice(&tpm_signature_hash);
    encoded[64..].copy_from_slice(&tee_hash);
    keccak(&encoded)
}

pub fn compute_key_fingerprint(type_id: u8, key: &[u8]) -> [u8; 32] {
    let padded = key.len().div_ceil(32) * 32;
    let mut encoded = vec![0u8; 128 + padded];
    encoded[..32].copy_from_slice(&keccak(KEY_DOMAIN.as_bytes()));
    encoded[63] = type_id;
    encoded[95] = 96;
    encoded[112..128].copy_from_slice(&(key.len() as u128).to_be_bytes());
    encoded[128..128 + key.len()].copy_from_slice(key);
    keccak(&encoded)
}

pub fn compute_session_qualifying_data(
    chain_id: u64,
    registry: [u8; 20],
    owner_fingerprint: [u8; 32],
    nonce: [u8; 32],
) -> [u8; 32] {
    let mut encoded = [0u8; 160];
    encoded[..32].copy_from_slice(&keccak(SESSION_NONCE_DOMAIN.as_bytes()));
    encoded[56..64].copy_from_slice(&chain_id.to_be_bytes());
    encoded[76..96].copy_from_slice(&registry);
    encoded[96..128].copy_from_slice(&owner_fingerprint);
    encoded[128..].copy_from_slice(&nonce);
    keccak(&encoded)
}

/// Verify a 65-byte recoverable ES256K signature against a SEC1 public key.
///
/// The signature is `r || s || v`. The recovery byte may use either `0/1`
/// or Ethereum's legacy `27/28` form.
pub fn recoverable_es256k_signature_matches(
    public_key: &[u8],
    digest: [u8; 32],
    bytes: &[u8],
) -> bool {
    if bytes.len() != 65 {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&bytes[..64]) else {
        return false;
    };
    let recovery = match bytes[64] {
        0 | 1 => bytes[64],
        27 | 28 => bytes[64] - 27,
        _ => return false,
    };
    let Some(recovery) = RecoveryId::from_byte(recovery) else {
        return false;
    };
    let Ok(recovered) = VerifyingKey::recover_from_prehash(&digest, &signature, recovery) else {
        return false;
    };
    VerifyingKey::from_sec1_bytes(public_key)
        .map(|expected| expected == recovered)
        .unwrap_or(false)
}

fn record(
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
    name: &str,
    valid: bool,
    detail: &str,
) {
    checks.push(SessionVerificationCheck {
        name: name.into(),
        valid,
        detail: (!detail.is_empty()).then(|| detail.into()),
    });
    if !valid {
        errors.push(format!("{name}: {detail}"));
    }
}

fn decode_b64(value: &str, field: &str, errors: &mut Vec<String>) -> Option<Vec<u8>> {
    if value.contains('=') {
        errors.push(format!("{field}: base64url padding is not allowed"));
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| {
            errors.push(format!("{field}: {error}"));
        })
        .ok()
}

fn decode_hex(value: &str, field: &str, errors: &mut Vec<String>) -> Option<Vec<u8>> {
    let Some(raw) = value.strip_prefix("0x") else {
        errors.push(format!("{field}: missing 0x prefix"));
        return None;
    };
    hex::decode(raw)
        .map_err(|error| errors.push(format!("{field}: {error}")))
        .ok()
}

fn decode_hex_32(value: &str, field: &str, errors: &mut Vec<String>) -> Option<[u8; 32]> {
    decode_hex(value, field, errors).and_then(|bytes| match <[u8; 32]>::try_from(bytes) {
        Ok(bytes) => Some(bytes),
        Err(bytes) => {
            errors.push(format!("{field}: expected 32 bytes, got {}", bytes.len()));
            None
        }
    })
}

fn decode_address(value: &str, field: &str, errors: &mut Vec<String>) -> Option<[u8; 20]> {
    decode_hex(value, field, errors).and_then(|bytes| match <[u8; 20]>::try_from(bytes) {
        Ok(bytes) => Some(bytes),
        Err(bytes) => {
            errors.push(format!("{field}: expected 20 bytes, got {}", bytes.len()));
            None
        }
    })
}

fn decode_hex_array(value: &str) -> Result<[u8; 32], String> {
    let raw = value.strip_prefix("0x").ok_or("missing 0x prefix")?;
    let bytes = hex::decode(raw).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, got {}", bytes.len()))
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_binding_must_match_verifier_selected_coordinates() {
        let trusted = TrustedSessionBinding {
            chain_id: 11_155_111,
            registry: [0x11; 20],
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_trusted_binding(
            BindingMode::Chain,
            1,
            [0x22; 20],
            Some(&trusted),
            &mut checks,
            &mut errors,
        );
        assert_eq!(errors.len(), 2);
        assert!(checks
            .iter()
            .any(|check| { check.name == "trusted-binding-chain-id" && !check.valid }));
        assert!(checks
            .iter()
            .any(|check| { check.name == "trusted-binding-registry" && !check.valid }));

        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_trusted_binding(
            BindingMode::Chain,
            trusted.chain_id,
            trusted.registry,
            Some(&trusted),
            &mut checks,
            &mut errors,
        );
        assert!(errors.is_empty());
        assert_eq!(checks.len(), 2);
        assert!(checks.iter().all(|check| check.valid));
    }

    #[test]
    fn verifier_selected_chain_does_not_require_chain_binding() {
        let trusted = TrustedSessionBinding {
            chain_id: 11_155_111,
            registry: [0x11; 20],
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_trusted_binding(
            BindingMode::Local,
            0,
            [0; 20],
            Some(&trusted),
            &mut checks,
            &mut errors,
        );
        assert!(checks.is_empty());
        assert!(errors.is_empty());
    }

    fn word(value: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&(value as u64).to_be_bytes());
        out
    }

    fn encode_bytes_array(values: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&word(32));
        out.extend_from_slice(&word(values.len()));
        let mut relative = values.len() * 32;
        for value in values {
            out.extend_from_slice(&word(relative));
            relative += 32 + value.len().div_ceil(32) * 32;
        }
        for value in values {
            out.extend_from_slice(&word(value.len()));
            out.extend_from_slice(value);
            out.resize(out.len() + (32 - value.len() % 32) % 32, 0);
        }
        out
    }

    fn encode_bytes_pair(first: &[u8], second: &[u8]) -> Vec<u8> {
        let second_offset = 64 + 32 + first.len().div_ceil(32) * 32;
        let mut out = Vec::new();
        out.extend_from_slice(&word(64));
        out.extend_from_slice(&word(second_offset));
        for value in [first, second] {
            out.extend_from_slice(&word(value.len()));
            out.extend_from_slice(value);
            out.resize(out.len() + (32 - value.len() % 32) % 32, 0);
        }
        out
    }

    fn bundle_for_policy(policy: SessionPolicy) -> SessionEvidenceBundle {
        SessionEvidenceBundle {
            format: 1,
            binding: SessionBinding {
                mode: BindingMode::Local,
                chain_id: 0,
                registry: format!("0x{}", "00".repeat(20)),
                owner_nonce: format!("0x{}", "00".repeat(32)),
                qualifying_data: format!("0x{}", "00".repeat(32)),
            },
            platform: SessionPlatform {
                cloud: "qemu".into(),
                attestation_mode: SessionAttestationMode::Emulation,
                tee: "emulation".into(),
                machine_type: "qemu".into(),
            },
            tee_evidence: RawEvidence {
                kind: "emulation".into(),
                report: String::new(),
                auxiliary: None,
            },
            ak_evidence: AkEvidence {
                kind: "emulation".into(),
                ak_public: String::new(),
                collateral: String::new(),
            },
            tpm_quote: TpmQuoteEvidence {
                tpm2b_attest: String::new(),
                tpm_signature: String::new(),
                signature_hash: format!("0x{}", "00".repeat(32)),
            },
            tpm_certify: TpmCertifyEvidence {
                tpm2b_attest: String::new(),
                tpm_signature: String::new(),
                tpmt_public: String::new(),
            },
            pcr_values: vec![SessionPcrValue {
                index: 7,
                sha256: format!("0x{}", "11".repeat(32)),
                sha384: None,
            }],
            event_log_hashes: Vec::new(),
            session_key: SessionPublicKey {
                type_id: 3,
                bytes: "0x".into(),
                fingerprint: format!("0x{}", "00".repeat(32)),
            },
            session_key_delegation: SessionKeyDelegation {
                tpm_signing_key: SessionPublicKey {
                    type_id: 0,
                    bytes: String::new(),
                    fingerprint: format!("0x{}", "00".repeat(32)),
                },
                digest: format!("0x{}", "00".repeat(32)),
                signature: String::new(),
            },
            session_id: format!("0x{}", "00".repeat(32)),
            policy,
            owner: SessionOwner {
                fingerprint: format!("0x{}", "00".repeat(32)),
                contract_authorization: None,
            },
        }
    }

    fn replay(events: &[[u8; 32]]) -> [u8; 32] {
        let mut value = [0u8; 32];
        for event in events {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(&value);
            input[32..].copy_from_slice(event);
            value = Sha256::digest(input).into();
        }
        value
    }

    #[test]
    fn all_policy_modes_and_ordered_landmarks() {
        let events = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let final_value = replay(&events);
        let hex = |value: [u8; 32]| format!("0x{}", hex::encode(value));

        let static_policy = SessionPcrPolicy {
            pcr_index: 0,
            verify_type: SessionPcrVerifyType::Static,
            match_data: vec![hex(final_value)],
        };
        evaluate_session_pcr_policy(&static_policy, final_value, &events).unwrap();

        let subset = SessionPcrPolicy {
            pcr_index: 10,
            verify_type: SessionPcrVerifyType::DynamicSubset,
            match_data: vec![hex(events[2]), hex(events[0])],
        };
        evaluate_session_pcr_policy(&subset, final_value, &events).unwrap();
        let empty_subset = SessionPcrPolicy {
            match_data: Vec::new(),
            ..subset.clone()
        };
        assert_eq!(
            evaluate_session_pcr_policy(&empty_subset, final_value, &events).unwrap_err(),
            "DYNAMIC_SUBSET policy has no required landmarks"
        );
        let missing_subset = SessionPcrPolicy {
            match_data: vec![hex(events[0]), hex([4u8; 32])],
            ..subset
        };
        assert_eq!(
            evaluate_session_pcr_policy(&missing_subset, final_value, &events).unwrap_err(),
            "DYNAMIC_SUBSET required landmark 1 is missing"
        );

        let subsequence = SessionPcrPolicy {
            pcr_index: 10,
            verify_type: SessionPcrVerifyType::DynamicSubsequence,
            match_data: vec![hex(events[0]), hex(events[2])],
        };
        evaluate_session_pcr_policy(&subsequence, final_value, &events).unwrap();
        let empty_subsequence = SessionPcrPolicy {
            match_data: Vec::new(),
            ..subsequence.clone()
        };
        assert_eq!(
            evaluate_session_pcr_policy(&empty_subsequence, final_value, &events).unwrap_err(),
            "DYNAMIC_SUBSEQUENCE policy has no required landmarks"
        );
        let reversed = SessionPcrPolicy {
            match_data: vec![hex(events[2]), hex(events[0])],
            ..subsequence
        };
        assert!(evaluate_session_pcr_policy(&reversed, final_value, &events).is_err());
    }

    #[test]
    fn gcp_cert_chain_collateral_decodes_canonical_abi_bytes_array() {
        let encoded = encode_bytes_array(&[b"leaf", b"root"]);
        assert_eq!(
            decode_abi_bytes_array(&encoded).unwrap(),
            vec![b"leaf".to_vec(), b"root".to_vec()]
        );

        let mut noncanonical = encoded;
        noncanonical[95] += 32;
        assert!(decode_abi_bytes_array(&noncanonical)
            .unwrap_err()
            .contains("non-canonical offset"));
    }

    #[test]
    fn azure_collateral_decodes_canonical_abi_bytes_pair() {
        let encoded = encode_bytes_pair(b"jwt", b"hcl-var-data");
        assert_eq!(
            decode_abi_bytes_pair(&encoded).unwrap(),
            (b"jwt".to_vec(), b"hcl-var-data".to_vec())
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_abi_bytes_pair(&trailing).is_err());
    }

    #[test]
    fn trusted_policy_must_match_bundle_projection_and_drives_evaluation() {
        let pcr = SessionPcrPolicy {
            pcr_index: 7,
            verify_type: SessionPcrVerifyType::Static,
            match_data: vec![format!("0x{}", "11".repeat(32))],
        };
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_specs: vec![pcr.clone()],
        };
        let bundle = bundle_for_policy(policy);
        let trusted = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_specs: vec![pcr],
            effective_attributes: vec![SessionAttribute {
                key: [0x10; 32],
                value: [0x20; 32],
            }],
            attribute_requirements: vec![SessionAttributeRequirement {
                key: [0x10; 32],
                allowed_values: vec![[0x20; 32]],
            }],
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(&bundle, &trusted, &mut checks, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");

        let untrusted = TrustedSessionPolicy {
            workload_id: [9; 32],
            ..trusted.clone()
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(&bundle, &untrusted, &mut checks, &mut errors);
        assert!(errors.iter().any(|error| error.starts_with("workload-id:")));

        let invalid_attribute = TrustedSessionPolicy {
            workload_id: [1; 32],
            effective_attributes: vec![SessionAttribute {
                key: [0x10; 32],
                value: [0x21; 32],
            }],
            ..untrusted.clone()
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(&bundle, &invalid_attribute, &mut checks, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.starts_with("attribute-requirement-0:")));

        let duplicate_attributes = TrustedSessionPolicy {
            effective_attributes: vec![
                SessionAttribute {
                    key: [0x10; 32],
                    value: [0x20; 32],
                },
                SessionAttribute {
                    key: [0x10; 32],
                    value: [0x21; 32],
                },
            ],
            ..trusted
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(&bundle, &duplicate_attributes, &mut checks, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.starts_with("trusted-effective-attribute-keys:")));
    }

    #[test]
    fn certify_object_attributes_match_contract_masks() {
        let mut public = vec![0u8; 8];
        public[4..8].copy_from_slice(&0x0004_0072u32.to_be_bytes());
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_tpmt_public_attributes(&public, &mut checks, &mut errors);
        assert!(errors.is_empty());

        public[4..8].copy_from_slice(&0x0004_0076u32.to_be_bytes());
        verify_tpmt_public_attributes(&public, &mut checks, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.starts_with("tpm-certify-object-attributes:")));
    }

    #[test]
    fn unsupported_or_malformed_certified_public_key_fails_closed() {
        for tpmt_public in [vec![0x00, 0x01], vec![0x00, 0x23]] {
            let mut checks = Vec::new();
            let mut errors = Vec::new();

            verify_certified_delegation_key(
                &tpmt_public,
                &format!("0x04{}", "11".repeat(64)),
                &mut checks,
                &mut errors,
            );

            let check = checks
                .iter()
                .find(|check| check.name == "tpm-certify-public-key")
                .expect("the certified public-key check must never be skipped");
            assert!(!check.valid);
            assert!(errors
                .iter()
                .any(|error| error.starts_with("tpm-certify-public-key:")));
        }
    }

    #[test]
    fn gcp_session_path_fails_when_typed_roots_are_empty() {
        let mut bundle = bundle_for_policy(SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_specs: Vec::new(),
        });
        bundle.platform.cloud = "gcp".into();
        bundle.platform.tee = "sev-snp".into();
        bundle.ak_evidence.kind = "gcp_cert_chain".into();
        bundle.ak_evidence.collateral =
            URL_SAFE_NO_PAD.encode(encode_bytes_array(&[b"leaf", b"root"]));
        bundle.tee_evidence.kind = "legacy_sev".into();
        bundle.tee_evidence.auxiliary = Some(String::new());

        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_gcp_platform(
            &bundle,
            &CertificateTrust::default(),
            Some(&CertificateTrust::default()),
            None,
            &mut checks,
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("no trusted GCP AK root certificates or root hashes configured")
        }));
        assert!(errors.iter().any(|error| {
            error.contains("no trusted AMD SEV-SNP ARK root certificates or root hashes configured")
        }));
    }

    #[test]
    fn local_binding_does_not_bypass_missing_hardware_evidence() {
        let bundle = bundle_for_policy(SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_specs: Vec::new(),
        });
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_production_evidence_kind(&bundle, &mut checks, &mut errors);
        verify_raw_quote(&bundle, &mut checks, &mut errors);
        verify_raw_certify(&bundle, &mut checks, &mut errors);
        verify_delegation(&bundle, &mut checks, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.starts_with("production-evidence:")));
        assert!(errors
            .iter()
            .any(|error| error.starts_with("tpm-quote-structure:")));
        assert!(errors
            .iter()
            .any(|error| error.starts_with("tpm-certify-structure:")));
        assert!(errors.iter().any(|error| error.contains("tpm_signing_key")));
    }

    #[test]
    fn chain_submission_binding_matches_cross_language_vector() {
        let challenge: [u8; 32] = std::array::from_fn(|index| index as u8);
        let jcs = br#"{"chain_id":1,"data":"0x1234","op_expires_at":1700000300,"session_id":"0x3333333333333333333333333333333333333333333333333333333333333333","to":"0x1111111111111111111111111111111111111111","value":"0x0"}"#;
        assert_eq!(
            hex::encode(chain_submission_request_binding_digest(challenge, jcs)),
            "1d60f0fda5b471ba8f1c5f57edacabbb4ebf2040f67c711bf04c4f595a719b4f"
        );
    }

    #[test]
    fn certify_name_binds_complete_tpmt_public() {
        let tpmt_public = [0x00, 0x23, 0x00, 0x0b, 0xaa, 0xbb, 0xcc];
        let expected_name = tpmt_public_name(&tpmt_public).unwrap();
        let mut attest = Vec::new();
        attest.extend_from_slice(&0xff54_4347u32.to_be_bytes());
        attest.extend_from_slice(&0x8017u16.to_be_bytes());
        attest.extend_from_slice(&0u16.to_be_bytes());
        attest.extend_from_slice(&0u16.to_be_bytes());
        attest.extend_from_slice(&[0u8; 17]);
        attest.extend_from_slice(&[0u8; 8]);
        attest.extend_from_slice(&(expected_name.len() as u16).to_be_bytes());
        attest.extend_from_slice(&expected_name);
        attest.extend_from_slice(&0u16.to_be_bytes());

        assert_eq!(parse_certified_name(&attest).unwrap(), expected_name);
        let last = attest.len() - 3;
        attest[last] ^= 1;
        assert_ne!(parse_certified_name(&attest).unwrap(), expected_name);
    }

    #[test]
    fn certify_parser_rejects_quote_attestation_type() {
        let mut attest = Vec::new();
        attest.extend_from_slice(&0xff54_4347u32.to_be_bytes());
        attest.extend_from_slice(&0x8018u16.to_be_bytes());
        assert!(parse_certified_name(&attest).is_err());
    }
}
