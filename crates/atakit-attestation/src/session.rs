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

use std::collections::BTreeMap;
use std::time::SystemTime;
use std::{fmt, marker::PhantomData};

use atakit_cvm_encoding::pcr_comparison::{
    decode256, decode384, encode_extend_from_zero256, encode_extend_from_zero384, PcrComparison256,
    PcrComparison384,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256, Sha384};
use sha3::Keccak256;
use signature::{hazmat::PrehashVerifier, Verifier};

use crate::{AmdSnpVerificationCollateral, IntelTdxDcapCollateral, PcrBankSelection};

const SESSION_DOMAIN: &str = "CVM_SESSION_V1";
const SESSION_NONCE_DOMAIN: &str = "CVM_SESSION_REG_NONCE_V1";
const DELEGATION_DOMAIN: &str = "CVM_SESSION_KEY_DELEGATION";
const EVIDENCE_BINDING_DOMAIN: &str = "ATAKIT_PORTAL_SESSION_REQUEST_BINDING_EVIDENCE_BUNDLE_V1";
const CHAIN_SUBMISSION_BINDING_DOMAIN: &str =
    "ATAKIT_PORTAL_SESSION_REQUEST_BINDING_CHAIN_SUBMISSION_V1";

const MAX_SESSION_PCRS: usize = 24;
const MAX_SESSION_EVENT_HASHES_PER_BANK: usize = u16::MAX as usize;
const MAX_SESSION_EVENT_HASHES_TOTAL: usize = 2 * u16::MAX as usize;

fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAX: usize>(PhantomData<T>);

    impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "an array containing at most {MAX} entries")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|length| length > MAX) {
                return Err(A::Error::custom(format!(
                    "array contains more than {MAX} entries"
                )));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX {
                    return Err(A::Error::custom(format!(
                        "array contains more than {MAX} entries"
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(PhantomData))
}

fn deserialize_session_pcrs<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserialize_bounded_vec::<D, T, MAX_SESSION_PCRS>(deserializer)
}

fn deserialize_session_event_hashes<'de, D, const HASH_BYTES: usize>(
    deserializer: D,
) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EventHashesVisitor<const HASH_BYTES: usize>;

    impl<'de, const HASH_BYTES: usize> Visitor<'de> for EventHashesVisitor<HASH_BYTES> {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "an array containing at most {MAX_SESSION_EVENT_HASHES_PER_BANK} 0x-prefixed {HASH_BYTES}-byte hashes"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|length| length > MAX_SESSION_EVENT_HASHES_PER_BANK)
            {
                return Err(A::Error::custom(format!(
                    "array contains more than {MAX_SESSION_EVENT_HASHES_PER_BANK} entries"
                )));
            }
            let mut values = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_SESSION_EVENT_HASHES_PER_BANK),
            );
            while let Some(value) = sequence.next_element::<String>()? {
                if values.len() == MAX_SESSION_EVENT_HASHES_PER_BANK {
                    return Err(A::Error::custom(format!(
                        "array contains more than {MAX_SESSION_EVENT_HASHES_PER_BANK} entries"
                    )));
                }
                let encoded = value.strip_prefix("0x").ok_or_else(|| {
                    A::Error::custom(format!(
                        "event hash must be 0x-prefixed and encode exactly {HASH_BYTES} bytes"
                    ))
                })?;
                if encoded.len() != HASH_BYTES * 2
                    || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(A::Error::custom(format!(
                        "event hash must be 0x-prefixed and encode exactly {HASH_BYTES} bytes"
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(EventHashesVisitor::<HASH_BYTES>)
}

fn total_session_event_hash_count_is_valid(counts: impl IntoIterator<Item = usize>) -> bool {
    matches!(
        counts
            .into_iter()
            .try_fold(0usize, |total, count| total.checked_add(count)),
        Some(total) if total <= MAX_SESSION_EVENT_HASHES_TOTAL
    )
}

#[derive(Debug, Clone, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_binding: Option<SessionProviderBindingEvidence>,
}

/// Launch-time TPM evidence retained across `rotateKey`.
///
/// Rotation has no new TEE report and therefore no new generated provider
/// PCR15 rule. This bounded projection keeps the last full-attestation quote
/// that bound the provider TEE report to the TPM. It is not recursive, so
/// repeated rotations cannot grow the evidence bundle without bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionProviderBindingEvidence {
    pub binding: SessionBinding,
    pub tpm_quote: TpmQuoteEvidence,
    pub tpm_certify: TpmCertifyEvidence,
    #[serde(deserialize_with = "deserialize_session_pcrs")]
    pub pcr_values: Vec<SessionPcrValue>,
    #[serde(deserialize_with = "deserialize_session_pcrs")]
    pub event_log_hashes: Vec<SessionEventHashes>,
    pub tpm_signing_key: SessionPublicKey,
    pub session_id: String,
    pub policy: SessionPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionEvidenceBundleWire {
    format: u8,
    binding: SessionBinding,
    platform: SessionPlatform,
    tee_evidence: RawEvidence,
    ak_evidence: AkEvidence,
    tpm_quote: TpmQuoteEvidence,
    tpm_certify: TpmCertifyEvidence,
    #[serde(deserialize_with = "deserialize_session_pcrs")]
    pcr_values: Vec<SessionPcrValue>,
    #[serde(deserialize_with = "deserialize_session_pcrs")]
    event_log_hashes: Vec<SessionEventHashes>,
    session_key: SessionPublicKey,
    session_key_delegation: SessionKeyDelegation,
    session_id: String,
    policy: SessionPolicy,
    owner: SessionOwner,
    #[serde(default)]
    provider_binding: Option<SessionProviderBindingEvidence>,
}

impl<'de> Deserialize<'de> for SessionEvidenceBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SessionEvidenceBundleWire::deserialize(deserializer)?;
        let event_hash_counts = wire
            .event_log_hashes
            .iter()
            .chain(
                wire.provider_binding
                    .iter()
                    .flat_map(|binding| binding.event_log_hashes.iter()),
            )
            .flat_map(|hashes| [hashes.sha256.len(), hashes.sha384.len()]);
        if !total_session_event_hash_count_is_valid(event_hash_counts) {
            return Err(D::Error::custom(format!(
                "event_log_hashes contains more than {MAX_SESSION_EVENT_HASHES_TOTAL} hashes in total"
            )));
        }
        Ok(Self {
            format: wire.format,
            binding: wire.binding,
            platform: wire.platform,
            tee_evidence: wire.tee_evidence,
            ak_evidence: wire.ak_evidence,
            tpm_quote: wire.tpm_quote,
            tpm_certify: wire.tpm_certify,
            pcr_values: wire.pcr_values,
            event_log_hashes: wire.event_log_hashes,
            session_key: wire.session_key,
            session_key_delegation: wire.session_key_delegation,
            session_id: wire.session_id,
            policy: wire.policy,
            owner: wire.owner,
            provider_binding: wire.provider_binding,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct SessionPlatform {
    pub cloud: String,
    pub cloud_provenance: SessionCloudProvenance,
    pub attestation_mode: SessionAttestationMode,
    pub tee: String,
    pub machine_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCloudProvenance {
    pub source: SessionCloudSource,
    pub detection: SessionCloudDetectionObservation,
    pub user_provided: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCloudSource {
    Dmi,
    Metadata,
    UserProvided,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCloudProvider {
    Gcp,
    Azure,
    Aws,
    Qemu,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCloudDetectionObservation {
    pub dmi: SessionDmiCloudObservation,
    pub metadata: SessionMetadataCloudObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionDmiCloudObservation {
    pub sys_vendor: Option<String>,
    pub product_name: Option<String>,
    pub bios_vendor: Option<String>,
    pub detected_cloud: SessionCloudProvider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMetadataCloudObservation {
    pub gcp: SessionMetadataProbeObservation,
    pub azure: SessionMetadataProbeObservation,
    pub aws: SessionMetadataProbeObservation,
    pub detected_cloud: SessionCloudProvider,
    pub conflict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMetadataProbeObservation {
    pub attempted: bool,
    pub matched: bool,
    pub http_status: Option<u16>,
    pub response_headers: BTreeMap<String, String>,
    pub response_body: Option<String>,
    pub error: Option<String>,
}

#[cfg(test)]
pub(crate) fn test_session_cloud_provenance(
    detected_cloud: SessionCloudProvider,
) -> SessionCloudProvenance {
    let probe = SessionMetadataProbeObservation {
        attempted: false,
        matched: false,
        http_status: None,
        response_headers: BTreeMap::new(),
        response_body: None,
        error: None,
    };
    SessionCloudProvenance {
        source: SessionCloudSource::Dmi,
        detection: SessionCloudDetectionObservation {
            dmi: SessionDmiCloudObservation {
                sys_vendor: None,
                product_name: None,
                bios_vendor: None,
                detected_cloud,
            },
            metadata: SessionMetadataCloudObservation {
                gcp: probe.clone(),
                azure: probe.clone(),
                aws: probe,
                detected_cloud: SessionCloudProvider::Unknown,
                conflict: false,
            },
        },
        user_provided: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAttestationMode {
    Hardware,
    Emulation,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEvidence {
    pub kind: String,
    pub report: String,
    pub auxiliary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AkEvidence {
    pub kind: String,
    pub ak_public: String,
    pub collateral: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmQuoteEvidence {
    pub tpms_attest: String,
    pub tpm_signature: String,
    pub signature_hash: String,
    pub pcr0_startup_locality: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmCertifyEvidence {
    pub tpms_attest: String,
    pub tpm_signature: String,
    pub tpmt_public: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPcrValue {
    pub index: u8,
    pub sha256: Option<String>,
    pub sha384: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEventHashes {
    pub pcr_index: u8,
    #[serde(deserialize_with = "deserialize_session_event_hashes::<_, 32>")]
    pub sha256: Vec<String>,
    #[serde(deserialize_with = "deserialize_session_event_hashes::<_, 48>")]
    pub sha384: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPublicKey {
    pub type_id: u8,
    pub bytes: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionKeyDelegation {
    pub tpm_signing_key: SessionPublicKey,
    pub digest: String,
    pub signature: String,
    pub session_key_possession_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPolicy {
    pub workload_id: String,
    pub base_image_id: String,
    pub platform_profile_id: String,
    pub measurement_variant_id: String,
    pub pcr_bank_selection: PcrBankSelection,
    pub invariant_pcr_policy: SessionPcrPolicyBlock,
    pub variant_pcr_policy: SessionPcrPolicyBlock,
    pub workload_pcr_policy: SessionPcrPolicyBlock,
    pub provider_pcr_policy: SessionPcrPolicyBlock,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPcrPolicyBlock {
    #[serde(deserialize_with = "deserialize_session_pcrs")]
    pub pcr_specs256: Vec<SessionPcrPolicy>,
    #[serde(deserialize_with = "deserialize_session_pcrs")]
    pub pcr_specs384: Vec<SessionPcrPolicy384>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPcrPolicy {
    pub pcr_index: u8,
    pub comparison: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPcrPolicy384 {
    pub pcr_index: u8,
    pub comparison: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionOwner {
    pub fingerprint: String,
    /// Optional on-chain transaction projection. It remains request-bound as
    /// part of the bundle JSON but is not an offline session-validity input.
    pub contract_authorization: Option<SessionContractAuthorization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContractAuthorization {
    pub op_expires_at: u64,
    pub payload: String,
    pub signature: String,
    #[serde(default)]
    pub calldata_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Chain coordinates selected by the verifier. This value is required for
    /// chain-bound sessions. Portal evidence never selects these values.
    /// Local-bound sessions do not use them.
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
    /// Trusted 32-byte hashes of DER certificates.
    ///
    /// Each verifier defines the required algorithm. GCP AK roots use
    /// Keccak-256. AMD ARK roots use SHA-256.
    pub hashes: Vec<[u8; 32]>,
}

/// Provider-specific trust input. The caller resolves and supplies these
/// values; the verifier never fetches or silently substitutes trust material.
#[derive(Debug, Clone)]
pub enum SessionPlatformTrust {
    GcpTdx {
        gcp_ak_roots: CertificateTrust,
        dcap_collateral: IntelTdxDcapCollateral,
    },
    GcpSnp {
        gcp_ak_roots: CertificateTrust,
        amd_ark_roots: CertificateTrust,
        amd_snp_collateral: AmdSnpVerificationCollateral,
    },
    AzureTdx {
        maa_signing_keys: Vec<AzureMaaTrustKey>,
        dcap_collateral: IntelTdxDcapCollateral,
    },
    AzureSnp {
        maa_signing_keys: Vec<AzureMaaTrustKey>,
        amd_ark_roots: CertificateTrust,
        amd_snp_collateral: AmdSnpVerificationCollateral,
    },
    AwsSnp {
        aws_nitro_roots: CertificateTrust,
        aws_document_maximum_age_seconds: u64,
        aws_document_allowed_future_clock_difference_seconds: u64,
        amd_ark_roots: CertificateTrust,
        amd_snp_collateral: AmdSnpVerificationCollateral,
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

/// A verifier-supplied Azure MAA signing certificate, reduced to the two values
/// a certificate actually carries.
///
/// There is deliberately no `kid` or `issuer` here. Both are JSON Web Token
/// concepts that do not exist in X.509: `kid` names a key in a JWT header and
/// `issuer` is the token's `iss` claim, an attestation instance URL. A verifier
/// takes them from the token under verification, and the signature check is
/// what binds a key to that token — a `kid` in the header is attacker-supplied
/// and authenticates nothing on its own.
#[derive(Debug, Clone)]
pub struct AzureMaaTrustCertificate {
    /// PKCS#1 DER or a supported RSA public-key encoding, taken from the
    /// certificate's `SubjectPublicKeyInfo`.
    pub public_key: Vec<u8>,
    /// Unix seconds, taken from the certificate's validity period. A bare
    /// public key cannot supply this, which is why the verifier takes a
    /// certificate.
    pub not_after: u64,
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
    pub pcr_bank_selection: PcrBankSelection,
    pub invariant_pcr_policy: SessionPcrPolicyBlock,
    pub variant_pcr_policy: SessionPcrPolicyBlock,
    pub workload_pcr_policy: SessionPcrPolicyBlock,
    pub provider_pcr_policy: SessionPcrPolicyBlock,
    pub effective_attributes: Vec<SessionAttribute>,
    pub attribute_requirements: Vec<SessionAttributeRequirement>,
    /// AMD SEV-SNP registry defaults supplied by the verifier or read from
    /// AmdSnpSecurityPolicyRegistry.
    pub amd_snp_security_policies: Vec<super::AmdSnpSecurityPolicy>,
}

impl TrustedSessionPolicy {
    fn complete_pcr_specs256(&self) -> Vec<SessionPcrPolicy> {
        [
            &self.invariant_pcr_policy,
            &self.variant_pcr_policy,
            &self.workload_pcr_policy,
            &self.provider_pcr_policy,
        ]
        .into_iter()
        .flat_map(|block| block.pcr_specs256.iter().cloned())
        .collect()
    }

    fn complete_pcr_specs384(&self) -> Vec<SessionPcrPolicy384> {
        [
            &self.invariant_pcr_policy,
            &self.variant_pcr_policy,
            &self.workload_pcr_policy,
            &self.provider_pcr_policy,
        ]
        .into_iter()
        .flat_map(|block| block.pcr_specs384.iter().cloned())
        .collect()
    }
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
    /// Algorithm identifier of the verified session public key. `verify_key_types`
    /// requires ES256K (`3`) for the session request binding.
    pub session_key_type_id: u8,
    /// The verified session public key itself. `session_key_fingerprint` is
    /// recomputed from these bytes and checked against the bundle's claim, and
    /// `session_key_delegation.session_key_possession_signature` is verified
    /// against it, so this surfaces an already-verified value rather than
    /// introducing a new check.
    pub session_public_key: Vec<u8>,
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
    /// Failure reason. Successful checks always use `None`.
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
    verify_session_bundle_at(inputs, SystemTime::now())
}

/// Verifies a production session at a caller-selected time. Every certificate,
/// collateral, and token time check uses this same value.
pub fn verify_session_bundle_at(
    inputs: SessionVerificationInputs,
    verification_time: SystemTime,
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
        bundle.format == 2,
        "expected format 2",
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

    let verified_tdx_tcb_status_bit = verify_platform_attestation(
        bundle,
        &inputs.trust.platform,
        verification_time,
        &mut checks,
        &mut errors,
    );
    verify_provider_binding_evidence(
        bundle,
        &inputs.trust,
        verified_tdx_tcb_status_bit,
        &mut checks,
        &mut errors,
    );
    let authenticated_pcrs = verify_raw_quote(bundle, &mut checks, &mut errors);
    verify_quote_projection(
        bundle,
        authenticated_pcrs.as_deref(),
        &mut checks,
        &mut errors,
    );
    verify_raw_certify(bundle, &mut checks, &mut errors);
    verify_delegation(bundle, &mut checks, &mut errors);

    let binding_registry = verify_binding(
        bundle,
        inputs.trust.binding.as_ref(),
        &mut checks,
        &mut errors,
    );
    let resolved_policy = if bundle.provider_binding.is_some() {
        let mut policy = inputs.trust.policy.clone();
        policy.provider_pcr_policy = SessionPcrPolicyBlock::default();
        policy
    } else {
        resolve_provider_pcr_rules(
            bundle,
            &inputs.trust.platform,
            &inputs.trust.policy,
            &mut checks,
            &mut errors,
        )
    };
    verify_policies(
        bundle,
        &resolved_policy,
        verified_tdx_tcb_status_bit,
        &mut checks,
        &mut errors,
    );
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
            session_key_type_id: bundle.session_key.type_id,
            session_public_key: session_key.expect("validated session key"),
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

/// Reconstruct the evidence authenticated by the retained provider attestation.
/// The shared AK and TEE evidence stay unchanged; rotation's fresh evidence is
/// still verified separately against the top-level session binding.
fn provider_attestation_bundle(
    bundle: &SessionEvidenceBundle,
) -> std::borrow::Cow<'_, SessionEvidenceBundle> {
    let Some(provider_binding) = &bundle.provider_binding else {
        return std::borrow::Cow::Borrowed(bundle);
    };
    let mut projected = bundle.clone();
    projected.binding = provider_binding.binding.clone();
    projected.tpm_quote = provider_binding.tpm_quote.clone();
    projected.tpm_certify = provider_binding.tpm_certify.clone();
    projected.pcr_values = provider_binding.pcr_values.clone();
    projected.event_log_hashes = provider_binding.event_log_hashes.clone();
    projected.session_key_delegation.tpm_signing_key = provider_binding.tpm_signing_key.clone();
    projected.session_id = provider_binding.session_id.clone();
    projected.policy = provider_binding.policy.clone();
    projected.provider_binding = None;
    std::borrow::Cow::Owned(projected)
}

fn verify_provider_binding_evidence(
    bundle: &SessionEvidenceBundle,
    trust: &SessionTrust,
    verified_tdx_tcb_status_bit: Option<u16>,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let Some(provider_binding) = &bundle.provider_binding else {
        return;
    };

    let mut binding_checks = Vec::new();
    let mut binding_errors = Vec::new();
    record(
        &mut binding_checks,
        &mut binding_errors,
        "chain-mode",
        bundle.binding.mode == BindingMode::Chain
            && provider_binding.binding.mode == BindingMode::Chain,
        "provider-binding evidence is allowed only for chain-bound key rotation",
    );
    record(
        &mut binding_checks,
        &mut binding_errors,
        "tpm-signing-key-type",
        provider_binding.tpm_signing_key.type_id == 2,
        "provider-binding TPM signing key must use ES256",
    );
    let signing_key = decode_hex(
        &provider_binding.tpm_signing_key.bytes,
        "provider_binding.tpm_signing_key.bytes",
        &mut binding_errors,
    );
    let signing_key_fingerprint = decode_hex_32(
        &provider_binding.tpm_signing_key.fingerprint,
        "provider_binding.tpm_signing_key.fingerprint",
        &mut binding_errors,
    );
    if let (Some(key), Some(expected)) = (signing_key.as_ref(), signing_key_fingerprint) {
        record(
            &mut binding_checks,
            &mut binding_errors,
            "tpm-signing-key-fingerprint",
            compute_key_fingerprint(provider_binding.tpm_signing_key.type_id, key) == expected,
            "provider-binding TPM signing-key fingerprint mismatch",
        );
    }

    let projected = provider_attestation_bundle(bundle);

    let session_id = decode_hex_32(
        &projected.session_id,
        "provider_binding.session_id",
        &mut binding_errors,
    );
    let tpm_signature = decode_b64(
        &projected.tpm_quote.tpm_signature,
        "provider_binding.tpm_quote.tpm_signature",
        &mut binding_errors,
    );
    let tee_report = decode_b64(
        &projected.tee_evidence.report,
        "tee_evidence.report",
        &mut binding_errors,
    );
    if let (Some(signature), Some(report), Some(expected_id)) =
        (tpm_signature.as_ref(), tee_report.as_ref(), session_id)
    {
        let signature_hash: [u8; 32] = Keccak256::digest(signature).into();
        let tee_hash: [u8; 32] = Keccak256::digest(report).into();
        record(
            &mut binding_checks,
            &mut binding_errors,
            "session-id",
            compute_session_id(signature_hash, tee_hash) == expected_id,
            "provider-binding session ID does not match its Quote signature and TEE report hash",
        );
    }

    let authenticated_pcrs = verify_raw_quote(&projected, &mut binding_checks, &mut binding_errors);
    verify_quote_projection(
        &projected,
        authenticated_pcrs.as_deref(),
        &mut binding_checks,
        &mut binding_errors,
    );
    verify_raw_certify(&projected, &mut binding_checks, &mut binding_errors);
    verify_binding(
        &projected,
        trust.binding.as_ref(),
        &mut binding_checks,
        &mut binding_errors,
    );
    let resolved_policy = resolve_provider_pcr_rules(
        &projected,
        &trust.platform,
        &trust.policy,
        &mut binding_checks,
        &mut binding_errors,
    );
    verify_policies(
        &projected,
        &resolved_policy,
        verified_tdx_tcb_status_bit,
        &mut binding_checks,
        &mut binding_errors,
    );

    checks.extend(binding_checks.into_iter().map(|mut check| {
        check.name = format!("provider-binding-{}", check.name);
        check
    }));
    errors.extend(
        binding_errors
            .into_iter()
            .map(|error| format!("provider binding: {error}")),
    );
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
    current_time: SystemTime,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) -> Option<u16> {
    match trust {
        SessionPlatformTrust::GcpTdx {
            gcp_ak_roots,
            dcap_collateral,
        } => {
            if !require_platform(bundle, "gcp", "tdx", checks, errors) {
                return None;
            }
            verify_gcp_platform(
                bundle,
                gcp_ak_roots,
                None,
                Some(dcap_collateral),
                current_time,
                checks,
                errors,
            )
        }
        SessionPlatformTrust::GcpSnp {
            gcp_ak_roots,
            amd_ark_roots,
            amd_snp_collateral,
        } => {
            if !require_platform(bundle, "gcp", "sev-snp", checks, errors) {
                return None;
            }
            verify_gcp_platform(
                bundle,
                gcp_ak_roots,
                Some((amd_ark_roots, amd_snp_collateral)),
                None,
                current_time,
                checks,
                errors,
            )
        }
        SessionPlatformTrust::AzureTdx {
            maa_signing_keys,
            dcap_collateral,
        } => {
            if !require_platform(bundle, "azure", "tdx", checks, errors) {
                return None;
            }
            verify_azure_platform(
                bundle,
                maa_signing_keys,
                None,
                Some(dcap_collateral),
                current_time,
                checks,
                errors,
            )
        }
        SessionPlatformTrust::AzureSnp {
            maa_signing_keys,
            amd_ark_roots,
            amd_snp_collateral,
        } => {
            if !require_platform(bundle, "azure", "sev-snp", checks, errors) {
                return None;
            }
            verify_azure_platform(
                bundle,
                maa_signing_keys,
                Some(AzureSnpTrust {
                    amd_ark_roots,
                    amd_snp_collateral,
                }),
                None,
                current_time,
                checks,
                errors,
            )
        }
        SessionPlatformTrust::AwsSnp {
            aws_nitro_roots,
            aws_document_maximum_age_seconds,
            aws_document_allowed_future_clock_difference_seconds,
            amd_ark_roots,
            amd_snp_collateral,
        } => {
            if !require_platform(bundle, "aws", "sev-snp", checks, errors) {
                return None;
            }
            verify_aws_platform(
                bundle,
                aws_nitro_roots,
                *aws_document_maximum_age_seconds,
                *aws_document_allowed_future_clock_difference_seconds,
                amd_ark_roots,
                amd_snp_collateral,
                current_time,
                checks,
                errors,
            );
            None
        }
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
    amd_snp_trust: Option<(&CertificateTrust, &AmdSnpVerificationCollateral)>,
    dcap_collateral: Option<&IntelTdxDcapCollateral>,
    current_time: SystemTime,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) -> Option<u16> {
    if bundle.ak_evidence.kind != "gcp_cert_chain" {
        record(
            checks,
            errors,
            "gcp-ak-cert-chain",
            false,
            "GCP session verification requires ak_evidence.kind=gcp_cert_chain",
        );
        return None;
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
        &bundle.tpm_quote.tpms_attest,
        "tpm_quote.tpms_attest",
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
        return None;
    };
    let chain = match decode_abi_bytes_array(&collateral) {
        Ok(chain) => chain,
        Err(detail) => {
            record(checks, errors, "gcp-ak-cert-chain", false, &detail);
            return None;
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
        &gcp_ak_roots.hashes,
        current_time,
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
    let tdx_tcb_status_bit = match (amd_snp_trust, dcap_collateral) {
        (Some((amd, collateral)), None) => {
            super::verification_core::verify_gcp_snp_vendor_report(
                &mut report,
                &mut core_errors,
                Some(&tee_evidence),
                Some(collateral),
                super::verification_core::AmdSnpTrust {
                    ark_roots: &amd.certificates,
                    ark_root_hashes: &amd.hashes,
                },
                current_time,
            );
            None
        }
        (None, Some(dcap)) => super::verification_core::verify_gcp_tdx_vendor_report(
            &mut report,
            &mut core_errors,
            Some(&tee_evidence),
            Some(dcap),
            current_time,
        ),
        _ => {
            record(
                checks,
                errors,
                "platform-attestation",
                false,
                "GCP trust input is inconsistent with the selected TEE",
            );
            None
        }
    };
    import_core_checks(report, checks, errors);
    tdx_tcb_status_bit
}

#[allow(clippy::too_many_arguments)]
fn verify_aws_platform(
    bundle: &SessionEvidenceBundle,
    aws_nitro_roots: &CertificateTrust,
    aws_document_maximum_age_seconds: u64,
    aws_document_allowed_future_clock_difference_seconds: u64,
    amd_ark_roots: &CertificateTrust,
    amd_snp_collateral: &AmdSnpVerificationCollateral,
    current_time: SystemTime,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    // The NitroTPM document and SNP report belong to the original provider
    // binding, not rotation's fresh nonce/PCR snapshot. Verify both original
    // and current quotes under the same AK; never substitute the old quote for
    // the new session's signature/challenge/policy checks.
    verify_aws_quote_signature(bundle, checks, errors);
    let provider_bundle = provider_attestation_bundle(bundle);
    if bundle.provider_binding.is_some() {
        verify_aws_quote_signature(&provider_bundle, checks, errors);
    }
    let bundle = provider_bundle.as_ref();
    if bundle.tee_evidence.kind != "configfs_tsm" {
        record(
            checks,
            errors,
            "aws-nitrotpm-binding",
            false,
            "AWS session verification requires tee_evidence.kind=configfs_tsm",
        );
        return;
    }
    if bundle.ak_evidence.kind != "aws_nitro_doc" {
        record(
            checks,
            errors,
            "aws-nitrotpm-binding",
            false,
            "AWS session verification requires ak_evidence.kind=aws_nitro_doc",
        );
        return;
    }
    let Some(ak_public) = decode_b64(
        &bundle.ak_evidence.ak_public,
        "ak_evidence.ak_public",
        errors,
    ) else {
        return;
    };
    let Some(tpms_attest) = decode_b64(
        &bundle.tpm_quote.tpms_attest,
        "tpm_quote.tpms_attest",
        errors,
    ) else {
        return;
    };
    let Some(qualifying_data) = decode_hex_32(
        &bundle.binding.qualifying_data,
        "binding.qualifying_data",
        errors,
    ) else {
        return;
    };
    let evidence = super::TeeEvidence {
        kind: "configfs-tsm".to_string(),
        report: bundle.tee_evidence.report.clone(),
        auxiliary: bundle.tee_evidence.auxiliary.clone(),
    };
    let binding = super::AkBinding {
        kind: "aws-nitro-doc".to_string(),
        data: bundle.ak_evidence.collateral.clone(),
    };
    let pcrs = bundle
        .pcr_values
        .iter()
        .map(|pcr| super::PcrEvidence {
            index: pcr.index,
            sha256: pcr.sha256.clone(),
            sha384: pcr.sha384.clone(),
        })
        .collect::<Vec<_>>();
    let trust = super::TrustAnchors {
        amd_ark_roots: amd_ark_roots.certificates.clone(),
        amd_ark_root_hashes: amd_ark_roots.hashes.clone(),
        aws_nitro_roots: aws_nitro_roots.certificates.clone(),
        aws_nitro_root_hashes: aws_nitro_roots.hashes.clone(),
        aws_document_maximum_age_seconds: Some(aws_document_maximum_age_seconds),
        aws_document_allowed_future_clock_difference_seconds: Some(
            aws_document_allowed_future_clock_difference_seconds,
        ),
        ..super::TrustAnchors::default()
    };
    let mut report = super::VerificationReport {
        checks: Vec::new(),
        evidence: super::EvidenceSummary::default(),
    };
    let mut core_errors = Vec::new();
    super::aws_nitrotpm::verify_aws_tls_attestation(
        &mut report,
        &mut core_errors,
        &binding,
        &evidence,
        &ak_public,
        &tpms_attest,
        &pcrs,
        &qualifying_data,
        true,
        &trust,
        current_time,
    );
    super::verification_core::verify_aws_snp_vendor_report(
        &mut report,
        &mut core_errors,
        Some(&evidence),
        Some(amd_snp_collateral),
        super::verification_core::AmdSnpTrust {
            ark_roots: &amd_ark_roots.certificates,
            ark_root_hashes: &amd_ark_roots.hashes,
        },
        current_time,
    );
    import_core_checks(report, checks, errors);
}

struct AzureSnpTrust<'a> {
    amd_ark_roots: &'a CertificateTrust,
    amd_snp_collateral: &'a AmdSnpVerificationCollateral,
}

fn verify_aws_quote_signature(
    bundle: &SessionEvidenceBundle,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let ak = decode_b64(
        &bundle.ak_evidence.ak_public,
        "ak_evidence.ak_public",
        errors,
    );
    let quote = decode_b64(
        &bundle.tpm_quote.tpms_attest,
        "tpm_quote.tpms_attest",
        errors,
    );
    let signature = decode_b64(
        &bundle.tpm_quote.tpm_signature,
        "tpm_quote.tpm_signature",
        errors,
    );
    if let (Some(ak), Some(quote), Some(signature)) = (ak, quote, signature) {
        let mut report = super::VerificationReport {
            checks: Vec::new(),
            evidence: super::EvidenceSummary::default(),
        };
        let mut core_errors = Vec::new();
        super::verification_core::verify_tpm_quote_signature(
            &mut report,
            &mut core_errors,
            &ak,
            &quote,
            &signature,
        );
        import_core_checks(report, checks, errors);
    }
}

fn verify_azure_platform(
    bundle: &SessionEvidenceBundle,
    maa_signing_keys: &[AzureMaaTrustKey],
    snp_trust: Option<AzureSnpTrust<'_>>,
    dcap_collateral: Option<&IntelTdxDcapCollateral>,
    current_time: SystemTime,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) -> Option<u16> {
    let binding = azure_ak_binding(bundle, errors)?;
    let quote = decode_b64(
        &bundle.tpm_quote.tpms_attest,
        "tpm_quote.tpms_attest",
        errors,
    );
    let quote_signature = decode_b64(
        &bundle.tpm_quote.tpm_signature,
        "tpm_quote.tpm_signature",
        errors,
    );
    let (Some(quote), Some(quote_signature)) = (quote, quote_signature) else {
        return None;
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
        current_time,
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
    let tdx_tcb_status_bit = match (snp_trust, dcap_collateral) {
        (Some(snp_trust), None) => {
            super::verification_core::verify_azure_snp_vendor_report(
                &mut report,
                &mut core_errors,
                Some(&tee_evidence),
                Some(snp_trust.amd_snp_collateral),
                super::verification_core::AmdSnpTrust {
                    ark_roots: &snp_trust.amd_ark_roots.certificates,
                    ark_root_hashes: &snp_trust.amd_ark_roots.hashes,
                },
                current_time,
            );
            None
        }
        (None, Some(dcap)) => super::verification_core::verify_azure_tdx_vendor_report(
            &mut report,
            &mut core_errors,
            Some(&tee_evidence),
            Some(dcap),
            current_time,
        ),
        _ => {
            record(
                checks,
                errors,
                "platform-attestation",
                false,
                "Azure trust input is inconsistent with the selected TEE",
            );
            None
        }
    };
    import_core_checks(report, checks, errors);
    tdx_tcb_status_bit
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

/// Return the GCP attestation-key root certificate carried by a committed
/// session evidence bundle.
///
/// The bundle stores the certificate chain as canonical `abi.encode(bytes[])`.
/// Trust resolution needs the root before the full session verifier runs, so
/// this helper uses the same strict decoder as the verification path.
pub fn gcp_ak_root_from_session_bundle(bundle: &SessionEvidenceBundle) -> Result<Vec<u8>, String> {
    if bundle.ak_evidence.kind != "gcp_cert_chain" {
        return Err(format!(
            "GCP session verification requires ak_evidence.kind=gcp_cert_chain, got {}",
            bundle.ak_evidence.kind
        ));
    }
    let mut errors = Vec::new();
    let collateral = decode_b64(
        &bundle.ak_evidence.collateral,
        "ak_evidence.collateral",
        &mut errors,
    )
    .ok_or_else(|| errors.join("; "))?;
    let mut chain = decode_abi_bytes_array(&collateral)?;
    chain
        .pop()
        .ok_or_else(|| "GCP AK collateral certificate chain is empty".to_string())
}

/// Project the AWS NitroTPM document from a committed session evidence bundle.
/// Callers use this to resolve the document's root certificate before the full
/// session verification runs.
pub fn aws_nitro_binding_from_session_bundle(
    bundle: &SessionEvidenceBundle,
) -> Result<super::AkBinding, String> {
    if bundle.ak_evidence.kind != "aws_nitro_doc" {
        return Err(format!(
            "AWS session verification requires ak_evidence.kind=aws_nitro_doc, got {}",
            bundle.ak_evidence.kind
        ));
    }
    Ok(super::AkBinding {
        kind: "aws-nitro-doc".to_string(),
        data: bundle.ak_evidence.collateral.clone(),
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
) -> Option<Vec<super::PcrEvidence>> {
    let quote = decode_b64(
        &bundle.tpm_quote.tpms_attest,
        "tpm_quote.tpms_attest",
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
        return None;
    };
    let pcrs = bundle
        .pcr_values
        .iter()
        .map(|pcr| super::PcrEvidence {
            index: pcr.index,
            sha256: pcr.sha256.clone(),
            sha384: pcr.sha384.clone(),
        })
        .collect::<Vec<_>>();
    let mut report = super::VerificationReport {
        checks: Vec::new(),
        evidence: super::EvidenceSummary::default(),
    };
    let mut quote_errors = Vec::new();
    let authenticated_pcrs = super::verification_core::verify_tpm_quote(
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
    authenticated_pcrs
}

fn verify_quote_projection(
    bundle: &SessionEvidenceBundle,
    authenticated_pcrs: Option<&[super::PcrEvidence]>,
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
        authenticated_pcrs.is_some_and(|pcrs| {
            pcrs.len() == bundle.pcr_values.len()
                && pcrs
                    .iter()
                    .zip(&bundle.pcr_values)
                    .all(|(authenticated, supplied)| {
                        authenticated.index == supplied.index
                            && match bundle.policy.pcr_bank_selection {
                                PcrBankSelection::Sha256 => authenticated.sha256.is_some(),
                                PcrBankSelection::Sha384 => authenticated.sha384.is_some(),
                                PcrBankSelection::Sha256AndSha384 => {
                                    authenticated.sha256.is_some() && authenticated.sha384.is_some()
                                }
                            }
                    })
        }),
        "the Quote did not authenticate every supplied PCR in every policy-selected bank",
    );
}

fn verify_raw_certify(
    bundle: &SessionEvidenceBundle,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    let attest = decode_b64(
        &bundle.tpm_certify.tpms_attest,
        "tpm_certify.tpms_attest",
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
    let body = match super::verification_core::tpms_attest_body(&attest) {
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

        let session_key = decode_hex(&bundle.session_key.bytes, "session_key.bytes", errors);
        let possession_signature = decode_hex(
            &bundle
                .session_key_delegation
                .session_key_possession_signature,
            "session_key_delegation.session_key_possession_signature",
            errors,
        );
        if let (Some(key), Some(signature)) = (session_key, possession_signature) {
            record(
                checks,
                errors,
                "session-key-possession-signature",
                recoverable_es256k_signature_matches(&key, expected, &signature),
                "session-key possession signature mismatch",
            );
        }
    }
}

/// Compute the digest authorizing a session key to sign for a workload.
pub fn delegation_digest(
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
    evaluate_session_pcr_policy_with_startup_locality(policy, measured_value, measured_events, 0xff)
}

pub(crate) fn evaluate_session_pcr_policy_with_startup_locality(
    policy: &SessionPcrPolicy,
    measured_value: [u8; 32],
    measured_events: &[[u8; 32]],
    startup_locality: u8,
) -> std::result::Result<(), String> {
    let comparison = decode_policy_comparison_hex(&policy.comparison)?;
    let comparison = decode256(&comparison).map_err(|error| error.to_string())?;
    evaluate_comparison256(
        &comparison,
        measured_value,
        measured_events,
        policy.pcr_index,
        startup_locality,
    )
}

pub(crate) fn evaluate_session_pcr_policy384(
    policy: &SessionPcrPolicy384,
    measured_value: [u8; 48],
    measured_events: &[[u8; 48]],
    startup_locality: u8,
) -> std::result::Result<(), String> {
    let comparison = decode_policy_comparison_hex(&policy.comparison)?;
    let comparison = decode384(&comparison).map_err(|error| error.to_string())?;
    evaluate_comparison384(
        &comparison,
        measured_value,
        measured_events,
        policy.pcr_index,
        startup_locality,
    )
}

fn decode_policy_comparison_hex(value: &str) -> std::result::Result<Vec<u8>, String> {
    let clean = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(clean).map_err(|error| format!("invalid PCR comparison hex: {error}"))
}

fn evaluate_comparison256(
    comparison: &PcrComparison256,
    measured_value: [u8; 32],
    measured_events: &[[u8; 32]],
    pcr_index: u8,
    startup_locality: u8,
) -> std::result::Result<(), String> {
    match comparison {
        PcrComparison256::Static(expected) => {
            if expected.as_slice() != measured_value {
                return Err("STATIC PCR value mismatch".to_string());
            }
            return Ok(());
        }
        PcrComparison256::ExtendFromZero(extend_value) => {
            let mut input = [0u8; 64];
            input[32..].copy_from_slice(extend_value.as_slice());
            let expected: [u8; 32] = Sha256::digest(input).into();
            if expected != measured_value {
                return Err("EXTEND_FROM_ZERO PCR value mismatch".to_string());
            }
            return Ok(());
        }
        PcrComparison256::DynamicSubset(expected) => {
            require_dynamic_events(measured_events, "DYNAMIC_SUBSET")?;
            if expected.is_empty()
                || expected.iter().any(|required| {
                    !measured_events
                        .iter()
                        .any(|event| required.as_slice() == event)
                })
            {
                return Err("DYNAMIC_SUBSET required landmark is missing".to_string());
            }
        }
        PcrComparison256::DynamicSubsequence(expected) => {
            require_dynamic_events(measured_events, "DYNAMIC_SUBSEQUENCE")?;
            let mut landmark = 0;
            for event in measured_events {
                if expected
                    .get(landmark)
                    .is_some_and(|required| required.as_slice() == event)
                {
                    landmark += 1;
                }
            }
            if expected.is_empty() || landmark != expected.len() {
                return Err("DYNAMIC_SUBSEQUENCE required landmark is missing".to_string());
            }
        }
        PcrComparison256::DynamicIndexedEventSets(rule) => {
            require_dynamic_events(measured_events, "DYNAMIC_INDEXED_EVENT_SETS")?;
            if measured_events.len() != usize::from(rule.expected_event_count) {
                return Err("DYNAMIC_INDEXED_EVENT_SETS event count mismatch".to_string());
            }
            validate_indexed_events(
                rule.checked_events
                    .iter()
                    .map(|checked| {
                        (
                            checked.event_index,
                            checked.allowed_values.len(),
                            checked
                                .allowed_values
                                .windows(2)
                                .all(|pair| pair[0] < pair[1]),
                            measured_events
                                .get(usize::from(checked.event_index))
                                .is_some_and(|measured| {
                                    checked
                                        .allowed_values
                                        .iter()
                                        .any(|allowed| allowed.as_slice() == measured)
                                }),
                        )
                    })
                    .collect::<Vec<_>>(),
                rule.expected_event_count,
            )?;
        }
    }
    verify_event_replay(
        measured_value,
        measured_events,
        pcr_index,
        startup_locality,
        |input| Sha256::digest(input).into(),
    )
}

fn evaluate_comparison384(
    comparison: &PcrComparison384,
    measured_value: [u8; 48],
    measured_events: &[[u8; 48]],
    pcr_index: u8,
    startup_locality: u8,
) -> std::result::Result<(), String> {
    match comparison {
        PcrComparison384::Static(expected) => {
            if expected != &measured_value {
                return Err("STATIC PCR value mismatch".to_string());
            }
            return Ok(());
        }
        PcrComparison384::ExtendFromZero(extend_value) => {
            let mut input = [0u8; 96];
            input[48..].copy_from_slice(extend_value);
            let expected: [u8; 48] = Sha384::digest(input).into();
            if expected != measured_value {
                return Err("EXTEND_FROM_ZERO PCR value mismatch".to_string());
            }
            return Ok(());
        }
        PcrComparison384::DynamicSubset(expected) => {
            require_dynamic_events(measured_events, "DYNAMIC_SUBSET")?;
            if expected.is_empty()
                || expected
                    .iter()
                    .any(|required| !measured_events.contains(required))
            {
                return Err("DYNAMIC_SUBSET required landmark is missing".to_string());
            }
        }
        PcrComparison384::DynamicSubsequence(expected) => {
            require_dynamic_events(measured_events, "DYNAMIC_SUBSEQUENCE")?;
            let mut landmark = 0;
            for event in measured_events {
                if expected.get(landmark) == Some(event) {
                    landmark += 1;
                }
            }
            if expected.is_empty() || landmark != expected.len() {
                return Err("DYNAMIC_SUBSEQUENCE required landmark is missing".to_string());
            }
        }
        PcrComparison384::DynamicIndexedEventSets(rule) => {
            require_dynamic_events(measured_events, "DYNAMIC_INDEXED_EVENT_SETS")?;
            if measured_events.len() != usize::from(rule.expected_event_count) {
                return Err("DYNAMIC_INDEXED_EVENT_SETS event count mismatch".to_string());
            }
            validate_indexed_events(
                rule.checked_events
                    .iter()
                    .map(|checked| {
                        (
                            checked.event_index,
                            checked.allowed_values.len(),
                            checked
                                .allowed_values
                                .windows(2)
                                .all(|pair| pair[0] < pair[1]),
                            measured_events
                                .get(usize::from(checked.event_index))
                                .is_some_and(|measured| checked.allowed_values.contains(measured)),
                        )
                    })
                    .collect::<Vec<_>>(),
                rule.expected_event_count,
            )?;
        }
    }
    verify_event_replay(
        measured_value,
        measured_events,
        pcr_index,
        startup_locality,
        |input| Sha384::digest(input).into(),
    )
}

fn require_dynamic_events<const N: usize>(
    measured_events: &[[u8; N]],
    comparison_type: &str,
) -> std::result::Result<(), String> {
    if measured_events.is_empty() {
        Err(format!("{comparison_type} measured event log is empty"))
    } else {
        Ok(())
    }
}

fn validate_indexed_events(
    checks: Vec<(u16, usize, bool, bool)>,
    expected_event_count: u16,
) -> std::result::Result<(), String> {
    if checks.is_empty() {
        return Err("DYNAMIC_INDEXED_EVENT_SETS has no checked events".to_string());
    }
    let mut previous = None;
    for (event_index, allowed_count, allowed_sorted, matched) in checks {
        if event_index >= expected_event_count {
            return Err("DYNAMIC_INDEXED_EVENT_SETS checked index is out of range".to_string());
        }
        if previous.is_some_and(|previous| event_index <= previous) {
            return Err("DYNAMIC_INDEXED_EVENT_SETS checked indexes are not sorted".to_string());
        }
        if allowed_count == 0 || !allowed_sorted {
            return Err("DYNAMIC_INDEXED_EVENT_SETS allowed set is not canonical".to_string());
        }
        if !matched {
            return Err("DYNAMIC_INDEXED_EVENT_SETS checked event mismatch".to_string());
        }
        previous = Some(event_index);
    }
    Ok(())
}

fn verify_event_replay<const N: usize>(
    measured_value: [u8; N],
    measured_events: &[[u8; N]],
    pcr_index: u8,
    startup_locality: u8,
    hash: impl Fn(&[u8]) -> [u8; N],
) -> std::result::Result<(), String> {
    if startup_locality != 0xff && startup_locality > 4 {
        return Err(format!("invalid PCR0 StartupLocality {startup_locality}"));
    }
    let mut replay = [0u8; N];
    if pcr_index == 0 && startup_locality != 0xff {
        replay[N - 1] = startup_locality;
    }
    for event in measured_events {
        let mut input = Vec::with_capacity(N * 2);
        input.extend_from_slice(&replay);
        input.extend_from_slice(event);
        replay = hash(&input);
    }
    if replay == measured_value {
        Ok(())
    } else {
        Err("PCR event replay does not match measured value".to_string())
    }
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
    if mode != BindingMode::Chain {
        return;
    }
    let Some(trusted) = trusted else {
        record(
            checks,
            errors,
            "trusted-binding-present",
            false,
            "chain-bound session verification requires verifier-selected chain coordinates",
        );
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

fn resolve_provider_pcr_rules(
    bundle: &SessionEvidenceBundle,
    platform: &SessionPlatformTrust,
    trusted: &TrustedSessionPolicy,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) -> TrustedSessionPolicy {
    let mut resolved = trusted.clone();
    let result = (|| -> std::result::Result<(), String> {
        let mut decode_errors = Vec::new();
        let report = decode_b64(
            &bundle.tee_evidence.report,
            "tee_evidence.report",
            &mut decode_errors,
        )
        .ok_or_else(|| decode_errors.join("; "))?;

        match platform {
            SessionPlatformTrust::AzureTdx { .. } | SessionPlatformTrust::AzureSnp { .. } => {}
            SessionPlatformTrust::GcpTdx { .. } => {
                if matches!(trusted.pcr_bank_selection, PcrBankSelection::Sha384) {
                    return Err("GCP provider PCR15 requires the SHA-256 PCR bank".to_string());
                }
                let report_start = super::verification_core::tdx_quote_report_start(&report)?;
                let uuid_start = report_start + super::TDX_REPORT_REPORT_DATA_OFFSET;
                let uuid = report
                    .get(uuid_start..uuid_start + super::GCP_TDX_UUID_LEN)
                    .ok_or_else(|| {
                        "GCP TDX quote is too short for the REPORT_DATA UUID".to_string()
                    })?;
                let mut extend_value = [0u8; 32];
                extend_value[16..].copy_from_slice(uuid);
                resolved
                    .provider_pcr_policy
                    .pcr_specs256
                    .push(SessionPcrPolicy {
                        pcr_index: 15,
                        comparison: format!(
                            "0x{}",
                            hex::encode(encode_extend_from_zero256(extend_value))
                        ),
                    });
            }
            SessionPlatformTrust::GcpSnp { .. } => {
                if matches!(trusted.pcr_bank_selection, PcrBankSelection::Sha384) {
                    return Err("GCP provider PCR15 requires the SHA-256 PCR bank".to_string());
                }
                if report.len() != super::SNP_REPORT_SIZE {
                    return Err(format!(
                        "AMD SEV-SNP report must contain {} bytes, got {}",
                        super::SNP_REPORT_SIZE,
                        report.len()
                    ));
                }
                let report_id = report[super::SNP_REPORT_REPORT_ID_OFFSET
                    ..super::SNP_REPORT_REPORT_ID_OFFSET + super::SNP_REPORT_REPORT_ID_LEN]
                    .try_into()
                    .expect("fixed report ID length");
                resolved
                    .provider_pcr_policy
                    .pcr_specs256
                    .push(SessionPcrPolicy {
                        pcr_index: 15,
                        comparison: format!(
                            "0x{}",
                            hex::encode(encode_extend_from_zero256(report_id))
                        ),
                    });
            }
            SessionPlatformTrust::AwsSnp { .. } => {
                if matches!(trusted.pcr_bank_selection, PcrBankSelection::Sha256) {
                    return Err("AWS provider PCR15 requires the SHA-384 PCR bank".to_string());
                }
                if report.len() != super::SNP_REPORT_SIZE {
                    return Err(format!(
                        "AMD SEV-SNP report must contain {} bytes, got {}",
                        super::SNP_REPORT_SIZE,
                        report.len()
                    ));
                }
                let report_id = &report[super::SNP_REPORT_REPORT_ID_OFFSET
                    ..super::SNP_REPORT_REPORT_ID_OFFSET + super::SNP_REPORT_REPORT_ID_LEN];
                let mut extend_value384 = [0u8; 48];
                extend_value384[16..].copy_from_slice(report_id);
                resolved
                    .provider_pcr_policy
                    .pcr_specs384
                    .push(SessionPcrPolicy384 {
                        pcr_index: 15,
                        comparison: format!(
                            "0x{}",
                            hex::encode(encode_extend_from_zero384(extend_value384))
                        ),
                    });
                if matches!(
                    trusted.pcr_bank_selection,
                    PcrBankSelection::Sha256AndSha384
                ) {
                    resolved
                        .provider_pcr_policy
                        .pcr_specs256
                        .push(SessionPcrPolicy {
                            pcr_index: 15,
                            comparison: format!(
                                "0x{}",
                                hex::encode(encode_extend_from_zero256(
                                    report_id.try_into().expect("fixed report ID length")
                                ))
                            ),
                        });
                }
            }
        }
        Ok(())
    })();

    match result {
        Ok(()) => record(checks, errors, "provider-pcr15-rule", true, ""),
        Err(detail) => record(checks, errors, "provider-pcr15-rule", false, &detail),
    }
    resolved
}

fn verify_policies(
    bundle: &SessionEvidenceBundle,
    trusted: &TrustedSessionPolicy,
    verified_tdx_tcb_status_bit: Option<u16>,
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
    let bundle_projection_is_empty = [
        &bundle.policy.invariant_pcr_policy,
        &bundle.policy.variant_pcr_policy,
        &bundle.policy.workload_pcr_policy,
        &bundle.policy.provider_pcr_policy,
    ]
    .into_iter()
    .all(|block| block.pcr_specs256.is_empty() && block.pcr_specs384.is_empty());
    let bundle_projection_matches = bundle_projection_is_empty
        || (bundle.policy.pcr_bank_selection == trusted.pcr_bank_selection
            && bundle.policy.invariant_pcr_policy == trusted.invariant_pcr_policy
            && bundle.policy.variant_pcr_policy == trusted.variant_pcr_policy
            && bundle.policy.workload_pcr_policy == trusted.workload_pcr_policy
            && bundle.policy.provider_pcr_policy == trusted.provider_pcr_policy);
    record(
        checks,
        errors,
        "trusted-pcr-policy-projection",
        bundle_projection_matches,
        "bundle PCR policy blocks differ from the caller-supplied trusted policy blocks",
    );
    let pcr_specs256 = trusted.complete_pcr_specs256();
    let pcr_specs384 = trusted.complete_pcr_specs384();
    verify_attribute_policy(bundle, trusted, verified_tdx_tcb_status_bit, checks, errors);
    let selected_policy_is_empty = match trusted.pcr_bank_selection {
        PcrBankSelection::Sha256 => pcr_specs256.is_empty(),
        PcrBankSelection::Sha384 => pcr_specs384.is_empty(),
        PcrBankSelection::Sha256AndSha384 => pcr_specs256.is_empty() && pcr_specs384.is_empty(),
    };
    if selected_policy_is_empty {
        record(
            checks,
            errors,
            "trusted-pcr-policy",
            false,
            "caller-supplied trusted PCR policy has no rule in a selected bank",
        );
        return;
    }

    for policy in pcr_specs256
        .iter()
        .filter(|_| !matches!(trusted.pcr_bank_selection, PcrBankSelection::Sha384))
    {
        let name = format!("pcr-policy-sha256-{}", policy.pcr_index);
        let Some(value) = bundle
            .pcr_values
            .iter()
            .find(|value| value.index == policy.pcr_index)
        else {
            record(checks, errors, &name, false, "PCR value is absent");
            continue;
        };
        let Some(measured_value) = value.sha256.as_deref() else {
            record(checks, errors, &name, false, "SHA-256 PCR value is absent");
            continue;
        };
        let Some(measured) = decode_hex_32(measured_value, "pcr_values.sha256", errors) else {
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
            Ok(events) => match evaluate_session_pcr_policy_with_startup_locality(
                policy,
                measured,
                events.as_deref().unwrap_or_default(),
                bundle.tpm_quote.pcr0_startup_locality,
            ) {
                Ok(()) => record(checks, errors, &name, true, ""),
                Err(detail) => record(checks, errors, &name, false, &detail),
            },
            Err(detail) => record(checks, errors, &name, false, &detail),
        }
    }

    for policy in pcr_specs384
        .iter()
        .filter(|_| !matches!(trusted.pcr_bank_selection, PcrBankSelection::Sha256))
    {
        let name = format!("pcr-policy-sha384-{}", policy.pcr_index);
        let Some(value) = bundle
            .pcr_values
            .iter()
            .find(|value| value.index == policy.pcr_index)
        else {
            record(checks, errors, &name, false, "PCR value is absent");
            continue;
        };
        let Some(measured_value) = value.sha384.as_deref() else {
            record(checks, errors, &name, false, "SHA-384 PCR value is absent");
            continue;
        };
        let measured = match decode_hex_48(measured_value) {
            Ok(value) => value,
            Err(detail) => {
                record(checks, errors, &name, false, &detail);
                continue;
            }
        };
        let events = bundle
            .event_log_hashes
            .iter()
            .find(|events| events.pcr_index == policy.pcr_index)
            .map(|events| {
                events
                    .sha384
                    .iter()
                    .map(|event| decode_hex_48(event))
                    .collect::<std::result::Result<Vec<_>, _>>()
            })
            .transpose();
        match events {
            Ok(events) => match evaluate_session_pcr_policy384(
                policy,
                measured,
                events.as_deref().unwrap_or_default(),
                bundle.tpm_quote.pcr0_startup_locality,
            ) {
                Ok(()) => record(checks, errors, &name, true, ""),
                Err(detail) => record(checks, errors, &name, false, &detail),
            },
            Err(detail) => record(checks, errors, &name, false, &detail),
        }
    }
}

fn verify_attribute_policy(
    bundle: &SessionEvidenceBundle,
    trusted: &TrustedSessionPolicy,
    verified_tdx_tcb_status_bit: Option<u16>,
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

    let verified_states = verified_tee_attribute_states(bundle);
    record(
        checks,
        errors,
        "verified-tee-attribute-report-fields",
        verified_states.is_ok(),
        &verified_states.as_ref().err().cloned().unwrap_or_default(),
    );
    if let Ok(verified_states) = verified_states {
        let tee_platform = match bundle.platform.tee.as_str() {
            "tdx" => Some(atakit_core::tee_attributes::TeePlatform::IntelTdx),
            "sev-snp" => Some(atakit_core::tee_attributes::TeePlatform::AmdSevSnp),
            _ => None,
        };
        for (attribute, enabled) in atakit_core::tee_attributes::VerifiedTeeAttribute::BOOLEAN
            .into_iter()
            .zip(verified_states)
        {
            if Some(attribute.platform()) != tee_platform {
                continue;
            }
            let key = attribute.key();
            let verified_value = atakit_core::tee_attributes::bool_value(enabled);
            let declared_value = trusted
                .effective_attributes
                .iter()
                .find(|item| item.key == key)
                .map(|item| item.value)
                .unwrap_or(atakit_core::tee_attributes::ATTRIBUTE_FALSE);
            let declared_is_boolean = declared_value
                == atakit_core::tee_attributes::ATTRIBUTE_FALSE
                || declared_value == atakit_core::tee_attributes::ATTRIBUTE_TRUE;
            let declaration_matches = declared_is_boolean && declared_value == verified_value;
            let declaration_detail = format!(
                "base-image declaration for {} is 0x{}, verified value is 0x{}",
                attribute.name(),
                hex::encode(declared_value),
                hex::encode(verified_value)
            );
            record(
                checks,
                errors,
                &format!("tee-attribute-base-image-{}", attribute.name()),
                declaration_matches,
                if declaration_matches {
                    ""
                } else {
                    &declaration_detail
                },
            );

            let requirement = trusted
                .attribute_requirements
                .iter()
                .find(|item| item.key == key);
            let allowed_values = requirement
                .map(|item| item.allowed_values.as_slice())
                .unwrap_or(std::slice::from_ref(
                    &atakit_core::tee_attributes::ATTRIBUTE_FALSE,
                ));
            let canonical = allowed_values == [atakit_core::tee_attributes::ATTRIBUTE_FALSE]
                || allowed_values
                    == [
                        atakit_core::tee_attributes::ATTRIBUTE_FALSE,
                        atakit_core::tee_attributes::ATTRIBUTE_TRUE,
                    ];
            let requirement_matches = canonical && allowed_values.contains(&verified_value);
            let requirement_detail = format!(
                "workload requirement for {} does not permit verified value 0x{}",
                attribute.name(),
                hex::encode(verified_value)
            );
            record(
                checks,
                errors,
                &format!("tee-attribute-workload-{}", attribute.name()),
                requirement_matches,
                if requirement_matches {
                    ""
                } else {
                    &requirement_detail
                },
            );
        }

        if tee_platform == Some(atakit_core::tee_attributes::TeePlatform::IntelTdx) {
            if let Some(actual_bit) = verified_tdx_tcb_status_bit {
                let key = atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_KEY;
                let base_value = trusted
                    .effective_attributes
                    .iter()
                    .find(|item| item.key == key)
                    .map(|item| &item.value);
                let base_matches = super::tdx_tcb_status_policy_matches(base_value, actual_bit);
                record(
                    checks,
                    errors,
                    "tee-attribute-base-image-intel-tdx-tcb-status",
                    base_matches,
                    &format!(
                        "base-image Intel TDX TCB status mask is invalid or does not permit verified status bit 0x{actual_bit:x}"
                    ),
                );
                let workload_matches = match trusted
                    .attribute_requirements
                    .iter()
                    .find(|item| item.key == key)
                    .map(|item| item.allowed_values.as_slice())
                {
                    Some([value]) => super::tdx_tcb_status_policy_matches(Some(value), actual_bit),
                    Some(_) => false,
                    None => super::tdx_tcb_status_policy_matches(None, actual_bit),
                };
                record(
                    checks,
                    errors,
                    "tee-attribute-workload-intel-tdx-tcb-status",
                    workload_matches,
                    &format!(
                        "workload Intel TDX TCB status mask is invalid or does not permit verified status bit 0x{actual_bit:x}"
                    ),
                );
            }
        }

        if tee_platform == Some(atakit_core::tee_attributes::TeePlatform::AmdSevSnp) {
            match verified_amd_snp_security_state(bundle) {
                Ok(state) => match super::select_amd_snp_security_policy(
                    &trusted.amd_snp_security_policies,
                    state.cpuid,
                ) {
                    Ok(registry_default) => verify_amd_snp_session_policy(
                        state,
                        registry_default,
                        trusted,
                        checks,
                        errors,
                    ),
                    Err(detail) => record(
                        checks,
                        errors,
                        "amd-sev-snp-registry-default",
                        false,
                        &detail,
                    ),
                },
                Err(detail) => record(checks, errors, "amd-sev-snp-security-state", false, &detail),
            }
        }
    }

    for (index, requirement) in trusted.attribute_requirements.iter().enumerate() {
        if atakit_core::tee_attributes::VerifiedTeeAttribute::from_key(&requirement.key).is_some() {
            continue;
        }
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

fn verify_amd_snp_session_policy(
    state: super::AmdSnpSecurityState,
    registry_default: &super::AmdSnpSecurityPolicy,
    trusted: &TrustedSessionPolicy,
    checks: &mut Vec<SessionVerificationCheck>,
    errors: &mut Vec<String>,
) {
    use atakit_core::tee_attributes::{
        amd_sev_snp_platform_info_matches, amd_sev_snp_tcb_meets_minimum,
        merge_amd_sev_snp_platform_info_policies, AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
        AMD_SEV_SNP_TCB_MINIMUM_KEY,
    };

    let mitigation_policy = super::validate_amd_snp_mitigation_policy(
        state.report_version,
        state.launch_mitigation_vector,
        state.current_mitigation_vector,
        registry_default,
    );
    record(
        checks,
        errors,
        "amd-sev-snp-mitigation-vector-policy",
        mitigation_policy.is_ok(),
        &mitigation_policy.err().unwrap_or_else(|| {
            "verified AMD SEV-SNP mitigation vectors satisfy the registry policy".to_string()
        }),
    );

    let base_tcb = trusted
        .effective_attributes
        .iter()
        .find(|item| item.key == AMD_SEV_SNP_TCB_MINIMUM_KEY)
        .map(|item| item.value)
        .unwrap_or(registry_default.minimum_tcb);
    let base_tcb_matches = amd_sev_snp_tcb_meets_minimum(&state.tcb_values, &base_tcb);
    record(
        checks,
        errors,
        "tee-attribute-base-image-amd-sev-snp-tcb-minimum",
        base_tcb_matches,
        &format!(
            "verified AMD SEV-SNP TCB 0x{} does not meet the resolved base-image minimum",
            hex::encode(state.tcb_values)
        ),
    );

    let workload_tcb = resolve_packed_session_requirement(
        &trusted.attribute_requirements,
        AMD_SEV_SNP_TCB_MINIMUM_KEY,
        registry_default.minimum_tcb,
    );
    let (workload_tcb_matches, workload_tcb_detail) = match workload_tcb {
        Ok(workload_tcb) => (
            amd_sev_snp_tcb_meets_minimum(&state.tcb_values, &workload_tcb),
            format!(
                "verified AMD SEV-SNP TCB 0x{} does not meet the resolved workload minimum",
                hex::encode(state.tcb_values)
            ),
        ),
        Err(detail) => (false, detail),
    };
    record(
        checks,
        errors,
        "tee-attribute-workload-amd-sev-snp-tcb-minimum",
        workload_tcb_matches,
        &workload_tcb_detail,
    );

    let base_platform_info = trusted
        .effective_attributes
        .iter()
        .find(|item| item.key == AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY)
        .map(|item| item.value)
        .unwrap_or(registry_default.platform_info_policy);
    let base_platform_info_matches =
        amd_sev_snp_platform_info_matches(state.platform_info, &base_platform_info);
    record(
        checks,
        errors,
        "tee-attribute-base-image-amd-sev-snp-platform-info-policy",
        base_platform_info_matches,
        &format!(
            "verified AMD SEV-SNP PLATFORM_INFO 0x{:016x} does not meet the resolved base-image policy",
            state.platform_info
        ),
    );

    let workload_platform_info = resolve_packed_session_requirement(
        &trusted.attribute_requirements,
        AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
        registry_default.platform_info_policy,
    );
    let (workload_platform_info_matches, workload_platform_info_detail) =
        match workload_platform_info {
            Ok(workload_platform_info) => {
                let effective = merge_amd_sev_snp_platform_info_policies(
                    &base_platform_info,
                    &workload_platform_info,
                );
                (
                    effective.as_ref().is_some_and(|policy| {
                        amd_sev_snp_platform_info_matches(state.platform_info, policy)
                    }),
                    format!(
                        "verified AMD SEV-SNP PLATFORM_INFO 0x{:016x} conflicts with or does not meet the resolved base-image and workload policies",
                        state.platform_info
                    ),
                )
            }
            Err(detail) => (false, detail),
        };
    record(
        checks,
        errors,
        "tee-attribute-workload-amd-sev-snp-platform-info-policy",
        workload_platform_info_matches,
        &workload_platform_info_detail,
    );
}

/// Resolve a workload's explicit value for a reserved packed attribute.
///
/// Mirrors `resolve_packed_workload_requirement` on the TLS path and
/// `AmdSnpSecurityPolicyRegistry._requirementOrDefault` on chain: omitting the
/// requirement defers to the registry default, but a requirement that is
/// present must name exactly one value. Substituting the default for a
/// malformed requirement would hand the session a policy it never selected.
fn resolve_packed_session_requirement(
    requirements: &[SessionAttributeRequirement],
    key: [u8; 32],
    default_value: [u8; 32],
) -> std::result::Result<[u8; 32], String> {
    let Some(requirement) = requirements.iter().find(|item| item.key == key) else {
        return Ok(default_value);
    };
    if requirement.allowed_values.len() != 1 {
        return Err(format!(
            "workload requirement for reserved packed attribute 0x{} must contain exactly one value, got {}",
            hex::encode(key),
            requirement.allowed_values.len()
        ));
    }
    Ok(requirement.allowed_values[0])
}

fn verified_amd_snp_security_state(
    bundle: &SessionEvidenceBundle,
) -> std::result::Result<super::AmdSnpSecurityState, String> {
    let report = decode_tee_report(bundle)?;
    super::amd_snp_security_state(&report)
}

fn verified_tee_attribute_states(
    bundle: &SessionEvidenceBundle,
) -> std::result::Result<[bool; 3], String> {
    let report = decode_tee_report(bundle)?;
    super::verification_core::verified_tee_attribute_states(&bundle.platform.tee, &report)
}

fn decode_tee_report(bundle: &SessionEvidenceBundle) -> std::result::Result<Vec<u8>, String> {
    if bundle.tee_evidence.report.contains('=') {
        return Err("tee_evidence.report base64url padding is not allowed".into());
    }
    URL_SAFE_NO_PAD
        .decode(&bundle.tee_evidence.report)
        .map_err(|error| format!("tee_evidence.report did not decode: {error}"))
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
    atakit_cvm_encoding::key_fingerprint(type_id, key)
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

/// Verify a 65-byte recoverable ES256K signature against a 65-byte
/// uncompressed SEC1 public key.
///
/// The signature is the canonical Ethereum legacy `r || s || v` form. The
/// recovery byte must be `27` or `28`, and `s` must be in the lower half of
/// the secp256k1 group order, matching `SignatureVerifier._verifySecp256k1`.
pub fn recoverable_es256k_signature_matches(
    public_key: &[u8],
    digest: [u8; 32],
    bytes: &[u8],
) -> bool {
    if public_key.len() != 65 || public_key[0] != 0x04 || bytes.len() != 65 {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&bytes[..64]) else {
        return false;
    };
    if signature.normalize_s().is_some() {
        return false;
    }
    let recovery = match bytes[64] {
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
        detail: (!valid && !detail.is_empty()).then(|| detail.into()),
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

fn decode_hex_48(value: &str) -> Result<[u8; 48], String> {
    let raw = value.strip_prefix("0x").ok_or("missing 0x prefix")?;
    let bytes = hex::decode(raw).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 48 bytes, got {}", bytes.len()))
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    fn aws_rotation_fixture() -> SessionEvidenceBundle {
        let response: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/aws-rotation/evidence.json")).unwrap();
        serde_json::from_value(response["evidence_bundle"].clone()).unwrap()
    }

    fn aws_rotation_checks(bundle: &SessionEvidenceBundle) -> Vec<SessionVerificationCheck> {
        // Trust comes from the fixed original fixture, never the mutated input.
        let binding = aws_nitro_binding_from_session_bundle(&aws_rotation_fixture()).unwrap();
        let roots = CertificateTrust {
            certificates: vec![super::super::aws_nitro_root_certificate(&binding).unwrap()],
            hashes: vec![],
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        // These tests isolate the real NitroTPM document and TPM signatures.
        // The independent SNP vendor certificate check intentionally has no
        // collateral here; it is not claimed as a full-session acceptance test.
        let snp = AmdSnpVerificationCollateral::from_vcek_chain(vec![], vec![], vec![], vec![]);
        verify_aws_platform(
            bundle,
            &roots,
            3600,
            60,
            &CertificateTrust::default(),
            &snp,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1789198200),
            &mut checks,
            &mut errors,
        );
        checks
    }

    #[test]
    fn aws_rotation_verifies_retained_document_and_both_quote_signatures() {
        let bundle = aws_rotation_fixture();
        assert_ne!(
            bundle.binding.qualifying_data,
            bundle
                .provider_binding
                .as_ref()
                .unwrap()
                .binding
                .qualifying_data
        );
        let checks = aws_rotation_checks(&bundle);
        assert!(
            checks
                .iter()
                .any(|c| c.name == "aws-nitrotpm-binding" && c.valid),
            "{checks:?}"
        );
        let signatures: Vec<_> = checks
            .iter()
            .filter(|c| c.name == "tpm-quote-signature")
            .collect();
        assert_eq!(signatures.len(), 2, "{checks:?}");
        assert!(signatures.iter().all(|c| c.valid), "{checks:?}");
    }

    #[test]
    fn aws_initial_binding_uses_current_quote_without_provider_projection() {
        let bundle = provider_attestation_bundle(&aws_rotation_fixture()).into_owned();
        assert!(bundle.provider_binding.is_none());
        let checks = aws_rotation_checks(&bundle);
        assert!(
            checks
                .iter()
                .any(|c| c.name == "aws-nitrotpm-binding" && c.valid),
            "{checks:?}"
        );
        assert_eq!(
            checks
                .iter()
                .filter(|c| c.name == "tpm-quote-signature" && c.valid)
                .count(),
            1
        );
    }

    #[test]
    fn aws_rotation_cannot_drop_original_provider_binding() {
        let mut bundle = aws_rotation_fixture();
        bundle.provider_binding = None;
        let checks = aws_rotation_checks(&bundle);
        assert!(checks
            .iter()
            .any(|c| c.name == "aws-nitrotpm-binding" && !c.valid));
    }

    #[test]
    fn aws_rotation_rejects_wrong_original_nonce_and_pcr_values() {
        for tamper_nonce in [true, false] {
            let mut bundle = aws_rotation_fixture();
            let original = bundle.provider_binding.as_mut().unwrap();
            if tamper_nonce {
                original.binding.qualifying_data = format!("0x{}", "55".repeat(32));
            } else {
                original.pcr_values[0].sha384 = Some(format!("0x{}", "55".repeat(48)));
            }
            let checks = aws_rotation_checks(&bundle);
            assert!(
                checks
                    .iter()
                    .any(|c| c.name == "aws-nitrotpm-binding" && !c.valid),
                "{checks:?}"
            );
        }
    }

    #[test]
    fn aws_rotation_rejects_tampered_original_or_current_quote_signature() {
        for original in [false, true] {
            let mut bundle = aws_rotation_fixture();
            let quote = if original {
                &mut bundle.provider_binding.as_mut().unwrap().tpm_quote
            } else {
                &mut bundle.tpm_quote
            };
            let mut signature = URL_SAFE_NO_PAD.decode(&quote.tpm_signature).unwrap();
            *signature.last_mut().unwrap() ^= 1;
            quote.tpm_signature = URL_SAFE_NO_PAD.encode(signature);
            let checks = aws_rotation_checks(&bundle);
            assert!(
                checks
                    .iter()
                    .any(|c| c.name == "tpm-quote-signature" && !c.valid),
                "{checks:?}"
            );
        }
    }

    #[test]
    fn aws_rotation_still_checks_new_quote_challenge_and_pcr_digest() {
        for tamper_nonce in [true, false] {
            let mut bundle = aws_rotation_fixture();
            if tamper_nonce {
                bundle.binding.qualifying_data = format!("0x{}", "55".repeat(32));
            } else {
                bundle.pcr_values[0].sha384 = Some(format!("0x{}", "55".repeat(48)));
            }
            // The original document remains valid, but the current quote must fail.
            let checks = aws_rotation_checks(&bundle);
            assert!(checks
                .iter()
                .any(|c| c.name == "aws-nitrotpm-binding" && c.valid));
            let mut errors = Vec::new();
            let mut checks = Vec::new();
            verify_raw_quote(&bundle, &mut checks, &mut errors);
            assert!(!errors.is_empty(), "{checks:?}");
        }
    }

    #[test]
    fn aws_rotation_rejects_changed_attestation_key() {
        let mut bundle = aws_rotation_fixture();
        let mut key = URL_SAFE_NO_PAD
            .decode(&bundle.ak_evidence.ak_public)
            .unwrap();
        *key.last_mut().unwrap() ^= 1;
        bundle.ak_evidence.ak_public = URL_SAFE_NO_PAD.encode(key);
        let checks = aws_rotation_checks(&bundle);
        assert!(
            checks
                .iter()
                .any(|c| c.name == "aws-nitrotpm-binding" && !c.valid),
            "{checks:?}"
        );
    }

    #[test]
    fn gcp_indexed_gpt_policy_rejects_changes_outside_gpt() {
        use super::*;
        use atakit_cvm_encoding::pcr_comparison::{IndexedEventSet256, IndexedEventSets256};

        for (pcr_index, count) in [(2, 3usize), (5, 4usize)] {
            let events: Vec<[u8; 32]> = (0..count).map(|i| [i as u8 + 1; 32]).collect();
            let policy = PcrComparison256::DynamicIndexedEventSets(IndexedEventSets256 {
                expected_event_count: count as u16,
                checked_events: (0..count)
                    .filter(|&i| i != 1)
                    .map(|i| IndexedEventSet256 {
                        event_index: i as u16,
                        allowed_values: vec![events[i]],
                    })
                    .collect(),
            });
            let replay = |events: &[[u8; 32]]| {
                events.iter().fold([0u8; 32], |previous, event| {
                    let mut hash = Sha256::new();
                    hash.update(previous);
                    hash.update(event);
                    hash.finalize().into()
                })
            };
            let check = |events: &[[u8; 32]]| {
                evaluate_comparison256(&policy, replay(events), events, pcr_index, 0xff)
            };
            assert!(check(&events).is_ok());
            let mut changed_gpt = events.clone();
            changed_gpt[1] = [99; 32];
            assert!(check(&changed_gpt).is_ok());
            for index in (0..count).filter(|&i| i != 1) {
                let mut changed = events.clone();
                changed[index] = [99; 32];
                assert!(check(&changed)
                    .unwrap_err()
                    .contains("checked event mismatch"));
            }
            let mut extra = events.clone();
            extra.push([99; 32]);
            assert!(check(&extra).unwrap_err().contains("event count mismatch"));
            assert!(check(&events[..count - 1])
                .unwrap_err()
                .contains("event count mismatch"));
            assert!(evaluate_comparison256(
                &policy,
                replay(&events),
                &changed_gpt,
                pcr_index,
                0xff
            )
            .unwrap_err()
            .contains("replay"));
        }
    }

    use super::*;
    use atakit_cvm_encoding::pcr_comparison::{
        encode_dynamic256, encode_static256, encode_static384, DYNAMIC_SUBSEQUENCE, DYNAMIC_SUBSET,
    };
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    #[test]
    fn successful_checks_omit_failure_detail() {
        let mut checks = Vec::new();
        let mut errors = Vec::new();

        record(
            &mut checks,
            &mut errors,
            "successful-check",
            true,
            "this text describes a failure",
        );
        record(
            &mut checks,
            &mut errors,
            "failed-check",
            false,
            "the check failed",
        );

        assert_eq!(checks.len(), 2);
        assert!(checks[0].valid);
        assert_eq!(checks[0].detail, None);
        assert!(!checks[1].valid);
        assert_eq!(checks[1].detail.as_deref(), Some("the check failed"));
        assert_eq!(errors, ["failed-check: the check failed"]);
    }

    #[test]
    fn es256k_verification_matches_contract_canonical_signature_rules() {
        const SECP256K1_ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];

        let signing_key = SigningKey::from_slice(&[7u8; 32]).expect("valid test key");
        let digest = [0x42; 32];
        let (signature, recovery_id): (Signature, RecoveryId) = signing_key
            .sign_prehash(&digest)
            .expect("recoverable ES256K signature");
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let mut encoded = [0u8; 65];
        encoded[..64].copy_from_slice(&signature.to_bytes());
        encoded[64] = recovery_id.to_byte() + 27;

        assert!(recoverable_es256k_signature_matches(
            public_key.as_bytes(),
            digest,
            &encoded
        ));

        let compressed_public_key = signing_key.verifying_key().to_encoded_point(true);
        assert!(!recoverable_es256k_signature_matches(
            compressed_public_key.as_bytes(),
            digest,
            &encoded
        ));

        let mut raw_recovery = encoded;
        raw_recovery[64] -= 27;
        assert!(!recoverable_es256k_signature_matches(
            public_key.as_bytes(),
            digest,
            &raw_recovery
        ));

        let mut high_s = encoded;
        let low_s = signature.s().to_bytes();
        let mut borrow = 0u16;
        for index in (0..32).rev() {
            let order = u16::from(SECP256K1_ORDER[index]);
            let subtrahend = u16::from(low_s[index]) + borrow;
            if order >= subtrahend {
                high_s[32 + index] = (order - subtrahend) as u8;
                borrow = 0;
            } else {
                high_s[32 + index] = (order + 256 - subtrahend) as u8;
                borrow = 1;
            }
        }
        high_s[64] = if encoded[64] == 27 { 28 } else { 27 };
        assert!(!recoverable_es256k_signature_matches(
            public_key.as_bytes(),
            digest,
            &high_s
        ));
    }

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
    fn chain_binding_requires_verifier_selected_coordinates() {
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_trusted_binding(
            BindingMode::Chain,
            11_155_111,
            [0x11; 20],
            None,
            &mut checks,
            &mut errors,
        );
        assert_eq!(
            errors,
            ["trusted-binding-present: chain-bound session verification requires verifier-selected chain coordinates"]
        );
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "trusted-binding-present");
        assert!(!checks[0].valid);
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
            format: 2,
            binding: SessionBinding {
                mode: BindingMode::Local,
                chain_id: 0,
                registry: format!("0x{}", "00".repeat(20)),
                owner_nonce: format!("0x{}", "00".repeat(32)),
                qualifying_data: format!("0x{}", "00".repeat(32)),
            },
            platform: SessionPlatform {
                cloud: "qemu".into(),
                cloud_provenance: test_session_cloud_provenance(SessionCloudProvider::Qemu),
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
                tpms_attest: String::new(),
                tpm_signature: String::new(),
                signature_hash: format!("0x{}", "00".repeat(32)),
                pcr0_startup_locality: 0,
            },
            tpm_certify: TpmCertifyEvidence {
                tpms_attest: String::new(),
                tpm_signature: String::new(),
                tpmt_public: String::new(),
            },
            pcr_values: vec![SessionPcrValue {
                index: 7,
                sha256: Some(format!("0x{}", "11".repeat(32))),
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
                session_key_possession_signature: String::new(),
            },
            session_id: format!("0x{}", "00".repeat(32)),
            policy,
            owner: SessionOwner {
                fingerprint: format!("0x{}", "00".repeat(32)),
                contract_authorization: None,
            },
            provider_binding: None,
        }
    }

    #[test]
    fn session_evidence_json_bounds_collections_and_rejects_unknown_fields() {
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };
        let value = serde_json::to_value(bundle_for_policy(policy)).expect("serialize bundle");

        let mut without_cloud_provenance = value.clone();
        without_cloud_provenance["platform"]
            .as_object_mut()
            .expect("platform object")
            .remove("cloud_provenance");
        let error = serde_json::from_value::<SessionEvidenceBundle>(without_cloud_provenance)
            .expect_err("cloud_provenance must be required");
        assert!(error.to_string().contains("missing field"), "{error}");

        let mut with_cloud_provenance = value.clone();
        with_cloud_provenance["platform"]["cloud_provenance"] = serde_json::json!({
            "source": "dmi",
            "detection": {
                "dmi": {
                    "sys_vendor": "Amazon EC2",
                    "product_name": "m6a.large",
                    "bios_vendor": "Amazon EC2",
                    "detected_cloud": "aws"
                },
                "metadata": {
                    "gcp": {
                        "attempted": false,
                        "matched": false,
                        "http_status": null,
                        "response_headers": {},
                        "response_body": null,
                        "error": null
                    },
                    "azure": {
                        "attempted": false,
                        "matched": false,
                        "http_status": null,
                        "response_headers": {},
                        "response_body": null,
                        "error": null
                    },
                    "aws": {
                        "attempted": false,
                        "matched": false,
                        "http_status": null,
                        "response_headers": {},
                        "response_body": null,
                        "error": null
                    },
                    "detected_cloud": "unknown",
                    "conflict": false
                }
            },
            "user_provided": null
        });
        let decoded = serde_json::from_value::<SessionEvidenceBundle>(with_cloud_provenance)
            .expect("current portal cloud_provenance must decode");
        let provenance = decoded.platform.cloud_provenance;
        assert_eq!(provenance.source, SessionCloudSource::Dmi);
        assert_eq!(
            provenance.detection.dmi.detected_cloud,
            SessionCloudProvider::Aws
        );

        let mut too_many_pcrs = value.clone();
        too_many_pcrs["pcr_values"] = serde_json::Value::Array(
            (0..=MAX_SESSION_PCRS)
                .map(|index| {
                    serde_json::json!({
                        "index": index,
                        "sha256": null,
                        "sha384": null
                    })
                })
                .collect(),
        );
        let error = serde_json::from_value::<SessionEvidenceBundle>(too_many_pcrs)
            .expect_err("more than 24 PCR entries must fail");
        assert!(
            error.to_string().contains("more than 24 entries"),
            "{error}"
        );

        let valid_sha256_hash = format!("0x{}", "00".repeat(32));
        let mut invalid_event_hash = value.clone();
        invalid_event_hash["event_log_hashes"] = serde_json::json!([{
            "pcr_index": 10,
            "sha256": [""],
            "sha384": []
        }]);
        let error = serde_json::from_value::<SessionEvidenceBundle>(invalid_event_hash)
            .expect_err("an empty event hash must fail during parsing");
        assert!(
            error
                .to_string()
                .contains("event hash must be 0x-prefixed and encode exactly 32 bytes"),
            "{error}"
        );

        let mut too_many_event_hashes = value.clone();
        too_many_event_hashes["event_log_hashes"] = serde_json::json!([{
            "pcr_index": 10,
            "sha256": vec![valid_sha256_hash; MAX_SESSION_EVENT_HASHES_PER_BANK + 1],
            "sha384": []
        }]);
        let error = serde_json::from_value::<SessionEvidenceBundle>(too_many_event_hashes)
            .expect_err("more than 65535 event hashes must fail");
        assert!(
            error.to_string().contains("more than 65535 entries"),
            "{error}"
        );

        assert!(total_session_event_hash_count_is_valid([
            MAX_SESSION_EVENT_HASHES_PER_BANK,
            MAX_SESSION_EVENT_HASHES_PER_BANK,
        ]));
        assert!(!total_session_event_hash_count_is_valid([
            MAX_SESSION_EVENT_HASHES_PER_BANK,
            MAX_SESSION_EVENT_HASHES_PER_BANK,
            1,
        ]));

        let mut unknown_field = value;
        unknown_field["unexpected"] = serde_json::Value::Bool(true);
        let error = serde_json::from_value::<SessionEvidenceBundle>(unknown_field)
            .expect_err("unknown bundle fields must fail");
        assert!(error.to_string().contains("unknown field"), "{error}");

        let error = serde_json::from_value::<SessionRequestBinding>(serde_json::json!({
            "challenge": URL_SAFE_NO_PAD.encode([0x55; 32]),
            "signature": "0x",
            "unexpected": true
        }))
        .expect_err("unknown request-binding fields must fail");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    fn tdx_bundle_for_policy(policy: SessionPolicy) -> SessionEvidenceBundle {
        let mut bundle = bundle_for_policy(policy);
        let mut report = vec![0u8; crate::TDX_QUOTE_HEADER_LEN + 584];
        report[0..2].copy_from_slice(&4u16.to_le_bytes());
        report[4..8].copy_from_slice(&crate::TDX_TEE_TYPE.to_le_bytes());
        report[crate::TDX_QUOTE_HEADER_LEN + crate::TDX_REPORT_ATTRIBUTES_OFFSET + 3] = 0x10;
        bundle.platform.attestation_mode = SessionAttestationMode::Hardware;
        bundle.platform.tee = "tdx".into();
        bundle.tee_evidence.kind = "tdx".into();
        bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);
        bundle
    }

    fn snp_bundle_for_policy(policy: SessionPolicy) -> SessionEvidenceBundle {
        let mut bundle = bundle_for_policy(policy);
        let mut report = vec![0u8; crate::SNP_REPORT_SIZE];
        report[crate::SNP_REPORT_VERSION_OFFSET..crate::SNP_REPORT_VERSION_OFFSET + 4]
            .copy_from_slice(&3u32.to_le_bytes());
        report[crate::SNP_REPORT_POLICY_OFFSET..crate::SNP_REPORT_POLICY_OFFSET + 8]
            .copy_from_slice(&(1u64 << 17).to_le_bytes());
        report[crate::SNP_REPORT_SIG_ALGO_OFFSET..crate::SNP_REPORT_SIG_ALGO_OFFSET + 4]
            .copy_from_slice(&crate::SNP_SIG_ALGO_ECDSA_P384_SHA384.to_le_bytes());
        report[crate::SNP_REPORT_CPUID_OFFSET..crate::SNP_REPORT_CPUID_OFFSET + 3]
            .copy_from_slice(&[0x19, 0, 0]);
        bundle.platform.attestation_mode = SessionAttestationMode::Hardware;
        bundle.platform.tee = "sev-snp".into();
        bundle.tee_evidence.kind = "sev-snp".into();
        bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);
        bundle
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
        let comparison = |value: &[u8]| format!("0x{}", hex::encode(value));

        let static_policy = SessionPcrPolicy {
            pcr_index: 0,
            comparison: comparison(&encode_static256(final_value)),
        };
        evaluate_session_pcr_policy(&static_policy, final_value, &events).unwrap();
        for malformed in ["0x".to_string(), format!("{}00", static_policy.comparison)] {
            let policy = SessionPcrPolicy {
                comparison: malformed,
                ..static_policy.clone()
            };
            assert!(evaluate_session_pcr_policy(&policy, final_value, &events).is_err());
        }

        let subset = SessionPcrPolicy {
            pcr_index: 10,
            comparison: comparison(
                &encode_dynamic256(DYNAMIC_SUBSET, vec![events[2], events[0]]).unwrap(),
            ),
        };
        evaluate_session_pcr_policy(&subset, final_value, &events).unwrap();
        let empty_subset = SessionPcrPolicy {
            comparison: comparison(&encode_dynamic256(DYNAMIC_SUBSET, Vec::new()).unwrap()),
            ..subset.clone()
        };
        assert_eq!(
            evaluate_session_pcr_policy(&empty_subset, final_value, &events).unwrap_err(),
            "DYNAMIC_SUBSET required landmark is missing"
        );
        let missing_subset = SessionPcrPolicy {
            comparison: comparison(
                &encode_dynamic256(DYNAMIC_SUBSET, vec![events[0], [4u8; 32]]).unwrap(),
            ),
            ..subset
        };
        assert_eq!(
            evaluate_session_pcr_policy(&missing_subset, final_value, &events).unwrap_err(),
            "DYNAMIC_SUBSET required landmark is missing"
        );

        let subsequence = SessionPcrPolicy {
            pcr_index: 10,
            comparison: comparison(
                &encode_dynamic256(DYNAMIC_SUBSEQUENCE, vec![events[0], events[2]]).unwrap(),
            ),
        };
        evaluate_session_pcr_policy(&subsequence, final_value, &events).unwrap();
        let empty_subsequence = SessionPcrPolicy {
            comparison: comparison(&encode_dynamic256(DYNAMIC_SUBSEQUENCE, Vec::new()).unwrap()),
            ..subsequence.clone()
        };
        assert_eq!(
            evaluate_session_pcr_policy(&empty_subsequence, final_value, &events).unwrap_err(),
            "DYNAMIC_SUBSEQUENCE required landmark is missing"
        );
        let reversed = SessionPcrPolicy {
            comparison: comparison(
                &encode_dynamic256(DYNAMIC_SUBSEQUENCE, vec![events[2], events[0]]).unwrap(),
            ),
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
            comparison: format!("0x{}", hex::encode(encode_static256([0x11; 32]))),
        };
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock {
                pcr_specs384: Vec::new(),
                pcr_specs256: vec![pcr.clone()],
            },
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };
        let bundle = bundle_for_policy(policy);
        let trusted = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock {
                pcr_specs384: Vec::new(),
                pcr_specs256: vec![pcr],
            },
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
            effective_attributes: vec![SessionAttribute {
                key: [0x10; 32],
                value: [0x20; 32],
            }],
            attribute_requirements: vec![SessionAttributeRequirement {
                key: [0x10; 32],
                allowed_values: vec![[0x20; 32]],
            }],
            amd_snp_security_policies: Vec::new(),
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(&bundle, &trusted, Some(1), &mut checks, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");

        let untrusted = TrustedSessionPolicy {
            workload_id: [9; 32],
            ..trusted.clone()
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(&bundle, &untrusted, Some(1), &mut checks, &mut errors);
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
        verify_policies(
            &bundle,
            &invalid_attribute,
            Some(1),
            &mut checks,
            &mut errors,
        );
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
        verify_policies(
            &bundle,
            &duplicate_attributes,
            Some(1),
            &mut checks,
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.starts_with("trusted-effective-attribute-keys:")));
    }

    #[test]
    fn trusted_policy_projection_preserves_named_azure_blocks() {
        let rule = |pcr_index| SessionPcrPolicy {
            pcr_index,
            comparison: format!("0x{}", hex::encode(encode_static256([pcr_index; 32]))),
        };
        let invariant_pcr_policy = SessionPcrPolicyBlock {
            pcr_specs256: [4, 9, 11].into_iter().map(rule).collect(),
            pcr_specs384: Vec::new(),
        };
        let variant_pcr_policy = SessionPcrPolicyBlock {
            pcr_specs256: [0, 2, 3, 7].into_iter().map(rule).collect(),
            pcr_specs384: Vec::new(),
        };
        let workload_pcr_policy = SessionPcrPolicyBlock {
            pcr_specs256: vec![rule(23)],
            pcr_specs384: Vec::new(),
        };
        let bundle = bundle_for_policy(SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: invariant_pcr_policy.clone(),
            variant_pcr_policy: variant_pcr_policy.clone(),
            workload_pcr_policy: workload_pcr_policy.clone(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        });
        let trusted = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy,
            variant_pcr_policy,
            workload_pcr_policy,
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
            effective_attributes: Vec::new(),
            attribute_requirements: Vec::new(),
            amd_snp_security_policies: Vec::new(),
        };

        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(&bundle, &trusted, None, &mut checks, &mut errors);
        assert!(checks
            .iter()
            .any(|check| { check.name == "trusted-pcr-policy-projection" && check.valid }));

        let empty_projection = bundle_for_policy(SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            // An empty projection supplies no policy. Its bank selection is
            // only the shape of the Quote the portal collected, so it is not
            // a second trusted policy input.
            pcr_bank_selection: PcrBankSelection::Sha384,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        });
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(&empty_projection, &trusted, None, &mut checks, &mut errors);
        assert!(checks
            .iter()
            .any(|check| { check.name == "trusted-pcr-policy-projection" && check.valid }));

        let mut moved_between_blocks = trusted.clone();
        let moved_rule = moved_between_blocks
            .variant_pcr_policy
            .pcr_specs256
            .remove(0);
        moved_between_blocks
            .invariant_pcr_policy
            .pcr_specs256
            .push(moved_rule);
        assert_eq!(
            trusted.complete_pcr_specs256(),
            moved_between_blocks.complete_pcr_specs256(),
            "the flattened rule sequence is deliberately unchanged"
        );

        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_policies(
            &bundle,
            &moved_between_blocks,
            None,
            &mut checks,
            &mut errors,
        );
        assert!(checks
            .iter()
            .any(|check| { check.name == "trusted-pcr-policy-projection" && !check.valid }));
    }

    #[test]
    fn sha384_session_does_not_evaluate_committed_sha256_rules() {
        let pcr256 = SessionPcrPolicy {
            pcr_index: 7,
            comparison: format!("0x{}", hex::encode(encode_static256([0x11; 32]))),
        };
        let pcr384 = SessionPcrPolicy384 {
            pcr_index: 7,
            comparison: format!("0x{}", hex::encode(encode_static384([0x22; 48]))),
        };
        let mut bundle = bundle_for_policy(SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha384,
            invariant_pcr_policy: SessionPcrPolicyBlock {
                pcr_specs256: vec![pcr256.clone()],
                pcr_specs384: vec![pcr384.clone()],
            },
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        });
        bundle.pcr_values[0].sha256 = None;
        bundle.pcr_values[0].sha384 = Some(format!("0x{}", "22".repeat(48)));
        let trusted = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_bank_selection: PcrBankSelection::Sha384,
            invariant_pcr_policy: SessionPcrPolicyBlock {
                pcr_specs256: vec![pcr256],
                pcr_specs384: vec![pcr384],
            },
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
            effective_attributes: Vec::new(),
            attribute_requirements: Vec::new(),
            amd_snp_security_policies: Vec::new(),
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();

        verify_policies(&bundle, &trusted, None, &mut checks, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
        assert!(!checks
            .iter()
            .any(|check| check.name == "pcr-policy-sha256-7"));
        assert!(checks
            .iter()
            .any(|check| check.name == "pcr-policy-sha384-7" && check.valid));
    }

    #[test]
    fn verified_tdx_debug_drives_base_image_and_workload_policy() {
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };
        let mut bundle = tdx_bundle_for_policy(policy);
        let mut report = URL_SAFE_NO_PAD.decode(&bundle.tee_evidence.report).unwrap();
        report[crate::TDX_QUOTE_HEADER_LEN + crate::TDX_REPORT_ATTRIBUTES_OFFSET] = 1;
        bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);

        let base_policy = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
            effective_attributes: vec![SessionAttribute {
                key: atakit_core::tee_attributes::INTEL_TDX_DEBUG_KEY,
                value: atakit_core::tee_attributes::ATTRIBUTE_TRUE,
            }],
            attribute_requirements: vec![SessionAttributeRequirement {
                key: atakit_core::tee_attributes::INTEL_TDX_DEBUG_KEY,
                allowed_values: vec![
                    atakit_core::tee_attributes::ATTRIBUTE_FALSE,
                    atakit_core::tee_attributes::ATTRIBUTE_TRUE,
                ],
            }],
            amd_snp_security_policies: Vec::new(),
        };

        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &base_policy, Some(1), &mut checks, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");

        let missing_base_declaration = TrustedSessionPolicy {
            effective_attributes: Vec::new(),
            ..base_policy.clone()
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(
            &bundle,
            &missing_base_declaration,
            Some(1),
            &mut checks,
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.starts_with("tee-attribute-base-image-atakit.attestation.v1.tee.intel-tdx")
        }));

        let missing_workload_requirement = TrustedSessionPolicy {
            attribute_requirements: Vec::new(),
            ..base_policy
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(
            &bundle,
            &missing_workload_requirement,
            Some(1),
            &mut checks,
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.starts_with("tee-attribute-workload-atakit.attestation.v1.tee.intel-tdx")
        }));
    }

    #[test]
    fn verified_tdx_tcb_status_requires_canonical_base_and_workload_masks() {
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };
        let bundle = tdx_bundle_for_policy(policy);
        let key = atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_KEY;
        let relaxed_mask = atakit_core::tee_attributes::u16_value(0x9);
        let trusted = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
            effective_attributes: vec![SessionAttribute {
                key,
                value: relaxed_mask,
            }],
            attribute_requirements: vec![SessionAttributeRequirement {
                key,
                allowed_values: vec![relaxed_mask],
            }],
            amd_snp_security_policies: Vec::new(),
        };

        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &trusted, Some(0x8), &mut checks, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");

        let invalid_base = TrustedSessionPolicy {
            effective_attributes: vec![SessionAttribute {
                key,
                value: atakit_core::tee_attributes::u16_value(0x401),
            }],
            ..trusted.clone()
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &invalid_base, Some(0x8), &mut checks, &mut errors);
        assert!(errors
            .iter()
            .any(|error| { error.starts_with("tee-attribute-base-image-intel-tdx-tcb-status:") }));

        let invalid_workload = TrustedSessionPolicy {
            attribute_requirements: vec![SessionAttributeRequirement {
                key,
                allowed_values: vec![relaxed_mask, relaxed_mask],
            }],
            ..trusted
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(
            &bundle,
            &invalid_workload,
            Some(0x8),
            &mut checks,
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| { error.starts_with("tee-attribute-workload-intel-tdx-tcb-status:") }));
    }

    #[test]
    fn verified_amd_snp_registry_defaults_apply_to_session_evidence() {
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };
        let mut bundle = snp_bundle_for_policy(policy);
        let mut report = URL_SAFE_NO_PAD.decode(&bundle.tee_evidence.report).unwrap();
        let raw_tcb = [4, 0, 0, 0, 0, 0, 29, 222];
        for offset in [
            crate::SNP_REPORT_CURRENT_TCB_OFFSET,
            crate::SNP_REPORT_REPORTED_TCB_OFFSET,
            crate::SNP_REPORT_COMMITTED_TCB_OFFSET,
            crate::SNP_REPORT_LAUNCH_TCB_OFFSET,
        ] {
            report[offset..offset + 8].copy_from_slice(&raw_tcb);
        }
        report[crate::SNP_REPORT_PLATFORM_INFO_OFFSET..crate::SNP_REPORT_PLATFORM_INFO_OFFSET + 8]
            .copy_from_slice(&0x20u64.to_le_bytes());
        bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);

        let trusted = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
            effective_attributes: Vec::new(),
            attribute_requirements: Vec::new(),
            amd_snp_security_policies: vec![crate::AmdSnpSecurityPolicy {
                cpuid: 0x190000,
                minimum_tcb: atakit_core::tee_attributes::parse_bytes32_hex(
                    "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
                )
                .unwrap(),
                platform_info_policy: atakit_core::tee_attributes::parse_bytes32_hex(
                    "0x0000000000000000000000000000000000000000000000000000000000000020",
                )
                .unwrap(),
                required_launch_mitigation_vector: 0,
                required_current_mitigation_vector: 0,
            }],
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &trusted, None, &mut checks, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");

        let mut missing_default = trusted;
        missing_default.amd_snp_security_policies.clear();
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &missing_default, None, &mut checks, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.starts_with("amd-sev-snp-registry-default:")));
    }

    #[test]
    fn verified_amd_snp_mitigation_vectors_apply_to_session_evidence() {
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };
        let mut bundle = snp_bundle_for_policy(policy);
        let mut report = URL_SAFE_NO_PAD.decode(&bundle.tee_evidence.report).unwrap();
        report[crate::SNP_REPORT_VERSION_OFFSET..crate::SNP_REPORT_VERSION_OFFSET + 4]
            .copy_from_slice(&5u32.to_le_bytes());
        report[crate::SNP_REPORT_LAUNCH_MITIGATION_VECTOR_OFFSET
            ..crate::SNP_REPORT_LAUNCH_MITIGATION_VECTOR_OFFSET + 8]
            .copy_from_slice(&0b1011u64.to_le_bytes());
        report[crate::SNP_REPORT_CURRENT_MITIGATION_VECTOR_OFFSET
            ..crate::SNP_REPORT_CURRENT_MITIGATION_VECTOR_OFFSET + 8]
            .copy_from_slice(&0b1110u64.to_le_bytes());
        bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);

        let trusted = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
            effective_attributes: Vec::new(),
            attribute_requirements: Vec::new(),
            amd_snp_security_policies: vec![crate::AmdSnpSecurityPolicy {
                cpuid: 0x190000,
                minimum_tcb: [0; 32],
                platform_info_policy: [0; 32],
                required_launch_mitigation_vector: 0b0011,
                required_current_mitigation_vector: 0b1100,
            }],
        };
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &trusted, None, &mut checks, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(checks
            .iter()
            .any(|check| { check.name == "amd-sev-snp-mitigation-vector-policy" && check.valid }));

        let mut missing_current_bit = bundle.clone();
        let mut report = URL_SAFE_NO_PAD
            .decode(&missing_current_bit.tee_evidence.report)
            .unwrap();
        report[crate::SNP_REPORT_CURRENT_MITIGATION_VECTOR_OFFSET
            ..crate::SNP_REPORT_CURRENT_MITIGATION_VECTOR_OFFSET + 8]
            .copy_from_slice(&0b1000u64.to_le_bytes());
        missing_current_bit.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(
            &missing_current_bit,
            &trusted,
            None,
            &mut checks,
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.starts_with("amd-sev-snp-mitigation-vector-policy:")
                && error.contains("CURRENT_MIT_VECTOR")
        }));

        let version_three = snp_bundle_for_policy(bundle.policy.clone());
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&version_three, &trusted, None, &mut checks, &mut errors);
        assert!(errors.iter().any(|error| {
            error.starts_with("amd-sev-snp-mitigation-vector-policy:")
                && error.contains("version 5 is required")
        }));
    }

    #[test]
    fn verified_amd_snp_policy_allows_only_coordinated_relaxation() {
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };
        let mut bundle = snp_bundle_for_policy(policy);
        let mut report = URL_SAFE_NO_PAD.decode(&bundle.tee_evidence.report).unwrap();
        let lower_raw_tcb = [3, 0, 0, 0, 0, 0, 29, 222];
        for offset in [
            crate::SNP_REPORT_CURRENT_TCB_OFFSET,
            crate::SNP_REPORT_REPORTED_TCB_OFFSET,
            crate::SNP_REPORT_COMMITTED_TCB_OFFSET,
            crate::SNP_REPORT_LAUNCH_TCB_OFFSET,
        ] {
            report[offset..offset + 8].copy_from_slice(&lower_raw_tcb);
        }
        report[crate::SNP_REPORT_PLATFORM_INFO_OFFSET..crate::SNP_REPORT_PLATFORM_INFO_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);

        let lower_tcb = atakit_core::tee_attributes::parse_bytes32_hex(
            "0x00000000de1d000300000000de1d000300000000de1d000300000000de1d0003",
        )
        .unwrap();
        let lower_platform = [0; 32];
        let trusted = TrustedSessionPolicy {
            workload_id: [1; 32],
            base_image_id: [2; 32],
            platform_profile_id: [3; 32],
            measurement_variant_id: [4; 32],
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
            effective_attributes: vec![
                SessionAttribute {
                    key: atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_KEY,
                    value: lower_tcb,
                },
                SessionAttribute {
                    key: atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
                    value: lower_platform,
                },
            ],
            attribute_requirements: vec![
                SessionAttributeRequirement {
                    key: atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_KEY,
                    allowed_values: vec![lower_tcb],
                },
                SessionAttributeRequirement {
                    key: atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
                    allowed_values: vec![lower_platform],
                },
            ],
            amd_snp_security_policies: vec![crate::AmdSnpSecurityPolicy {
                cpuid: 0x190000,
                minimum_tcb: atakit_core::tee_attributes::parse_bytes32_hex(
                    "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
                )
                .unwrap(),
                platform_info_policy: atakit_core::tee_attributes::parse_bytes32_hex(
                    "0x0000000000000000000000000000000000000000000000000000000000000020",
                )
                .unwrap(),
                required_launch_mitigation_vector: 0,
                required_current_mitigation_vector: 0,
            }],
        };

        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &trusted, None, &mut checks, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");

        let mut base_only = trusted.clone();
        base_only.attribute_requirements.clear();
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &base_only, None, &mut checks, &mut errors);
        assert!(errors
            .iter()
            .any(|error| { error.starts_with("tee-attribute-workload-amd-sev-snp-tcb-minimum:") }));
        assert!(errors.iter().any(|error| {
            error.starts_with("tee-attribute-workload-amd-sev-snp-platform-info-policy:")
        }));

        let mut workload_only = trusted;
        workload_only.effective_attributes.clear();
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_attribute_policy(&bundle, &workload_only, None, &mut checks, &mut errors);
        assert!(errors.iter().any(|error| {
            error.starts_with("tee-attribute-base-image-amd-sev-snp-tcb-minimum:")
        }));
        assert!(errors.iter().any(|error| {
            error.starts_with("tee-attribute-base-image-amd-sev-snp-platform-info-policy:")
        }));
    }

    #[test]
    fn verified_tee_attribute_policy_matrices_match_session_registry() {
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };

        for attribute in atakit_core::tee_attributes::VerifiedTeeAttribute::BOOLEAN {
            for actual in [false, true] {
                for base_mode in 0..3 {
                    for workload_mode in 0..3 {
                        let bundle = match attribute {
                            atakit_core::tee_attributes::VerifiedTeeAttribute::IntelTdxDebug => {
                                let mut bundle = tdx_bundle_for_policy(policy.clone());
                                if actual {
                                    let mut report =
                                        URL_SAFE_NO_PAD.decode(&bundle.tee_evidence.report).unwrap();
                                    report[crate::TDX_QUOTE_HEADER_LEN
                                        + crate::TDX_REPORT_ATTRIBUTES_OFFSET] = 1;
                                    bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);
                                }
                                bundle
                            }
                            atakit_core::tee_attributes::VerifiedTeeAttribute::AmdSevSnpDebug
                            | atakit_core::tee_attributes::VerifiedTeeAttribute::AmdSevSnpMigrateMa => {
                                let mut bundle = snp_bundle_for_policy(policy.clone());
                                if actual {
                                    let mut report =
                                        URL_SAFE_NO_PAD.decode(&bundle.tee_evidence.report).unwrap();
                                    let bit = match attribute {
                                        atakit_core::tee_attributes::VerifiedTeeAttribute::AmdSevSnpDebug => 19,
                                        atakit_core::tee_attributes::VerifiedTeeAttribute::AmdSevSnpMigrateMa => 18,
                                        _ => unreachable!(),
                                    };
                                    let policy = (1u64 << 17) | (1u64 << bit);
                                    report[crate::SNP_REPORT_POLICY_OFFSET
                                        ..crate::SNP_REPORT_POLICY_OFFSET + 8]
                                        .copy_from_slice(&policy.to_le_bytes());
                                    bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(report);
                                }
                                bundle
                            }
                            atakit_core::tee_attributes::VerifiedTeeAttribute::IntelTdxTcbStatusAllowed
                            | atakit_core::tee_attributes::VerifiedTeeAttribute::AmdSevSnpTcbMinimum
                            | atakit_core::tee_attributes::VerifiedTeeAttribute::AmdSevSnpPlatformInfoPolicy => {
                                unreachable!("Boolean test matrix excludes packed attributes")
                            }
                        };

                        let effective_attributes = if base_mode == 0 {
                            Vec::new()
                        } else {
                            vec![SessionAttribute {
                                key: attribute.key(),
                                value: atakit_core::tee_attributes::bool_value(base_mode == 2),
                            }]
                        };
                        let attribute_requirements = match workload_mode {
                            0 => Vec::new(),
                            1 => vec![SessionAttributeRequirement {
                                key: attribute.key(),
                                allowed_values: vec![atakit_core::tee_attributes::ATTRIBUTE_FALSE],
                            }],
                            2 => vec![SessionAttributeRequirement {
                                key: attribute.key(),
                                allowed_values: vec![
                                    atakit_core::tee_attributes::ATTRIBUTE_FALSE,
                                    atakit_core::tee_attributes::ATTRIBUTE_TRUE,
                                ],
                            }],
                            _ => unreachable!(),
                        };
                        let trusted = TrustedSessionPolicy {
                            workload_id: [1; 32],
                            base_image_id: [2; 32],
                            platform_profile_id: [3; 32],
                            measurement_variant_id: [4; 32],
                            pcr_bank_selection: PcrBankSelection::Sha256,
                            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
                            variant_pcr_policy: SessionPcrPolicyBlock::default(),
                            workload_pcr_policy: SessionPcrPolicyBlock::default(),
                            provider_pcr_policy: SessionPcrPolicyBlock::default(),
                            effective_attributes,
                            attribute_requirements,
                            amd_snp_security_policies: vec![crate::AmdSnpSecurityPolicy {
                                cpuid: 0x190000,
                                minimum_tcb: [0; 32],
                                platform_info_policy: [0; 32],
                                required_launch_mitigation_vector: 0,
                                required_current_mitigation_vector: 0,
                            }],
                        };

                        let mut checks = Vec::new();
                        let mut errors = Vec::new();
                        verify_attribute_policy(
                            &bundle,
                            &trusted,
                            Some(1),
                            &mut checks,
                            &mut errors,
                        );

                        let base_matches = if actual {
                            base_mode == 2
                        } else {
                            base_mode != 2
                        };
                        let workload_permits = !actual || workload_mode == 2;
                        assert_eq!(
                            errors.is_empty(),
                            base_matches && workload_permits,
                            "{} actual={actual} base_mode={base_mode} workload_mode={workload_mode}: {errors:?}",
                            attribute.name()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn verified_tee_report_fields_reject_unsupported_migration() {
        let policy = SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        };
        let mut bundle = tdx_bundle_for_policy(policy);
        let mut quote = vec![0u8; crate::TDX_QUOTE_HEADER_LEN + 6 + 648];
        quote[0..2].copy_from_slice(&5u16.to_le_bytes());
        quote[4..8].copy_from_slice(&crate::TDX_TEE_TYPE.to_le_bytes());
        quote[crate::TDX_QUOTE_HEADER_LEN..crate::TDX_QUOTE_HEADER_LEN + 2]
            .copy_from_slice(&crate::TDX_BODY_TD_REPORT15_TYPE.to_le_bytes());
        let start = crate::TDX_QUOTE_HEADER_LEN + 6;
        quote[start + crate::TDX_REPORT_ATTRIBUTES_OFFSET + 3] = 0x10;
        quote[start + crate::TDX_REPORT15_MR_SERVICETD_OFFSET] = 1;
        bundle.tee_evidence.report = URL_SAFE_NO_PAD.encode(quote);

        assert!(verified_tee_attribute_states(&bundle)
            .unwrap_err()
            .contains("MR_SERVICETD"));
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
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
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
        let amd_roots = CertificateTrust::default();
        let amd_snp_collateral = AmdSnpVerificationCollateral::from_vcek_chain(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![],
        );
        verify_gcp_platform(
            &bundle,
            &CertificateTrust::default(),
            Some((&amd_roots, &amd_snp_collateral)),
            None,
            SystemTime::now(),
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
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        });
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        verify_production_evidence_kind(&bundle, &mut checks, &mut errors);
        let _ = verify_raw_quote(&bundle, &mut checks, &mut errors);
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
    fn session_projection_accepts_an_additional_authenticated_sha384_bank() {
        let mut bundle = bundle_for_policy(SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        });
        bundle.event_log_hashes = vec![SessionEventHashes {
            pcr_index: 7,
            sha256: Vec::new(),
            sha384: Vec::new(),
        }];
        bundle.pcr_values[0].sha384 = Some(format!("0x{}", "22".repeat(48)));
        let authenticated = vec![crate::PcrEvidence {
            index: 7,
            sha256: bundle.pcr_values[0].sha256.clone(),
            sha384: bundle.pcr_values[0].sha384.clone(),
        }];
        let mut checks = Vec::new();
        let mut errors = Vec::new();

        verify_quote_projection(&bundle, Some(&authenticated), &mut checks, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn session_projection_accepts_sha384_only_authentication_for_sha384_policy() {
        let mut bundle = bundle_for_policy(SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha384,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        });
        bundle.event_log_hashes = vec![SessionEventHashes {
            pcr_index: 7,
            sha256: Vec::new(),
            sha384: Vec::new(),
        }];
        bundle.pcr_values[0].sha256 = None;
        bundle.pcr_values[0].sha384 = Some(format!("0x{}", "22".repeat(48)));
        let authenticated = vec![crate::PcrEvidence {
            index: 7,
            sha256: None,
            sha384: bundle.pcr_values[0].sha384.clone(),
        }];
        let mut checks = Vec::new();
        let mut errors = Vec::new();

        verify_quote_projection(&bundle, Some(&authenticated), &mut checks, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn session_projection_rejects_sha384_only_authentication() {
        let mut bundle = bundle_for_policy(SessionPolicy {
            workload_id: format!("0x{}", "01".repeat(32)),
            base_image_id: format!("0x{}", "02".repeat(32)),
            platform_profile_id: format!("0x{}", "03".repeat(32)),
            measurement_variant_id: format!("0x{}", "04".repeat(32)),
            pcr_bank_selection: PcrBankSelection::Sha256,
            invariant_pcr_policy: SessionPcrPolicyBlock::default(),
            variant_pcr_policy: SessionPcrPolicyBlock::default(),
            workload_pcr_policy: SessionPcrPolicyBlock::default(),
            provider_pcr_policy: SessionPcrPolicyBlock::default(),
        });
        bundle.event_log_hashes = vec![SessionEventHashes {
            pcr_index: 7,
            sha256: Vec::new(),
            sha384: Vec::new(),
        }];
        bundle.pcr_values[0].sha384 = Some(format!("0x{}", "22".repeat(48)));
        let authenticated = vec![crate::PcrEvidence {
            index: 7,
            sha256: None,
            sha384: bundle.pcr_values[0].sha384.clone(),
        }];
        let mut checks = Vec::new();
        let mut errors = Vec::new();

        verify_quote_projection(&bundle, Some(&authenticated), &mut checks, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.starts_with("pcr-bank-projection:")));
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

    #[test]
    fn packed_session_requirement_rejects_malformed_value_counts() {
        let key = [0x11; 32];
        let default_value = [0x22; 32];
        let explicit_value = [0x33; 32];
        let requirement = |allowed_values: Vec<[u8; 32]>| {
            vec![SessionAttributeRequirement {
                key,
                allowed_values,
            }]
        };

        // An absent requirement defers to the registry default.
        assert_eq!(
            resolve_packed_session_requirement(&[], key, default_value).unwrap(),
            default_value
        );
        assert_eq!(
            resolve_packed_session_requirement(
                &requirement(vec![explicit_value]),
                key,
                default_value,
            )
            .unwrap(),
            explicit_value
        );
        // A present-but-malformed requirement must fail rather than silently
        // resolving to the registry default the workload never selected.
        for allowed_values in [Vec::new(), vec![explicit_value, explicit_value]] {
            let error = resolve_packed_session_requirement(
                &requirement(allowed_values),
                key,
                default_value,
            )
            .unwrap_err();
            assert!(error.contains("must contain exactly one value"), "{error}");
        }
    }
}
