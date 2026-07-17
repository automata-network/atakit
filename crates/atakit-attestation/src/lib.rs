use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use k256::ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::EncodedPoint;
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256, Sha384};
use sha3::Keccak256;
use signature::Verifier;
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

mod session;
mod verification_core;
pub use session::*;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("invalid base64url field {field}: {detail}")]
    Base64 { field: &'static str, detail: String },
    #[error("invalid hex field {field}: {detail}")]
    Hex { field: &'static str, detail: String },
    #[error("measurement pack parse failed: {0}")]
    MeasurementPack(String),
    #[error("measurement pack signature verification failed: {0}")]
    MeasurementPackSignature(String),
}

pub type Result<T> = std::result::Result<T, AttestationError>;

const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_ECC: u16 = 0x0023;
const TDX_QUOTE_HEADER_LEN: usize = 48;
const TDX_QUOTE_V5_BODY_HEADER_LEN: usize = 6;
const TDX_TEE_TYPE: u32 = 0x0000_0081;
const TDX_BODY_TD_REPORT10_TYPE: u16 = 2;
const TDX_BODY_TD_REPORT15_TYPE: u16 = 3;
const TDX_REPORT_RTMR3_OFFSET: usize = 472;
const TDX_REPORT_REPORT_DATA_OFFSET: usize = 520;
const GCP_TDX_UUID_LEN: usize = 16;
const SNP_REPORT_REPORT_ID_OFFSET: usize = 0x140;
const SNP_REPORT_REPORT_ID_LEN: usize = 32;
const SNP_REPORT_SIGNATURE_OFFSET: usize = 0x2a0;
const SNP_REPORT_SIGNED_LEN: usize = 0x2a0;
const SNP_REPORT_MIN_LEN: usize = 0x4a0;
const SNP_REPORT_SIG_ALGO_OFFSET: usize = 0x34;
const SNP_REPORT_KEY_SETTINGS_OFFSET: usize = 0x48;
const SNP_REPORT_REPORTED_TCB_OFFSET: usize = 0x180;
const SNP_REPORT_CHIP_ID_OFFSET: usize = 0x1a0;
const SNP_SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;
const SNP_CERT_TABLE_ARK_GUID: [u8; 16] = [
    0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae,
];
const SNP_CERT_TABLE_ASK_GUID: [u8; 16] = [
    0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82,
];
const SNP_CERT_TABLE_VCEK_GUID: [u8; 16] = [
    0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];
const SNP_CERT_TABLE_VLEK_GUID: [u8; 16] = [
    0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsAttestationResponse {
    pub format: u8,
    pub nonce: String,
    pub tls_cert_der: String,
    pub tls_cert_sha256: String,
    pub qualifying_data: String,
    pub platform: PlatformEvidence,
    pub tpm: TpmEvidence,
    #[serde(default)]
    pub tee_evidence: Option<TeeEvidence>,
    #[serde(default)]
    pub ak_binding: Option<AkBinding>,
    #[serde(default)]
    pub collateral: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformEvidence {
    pub cloud: String,
    pub tee: String,
    pub machine_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpmEvidence {
    pub ak_public: String,
    pub quote: String,
    pub signature: String,
    #[serde(default)]
    pub pcrs: Vec<PcrEvidence>,
    #[serde(default)]
    pub event_log_hashes: Vec<PcrEventHashes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrEvidence {
    pub index: u8,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub sha384: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PcrEventHashes {
    pub pcr_index: u8,
    #[serde(default)]
    pub sha256: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeEvidence {
    pub kind: String,
    pub report: String,
    #[serde(default)]
    pub auxiliary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkBinding {
    pub kind: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementPack {
    pub schema: String,
    pub revision: u64,
    #[serde(rename = "publishedAt")]
    pub published_at: String,
    #[serde(rename = "baseImage")]
    pub base_image: BaseImage,
    #[serde(default)]
    pub profiles: Vec<MeasurementProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseImage {
    pub name: String,
    pub version: String,
    pub id: String,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(rename = "archiveSha256", default)]
    pub archive_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementProfile {
    pub name: String,
    pub id: String,
    pub cloud: String,
    pub tee: String,
    #[serde(default)]
    pub invariants: Vec<PcrSpec>,
    #[serde(default)]
    pub variants: Vec<MeasurementVariant>,
    #[serde(default)]
    pub attributes: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementVariant {
    pub name: String,
    pub id: String,
    #[serde(rename = "machineTypes", default)]
    pub machine_types: Vec<String>,
    #[serde(rename = "overridePcrs", default)]
    pub override_pcrs: Vec<PcrSpec>,
    #[serde(default)]
    pub attributes: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrSpec {
    #[serde(rename = "pcrIndex")]
    pub pcr_index: u8,
    #[serde(rename = "verifyType")]
    pub verify_type: String,
    #[serde(rename = "matchData", default)]
    pub match_data: Vec<String>,
    #[serde(rename = "eventIndices", default)]
    pub event_indices: Vec<u64>,
    #[serde(rename = "totalEvents", default)]
    pub total_events: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VerificationInputs {
    pub nonce: [u8; 32],
    pub live_peer_cert_der: Vec<u8>,
    pub response: TlsAttestationResponse,
    pub measurement_policy: Option<MeasurementPolicy>,
    pub trust_anchors: TrustAnchors,
}

#[derive(Debug, Clone)]
pub struct MeasurementPolicy {
    pub source: String,
    pub pack: MeasurementPack,
}

#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    pub gcp_roots: Vec<Vec<u8>>,
    pub gcp_root_hashes: Vec<[u8; 32]>,
    pub azure_maa_keys: Vec<Vec<u8>>,
    pub amd_ark_roots: Vec<Vec<u8>>,
    pub amd_ark_root_hashes: Vec<[u8; 32]>,
    pub aws_nitro_roots: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedTlsIdentity {
    pub cert_der: Vec<u8>,
    pub cert_sha256: [u8; 32],
    pub base_image_id: Option<[u8; 32]>,
    pub platform_profile_id: Option<[u8; 32]>,
    pub variant_id: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub checks: Vec<VerificationCheck>,
    pub evidence: EvidenceSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub name: String,
    pub result: CheckResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckResult {
    Pass,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSummary {
    #[serde(default)]
    pub tls_cert_der: Option<String>,
    #[serde(default)]
    pub live_tls_cert_sha256: Option<String>,
    #[serde(default)]
    pub response_tls_cert_sha256: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub qualifying_data: Option<String>,
    #[serde(default)]
    pub cloud: Option<String>,
    #[serde(default)]
    pub tee: Option<String>,
    #[serde(default)]
    pub machine_type: Option<String>,
    #[serde(default)]
    pub measurement_source: Option<String>,
    #[serde(default)]
    pub tpm_ak_public: Option<String>,
    #[serde(default)]
    pub tpm_quote: Option<String>,
    #[serde(default)]
    pub tpm_signature: Option<String>,
    #[serde(default)]
    pub pcrs: Vec<PcrEvidence>,
    #[serde(default)]
    pub event_log_hashes: Vec<PcrEventHashes>,
    #[serde(default)]
    pub tee_evidence_kind: Option<String>,
    #[serde(default)]
    pub tee_evidence_report: Option<String>,
    #[serde(default)]
    pub tee_evidence_auxiliary: Option<String>,
    #[serde(default)]
    pub ak_binding_kind: Option<String>,
    #[serde(default)]
    pub ak_binding_data: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub collateral: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationFailure {
    pub report: Box<VerificationReport>,
    pub errors: Vec<VerificationError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationError {
    pub check: String,
    pub detail: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureMaaAkBinding {
    jwt: String,
    hcl_var_data: String,
}

#[derive(Debug, Deserialize)]
struct AzureMaaJwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureMaaJwtClaims {
    iss: String,
    #[serde(rename = "x-ms-attestation-type")]
    attestation_type: String,
    #[serde(rename = "x-ms-compliance-status")]
    compliance_status: String,
    #[serde(default)]
    tdx_report_data: Option<String>,
    #[serde(rename = "x-ms-sevsnpvm-reportdata", default)]
    snp_report_data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureHclVarData {
    #[serde(default)]
    keys: Vec<AzureJwk>,
}

#[derive(Debug, Deserialize)]
struct AzureJwk {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    kty: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

pub fn parse_measurement_pack(bytes: &[u8]) -> Result<MeasurementPack> {
    serde_json::from_slice(bytes).map_err(|e| AttestationError::MeasurementPack(e.to_string()))
}

pub fn verify_measurement_pack(
    bytes: &[u8],
    sig: &[u8],
    trusted_publisher_keys: &[Vec<u8>],
) -> Result<MeasurementPack> {
    if sig.is_empty() {
        return Err(AttestationError::MeasurementPackSignature(
            "detached signature is empty".to_string(),
        ));
    }
    if trusted_publisher_keys.is_empty() {
        return Err(AttestationError::MeasurementPackSignature(
            "no trusted measurement publisher keys configured".to_string(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| AttestationError::MeasurementPack(e.to_string()))?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|e| {
        AttestationError::MeasurementPackSignature(format!("canonicalization failed: {e}"))
    })?;
    if canonical != bytes {
        return Err(AttestationError::MeasurementPackSignature(
            "measurement pack JSON is not canonical".to_string(),
        ));
    }
    let signature = parse_es256k_signature(sig)?;
    let mut key_errors = Vec::new();
    for key_bytes in trusted_publisher_keys {
        let verifying_key = match K256VerifyingKey::from_sec1_bytes(key_bytes) {
            Ok(key) => key,
            Err(e) => {
                key_errors.push(format!("trusted key did not parse as SEC1 ES256K: {e}"));
                continue;
            }
        };
        if verifying_key.verify(bytes, &signature).is_ok() {
            return parse_measurement_pack(bytes);
        }
    }
    let detail = if key_errors.is_empty() {
        "signature did not verify under any trusted publisher key".to_string()
    } else {
        format!(
            "signature did not verify under any trusted publisher key; key parse errors: {}",
            key_errors.join("; ")
        )
    };
    Err(AttestationError::MeasurementPackSignature(detail))
}

fn parse_es256k_signature(sig: &[u8]) -> Result<K256Signature> {
    match sig.len() {
        64 => K256Signature::from_slice(sig),
        65 => K256Signature::from_slice(&sig[..64]),
        _ => K256Signature::from_der(sig),
    }
    .map_err(|e| AttestationError::MeasurementPackSignature(e.to_string()))
}

pub fn verify_tls_attestation(
    inputs: VerificationInputs,
) -> std::result::Result<VerifiedTlsIdentity, VerificationFailure> {
    let mut verified_base_image_id = None;
    let mut verified_platform_profile_id = None;
    let mut verified_variant_id = None;
    let mut report = VerificationReport {
        checks: Vec::new(),
        evidence: EvidenceSummary {
            cloud: Some(inputs.response.platform.cloud.clone()),
            tee: Some(inputs.response.platform.tee.clone()),
            machine_type: Some(inputs.response.platform.machine_type.clone()),
            measurement_source: inputs
                .measurement_policy
                .as_ref()
                .map(|policy| policy.source.clone()),
            tls_cert_der: Some(inputs.response.tls_cert_der.clone()),
            tpm_ak_public: Some(inputs.response.tpm.ak_public.clone()),
            tpm_quote: Some(inputs.response.tpm.quote.clone()),
            tpm_signature: Some(inputs.response.tpm.signature.clone()),
            pcrs: inputs.response.tpm.pcrs.clone(),
            event_log_hashes: inputs.response.tpm.event_log_hashes.clone(),
            tee_evidence_kind: inputs
                .response
                .tee_evidence
                .as_ref()
                .map(|evidence| evidence.kind.clone()),
            tee_evidence_report: inputs
                .response
                .tee_evidence
                .as_ref()
                .map(|evidence| evidence.report.clone()),
            tee_evidence_auxiliary: inputs
                .response
                .tee_evidence
                .as_ref()
                .and_then(|evidence| evidence.auxiliary.clone()),
            ak_binding_kind: inputs
                .response
                .ak_binding
                .as_ref()
                .map(|binding| binding.kind.clone()),
            ak_binding_data: inputs
                .response
                .ak_binding
                .as_ref()
                .map(|binding| binding.data.clone()),
            collateral: inputs.response.collateral.clone(),
            ..EvidenceSummary::default()
        },
    };
    let mut errors = Vec::new();

    check(
        &mut report,
        &mut errors,
        "response-format",
        inputs.response.format == 1,
        format!("expected 1, got {}", inputs.response.format),
    );

    let response_nonce = decode_b64_32("nonce", &inputs.response.nonce);
    match response_nonce {
        Ok(response_nonce) => {
            report.evidence.nonce = Some(inputs.response.nonce.clone());
            check(
                &mut report,
                &mut errors,
                "nonce",
                response_nonce == inputs.nonce,
                "response nonce does not match request nonce".to_string(),
            );
        }
        Err(e) => fail(&mut report, &mut errors, "nonce", e.to_string()),
    }

    let response_cert_der = match decode_b64("tlsCertDer", &inputs.response.tls_cert_der) {
        Ok(bytes) => {
            pass(&mut report, "tls-cert-der");
            Some(bytes)
        }
        Err(e) => {
            fail(&mut report, &mut errors, "tls-cert-der", e.to_string());
            None
        }
    };

    let response_cert_sha = match decode_hex_32("tlsCertSha256", &inputs.response.tls_cert_sha256) {
        Ok(bytes) => {
            report.evidence.response_tls_cert_sha256 = Some(inputs.response.tls_cert_sha256);
            Some(bytes)
        }
        Err(e) => {
            fail(
                &mut report,
                &mut errors,
                "response-cert-sha256",
                e.to_string(),
            );
            None
        }
    };

    let tpm_quote_bytes = match decode_b64("tpm.quote", &inputs.response.tpm.quote) {
        Ok(bytes) if !bytes.is_empty() => {
            pass(&mut report, "tpm-quote");
            Some(bytes)
        }
        Ok(_) => {
            fail(
                &mut report,
                &mut errors,
                "tpm-quote",
                "tpm.quote is empty".to_string(),
            );
            None
        }
        Err(e) => {
            fail(&mut report, &mut errors, "tpm-quote", e.to_string());
            None
        }
    };
    let tpm_signature_bytes = match decode_b64("tpm.signature", &inputs.response.tpm.signature) {
        Ok(bytes) if !bytes.is_empty() => {
            pass(&mut report, "tpm-signature");
            Some(bytes)
        }
        Ok(_) => {
            fail(
                &mut report,
                &mut errors,
                "tpm-signature",
                "tpm.signature is empty".to_string(),
            );
            None
        }
        Err(e) => {
            fail(&mut report, &mut errors, "tpm-signature", e.to_string());
            None
        }
    };

    let live_sha: [u8; 32] = Sha256::digest(&inputs.live_peer_cert_der).into();
    report.evidence.live_tls_cert_sha256 = Some(hex0x(&live_sha));

    if let (Some(cert_der), Some(expected_sha)) = (&response_cert_der, response_cert_sha) {
        let actual_sha: [u8; 32] = Sha256::digest(cert_der).into();
        check(
            &mut report,
            &mut errors,
            "response-cert-hash",
            actual_sha == expected_sha,
            "tlsCertDer hash does not match tlsCertSha256".to_string(),
        );
        check(
            &mut report,
            &mut errors,
            "live-cert-hash",
            live_sha == expected_sha,
            "live peer certificate hash does not match attested hash".to_string(),
        );

        let expected_qd = compute_tls_bootstrap_qualifying_data(&inputs.nonce, &expected_sha);
        match decode_hex_32("qualifyingData", &inputs.response.qualifying_data) {
            Ok(got_qd) => {
                report.evidence.qualifying_data = Some(inputs.response.qualifying_data);
                check(
                    &mut report,
                    &mut errors,
                    "qualifying-data",
                    got_qd == expected_qd,
                    "qualifyingData does not match nonce and TLS cert hash".to_string(),
                );
                if let Some(tpm_quote_bytes) = &tpm_quote_bytes {
                    verification_core::verify_tpm_quote(
                        &mut report,
                        &mut errors,
                        tpm_quote_bytes,
                        &expected_qd,
                        &inputs.response.tpm.pcrs,
                    );
                } else {
                    skipped(&mut report, "tpm-quote-structure", "missing TPM quote");
                    skipped(&mut report, "tpm-quote-challenge", "missing TPM quote");
                    skipped(&mut report, "tpm-quote-pcr-digest", "missing TPM quote");
                }
            }
            Err(e) => fail(&mut report, &mut errors, "qualifying-data", e.to_string()),
        }
    } else {
        skipped(
            &mut report,
            "response-cert-hash",
            "missing certificate or hash",
        );
        skipped(&mut report, "live-cert-hash", "missing certificate or hash");
        skipped(
            &mut report,
            "qualifying-data",
            "missing certificate or hash",
        );
        skipped(
            &mut report,
            "tpm-quote-structure",
            "missing certificate or hash",
        );
        skipped(
            &mut report,
            "tpm-quote-challenge",
            "missing certificate or hash",
        );
        skipped(
            &mut report,
            "tpm-quote-pcr-digest",
            "missing certificate or hash",
        );
    }

    match inputs.response.platform.cloud.as_str() {
        "gcp" | "azure" => pass(&mut report, "platform-supported"),
        "aws" => fail(
            &mut report,
            &mut errors,
            "platform-supported",
            "AWS NitroTPM verifier is unsupported in v1".to_string(),
        ),
        cloud => fail(
            &mut report,
            &mut errors,
            "platform-supported",
            format!("unsupported cloud for production TLS attestation: {cloud}"),
        ),
    }

    let tpm_ak_public = match decode_b64("tpm.akPublic", &inputs.response.tpm.ak_public) {
        Ok(bytes) if !bytes.is_empty() => {
            pass(&mut report, "tpm-ak-public");
            Some(bytes)
        }
        Ok(_) if inputs.response.platform.cloud == "azure" => {
            skipped(
                &mut report,
                "tpm-ak-public",
                "Azure HCLAk public material is carried in akBinding var_data",
            );
            None
        }
        Ok(_) => {
            fail(
                &mut report,
                &mut errors,
                "tpm-ak-public",
                "tpm.akPublic is empty".to_string(),
            );
            None
        }
        Err(e) => {
            fail(&mut report, &mut errors, "tpm-ak-public", e.to_string());
            None
        }
    };
    match (
        inputs.response.platform.cloud.as_str(),
        &tpm_ak_public,
        &tpm_quote_bytes,
        &tpm_signature_bytes,
        inputs.response.ak_binding.as_ref(),
    ) {
        ("azure", _, Some(tpm_quote), Some(tpm_signature), Some(binding)) => {
            verification_core::verify_azure_maa_jwt_binding(
                &mut report,
                &mut errors,
                binding,
                &inputs.trust_anchors.azure_maa_keys,
                &inputs.response.platform.tee,
            );
            verification_core::verify_azure_hclak_quote_signature(
                &mut report,
                &mut errors,
                binding,
                tpm_quote,
                tpm_signature,
            )
        }
        ("azure", _, _, _, _) => fail(
            &mut report,
            &mut errors,
            "tpm-quote-signature",
            "missing Azure HCLAk binding, TPM quote, or TPM signature".to_string(),
        ),
        ("gcp", Some(ak_public), Some(tpm_quote), Some(tpm_signature), Some(binding)) => {
            verification_core::verify_gcp_ak_cert_chain(
                &mut report,
                &mut errors,
                binding,
                ak_public,
                &inputs.trust_anchors.gcp_roots,
                &inputs.trust_anchors.gcp_root_hashes,
            );
            verification_core::verify_tpm_quote_signature(
                &mut report,
                &mut errors,
                ak_public,
                tpm_quote,
                tpm_signature,
            )
        }
        ("gcp", _, _, _, _) => fail(
            &mut report,
            &mut errors,
            "gcp-ak-cert-chain",
            "missing GCP AK cert chain, AK public key, TPM quote, or TPM signature".to_string(),
        ),
        (_, Some(ak_public), Some(tpm_quote), Some(tpm_signature), _) => {
            verification_core::verify_tpm_quote_signature(
                &mut report,
                &mut errors,
                ak_public,
                tpm_quote,
                tpm_signature,
            )
        }
        _ => skipped(
            &mut report,
            "tpm-quote-signature",
            "missing AK public key, quote, or signature",
        ),
    }
    match &inputs.response.tee_evidence {
        Some(evidence) => match decode_b64("teeEvidence.report", &evidence.report) {
            Ok(bytes) if !bytes.is_empty() => pass(&mut report, "tee-evidence"),
            Ok(_) if evidence.kind == "none" || evidence.kind == "emulation" => fail(
                &mut report,
                &mut errors,
                "tee-evidence",
                format!(
                    "TEE evidence kind {} is not production evidence",
                    evidence.kind
                ),
            ),
            Ok(_) => fail(
                &mut report,
                &mut errors,
                "tee-evidence",
                "teeEvidence.report is empty".to_string(),
            ),
            Err(e) => fail(&mut report, &mut errors, "tee-evidence", e.to_string()),
        },
        None => fail(
            &mut report,
            &mut errors,
            "tee-evidence",
            "teeEvidence is missing".to_string(),
        ),
    }
    if inputs.response.platform.cloud == "gcp" {
        verification_core::verify_gcp_tee_vtpm_binding(
            &mut report,
            &mut errors,
            inputs.response.tee_evidence.as_ref(),
            &inputs.response.platform.tee,
            &inputs.response.tpm.pcrs,
        );
        verification_core::verify_gcp_tee_vendor_report(
            &mut report,
            &mut errors,
            inputs.response.tee_evidence.as_ref(),
            &inputs.response.platform.tee,
            &inputs.response.collateral,
            &inputs.trust_anchors.amd_ark_roots,
            &inputs.trust_anchors.amd_ark_root_hashes,
        );
    }

    match &inputs.response.ak_binding {
        Some(binding) => match decode_b64("akBinding.data", &binding.data) {
            Ok(bytes) if !bytes.is_empty() => pass(&mut report, "ak-binding"),
            Ok(_) => fail(
                &mut report,
                &mut errors,
                "ak-binding",
                "akBinding.data is empty".to_string(),
            ),
            Err(e) => fail(&mut report, &mut errors, "ak-binding", e.to_string()),
        },
        None => fail(
            &mut report,
            &mut errors,
            "ak-binding",
            "akBinding is missing".to_string(),
        ),
    }

    if let Some(policy) = &inputs.measurement_policy {
        check(
            &mut report,
            &mut errors,
            "measurement-pack-schema",
            policy.pack.schema == "atakit.measurement-pack.v1",
            format!("unsupported schema {}", policy.pack.schema),
        );

        let expected_base_image_id = compute_base_image_id(
            &policy.pack.base_image.name,
            &policy.pack.base_image.version,
        );
        match decode_hex_32("baseImage.id", &policy.pack.base_image.id) {
            Ok(id) => {
                check(
                    &mut report,
                    &mut errors,
                    "base-image-id",
                    id == expected_base_image_id,
                    format!(
                        "baseImage.id does not match derived id for {}:{}; expected {}",
                        policy.pack.base_image.name,
                        policy.pack.base_image.version,
                        hex0x(&expected_base_image_id)
                    ),
                );
                if id == expected_base_image_id {
                    verified_base_image_id = Some(id);
                }
            }
            Err(e) => fail(&mut report, &mut errors, "base-image-id", e.to_string()),
        }

        let matching_profiles = policy
            .pack
            .profiles
            .iter()
            .filter(|profile| {
                profile.cloud == inputs.response.platform.cloud
                    && profile.tee == inputs.response.platform.tee
            })
            .collect::<Vec<_>>();
        let profile = match matching_profiles.as_slice() {
            [profile] => *profile,
            [] => {
                fail(
                    &mut report,
                    &mut errors,
                    "measurement-profile",
                    format!(
                        "no profile for cloud={} tee={}",
                        inputs.response.platform.cloud, inputs.response.platform.tee
                    ),
                );
                return Err(VerificationFailure {
                    report: Box::new(report),
                    errors,
                });
            }
            profiles => {
                let names = profiles
                    .iter()
                    .map(|profile| profile.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                fail(
                    &mut report,
                    &mut errors,
                    "measurement-profile",
                    format!(
                        "ambiguous profiles for cloud={} tee={}: {names}",
                        inputs.response.platform.cloud, inputs.response.platform.tee
                    ),
                );
                return Err(VerificationFailure {
                    report: Box::new(report),
                    errors,
                });
            }
        };
        pass(&mut report, "measurement-profile");

        let expected_profile_id =
            compute_platform_profile_id(&expected_base_image_id, &profile.name);
        match decode_hex_32("profile.id", &profile.id) {
            Ok(id) => {
                check(
                    &mut report,
                    &mut errors,
                    "platform-profile-id",
                    id == expected_profile_id,
                    format!(
                        "profile.id does not match derived id for profile {}; expected {}",
                        profile.name,
                        hex0x(&expected_profile_id)
                    ),
                );
                if id == expected_profile_id {
                    verified_platform_profile_id = Some(id);
                }
            }
            Err(e) => fail(
                &mut report,
                &mut errors,
                "platform-profile-id",
                e.to_string(),
            ),
        }

        let matching_variants = profile
            .variants
            .iter()
            .filter(|variant| {
                variant
                    .machine_types
                    .iter()
                    .any(|machine_type| machine_type == &inputs.response.platform.machine_type)
            })
            .collect::<Vec<_>>();
        let variant = match matching_variants.as_slice() {
            [variant] => *variant,
            [] => {
                fail(
                    &mut report,
                    &mut errors,
                    "measurement-variant",
                    format!(
                        "no variant for machineType={}",
                        inputs.response.platform.machine_type
                    ),
                );
                return Err(VerificationFailure {
                    report: Box::new(report),
                    errors,
                });
            }
            variants => {
                let names = variants
                    .iter()
                    .map(|variant| variant.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                fail(
                    &mut report,
                    &mut errors,
                    "measurement-variant",
                    format!(
                        "ambiguous variants for machineType={}: {names}",
                        inputs.response.platform.machine_type
                    ),
                );
                return Err(VerificationFailure {
                    report: Box::new(report),
                    errors,
                });
            }
        };
        pass(&mut report, "measurement-variant");

        let expected_variant_id = compute_variant_id(&expected_profile_id, &variant.name);
        match decode_hex_32("variant.id", &variant.id) {
            Ok(id) => {
                check(
                    &mut report,
                    &mut errors,
                    "variant-id",
                    id == expected_variant_id,
                    format!(
                        "variant.id does not match derived id for variant {}; expected {}",
                        variant.name,
                        hex0x(&expected_variant_id)
                    ),
                );
                if id == expected_variant_id {
                    verified_variant_id = Some(id);
                }
            }
            Err(e) => fail(&mut report, &mut errors, "variant-id", e.to_string()),
        }

        match effective_pcr_specs(profile, variant) {
            Ok(pcr_specs) if pcr_specs.is_empty() => fail(
                &mut report,
                &mut errors,
                "measurement-pcrs",
                "selected profile/variant has no PCR specs".to_string(),
            ),
            Ok(pcr_specs) => {
                for spec in pcr_specs {
                    verify_pcr_spec(
                        &mut report,
                        &mut errors,
                        spec,
                        &inputs.response.tpm.pcrs,
                        &inputs.response.tpm.event_log_hashes,
                    );
                }
            }
            Err(detail) => fail(&mut report, &mut errors, "measurement-pcrs", detail),
        }
    } else {
        fail(
            &mut report,
            &mut errors,
            "measurement-policy",
            "no trusted measurement policy supplied".to_string(),
        );
    }

    if errors.is_empty() {
        Ok(VerifiedTlsIdentity {
            cert_der: response_cert_der.unwrap_or_default(),
            cert_sha256: response_cert_sha.unwrap_or(live_sha),
            base_image_id: verified_base_image_id,
            platform_profile_id: verified_platform_profile_id,
            variant_id: verified_variant_id,
        })
    } else {
        Err(VerificationFailure {
            report: Box::new(report),
            errors,
        })
    }
}

fn effective_pcr_specs<'a>(
    profile: &'a MeasurementProfile,
    variant: &'a MeasurementVariant,
) -> std::result::Result<Vec<&'a PcrSpec>, String> {
    let mut specs = BTreeMap::new();
    for spec in &profile.invariants {
        if specs.insert(spec.pcr_index, spec).is_some() {
            return Err(format!(
                "duplicate invariant PCR index {} in profile {}",
                spec.pcr_index, profile.name
            ));
        }
    }

    let mut override_indices = BTreeSet::new();
    for spec in &variant.override_pcrs {
        if !override_indices.insert(spec.pcr_index) {
            return Err(format!(
                "duplicate override PCR index {} in variant {}",
                spec.pcr_index, variant.name
            ));
        }
        specs.insert(spec.pcr_index, spec);
    }

    Ok(specs.into_values().collect())
}

pub fn compute_tls_bootstrap_qualifying_data(
    nonce: &[u8; 32],
    tls_cert_sha256: &[u8; 32],
) -> [u8; 32] {
    let domain: [u8; 32] = Keccak256::digest(b"ATAKIT_TLS_BOOTSTRAP_V1").into();
    let mut encoded = [0u8; 96];
    encoded[0..32].copy_from_slice(&domain);
    encoded[32..64].copy_from_slice(nonce);
    encoded[64..96].copy_from_slice(tls_cert_sha256);
    Keccak256::digest(encoded).into()
}

pub fn compute_base_image_id(name: &str, version: &str) -> [u8; 32] {
    let domain: [u8; 32] = Keccak256::digest(b"CVM_BASEIMAGE_V1").into();
    Keccak256::digest(abi_encode_bytes32_string_string(&domain, name, version)).into()
}

pub fn compute_platform_profile_id(base_image_id: &[u8; 32], profile_name: &str) -> [u8; 32] {
    let domain: [u8; 32] = Keccak256::digest(b"CVM_PLATFORM_PROFILE_V1").into();
    Keccak256::digest(abi_encode_bytes32_bytes32_string(
        &domain,
        base_image_id,
        profile_name,
    ))
    .into()
}

pub fn compute_variant_id(platform_profile_id: &[u8; 32], variant_name: &str) -> [u8; 32] {
    let domain: [u8; 32] = Keccak256::digest(b"CVM_PLATFORM_VARIANT_V1").into();
    Keccak256::digest(abi_encode_bytes32_bytes32_string(
        &domain,
        platform_profile_id,
        variant_name,
    ))
    .into()
}

fn abi_encode_bytes32_string_string(domain: &[u8; 32], first: &str, second: &str) -> Vec<u8> {
    let first_bytes = first.as_bytes();
    let second_bytes = second.as_bytes();
    let first_offset = 96usize;
    let second_offset = first_offset + abi_dynamic_string_len(first_bytes);
    let mut out = Vec::with_capacity(second_offset + abi_dynamic_string_len(second_bytes));
    out.extend_from_slice(domain);
    out.extend_from_slice(&abi_word_usize(first_offset));
    out.extend_from_slice(&abi_word_usize(second_offset));
    write_abi_string(&mut out, first_bytes);
    write_abi_string(&mut out, second_bytes);
    out
}

fn abi_encode_bytes32_bytes32_string(domain: &[u8; 32], parent: &[u8; 32], value: &str) -> Vec<u8> {
    let value_bytes = value.as_bytes();
    let value_offset = 96usize;
    let mut out = Vec::with_capacity(value_offset + abi_dynamic_string_len(value_bytes));
    out.extend_from_slice(domain);
    out.extend_from_slice(parent);
    out.extend_from_slice(&abi_word_usize(value_offset));
    write_abi_string(&mut out, value_bytes);
    out
}

fn abi_dynamic_string_len(bytes: &[u8]) -> usize {
    32 + bytes.len().div_ceil(32) * 32
}

fn write_abi_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&abi_word_usize(bytes.len()));
    out.extend_from_slice(bytes);
    let padding = (32 - bytes.len() % 32) % 32;
    out.resize(out.len() + padding, 0);
}

fn abi_word_usize(value: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    out
}

fn verify_pcr_spec(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    spec: &PcrSpec,
    pcrs: &[PcrEvidence],
    event_log_hashes: &[PcrEventHashes],
) {
    let check_name = format!("pcr-{}-{}", spec.pcr_index, spec.verify_type);
    if spec.match_data.is_empty() {
        fail(
            report,
            errors,
            &check_name,
            "PCR spec has no matchData".to_string(),
        );
        return;
    }
    let Some(pcr) = pcrs.iter().find(|pcr| pcr.index == spec.pcr_index) else {
        fail(
            report,
            errors,
            &check_name,
            format!("TPM evidence does not contain PCR {}", spec.pcr_index),
        );
        return;
    };
    if spec.verify_type.eq_ignore_ascii_case("static") {
        let expected = spec
            .match_data
            .iter()
            .map(|value| normalize_hex(value))
            .collect::<Vec<_>>();
        let actual = [&pcr.sha256, &pcr.sha384]
            .into_iter()
            .filter_map(|value| value.as_ref())
            .map(|value| normalize_hex(value))
            .collect::<Vec<_>>();
        check(
            report,
            errors,
            &check_name,
            actual.iter().any(|value| expected.contains(value)),
            format!(
                "PCR {} did not match any static measurement",
                spec.pcr_index
            ),
        );
        return;
    }

    let verify_type = match spec.verify_type.to_ascii_uppercase().as_str() {
        "DYNAMIC_SUBSET" | "DYNAMIC-SUBSET" => SessionPcrVerifyType::DynamicSubset,
        "DYNAMIC_SUBSEQUENCE" | "DYNAMIC-SUBSEQUENCE" => SessionPcrVerifyType::DynamicSubsequence,
        other => {
            fail(
                report,
                errors,
                &check_name,
                format!("unsupported PCR verifyType {other}"),
            );
            return;
        }
    };
    let Some(measured_sha256) = pcr.sha256.as_deref() else {
        fail(
            report,
            errors,
            &check_name,
            "dynamic PCR has no SHA-256 value".to_string(),
        );
        return;
    };
    let measured = match decode_hex_32("pcr.sha256", measured_sha256) {
        Ok(value) => value,
        Err(error) => {
            fail(report, errors, &check_name, error.to_string());
            return;
        }
    };
    let event_values = event_log_hashes
        .iter()
        .find(|events| events.pcr_index == spec.pcr_index)
        .map(|events| events.sha256.as_slice())
        .unwrap_or_default();
    let decoded = event_values
        .iter()
        .map(|event| decode_hex_32("eventLogHashes.sha256", event))
        .collect::<Result<Vec<_>>>();
    let decoded = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            fail(report, errors, &check_name, error.to_string());
            return;
        }
    };
    let policy = SessionPcrPolicy {
        pcr_index: spec.pcr_index,
        verify_type,
        match_data: spec.match_data.clone(),
    };
    match verification_core::evaluate_pcr_policy(&policy, measured, &decoded) {
        Ok(()) => pass(report, &check_name),
        Err(detail) => fail(report, errors, &check_name, detail),
    }
}

fn decode_b64(field: &'static str, value: &str) -> Result<Vec<u8>> {
    if value.contains('=') {
        return Err(AttestationError::Base64 {
            field,
            detail: "padding is not allowed".to_string(),
        });
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| AttestationError::Base64 {
            field,
            detail: e.to_string(),
        })
}

fn decode_b64_32(field: &'static str, value: &str) -> Result<[u8; 32]> {
    let bytes = decode_b64(field, value)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| AttestationError::Base64 {
        field,
        detail: format!("expected 32 bytes, got {}", bytes.len()),
    })
}

fn decode_hex_32(field: &'static str, value: &str) -> Result<[u8; 32]> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(raw).map_err(|e| AttestationError::Hex {
        field,
        detail: e.to_string(),
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| AttestationError::Hex {
        field,
        detail: format!("expected 32 bytes, got {}", bytes.len()),
    })
}

fn check(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    name: &str,
    ok: bool,
    detail: String,
) {
    if ok {
        pass(report, name);
    } else {
        fail(report, errors, name, detail);
    }
}

fn pass(report: &mut VerificationReport, name: &str) {
    report.checks.push(VerificationCheck {
        name: name.to_string(),
        result: CheckResult::Pass,
        detail: None,
    });
}

fn fail(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    name: &str,
    detail: String,
) {
    report.checks.push(VerificationCheck {
        name: name.to_string(),
        result: CheckResult::Fail,
        detail: Some(detail.clone()),
    });
    errors.push(VerificationError {
        check: name.to_string(),
        detail,
    });
}

fn skipped(report: &mut VerificationReport, name: &str, detail: &str) {
    report.checks.push(VerificationCheck {
        name: name.to_string(),
        result: CheckResult::Skipped,
        detail: Some(detail.to_string()),
    });
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn normalize_hex(value: &str) -> String {
    value
        .strip_prefix("0x")
        .unwrap_or(value)
        .to_ascii_lowercase()
}

fn pad_left(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let n = bytes.len().min(len);
    out[len - n..].copy_from_slice(&bytes[bytes.len() - n..]);
    out
}

#[cfg(test)]
mod tests {
    use super::verification_core::*;
    use super::*;
    use k256::ecdsa::SigningKey as K256SigningKey;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use rsa::rand_core::OsRng;
    use rsa::signature::SignatureEncoding;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use signature::{hazmat::PrehashSigner, Keypair, Signer};

    fn response_for(nonce: [u8; 32], cert: &[u8], cloud: &str) -> TlsAttestationResponse {
        let cert_sha: [u8; 32] = Sha256::digest(cert).into();
        let qd = compute_tls_bootstrap_qualifying_data(&nonce, &cert_sha);
        let pcr = [0xaau8; 32];
        let pcr15 = if cloud == "gcp" {
            Some(expected_gcp_tdx_pcr15_for_uuid(&[0x42u8; 16]))
        } else {
            None
        };
        let quote = match pcr15 {
            Some(pcr15) => fake_tpm_quote(&qd, &[(4, pcr), (15, pcr15)]),
            None => fake_tpm_quote(&qd, &[(4, pcr)]),
        };
        let (ak_public, signature) = fake_ak_and_signature(&quote);
        let mut pcrs = vec![PcrEvidence {
            index: 4,
            sha256: Some(hex0x(&pcr)),
            sha384: None,
        }];
        if let Some(pcr15) = pcr15 {
            pcrs.push(PcrEvidence {
                index: 15,
                sha256: Some(hex0x(&pcr15)),
                sha384: None,
            });
        }
        TlsAttestationResponse {
            format: 1,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            tls_cert_der: URL_SAFE_NO_PAD.encode(cert),
            tls_cert_sha256: hex0x(&cert_sha),
            qualifying_data: hex0x(&qd),
            platform: PlatformEvidence {
                cloud: cloud.to_string(),
                tee: "tdx".to_string(),
                machine_type: "c3-standard-4".to_string(),
            },
            tpm: TpmEvidence {
                ak_public: URL_SAFE_NO_PAD.encode(ak_public),
                quote: URL_SAFE_NO_PAD.encode(quote),
                signature: URL_SAFE_NO_PAD.encode(signature),
                pcrs,
                event_log_hashes: Vec::new(),
            },
            tee_evidence: Some(TeeEvidence {
                kind: "configfs-tsm".to_string(),
                report: URL_SAFE_NO_PAD.encode(fake_gcp_tdx_full_quote_v4(&[0x42u8; 16])),
                auxiliary: None,
            }),
            ak_binding: Some(AkBinding {
                kind: "gcp-cert-chain".to_string(),
                data: URL_SAFE_NO_PAD.encode(b"ak-binding"),
            }),
            collateral: serde_json::Value::Null,
        }
    }

    fn gcp_response_and_roots(
        nonce: [u8; 32],
        cert: &[u8],
    ) -> (TlsAttestationResponse, Vec<Vec<u8>>) {
        let cert_sha: [u8; 32] = Sha256::digest(cert).into();
        let qd = compute_tls_bootstrap_qualifying_data(&nonce, &cert_sha);
        let pcr = [0xaau8; 32];
        let uuid = [0x42u8; 16];
        let pcr15 = expected_gcp_tdx_pcr15_for_uuid(&uuid);
        let quote = fake_tpm_quote(&qd, &[(4, pcr), (15, pcr15)]);
        let (ak_public, signature, cert_chain, roots) = fake_gcp_ak_chain_and_signature(&quote);
        (
            TlsAttestationResponse {
                format: 1,
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                tls_cert_der: URL_SAFE_NO_PAD.encode(cert),
                tls_cert_sha256: hex0x(&cert_sha),
                qualifying_data: hex0x(&qd),
                platform: PlatformEvidence {
                    cloud: "gcp".to_string(),
                    tee: "tdx".to_string(),
                    machine_type: "c3-standard-4".to_string(),
                },
                tpm: TpmEvidence {
                    ak_public: URL_SAFE_NO_PAD.encode(ak_public),
                    quote: URL_SAFE_NO_PAD.encode(quote),
                    signature: URL_SAFE_NO_PAD.encode(signature),
                    pcrs: vec![
                        PcrEvidence {
                            index: 4,
                            sha256: Some(hex0x(&pcr)),
                            sha384: None,
                        },
                        PcrEvidence {
                            index: 15,
                            sha256: Some(hex0x(&pcr15)),
                            sha384: None,
                        },
                    ],
                    event_log_hashes: Vec::new(),
                },
                tee_evidence: Some(TeeEvidence {
                    kind: "configfs-tsm".to_string(),
                    report: URL_SAFE_NO_PAD.encode(fake_gcp_tdx_full_quote_v4(&uuid)),
                    auxiliary: None,
                }),
                ak_binding: Some(AkBinding {
                    kind: "gcp-cert-chain".to_string(),
                    data: URL_SAFE_NO_PAD.encode(
                        serde_json::to_vec(
                            &cert_chain
                                .iter()
                                .map(|cert| URL_SAFE_NO_PAD.encode(cert))
                                .collect::<Vec<_>>(),
                        )
                        .expect("GCP cert chain JSON"),
                    ),
                }),
                collateral: serde_json::Value::Null,
            },
            roots,
        )
    }

    fn gcp_snp_response_roots_and_ark(
        nonce: [u8; 32],
        cert: &[u8],
    ) -> (TlsAttestationResponse, Vec<Vec<u8>>, Vec<u8>) {
        let (snp_report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let cert_sha: [u8; 32] = Sha256::digest(cert).into();
        let qd = compute_tls_bootstrap_qualifying_data(&nonce, &cert_sha);
        let pcr = [0xaau8; 32];
        let pcr15 = expected_gcp_snp_pcr15(&snp_report).expect("fixture SNP PCR15");
        let quote = fake_tpm_quote(&qd, &[(4, pcr), (15, pcr15)]);
        let (ak_public, signature, cert_chain, roots) = fake_gcp_ak_chain_and_signature(&quote);
        (
            TlsAttestationResponse {
                format: 1,
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                tls_cert_der: URL_SAFE_NO_PAD.encode(cert),
                tls_cert_sha256: hex0x(&cert_sha),
                qualifying_data: hex0x(&qd),
                platform: PlatformEvidence {
                    cloud: "gcp".to_string(),
                    tee: "sev-snp".to_string(),
                    machine_type: "n2d-standard-4".to_string(),
                },
                tpm: TpmEvidence {
                    ak_public: URL_SAFE_NO_PAD.encode(ak_public),
                    quote: URL_SAFE_NO_PAD.encode(quote),
                    signature: URL_SAFE_NO_PAD.encode(signature),
                    pcrs: vec![
                        PcrEvidence {
                            index: 4,
                            sha256: Some(hex0x(&pcr)),
                            sha384: None,
                        },
                        PcrEvidence {
                            index: 15,
                            sha256: Some(hex0x(&pcr15)),
                            sha384: None,
                        },
                    ],
                    event_log_hashes: Vec::new(),
                },
                tee_evidence: Some(TeeEvidence {
                    kind: "configfs-tsm".to_string(),
                    report: URL_SAFE_NO_PAD.encode(snp_report),
                    auxiliary: Some(URL_SAFE_NO_PAD.encode(auxblob)),
                }),
                ak_binding: Some(AkBinding {
                    kind: "gcp-cert-chain".to_string(),
                    data: URL_SAFE_NO_PAD.encode(
                        serde_json::to_vec(
                            &cert_chain
                                .iter()
                                .map(|cert| URL_SAFE_NO_PAD.encode(cert))
                                .collect::<Vec<_>>(),
                        )
                        .expect("GCP cert chain JSON"),
                    ),
                }),
                collateral: serde_json::Value::Null,
            },
            roots,
            ark.to_vec(),
        )
    }

    fn fake_gcp_tdx_quote_body(uuid: &[u8; 16]) -> Vec<u8> {
        let mut quote = vec![0u8; TDX_REPORT_REPORT_DATA_OFFSET + 64];
        let mut rtmr3_input = Vec::with_capacity(96);
        rtmr3_input.extend_from_slice(&[0u8; 48]);
        rtmr3_input.extend_from_slice(&[0u8; 32]);
        rtmr3_input.extend_from_slice(uuid);
        let rtmr3: [u8; 48] = Sha384::digest(&rtmr3_input).into();
        quote[TDX_REPORT_RTMR3_OFFSET..TDX_REPORT_RTMR3_OFFSET + 48].copy_from_slice(&rtmr3);
        quote[TDX_REPORT_REPORT_DATA_OFFSET..TDX_REPORT_REPORT_DATA_OFFSET + 16]
            .copy_from_slice(uuid);
        quote
    }

    fn fake_gcp_tdx_full_quote_v4(uuid: &[u8; 16]) -> Vec<u8> {
        let mut quote = vec![0u8; TDX_QUOTE_HEADER_LEN];
        quote[0..2].copy_from_slice(&4u16.to_le_bytes());
        quote[4..8].copy_from_slice(&TDX_TEE_TYPE.to_le_bytes());
        quote.extend_from_slice(&fake_gcp_tdx_quote_body(uuid));
        quote
    }

    fn fixture_gcp_snp_report_and_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        fn decode_fixture(encoded: &str) -> Vec<u8> {
            base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .expect("embedded GCP SNP fixture must be valid base64")
        }

        let report = decode_fixture(include_str!(
            "../testdata/fedora-oci-gcp-n2d-standard-4/report.bin.b64"
        ));
        let ark = decode_fixture(include_str!(
            "../testdata/fedora-oci-gcp-n2d-standard-4/ark.der.b64"
        ));
        let ask = decode_fixture(include_str!(
            "../testdata/fedora-oci-gcp-n2d-standard-4/ask.der.b64"
        ));
        let vcek = decode_fixture(include_str!(
            "../testdata/fedora-oci-gcp-n2d-standard-4/vcek.der.b64"
        ));
        let auxblob = fake_amd_snp_auxblob(&ark, &ask, &vcek);
        (report, ark, auxblob)
    }

    fn fake_amd_snp_auxblob(ark: &[u8], ask: &[u8], vcek: &[u8]) -> Vec<u8> {
        let entries = [
            (SNP_CERT_TABLE_ARK_GUID, ark),
            (SNP_CERT_TABLE_ASK_GUID, ask),
            (SNP_CERT_TABLE_VCEK_GUID, vcek),
        ];
        let table_len = 24 * (entries.len() + 1);
        let mut out = vec![0u8; table_len];
        let mut cert_offset = table_len;
        for (idx, (guid, cert)) in entries.iter().enumerate() {
            let entry_offset = idx * 24;
            out[entry_offset..entry_offset + 16].copy_from_slice(guid);
            out[entry_offset + 16..entry_offset + 20]
                .copy_from_slice(&(cert_offset as u32).to_le_bytes());
            out[entry_offset + 20..entry_offset + 24]
                .copy_from_slice(&(cert.len() as u32).to_le_bytes());
            cert_offset += cert.len();
        }
        for (_, cert) in entries {
            out.extend_from_slice(cert);
        }
        out
    }

    #[test]
    fn parses_amd_snp_auxblob_raw_cert_table_guids() {
        let ark = b"ark";
        let ask = b"ask";
        let vcek = b"vcek";
        let certs =
            parse_amd_snp_cert_table(&fake_amd_snp_auxblob(ark, ask, vcek)).expect("SNP certs");

        assert_eq!(certs.ark.as_deref(), Some(ark.as_slice()));
        assert_eq!(certs.ask.as_deref(), Some(ask.as_slice()));
        assert_eq!(certs.vcek.as_deref(), Some(vcek.as_slice()));
    }

    fn expected_gcp_tdx_pcr15_for_uuid(uuid: &[u8; 16]) -> [u8; 32] {
        let mut pcr_input = Vec::with_capacity(64);
        pcr_input.extend_from_slice(&[0u8; 32]);
        pcr_input.extend_from_slice(&[0u8; 16]);
        pcr_input.extend_from_slice(uuid);
        Sha256::digest(&pcr_input).into()
    }

    type FakeGcpAkChain = (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>);
    type FakeGcpAkMaterial = (P256SigningKey, Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>);

    fn fake_gcp_ak_chain_and_signature(tpm2b_attest: &[u8]) -> FakeGcpAkChain {
        let (signing_key, ak_public, cert_chain, roots) = fake_gcp_ak_chain();
        let signature: P256Signature = signing_key.sign(tpm2b_attest_body(tpm2b_attest).unwrap());
        (
            ak_public,
            fake_tpmt_signature_ecdsa(&signature),
            cert_chain,
            roots,
        )
    }

    fn fake_gcp_ak_chain() -> FakeGcpAkMaterial {
        let mut ca_params =
            CertificateParams::new(Vec::new()).expect("empty subject alt names are valid");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().expect("test CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("test CA cert");

        let mut leaf_params =
            CertificateParams::new(vec!["gcp-ak.test".to_string()]).expect("test AK cert params");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_key = KeyPair::generate().expect("test AK key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("test AK cert");

        let signing_key =
            P256SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).expect("test AK PKCS#8");
        let ak_public = fake_tpmt_public_ecc(signing_key.verifying_key());
        (
            signing_key,
            ak_public,
            vec![
                leaf_cert.der().as_ref().to_vec(),
                ca_cert.der().as_ref().to_vec(),
            ],
            vec![ca_cert.der().as_ref().to_vec()],
        )
    }

    fn fake_ak_and_signature(tpm2b_attest: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let signing_key = P256SigningKey::from_slice(&[7u8; 32]).expect("test signing key");
        let verify_key = signing_key.verifying_key();
        let signature: P256Signature = signing_key.sign(tpm2b_attest_body(tpm2b_attest).unwrap());
        (
            fake_tpmt_public_ecc(verify_key),
            fake_tpmt_signature_ecdsa(&signature),
        )
    }

    fn fake_tpmt_public_ecc(verify_key: &P256VerifyingKey) -> Vec<u8> {
        fake_tpmt_public_ecc_with_attributes(verify_key, 0x0006_0072)
    }

    fn fake_tpmt_public_ecc_with_attributes(
        verify_key: &P256VerifyingKey,
        object_attributes: u32,
    ) -> Vec<u8> {
        let point = verify_key.to_encoded_point(false);
        let x = point.x().expect("x");
        let y = point.y().expect("y");
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&object_attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // authPolicy
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
        out.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes()); // scheme
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&0x0003u16.to_be_bytes()); // NIST P-256
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
        out.extend_from_slice(&(x.len() as u16).to_be_bytes());
        out.extend_from_slice(x);
        out.extend_from_slice(&(y.len() as u16).to_be_bytes());
        out.extend_from_slice(y);
        out
    }

    fn fake_tpm_certify(tpmt_public: &[u8]) -> Vec<u8> {
        let mut name = Vec::with_capacity(34);
        name.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        name.extend_from_slice(&Sha256::digest(tpmt_public));

        let mut body = Vec::new();
        body.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        body.extend_from_slice(&0x8017u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner
        body.extend_from_slice(&0u16.to_be_bytes()); // extraData
        body.extend_from_slice(&[0u8; 17]); // clockInfo
        body.extend_from_slice(&[0u8; 8]); // firmwareVersion
        body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        body.extend_from_slice(&name);
        body.extend_from_slice(&0u16.to_be_bytes()); // qualifiedName

        let mut out = Vec::with_capacity(body.len() + 2);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn solidity_abi_bytes_array(values: &[&[u8]]) -> Vec<u8> {
        let word = |value: usize| {
            let mut out = [0u8; 32];
            out[24..].copy_from_slice(&(value as u64).to_be_bytes());
            out
        };
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

    fn fake_tpmt_signature_ecdsa(signature: &P256Signature) -> Vec<u8> {
        let raw = signature.to_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&32u16.to_be_bytes());
        out.extend_from_slice(&raw[0..32]);
        out.extend_from_slice(&32u16.to_be_bytes());
        out.extend_from_slice(&raw[32..64]);
        out
    }

    fn fake_azure_ak_binding_and_signature(tpm2b_attest: &[u8]) -> (AkBinding, Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("test RSA key");
        let signing_key = RsaSigningKey::<rsa::sha2::Sha256>::new(private_key);
        let public_key = signing_key.verifying_key();
        let public_key = public_key.as_ref();
        let signature: RsaSignature =
            signing_key.sign(tpm2b_attest_body(tpm2b_attest).expect("TPM attest body"));
        let hcl_var_data = serde_json::json!({
            "keys": [{
                "kid": "HCLAkPub",
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())
            }]
        });
        let hcl_var_data = serde_json::to_vec(&hcl_var_data).expect("hcl var data JSON");
        let (jwt, trusted_maa_key) = fake_azure_maa_jwt(&hcl_var_data, "tdx");
        let binding = serde_json::json!({
            "jwt": jwt,
            "hclVarData": URL_SAFE_NO_PAD.encode(hcl_var_data)
        });
        let binding = serde_json::to_vec(&binding).expect("binding JSON");
        (
            AkBinding {
                kind: "azure-maa-jwt".to_string(),
                data: URL_SAFE_NO_PAD.encode(binding),
            },
            fake_tpmt_signature_rsassa(&signature.to_bytes()),
            trusted_maa_key,
        )
    }

    fn fake_azure_maa_jwt(hcl_var_data: &[u8], tee: &str) -> (String, Vec<u8>) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("test MAA RSA key");
        let signing_key = RsaSigningKey::<rsa::sha2::Sha256>::new(private_key);
        let public_key = signing_key.verifying_key();
        let public_key = public_key.as_ref();
        let trusted_key = serde_json::to_vec(&serde_json::json!({
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())
        }))
        .expect("trusted MAA key JSON");

        let mut report_data = [0u8; 64];
        let hcl_hash: [u8; 32] = Sha256::digest(hcl_var_data).into();
        report_data[0..32].copy_from_slice(&hcl_hash);
        let (attestation_type, report_data_claim) = match tee {
            "tdx" => ("tdxvm", "tdx_report_data"),
            "sev-snp" => ("sevsnpvm", "x-ms-sevsnpvm-reportdata"),
            other => panic!("unsupported test tee: {other}"),
        };
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "RS256",
                "kid": "test-maa-key"
            }))
            .expect("jwt header"),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": "https://sharedeus.eus.attest.azure.net",
                "x-ms-attestation-type": attestation_type,
                "x-ms-compliance-status": "azure-compliant-cvm",
                report_data_claim: hex::encode(report_data)
            }))
            .expect("jwt claims"),
        );
        let signing_input = format!("{header}.{claims}");
        let signature: RsaSignature = signing_key.sign(signing_input.as_bytes());
        (
            format!(
                "{signing_input}.{}",
                URL_SAFE_NO_PAD.encode(signature.to_bytes())
            ),
            trusted_key,
        )
    }

    fn fake_tpmt_signature_rsassa(signature: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        out.extend_from_slice(signature);
        out
    }

    fn fake_tpm_quote(qualifying_data: &[u8; 32], pcrs: &[(u8, [u8; 32])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        body.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner
        body.extend_from_slice(&(qualifying_data.len() as u16).to_be_bytes());
        body.extend_from_slice(qualifying_data);
        body.extend_from_slice(&[0u8; 17]); // clockInfo
        body.extend_from_slice(&[0u8; 8]); // firmwareVersion
        body.extend_from_slice(&1u32.to_be_bytes()); // PCR selection count
        body.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        body.push(3); // sizeofSelect for PCRs 0..=23
        let mut select = [0u8; 3];
        for (index, _) in pcrs {
            select[usize::from(index / 8)] |= 1 << (index % 8);
        }
        body.extend_from_slice(&select);
        let mut pcr_concat = Vec::with_capacity(pcrs.len() * 32);
        for (_, value) in pcrs {
            pcr_concat.extend_from_slice(value);
        }
        let digest: [u8; 32] = Sha256::digest(&pcr_concat).into();
        body.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        body.extend_from_slice(&digest);

        let mut out = Vec::with_capacity(body.len() + 2);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn measurement_policy(expected_pcr: &str) -> MeasurementPolicy {
        measurement_policy_for_cloud(expected_pcr, "gcp")
    }

    fn measurement_policy_for_cloud(expected_pcr: &str, cloud: &str) -> MeasurementPolicy {
        measurement_policy_for_platform(expected_pcr, cloud, "tdx", "c3-standard-4")
    }

    fn measurement_policy_for_platform(
        expected_pcr: &str,
        cloud: &str,
        tee: &str,
        machine_type: &str,
    ) -> MeasurementPolicy {
        let base_image_id = compute_base_image_id("base", "v1");
        let profile_name = format!("{cloud}-{tee}");
        let profile_id = compute_platform_profile_id(&base_image_id, &profile_name);
        let variant_id = compute_variant_id(&profile_id, machine_type);
        MeasurementPolicy {
            source: "test-pack".to_string(),
            pack: MeasurementPack {
                schema: "atakit.measurement-pack.v1".to_string(),
                revision: 1,
                published_at: "2026-07-07T00:00:00Z".to_string(),
                base_image: BaseImage {
                    name: "base".to_string(),
                    version: "v1".to_string(),
                    id: hex0x(&base_image_id),
                    uri: None,
                    archive_sha256: None,
                },
                profiles: vec![MeasurementProfile {
                    name: profile_name,
                    id: hex0x(&profile_id),
                    cloud: cloud.to_string(),
                    tee: tee.to_string(),
                    invariants: vec![PcrSpec {
                        pcr_index: 4,
                        verify_type: "static".to_string(),
                        match_data: vec![expected_pcr.to_string()],
                        event_indices: Vec::new(),
                        total_events: None,
                    }],
                    variants: vec![MeasurementVariant {
                        name: machine_type.to_string(),
                        id: hex0x(&variant_id),
                        machine_types: vec![machine_type.to_string()],
                        override_pcrs: Vec::new(),
                        attributes: Vec::new(),
                    }],
                    attributes: Vec::new(),
                }],
            },
        }
    }

    fn assert_only_gcp_vendor_gap(failure: &VerificationFailure) {
        assert_eq!(failure.errors.len(), 1, "{:?}", failure.errors);
        assert_eq!(failure.errors[0].check, "gcp-tee-vendor-report");
    }

    fn assert_check_passed(failure: &VerificationFailure, name: &str) {
        assert!(
            failure
                .report
                .checks
                .iter()
                .any(|check| check.name == name && check.result == CheckResult::Pass),
            "check {name} did not pass: {:?}",
            failure.report.checks
        );
    }

    #[test]
    fn gcp_tdx_pcr15_binding_parses_full_quote_and_body_fixture() {
        let uuid = [0x42u8; 16];
        let expected = expected_gcp_tdx_pcr15_for_uuid(&uuid);
        for quote in [
            fake_gcp_tdx_full_quote_v4(&uuid),
            fake_gcp_tdx_quote_body(&uuid),
        ] {
            let mut report = VerificationReport {
                checks: Vec::new(),
                evidence: EvidenceSummary::default(),
            };
            let mut errors = Vec::new();

            let got = expected_gcp_tdx_pcr15(&mut report, &mut errors, &quote)
                .expect("GCP TDX PCR15 should derive from quote");

            assert_eq!(got, expected);
            assert!(
                errors.is_empty(),
                "unexpected binding errors for quote len {}: {errors:?}",
                quote.len()
            );
        }
    }

    #[test]
    fn verifier_reaches_gcp_vendor_gap_after_tls_binding_checks_pass() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let (response, gcp_roots) = gcp_response_and_roots(nonce, cert);
        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&pcr)),
            trust_anchors: TrustAnchors {
                gcp_roots,
                ..TrustAnchors::default()
            },
        })
        .expect_err("GCP TDX must fail closed without DCAP collateral");

        assert_only_gcp_vendor_gap(&failure);
        for check in [
            "gcp-ak-cert-chain",
            "tpm-quote-signature",
            "gcp-tdx-rtmr3-binding",
            "gcp-tee-vtpm-binding",
            "pcr-4-static",
        ] {
            assert_check_passed(&failure, check);
        }
    }

    #[test]
    fn verifies_gcp_snp_vendor_report_fixture() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();

        verify_snp_report_with_aux_certs(&report, &auxblob, &[ark.to_vec()], &[])
            .expect("GCP SEV-SNP fixture report should verify under fixture ARK");
    }

    #[test]
    fn verifies_gcp_snp_vendor_report_fixture_with_ark_hash() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let ark_hash: [u8; 32] = Sha256::digest(&ark).into();

        verify_snp_report_with_aux_certs(&report, &auxblob, &[], &[ark_hash])
            .expect("GCP SEV-SNP fixture report should verify under fixture ARK hash");
    }

    #[test]
    fn verifier_accepts_gcp_snp_tls_attestation_fixture() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let (response, gcp_roots, amd_ark) = gcp_snp_response_roots_and_ark(nonce, cert);

        let identity = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy_for_platform(
                &pcr,
                "gcp",
                "sev-snp",
                "n2d-standard-4",
            )),
            trust_anchors: TrustAnchors {
                gcp_roots,
                amd_ark_roots: vec![amd_ark],
                ..TrustAnchors::default()
            },
        })
        .expect("GCP SEV-SNP TLS attestation should verify with trusted roots");

        assert_eq!(identity.cert_der, cert);
        assert!(identity.base_image_id.is_some());
        assert!(identity.platform_profile_id.is_some());
        assert!(identity.variant_id.is_some());
    }

    #[test]
    fn rejects_gcp_snp_vendor_report_without_trusted_ark() {
        let (report, _, auxblob) = fixture_gcp_snp_report_and_certs();
        let err = verify_snp_report_with_aux_certs(&report, &auxblob, &[], &[])
            .expect_err("missing trusted ARK root must fail closed");

        assert!(err.contains("trusted AMD ARK roots"), "{err}");
    }

    #[test]
    fn rejects_gcp_snp_vendor_report_signature_tamper() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let mut tampered = report.to_vec();
        tampered[16] ^= 0x01;

        let err = verify_snp_report_with_aux_certs(&tampered, &auxblob, &[ark.to_vec()], &[])
            .expect_err("tampered SNP report must fail signature verification");

        assert!(err.contains("signature"), "{err}");
    }

    #[test]
    fn base_image_id_matches_existing_vector() {
        assert_eq!(
            hex0x(&compute_base_image_id("test-image", "v1.0.0")),
            "0xe1a0a8f3eb93a84d2c524e46e6604d6dea9f5254e5b2eefb07134fa47f7173a5"
        );
    }

    #[test]
    fn verifier_rejects_missing_measurement_policy() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: None,
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("missing policy must fail closed");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "measurement-policy"));
    }

    #[test]
    fn verifier_selects_measurement_ids_before_gcp_vendor_gap() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let (response, gcp_roots) = gcp_response_and_roots(nonce, cert);
        let gcp_root_hash: [u8; 32] = Keccak256::digest(&gcp_roots[0]).into();

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&pcr)),
            trust_anchors: TrustAnchors {
                gcp_root_hashes: vec![gcp_root_hash],
                ..TrustAnchors::default()
            },
        })
        .expect_err("GCP TDX must fail closed without DCAP collateral");

        assert_only_gcp_vendor_gap(&failure);
        assert_check_passed(&failure, "base-image-id");
        assert_check_passed(&failure, "platform-profile-id");
        assert_check_passed(&failure, "variant-id");
        assert_check_passed(&failure, "pcr-4-static");
    }

    #[test]
    fn verifier_rejects_gcp_pcr15_tee_binding_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let (mut response, gcp_roots) = gcp_response_and_roots(nonce, cert);
        response
            .tpm
            .pcrs
            .iter_mut()
            .find(|pcr| pcr.index == 15)
            .expect("PCR15 fixture")
            .sha256 = Some(format!("0x{}", "bb".repeat(32)));

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&pcr)),
            trust_anchors: TrustAnchors {
                gcp_roots,
                ..TrustAnchors::default()
            },
        })
        .expect_err("GCP PCR15 mismatch should fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "gcp-tee-vtpm-binding"));
    }

    #[test]
    fn verifier_applies_variant_pcr_override() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let (response, gcp_roots) = gcp_response_and_roots(nonce, cert);
        let mut policy = measurement_policy(&format!("0x{}", "bb".repeat(32)));
        policy.pack.profiles[0].variants[0]
            .override_pcrs
            .push(PcrSpec {
                pcr_index: 4,
                verify_type: "static".to_string(),
                match_data: vec![format!("0x{}", "aa".repeat(32))],
                event_indices: Vec::new(),
                total_events: None,
            });

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors {
                gcp_roots,
                ..TrustAnchors::default()
            },
        })
        .expect_err("GCP TDX must fail closed without DCAP collateral");

        assert_only_gcp_vendor_gap(&failure);
        assert_check_passed(&failure, "pcr-4-static");
    }

    #[test]
    fn verifier_rejects_ambiguous_measurement_profile() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        let mut duplicate = policy.pack.profiles[0].clone();
        duplicate.name = "gcp-tdx-duplicate".to_string();
        duplicate.id = hex0x(&compute_platform_profile_id(
            &compute_base_image_id("base", "v1"),
            &duplicate.name,
        ));
        policy.pack.profiles.push(duplicate);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("ambiguous profiles should fail closed");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "measurement-profile"));
    }

    #[test]
    fn verifier_rejects_ambiguous_measurement_variant() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        let profile_id =
            compute_platform_profile_id(&compute_base_image_id("base", "v1"), "gcp-tdx");
        let mut duplicate = policy.pack.profiles[0].variants[0].clone();
        duplicate.name = "c3-standard-4-duplicate".to_string();
        duplicate.id = hex0x(&compute_variant_id(&profile_id, &duplicate.name));
        policy.pack.profiles[0].variants.push(duplicate);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("ambiguous variants should fail closed");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "measurement-variant"));
    }

    #[test]
    fn verifier_rejects_variant_without_machine_type_match() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        policy.pack.profiles[0].variants[0].machine_types.clear();

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("variant without machine type match should fail closed");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "measurement-variant"));
    }

    #[test]
    fn verifier_rejects_empty_pcr_policy() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        policy.pack.profiles[0].invariants.clear();

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("empty PCR policy should fail closed");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "measurement-pcrs"));
    }

    #[test]
    fn verifier_rejects_dynamic_pcr_without_event_log() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        policy.pack.profiles[0].invariants[0].verify_type = "dynamicSubset".to_string();

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("dynamic PCR without an event log should fail closed");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "pcr-4-dynamicSubset"));
    }

    #[test]
    fn verifier_rejects_static_pcr_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "gcp");
        response.tpm.pcrs[0].sha256 = Some(format!("0x{}", "bb".repeat(32)));

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&format!("0x{}", "aa".repeat(32)))),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("PCR mismatch should fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "pcr-4-static"));
    }

    #[test]
    fn verifier_rejects_measurement_pack_id_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        policy.pack.profiles[0].variants[0].id = format!("0x{}", "44".repeat(32));

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("measurement pack ID mismatch should fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "variant-id"));
    }

    #[test]
    fn verifier_rejects_tpm_quote_pcr_digest_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "gcp");
        response.tpm.pcrs[0].sha256 = Some(format!("0x{}", "bb".repeat(32)));

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&format!("0x{}", "bb".repeat(32)))),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("response PCRs should not match quoted digest");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "tpm-quote-pcr-digest"));
    }

    #[test]
    fn verifier_rejects_pcr_values_outside_quote_selection() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "gcp");
        response.tpm.pcrs.push(PcrEvidence {
            index: 5,
            sha256: Some(format!("0x{}", "cc".repeat(32))),
            sha384: None,
        });

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&format!("0x{}", "aa".repeat(32)))),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("PCR values outside the Quote selection must fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "tpm-quote-pcr-selection"));
    }

    #[test]
    fn verifier_accepts_raw_tpms_attest_without_tpm2b_size_prefix() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "gcp");
        let prefixed_quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        assert_eq!(
            u16::from_be_bytes([prefixed_quote[0], prefixed_quote[1]]) as usize,
            prefixed_quote.len() - 2
        );
        response.tpm.quote = URL_SAFE_NO_PAD.encode(&prefixed_quote[2..]);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&format!("0x{}", "aa".repeat(32)))),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("GCP response still lacks production AK/vendor trust anchors");

        assert_check_passed(&failure, "tpm-quote-structure");
        assert_check_passed(&failure, "tpm-quote-challenge");
        assert_check_passed(&failure, "tpm-quote-pcr-digest");
        assert_check_passed(&failure, "tpm-quote-signature");
    }

    #[test]
    fn verifier_rejects_tpm_quote_signature_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "gcp");
        let mut signature = URL_SAFE_NO_PAD.decode(&response.tpm.signature).unwrap();
        let last = signature.last_mut().unwrap();
        *last ^= 0x01;
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&format!("0x{}", "aa".repeat(32)))),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("quote signature mismatch should fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "tpm-quote-signature"));
    }

    #[test]
    fn verifier_accepts_azure_hclak_rsa_quote_signature() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "azure");
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, signature, trusted_maa_key) = fake_azure_ak_binding_and_signature(&quote);
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.ak_binding = Some(binding);

        let result = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![trusted_maa_key],
                ..TrustAnchors::default()
            },
        });

        assert!(result.is_ok());
    }

    #[test]
    fn session_core_authenticates_azure_maa_key_and_raw_report_binding() {
        let quote = fake_tpm_quote(&[0u8; 32], &[(4, [0xaau8; 32])]);
        let (binding, _, trusted_maa_key) = fake_azure_ak_binding_and_signature(&quote);
        let binding_json: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&binding.data)
                .expect("binding base64"),
        )
        .expect("binding JSON");
        let hcl_var_data = URL_SAFE_NO_PAD
            .decode(binding_json["hclVarData"].as_str().expect("hclVarData"))
            .expect("hclVarData base64");
        let mut duplicate_hcl: serde_json::Value =
            serde_json::from_slice(&hcl_var_data).expect("HCL var_data JSON");
        let duplicate_key = duplicate_hcl["keys"][0].clone();
        duplicate_hcl["keys"]
            .as_array_mut()
            .expect("HCL keys array")
            .push(duplicate_key);
        let mut duplicate_binding_json = binding_json.clone();
        duplicate_binding_json["hclVarData"] = serde_json::Value::String(
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&duplicate_hcl).unwrap()),
        );
        let duplicate_binding = AkBinding {
            kind: "azure-maa-jwt".into(),
            data: URL_SAFE_NO_PAD.encode(serde_json::to_vec(&duplicate_binding_json).unwrap()),
        };
        assert!(parse_azure_hclak_public_key(&duplicate_binding)
            .unwrap_err()
            .contains("2 HCLAkPub entries"));
        let mut raw_tdx_quote = fake_gcp_tdx_full_quote_v4(&[0u8; 16]);
        let report_start = gcp_tdx_report_start(&raw_tdx_quote).expect("TDX report start");
        let report_data_start = report_start + TDX_REPORT_REPORT_DATA_OFFSET;
        raw_tdx_quote[report_data_start..report_data_start + 32]
            .copy_from_slice(&Sha256::digest(&hcl_var_data));
        raw_tdx_quote[report_data_start + 32..report_data_start + 64].fill(0);
        let evidence = TeeEvidence {
            kind: "azure_tdx".into(),
            report: URL_SAFE_NO_PAD.encode(raw_tdx_quote),
            auxiliary: Some(URL_SAFE_NO_PAD.encode(hcl_var_data)),
        };
        let trust = AzureMaaTrustKey {
            kid: "test-maa-key".into(),
            issuer: "https://sharedeus.eus.attest.azure.net".into(),
            not_after: u64::MAX,
            public_key: trusted_maa_key,
        };
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();
        verify_azure_maa_session_binding(
            &mut report,
            &mut errors,
            &binding,
            std::slice::from_ref(&trust),
            "tdx",
        );
        verify_azure_tee_var_data_binding(&mut report, &mut errors, &evidence, "tdx");
        assert!(errors.is_empty(), "{errors:?}");

        let mut duplicate_report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut duplicate_errors = Vec::new();
        verify_azure_maa_session_binding(
            &mut duplicate_report,
            &mut duplicate_errors,
            &binding,
            &[trust.clone(), trust.clone()],
            "tdx",
        );
        assert!(duplicate_errors
            .iter()
            .any(|error| error.check == "azure-maa-trust-selection"));

        let mut expired_report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut expired_errors = Vec::new();
        verify_azure_maa_session_binding(
            &mut expired_report,
            &mut expired_errors,
            &binding,
            &[AzureMaaTrustKey {
                not_after: 0,
                ..trust
            }],
            "tdx",
        );
        assert!(expired_errors
            .iter()
            .any(|error| error.check == "azure-maa-trust-selection"));

        let mut mismatched_evidence = evidence;
        let mut auxiliary = URL_SAFE_NO_PAD
            .decode(mismatched_evidence.auxiliary.as_deref().unwrap())
            .unwrap();
        auxiliary[0] ^= 1;
        mismatched_evidence.auxiliary = Some(URL_SAFE_NO_PAD.encode(auxiliary));
        let mut mismatch_report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut mismatch_errors = Vec::new();
        verify_azure_tee_var_data_binding(
            &mut mismatch_report,
            &mut mismatch_errors,
            &mismatched_evidence,
            "tdx",
        );
        assert!(mismatch_errors
            .iter()
            .any(|error| error.check == "azure-tee-var-data-binding"));
    }

    #[test]
    fn public_session_verifier_accepts_complete_local_bound_gcp_snp_evidence() {
        use crate::session::{
            compute_key_fingerprint, compute_session_id, compute_session_qualifying_data,
            request_binding_digest, AkEvidence, BindingMode, CertificateTrust, RawEvidence,
            SessionBinding, SessionEventHashes, SessionEvidenceBundle, SessionKeyDelegation,
            SessionOwner, SessionPcrPolicy, SessionPcrValue, SessionPcrVerifyType, SessionPlatform,
            SessionPlatformTrust, SessionPolicy, SessionPublicKey, SessionRecomputation,
            SessionRequestBinding, SessionTrust, SessionVerificationInputs, TpmCertifyEvidence,
            TpmQuoteEvidence, TrustedSessionPolicy,
        };

        let (snp_report, amd_ark, snp_cert_table) = fixture_gcp_snp_report_and_certs();
        let pcr4 = [0xaau8; 32];
        let pcr15 = expected_gcp_snp_pcr15(&snp_report).expect("fixture SNP PCR15");
        let owner_fingerprint = [0x11u8; 32];
        let owner_nonce = [0x22u8; 32];
        let registry = [0u8; 20];
        let qualifying_data =
            compute_session_qualifying_data(0, registry, owner_fingerprint, owner_nonce);

        let quote = fake_tpm_quote(&qualifying_data, &[(4, pcr4), (15, pcr15)]);
        let (ak_signing_key, ak_public, ak_chain, ak_roots) = fake_gcp_ak_chain();
        let quote_signature: P256Signature =
            ak_signing_key.sign(tpm2b_attest_body(&quote).expect("Quote body"));
        let quote_signature = fake_tpmt_signature_ecdsa(&quote_signature);

        let tpm_signing_key = P256SigningKey::from_slice(&[9u8; 32]).expect("TPM signing key");
        let tpm_signing_public = tpm_signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let tpmt_public =
            fake_tpmt_public_ecc_with_attributes(tpm_signing_key.verifying_key(), 0x0004_0072);
        let certify = fake_tpm_certify(&tpmt_public);
        let certify_signature: P256Signature =
            ak_signing_key.sign(tpm2b_attest_body(&certify).expect("Certify body"));
        let certify_signature = fake_tpmt_signature_ecdsa(&certify_signature);

        let session_signing_key = K256SigningKey::random(&mut OsRng);
        let session_public = session_signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let session_key_fingerprint = compute_key_fingerprint(3, &session_public);
        let tpm_signing_fingerprint = compute_key_fingerprint(2, &tpm_signing_public);
        let tee_report_hash: [u8; 32] = Keccak256::digest(&snp_report).into();
        let quote_signature_hash: [u8; 32] = Keccak256::digest(&quote_signature).into();
        let session_id = compute_session_id(quote_signature_hash, tee_report_hash);

        let workload_id = [0x31u8; 32];
        let base_image_id = [0x32u8; 32];
        let platform_profile_id = [0x33u8; 32];
        let measurement_variant_id = [0x34u8; 32];
        let mut delegation_abi = [0u8; 224];
        delegation_abi[..32].copy_from_slice(&Keccak256::digest(b"CVM_SESSION_KEY_DELEGATION"));
        delegation_abi[76..96].copy_from_slice(&registry);
        delegation_abi[96..128].copy_from_slice(&base_image_id);
        delegation_abi[128..160].copy_from_slice(&workload_id);
        delegation_abi[160..192].copy_from_slice(&session_id);
        delegation_abi[192..224].copy_from_slice(&session_key_fingerprint);
        let delegation_digest: [u8; 32] = Keccak256::digest(delegation_abi).into();
        let delegation_signature: P256Signature = tpm_signing_key
            .sign_prehash(&delegation_digest)
            .expect("delegation signature");

        let mut quoted_pcrs = Vec::with_capacity(64);
        quoted_pcrs.extend_from_slice(&pcr4);
        quoted_pcrs.extend_from_slice(&pcr15);
        let quote_pcr_digest: [u8; 32] = Sha256::digest(quoted_pcrs).into();
        let pcr4_policy = SessionPcrPolicy {
            pcr_index: 4,
            verify_type: SessionPcrVerifyType::Static,
            match_data: vec![hex0x(&pcr4)],
        };
        let mut bundle = SessionEvidenceBundle {
            format: 1,
            binding: SessionBinding {
                mode: BindingMode::Local,
                chain_id: 0,
                registry: hex0x(&registry),
                owner_nonce: hex0x(&owner_nonce),
                qualifying_data: hex0x(&qualifying_data),
            },
            platform: SessionPlatform {
                cloud: "gcp".into(),
                tee: "sev-snp".into(),
                machine_type: "n2d-standard-4".into(),
            },
            tee_evidence: RawEvidence {
                kind: "configfs_tsm".into(),
                report: URL_SAFE_NO_PAD.encode(&snp_report),
                auxiliary: Some(URL_SAFE_NO_PAD.encode(&snp_cert_table)),
            },
            ak_evidence: AkEvidence {
                kind: "gcp_cert_chain".into(),
                ak_public: URL_SAFE_NO_PAD.encode(&ak_public),
                collateral: URL_SAFE_NO_PAD.encode(solidity_abi_bytes_array(
                    &ak_chain.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                )),
            },
            tpm_quote: TpmQuoteEvidence {
                tpm2b_attest: URL_SAFE_NO_PAD.encode(&quote),
                tpm_signature: URL_SAFE_NO_PAD.encode(&quote_signature),
                signature_hash: hex0x(&quote_signature_hash),
            },
            tpm_certify: TpmCertifyEvidence {
                tpm2b_attest: URL_SAFE_NO_PAD.encode(&certify),
                tpm_signature: URL_SAFE_NO_PAD.encode(&certify_signature),
                tpmt_public: URL_SAFE_NO_PAD.encode(&tpmt_public),
            },
            pcr_values: vec![
                SessionPcrValue {
                    index: 4,
                    sha256: hex0x(&pcr4),
                    sha384: None,
                },
                SessionPcrValue {
                    index: 15,
                    sha256: hex0x(&pcr15),
                    sha384: None,
                },
            ],
            event_log_hashes: vec![
                SessionEventHashes {
                    pcr_index: 4,
                    sha256: Vec::new(),
                },
                SessionEventHashes {
                    pcr_index: 15,
                    sha256: Vec::new(),
                },
            ],
            session_key: SessionPublicKey {
                type_id: 3,
                bytes: hex0x(&session_public),
                fingerprint: hex0x(&session_key_fingerprint),
            },
            session_key_delegation: SessionKeyDelegation {
                tpm_signing_key: SessionPublicKey {
                    type_id: 2,
                    bytes: hex0x(&tpm_signing_public),
                    fingerprint: hex0x(&tpm_signing_fingerprint),
                },
                digest: hex0x(&delegation_digest),
                signature: hex0x(delegation_signature.to_der().as_bytes()),
            },
            session_id: hex0x(&session_id),
            policy: SessionPolicy {
                workload_id: hex0x(&workload_id),
                base_image_id: hex0x(&base_image_id),
                platform_profile_id: hex0x(&platform_profile_id),
                measurement_variant_id: hex0x(&measurement_variant_id),
                pcr_specs: vec![pcr4_policy.clone()],
            },
            owner: SessionOwner {
                fingerprint: hex0x(&owner_fingerprint),
                contract_authorization: None,
            },
            recomputation: SessionRecomputation {
                tee_report_bytes_hash: hex0x(&tee_report_hash),
                tpm_signature_hash: hex0x(&quote_signature_hash),
                session_id: hex0x(&session_id),
                quote_pcr_digest: hex0x(&quote_pcr_digest),
            },
        };

        let challenge = [0x55u8; 32];
        let canonical = serde_json_canonicalizer::to_vec(&bundle).expect("canonical bundle");
        let binding_digest = request_binding_digest(
            "ATAKIT_PORTAL_SESSION_REQUEST_BINDING_EVIDENCE_BUNDLE_V1",
            challenge,
            &canonical,
        );
        let (binding_signature, recovery_id) = session_signing_key
            .sign_prehash_recoverable(&binding_digest)
            .expect("request-binding signature");
        let mut binding_signature = binding_signature.to_bytes().to_vec();
        binding_signature.push(recovery_id.to_byte());

        let inputs = SessionVerificationInputs {
            bundle: bundle.clone(),
            request_binding: SessionRequestBinding {
                challenge: URL_SAFE_NO_PAD.encode(challenge),
                signature: hex0x(&binding_signature),
            },
            trust: SessionTrust {
                platform: SessionPlatformTrust::GcpSnp {
                    gcp_ak_roots: CertificateTrust {
                        certificates: ak_roots,
                        keccak256_hashes: Vec::new(),
                    },
                    amd_ark_roots: CertificateTrust {
                        certificates: vec![amd_ark],
                        keccak256_hashes: Vec::new(),
                    },
                },
                policy: TrustedSessionPolicy {
                    workload_id,
                    base_image_id,
                    platform_profile_id,
                    measurement_variant_id,
                    pcr_specs: vec![pcr4_policy],
                    effective_attributes: Vec::new(),
                    attribute_requirements: Vec::new(),
                },
            },
        };
        let verified = crate::session::verify_session_bundle(inputs.clone())
            .expect("complete local-bound GCP SNP evidence must verify");

        assert_eq!(verified.session_id, session_id);
        assert_eq!(verified.binding_mode, BindingMode::Local);
        assert!(bundle.owner.contract_authorization.take().is_none());

        let mut untrusted = inputs;
        let SessionPlatformTrust::GcpSnp {
            gcp_ak_roots,
            amd_ark_roots,
        } = &mut untrusted.trust.platform
        else {
            unreachable!("test selected GCP SNP trust")
        };
        gcp_ak_roots.certificates.clear();
        amd_ark_roots.certificates.clear();
        let failure = crate::session::verify_session_bundle(untrusted)
            .expect_err("evidence without caller-supplied trusted roots must fail");
        assert!(failure
            .errors
            .iter()
            .any(|error| error.contains("no trusted GCP AK root")));
        assert!(failure
            .errors
            .iter()
            .any(|error| error.contains("no trusted AMD SEV-SNP ARK root")));
    }

    #[test]
    fn verifier_rejects_azure_hclak_rsa_signature_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "azure");
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, mut signature, trusted_maa_key) = fake_azure_ak_binding_and_signature(&quote);
        let last = signature.last_mut().unwrap();
        *last ^= 0x01;
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.ak_binding = Some(binding);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![trusted_maa_key],
                ..TrustAnchors::default()
            },
        })
        .expect_err("Azure quote signature mismatch should fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "tpm-quote-signature"));
    }

    #[test]
    fn verifier_rejects_azure_maa_report_data_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "azure");
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, signature, _) = fake_azure_ak_binding_and_signature(&quote);
        let mut binding_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&binding.data).unwrap()).unwrap();
        let hcl_var_data = URL_SAFE_NO_PAD
            .decode(binding_json["hclVarData"].as_str().unwrap())
            .unwrap();
        let (bad_jwt, bad_trusted_maa_key) =
            fake_azure_maa_jwt(&[hcl_var_data, b"changed".to_vec()].concat(), "tdx");
        binding_json["jwt"] = serde_json::Value::String(bad_jwt);
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.ak_binding = Some(AkBinding {
            kind: "azure-maa-jwt".to_string(),
            data: URL_SAFE_NO_PAD.encode(serde_json::to_vec(&binding_json).unwrap()),
        });

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![bad_trusted_maa_key],
                ..TrustAnchors::default()
            },
        })
        .expect_err("Azure MAA report_data mismatch should fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "azure-maa-jwt"));
    }

    #[test]
    fn verifier_rejects_tpm_quote_challenge_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "gcp");
        response.tpm.quote =
            URL_SAFE_NO_PAD.encode(fake_tpm_quote(&[0x55u8; 32], &[(4, [0xaau8; 32])]));

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: Some(measurement_policy(&format!("0x{}", "aa".repeat(32)))),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("quote challenge mismatch should fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "tpm-quote-challenge"));
    }

    #[test]
    fn verifier_reports_wrong_nonce_and_cert() {
        let response = response_for([1u8; 32], b"cert-a", "gcp");
        let result = verify_tls_attestation(VerificationInputs {
            nonce: [2u8; 32],
            live_peer_cert_der: b"cert-b".to_vec(),
            response,
            measurement_policy: None,
            trust_anchors: TrustAnchors::default(),
        });
        let failure = result.unwrap_err();
        assert!(failure.errors.iter().any(|e| e.check == "nonce"));
        assert!(failure.errors.iter().any(|e| e.check == "live-cert-hash"));
    }

    #[test]
    fn verifier_rejects_aws_v1() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "aws");
        let result = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: None,
            trust_anchors: TrustAnchors::default(),
        });
        assert!(result
            .unwrap_err()
            .errors
            .iter()
            .any(|e| e.check == "platform-supported"));
    }

    #[test]
    fn verifier_rejects_qemu_as_production_evidence() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "qemu");
        let result = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            measurement_policy: None,
            trust_anchors: TrustAnchors::default(),
        });
        assert!(result
            .unwrap_err()
            .errors
            .iter()
            .any(|e| e.check == "platform-supported"));
    }

    #[test]
    fn parse_measurement_pack_json() {
        let bytes = br#"{
          "schema":"atakit.measurement-pack.v1",
          "revision":1,
          "publishedAt":"2026-07-07T00:00:00Z",
          "baseImage":{"name":"automata-linux","version":"v0.5.0","id":"0x00"},
          "profiles":[]
        }"#;
        let pack = parse_measurement_pack(bytes).unwrap();
        assert_eq!(pack.schema, "atakit.measurement-pack.v1");
        assert_eq!(pack.base_image.name, "automata-linux");
    }

    #[test]
    fn verify_measurement_pack_accepts_trusted_es256k_signature() {
        let bytes = br#"{"baseImage":{"id":"0x00","name":"base","version":"v1"},"profiles":[],"publishedAt":"2026-07-07T00:00:00Z","revision":1,"schema":"atakit.measurement-pack.v1"}"#;
        let signing_key = K256SigningKey::from_slice(&[9u8; 32]).expect("test publisher key");
        let signature: K256Signature = signing_key.sign(bytes);
        let trusted_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let pack = verify_measurement_pack(bytes, &signature.to_bytes(), &[trusted_key]).unwrap();

        assert_eq!(pack.base_image.name, "base");
    }

    #[test]
    fn verify_measurement_pack_rejects_missing_trusted_key() {
        let bytes = br#"{"baseImage":{"id":"0x00","name":"base","version":"v1"},"profiles":[],"publishedAt":"2026-07-07T00:00:00Z","revision":1,"schema":"atakit.measurement-pack.v1"}"#;
        let signing_key = K256SigningKey::from_slice(&[9u8; 32]).expect("test publisher key");
        let signature: K256Signature = signing_key.sign(bytes);

        let err = verify_measurement_pack(bytes, &signature.to_bytes(), &[]).unwrap_err();

        assert!(err
            .to_string()
            .contains("no trusted measurement publisher keys"));
    }

    #[test]
    fn verify_measurement_pack_rejects_untrusted_signature() {
        let bytes = br#"{"baseImage":{"id":"0x00","name":"base","version":"v1"},"profiles":[],"publishedAt":"2026-07-07T00:00:00Z","revision":1,"schema":"atakit.measurement-pack.v1"}"#;
        let signing_key = K256SigningKey::from_slice(&[9u8; 32]).expect("test publisher key");
        let other_key = K256SigningKey::from_slice(&[8u8; 32]).expect("test publisher key");
        let signature: K256Signature = signing_key.sign(bytes);
        let trusted_key = other_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let err =
            verify_measurement_pack(bytes, &signature.to_bytes(), &[trusted_key]).unwrap_err();

        assert!(err.to_string().contains("signature did not verify"));
    }

    #[test]
    fn verify_measurement_pack_rejects_noncanonical_json() {
        let bytes = br#"{"schema":"atakit.measurement-pack.v1","revision":1,"publishedAt":"2026-07-07T00:00:00Z","baseImage":{"name":"base","version":"v1","id":"0x00"},"profiles":[]}"#;
        let signing_key = K256SigningKey::from_slice(&[9u8; 32]).expect("test publisher key");
        let signature: K256Signature = signing_key.sign(bytes);
        let trusted_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let err =
            verify_measurement_pack(bytes, &signature.to_bytes(), &[trusted_key]).unwrap_err();

        assert!(err.to_string().contains("not canonical"));
    }
}
