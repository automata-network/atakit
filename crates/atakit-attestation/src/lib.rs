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
                    verify_tpm_quote(
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
            verify_azure_maa_jwt_binding(
                &mut report,
                &mut errors,
                binding,
                &inputs.trust_anchors.azure_maa_keys,
                &inputs.response.platform.tee,
            );
            verify_azure_hclak_quote_signature(
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
            verify_gcp_ak_cert_chain(
                &mut report,
                &mut errors,
                binding,
                ak_public,
                &inputs.trust_anchors.gcp_roots,
                &inputs.trust_anchors.gcp_root_hashes,
            );
            verify_tpm_quote_signature(
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
            verify_tpm_quote_signature(
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
        verify_gcp_tee_vtpm_binding(
            &mut report,
            &mut errors,
            inputs.response.tee_evidence.as_ref(),
            &inputs.response.platform.tee,
            &inputs.response.tpm.pcrs,
        );
        verify_gcp_tee_vendor_report(
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
                    verify_pcr_spec(&mut report, &mut errors, spec, &inputs.response.tpm.pcrs);
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

fn verify_gcp_ak_cert_chain(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    binding: &AkBinding,
    ak_public: &[u8],
    trusted_roots: &[Vec<u8>],
    trusted_root_hashes: &[[u8; 32]],
) {
    if binding.kind != "gcp-cert-chain" {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            format!(
                "GCP AK verification requires akBinding.kind=gcp-cert-chain, got {}",
                binding.kind
            ),
        );
        return;
    }
    if trusted_roots.is_empty() && trusted_root_hashes.is_empty() {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            "no trusted GCP AK root certificates or root hashes configured".to_string(),
        );
        return;
    }

    let chain = match parse_gcp_cert_chain(binding) {
        Ok(chain) => chain,
        Err(detail) => {
            fail(report, errors, "gcp-ak-cert-chain", detail);
            return;
        }
    };
    if chain.len() < 2 {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            "GCP AK cert chain must include at least leaf and root".to_string(),
        );
        return;
    }

    let (_, leaf) = match X509Certificate::from_der(&chain[0]) {
        Ok(parsed) => parsed,
        Err(e) => {
            fail(
                report,
                errors,
                "gcp-ak-cert-chain",
                format!("GCP AK leaf certificate did not parse: {e}"),
            );
            return;
        }
    };
    let ak_key = match parse_tpmt_public_ecc_p256(ak_public) {
        Ok(key) => key,
        Err(detail) => {
            fail(report, errors, "gcp-ak-cert-chain", detail);
            return;
        }
    };
    let ak_sec1 = ak_key.to_encoded_point(false);
    if leaf
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref()
        != ak_sec1.as_bytes()
    {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            "GCP AK certificate public key does not match tpm.akPublic".to_string(),
        );
        return;
    }

    for idx in 0..chain.len() - 1 {
        let (_, child) = match X509Certificate::from_der(&chain[idx]) {
            Ok(parsed) => parsed,
            Err(e) => {
                fail(
                    report,
                    errors,
                    "gcp-ak-cert-chain",
                    format!("GCP AK chain certificate {idx} did not parse: {e}"),
                );
                return;
            }
        };
        let (_, parent) = match X509Certificate::from_der(&chain[idx + 1]) {
            Ok(parsed) => parsed,
            Err(e) => {
                fail(
                    report,
                    errors,
                    "gcp-ak-cert-chain",
                    format!("GCP AK chain certificate {} did not parse: {e}", idx + 1),
                );
                return;
            }
        };
        if parent.subject() != child.issuer() {
            fail(
                report,
                errors,
                "gcp-ak-cert-chain",
                format!("GCP AK chain issuer/subject mismatch at certificate {idx}"),
            );
            return;
        }
        if let Err(e) = child.verify_signature(Some(&parent.tbs_certificate.subject_pki)) {
            fail(
                report,
                errors,
                "gcp-ak-cert-chain",
                format!("GCP AK chain signature failed at certificate {idx}: {e}"),
            );
            return;
        }
    }

    let root_der = chain.last().expect("checked chain len");
    let root_hash: [u8; 32] = Keccak256::digest(root_der).into();
    if !trusted_roots.iter().any(|trusted| trusted == root_der)
        && !trusted_root_hashes
            .iter()
            .any(|trusted| trusted == &root_hash)
    {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            format!(
                "GCP AK chain root is not trusted; keccak256(root_der)=0x{}",
                hex::encode(root_hash)
            ),
        );
        return;
    }
    let (_, root) = match X509Certificate::from_der(root_der) {
        Ok(parsed) => parsed,
        Err(e) => {
            fail(
                report,
                errors,
                "gcp-ak-cert-chain",
                format!("GCP AK root certificate did not parse: {e}"),
            );
            return;
        }
    };
    if root.subject() != root.issuer() {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            "GCP AK trusted root is not self-issued".to_string(),
        );
        return;
    }
    if let Err(e) = root.verify_signature(None) {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            format!("GCP AK trusted root self-signature failed: {e}"),
        );
        return;
    }

    pass(report, "gcp-ak-cert-chain");
}

fn parse_gcp_cert_chain(binding: &AkBinding) -> std::result::Result<Vec<Vec<u8>>, String> {
    let encoded_chain = decode_b64("akBinding.data", &binding.data).map_err(|e| e.to_string())?;
    let certs: Vec<String> = serde_json::from_slice(&encoded_chain)
        .map_err(|e| format!("GCP akBinding.data JSON did not parse as cert array: {e}"))?;
    certs
        .iter()
        .enumerate()
        .map(|(idx, cert)| {
            decode_b64("gcp.cert", cert)
                .map_err(|e| format!("GCP cert chain entry {idx} did not decode: {e}"))
        })
        .collect()
}

fn verify_gcp_tee_vtpm_binding(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    tee: &str,
    pcrs: &[PcrEvidence],
) {
    let Some(evidence) = evidence else {
        fail(
            report,
            errors,
            "gcp-tee-vtpm-binding",
            "GCP TEE evidence is missing".to_string(),
        );
        return;
    };
    let tee_report = match decode_b64("teeEvidence.report", &evidence.report) {
        Ok(bytes) => bytes,
        Err(e) => {
            fail(report, errors, "gcp-tee-vtpm-binding", e.to_string());
            return;
        }
    };
    let expected_pcr15 = match tee {
        "tdx" => match expected_gcp_tdx_pcr15(report, errors, &tee_report) {
            Some(expected) => expected,
            None => return,
        },
        "sev-snp" => match expected_gcp_snp_pcr15(&tee_report) {
            Ok(expected) => expected,
            Err(detail) => {
                fail(report, errors, "gcp-tee-vtpm-binding", detail);
                return;
            }
        },
        other => {
            fail(
                report,
                errors,
                "gcp-tee-vtpm-binding",
                format!("GCP TEE/vTPM binding is unsupported for tee={other}"),
            );
            return;
        }
    };
    verify_expected_pcr15(report, errors, pcrs, &expected_pcr15);
}

fn expected_gcp_tdx_pcr15(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    quote: &[u8],
) -> Option<[u8; 32]> {
    let report_start = match gcp_tdx_report_start(quote) {
        Ok(start) => start,
        Err(detail) => {
            fail(report, errors, "gcp-tee-vtpm-binding", detail);
            return None;
        }
    };
    let report_data_start = report_start + TDX_REPORT_REPORT_DATA_OFFSET;
    let uuid_end = report_data_start + GCP_TDX_UUID_LEN;
    if quote.len() < uuid_end {
        fail(
            report,
            errors,
            "gcp-tee-vtpm-binding",
            format!(
                "GCP TDX quote is too short for report_data UUID: got {}, need {uuid_end}",
                quote.len()
            ),
        );
        return None;
    }
    let rtmr3_start = report_start + TDX_REPORT_RTMR3_OFFSET;
    let rtmr3_end = rtmr3_start + 48;
    if quote.len() < rtmr3_end {
        fail(
            report,
            errors,
            "gcp-tdx-rtmr3-binding",
            format!(
                "GCP TDX quote is too short for RTMR3: got {}, need {rtmr3_end}",
                quote.len()
            ),
        );
        return None;
    }
    let uuid = &quote[report_data_start..uuid_end];
    let actual_rtmr3 = &quote[rtmr3_start..rtmr3_end];

    let mut rtmr3_input = Vec::with_capacity(96);
    rtmr3_input.extend_from_slice(&[0u8; 48]);
    rtmr3_input.extend_from_slice(&[0u8; 32]);
    rtmr3_input.extend_from_slice(uuid);
    let expected_rtmr3: [u8; 48] = Sha384::digest(&rtmr3_input).into();
    check(
        report,
        errors,
        "gcp-tdx-rtmr3-binding",
        actual_rtmr3 == expected_rtmr3,
        format!(
            "GCP TDX RTMR3 does not match report_data UUID; expected 0x{}",
            hex::encode(expected_rtmr3)
        ),
    );

    let mut pcr_input = Vec::with_capacity(64);
    pcr_input.extend_from_slice(&[0u8; 32]);
    pcr_input.extend_from_slice(&[0u8; 16]);
    pcr_input.extend_from_slice(uuid);
    Some(Sha256::digest(&pcr_input).into())
}

fn gcp_tdx_report_start(quote: &[u8]) -> std::result::Result<usize, String> {
    let Some(version) = read_le_u16_opt(quote, 0) else {
        return Ok(0);
    };
    let Some(tee_type) = read_le_u32_opt(quote, 4) else {
        return Ok(0);
    };
    match version {
        4 if tee_type == TDX_TEE_TYPE => Ok(TDX_QUOTE_HEADER_LEN),
        5 if tee_type == TDX_TEE_TYPE => {
            let body_type = read_le_u16_opt(quote, TDX_QUOTE_HEADER_LEN)
                .ok_or_else(|| "GCP TDX quote v5 is too short for body header".to_string())?;
            match body_type {
                TDX_BODY_TD_REPORT10_TYPE | TDX_BODY_TD_REPORT15_TYPE => {
                    Ok(TDX_QUOTE_HEADER_LEN + TDX_QUOTE_V5_BODY_HEADER_LEN)
                }
                other => Err(format!(
                    "GCP TDX quote v5 has unsupported body type {other}"
                )),
            }
        }
        4 | 5 => Err(format!("GCP TDX quote has non-TDX tee_type 0x{tee_type:x}")),
        // Unit fixtures and some low-level callers pass only the TDREPORT
        // body. Real endpoint evidence is a full TDQUOTE and takes the
        // branches above.
        _ => Ok(0),
    }
}

fn read_le_u16_opt(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_le_u32_opt(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn expected_gcp_snp_pcr15(report: &[u8]) -> std::result::Result<[u8; 32], String> {
    let end = SNP_REPORT_REPORT_ID_OFFSET + SNP_REPORT_REPORT_ID_LEN;
    if report.len() < end {
        return Err(format!(
            "GCP SNP report is too short for report_id: got {}, need {end}",
            report.len()
        ));
    }
    let report_id = &report[SNP_REPORT_REPORT_ID_OFFSET..end];
    let mut pcr_input = Vec::with_capacity(64);
    pcr_input.extend_from_slice(&[0u8; 32]);
    pcr_input.extend_from_slice(report_id);
    Ok(Sha256::digest(&pcr_input).into())
}

fn verify_expected_pcr15(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    pcrs: &[PcrEvidence],
    expected_pcr15: &[u8; 32],
) {
    let Some(pcr15) = pcrs.iter().find(|pcr| pcr.index == 15) else {
        fail(
            report,
            errors,
            "gcp-tee-vtpm-binding",
            "TPM evidence does not contain PCR 15".to_string(),
        );
        return;
    };
    let Some(actual) = &pcr15.sha256 else {
        fail(
            report,
            errors,
            "gcp-tee-vtpm-binding",
            "TPM evidence PCR 15 does not contain a SHA-256 value".to_string(),
        );
        return;
    };
    match decode_hex_32("pcr15.sha256", actual) {
        Ok(actual) => check(
            report,
            errors,
            "gcp-tee-vtpm-binding",
            actual == *expected_pcr15,
            format!(
                "GCP PCR15 does not match TEE binding value; expected {}",
                hex0x(expected_pcr15)
            ),
        ),
        Err(e) => fail(report, errors, "gcp-tee-vtpm-binding", e.to_string()),
    }
}

fn verify_gcp_tee_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    tee: &str,
    collateral: &serde_json::Value,
    trusted_amd_ark_roots: &[Vec<u8>],
    trusted_amd_ark_root_hashes: &[[u8; 32]],
) {
    match tee {
        "sev-snp" => verify_gcp_snp_vendor_report(
            report,
            errors,
            evidence,
            trusted_amd_ark_roots,
            trusted_amd_ark_root_hashes,
        ),
        "tdx" => verify_gcp_tdx_vendor_report(report, errors, evidence, collateral),
        other => fail(
            report,
            errors,
            "gcp-tee-vendor-report",
            format!("GCP raw TEE vendor verification is unsupported for tee={other}"),
        ),
    }
}

fn verify_gcp_tdx_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    collateral: &serde_json::Value,
) {
    let Some(evidence) = evidence else {
        fail(
            report,
            errors,
            "gcp-tee-vendor-report",
            "GCP TDX TEE evidence is missing".to_string(),
        );
        return;
    };
    let raw_quote = match decode_b64("teeEvidence.report", &evidence.report) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            fail(
                report,
                errors,
                "gcp-tee-vendor-report",
                "GCP TDX quote is empty".to_string(),
            );
            return;
        }
        Err(e) => {
            fail(report, errors, "gcp-tee-vendor-report", e.to_string());
            return;
        }
    };
    let collateral = match parse_gcp_tdx_dcap_collateral(collateral) {
        Ok(collateral) => collateral,
        Err(detail) => {
            fail(report, errors, "gcp-tee-vendor-report", detail);
            return;
        }
    };
    let now_secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(e) => {
            fail(
                report,
                errors,
                "gcp-tee-vendor-report",
                format!("system clock is before Unix epoch: {e}"),
            );
            return;
        }
    };
    match dcap_qvl::verify::QuoteVerifier::new_prod().verify(&raw_quote, &collateral, now_secs) {
        Ok(_) => pass(report, "gcp-tee-vendor-report"),
        Err(e) => fail(
            report,
            errors,
            "gcp-tee-vendor-report",
            format!("GCP TDX DCAP quote verification failed: {e:#}"),
        ),
    }
}

fn parse_gcp_tdx_dcap_collateral(
    collateral: &serde_json::Value,
) -> std::result::Result<dcap_qvl::QuoteCollateralV3, String> {
    let value = collateral.get("gcpTdxDcap").unwrap_or(collateral);
    if value.is_null() || value.as_object().is_some_and(|object| object.is_empty()) {
        return Err(
            "GCP TDX DCAP collateral is missing; expected collateral.gcpTdxDcap".to_string(),
        );
    }
    serde_json::from_value(value.clone())
        .map_err(|e| format!("GCP TDX DCAP collateral did not parse: {e}"))
}

fn verify_gcp_snp_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    trusted_amd_ark_roots: &[Vec<u8>],
    trusted_amd_ark_root_hashes: &[[u8; 32]],
) {
    let Some(evidence) = evidence else {
        fail(
            report,
            errors,
            "gcp-tee-vendor-report",
            "GCP SNP TEE evidence is missing".to_string(),
        );
        return;
    };
    let snp_report = match decode_b64("teeEvidence.report", &evidence.report) {
        Ok(bytes) => bytes,
        Err(e) => {
            fail(report, errors, "gcp-tee-vendor-report", e.to_string());
            return;
        }
    };
    let Some(auxiliary) = &evidence.auxiliary else {
        fail(
            report,
            errors,
            "gcp-tee-vendor-report",
            "GCP SNP auxiliary cert table is missing".to_string(),
        );
        return;
    };
    let auxblob = match decode_b64("teeEvidence.auxiliary", auxiliary) {
        Ok(bytes) => bytes,
        Err(e) => {
            fail(report, errors, "gcp-tee-vendor-report", e.to_string());
            return;
        }
    };
    if trusted_amd_ark_roots.is_empty() && trusted_amd_ark_root_hashes.is_empty() {
        fail(
            report,
            errors,
            "gcp-tee-vendor-report",
            "no trusted AMD SEV-SNP ARK root certificates or root hashes configured".to_string(),
        );
        return;
    }
    match verify_snp_report_with_aux_certs(
        &snp_report,
        &auxblob,
        trusted_amd_ark_roots,
        trusted_amd_ark_root_hashes,
    ) {
        Ok(()) => pass(report, "gcp-tee-vendor-report"),
        Err(detail) => fail(report, errors, "gcp-tee-vendor-report", detail),
    }
}

fn verify_snp_report_with_aux_certs(
    report: &[u8],
    auxblob: &[u8],
    trusted_amd_ark_roots: &[Vec<u8>],
    trusted_amd_ark_root_hashes: &[[u8; 32]],
) -> std::result::Result<(), String> {
    if report.len() < SNP_REPORT_MIN_LEN {
        return Err(format!(
            "GCP SNP report is too short: got {}, need at least {SNP_REPORT_MIN_LEN}",
            report.len()
        ));
    }
    let sig_algo = read_le_u32(report, SNP_REPORT_SIG_ALGO_OFFSET, "SNP sig_algo")?;
    if sig_algo != SNP_SIG_ALGO_ECDSA_P384_SHA384 {
        return Err(format!(
            "GCP SNP report sig_algo is {sig_algo}, expected ECDSA P-384 SHA-384 ({SNP_SIG_ALGO_ECDSA_P384_SHA384})"
        ));
    }

    let certs = parse_amd_snp_cert_table(auxblob)?;
    let ark = certs
        .ark
        .as_deref()
        .ok_or_else(|| "GCP SNP auxblob missing ARK certificate".to_string())?;
    let ask = certs
        .ask
        .as_deref()
        .ok_or_else(|| "GCP SNP auxblob missing ASK certificate".to_string())?;
    let signer = snp_signing_key_type(report)?;
    let vek =
        match signer {
            SnpSigningKeyType::Vcek => certs.vcek.as_deref().ok_or_else(|| {
                "GCP SNP report is VCEK-signed but auxblob lacks VCEK".to_string()
            })?,
            SnpSigningKeyType::Vlek => certs.vlek.as_deref().ok_or_else(|| {
                "GCP SNP report is VLEK-signed but auxblob lacks VLEK".to_string()
            })?,
        };

    verify_amd_snp_cert_chain(
        ark,
        ask,
        vek,
        trusted_amd_ark_roots,
        trusted_amd_ark_root_hashes,
    )?;
    verify_snp_vek_extensions(vek, report, signer)?;
    verify_snp_report_signature(vek, report)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnpSigningKeyType {
    Vcek,
    Vlek,
}

fn snp_signing_key_type(report: &[u8]) -> std::result::Result<SnpSigningKeyType, String> {
    let key_settings = read_le_u32(report, SNP_REPORT_KEY_SETTINGS_OFFSET, "SNP key_settings")?;
    match key_settings & 0b11100 {
        0b000 => Ok(SnpSigningKeyType::Vcek),
        0b100 => Ok(SnpSigningKeyType::Vlek),
        value => Err(format!("unknown SNP signing key type bits 0x{value:x}")),
    }
}

#[derive(Default)]
struct AmdSnpCertTable {
    ark: Option<Vec<u8>>,
    ask: Option<Vec<u8>>,
    vcek: Option<Vec<u8>>,
    vlek: Option<Vec<u8>>,
}

fn parse_amd_snp_cert_table(auxblob: &[u8]) -> std::result::Result<AmdSnpCertTable, String> {
    let mut table = AmdSnpCertTable::default();
    let mut offset = 0usize;
    while offset + 24 <= auxblob.len() {
        let guid_bytes = &auxblob[offset..offset + 16];
        if guid_bytes.iter().all(|&b| b == 0) {
            break;
        }
        let cert_offset = u32::from_le_bytes(
            auxblob[offset + 16..offset + 20]
                .try_into()
                .expect("slice length"),
        ) as usize;
        let cert_len = u32::from_le_bytes(
            auxblob[offset + 20..offset + 24]
                .try_into()
                .expect("slice length"),
        ) as usize;
        let cert_end = cert_offset
            .checked_add(cert_len)
            .ok_or_else(|| "SNP cert table entry overflows usize".to_string())?;
        if cert_end > auxblob.len() {
            return Err(format!(
                "SNP cert table entry extends past auxblob: offset={cert_offset} len={cert_len} auxblob={}",
                auxblob.len()
            ));
        }
        let cert = auxblob[cert_offset..cert_end].to_vec();
        if guid_bytes == SNP_CERT_TABLE_ARK_GUID {
            table.ark = Some(cert);
        } else if guid_bytes == SNP_CERT_TABLE_ASK_GUID {
            table.ask = Some(cert);
        } else if guid_bytes == SNP_CERT_TABLE_VCEK_GUID {
            table.vcek = Some(cert);
        } else if guid_bytes == SNP_CERT_TABLE_VLEK_GUID {
            table.vlek = Some(cert);
        }
        offset += 24;
    }
    Ok(table)
}

fn verify_amd_snp_cert_chain(
    ark_der: &[u8],
    ask_der: &[u8],
    vek_der: &[u8],
    trusted_amd_ark_roots: &[Vec<u8>],
    trusted_amd_ark_root_hashes: &[[u8; 32]],
) -> std::result::Result<(), String> {
    let ark_hash: [u8; 32] = Sha256::digest(ark_der).into();
    if !trusted_amd_ark_roots
        .iter()
        .any(|trusted| trusted.as_slice() == ark_der)
        && !trusted_amd_ark_root_hashes.contains(&ark_hash)
    {
        return Err(format!(
            "SNP ARK certificate is not in trusted AMD ARK roots; sha256(ark_der)=0x{}",
            hex::encode(ark_hash)
        ));
    }

    let (_, ark) = X509Certificate::from_der(ark_der)
        .map_err(|e| format!("SNP ARK certificate did not parse: {e}"))?;
    let (_, ask) = X509Certificate::from_der(ask_der)
        .map_err(|e| format!("SNP ASK certificate did not parse: {e}"))?;
    let (_, vek) = X509Certificate::from_der(vek_der)
        .map_err(|e| format!("SNP VEK certificate did not parse: {e}"))?;

    if ark.subject() != ark.issuer() {
        return Err("SNP ARK trusted root is not self-issued".to_string());
    }
    verify_amd_snp_cert_signature(ark_der, &ark, &ark, "SNP ARK self-signature")?;
    if ask.issuer() != ark.subject() {
        return Err("SNP ASK issuer does not match ARK subject".to_string());
    }
    verify_amd_snp_cert_signature(ask_der, &ask, &ark, "SNP ASK signature")?;
    if vek.issuer() != ask.subject() {
        return Err("SNP VEK issuer does not match ASK subject".to_string());
    }
    verify_amd_snp_cert_signature(vek_der, &vek, &ask, "SNP VEK signature")?;
    Ok(())
}

fn verify_amd_snp_cert_signature(
    cert_der: &[u8],
    cert: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    label: &str,
) -> std::result::Result<(), String> {
    let public_key = RsaPublicKey::from_pkcs1_der(
        issuer
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
    )
    .map_err(|e| format!("{label} issuer key is not RSA PKCS#1: {e}"))?;
    let signature = RsaPssSignature::try_from(cert.signature_value.data.as_ref())
        .map_err(|e| format!("{label} value is not a valid RSA-PSS signature: {e}"))?;
    let verifying_key = RsaPssVerifyingKey::<Sha384>::new_with_salt_len(public_key, 48);
    let tbs_der = tbs_certificate_der(cert_der).map_err(|e| format!("{label}: {e}"))?;
    verifying_key
        .verify(tbs_der, &signature)
        .map_err(|e| format!("{label} failed: {e}"))
}

fn tbs_certificate_der(cert_der: &[u8]) -> std::result::Result<&[u8], String> {
    let (outer_content_offset, outer_len) = der_tlv(cert_der, 0x30, "certificate")?;
    let outer_end = outer_content_offset
        .checked_add(outer_len)
        .ok_or_else(|| "certificate length overflows usize".to_string())?;
    if outer_end > cert_der.len() {
        return Err("certificate DER length exceeds buffer".to_string());
    }
    let tbs_start = outer_content_offset;
    let (tbs_content_offset, tbs_len) =
        der_tlv(&cert_der[tbs_start..outer_end], 0x30, "tbsCertificate")?;
    let tbs_end = tbs_start
        .checked_add(tbs_content_offset)
        .and_then(|value| value.checked_add(tbs_len))
        .ok_or_else(|| "tbsCertificate length overflows usize".to_string())?;
    Ok(&cert_der[tbs_start..tbs_end])
}

fn der_tlv(
    data: &[u8],
    expected_tag: u8,
    label: &str,
) -> std::result::Result<(usize, usize), String> {
    if data.first().copied() != Some(expected_tag) {
        return Err(format!(
            "{label} DER did not start with tag 0x{expected_tag:02x}"
        ));
    }
    let first_len = *data
        .get(1)
        .ok_or_else(|| format!("{label} DER is missing length"))?;
    if first_len & 0x80 == 0 {
        return Ok((2, usize::from(first_len)));
    }
    let len_len = usize::from(first_len & 0x7f);
    if len_len == 0 || len_len > 4 {
        return Err(format!(
            "{label} DER has unsupported length width {len_len}"
        ));
    }
    let len_bytes = data
        .get(2..2 + len_len)
        .ok_or_else(|| format!("{label} DER length is truncated"))?;
    let mut len = 0usize;
    for byte in len_bytes {
        len = (len << 8) | usize::from(*byte);
    }
    Ok((2 + len_len, len))
}

fn verify_snp_vek_extensions(
    vek_der: &[u8],
    report: &[u8],
    signer: SnpSigningKeyType,
) -> std::result::Result<(), String> {
    let (_, vek) = X509Certificate::from_der(vek_der)
        .map_err(|e| format!("SNP VEK certificate did not parse: {e}"))?;
    let tcb = SnpTcb::from_report(report)?;
    check_snp_tcb_extension(&vek, "1.3.6.1.4.1.3704.1.3.1", tcb.bootloader, "bootloader")?;
    check_snp_tcb_extension(&vek, "1.3.6.1.4.1.3704.1.3.2", tcb.tee, "tee")?;
    check_snp_tcb_extension(&vek, "1.3.6.1.4.1.3704.1.3.3", tcb.snp, "snp")?;
    check_snp_tcb_extension(&vek, "1.3.6.1.4.1.3704.1.3.8", tcb.microcode, "microcode")?;

    if signer == SnpSigningKeyType::Vcek {
        let chip_id = read_exact_at(report, SNP_REPORT_CHIP_ID_OFFSET, 64, "SNP chip_id")?;
        check_snp_octet_extension(&vek, "1.3.6.1.4.1.3704.1.4", chip_id, "chip_id")?;
    }
    Ok(())
}

struct SnpTcb {
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

impl SnpTcb {
    fn from_report(report: &[u8]) -> std::result::Result<Self, String> {
        let tcb = read_exact_at(
            report,
            SNP_REPORT_REPORTED_TCB_OFFSET,
            8,
            "SNP reported_tcb",
        )?;
        Ok(Self {
            bootloader: tcb[0],
            tee: tcb[1],
            snp: tcb[6],
            microcode: tcb[7],
        })
    }
}

fn check_snp_tcb_extension(
    cert: &X509Certificate<'_>,
    oid: &str,
    expected: u8,
    name: &str,
) -> std::result::Result<(), String> {
    let Some(ext) = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == oid)
    else {
        return Ok(());
    };
    let value = match ext.value {
        [0x02, 0x01, value] | [0x02, 0x02, 0x00, value] => *value,
        raw if raw.len() == 1 => raw[0],
        raw => {
            return Err(format!(
                "SNP VEK {name} extension has unsupported encoding: 0x{}",
                hex::encode(raw)
            ))
        }
    };
    if value != expected {
        return Err(format!(
            "SNP VEK {name} extension value {value} does not match report value {expected}"
        ));
    }
    Ok(())
}

fn check_snp_octet_extension(
    cert: &X509Certificate<'_>,
    oid: &str,
    expected: &[u8],
    name: &str,
) -> std::result::Result<(), String> {
    let Some(ext) = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == oid)
    else {
        return Ok(());
    };
    let actual = if ext.value.len() >= 2 && ext.value[0] == 0x04 {
        let len = usize::from(ext.value[1]);
        if ext.value.len() != len + 2 {
            return Err(format!(
                "SNP VEK {name} extension OCTET STRING length is malformed"
            ));
        }
        &ext.value[2..]
    } else {
        ext.value
    };
    if actual != expected {
        return Err(format!(
            "SNP VEK {name} extension does not match report value"
        ));
    }
    Ok(())
}

fn verify_snp_report_signature(vek_der: &[u8], report: &[u8]) -> std::result::Result<(), String> {
    let (_, vek) = X509Certificate::from_der(vek_der)
        .map_err(|e| format!("SNP VEK certificate did not parse: {e}"))?;
    let public_key = vek
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| format!("SNP VEK public key is not P-384 SEC1: {e}"))?;
    let signature = parse_snp_report_signature(report)?;
    verifying_key
        .verify(&report[..SNP_REPORT_SIGNED_LEN], &signature)
        .map_err(|e| format!("SNP report signature did not verify under VEK: {e}"))
}

fn parse_snp_report_signature(report: &[u8]) -> std::result::Result<P384Signature, String> {
    let end = SNP_REPORT_SIGNATURE_OFFSET + 144;
    if report.len() < end {
        return Err(format!(
            "SNP report is too short for signature: got {}, need {end}",
            report.len()
        ));
    }
    let r = le_72_to_be_48(&report[SNP_REPORT_SIGNATURE_OFFSET..SNP_REPORT_SIGNATURE_OFFSET + 72]);
    let s = le_72_to_be_48(
        &report[SNP_REPORT_SIGNATURE_OFFSET + 72..SNP_REPORT_SIGNATURE_OFFSET + 144],
    );
    P384Signature::from_scalars(r, s).map_err(|e| format!("SNP signature is invalid: {e}"))
}

fn le_72_to_be_48(value: &[u8]) -> [u8; 48] {
    debug_assert_eq!(value.len(), 72);
    let mut out = [0u8; 48];
    for idx in 0..48 {
        out[47 - idx] = value[idx];
    }
    out
}

fn read_le_u32(data: &[u8], offset: usize, field: &str) -> std::result::Result<u32, String> {
    let bytes = read_exact_at(data, offset, 4, field)?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("slice length")))
}

fn read_exact_at<'a>(
    data: &'a [u8],
    offset: usize,
    len: usize,
    field: &str,
) -> std::result::Result<&'a [u8], String> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| format!("{field} offset overflows usize"))?;
    data.get(offset..end)
        .ok_or_else(|| format!("{field} is out of bounds: got {}, need {end}", data.len()))
}

fn verify_azure_maa_jwt_binding(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    binding: &AkBinding,
    trusted_maa_keys: &[Vec<u8>],
    tee: &str,
) {
    let binding = match parse_azure_maa_binding(binding) {
        Ok(binding) => binding,
        Err(detail) => {
            fail(report, errors, "azure-maa-jwt", detail);
            return;
        }
    };
    let hcl_var_data = match decode_b64("akBinding.hclVarData", &binding.hcl_var_data) {
        Ok(bytes) => bytes,
        Err(e) => {
            fail(report, errors, "azure-maa-jwt", e.to_string());
            return;
        }
    };
    let (signing_input, header, claims, signature) = match parse_azure_maa_jwt(&binding.jwt) {
        Ok(parsed) => parsed,
        Err(detail) => {
            fail(report, errors, "azure-maa-jwt", detail);
            return;
        }
    };

    if header.alg != "RS256" {
        fail(
            report,
            errors,
            "azure-maa-jwt",
            format!("MAA JWT alg is {}, expected RS256", header.alg),
        );
        return;
    }
    if trusted_maa_keys.is_empty() {
        fail(
            report,
            errors,
            "azure-maa-jwt",
            "no trusted Azure MAA signing keys configured".to_string(),
        );
        return;
    }
    if claims.iss.is_empty() {
        fail(
            report,
            errors,
            "azure-maa-jwt",
            "MAA JWT issuer is empty".to_string(),
        );
        return;
    }
    if claims.compliance_status != "azure-compliant-cvm" {
        fail(
            report,
            errors,
            "azure-maa-jwt",
            format!(
                "MAA compliance status is {}, expected azure-compliant-cvm",
                claims.compliance_status
            ),
        );
        return;
    }

    let expected_attestation_type = match tee {
        "tdx" => "tdxvm",
        "sev-snp" => "sevsnpvm",
        other => {
            fail(
                report,
                errors,
                "azure-maa-jwt",
                format!("unsupported Azure TEE type for MAA JWT: {other}"),
            );
            return;
        }
    };
    if claims.attestation_type != expected_attestation_type {
        fail(
            report,
            errors,
            "azure-maa-jwt",
            format!(
                "MAA attestation type is {}, expected {expected_attestation_type}",
                claims.attestation_type
            ),
        );
        return;
    }

    let report_data = match azure_report_data_claim(&claims, tee) {
        Ok(report_data) => report_data,
        Err(detail) => {
            fail(report, errors, "azure-maa-jwt", detail);
            return;
        }
    };
    let hcl_hash: [u8; 32] = Sha256::digest(&hcl_var_data).into();
    if report_data[0..32] != hcl_hash {
        fail(
            report,
            errors,
            "azure-maa-jwt",
            "MAA report_data prefix does not match sha256(hclVarData)".to_string(),
        );
        return;
    }
    if report_data[32..64] != [0u8; 32] {
        fail(
            report,
            errors,
            "azure-maa-jwt",
            "MAA report_data suffix is not zero".to_string(),
        );
        return;
    }

    let signature = match RsaSignature::try_from(signature.as_slice()) {
        Ok(signature) => signature,
        Err(e) => {
            fail(
                report,
                errors,
                "azure-maa-jwt",
                format!("MAA JWT signature is invalid: {e}"),
            );
            return;
        }
    };

    let mut key_errors = Vec::new();
    for key_bytes in trusted_maa_keys {
        let key = match parse_rsa_public_key(key_bytes) {
            Ok(key) => key,
            Err(detail) => {
                key_errors.push(detail);
                continue;
            }
        };
        let verifier = RsaVerifyingKey::<rsa::sha2::Sha256>::new(key);
        if verifier
            .verify(signing_input.as_bytes(), &signature)
            .is_ok()
        {
            pass(report, "azure-maa-jwt");
            return;
        }
    }

    let kid = header.kid.unwrap_or_else(|| "<missing>".to_string());
    let detail = if key_errors.is_empty() {
        format!("MAA JWT signature did not verify under any trusted key; kid={kid}")
    } else {
        format!(
            "MAA JWT signature did not verify under any trusted key; kid={kid}; key parse errors: {}",
            key_errors.join("; ")
        )
    };
    fail(report, errors, "azure-maa-jwt", detail);
}

fn parse_azure_maa_binding(binding: &AkBinding) -> std::result::Result<AzureMaaAkBinding, String> {
    if binding.kind != "azure-maa-jwt" {
        return Err(format!(
            "Azure MAA binding requires akBinding.kind=azure-maa-jwt, got {}",
            binding.kind
        ));
    }
    let binding_bytes = decode_b64("akBinding.data", &binding.data).map_err(|e| e.to_string())?;
    serde_json::from_slice(&binding_bytes)
        .map_err(|e| format!("Azure akBinding.data JSON did not parse: {e}"))
}

fn parse_azure_maa_jwt(
    jwt: &str,
) -> std::result::Result<(String, AzureMaaJwtHeader, AzureMaaJwtClaims, Vec<u8>), String> {
    let mut parts = jwt.split('.');
    let header = parts
        .next()
        .ok_or_else(|| "MAA JWT is missing header".to_string())?;
    let claims = parts
        .next()
        .ok_or_else(|| "MAA JWT is missing claims".to_string())?;
    let signature = parts
        .next()
        .ok_or_else(|| "MAA JWT is missing signature".to_string())?;
    if parts.next().is_some() {
        return Err("MAA JWT has more than three compact-JWS parts".to_string());
    }
    let header_value: AzureMaaJwtHeader =
        serde_json::from_slice(&decode_b64("maa.jwt.header", header).map_err(|e| e.to_string())?)
            .map_err(|e| format!("MAA JWT header JSON did not parse: {e}"))?;
    let claims_value: AzureMaaJwtClaims =
        serde_json::from_slice(&decode_b64("maa.jwt.claims", claims).map_err(|e| e.to_string())?)
            .map_err(|e| format!("MAA JWT claims JSON did not parse: {e}"))?;
    let signature = decode_b64("maa.jwt.signature", signature).map_err(|e| e.to_string())?;
    Ok((
        format!("{header}.{claims}"),
        header_value,
        claims_value,
        signature,
    ))
}

fn azure_report_data_claim(
    claims: &AzureMaaJwtClaims,
    tee: &str,
) -> std::result::Result<[u8; 64], String> {
    let value = match tee {
        "tdx" => claims
            .tdx_report_data
            .as_deref()
            .ok_or_else(|| "MAA JWT is missing tdx_report_data".to_string())?,
        "sev-snp" => claims
            .snp_report_data
            .as_deref()
            .ok_or_else(|| "MAA JWT is missing x-ms-sevsnpvm-reportdata".to_string())?,
        other => {
            return Err(format!(
                "unsupported Azure TEE type for report_data: {other}"
            ))
        }
    };
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(raw).map_err(|e| format!("MAA report_data hex did not parse: {e}"))?;
    <[u8; 64]>::try_from(bytes.as_slice())
        .map_err(|_| format!("MAA report_data must be 64 bytes, got {}", bytes.len()))
}

fn parse_rsa_public_key(key_bytes: &[u8]) -> std::result::Result<RsaPublicKey, String> {
    if let Ok(key) = RsaPublicKey::from_pkcs1_der(key_bytes) {
        return Ok(key);
    }
    let jwk: AzureJwk = serde_json::from_slice(key_bytes)
        .map_err(|e| format!("trusted MAA key is neither PKCS#1 DER nor JWK JSON: {e}"))?;
    if jwk.kty.as_deref() != Some("RSA") {
        return Err(format!(
            "trusted MAA JWK kty is {}, expected RSA",
            jwk.kty.as_deref().unwrap_or("<missing>")
        ));
    }
    rsa_public_key_from_jwk(&jwk, "trusted MAA key")
}

fn verify_azure_hclak_quote_signature(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    binding: &AkBinding,
    tpm2b_attest: &[u8],
    tpm_signature: &[u8],
) {
    if binding.kind != "azure-maa-jwt" {
        fail(
            report,
            errors,
            "tpm-quote-signature",
            format!(
                "Azure TPM quote signature requires akBinding.kind=azure-maa-jwt, got {}",
                binding.kind
            ),
        );
        return;
    }
    let body = match tpm2b_attest_body(tpm2b_attest) {
        Ok(body) => body,
        Err(detail) => {
            fail(report, errors, "tpm-quote-signature", detail);
            return;
        }
    };
    let public_key = match parse_azure_hclak_public_key(binding) {
        Ok(key) => key,
        Err(detail) => {
            fail(report, errors, "tpm-quote-signature", detail);
            return;
        }
    };
    let signature = match parse_tpmt_signature_rsassa_sha256(tpm_signature) {
        Ok(signature) => signature,
        Err(detail) => {
            fail(report, errors, "tpm-quote-signature", detail);
            return;
        }
    };

    match public_key.verify(body, &signature) {
        Ok(()) => pass(report, "tpm-quote-signature"),
        Err(e) => fail(
            report,
            errors,
            "tpm-quote-signature",
            format!("TPM quote signature did not verify under Azure HCLAkPub: {e}"),
        ),
    }
}

fn parse_azure_hclak_public_key(
    binding: &AkBinding,
) -> std::result::Result<RsaVerifyingKey<rsa::sha2::Sha256>, String> {
    let binding = parse_azure_maa_binding(binding)?;
    let hcl_var_data =
        decode_b64("akBinding.hclVarData", &binding.hcl_var_data).map_err(|e| e.to_string())?;
    let var_data: AzureHclVarData = serde_json::from_slice(&hcl_var_data)
        .map_err(|e| format!("Azure hclVarData JSON did not parse: {e}"))?;
    let hcl_ak = var_data
        .keys
        .iter()
        .find(|key| key.kid.as_deref() == Some("HCLAkPub"))
        .ok_or_else(|| "Azure hclVarData does not contain HCLAkPub".to_string())?;
    if hcl_ak.kty.as_deref() != Some("RSA") {
        return Err(format!(
            "Azure HCLAkPub kty is {}, expected RSA",
            hcl_ak.kty.as_deref().unwrap_or("<missing>")
        ));
    }
    let public_key = rsa_public_key_from_jwk(hcl_ak, "Azure HCLAkPub")?;
    Ok(RsaVerifyingKey::<rsa::sha2::Sha256>::new(public_key))
}

fn rsa_public_key_from_jwk(
    jwk: &AzureJwk,
    label: &str,
) -> std::result::Result<RsaPublicKey, String> {
    let n = jwk
        .n
        .as_deref()
        .ok_or_else(|| format!("{label} is missing modulus n"))
        .and_then(|value| decode_b64("rsa.n", value).map_err(|e| e.to_string()))?;
    let e = jwk
        .e
        .as_deref()
        .ok_or_else(|| format!("{label} is missing exponent e"))
        .and_then(|value| decode_b64("rsa.e", value).map_err(|e| e.to_string()))?;
    RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        .map_err(|e| format!("{label} RSA key is invalid: {e}"))
}

fn verify_tpm_quote(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    tpm2b_attest: &[u8],
    expected_qualifying_data: &[u8; 32],
    pcrs: &[PcrEvidence],
) {
    let parsed = match parse_tpm_quote(tpm2b_attest) {
        Ok(parsed) => {
            pass(report, "tpm-quote-structure");
            parsed
        }
        Err(detail) => {
            fail(report, errors, "tpm-quote-structure", detail);
            skipped(report, "tpm-quote-challenge", "TPM quote did not parse");
            skipped(report, "tpm-quote-pcr-digest", "TPM quote did not parse");
            return;
        }
    };

    check(
        report,
        errors,
        "tpm-quote-challenge",
        parsed.extra_data == expected_qualifying_data,
        "TPM quote extraData does not match expected qualifyingData".to_string(),
    );

    if parsed.sha256_pcr_indices.is_empty() {
        fail(
            report,
            errors,
            "tpm-quote-pcr-digest",
            "TPM quote does not select any SHA-256 PCRs".to_string(),
        );
        return;
    }
    if parsed.pcr_digest.len() != 32 {
        fail(
            report,
            errors,
            "tpm-quote-pcr-digest",
            format!(
                "TPM quote SHA-256 PCR digest is {} bytes, expected 32",
                parsed.pcr_digest.len()
            ),
        );
        return;
    }

    let mut pcr_concat = Vec::with_capacity(parsed.sha256_pcr_indices.len() * 32);
    for index in &parsed.sha256_pcr_indices {
        let Some(pcr) = pcrs.iter().find(|pcr| &pcr.index == index) else {
            fail(
                report,
                errors,
                "tpm-quote-pcr-digest",
                format!("TPM quote selects PCR {index}, but response.pcrs omits it"),
            );
            return;
        };
        let Some(value) = &pcr.sha256 else {
            fail(
                report,
                errors,
                "tpm-quote-pcr-digest",
                format!("TPM quote selects PCR {index}, but response.pcrs has no sha256 value"),
            );
            return;
        };
        match decode_hex_32("pcr.sha256", value) {
            Ok(bytes) => pcr_concat.extend_from_slice(&bytes),
            Err(e) => {
                fail(
                    report,
                    errors,
                    "tpm-quote-pcr-digest",
                    format!("PCR {index}: {e}"),
                );
                return;
            }
        }
    }

    let expected_digest: [u8; 32] = Sha256::digest(&pcr_concat).into();
    check(
        report,
        errors,
        "tpm-quote-pcr-digest",
        parsed.pcr_digest == expected_digest,
        "TPM quote PCR digest does not match response PCR values".to_string(),
    );
}

fn verify_tpm_quote_signature(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    ak_public: &[u8],
    tpm2b_attest: &[u8],
    tpm_signature: &[u8],
) {
    let body = match tpm2b_attest_body(tpm2b_attest) {
        Ok(body) => body,
        Err(detail) => {
            fail(report, errors, "tpm-quote-signature", detail);
            return;
        }
    };
    let public_key = match parse_tpmt_public_ecc_p256(ak_public) {
        Ok(key) => key,
        Err(detail) => {
            fail(report, errors, "tpm-quote-signature", detail);
            return;
        }
    };
    let signature = match parse_tpmt_signature_ecdsa_sha256(tpm_signature) {
        Ok(signature) => signature,
        Err(detail) => {
            fail(report, errors, "tpm-quote-signature", detail);
            return;
        }
    };

    match public_key.verify(body, &signature) {
        Ok(()) => pass(report, "tpm-quote-signature"),
        Err(e) => fail(
            report,
            errors,
            "tpm-quote-signature",
            format!("TPM quote signature did not verify under AK: {e}"),
        ),
    }
}

fn tpm2b_attest_body(tpm2b_attest: &[u8]) -> std::result::Result<&[u8], String> {
    if tpm2b_attest.len() >= 4
        && u32::from_be_bytes([
            tpm2b_attest[0],
            tpm2b_attest[1],
            tpm2b_attest[2],
            tpm2b_attest[3],
        ]) == TPM_GENERATED_VALUE
    {
        return Ok(tpm2b_attest);
    }
    if tpm2b_attest.len() < 2 {
        return Err("TPM2B_ATTEST is shorter than its size prefix".to_string());
    }
    let declared = u16::from_be_bytes([tpm2b_attest[0], tpm2b_attest[1]]) as usize;
    let body = &tpm2b_attest[2..];
    if declared != body.len() {
        return Err(format!(
            "TPM2B_ATTEST size prefix declares {declared} bytes, got {}",
            body.len()
        ));
    }
    Ok(body)
}

fn parse_tpmt_public_ecc_p256(tpmt_public: &[u8]) -> std::result::Result<P256VerifyingKey, String> {
    let mut reader = ByteReader::new(tpmt_public);
    let public_alg = reader.read_u16("tpmtPublic.type")?;
    if public_alg != TPM_ALG_ECC {
        return Err(format!(
            "TPMT_PUBLIC type 0x{public_alg:04x} is not ECC; only GCP-style ECC AK verification is implemented"
        ));
    }
    let name_alg = reader.read_u16("tpmtPublic.nameAlg")?;
    if name_alg != TPM_ALG_SHA256 {
        return Err(format!(
            "TPMT_PUBLIC nameAlg 0x{name_alg:04x} is not SHA-256"
        ));
    }
    reader.read_exact("tpmtPublic.objectAttributes", 4)?;
    let _auth_policy = reader.read_tpm2b("tpmtPublic.authPolicy")?;
    read_tpmt_sym_def_object(&mut reader)?;
    read_tpmt_scheme(&mut reader, "tpmtPublic.eccDetail.scheme")?;
    let curve_id = reader.read_u16("tpmtPublic.eccDetail.curveId")?;
    if curve_id != 0x0003 {
        return Err(format!(
            "TPMT_PUBLIC ECC curve 0x{curve_id:04x} is not NIST P-256"
        ));
    }
    read_tpmt_scheme(&mut reader, "tpmtPublic.eccDetail.kdf")?;
    let x = reader.read_tpm2b("tpmtPublic.unique.ecc.x")?;
    let y = reader.read_tpm2b("tpmtPublic.unique.ecc.y")?;
    if !reader.is_empty() {
        return Err(format!(
            "TPMT_PUBLIC has {} trailing bytes",
            reader.remaining()
        ));
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&pad_left(x, 32));
    sec1.extend_from_slice(&pad_left(y, 32));
    let point = EncodedPoint::from_bytes(&sec1).map_err(|e| format!("P-256 SEC1 point: {e}"))?;
    P256VerifyingKey::from_encoded_point(&point).map_err(|e| format!("P-256 verifying key: {e}"))
}

fn read_tpmt_sym_def_object(reader: &mut ByteReader<'_>) -> std::result::Result<(), String> {
    let alg = reader.read_u16("TPMT_SYM_DEF_OBJECT.algorithm")?;
    if alg != TPM_ALG_NULL {
        reader.read_u16("TPMT_SYM_DEF_OBJECT.keyBits")?;
        reader.read_u16("TPMT_SYM_DEF_OBJECT.mode")?;
    }
    Ok(())
}

fn read_tpmt_scheme(
    reader: &mut ByteReader<'_>,
    field: &'static str,
) -> std::result::Result<(), String> {
    let scheme = reader.read_u16(field)?;
    if scheme != TPM_ALG_NULL {
        reader.read_u16(field)?;
    }
    Ok(())
}

fn parse_tpmt_signature_ecdsa_sha256(
    tpm_signature: &[u8],
) -> std::result::Result<P256Signature, String> {
    let mut reader = ByteReader::new(tpm_signature);
    let sig_alg = reader.read_u16("signature.sigAlg")?;
    if sig_alg != TPM_ALG_ECDSA {
        return Err(format!(
            "TPMT_SIGNATURE sigAlg 0x{sig_alg:04x} is not ECDSA"
        ));
    }
    let hash_alg = reader.read_u16("signature.hash")?;
    if hash_alg != TPM_ALG_SHA256 {
        return Err(format!(
            "TPMT_SIGNATURE hash 0x{hash_alg:04x} is not SHA-256"
        ));
    }
    let r = reader.read_tpm2b("signature.ecdsa.r")?;
    let s = reader.read_tpm2b("signature.ecdsa.s")?;
    if !reader.is_empty() {
        return Err(format!(
            "TPMT_SIGNATURE has {} trailing bytes",
            reader.remaining()
        ));
    }
    let mut raw = [0u8; 64];
    raw[0..32].copy_from_slice(&pad_left(r, 32));
    raw[32..64].copy_from_slice(&pad_left(s, 32));
    P256Signature::from_slice(&raw).map_err(|e| format!("P-256 signature: {e}"))
}

fn parse_tpmt_signature_rsassa_sha256(
    tpm_signature: &[u8],
) -> std::result::Result<RsaSignature, String> {
    let mut reader = ByteReader::new(tpm_signature);
    let sig_alg = reader.read_u16("signature.sigAlg")?;
    if sig_alg != TPM_ALG_RSASSA {
        return Err(format!(
            "TPMT_SIGNATURE sigAlg 0x{sig_alg:04x} is not RSASSA"
        ));
    }
    let hash_alg = reader.read_u16("signature.hash")?;
    if hash_alg != TPM_ALG_SHA256 {
        return Err(format!(
            "TPMT_SIGNATURE hash 0x{hash_alg:04x} is not SHA-256"
        ));
    }
    let sig = reader.read_tpm2b("signature.rsassa.sig")?;
    if !reader.is_empty() {
        return Err(format!(
            "TPMT_SIGNATURE has {} trailing bytes",
            reader.remaining()
        ));
    }
    RsaSignature::try_from(sig).map_err(|e| format!("RSA signature: {e}"))
}

#[derive(Debug)]
struct ParsedTpmQuote {
    extra_data: Vec<u8>,
    sha256_pcr_indices: Vec<u8>,
    pcr_digest: Vec<u8>,
}

fn parse_tpm_quote(tpm2b_attest: &[u8]) -> std::result::Result<ParsedTpmQuote, String> {
    let body = tpm2b_attest_body(tpm2b_attest)?;

    let mut reader = ByteReader::new(body);
    let magic = reader.read_u32("magic")?;
    if magic != TPM_GENERATED_VALUE {
        return Err(format!(
            "TPMS_ATTEST magic 0x{magic:08x} is not TPM_GENERATED_VALUE"
        ));
    }
    let attest_type = reader.read_u16("type")?;
    if attest_type != TPM_ST_ATTEST_QUOTE {
        return Err(format!(
            "TPMS_ATTEST type 0x{attest_type:04x} is not TPM_ST_ATTEST_QUOTE"
        ));
    }

    let _qualified_signer = reader.read_tpm2b("qualifiedSigner")?;
    let extra_data = reader.read_tpm2b("extraData")?.to_vec();
    reader.read_exact("clockInfo", 17)?;
    reader.read_exact("firmwareVersion", 8)?;

    let selection_count = reader.read_u32("attested.quote.pcrSelect.count")?;
    let mut sha256_pcr_indices = Vec::new();
    for selection_idx in 0..selection_count {
        let hash_alg = reader.read_u16("attested.quote.pcrSelect.hash")?;
        let select_len = reader.read_u8("attested.quote.pcrSelect.sizeofSelect")? as usize;
        let select = reader.read_exact("attested.quote.pcrSelect.pcrSelect", select_len)?;
        if hash_alg == TPM_ALG_SHA256 {
            for (byte_idx, byte) in select.iter().enumerate() {
                for bit in 0..8 {
                    if byte & (1 << bit) != 0 {
                        let index = byte_idx * 8 + bit;
                        let index = u8::try_from(index).map_err(|_| {
                            format!(
                                "SHA-256 PCR selection {selection_idx} contains out-of-range PCR index {index}"
                            )
                        })?;
                        sha256_pcr_indices.push(index);
                    }
                }
            }
        }
    }
    let pcr_digest = reader.read_tpm2b("attested.quote.pcrDigest")?.to_vec();
    if !reader.is_empty() {
        return Err(format!(
            "TPMS_ATTEST has {} trailing bytes after quote info",
            reader.remaining()
        ));
    }

    Ok(ParsedTpmQuote {
        extra_data,
        sha256_pcr_indices,
        pcr_digest,
    })
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn read_u8(&mut self, field: &'static str) -> std::result::Result<u8, String> {
        let bytes = self.read_exact(field, 1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self, field: &'static str) -> std::result::Result<u16, String> {
        let bytes = self.read_exact(field, 2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, field: &'static str) -> std::result::Result<u32, String> {
        let bytes = self.read_exact(field, 4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_tpm2b(&mut self, field: &'static str) -> std::result::Result<&'a [u8], String> {
        let len = self.read_u16(field)? as usize;
        self.read_exact(field, len)
    }

    fn read_exact(
        &mut self,
        field: &'static str,
        len: usize,
    ) -> std::result::Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| format!("{field} length overflow"))?;
        if end > self.bytes.len() {
            return Err(format!(
                "{field} overruns TPMS_ATTEST: need {len} bytes at offset {}, remaining {}",
                self.offset,
                self.remaining()
            ));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}

fn verify_pcr_spec(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    spec: &PcrSpec,
    pcrs: &[PcrEvidence],
) {
    let check_name = format!("pcr-{}-{}", spec.pcr_index, spec.verify_type);
    if spec.verify_type != "static" {
        fail(
            report,
            errors,
            &check_name,
            format!(
                "PCR verifyType {} is not supported by the v1 TLS verifier",
                spec.verify_type
            ),
        );
        return;
    }
    if spec.match_data.is_empty() {
        fail(
            report,
            errors,
            &check_name,
            "static PCR spec has no matchData".to_string(),
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
    use signature::{Keypair, Signer};

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

    fn fake_gcp_ak_chain_and_signature(tpm2b_attest: &[u8]) -> FakeGcpAkChain {
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
        let signature: P256Signature = signing_key.sign(tpm2b_attest_body(tpm2b_attest).unwrap());
        let verify_key = signing_key.verifying_key();
        (
            fake_tpmt_public_ecc(verify_key),
            fake_tpmt_signature_ecdsa(&signature),
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
        let point = verify_key.to_encoded_point(false);
        let x = point.x().expect("x");
        let y = point.y().expect("y");
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&0x0006_0072u32.to_be_bytes());
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
    fn verifier_rejects_unsupported_pcr_verify_type() {
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
        .expect_err("unsupported PCR policy should fail closed");

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
