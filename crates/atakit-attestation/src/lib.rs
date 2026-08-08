use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{
    ParsedPublicKey as ParsedRsaPublicKey, RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use k256::ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::EncodedPoint;
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256, Sha384};
use sha3::Keccak256;
use signature::Verifier;
use thiserror::Error;
use x509_parser::parse_x509_crl;
use x509_parser::prelude::{FromDer, X509Certificate, X509Version};
use x509_parser::time::ASN1Time;

mod amd_snp_policy;
mod aws_nitrotpm;
mod session;
mod tdx_dcap;
mod verification_core;
pub use amd_snp_policy::*;
pub use aws_nitrotpm::aws_nitro_root_certificate;
pub use session::*;
pub use tdx_dcap::*;

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
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_ECC: u16 = 0x0023;
const TDX_QUOTE_HEADER_LEN: usize = 48;
const TDX_QUOTE_V5_BODY_HEADER_LEN: usize = 6;
const TDX_TEE_TYPE: u32 = 0x0000_0081;
const TDX_BODY_TD_REPORT10_TYPE: u16 = 2;
const TDX_BODY_TD_REPORT15_TYPE: u16 = 3;
const TDX_REPORT_ATTRIBUTES_OFFSET: usize = 120;
const TDX_REPORT_RTMR3_OFFSET: usize = 472;
const TDX_REPORT_REPORT_DATA_OFFSET: usize = 520;
const TDX_REPORT15_MR_SERVICETD_OFFSET: usize = 600;
const GCP_TDX_UUID_LEN: usize = 16;
const SNP_REPORT_REPORT_ID_OFFSET: usize = 0x140;
const SNP_REPORT_REPORT_ID_LEN: usize = 32;
const SNP_REPORT_SIGNATURE_OFFSET: usize = 0x2a0;
const SNP_REPORT_SIGNED_LEN: usize = 0x2a0;
const SNP_REPORT_SIZE: usize = 0x4a0;
const SNP_REPORT_VERSION_OFFSET: usize = 0;
const SNP_REPORT_POLICY_OFFSET: usize = 8;
const SNP_REPORT_VMPL_OFFSET: usize = 0x30;
const SNP_REPORT_ID_MA_OFFSET: usize = 0x160;
const SNP_REPORT_ID_MA_LEN: usize = 32;
const SNP_REPORT_SIG_ALGO_OFFSET: usize = 0x34;
const SNP_REPORT_CURRENT_TCB_OFFSET: usize = 0x38;
const SNP_REPORT_PLATFORM_INFO_OFFSET: usize = 0x40;
const SNP_REPORT_KEY_SETTINGS_OFFSET: usize = 0x48;
const SNP_REPORT_RESERVED_1_OFFSET: usize = 0x4c;
const SNP_REPORT_REPORTED_TCB_OFFSET: usize = 0x180;
const SNP_REPORT_CPUID_OFFSET: usize = 0x188;
const SNP_REPORT_CPUID_RESERVED_OFFSET: usize = 0x18b;
const SNP_REPORT_CPUID_RESERVED_LEN: usize = 21;
const SNP_REPORT_CHIP_ID_OFFSET: usize = 0x1a0;
const SNP_REPORT_COMMITTED_TCB_OFFSET: usize = 0x1e0;
const SNP_REPORT_CURRENT_VERSION_RESERVED_OFFSET: usize = 0x1eb;
const SNP_REPORT_COMMITTED_VERSION_RESERVED_OFFSET: usize = 0x1ef;
const SNP_REPORT_LAUNCH_TCB_OFFSET: usize = 0x1f0;
const SNP_REPORT_LAUNCH_MITIGATION_VECTOR_OFFSET: usize = 0x1f8;
const SNP_REPORT_CURRENT_MITIGATION_VECTOR_OFFSET: usize = 0x200;
const SNP_REPORT_CURRENT_MITIGATION_VECTOR_END: usize = 0x208;
const SNP_POLICY_MIGRATE_MA: u64 = 1 << 18;
const SNP_POLICY_DEBUG: u64 = 1 << 19;
const SNP_SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;
const SNP_CERT_TABLE_ENTRY_BYTES: usize = 24;
const MAX_SNP_CERT_TABLE_BYTES: usize = 1024 * 1024;
const MAX_SNP_CERT_TABLE_ENTRIES: usize = 64;
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

/// The endorsement key that signed an AMD SEV-SNP attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdSnpSigningKeyType {
    Vcek,
    Vlek,
}

/// Return the endorsement-key type selected by an AMD SEV-SNP report.
pub fn amd_snp_signing_key_type(
    report: &[u8],
) -> std::result::Result<AmdSnpSigningKeyType, String> {
    if report.len() != SNP_REPORT_SIZE {
        return Err(format!(
            "SNP report has invalid size: got {}, expected {SNP_REPORT_SIZE}",
            report.len()
        ));
    }
    verification_core::snp_signing_key_type(report)
}

/// Fields needed to request the report's VCEK from AMD KDS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmdSnpVcekRequest {
    pub chip_id: [u8; 64],
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
    pub cpuid_family: u8,
    pub cpuid_model: u8,
}

/// Parse the VCEK lookup fields from a raw SEV-SNP attestation report.
pub fn amd_snp_vcek_request(report: &[u8]) -> std::result::Result<AmdSnpVcekRequest, String> {
    if report.len() != SNP_REPORT_SIZE {
        return Err(format!(
            "SNP report has invalid size: got {}, expected {SNP_REPORT_SIZE}",
            report.len()
        ));
    }
    if amd_snp_signing_key_type(report)? != AmdSnpSigningKeyType::Vcek {
        return Err("AMD KDS VCEK lookup cannot resolve a VLEK-signed SNP report".to_string());
    }
    let tcb = &report[SNP_REPORT_REPORTED_TCB_OFFSET..SNP_REPORT_REPORTED_TCB_OFFSET + 8];
    let chip_id = report[SNP_REPORT_CHIP_ID_OFFSET..SNP_REPORT_CHIP_ID_OFFSET + 64]
        .try_into()
        .expect("checked report length");
    Ok(AmdSnpVcekRequest {
        chip_id,
        bootloader: tcb[0],
        tee: tcb[1],
        snp: tcb[6],
        microcode: tcb[7],
        cpuid_family: report[SNP_REPORT_REPORTED_TCB_OFFSET + 8],
        cpuid_model: report[SNP_REPORT_REPORTED_TCB_OFFSET + 9],
    })
}

/// Return the AMD Key Distribution Service product name for an SNP report.
pub fn amd_snp_kds_product(report: &[u8]) -> std::result::Result<&'static str, String> {
    if report.len() != SNP_REPORT_SIZE {
        return Err(format!(
            "SNP report has invalid size: got {}, expected {SNP_REPORT_SIZE}",
            report.len()
        ));
    }
    let family = report[SNP_REPORT_REPORTED_TCB_OFFSET + 8];
    let model = report[SNP_REPORT_REPORTED_TCB_OFFSET + 9];
    match (family, model) {
        (0x19, 0x00..=0x0f) => Ok("Milan"),
        (0x19, 0x10..=0x1f) => Ok("Genoa"),
        _ => Err(format!(
            "unsupported AMD SNP CPUID family 0x{family:02x}, model 0x{model:02x} for KDS lookup"
        )),
    }
}

/// Build the standard SNP certificate-table byte layout from DER certificates.
pub fn amd_snp_vcek_cert_table(
    ark: &[u8],
    ask: &[u8],
    vcek: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    let entries = [
        ("ARK", SNP_CERT_TABLE_ARK_GUID, ark),
        ("ASK", SNP_CERT_TABLE_ASK_GUID, ask),
        ("VCEK", SNP_CERT_TABLE_VCEK_GUID, vcek),
    ];
    if let Some((label, _, _)) = entries.iter().find(|(_, _, cert)| cert.is_empty()) {
        return Err(format!("SNP {label} certificate is empty"));
    }
    let table_len = SNP_CERT_TABLE_ENTRY_BYTES
        .checked_mul(entries.len() + 1)
        .ok_or_else(|| "SNP certificate-table header length overflow".to_string())?;
    let mut output = vec![0u8; table_len];
    let mut cert_offset = table_len;
    for (index, (_, guid, cert)) in entries.iter().enumerate() {
        let entry_offset = index * SNP_CERT_TABLE_ENTRY_BYTES;
        let offset = u32::try_from(cert_offset)
            .map_err(|_| "SNP certificate-table offset exceeds u32".to_string())?;
        let length = u32::try_from(cert.len())
            .map_err(|_| "SNP certificate length exceeds u32".to_string())?;
        output[entry_offset..entry_offset + 16].copy_from_slice(guid);
        output[entry_offset + 16..entry_offset + 20].copy_from_slice(&offset.to_le_bytes());
        output[entry_offset + 20..entry_offset + 24].copy_from_slice(&length.to_le_bytes());
        cert_offset = cert_offset
            .checked_add(cert.len())
            .ok_or_else(|| "SNP certificate-table length overflow".to_string())?;
        if cert_offset > MAX_SNP_CERT_TABLE_BYTES {
            return Err(format!(
                "SNP certificate table exceeds the {MAX_SNP_CERT_TABLE_BYTES}-byte limit"
            ));
        }
    }
    for (_, _, cert) in entries {
        output.extend_from_slice(cert);
    }
    Ok(output)
}

#[derive(Debug, Error)]
pub enum AmdSnpVerificationCollateralError {
    #[error("invalid AMD SEV-SNP certificate table: {0}")]
    CertificateTable(String),
    #[error("AMD SEV-SNP certificate collateral is missing {0}")]
    MissingCertificate(&'static str),
}

/// Verifier-resolved AMD SEV-SNP certificate and revocation collateral.
///
/// The ARK certificate is a candidate chain root. The verifier must still
/// approve that exact ARK certificate or its hash through [`TrustAnchors`].
#[derive(Debug, Clone)]
pub struct AmdSnpVerificationCollateral {
    pub(crate) ark_der: Vec<u8>,
    pub(crate) intermediate_ca_der: Vec<u8>,
    pub(crate) vcek_der: Option<Vec<u8>>,
    pub(crate) vlek_der: Option<Vec<u8>>,
    pub(crate) crls_der: Vec<Vec<u8>>,
}

impl AmdSnpVerificationCollateral {
    pub fn from_vcek_chain(
        ark_der: Vec<u8>,
        ask_der: Vec<u8>,
        vcek_der: Vec<u8>,
        crls_der: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            ark_der,
            intermediate_ca_der: ask_der,
            vcek_der: Some(vcek_der),
            vlek_der: None,
            crls_der,
        }
    }

    pub fn from_vlek_chain(
        ark_der: Vec<u8>,
        asvk_der: Vec<u8>,
        vlek_der: Vec<u8>,
        crls_der: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            ark_der,
            intermediate_ca_der: asvk_der,
            vcek_der: None,
            vlek_der: Some(vlek_der),
            crls_der,
        }
    }

    pub fn from_certificate_table(
        table: &[u8],
        crls_der: Vec<Vec<u8>>,
    ) -> std::result::Result<Self, AmdSnpVerificationCollateralError> {
        let parsed = verification_core::parse_amd_snp_cert_table(table)
            .map_err(AmdSnpVerificationCollateralError::CertificateTable)?;
        let ark_der = parsed
            .ark
            .ok_or(AmdSnpVerificationCollateralError::MissingCertificate("ARK"))?;
        let intermediate_ca_der =
            parsed
                .ask
                .ok_or(AmdSnpVerificationCollateralError::MissingCertificate(
                    "ASK or ASVK intermediate CA",
                ))?;
        if parsed.vcek.is_none() && parsed.vlek.is_none() {
            return Err(AmdSnpVerificationCollateralError::MissingCertificate(
                "VCEK or VLEK",
            ));
        }
        Ok(Self {
            ark_der,
            intermediate_ca_der,
            vcek_der: parsed.vcek,
            vlek_der: parsed.vlek,
            crls_der,
        })
    }

    pub fn ark_der(&self) -> &[u8] {
        &self.ark_der
    }

    pub fn crls_der(&self) -> &[Vec<u8>] {
        &self.crls_der
    }
}

pub fn amd_snp_vlek_from_certificate_table(
    table: &[u8],
) -> std::result::Result<Vec<u8>, AmdSnpVerificationCollateralError> {
    verification_core::parse_amd_snp_cert_table(table)
        .map_err(AmdSnpVerificationCollateralError::CertificateTable)?
        .vlek
        .ok_or(AmdSnpVerificationCollateralError::MissingCertificate(
            "VLEK",
        ))
}

/// Return the ARK DER certificate from a standard SNP certificate table.
pub fn amd_snp_ark_from_cert_table(table: &[u8]) -> std::result::Result<Vec<u8>, String> {
    verification_core::parse_amd_snp_cert_table(table)?
        .ark
        .ok_or_else(|| "SNP certificate table is missing the ARK certificate".to_string())
}

/// Select the manually trusted MAA key that signed an Azure binding and add
/// the JWT metadata required by session verification.
///
/// Manual keys are explicit operator trust and do not carry registry expiry
/// metadata. The returned key therefore remains valid until the operator
/// removes it. Callers still perform complete TLS and session verification.
pub fn select_azure_maa_manual_trust_key(
    binding: &AkBinding,
    trusted_keys: &[AzureMaaTrustCertificate],
) -> std::result::Result<AzureMaaTrustKey, String> {
    if trusted_keys.is_empty() {
        return Err("no manually trusted Azure MAA signing keys configured".to_string());
    }
    let binding = verification_core::parse_azure_maa_binding(binding)?;
    let (signing_input, header, claims, signature) =
        verification_core::parse_azure_maa_jwt(&binding.jwt)?;
    if header.alg != "RS256" {
        return Err(format!("MAA JWT alg is {}, expected RS256", header.alg));
    }
    let kid = header
        .kid
        .filter(|kid| !kid.is_empty())
        .ok_or_else(|| "MAA JWT kid is missing".to_string())?;
    if claims.iss.is_empty() {
        return Err("MAA JWT issuer is empty".to_string());
    }
    let mut key_errors = Vec::new();
    for certificate in trusted_keys {
        let key = match verification_core::parse_rsa_public_key(&certificate.public_key) {
            Ok(key) => key,
            Err(detail) => {
                key_errors.push(detail);
                continue;
            }
        };
        if key.verify_sig(signing_input.as_bytes(), &signature).is_ok() {
            // `not_after` comes from the certificate's validity period. It was
            // previously `u64::MAX`, because a bare public key carries no
            // expiry — which made the downstream expiry check in
            // `verify_azure_maa_session_binding` unable to fire for any
            // manually supplied key. `kid` and `issuer` still come from the
            // token; a certificate cannot supply either.
            return Ok(AzureMaaTrustKey {
                kid,
                issuer: claims.iss,
                not_after: certificate.not_after,
                public_key: certificate.public_key.clone(),
            });
        }
    }
    let detail = if key_errors.is_empty() {
        format!("MAA JWT signature did not verify under any manually trusted key; kid={kid}")
    } else {
        format!(
            "MAA JWT signature did not verify under any manually trusted key; kid={kid}; key parse errors: {}",
            key_errors.join("; ")
        )
    };
    Err(detail)
}

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
    pub pcr0_startup_locality: u8,
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
    #[serde(default)]
    pub sha384: Vec<String>,
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

/// `schema` of a base-image measurement pack body.
pub const BASE_IMAGE_MEASUREMENT_PACK_SCHEMA: &str = "atakit.base_image_measurement_pack.v4";
/// `schema` of a workload measurement pack body.
pub const WORKLOAD_MEASUREMENT_PACK_SCHEMA: &str = "atakit.workload_measurement_pack.v1";

/// The envelope shared by every measurement pack, of either kind.
///
/// One implementation, because two copies of signature and subject verification
/// are two chances to differ. `measurements` stays unparsed until the caller has
/// checked the envelope and asserted which kind it asked for: a pack whose
/// `schema` is the wrong kind must be rejected before its body is read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementPack {
    pub schema: String,
    pub revision: u64,
    /// Publication time, Unix seconds.
    ///
    /// Not an RFC 3339 string: RFC 8785 canonicalizes JSON structure, not string
    /// semantics, so three spellings of one instant are three distinct signed
    /// byte strings. An integer admits exactly one encoding.
    pub published_at: u64,
    pub subject: Subject,
    pub measurements: serde_json::Value,
}

impl MeasurementPack {
    /// Interpret `measurements` as the requested kind.
    ///
    /// The schema is checked before the body is deserialized, so a workload pack
    /// can never be read as a base-image pack or the reverse.
    pub fn body<T: serde::de::DeserializeOwned>(&self, expected_schema: &str) -> Result<T> {
        if self.schema != expected_schema {
            return Err(AttestationError::MeasurementPack(format!(
                "expected schema {expected_schema}, got {}",
                self.schema
            )));
        }
        serde_json::from_value(self.measurements.clone())
            .map_err(|e| AttestationError::MeasurementPack(format!("measurements: {e}")))
    }
}

/// What a pack makes a statement about.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    /// Owner fingerprint of the publisher, and an input to `id`.
    pub publisher: String,
    pub name: String,
    pub version: String,
    /// Expected derived id. The verifier recomputes it from `publisher`, `name`,
    /// and `version` and rejects a mismatch, which is what makes the publisher
    /// binding enforceable rather than advisory.
    pub id: String,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub archive_sha256: Option<String>,
}

/// Body of a base-image measurement pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseImageMeasurements {
    #[serde(default)]
    pub profiles: Vec<MeasurementProfile>,
}

/// Body of a workload measurement pack.
///
/// PCR23 is the hash of the compiled `manifest.json`, so these two values are
/// the workload's complete measured identity. Both banks are required: a pack
/// carrying only one would silently constrain nothing on a target attesting in
/// the other.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadMeasurements {
    pub pcr23_sha256: String,
    pub pcr23_sha384: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementProfile {
    pub name: String,
    pub id: String,
    pub cloud: String,
    pub tee: String,
    pub pcr_bank_selection: PcrBankSelection,
    #[serde(default)]
    pub invariant_pcrs256: Vec<PcrSpec256>,
    #[serde(default)]
    pub invariant_pcrs384: Vec<PcrSpec384>,
    #[serde(default)]
    pub variants: Vec<MeasurementVariant>,
    #[serde(default)]
    pub attributes: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementVariant {
    pub name: String,
    pub id: String,
    #[serde(default)]
    pub machine_types: Vec<String>,
    #[serde(default)]
    pub variant_pcrs256: Vec<PcrSpec256>,
    #[serde(default)]
    pub variant_pcrs384: Vec<PcrSpec384>,
    #[serde(default)]
    pub attributes: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PcrBankSelection {
    Sha256,
    Sha384,
    Sha256AndSha384,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcrSpec256 {
    pub pcr_index: u8,
    pub comparison: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcrSpec384 {
    pub pcr_index: u8,
    pub comparison: String,
}

#[derive(Debug, Clone)]
pub struct VerificationInputs {
    pub nonce: [u8; 32],
    pub live_peer_cert_der: Vec<u8>,
    pub response: TlsAttestationResponse,
    /// Verifier-resolved Intel TDX DCAP collateral. This is separate from the
    /// portal response because the portal returns local evidence only.
    pub intel_tdx_dcap_collateral: Option<IntelTdxDcapCollateral>,
    /// Verifier-resolved AMD SEV-SNP certificate and revocation collateral.
    /// The approved ARK roots remain separate in `trust_anchors`.
    pub amd_snp_collateral: Option<AmdSnpVerificationCollateral>,
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
    /// Verifier-supplied Azure MAA signing certificates. Each carries its own
    /// expiry, so a manually trusted key expires like a chain-resolved one.
    pub azure_maa_keys: Vec<AzureMaaTrustCertificate>,
    pub amd_ark_roots: Vec<Vec<u8>>,
    pub amd_ark_root_hashes: Vec<[u8; 32]>,
    /// AMD SEV-SNP registry defaults supplied by the verifier or read from
    /// AmdSnpSecurityPolicyRegistry.
    pub amd_snp_security_policies: Vec<AmdSnpSecurityPolicy>,
    pub aws_nitro_roots: Vec<Vec<u8>>,
    pub aws_nitro_root_hashes: Vec<[u8; 32]>,
    pub aws_document_maximum_age_seconds: Option<u64>,
    pub aws_document_allowed_future_clock_difference_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmdSnpSecurityPolicy {
    /// Exact family || model || stepping value from the signed report.
    pub cpuid: u32,
    /// Packed CURRENT, REPORTED, COMMITTED, and LAUNCH minimum TCB values.
    pub minimum_tcb: [u8; 32],
    /// Packed PLATFORM_INFO required-clear and required-set masks.
    pub platform_info_policy: [u8; 32],
    /// Required bits in a version-5 report's LAUNCH_MIT_VECTOR.
    #[serde(default)]
    pub required_launch_mitigation_vector: u64,
    /// Required bits in a version-5 report's CURRENT_MIT_VECTOR.
    #[serde(default)]
    pub required_current_mitigation_vector: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmdSnpSecurityState {
    pub debug: bool,
    pub migrate_ma: bool,
    pub tcb_values: [u8; 32],
    pub platform_info: u64,
    pub cpuid: u32,
    #[serde(default)]
    pub report_version: u32,
    #[serde(default)]
    pub launch_mitigation_vector: u64,
    #[serde(default)]
    pub current_mitigation_vector: u64,
}

/// Extract and validate the security fields that drive AMD SEV-SNP policy.
///
/// Callers must also verify the report signature and certificate chain.
pub fn amd_snp_security_state(report: &[u8]) -> std::result::Result<AmdSnpSecurityState, String> {
    let state = verification_core::verified_snp_security_state(report)?;
    Ok(AmdSnpSecurityState {
        debug: state.debug,
        migrate_ma: state.migrate_ma,
        tcb_values: state.tcb_values,
        platform_info: state.platform_info,
        cpuid: state.cpuid,
        report_version: state.report_version,
        launch_mitigation_vector: state.launch_mitigation_vector,
        current_mitigation_vector: state.current_mitigation_vector,
    })
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
    exp: u64,
    nbf: u64,
    iat: u64,
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
    let pack: MeasurementPack = serde_json::from_slice(bytes)
        .map_err(|e| AttestationError::MeasurementPack(e.to_string()))?;
    if pack.schema != BASE_IMAGE_MEASUREMENT_PACK_SCHEMA
        && pack.schema != WORKLOAD_MEASUREMENT_PACK_SCHEMA
    {
        return Err(AttestationError::MeasurementPack(format!(
            "unsupported schema {}",
            pack.schema
        )));
    }
    Ok(pack)
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
    verify_tls_attestation_at(inputs, SystemTime::now())
}

/// Verifies TLS evidence and applies the selected workload manifest's verified
/// TEE attribute requirements before returning the trusted TLS identity.
pub fn verify_tls_attestation_with_workload_attributes(
    inputs: VerificationInputs,
    workload_attributes: &atakit_core::tee_attributes::AttributeRequirements,
) -> std::result::Result<VerifiedTlsIdentity, VerificationFailure> {
    verify_tls_attestation_with_workload_attributes_at(
        inputs,
        workload_attributes,
        SystemTime::now(),
    )
}

/// Verifies TLS evidence at a caller-selected time. Every certificate,
/// collateral, and token time check uses this same value.
pub fn verify_tls_attestation_at(
    inputs: VerificationInputs,
    verification_time: SystemTime,
) -> std::result::Result<VerifiedTlsIdentity, VerificationFailure> {
    verify_tls_attestation_internal(inputs, None, verification_time)
}

/// Verifies TLS evidence and workload attributes at a caller-selected time.
/// Every certificate, collateral, and token time check uses this same value.
pub fn verify_tls_attestation_with_workload_attributes_at(
    inputs: VerificationInputs,
    workload_attributes: &atakit_core::tee_attributes::AttributeRequirements,
    verification_time: SystemTime,
) -> std::result::Result<VerifiedTlsIdentity, VerificationFailure> {
    verify_tls_attestation_internal(inputs, Some(workload_attributes), verification_time)
}

fn verify_tls_attestation_internal(
    inputs: VerificationInputs,
    workload_attributes: Option<&atakit_core::tee_attributes::AttributeRequirements>,
    current_time: SystemTime,
) -> std::result::Result<VerifiedTlsIdentity, VerificationFailure> {
    let mut authenticated_pcrs = None;
    let mut verified_base_image_id = None;
    let mut verified_platform_profile_id = None;
    let mut verified_variant_id = None;
    let mut verified_tdx_tcb_status_bit = None;
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
        inputs.response.format == 2,
        format!("expected 2, got {}", inputs.response.format),
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
                    authenticated_pcrs = verification_core::verify_tpm_quote(
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
        "gcp" | "azure" | "aws" => pass(&mut report, "platform-supported"),
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
                current_time,
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
                current_time,
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
            authenticated_pcrs.as_deref().unwrap_or(&[]),
        );
        verified_tdx_tcb_status_bit = verification_core::verify_gcp_tee_vendor_report(
            &mut report,
            &mut errors,
            inputs.response.tee_evidence.as_ref(),
            &inputs.response.platform.tee,
            inputs.intel_tdx_dcap_collateral.as_ref(),
            verification_core::AmdSnpVerificationContext {
                collateral: inputs.amd_snp_collateral.as_ref(),
                trust: verification_core::AmdSnpTrust {
                    ark_roots: &inputs.trust_anchors.amd_ark_roots,
                    ark_root_hashes: &inputs.trust_anchors.amd_ark_root_hashes,
                },
            },
            current_time,
        );
    } else if inputs.response.platform.cloud == "azure" {
        match (
            inputs.response.tee_evidence.as_ref(),
            inputs.response.ak_binding.as_ref(),
        ) {
            (Some(evidence), Some(binding)) => {
                verification_core::verify_azure_tee_ak_binding(
                    &mut report,
                    &mut errors,
                    evidence,
                    binding,
                    &inputs.response.platform.tee,
                );
                match inputs.response.platform.tee.as_str() {
                    "tdx" => {
                        verified_tdx_tcb_status_bit =
                            verification_core::verify_azure_tdx_vendor_report(
                                &mut report,
                                &mut errors,
                                Some(evidence),
                                inputs.intel_tdx_dcap_collateral.as_ref(),
                                current_time,
                            );
                    }
                    "sev-snp" => verification_core::verify_azure_snp_vendor_report(
                        &mut report,
                        &mut errors,
                        Some(evidence),
                        inputs.amd_snp_collateral.as_ref(),
                        verification_core::AmdSnpTrust {
                            ark_roots: &inputs.trust_anchors.amd_ark_roots,
                            ark_root_hashes: &inputs.trust_anchors.amd_ark_root_hashes,
                        },
                        current_time,
                    ),
                    other => fail(
                        &mut report,
                        &mut errors,
                        "azure-tee-vendor-report",
                        format!("Azure raw TEE vendor verification is unsupported for tee={other}"),
                    ),
                }
            }
            _ => fail(
                &mut report,
                &mut errors,
                "azure-tee-ak-binding",
                "Azure TEE evidence or AK binding is missing".to_string(),
            ),
        }
    } else if inputs.response.platform.cloud == "aws" {
        match (
            inputs.response.ak_binding.as_ref(),
            inputs.response.tee_evidence.as_ref(),
            tpm_ak_public.as_deref(),
            response_cert_sha,
        ) {
            (Some(binding), Some(evidence), Some(ak_public), Some(cert_sha)) => {
                let expected_qualifying_data =
                    compute_tls_bootstrap_qualifying_data(&inputs.nonce, &cert_sha);
                aws_nitrotpm::verify_aws_tls_attestation(
                    &mut report,
                    &mut errors,
                    binding,
                    evidence,
                    ak_public,
                    tpm_quote_bytes.as_deref().unwrap_or(&[]),
                    authenticated_pcrs.as_deref().unwrap_or(&[]),
                    &expected_qualifying_data,
                    false,
                    &inputs.trust_anchors,
                    current_time,
                );
                verification_core::verify_aws_snp_vendor_report(
                    &mut report,
                    &mut errors,
                    Some(evidence),
                    inputs.amd_snp_collateral.as_ref(),
                    verification_core::AmdSnpTrust {
                        ark_roots: &inputs.trust_anchors.amd_ark_roots,
                        ark_root_hashes: &inputs.trust_anchors.amd_ark_root_hashes,
                    },
                    current_time,
                );
            }
            _ => fail(
                &mut report,
                &mut errors,
                "aws-nitrotpm-binding",
                "AWS NitroTPM binding requires akBinding, teeEvidence, tpm.akPublic, and a valid TLS certificate hash"
                    .to_string(),
            ),
        }
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
            policy.pack.schema == BASE_IMAGE_MEASUREMENT_PACK_SCHEMA,
            format!(
                "expected schema {BASE_IMAGE_MEASUREMENT_PACK_SCHEMA}, got {}",
                policy.pack.schema
            ),
        );

        // Recomputing the id from the publisher is what makes the publisher
        // binding enforceable rather than advisory: a pack claiming one
        // publisher while carrying another's measurements derives an id that
        // does not match, and fails before any measurement is read.
        let subject = &policy.pack.subject;
        let expected_base_image_id = match decode_hex_32("subject.publisher", &subject.publisher) {
            Ok(publisher) => Some(compute_base_image_id(
                &publisher,
                &subject.name,
                &subject.version,
            )),
            Err(e) => {
                fail(&mut report, &mut errors, "subject-publisher", e.to_string());
                None
            }
        };
        match (
            decode_hex_32("subject.id", &subject.id),
            expected_base_image_id,
        ) {
            (Ok(id), Some(expected)) => {
                check(
                    &mut report,
                    &mut errors,
                    "base-image-id",
                    id == expected,
                    format!(
                        "subject.id does not match the id derived from {}/{}:{}; expected {}",
                        subject.publisher,
                        subject.name,
                        subject.version,
                        hex0x(&expected)
                    ),
                );
                if id == expected {
                    verified_base_image_id = Some(id);
                }
            }
            (Err(e), _) => fail(&mut report, &mut errors, "base-image-id", e.to_string()),
            (_, None) => {}
        }

        let body: BaseImageMeasurements = match policy.pack.body(BASE_IMAGE_MEASUREMENT_PACK_SCHEMA)
        {
            Ok(body) => body,
            Err(e) => {
                fail(
                    &mut report,
                    &mut errors,
                    "measurement-pack-body",
                    e.to_string(),
                );
                BaseImageMeasurements {
                    profiles: Vec::new(),
                }
            }
        };
        let matching_profiles = body
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

        match (
            &*inputs.response.platform.cloud,
            &profile.pcr_bank_selection,
        ) {
            ("aws", PcrBankSelection::Sha256) => fail(
                &mut report,
                &mut errors,
                "pcr-bank-selection",
                "AWS pcrBankSelection must include SHA-384".to_string(),
            ),
            ("gcp", PcrBankSelection::Sha384) => fail(
                &mut report,
                &mut errors,
                "pcr-bank-selection",
                "GCP pcrBankSelection must include SHA-256".to_string(),
            ),
            _ => pass(&mut report, "pcr-bank-selection"),
        }

        // The spec derives the profile id from subject.id, so this only means
        // anything once subject.id has been verified against the publisher.
        let Some(subject_id) = verified_base_image_id else {
            fail(
                &mut report,
                &mut errors,
                "platform-profile-id",
                "cannot derive the profile id because subject.id did not verify".to_string(),
            );
            return Err(VerificationFailure {
                report: Box::new(report),
                errors,
            });
        };
        let expected_profile_id = compute_platform_profile_id(&subject_id, &profile.name);
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

        verify_measurement_attributes(
            &mut report,
            &mut errors,
            profile,
            variant,
            &inputs.response.platform.tee,
            inputs.response.tee_evidence.as_ref(),
            verified_tdx_tcb_status_bit,
            workload_attributes,
            &inputs.trust_anchors.amd_snp_security_policies,
        );

        check(
            &mut report,
            &mut errors,
            "pcr0-startup-locality",
            inputs.response.tpm.pcr0_startup_locality == 0xff
                || inputs.response.tpm.pcr0_startup_locality <= 4,
            format!(
                "invalid PCR0 StartupLocality {}",
                inputs.response.tpm.pcr0_startup_locality
            ),
        );

        let pcrs = authenticated_pcrs.as_deref().unwrap_or(&[]);
        if matches!(
            profile.pcr_bank_selection,
            PcrBankSelection::Sha256 | PcrBankSelection::Sha256AndSha384
        ) {
            match effective_pcr_specs256(profile, variant) {
                Ok(specs) if specs.is_empty() => fail(
                    &mut report,
                    &mut errors,
                    "measurement-pcrs-sha256",
                    "selected SHA-256 profile/variant has no PCR specs".to_string(),
                ),
                Ok(specs) => {
                    for spec in specs {
                        verify_pcr_spec256(
                            &mut report,
                            &mut errors,
                            spec,
                            pcrs,
                            &inputs.response.tpm.event_log_hashes,
                            inputs.response.tpm.pcr0_startup_locality,
                        );
                    }
                }
                Err(detail) => fail(&mut report, &mut errors, "measurement-pcrs-sha256", detail),
            }
        }
        if matches!(
            profile.pcr_bank_selection,
            PcrBankSelection::Sha384 | PcrBankSelection::Sha256AndSha384
        ) {
            match effective_pcr_specs384(profile, variant) {
                Ok(specs) if specs.is_empty() => fail(
                    &mut report,
                    &mut errors,
                    "measurement-pcrs-sha384",
                    "selected SHA-384 profile/variant has no PCR specs".to_string(),
                ),
                Ok(specs) => {
                    for spec in specs {
                        verify_pcr_spec384(
                            &mut report,
                            &mut errors,
                            spec,
                            pcrs,
                            &inputs.response.tpm.event_log_hashes,
                            inputs.response.tpm.pcr0_startup_locality,
                        );
                    }
                }
                Err(detail) => fail(&mut report, &mut errors, "measurement-pcrs-sha384", detail),
            }
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

fn effective_pcr_specs256<'a>(
    profile: &'a MeasurementProfile,
    variant: &'a MeasurementVariant,
) -> std::result::Result<Vec<&'a PcrSpec256>, String> {
    let mut specs = BTreeMap::new();
    for spec in &profile.invariant_pcrs256 {
        if specs.insert(spec.pcr_index, spec).is_some() {
            return Err(format!(
                "duplicate invariant PCR index {} in profile {}",
                spec.pcr_index, profile.name
            ));
        }
    }

    let mut variant_indices = BTreeSet::new();
    for spec in &variant.variant_pcrs256 {
        if !variant_indices.insert(spec.pcr_index) {
            return Err(format!(
                "duplicate SHA-256 variant PCR index {} in variant {}",
                spec.pcr_index, variant.name
            ));
        }
        if specs.contains_key(&spec.pcr_index) {
            return Err(format!(
                "variant {} contains SHA-256 PCR index {} that profile {} declares invariant; \
                 profile invariants always hold and cannot be overridden",
                variant.name, spec.pcr_index, profile.name
            ));
        }
        specs.insert(spec.pcr_index, spec);
    }

    Ok(specs.into_values().collect())
}

fn effective_pcr_specs384<'a>(
    profile: &'a MeasurementProfile,
    variant: &'a MeasurementVariant,
) -> std::result::Result<Vec<&'a PcrSpec384>, String> {
    let mut specs = BTreeMap::new();
    for spec in &profile.invariant_pcrs384 {
        if specs.insert(spec.pcr_index, spec).is_some() {
            return Err(format!(
                "duplicate SHA-384 invariant PCR index {} in profile {}",
                spec.pcr_index, profile.name
            ));
        }
    }
    let mut variant_indices = BTreeSet::new();
    for spec in &variant.variant_pcrs384 {
        if !variant_indices.insert(spec.pcr_index) {
            return Err(format!(
                "duplicate SHA-384 variant PCR index {} in variant {}",
                spec.pcr_index, variant.name
            ));
        }
        if specs.contains_key(&spec.pcr_index) {
            return Err(format!(
                "variant {} contains SHA-384 PCR index {} that profile {} declares invariant; \
                 profile invariants always hold and cannot be overridden",
                variant.name, spec.pcr_index, profile.name
            ));
        }
        specs.insert(spec.pcr_index, spec);
    }
    Ok(specs.into_values().collect())
}

#[allow(clippy::too_many_arguments)]
fn verify_measurement_attributes(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    profile: &MeasurementProfile,
    variant: &MeasurementVariant,
    tee: &str,
    evidence: Option<&TeeEvidence>,
    verified_tdx_tcb_status_bit: Option<u16>,
    workload_attributes: Option<&atakit_core::tee_attributes::AttributeRequirements>,
    amd_snp_security_policies: &[AmdSnpSecurityPolicy],
) {
    let Some(evidence) = evidence else {
        fail(
            report,
            errors,
            "measurement-attributes",
            "TEE evidence is missing".to_string(),
        );
        return;
    };
    let report_bytes = match decode_b64("teeEvidence.report", &evidence.report) {
        Ok(bytes) => bytes,
        Err(error) => {
            fail(report, errors, "measurement-attributes", error.to_string());
            return;
        }
    };
    let verified_states = match verification_core::verified_tee_attribute_states(tee, &report_bytes)
    {
        Ok(states) => states,
        Err(detail) => {
            fail(report, errors, "measurement-attributes", detail);
            return;
        }
    };
    let effective_attributes = match effective_measurement_attributes(profile, variant) {
        Ok(attributes) => attributes,
        Err(detail) => {
            fail(report, errors, "measurement-attributes", detail);
            return;
        }
    };
    let tee_platform = match tee {
        "tdx" => Some(atakit_core::tee_attributes::TeePlatform::IntelTdx),
        "sev-snp" => Some(atakit_core::tee_attributes::TeePlatform::AmdSevSnp),
        _ => None,
    };
    let mut encoded_requirements = BTreeMap::new();
    if let Some(requirements) = workload_attributes {
        for (name, values) in requirements {
            match atakit_core::tee_attributes::encode_requirement(name, values) {
                Ok((key, allowed_values)) => {
                    encoded_requirements.insert(key, allowed_values);
                }
                Err(detail) => fail(report, errors, "workload-attributes", detail),
            }
        }
    }

    for (attribute, enabled) in atakit_core::tee_attributes::VerifiedTeeAttribute::BOOLEAN
        .into_iter()
        .zip(verified_states)
    {
        if Some(attribute.platform()) != tee_platform {
            continue;
        }
        let verified_value = atakit_core::tee_attributes::bool_value(enabled);
        let declared_value = effective_attributes
            .get(&attribute.key())
            .copied()
            .unwrap_or(atakit_core::tee_attributes::ATTRIBUTE_FALSE);
        check(
            report,
            errors,
            &format!("tee-attribute-base-image-{}", attribute.name()),
            declared_value == verified_value,
            format!(
                "base-image declaration for {} is 0x{}, verified value is 0x{}",
                attribute.name(),
                hex::encode(declared_value),
                hex::encode(verified_value)
            ),
        );
        if workload_attributes.is_some() {
            let allowed = encoded_requirements
                .get(&attribute.key())
                .map_or(!enabled, |values| values.contains(&verified_value));
            check(
                report,
                errors,
                &format!("tee-attribute-workload-{}", attribute.name()),
                allowed,
                format!(
                    "workload requirement for {} does not permit verified value {}",
                    attribute.name(),
                    enabled
                ),
            );
        }
    }

    if tee_platform == Some(atakit_core::tee_attributes::TeePlatform::IntelTdx) {
        if let Some(actual_bit) = verified_tdx_tcb_status_bit {
            let key = atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_KEY;
            let base_matches =
                tdx_tcb_status_policy_matches(effective_attributes.get(&key), actual_bit);
            check(
                report,
                errors,
                "tee-attribute-base-image-intel-tdx-tcb-status",
                base_matches,
                format!(
                    "base-image Intel TDX TCB status mask is invalid or does not permit verified status bit 0x{actual_bit:x}"
                ),
            );
            if workload_attributes.is_some() {
                let workload_matches = match encoded_requirements.get(&key).map(Vec::as_slice) {
                    Some([value]) => tdx_tcb_status_policy_matches(Some(value), actual_bit),
                    Some(_) => false,
                    None => tdx_tcb_status_policy_matches(None, actual_bit),
                };
                check(
                    report,
                    errors,
                    "tee-attribute-workload-intel-tdx-tcb-status",
                    workload_matches,
                    format!(
                        "workload Intel TDX TCB status mask is invalid or does not permit verified status bit 0x{actual_bit:x}"
                    ),
                );
            }
        }
    }

    if tee_platform == Some(atakit_core::tee_attributes::TeePlatform::AmdSevSnp) {
        match verification_core::verified_snp_security_state(&report_bytes) {
            Ok(state) => {
                let registry_default =
                    select_amd_snp_security_policy(amd_snp_security_policies, state.cpuid);
                match registry_default {
                    Ok(registry_default) => {
                        verify_amd_snp_measurement_policy(
                            report,
                            errors,
                            state,
                            registry_default,
                            &effective_attributes,
                            &encoded_requirements,
                            workload_attributes.is_some(),
                        );
                    }
                    Err(detail) => fail(report, errors, "amd-sev-snp-registry-default", detail),
                }
            }
            Err(detail) => fail(report, errors, "amd-sev-snp-security-state", detail),
        }
    }

    for (key, allowed_values) in encoded_requirements {
        if atakit_core::tee_attributes::VerifiedTeeAttribute::from_key(&key).is_some() {
            continue;
        }
        let Some(actual) = effective_attributes.get(&key) else {
            fail(
                report,
                errors,
                "workload-attribute",
                format!(
                    "base image does not declare required attribute 0x{}",
                    hex::encode(key)
                ),
            );
            continue;
        };
        check(
            report,
            errors,
            &format!("workload-attribute-{}", hex::encode(key)),
            allowed_values.is_empty() || allowed_values.contains(actual),
            format!(
                "workload requirement for attribute 0x{} does not permit value 0x{}",
                hex::encode(key),
                hex::encode(actual)
            ),
        );
    }
}

fn select_amd_snp_security_policy(
    policies: &[AmdSnpSecurityPolicy],
    cpuid: u32,
) -> std::result::Result<&AmdSnpSecurityPolicy, String> {
    let mut matching = policies.iter().filter(|policy| policy.cpuid == cpuid);
    let policy = matching.next().ok_or_else(|| {
        format!(
            "no active AmdSnpSecurityPolicyRegistry policy was supplied for CPUID 0x{cpuid:06x}"
        )
    })?;
    if matching.next().is_some() {
        return Err(format!(
            "multiple AMD SEV-SNP security policies were supplied for CPUID 0x{cpuid:06x}"
        ));
    }
    if !atakit_core::tee_attributes::valid_amd_sev_snp_tcb(&policy.minimum_tcb) {
        return Err(format!(
            "AMD SEV-SNP registry default minimum TCB is invalid for CPUID 0x{cpuid:06x}"
        ));
    }
    if !atakit_core::tee_attributes::valid_amd_sev_snp_platform_info_policy(
        &policy.platform_info_policy,
    ) {
        return Err(format!(
            "AMD SEV-SNP registry default PLATFORM_INFO policy is invalid for CPUID 0x{cpuid:06x}"
        ));
    }
    Ok(policy)
}

fn resolve_packed_workload_requirement(
    encoded_requirements: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    key: [u8; 32],
    default_value: [u8; 32],
) -> std::result::Result<[u8; 32], String> {
    let Some(values) = encoded_requirements.get(&key) else {
        return Ok(default_value);
    };
    if values.len() != 1 {
        return Err(format!(
            "workload requirement for reserved packed attribute 0x{} must contain exactly one value, got {}",
            hex::encode(key),
            values.len()
        ));
    }
    Ok(values[0])
}

fn verify_amd_snp_measurement_policy(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    state: verification_core::VerifiedAmdSnpSecurityState,
    registry_default: &AmdSnpSecurityPolicy,
    effective_attributes: &BTreeMap<[u8; 32], [u8; 32]>,
    encoded_requirements: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    has_workload: bool,
) {
    use atakit_core::tee_attributes::{
        amd_sev_snp_platform_info_matches, amd_sev_snp_tcb_meets_minimum,
        merge_amd_sev_snp_platform_info_policies, AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
        AMD_SEV_SNP_TCB_MINIMUM_KEY,
    };

    let mitigation_policy = validate_amd_snp_mitigation_policy(
        state.report_version,
        state.launch_mitigation_vector,
        state.current_mitigation_vector,
        registry_default,
    );
    check(
        report,
        errors,
        "amd-sev-snp-mitigation-vector-policy",
        mitigation_policy.is_ok(),
        mitigation_policy.err().unwrap_or_else(|| {
            "verified AMD SEV-SNP mitigation vectors satisfy the registry policy".to_string()
        }),
    );

    let base_tcb = effective_attributes
        .get(&AMD_SEV_SNP_TCB_MINIMUM_KEY)
        .copied()
        .unwrap_or(registry_default.minimum_tcb);
    let base_tcb_matches = amd_sev_snp_tcb_meets_minimum(&state.tcb_values, &base_tcb);
    check(
        report,
        errors,
        "tee-attribute-base-image-amd-sev-snp-tcb-minimum",
        base_tcb_matches,
        format!(
            "verified AMD SEV-SNP TCB 0x{} does not meet the resolved base-image minimum",
            hex::encode(state.tcb_values)
        ),
    );

    if has_workload {
        let workload_tcb = resolve_packed_workload_requirement(
            encoded_requirements,
            AMD_SEV_SNP_TCB_MINIMUM_KEY,
            registry_default.minimum_tcb,
        );
        let (matches, detail) = match workload_tcb {
            Ok(workload_tcb) => (
                amd_sev_snp_tcb_meets_minimum(&state.tcb_values, &workload_tcb),
                format!(
                    "verified AMD SEV-SNP TCB 0x{} does not meet the resolved workload minimum",
                    hex::encode(state.tcb_values)
                ),
            ),
            Err(detail) => (false, detail),
        };
        check(
            report,
            errors,
            "tee-attribute-workload-amd-sev-snp-tcb-minimum",
            matches,
            detail,
        );
    }

    let base_platform_info = effective_attributes
        .get(&AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY)
        .copied()
        .unwrap_or(registry_default.platform_info_policy);
    let base_platform_info_matches =
        amd_sev_snp_platform_info_matches(state.platform_info, &base_platform_info);
    check(
        report,
        errors,
        "tee-attribute-base-image-amd-sev-snp-platform-info-policy",
        base_platform_info_matches,
        format!(
            "verified AMD SEV-SNP PLATFORM_INFO 0x{:016x} does not meet the resolved base-image policy",
            state.platform_info
        ),
    );

    if has_workload {
        let workload_platform_info = resolve_packed_workload_requirement(
            encoded_requirements,
            AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
            registry_default.platform_info_policy,
        );
        let (workload_platform_info_matches, detail) = match workload_platform_info {
            Ok(workload_platform_info) => {
                let effective_platform_info = merge_amd_sev_snp_platform_info_policies(
                    &base_platform_info,
                    &workload_platform_info,
                );
                (
                    effective_platform_info.as_ref().is_some_and(|policy| {
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
        check(
            report,
            errors,
            "tee-attribute-workload-amd-sev-snp-platform-info-policy",
            workload_platform_info_matches,
            detail,
        );
    }
}

fn validate_amd_snp_mitigation_policy(
    report_version: u32,
    launch_mitigation_vector: u64,
    current_mitigation_vector: u64,
    policy: &AmdSnpSecurityPolicy,
) -> std::result::Result<(), String> {
    if (policy.required_launch_mitigation_vector != 0
        || policy.required_current_mitigation_vector != 0)
        && report_version != 5
    {
        return Err(format!(
            "AMD SEV-SNP report version {} cannot satisfy a mitigation-vector policy; version 5 is required",
            report_version
        ));
    }
    if launch_mitigation_vector & policy.required_launch_mitigation_vector
        != policy.required_launch_mitigation_vector
    {
        return Err(format!(
            "AMD SEV-SNP LAUNCH_MIT_VECTOR 0x{:016x} is missing required mask 0x{:016x}",
            launch_mitigation_vector, policy.required_launch_mitigation_vector
        ));
    }
    if current_mitigation_vector & policy.required_current_mitigation_vector
        != policy.required_current_mitigation_vector
    {
        return Err(format!(
            "AMD SEV-SNP CURRENT_MIT_VECTOR 0x{:016x} is missing required mask 0x{:016x}",
            current_mitigation_vector, policy.required_current_mitigation_vector
        ));
    }
    Ok(())
}

fn bytes32_to_u16(value: &[u8; 32]) -> Option<u16> {
    value[..30]
        .iter()
        .all(|byte| *byte == 0)
        .then(|| u16::from_be_bytes([value[30], value[31]]))
}

fn tdx_tcb_status_policy_matches(value: Option<&[u8; 32]>, actual_bit: u16) -> bool {
    let mask = match value {
        Some(value) => bytes32_to_u16(value),
        None => Some(atakit_core::tee_attributes::TDX_TCB_STATUS_OK),
    };
    mask.is_some_and(|mask| {
        atakit_core::tee_attributes::tdx_tcb_status_names(mask).is_some() && mask & actual_bit != 0
    })
}

fn effective_measurement_attributes(
    profile: &MeasurementProfile,
    variant: &MeasurementVariant,
) -> std::result::Result<BTreeMap<[u8; 32], [u8; 32]>, String> {
    let mut attributes = parse_measurement_attributes(&profile.attributes, "profile")?;
    for (key, value) in parse_measurement_attributes(&variant.attributes, "variant")? {
        attributes.insert(key, value);
    }
    Ok(attributes)
}

fn parse_measurement_attributes(
    values: &[serde_json::Value],
    owner: &str,
) -> std::result::Result<BTreeMap<[u8; 32], [u8; 32]>, String> {
    let mut attributes = BTreeMap::new();
    for value in values {
        let (key, value) = if let Some(name) = value.get("name").and_then(serde_json::Value::as_str)
        {
            use atakit_core::tee_attributes::{
                ReservedAttributeValueKind, VerifiedTeeAttribute, TEE_ATTRIBUTE_NAMESPACE,
            };
            match VerifiedTeeAttribute::from_name(name) {
                Some(attribute)
                    if attribute.value_kind() == ReservedAttributeValueKind::Boolean =>
                {
                    let enabled = value
                        .get("value")
                        .and_then(serde_json::Value::as_bool)
                        .ok_or_else(|| {
                            format!(
                                "{owner} readable reserved attribute {name} is missing Boolean value"
                            )
                        })?;
                    (
                        attribute.key(),
                        atakit_core::tee_attributes::bool_value(enabled),
                    )
                }
                Some(VerifiedTeeAttribute::IntelTdxTcbStatusAllowed) => {
                    let names = value
                        .get("value")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| {
                            format!(
                                "{owner} readable reserved attribute {name} value must be a status-name array"
                            )
                        })?
                        .iter()
                        .map(|value| {
                            value.as_str().ok_or_else(|| {
                                format!(
                                    "{owner} readable reserved attribute {name} status names must be strings"
                                )
                            })
                        })
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    let mask = atakit_core::tee_attributes::tdx_tcb_status_mask(names)
                        .ok_or_else(|| {
                            format!(
                                "{owner} readable reserved attribute {name} must contain unique supported status names and include ok"
                            )
                        })?;
                    (
                        atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_KEY,
                        atakit_core::tee_attributes::u16_value(mask),
                    )
                }
                Some(attribute) => {
                    let packed = value
                        .get("value")
                        .and_then(serde_json::Value::as_str)
                        .and_then(atakit_core::tee_attributes::parse_bytes32_hex)
                        .ok_or_else(|| {
                            format!(
                                "{owner} readable reserved attribute {name} value must be a 0x-prefixed bytes32 string"
                            )
                        })?;
                    let valid = match attribute.value_kind() {
                        ReservedAttributeValueKind::AmdSevSnpTcb => {
                            atakit_core::tee_attributes::valid_amd_sev_snp_tcb(&packed)
                        }
                        ReservedAttributeValueKind::AmdSevSnpPlatformInfoPolicy => {
                            atakit_core::tee_attributes::valid_amd_sev_snp_platform_info_policy(
                                &packed,
                            )
                        }
                        _ => unreachable!("Boolean and Intel TDX TCB values handled above"),
                    };
                    if !valid {
                        return Err(format!(
                            "{owner} readable reserved attribute {name} value is invalid"
                        ));
                    }
                    (attribute.key(), packed)
                }
                None if name.starts_with(TEE_ATTRIBUTE_NAMESPACE) => {
                    return Err(format!(
                        "{owner} attribute has unknown reserved name {name}"
                    ));
                }
                None => {
                    let string_value = value
                        .get("value")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            format!(
                                "{owner} custom readable attribute {name} value must be a string"
                            )
                        })?;
                    (
                        atakit_core::tee_attributes::attribute_key(name),
                        atakit_core::tee_attributes::attribute_string_value(string_value),
                    )
                }
            }
        } else {
            let key = value
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("{owner} attribute is missing string key"))?;
            let value = value
                .get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("{owner} attribute is missing string value"))?;
            (
                decode_hex_32("attribute.key", key).map_err(|error| error.to_string())?,
                decode_hex_32("attribute.value", value).map_err(|error| error.to_string())?,
            )
        };
        if let Some(attribute) = atakit_core::tee_attributes::VerifiedTeeAttribute::from_key(&key) {
            match attribute.value_kind() {
                atakit_core::tee_attributes::ReservedAttributeValueKind::Boolean
                    if value != atakit_core::tee_attributes::ATTRIBUTE_FALSE
                        && value != atakit_core::tee_attributes::ATTRIBUTE_TRUE =>
                {
                    return Err(format!(
                        "{owner} reserved Boolean attribute 0x{} has invalid value 0x{}",
                        hex::encode(key),
                        hex::encode(value)
                    ));
                }
                atakit_core::tee_attributes::ReservedAttributeValueKind::IntelTdxTcbStatusMask => {
                    let mask = bytes32_to_u16(&value).ok_or_else(|| {
                        format!("{owner} Intel TDX TCB status mask is not a uint16")
                    })?;
                    if atakit_core::tee_attributes::tdx_tcb_status_names(mask).is_none() {
                        return Err(format!(
                            "{owner} Intel TDX TCB status mask 0x{mask:x} is invalid"
                        ));
                    }
                }
                atakit_core::tee_attributes::ReservedAttributeValueKind::AmdSevSnpTcb
                    if !atakit_core::tee_attributes::valid_amd_sev_snp_tcb(&value) =>
                {
                    return Err(format!("{owner} AMD SEV-SNP TCB minimum is invalid"));
                }
                atakit_core::tee_attributes::ReservedAttributeValueKind::AmdSevSnpPlatformInfoPolicy
                    if !atakit_core::tee_attributes::valid_amd_sev_snp_platform_info_policy(&value) =>
                {
                    return Err(format!(
                        "{owner} AMD SEV-SNP PLATFORM_INFO policy is invalid"
                    ));
                }
                _ => {}
            }
        }
        if attributes.insert(key, value).is_some() {
            return Err(format!(
                "{owner} attributes contain a duplicate key 0x{}",
                hex::encode(key)
            ));
        }
    }
    Ok(attributes)
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

/// The on-chain base-image identifier.
///
/// Delegates to the registry crate that defines the encoding. A local copy that
/// drifted would derive identifiers registered to nobody.
pub fn compute_base_image_id(publisher: &[u8; 32], name: &str, version: &str) -> [u8; 32] {
    use automata_tee_workload_measurement::base_image_registry::BaseImageRegistry;
    use automata_tee_workload_measurement::types::AppRef;

    let app_ref = AppRef::new(alloy::primitives::B256::from(*publisher), name, version);
    BaseImageRegistry::get_image_id(&app_ref).into()
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

fn verify_pcr_spec256(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    spec: &PcrSpec256,
    pcrs: &[PcrEvidence],
    event_log_hashes: &[PcrEventHashes],
    startup_locality: u8,
) {
    let check_name = format!("pcr-sha256-{}", spec.pcr_index);
    let Some(pcr) = pcrs.iter().find(|pcr| pcr.index == spec.pcr_index) else {
        fail(
            report,
            errors,
            &check_name,
            format!("TPM evidence does not contain PCR {}", spec.pcr_index),
        );
        return;
    };
    let Some(measured_sha256) = pcr.sha256.as_deref() else {
        fail(
            report,
            errors,
            &check_name,
            "PCR has no SHA-256 value".to_string(),
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
        comparison: spec.comparison.clone(),
    };
    match session::evaluate_session_pcr_policy_with_startup_locality(
        &policy,
        measured,
        &decoded,
        startup_locality,
    ) {
        Ok(()) => pass(report, &check_name),
        Err(detail) => fail(report, errors, &check_name, detail),
    }
}

fn verify_pcr_spec384(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    spec: &PcrSpec384,
    pcrs: &[PcrEvidence],
    event_log_hashes: &[PcrEventHashes],
    startup_locality: u8,
) {
    let check_name = format!("pcr-sha384-{}", spec.pcr_index);
    let Some(pcr) = pcrs.iter().find(|pcr| pcr.index == spec.pcr_index) else {
        fail(
            report,
            errors,
            &check_name,
            format!("TPM evidence does not contain PCR {}", spec.pcr_index),
        );
        return;
    };
    let Some(measured_sha384) = pcr.sha384.as_deref() else {
        fail(
            report,
            errors,
            &check_name,
            "PCR has no SHA-384 value".to_string(),
        );
        return;
    };
    let measured = match decode_hex_array::<48>("pcr.sha384", measured_sha384) {
        Ok(value) => value,
        Err(error) => {
            fail(report, errors, &check_name, error.to_string());
            return;
        }
    };
    let event_values = event_log_hashes
        .iter()
        .find(|events| events.pcr_index == spec.pcr_index)
        .map(|events| events.sha384.as_slice())
        .unwrap_or_default();
    let decoded = event_values
        .iter()
        .map(|event| decode_hex_array::<48>("eventLogHashes.sha384", event))
        .collect::<Result<Vec<_>>>();
    let decoded = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            fail(report, errors, &check_name, error.to_string());
            return;
        }
    };
    let policy = SessionPcrPolicy384 {
        pcr_index: spec.pcr_index,
        comparison: spec.comparison.clone(),
    };
    match session::evaluate_session_pcr_policy384(&policy, measured, &decoded, startup_locality) {
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
    decode_hex_array(field, value)
}

fn decode_hex_array<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N]> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(raw).map_err(|e| AttestationError::Hex {
        field,
        detail: e.to_string(),
    })?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| AttestationError::Hex {
        field,
        detail: format!("expected {N} bytes, got {}", bytes.len()),
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
    use automata_tee_workload_measurement::pcr_comparison::{
        encode_dynamic256, encode_static256, encode_static384, DYNAMIC_SUBSEQUENCE, DYNAMIC_SUBSET,
    };
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{
        KeyPair as AwsLcKeyPair, RsaKeyPair, RsaPublicKeyComponents, RSA_PKCS1_SHA256,
    };
    use k256::ecdsa::SigningKey as K256SigningKey;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use signature::{hazmat::PrehashSigner, Signer};

    fn static_comparison256(value: [u8; 32]) -> String {
        hex0x(&encode_static256(value.into()))
    }

    fn static_comparison384(value: [u8; 48]) -> String {
        hex0x(&encode_static384(value))
    }

    fn dynamic_comparison256(comparison_type: u16, values: Vec<[u8; 32]>) -> String {
        hex0x(
            &encode_dynamic256(
                comparison_type,
                values.into_iter().map(Into::into).collect(),
            )
            .expect("valid dynamic PCR comparison type"),
        )
    }

    fn synthetic_snp_security_report(policy: u64) -> Vec<u8> {
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SNP_REPORT_VERSION_OFFSET..SNP_REPORT_VERSION_OFFSET + 4]
            .copy_from_slice(&3u32.to_le_bytes());
        report[SNP_REPORT_POLICY_OFFSET..SNP_REPORT_POLICY_OFFSET + 8]
            .copy_from_slice(&policy.to_le_bytes());
        report[SNP_REPORT_SIG_ALGO_OFFSET..SNP_REPORT_SIG_ALGO_OFFSET + 4]
            .copy_from_slice(&SNP_SIG_ALGO_ECDSA_P384_SHA384.to_le_bytes());
        report[SNP_REPORT_CPUID_OFFSET..SNP_REPORT_CPUID_OFFSET + 3].copy_from_slice(&[0x19, 0, 0]);
        report
    }

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
            format: 2,
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
                pcr0_startup_locality: 0,
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
                format: 2,
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
                    pcr0_startup_locality: 0,
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
                format: 2,
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
                    pcr0_startup_locality: 0,
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
        quote[TDX_REPORT_ATTRIBUTES_OFFSET + 3] = 0x10;
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

    fn fixture_amd_milan_crl() -> Vec<u8> {
        let encoded = include_str!("../testdata/fedora-oci-gcp-n2d-standard-4/milan.crl.der.b64")
            .lines()
            .collect::<String>();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("embedded AMD Milan CRL fixture must be valid base64")
    }

    fn snp_fixture_time() -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(1_784_851_200)
    }

    fn fake_amd_snp_cert_table(entries: &[([u8; 16], &[u8])]) -> Vec<u8> {
        let table_len = SNP_CERT_TABLE_ENTRY_BYTES * (entries.len() + 1);
        let mut out = vec![0u8; table_len];
        let mut cert_offset = table_len;
        for (idx, (guid, cert)) in entries.iter().enumerate() {
            let entry_offset = idx * SNP_CERT_TABLE_ENTRY_BYTES;
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

    fn fake_amd_snp_auxblob(ark: &[u8], ask: &[u8], vcek: &[u8]) -> Vec<u8> {
        fake_amd_snp_cert_table(&[
            (SNP_CERT_TABLE_ARK_GUID, ark),
            (SNP_CERT_TABLE_ASK_GUID, ask),
            (SNP_CERT_TABLE_VCEK_GUID, vcek),
        ])
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

    #[test]
    fn rejects_oversized_amd_snp_certificate_table() {
        let table = vec![0u8; MAX_SNP_CERT_TABLE_BYTES + 1];
        let error = parse_amd_snp_cert_table(&table).expect_err("oversized table must fail");

        assert!(error.contains("1048576-byte limit"), "{error}");
    }

    #[test]
    fn rejects_amd_snp_certificate_table_with_too_many_entries() {
        let entry_count = MAX_SNP_CERT_TABLE_ENTRIES + 1;
        let header_len = SNP_CERT_TABLE_ENTRY_BYTES * (entry_count + 1);
        let mut table = vec![0u8; header_len + entry_count];
        for index in 0..entry_count {
            let entry_offset = index * SNP_CERT_TABLE_ENTRY_BYTES;
            table[entry_offset] = 1;
            table[entry_offset + 16..entry_offset + 20]
                .copy_from_slice(&((header_len + index) as u32).to_le_bytes());
            table[entry_offset + 20..entry_offset + 24].copy_from_slice(&1u32.to_le_bytes());
        }

        let error = parse_amd_snp_cert_table(&table).expect_err("too many entries must fail");
        assert!(error.contains("more than 64 entries"), "{error}");
    }

    #[test]
    fn rejects_amd_snp_certificate_table_without_terminator() {
        let mut table = vec![0u8; SNP_CERT_TABLE_ENTRY_BYTES + 1];
        table[..16].copy_from_slice(&SNP_CERT_TABLE_ARK_GUID);
        table[16..20].copy_from_slice(&(SNP_CERT_TABLE_ENTRY_BYTES as u32).to_le_bytes());
        table[20..24].copy_from_slice(&1u32.to_le_bytes());
        table[SNP_CERT_TABLE_ENTRY_BYTES] = 1;

        let error = parse_amd_snp_cert_table(&table).expect_err("missing terminator must fail");
        assert!(error.contains("missing its zero terminator"), "{error}");
    }

    #[test]
    fn rejects_amd_snp_certificate_table_range_overlapping_header() {
        let header_len = SNP_CERT_TABLE_ENTRY_BYTES * 2;
        let mut table = vec![0u8; header_len + 1];
        table[..16].copy_from_slice(&SNP_CERT_TABLE_ARK_GUID);
        table[16..20].copy_from_slice(&(SNP_CERT_TABLE_ENTRY_BYTES as u32).to_le_bytes());
        table[20..24].copy_from_slice(&1u32.to_le_bytes());

        let error = parse_amd_snp_cert_table(&table).expect_err("header overlap must fail");
        assert!(error.contains("overlaps the header"), "{error}");
    }

    #[test]
    fn rejects_overlapping_amd_snp_certificate_ranges() {
        let header_len = SNP_CERT_TABLE_ENTRY_BYTES * 3;
        let mut table = vec![0u8; header_len + 3];
        for (index, guid) in [SNP_CERT_TABLE_ARK_GUID, SNP_CERT_TABLE_ASK_GUID]
            .iter()
            .enumerate()
        {
            let entry_offset = index * SNP_CERT_TABLE_ENTRY_BYTES;
            table[entry_offset..entry_offset + 16].copy_from_slice(guid);
            table[entry_offset + 16..entry_offset + 20]
                .copy_from_slice(&((header_len + index) as u32).to_le_bytes());
            table[entry_offset + 20..entry_offset + 24].copy_from_slice(&2u32.to_le_bytes());
        }

        let error = parse_amd_snp_cert_table(&table).expect_err("overlapping ranges must fail");
        assert!(error.contains("certificate ranges overlap"), "{error}");
    }

    #[test]
    fn rejects_duplicate_amd_snp_certificate_types() {
        let table = fake_amd_snp_cert_table(&[
            (SNP_CERT_TABLE_ARK_GUID, b"first"),
            (SNP_CERT_TABLE_ARK_GUID, b"second"),
        ]);

        let error = parse_amd_snp_cert_table(&table).expect_err("duplicate ARK must fail");
        assert!(error.contains("duplicate ARK entries"), "{error}");
    }

    #[test]
    fn accepts_unknown_amd_snp_certificate_type_without_selecting_it() {
        let table = fake_amd_snp_cert_table(&[
            ([0x42; 16], b"future certificate"),
            (SNP_CERT_TABLE_ARK_GUID, b"ark"),
            (SNP_CERT_TABLE_ASK_GUID, b"ask"),
            (SNP_CERT_TABLE_VCEK_GUID, b"vcek"),
        ]);

        let parsed = parse_amd_snp_cert_table(&table).expect("unknown entry type is extensible");
        assert_eq!(parsed.ark.as_deref(), Some(b"ark".as_slice()));
        assert_eq!(parsed.ask.as_deref(), Some(b"ask".as_slice()));
        assert_eq!(parsed.vcek.as_deref(), Some(b"vcek".as_slice()));
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

    fn fake_gcp_ak_chain_and_signature(tpms_attest: &[u8]) -> FakeGcpAkChain {
        let (signing_key, ak_public, cert_chain, roots) = fake_gcp_ak_chain();
        let signature: P256Signature = signing_key.sign(tpms_attest_body(tpms_attest).unwrap());
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

    #[test]
    fn rejects_non_ca_certificate_used_as_gcp_ak_issuer() {
        let mut root_params =
            CertificateParams::new(Vec::new()).expect("root certificate parameters");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let root_key = KeyPair::generate().expect("root key");
        let root = root_params
            .self_signed(&root_key)
            .expect("root certificate");

        let mut non_ca_params =
            CertificateParams::new(vec!["not-a-ca.test".into()]).expect("non-CA parameters");
        non_ca_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let non_ca_key = KeyPair::generate().expect("non-CA key");
        let non_ca = non_ca_params
            .signed_by(&non_ca_key, &root, &root_key)
            .expect("non-CA certificate");

        let mut ak_params =
            CertificateParams::new(vec!["forged-ak.test".into()]).expect("AK parameters");
        ak_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let ak_key = KeyPair::generate().expect("AK key");
        let ak = ak_params
            .signed_by(&ak_key, &non_ca, &non_ca_key)
            .expect("certificate signed by non-CA key");
        let signing_key =
            P256SigningKey::from_pkcs8_der(&ak_key.serialize_der()).expect("AK PKCS#8");
        let ak_public = fake_tpmt_public_ecc(signing_key.verifying_key());
        let chain = vec![
            ak.der().as_ref().to_vec(),
            non_ca.der().as_ref().to_vec(),
            root.der().as_ref().to_vec(),
        ];
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();

        verify_gcp_ak_cert_chain_der(
            &mut report,
            &mut errors,
            &chain,
            &ak_public,
            &[root.der().as_ref().to_vec()],
            &[],
            SystemTime::now(),
        );

        assert!(
            errors.iter().any(|error| {
                error.detail.contains("Basic Constraints")
                    || error.detail.contains("not a certificate authority")
            }),
            "{errors:?}"
        );
    }

    fn fake_ak_and_signature(tpms_attest: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let signing_key = P256SigningKey::from_slice(&[7u8; 32]).expect("test signing key");
        let verify_key = signing_key.verifying_key();
        let signature: P256Signature = signing_key.sign(tpms_attest_body(tpms_attest).unwrap());
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

    fn fake_azure_ak_binding_and_signature(tpms_attest: &[u8]) -> (AkBinding, Vec<u8>, Vec<u8>) {
        fake_azure_ak_binding_and_signature_for_tee(tpms_attest, "tdx")
    }

    fn fake_azure_ak_binding_and_signature_for_tee(
        tpms_attest: &[u8],
        tee: &str,
    ) -> (AkBinding, Vec<u8>, Vec<u8>) {
        let signing_key = RsaKeyPair::generate(KeySize::Rsa2048).expect("test RSA key");
        let public_key = RsaPublicKeyComponents::<Vec<u8>>::from(signing_key.public_key());
        let signature = sign_rsa_sha256(
            &signing_key,
            tpms_attest_body(tpms_attest).expect("TPM attest body"),
        );
        let hcl_var_data = serde_json::json!({
            "keys": [{
                "kid": "HCLAkPub",
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(public_key.n),
                "e": URL_SAFE_NO_PAD.encode(public_key.e)
            }]
        });
        let hcl_var_data = serde_json::to_vec(&hcl_var_data).expect("hcl var data JSON");
        let (jwt, trusted_maa_key) = fake_azure_maa_jwt(&hcl_var_data, tee);
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
            fake_tpmt_signature_rsassa(&signature),
            trusted_maa_key,
        )
    }

    fn bind_azure_tdx_evidence_to_ak_binding(response: &mut TlsAttestationResponse) {
        let binding = response.ak_binding.as_ref().expect("Azure AK binding");
        let binding_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&binding.data).unwrap()).unwrap();
        let hcl_var_data = URL_SAFE_NO_PAD
            .decode(binding_json["hclVarData"].as_str().unwrap())
            .unwrap();
        let evidence = response.tee_evidence.as_mut().expect("Azure TEE evidence");
        let mut quote = URL_SAFE_NO_PAD.decode(&evidence.report).unwrap();
        let report_start = tdx_quote_report_start(&quote).expect("TDX quote body");
        let report_data_start = report_start + TDX_REPORT_REPORT_DATA_OFFSET;
        let hcl_hash: [u8; 32] = Sha256::digest(&hcl_var_data).into();
        quote[report_data_start..report_data_start + 32].copy_from_slice(&hcl_hash);
        quote[report_data_start + 32..report_data_start + 64].fill(0);
        evidence.report = URL_SAFE_NO_PAD.encode(quote);
        evidence.auxiliary = Some(URL_SAFE_NO_PAD.encode(hcl_var_data));
    }

    fn bind_azure_snp_evidence_to_ak_binding(response: &mut TlsAttestationResponse) {
        let binding = response.ak_binding.as_ref().expect("Azure AK binding");
        let binding_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&binding.data).unwrap()).unwrap();
        let hcl_var_data = URL_SAFE_NO_PAD
            .decode(binding_json["hclVarData"].as_str().unwrap())
            .unwrap();
        let mut snp_report = synthetic_snp_security_report(1u64 << 17);
        let hcl_hash: [u8; 32] = Sha256::digest(&hcl_var_data).into();
        snp_report[0x50..0x70].copy_from_slice(&hcl_hash);
        let evidence = response.tee_evidence.as_mut().expect("Azure TEE evidence");
        evidence.report = URL_SAFE_NO_PAD.encode(snp_report);
        evidence.auxiliary = Some(URL_SAFE_NO_PAD.encode(hcl_var_data));
    }

    /// Wrap raw MAA key bytes as a trusted certificate that has not expired.
    /// Tests asserting expiry behaviour build the certificate directly.
    fn maa_cert(public_key: Vec<u8>) -> AzureMaaTrustCertificate {
        AzureMaaTrustCertificate {
            public_key,
            not_after: u64::MAX,
        }
    }

    fn fake_azure_maa_jwt(hcl_var_data: &[u8], tee: &str) -> (String, Vec<u8>) {
        fake_azure_maa_jwt_with_times(
            hcl_var_data,
            tee,
            1_700_000_000,
            1_700_000_000,
            4_102_444_800,
        )
    }

    fn fake_azure_maa_jwt_with_times(
        hcl_var_data: &[u8],
        tee: &str,
        iat: u64,
        nbf: u64,
        exp: u64,
    ) -> (String, Vec<u8>) {
        let signing_key = RsaKeyPair::generate(KeySize::Rsa2048).expect("test MAA RSA key");
        let public_key = RsaPublicKeyComponents::<Vec<u8>>::from(signing_key.public_key());
        let trusted_key = serde_json::to_vec(&serde_json::json!({
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode(public_key.n),
            "e": URL_SAFE_NO_PAD.encode(public_key.e)
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
                "iat": iat,
                "nbf": nbf,
                "exp": exp,
                "x-ms-runtime": {"exp": 4_102_444_800u64},
                "x-ms-attestation-type": attestation_type,
                "x-ms-compliance-status": "azure-compliant-cvm",
                report_data_claim: hex::encode(report_data)
            }))
            .expect("jwt claims"),
        );
        let signing_input = format!("{header}.{claims}");
        let signature = sign_rsa_sha256(&signing_key, signing_input.as_bytes());
        (
            format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)),
            trusted_key,
        )
    }

    fn sign_rsa_sha256(signing_key: &RsaKeyPair, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0u8; signing_key.public_modulus_len()];
        signing_key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut signature,
            )
            .expect("test RSA signature");
        signature
    }

    fn fake_tpmt_signature_rsassa(signature: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        out.extend_from_slice(signature);
        out
    }

    #[test]
    fn rsa_verifier_accepts_pkcs1_der_public_key() {
        let signing_key = RsaKeyPair::generate(KeySize::Rsa2048).expect("test RSA key");
        let message = b"PKCS#1 DER compatibility";
        let signature = sign_rsa_sha256(&signing_key, message);
        let public_key =
            parse_rsa_public_key(signing_key.public_key().as_ref()).expect("PKCS#1 public key");
        public_key
            .verify_sig(message, &signature)
            .expect("PKCS#1 RSA signature");
    }

    fn fake_tpm_quote(qualifying_data: &[u8; 32], pcrs: &[(u8, [u8; 32])]) -> Vec<u8> {
        fake_tpm_quote_banks(qualifying_data, pcrs, &[])
    }

    fn fake_tpm_quote_banks(
        qualifying_data: &[u8; 32],
        sha256_pcrs: &[(u8, [u8; 32])],
        sha384_pcrs: &[(u8, [u8; 48])],
    ) -> Vec<u8> {
        fake_tpm_quote_banks_with_order(qualifying_data, sha256_pcrs, sha384_pcrs, false)
    }

    fn fake_tpm_quote_banks_with_order(
        qualifying_data: &[u8; 32],
        sha256_pcrs: &[(u8, [u8; 32])],
        sha384_pcrs: &[(u8, [u8; 48])],
        sha384_first: bool,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        body.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner
        body.extend_from_slice(&(qualifying_data.len() as u16).to_be_bytes());
        body.extend_from_slice(qualifying_data);
        body.extend_from_slice(&[0u8; 17]); // clockInfo
        body.extend_from_slice(&[0u8; 8]); // firmwareVersion
        let selection_count =
            u32::from(!sha256_pcrs.is_empty()) + u32::from(!sha384_pcrs.is_empty());
        body.extend_from_slice(&selection_count.to_be_bytes());
        let bank_order = if sha384_first {
            [TPM_ALG_SHA384, TPM_ALG_SHA256]
        } else {
            [TPM_ALG_SHA256, TPM_ALG_SHA384]
        };
        for hash_alg in bank_order {
            let indices = match hash_alg {
                TPM_ALG_SHA256 => sha256_pcrs
                    .iter()
                    .map(|(index, _)| *index)
                    .collect::<Vec<_>>(),
                TPM_ALG_SHA384 => sha384_pcrs
                    .iter()
                    .map(|(index, _)| *index)
                    .collect::<Vec<_>>(),
                _ => unreachable!(),
            };
            if indices.is_empty() {
                continue;
            }
            body.extend_from_slice(&hash_alg.to_be_bytes());
            body.push(3); // sizeofSelect for PCRs 0..=23
            let mut select = [0u8; 3];
            for index in indices {
                select[usize::from(index / 8)] |= 1 << (index % 8);
            }
            body.extend_from_slice(&select);
        }
        let mut pcr_concat = Vec::with_capacity(sha256_pcrs.len() * 32 + sha384_pcrs.len() * 48);
        for hash_alg in bank_order {
            match hash_alg {
                TPM_ALG_SHA256 => {
                    for (_, value) in sha256_pcrs {
                        pcr_concat.extend_from_slice(value);
                    }
                }
                TPM_ALG_SHA384 => {
                    for (_, value) in sha384_pcrs {
                        pcr_concat.extend_from_slice(value);
                    }
                }
                _ => unreachable!(),
            }
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
        let expected_pcr = decode_hex_32("expected_pcr", expected_pcr)
            .expect("test PCR policy must contain one SHA-256 value");
        let base_image_id = compute_base_image_id(&TEST_PUBLISHER, "base", "v1");
        let profile_name = format!("{cloud}-{tee}");
        let profile_id = compute_platform_profile_id(&base_image_id, &profile_name);
        let variant_id = compute_variant_id(&profile_id, machine_type);
        MeasurementPolicy {
            source: "test-pack".to_string(),
            pack: base_image_pack(
                Subject {
                    publisher: hex0x(&TEST_PUBLISHER),
                    name: "base".to_string(),
                    version: "v1".to_string(),
                    id: hex0x(&base_image_id),
                    uri: None,
                    archive_sha256: None,
                },
                vec![MeasurementProfile {
                    name: profile_name,
                    id: hex0x(&profile_id),
                    cloud: cloud.to_string(),
                    tee: tee.to_string(),
                    pcr_bank_selection: PcrBankSelection::Sha256,
                    invariant_pcrs256: vec![PcrSpec256 {
                        pcr_index: 4,
                        comparison: static_comparison256(expected_pcr),
                    }],
                    variants: vec![MeasurementVariant {
                        name: machine_type.to_string(),
                        id: hex0x(&variant_id),
                        machine_types: vec![machine_type.to_string()],
                        variant_pcrs256: Vec::new(),
                        variant_pcrs384: Vec::new(),
                        attributes: Vec::new(),
                    }],
                    invariant_pcrs384: Vec::new(),
                    attributes: Vec::new(),
                }],
            ),
        }
    }

    /// Fixed publisher for tests that are not about publisher handling.
    const TEST_PUBLISHER: [u8; 32] = [0xaa; 32];

    /// Borrow the profiles inside a base-image pack body, writing them back on
    /// drop. Tests mutate profiles constantly; the production type keeps the
    /// body unparsed so the schema is checked before it is read.
    struct ProfilesGuard<'a> {
        pack: &'a mut MeasurementPack,
        profiles: Vec<MeasurementProfile>,
    }

    impl std::ops::Deref for ProfilesGuard<'_> {
        type Target = Vec<MeasurementProfile>;
        fn deref(&self) -> &Self::Target {
            &self.profiles
        }
    }

    impl std::ops::DerefMut for ProfilesGuard<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.profiles
        }
    }

    impl Drop for ProfilesGuard<'_> {
        fn drop(&mut self) {
            self.pack.measurements = serde_json::to_value(BaseImageMeasurements {
                profiles: std::mem::take(&mut self.profiles),
            })
            .expect("serialize test measurements");
        }
    }

    impl MeasurementPack {
        fn profiles_mut(&mut self) -> ProfilesGuard<'_> {
            let body: BaseImageMeasurements = self
                .body(BASE_IMAGE_MEASUREMENT_PACK_SCHEMA)
                .expect("test pack must be a base-image pack");
            ProfilesGuard {
                pack: self,
                profiles: body.profiles,
            }
        }

        fn profiles(&self) -> Vec<MeasurementProfile> {
            let body: BaseImageMeasurements = self
                .body(BASE_IMAGE_MEASUREMENT_PACK_SCHEMA)
                .expect("test pack must be a base-image pack");
            body.profiles
        }
    }

    /// Build a base-image pack envelope around a profile list.
    fn base_image_pack(subject: Subject, profiles: Vec<MeasurementProfile>) -> MeasurementPack {
        MeasurementPack {
            schema: BASE_IMAGE_MEASUREMENT_PACK_SCHEMA.to_string(),
            revision: 1,
            published_at: 1_786_000_000,
            subject,
            measurements: serde_json::to_value(BaseImageMeasurements { profiles })
                .expect("serialize test measurements"),
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
    fn gcp_tdx_pcr15_binding_requires_full_quote() {
        let uuid = [0x42u8; 16];
        let expected = expected_gcp_tdx_pcr15_for_uuid(&uuid);
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();
        let got =
            expected_gcp_tdx_pcr15(&mut report, &mut errors, &fake_gcp_tdx_full_quote_v4(&uuid))
                .expect("GCP TDX PCR15 should derive from a full quote");
        assert_eq!(got, expected);
        assert!(errors.is_empty(), "{errors:?}");

        let mut body_report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut body_errors = Vec::new();
        assert!(expected_gcp_tdx_pcr15(
            &mut body_report,
            &mut body_errors,
            &fake_gcp_tdx_quote_body(&uuid),
        )
        .is_none());
        assert!(body_errors
            .iter()
            .any(|error| error.detail.contains("unsupported version")));
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
            "pcr-sha256-4",
        ] {
            assert_check_passed(&failure, check);
        }
    }

    #[test]
    fn verifies_gcp_snp_vendor_report_fixture() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let crl = fixture_amd_milan_crl();

        verify_snp_report_with_aux_certs(
            snp_fixture_time(),
            &report,
            &auxblob,
            &[ark.to_vec()],
            &[],
            &[crl],
        )
        .expect("GCP SEV-SNP fixture report should verify under fixture ARK");
    }

    #[test]
    fn verifies_gcp_snp_vendor_report_fixture_with_ark_hash() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let ark_hash: [u8; 32] = Sha256::digest(&ark).into();
        let crl = fixture_amd_milan_crl();

        verify_snp_report_with_aux_certs(
            snp_fixture_time(),
            &report,
            &auxblob,
            &[],
            &[ark_hash],
            &[crl],
        )
        .expect("GCP SEV-SNP fixture report should verify under fixture ARK hash");
    }

    #[test]
    fn azure_snp_vendor_wrapper_accepts_ff_report_id_ma_absence_sentinel() {
        let (snp_report, ark, cert_table) = fixture_gcp_snp_report_and_certs();
        verify_snp_report_with_aux_certs(
            snp_fixture_time(),
            &snp_report,
            &cert_table,
            std::slice::from_ref(&ark),
            &[],
            &[fixture_amd_milan_crl()],
        )
        .expect("fixture report signature and certificate chain should verify");
        let evidence = TeeEvidence {
            kind: "azure-hcl-report".to_string(),
            report: URL_SAFE_NO_PAD.encode(snp_report),
            auxiliary: Some(URL_SAFE_NO_PAD.encode(b"HCL var_data")),
        };
        let collateral = AmdSnpVerificationCollateral::from_certificate_table(
            &cert_table,
            vec![fixture_amd_milan_crl()],
        )
        .expect("AMD SNP verification collateral");
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();

        verify_azure_snp_vendor_report(
            &mut report,
            &mut errors,
            Some(&evidence),
            Some(&collateral),
            AmdSnpTrust {
                ark_roots: &[ark],
                ark_root_hashes: &[],
            },
            snp_fixture_time(),
        );

        assert!(errors.is_empty(), "{errors:?}");
        assert!(report.checks.iter().any(|check| {
            check.name == "azure-tee-vendor-report" && check.result == CheckResult::Pass
        }));
    }

    #[test]
    fn vendor_policy_permits_gcp_snp_debug_for_measurement_policy_evaluation() {
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SNP_REPORT_VERSION_OFFSET..SNP_REPORT_VERSION_OFFSET + 4]
            .copy_from_slice(&3u32.to_le_bytes());
        let policy = (1u64 << 17) | SNP_POLICY_DEBUG;
        report[SNP_REPORT_POLICY_OFFSET..SNP_REPORT_POLICY_OFFSET + 8]
            .copy_from_slice(&policy.to_le_bytes());

        verify_snp_report_policy(&report)
            .expect("SNP DEBUG must reach verified TEE attribute policy evaluation");
    }

    #[test]
    fn vendor_policy_permits_gcp_snp_migrate_ma_for_measurement_policy_evaluation() {
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SNP_REPORT_VERSION_OFFSET..SNP_REPORT_VERSION_OFFSET + 4]
            .copy_from_slice(&3u32.to_le_bytes());
        let policy = (1u64 << 17) | SNP_POLICY_MIGRATE_MA;
        report[SNP_REPORT_POLICY_OFFSET..SNP_REPORT_POLICY_OFFSET + 8]
            .copy_from_slice(&policy.to_le_bytes());

        verify_snp_report_policy(&report)
            .expect("SNP MIGRATE_MA must reach verified TEE attribute policy evaluation");
    }

    #[test]
    fn rejects_gcp_snp_report_from_nonzero_vmpl() {
        let (mut report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        report[SNP_REPORT_VMPL_OFFSET..SNP_REPORT_VMPL_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());

        let error = verify_snp_report_with_aux_certs(
            snp_fixture_time(),
            &report,
            &auxblob,
            &[ark],
            &[],
            &[fixture_amd_milan_crl()],
        )
        .unwrap_err();
        assert!(error.contains("VMPL"), "{error}");
    }

    #[test]
    fn rejects_unsupported_gcp_snp_report_version() {
        let (mut report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        report[SNP_REPORT_VERSION_OFFSET..SNP_REPORT_VERSION_OFFSET + 4]
            .copy_from_slice(&6u32.to_le_bytes());

        let error = verify_snp_report_with_aux_certs(
            snp_fixture_time(),
            &report,
            &auxblob,
            &[ark],
            &[],
            &[fixture_amd_milan_crl()],
        )
        .unwrap_err();
        assert!(
            error.contains("unsupported SNP report version 6"),
            "{error}"
        );
    }

    #[test]
    fn rejects_gcp_snp_report_version_two() {
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SNP_REPORT_VERSION_OFFSET..SNP_REPORT_VERSION_OFFSET + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        report[SNP_REPORT_POLICY_OFFSET..SNP_REPORT_POLICY_OFFSET + 8]
            .copy_from_slice(&(1u64 << 17).to_le_bytes());

        let error = verify_snp_report_policy(&report).unwrap_err();
        assert!(
            error.contains("unsupported SNP report version 2"),
            "{error}"
        );
    }

    #[test]
    fn rejects_gcp_snp_report_without_amd_crl() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let error = verify_snp_report_with_aux_certs(
            snp_fixture_time(),
            &report,
            &auxblob,
            &[ark],
            &[],
            &[],
        )
        .unwrap_err();
        assert!(error.contains("revocation list"), "{error}");
    }

    #[test]
    fn rejects_gcp_snp_report_with_stale_amd_crl() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let after_crl_expiry = UNIX_EPOCH + std::time::Duration::from_secs(1_786_233_600);
        let error = verify_snp_report_with_aux_certs(
            after_crl_expiry,
            &report,
            &auxblob,
            &[ark],
            &[],
            &[fixture_amd_milan_crl()],
        )
        .unwrap_err();
        assert!(error.contains("CRL is stale"), "{error}");
    }

    #[test]
    fn rejects_gcp_snp_report_with_tampered_amd_crl() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let mut crl = fixture_amd_milan_crl();
        *crl.last_mut().unwrap() ^= 1;
        let error = verify_snp_report_with_aux_certs(
            snp_fixture_time(),
            &report,
            &auxblob,
            &[ark],
            &[],
            &[crl],
        )
        .unwrap_err();
        assert!(error.contains("CRL signature"), "{error}");
    }

    #[test]
    fn rejects_gcp_snp_report_with_expired_vek_certificate() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let after_vek_expiry = UNIX_EPOCH + std::time::Duration::from_secs(2_050_000_000);
        let error = verify_snp_report_with_aux_certs(
            after_vek_expiry,
            &report,
            &auxblob,
            &[ark],
            &[],
            &[fixture_amd_milan_crl()],
        )
        .unwrap_err();
        assert!(
            error.contains("SNP VEK certificate is not valid"),
            "{error}"
        );
    }

    #[test]
    fn required_snp_vek_extension_cannot_be_absent() {
        let (_, _, auxblob) = fixture_gcp_snp_report_and_certs();
        let certs = parse_amd_snp_cert_table(&auxblob).unwrap();
        let (_, vcek) = X509Certificate::from_der(certs.vcek.as_deref().unwrap()).unwrap();
        let error = check_snp_tcb_extension(&vcek, "1.2.3.4.5", 0, "test").unwrap_err();
        assert!(error.contains("missing required test extension"), "{error}");
    }

    #[test]
    fn verifier_accepts_gcp_snp_fixture_with_ff_report_id_ma_absence_sentinel() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let (response, gcp_roots, amd_ark) = gcp_snp_response_roots_and_ark(nonce, cert);
        let certificate_table = URL_SAFE_NO_PAD
            .decode(
                response
                    .tee_evidence
                    .as_ref()
                    .and_then(|evidence| evidence.auxiliary.as_deref())
                    .expect("GCP SNP auxiliary certificate table"),
            )
            .expect("base64url certificate table");
        let amd_snp_collateral = AmdSnpVerificationCollateral::from_certificate_table(
            &certificate_table,
            vec![fixture_amd_milan_crl()],
        )
        .expect("AMD SNP verification collateral");

        verify_tls_attestation_at(
            VerificationInputs {
                nonce,
                live_peer_cert_der: cert.to_vec(),
                response,
                intel_tdx_dcap_collateral: None,
                amd_snp_collateral: Some(amd_snp_collateral),
                measurement_policy: Some(measurement_policy_for_platform(
                    &pcr,
                    "gcp",
                    "sev-snp",
                    "n2d-standard-4",
                )),
                trust_anchors: TrustAnchors {
                    gcp_roots,
                    amd_ark_roots: vec![amd_ark],
                    amd_snp_security_policies: vec![AmdSnpSecurityPolicy {
                        cpuid: 0x190101,
                        minimum_tcb: [0; 32],
                        platform_info_policy: [0; 32],
                        required_launch_mitigation_vector: 0,
                        required_current_mitigation_vector: 0,
                    }],
                    ..TrustAnchors::default()
                },
            },
            snp_fixture_time(),
        )
        .expect("all-0xff SNP REPORT_ID_MA must mean no migration-agent association");
    }

    #[test]
    fn rejects_gcp_snp_vendor_report_without_trusted_ark() {
        let (report, _, auxblob) = fixture_gcp_snp_report_and_certs();
        let err =
            verify_snp_report_with_aux_certs(snp_fixture_time(), &report, &auxblob, &[], &[], &[])
                .expect_err("missing trusted ARK root must fail closed");

        assert!(err.contains("trusted AMD ARK roots"), "{err}");
    }

    #[test]
    fn rejects_gcp_snp_vendor_report_signature_tamper() {
        let (report, ark, auxblob) = fixture_gcp_snp_report_and_certs();
        let mut tampered = report.to_vec();
        tampered[16] ^= 0x01;
        let crl = fixture_amd_milan_crl();

        let err = verify_snp_report_with_aux_certs(
            snp_fixture_time(),
            &tampered,
            &auxblob,
            &[ark.to_vec()],
            &[],
            &[crl],
        )
        .expect_err("tampered SNP report must fail signature verification");

        assert!(err.contains("signature"), "{err}");
    }

    #[test]
    fn base_image_id_matches_existing_vector() {
        assert_eq!(
            hex0x(&compute_base_image_id(
                &TEST_PUBLISHER,
                "test-image",
                "v1.0.0"
            )),
            "0x7a66632ee498e2b70e9d9a39f6c42f2d3e044cbff702f43d0d18c4df69a63f39"
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
        assert_check_passed(&failure, "pcr-sha256-4");
    }

    #[test]
    fn verifier_enforces_tdx_debug_against_effective_measurement_attributes() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let (mut response, gcp_roots) = gcp_response_and_roots(nonce, cert);
        let evidence = response.tee_evidence.as_mut().expect("TEE evidence");
        let mut quote = URL_SAFE_NO_PAD.decode(&evidence.report).unwrap();
        let report_start = tdx_quote_report_start(&quote).unwrap();
        quote[report_start + TDX_REPORT_ATTRIBUTES_OFFSET] = 1;
        evidence.report = URL_SAFE_NO_PAD.encode(quote);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response: response.clone(),
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy(&pcr)),
            trust_anchors: TrustAnchors {
                gcp_roots: gcp_roots.clone(),
                ..TrustAnchors::default()
            },
        })
        .expect_err("missing Intel TDX debug declaration must fail");
        let check_name = format!(
            "tee-attribute-base-image-{}",
            atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME
        );
        assert!(failure.errors.iter().any(|error| error.check == check_name));

        let mut policy = measurement_policy(&pcr);
        policy.pack.profiles_mut()[0].attributes = vec![serde_json::json!({
            "name": atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME,
            "value": false,
        })];
        policy.pack.profiles_mut()[0].variants[0].attributes = vec![serde_json::json!({
            "name": atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME,
            "value": true,
        })];
        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response: response.clone(),
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy.clone()),
            trust_anchors: TrustAnchors {
                gcp_roots: gcp_roots.clone(),
                ..TrustAnchors::default()
            },
        })
        .expect_err("fixture still lacks TDX DCAP collateral");
        assert!(!failure.errors.iter().any(|error| error.check == check_name));
        assert_check_passed(&failure, &check_name);

        let workload_check_name = format!(
            "tee-attribute-workload-{}",
            atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME
        );
        let failure = verify_tls_attestation_with_workload_attributes(
            VerificationInputs {
                nonce,
                live_peer_cert_der: cert.to_vec(),
                response: response.clone(),
                intel_tdx_dcap_collateral: None,
                amd_snp_collateral: None,
                measurement_policy: Some(policy.clone()),
                trust_anchors: TrustAnchors {
                    gcp_roots: gcp_roots.clone(),
                    ..TrustAnchors::default()
                },
            },
            &BTreeMap::new(),
        )
        .expect_err("missing workload requirement must reject Intel TDX debug");
        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == workload_check_name));

        let allowed = BTreeMap::from([(
            atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME.to_string(),
            vec![
                atakit_core::tee_attributes::AttributeValue::Boolean(false),
                atakit_core::tee_attributes::AttributeValue::Boolean(true),
            ],
        )]);
        let failure = verify_tls_attestation_with_workload_attributes(
            VerificationInputs {
                nonce,
                live_peer_cert_der: cert.to_vec(),
                response: response.clone(),
                intel_tdx_dcap_collateral: None,
                amd_snp_collateral: None,
                measurement_policy: Some(policy.clone()),
                trust_anchors: TrustAnchors {
                    gcp_roots: gcp_roots.clone(),
                    ..TrustAnchors::default()
                },
            },
            &allowed,
        )
        .expect_err("fixture still lacks TDX DCAP collateral");
        assert!(!failure
            .errors
            .iter()
            .any(|error| error.check == workload_check_name));
        assert_check_passed(&failure, &workload_check_name);

        let malformed = BTreeMap::from([(
            atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME.to_string(),
            vec![atakit_core::tee_attributes::AttributeValue::Boolean(true)],
        )]);
        let failure = verify_tls_attestation_with_workload_attributes(
            VerificationInputs {
                nonce,
                live_peer_cert_der: cert.to_vec(),
                response,
                intel_tdx_dcap_collateral: None,
                amd_snp_collateral: None,
                measurement_policy: Some(policy),
                trust_anchors: TrustAnchors {
                    gcp_roots,
                    ..TrustAnchors::default()
                },
            },
            &malformed,
        )
        .expect_err("malformed workload requirement must fail");
        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "workload-attributes"));
    }

    #[test]
    fn verifier_enforces_snp_states_against_effective_measurement_attributes() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let (mut response, gcp_roots) = gcp_response_and_roots(nonce, cert);
        response.platform.tee = "sev-snp".to_string();
        response.platform.machine_type = "n2d-standard-4".to_string();
        let snp_report =
            synthetic_snp_security_report((1u64 << 17) | SNP_POLICY_DEBUG | SNP_POLICY_MIGRATE_MA);
        response.tee_evidence = Some(TeeEvidence {
            kind: "configfs-tsm".to_string(),
            report: URL_SAFE_NO_PAD.encode(snp_report),
            auxiliary: None,
        });

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response: response.clone(),
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_platform(
                &pcr,
                "gcp",
                "sev-snp",
                "n2d-standard-4",
            )),
            trust_anchors: TrustAnchors {
                gcp_roots: gcp_roots.clone(),
                ..TrustAnchors::default()
            },
        })
        .expect_err("missing AMD SEV-SNP declarations must fail");
        for name in [
            atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME,
            atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME,
        ] {
            let check_name = format!("tee-attribute-base-image-{name}");
            assert!(failure.errors.iter().any(|error| error.check == check_name));
        }

        let mut policy = measurement_policy_for_platform(&pcr, "gcp", "sev-snp", "n2d-standard-4");
        for name in [
            atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME,
            atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME,
        ] {
            policy.pack.profiles_mut()[0]
                .attributes
                .push(serde_json::json!({"name": name, "value": false}));
            policy.pack.profiles_mut()[0].variants[0]
                .attributes
                .push(serde_json::json!({"name": name, "value": true}));
        }
        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response: response.clone(),
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy.clone()),
            trust_anchors: TrustAnchors {
                gcp_roots: gcp_roots.clone(),
                ..TrustAnchors::default()
            },
        })
        .expect_err("synthetic AMD SEV-SNP evidence lacks vendor certificates");
        for name in [
            atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME,
            atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME,
        ] {
            let check_name = format!("tee-attribute-base-image-{name}");
            assert!(!failure.errors.iter().any(|error| error.check == check_name));
            assert_check_passed(&failure, &check_name);
        }

        let failure = verify_tls_attestation_with_workload_attributes(
            VerificationInputs {
                nonce,
                live_peer_cert_der: cert.to_vec(),
                response: response.clone(),
                intel_tdx_dcap_collateral: None,
                amd_snp_collateral: None,
                measurement_policy: Some(policy.clone()),
                trust_anchors: TrustAnchors {
                    gcp_roots: gcp_roots.clone(),
                    ..TrustAnchors::default()
                },
            },
            &BTreeMap::new(),
        )
        .expect_err("missing workload requirements must reject enabled AMD SEV-SNP states");
        for name in [
            atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME,
            atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME,
        ] {
            let check_name = format!("tee-attribute-workload-{name}");
            assert!(failure.errors.iter().any(|error| error.check == check_name));
        }

        let allowed = BTreeMap::from([
            (
                atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME.to_string(),
                vec![
                    atakit_core::tee_attributes::AttributeValue::Boolean(false),
                    atakit_core::tee_attributes::AttributeValue::Boolean(true),
                ],
            ),
            (
                atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME.to_string(),
                vec![
                    atakit_core::tee_attributes::AttributeValue::Boolean(false),
                    atakit_core::tee_attributes::AttributeValue::Boolean(true),
                ],
            ),
        ]);
        let failure = verify_tls_attestation_with_workload_attributes(
            VerificationInputs {
                nonce,
                live_peer_cert_der: cert.to_vec(),
                response,
                intel_tdx_dcap_collateral: None,
                amd_snp_collateral: None,
                measurement_policy: Some(policy),
                trust_anchors: TrustAnchors {
                    gcp_roots,
                    ..TrustAnchors::default()
                },
            },
            &allowed,
        )
        .expect_err("synthetic AMD SEV-SNP evidence lacks vendor certificates");
        for name in [
            atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME,
            atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME,
        ] {
            let check_name = format!("tee-attribute-workload-{name}");
            assert!(!failure.errors.iter().any(|error| error.check == check_name));
            assert_check_passed(&failure, &check_name);
        }
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
    /// A profile invariant always holds. A variant that pins an index the profile already
    /// declares invariant must be rejected, not resolved in the variant's favour — on-chain
    /// registration rejects the same overlap, so accepting it here would let offline TLS
    /// verification and `registerSession` disagree about the same measurement pack.
    fn verifier_rejects_variant_pcr_that_pins_an_invariant() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let (response, gcp_roots) = gcp_response_and_roots(nonce, cert);
        // Invariant PCR4 is deliberately wrong; the variant tries to relax it to the value the
        // machine actually reports. Previously the override won and `pcr-4-static` passed.
        let mut policy = measurement_policy(&format!("0x{}", "bb".repeat(32)));
        policy.pack.profiles_mut()[0].variants[0]
            .variant_pcrs256
            .push(PcrSpec256 {
                pcr_index: 4,
                comparison: static_comparison256([0xaa; 32]),
            });

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors {
                gcp_roots,
                ..TrustAnchors::default()
            },
        })
        .expect_err("variant pinning an invariant PCR must fail closed");

        let overlap = failure
            .errors
            .iter()
            .find(|error| error.check == "measurement-pcrs-sha256")
            .expect("expected a measurement-pcrs failure");
        assert!(
            overlap.detail.contains("declares invariant"),
            "unexpected detail: {}",
            overlap.detail
        );
        // The relaxed spec must never have been evaluated.
        assert!(
            !failure
                .report
                .checks
                .iter()
                .any(|check| check.name == "pcr-sha256-4"),
            "the overriding spec was evaluated: {:?}",
            failure.report.checks
        );
    }

    #[test]
    fn effective_pcr_specs_rejects_variant_pinning_an_invariant() {
        let policy = measurement_policy(&format!("0x{}", "bb".repeat(32)));
        let profiles = policy.pack.profiles();
        let profile = &profiles[0];
        let mut variant = profile.variants[0].clone();
        variant.variant_pcrs256.push(PcrSpec256 {
            pcr_index: 4,
            comparison: static_comparison256([0xaa; 32]),
        });

        let error = effective_pcr_specs256(profile, &variant)
            .expect_err("overlap with a profile invariant must be rejected");
        assert!(error.contains("declares invariant"), "unexpected: {error}");
    }

    #[test]
    fn effective_pcr_specs_allows_disjoint_variant() {
        let policy = measurement_policy(&format!("0x{}", "bb".repeat(32)));
        let profiles = policy.pack.profiles();
        let profile = &profiles[0];
        let mut variant = profile.variants[0].clone();
        variant.variant_pcrs256.push(PcrSpec256 {
            pcr_index: 10,
            comparison: static_comparison256([0xcc; 32]),
        });

        let specs = effective_pcr_specs256(profile, &variant).expect("disjoint variant is allowed");
        let indices: Vec<u8> = specs.iter().map(|spec| spec.pcr_index).collect();
        assert_eq!(indices, vec![4, 10]);
    }

    #[test]
    fn verifier_rejects_noncanonical_static_comparison() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let (response, gcp_roots) = gcp_response_and_roots(nonce, cert);
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        policy.pack.profiles_mut()[0].invariant_pcrs256[0]
            .comparison
            .push_str("00");

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors {
                gcp_roots,
                ..TrustAnchors::default()
            },
        })
        .expect_err("a non-canonical STATIC comparison must fail closed");

        let check = failure
            .errors
            .iter()
            .find(|error| error.check == "pcr-sha256-4")
            .expect("expected PCR4 failure");
        assert!(
            check
                .detail
                .contains("PCR comparison is not canonically ABI encoded"),
            "unexpected detail: {}",
            check.detail
        );
    }

    #[test]
    fn verifier_rejects_ambiguous_measurement_profile() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        let mut duplicate = policy.pack.profiles_mut()[0].clone();
        duplicate.name = "gcp-tdx-duplicate".to_string();
        duplicate.id = hex0x(&compute_platform_profile_id(
            &compute_base_image_id(&TEST_PUBLISHER, "base", "v1"),
            &duplicate.name,
        ));
        policy.pack.profiles_mut().push(duplicate);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
        let profile_id = compute_platform_profile_id(
            &compute_base_image_id(&TEST_PUBLISHER, "base", "v1"),
            "gcp-tdx",
        );
        let mut duplicate = policy.pack.profiles_mut()[0].variants[0].clone();
        duplicate.name = "c3-standard-4-duplicate".to_string();
        duplicate.id = hex0x(&compute_variant_id(&profile_id, &duplicate.name));
        policy.pack.profiles_mut()[0].variants.push(duplicate);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
        policy.pack.profiles_mut()[0].variants[0]
            .machine_types
            .clear();

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
        policy.pack.profiles_mut()[0].invariant_pcrs256.clear();

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("empty PCR policy should fail closed");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "measurement-pcrs-sha256"));
    }

    #[test]
    fn verifier_rejects_dynamic_pcr_without_event_log() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        policy.pack.profiles_mut()[0].invariant_pcrs256[0].comparison =
            dynamic_comparison256(DYNAMIC_SUBSET, vec![[0xaa; 32]]);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("dynamic PCR without an event log should fail closed");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "pcr-sha256-4"
                && error.detail.contains("measured event log is empty")));
    }

    #[test]
    fn verifier_decodes_dynamic_subsequence_comparison() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        policy.pack.profiles_mut()[0].invariant_pcrs256[0].comparison =
            dynamic_comparison256(DYNAMIC_SUBSEQUENCE, vec![[0xaa; 32]]);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("dynamic PCR without an event log should fail closed");

        assert!(failure.errors.iter().any(|error| {
            error.check == "pcr-sha256-4" && error.detail.contains("measured event log is empty")
        }));
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy(&format!("0x{}", "aa".repeat(32)))),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("PCR mismatch should fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "pcr-sha256-4"));
    }

    #[test]
    fn verifier_rejects_measurement_pack_id_mismatch() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "gcp");
        let mut policy = measurement_policy(&format!("0x{}", "aa".repeat(32)));
        policy.pack.profiles_mut()[0].variants[0].id = format!("0x{}", "44".repeat(32));

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
    fn verifier_does_not_use_unselected_sha384_for_static_policy() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "gcp");
        response.tpm.pcrs[0].sha384 = Some(format!("0x{}", "bb".repeat(48)));

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy(&format!("0x{}", "bb".repeat(32)))),
            trust_anchors: TrustAnchors::default(),
        })
        .expect_err("an unquoted SHA-384 PCR value must not satisfy static policy");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "pcr-sha256-4"));
        assert_check_passed(&failure, "tpm-quote-pcr-digest");
    }

    #[test]
    fn verifier_authenticates_sha384_only_quote_selection() {
        let qualifying_data = [0x11; 32];
        let sha384 = [0x44; 48];
        let quote = fake_tpm_quote_banks(&qualifying_data, &[], &[(4, sha384)]);
        let evidence = vec![PcrEvidence {
            index: 4,
            sha256: Some(format!("0x{}", "aa".repeat(32))),
            sha384: Some(hex0x(&sha384)),
        }];
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();

        let authenticated = verify_tpm_quote(
            &mut report,
            &mut errors,
            &quote,
            &qualifying_data,
            &evidence,
        )
        .expect("SHA-384 selection should authenticate");
        assert!(errors.is_empty(), "{errors:?}");
        let expected_sha384 = hex0x(&sha384);
        assert_eq!(authenticated[0].sha256, None);
        assert_eq!(
            authenticated[0].sha384.as_deref(),
            Some(expected_sha384.as_str())
        );

        verify_pcr_spec384(
            &mut report,
            &mut errors,
            &PcrSpec384 {
                pcr_index: 4,
                comparison: static_comparison384(sha384),
            },
            &authenticated,
            &[],
            0,
        );
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn verifier_authenticates_sha256_and_sha384_quote_selections_together() {
        let qualifying_data = [0x22; 32];
        let sha256 = [0x33; 32];
        let sha384 = [0x44; 48];
        let quote = fake_tpm_quote_banks(&qualifying_data, &[(4, sha256)], &[(4, sha384)]);
        let evidence = vec![PcrEvidence {
            index: 4,
            sha256: Some(hex0x(&sha256)),
            sha384: Some(hex0x(&sha384)),
        }];
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();

        let authenticated = verify_tpm_quote(
            &mut report,
            &mut errors,
            &quote,
            &qualifying_data,
            &evidence,
        )
        .expect("both selected banks should authenticate");
        assert!(errors.is_empty(), "{errors:?}");
        let expected_sha256 = hex0x(&sha256);
        let expected_sha384 = hex0x(&sha384);
        assert_eq!(
            authenticated[0].sha256.as_deref(),
            Some(expected_sha256.as_str())
        );
        assert_eq!(
            authenticated[0].sha384.as_deref(),
            Some(expected_sha384.as_str())
        );
    }

    #[test]
    fn verifier_rejects_sha384_before_sha256() {
        let qualifying_data = [0x22; 32];
        let sha256 = [0x33; 32];
        let sha384 = [0x44; 48];
        let quote =
            fake_tpm_quote_banks_with_order(&qualifying_data, &[(4, sha256)], &[(4, sha384)], true);
        let evidence = vec![PcrEvidence {
            index: 4,
            sha256: Some(hex0x(&sha256)),
            sha384: Some(hex0x(&sha384)),
        }];
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();

        assert!(verify_tpm_quote(
            &mut report,
            &mut errors,
            &quote,
            &qualifying_data,
            &evidence,
        )
        .is_none());
        assert!(errors.iter().any(|error| {
            error.check == "tpm-quote-pcr-selection"
                && error.detail.contains("SHA-256 before SHA-384")
        }));
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
    fn verifier_authenticates_azure_hclak_before_rejecting_unverified_tdx_report() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "azure");
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, signature, trusted_maa_key) = fake_azure_ak_binding_and_signature(&quote);
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.ak_binding = Some(binding);
        bind_azure_tdx_evidence_to_ak_binding(&mut response);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key)],
                ..TrustAnchors::default()
            },
        })
        .expect_err("Azure TDX report without DCAP collateral must fail");

        for check in [
            "azure-maa-jwt",
            "tpm-quote-signature",
            "azure-tee-ak-binding",
            "azure-tee-var-data-binding",
        ] {
            assert_check_passed(&failure, check);
        }
        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "azure-tee-vendor-report"));
    }

    #[test]
    fn verifier_rejects_azure_tdx_report_not_bound_to_hcl_data() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "azure");
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, signature, trusted_maa_key) = fake_azure_ak_binding_and_signature(&quote);
        let binding_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&binding.data).unwrap()).unwrap();
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.tee_evidence.as_mut().unwrap().auxiliary =
            Some(binding_json["hclVarData"].as_str().unwrap().to_string());
        response.ak_binding = Some(binding);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key)],
                ..TrustAnchors::default()
            },
        })
        .expect_err("Azure TDX report_data that does not bind HCL var_data must fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "azure-tee-var-data-binding"));
    }

    #[test]
    fn verifier_rejects_azure_tee_auxiliary_different_from_ak_binding() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "azure");
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, signature, trusted_maa_key) = fake_azure_ak_binding_and_signature(&quote);
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.ak_binding = Some(binding);
        bind_azure_tdx_evidence_to_ak_binding(&mut response);
        response.tee_evidence.as_mut().unwrap().auxiliary =
            Some(URL_SAFE_NO_PAD.encode(b"different HCL var_data"));

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key)],
                ..TrustAnchors::default()
            },
        })
        .expect_err("Azure TEE auxiliary data that differs from the MAA binding must fail");

        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "azure-tee-ak-binding"));
    }

    #[test]
    fn verifier_rejects_azure_snp_report_without_vendor_certificates() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let mut response = response_for(nonce, cert, "azure");
        response.platform.tee = "sev-snp".to_string();
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, signature, trusted_maa_key) =
            fake_azure_ak_binding_and_signature_for_tee(&quote, "sev-snp");
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.ak_binding = Some(binding);
        bind_azure_snp_evidence_to_ak_binding(&mut response);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key)],
                ..TrustAnchors::default()
            },
        })
        .expect_err("Azure SNP report without a certificate table must fail");

        for check in [
            "azure-maa-jwt",
            "tpm-quote-signature",
            "azure-tee-ak-binding",
            "azure-tee-var-data-binding",
        ] {
            assert_check_passed(&failure, check);
        }
        assert!(failure.errors.iter().any(|error| {
            error.check == "azure-tee-vendor-report"
                && error
                    .detail
                    .contains("Azure SNP verification collateral is missing")
        }));
    }

    #[test]
    fn verifier_enforces_azure_tdx_debug_against_effective_measurement_attributes() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let mut response = response_for(nonce, cert, "azure");
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, signature, trusted_maa_key) = fake_azure_ak_binding_and_signature(&quote);
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.ak_binding = Some(binding);
        bind_azure_tdx_evidence_to_ak_binding(&mut response);
        let evidence = response.tee_evidence.as_mut().expect("Azure TDX evidence");
        let mut tee_quote = URL_SAFE_NO_PAD.decode(&evidence.report).unwrap();
        let report_start = tdx_quote_report_start(&tee_quote).expect("TDX quote body");
        tee_quote[report_start + TDX_REPORT_ATTRIBUTES_OFFSET] |= 1;
        evidence.report = URL_SAFE_NO_PAD.encode(tee_quote);
        let check_name = format!(
            "tee-attribute-base-image-{}",
            atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME
        );

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response: response.clone(),
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_cloud(&pcr, "azure")),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key.clone())],
                ..TrustAnchors::default()
            },
        })
        .expect_err("missing Azure Intel TDX debug declaration must fail");
        assert!(failure.errors.iter().any(|error| error.check == check_name));

        let mut policy = measurement_policy_for_cloud(&pcr, "azure");
        policy.pack.profiles_mut()[0].attributes = vec![serde_json::json!({
            "name": atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME,
            "value": false,
        })];
        policy.pack.profiles_mut()[0].variants[0].attributes = vec![serde_json::json!({
            "name": atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME,
            "value": true,
        })];
        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key)],
                ..TrustAnchors::default()
            },
        })
        .expect_err("synthetic Azure Intel TDX evidence lacks DCAP collateral");
        assert!(!failure.errors.iter().any(|error| error.check == check_name));
        assert_check_passed(&failure, &check_name);
    }

    #[test]
    fn tls_policy_enforces_verified_tdx_tcb_status_masks() {
        let nonce = [1u8; 32];
        let response = response_for(nonce, b"cert", "gcp");
        let evidence = response.tee_evidence.as_ref().expect("GCP TDX evidence");
        let mut policy = measurement_policy_for_cloud(&format!("0x{}", "aa".repeat(32)), "gcp");
        let snapshot = policy.pack.profiles();
        let profile = &snapshot[0];
        let variant = &profile.variants[0];
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();
        verify_measurement_attributes(
            &mut report,
            &mut errors,
            profile,
            variant,
            "tdx",
            Some(evidence),
            Some(0x8),
            None,
            &[],
        );
        assert!(errors
            .iter()
            .any(|error| { error.check == "tee-attribute-base-image-intel-tdx-tcb-status" }));
        assert!(!errors
            .iter()
            .any(|error| { error.check == "tee-attribute-workload-intel-tdx-tcb-status" }));

        {
            let mut profiles = policy.pack.profiles_mut();
            profiles[0].attributes = vec![serde_json::json!({
                "name": atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
                "value": ["ok"],
            })];
            profiles[0].variants[0].attributes = vec![serde_json::json!({
                "name": atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
                "value": ["ok", "configuration-needed"],
            })];
        }
        let requirements = BTreeMap::from([(
            atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_NAME.to_string(),
            vec![
                atakit_core::tee_attributes::AttributeValue::String("ok".to_string()),
                atakit_core::tee_attributes::AttributeValue::String(
                    "configuration-needed".to_string(),
                ),
            ],
        )]);
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let profiles_snapshot = policy.pack.profiles();
        let mut errors = Vec::new();
        verify_measurement_attributes(
            &mut report,
            &mut errors,
            &profiles_snapshot[0],
            &profiles_snapshot[0].variants[0],
            "tdx",
            Some(evidence),
            Some(0x8),
            Some(&requirements),
            &[],
        );
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn tdx_tcb_status_policy_rejects_malformed_present_masks() {
        let ok =
            atakit_core::tee_attributes::u16_value(atakit_core::tee_attributes::TDX_TCB_STATUS_OK);
        let configuration_needed = atakit_core::tee_attributes::u16_value(0x9);
        let missing_ok = atakit_core::tee_attributes::u16_value(0x8);
        let unsupported_bit = atakit_core::tee_attributes::u16_value(0x401);
        let mut exceeds_u16 = ok;
        exceeds_u16[0] = 1;

        assert!(tdx_tcb_status_policy_matches(
            None,
            atakit_core::tee_attributes::TDX_TCB_STATUS_OK
        ));
        assert!(!tdx_tcb_status_policy_matches(None, 0x8));
        assert!(tdx_tcb_status_policy_matches(
            Some(&configuration_needed),
            0x8
        ));
        assert!(!tdx_tcb_status_policy_matches(Some(&missing_ok), 0x8));
        assert!(!tdx_tcb_status_policy_matches(
            Some(&unsupported_bit),
            atakit_core::tee_attributes::TDX_TCB_STATUS_OK
        ));
        assert!(!tdx_tcb_status_policy_matches(
            Some(&exceeds_u16),
            atakit_core::tee_attributes::TDX_TCB_STATUS_OK
        ));
    }

    #[test]
    fn packed_workload_requirement_rejects_malformed_value_counts() {
        let key = [0x11; 32];
        let default_value = [0x22; 32];
        let explicit_value = [0x33; 32];

        assert_eq!(
            resolve_packed_workload_requirement(&BTreeMap::new(), key, default_value).unwrap(),
            default_value
        );
        assert_eq!(
            resolve_packed_workload_requirement(
                &BTreeMap::from([(key, vec![explicit_value])]),
                key,
                default_value,
            )
            .unwrap(),
            explicit_value
        );
        for values in [Vec::new(), vec![explicit_value, explicit_value]] {
            let error = resolve_packed_workload_requirement(
                &BTreeMap::from([(key, values)]),
                key,
                default_value,
            )
            .unwrap_err();
            assert!(error.contains("must contain exactly one value"), "{error}");
        }
    }

    #[test]
    fn tls_policy_uses_amd_snp_registry_defaults() {
        let mut snp_report = synthetic_snp_security_report(1u64 << 17);
        let raw_tcb = [4, 0, 0, 0, 0, 0, 29, 222];
        for offset in [
            SNP_REPORT_CURRENT_TCB_OFFSET,
            SNP_REPORT_REPORTED_TCB_OFFSET,
            SNP_REPORT_COMMITTED_TCB_OFFSET,
            SNP_REPORT_LAUNCH_TCB_OFFSET,
        ] {
            snp_report[offset..offset + 8].copy_from_slice(&raw_tcb);
        }
        snp_report[SNP_REPORT_PLATFORM_INFO_OFFSET..SNP_REPORT_PLATFORM_INFO_OFFSET + 8]
            .copy_from_slice(&0x20u64.to_le_bytes());
        let evidence = TeeEvidence {
            kind: "configfs-tsm".to_string(),
            report: URL_SAFE_NO_PAD.encode(snp_report),
            auxiliary: None,
        };
        let mut policy = measurement_policy_for_platform(
            &format!("0x{}", "aa".repeat(32)),
            "gcp",
            "sev-snp",
            "n2d-standard-4",
        );
        let minimum_tcb = atakit_core::tee_attributes::parse_bytes32_hex(
            "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
        )
        .unwrap();
        let platform_info_policy = atakit_core::tee_attributes::parse_bytes32_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000020",
        )
        .unwrap();
        let registry_default = AmdSnpSecurityPolicy {
            cpuid: 0x190000,
            minimum_tcb,
            platform_info_policy,
            required_launch_mitigation_vector: 0,
            required_current_mitigation_vector: 0,
        };
        policy.pack.profiles_mut()[0].attributes = vec![
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_NAME,
                "value": "0x00000000df1e000500000000de1d000400000000de1d000400000000de1d0004",
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
                "value": "0x0000000000000000000000000000000000000000000000200000000000000000",
            }),
        ];
        policy.pack.profiles_mut()[0].variants[0].attributes = vec![
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_NAME,
                "value": "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
                "value": "0x0000000000000000000000000000000000000000000000000000000000000020",
            }),
        ];

        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let profiles_snapshot = policy.pack.profiles();
        let mut errors = Vec::new();
        verify_measurement_attributes(
            &mut report,
            &mut errors,
            &profiles_snapshot[0],
            &profiles_snapshot[0].variants[0],
            "sev-snp",
            Some(&evidence),
            None,
            None,
            &[registry_default],
        );
        assert!(errors.is_empty(), "{errors:?}");

        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let profiles_snapshot = policy.pack.profiles();
        let mut errors = Vec::new();
        verify_measurement_attributes(
            &mut report,
            &mut errors,
            &profiles_snapshot[0],
            &profiles_snapshot[0].variants[0],
            "sev-snp",
            Some(&evidence),
            None,
            None,
            &[],
        );
        assert!(errors
            .iter()
            .any(|error| error.check == "amd-sev-snp-registry-default"));
    }

    #[test]
    fn tls_policy_allows_amd_snp_base_only_and_coordinated_relaxation() {
        let mut snp_report = synthetic_snp_security_report(1u64 << 17);
        let lower_raw_tcb = [3, 0, 0, 0, 0, 0, 29, 222];
        for offset in [
            SNP_REPORT_CURRENT_TCB_OFFSET,
            SNP_REPORT_REPORTED_TCB_OFFSET,
            SNP_REPORT_COMMITTED_TCB_OFFSET,
            SNP_REPORT_LAUNCH_TCB_OFFSET,
        ] {
            snp_report[offset..offset + 8].copy_from_slice(&lower_raw_tcb);
        }
        snp_report[SNP_REPORT_PLATFORM_INFO_OFFSET..SNP_REPORT_PLATFORM_INFO_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        let evidence = TeeEvidence {
            kind: "configfs-tsm".to_string(),
            report: URL_SAFE_NO_PAD.encode(snp_report),
            auxiliary: None,
        };

        let lower_tcb = "0x00000000de1d000300000000de1d000300000000de1d000300000000de1d0003";
        let lower_platform = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let mut policy = measurement_policy_for_platform(
            &format!("0x{}", "aa".repeat(32)),
            "gcp",
            "sev-snp",
            "n2d-standard-4",
        );
        policy.pack.profiles_mut()[0].variants[0].attributes = vec![
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_NAME,
                "value": lower_tcb,
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
                "value": lower_platform,
            }),
        ];
        let registry_default = AmdSnpSecurityPolicy {
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
        };

        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let profiles_snapshot = policy.pack.profiles();
        let mut errors = Vec::new();
        verify_measurement_attributes(
            &mut report,
            &mut errors,
            &profiles_snapshot[0],
            &profiles_snapshot[0].variants[0],
            "sev-snp",
            Some(&evidence),
            None,
            None,
            std::slice::from_ref(&registry_default),
        );
        assert!(errors.is_empty(), "{errors:?}");

        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();
        let empty_workload = BTreeMap::new();
        verify_measurement_attributes(
            &mut report,
            &mut errors,
            &profiles_snapshot[0],
            &profiles_snapshot[0].variants[0],
            "sev-snp",
            Some(&evidence),
            None,
            Some(&empty_workload),
            std::slice::from_ref(&registry_default),
        );
        assert!(errors
            .iter()
            .any(|error| { error.check == "tee-attribute-workload-amd-sev-snp-tcb-minimum" }));
        assert!(errors.iter().any(|error| {
            error.check == "tee-attribute-workload-amd-sev-snp-platform-info-policy"
        }));

        let lower_workload = BTreeMap::from([
            (
                atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_NAME.to_string(),
                vec![atakit_core::tee_attributes::AttributeValue::String(
                    lower_tcb.to_string(),
                )],
            ),
            (
                atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME.to_string(),
                vec![atakit_core::tee_attributes::AttributeValue::String(
                    lower_platform.to_string(),
                )],
            ),
        ]);
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let profiles_snapshot = policy.pack.profiles();
        let mut errors = Vec::new();
        verify_measurement_attributes(
            &mut report,
            &mut errors,
            &profiles_snapshot[0],
            &profiles_snapshot[0].variants[0],
            "sev-snp",
            Some(&evidence),
            None,
            Some(&lower_workload),
            std::slice::from_ref(&registry_default),
        );
        assert!(errors.is_empty(), "{errors:?}");

        policy.pack.profiles_mut()[0].variants[0].attributes.clear();
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let profiles_snapshot = policy.pack.profiles();
        let mut errors = Vec::new();
        verify_measurement_attributes(
            &mut report,
            &mut errors,
            &profiles_snapshot[0],
            &profiles_snapshot[0].variants[0],
            "sev-snp",
            Some(&evidence),
            None,
            Some(&lower_workload),
            &[registry_default],
        );
        assert!(errors
            .iter()
            .any(|error| { error.check == "tee-attribute-base-image-amd-sev-snp-tcb-minimum" }));
        assert!(errors.iter().any(|error| {
            error.check == "tee-attribute-base-image-amd-sev-snp-platform-info-policy"
        }));
    }

    #[test]
    fn verifier_enforces_azure_snp_states_against_effective_measurement_attributes() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let pcr = format!("0x{}", "aa".repeat(32));
        let mut response = response_for(nonce, cert, "azure");
        response.platform.tee = "sev-snp".to_string();
        response.platform.machine_type = "n2d-standard-4".to_string();
        let quote = URL_SAFE_NO_PAD.decode(&response.tpm.quote).unwrap();
        let (binding, signature, trusted_maa_key) =
            fake_azure_ak_binding_and_signature_for_tee(&quote, "sev-snp");
        response.tpm.ak_public = String::new();
        response.tpm.signature = URL_SAFE_NO_PAD.encode(signature);
        response.ak_binding = Some(binding);
        bind_azure_snp_evidence_to_ak_binding(&mut response);
        let evidence = response.tee_evidence.as_mut().expect("Azure SNP evidence");
        let mut snp_report = URL_SAFE_NO_PAD.decode(&evidence.report).unwrap();
        snp_report[SNP_REPORT_POLICY_OFFSET..SNP_REPORT_POLICY_OFFSET + 8].copy_from_slice(
            &((1u64 << 17) | SNP_POLICY_DEBUG | SNP_POLICY_MIGRATE_MA).to_le_bytes(),
        );
        evidence.report = URL_SAFE_NO_PAD.encode(snp_report);

        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response: response.clone(),
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_platform(
                &pcr,
                "azure",
                "sev-snp",
                "n2d-standard-4",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key.clone())],
                ..TrustAnchors::default()
            },
        })
        .expect_err("missing Azure AMD SEV-SNP declarations must fail");
        for name in [
            atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME,
            atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME,
        ] {
            let check_name = format!("tee-attribute-base-image-{name}");
            assert!(failure.errors.iter().any(|error| error.check == check_name));
        }

        let mut policy =
            measurement_policy_for_platform(&pcr, "azure", "sev-snp", "n2d-standard-4");
        for name in [
            atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME,
            atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME,
        ] {
            policy.pack.profiles_mut()[0]
                .attributes
                .push(serde_json::json!({"name": name, "value": false}));
            policy.pack.profiles_mut()[0].variants[0]
                .attributes
                .push(serde_json::json!({"name": name, "value": true}));
        }
        let failure = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(policy),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key)],
                ..TrustAnchors::default()
            },
        })
        .expect_err("synthetic Azure AMD SEV-SNP evidence lacks vendor certificates");
        for name in [
            atakit_core::tee_attributes::AMD_SEV_SNP_DEBUG_NAME,
            atakit_core::tee_attributes::AMD_SEV_SNP_MIGRATE_MA_NAME,
        ] {
            let check_name = format!("tee-attribute-base-image-{name}");
            assert!(!failure.errors.iter().any(|error| error.check == check_name));
            assert_check_passed(&failure, &check_name);
        }
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
        let report_start = tdx_quote_report_start(&raw_tdx_quote).expect("TDX report start");
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
            SystemTime::now(),
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
            SystemTime::now(),
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
            SystemTime::now(),
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
    fn azure_maa_jwt_uses_verifier_selected_time() {
        let hcl_var_data = b"{\"keys\":[]}";
        let (jwt, trusted_key) = fake_azure_maa_jwt_with_times(hcl_var_data, "tdx", 100, 100, 200);
        let binding = AkBinding {
            kind: "azure-maa-jwt".into(),
            data: URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "jwt": jwt,
                    "hclVarData": URL_SAFE_NO_PAD.encode(hcl_var_data),
                }))
                .unwrap(),
            ),
        };

        for timestamp in [100, 199] {
            let mut report = VerificationReport {
                checks: Vec::new(),
                evidence: EvidenceSummary::default(),
            };
            let mut errors = Vec::new();
            verify_azure_maa_jwt_binding(
                &mut report,
                &mut errors,
                &binding,
                &[maa_cert(trusted_key.clone())],
                "tdx",
                UNIX_EPOCH + std::time::Duration::from_secs(timestamp),
            );
            assert!(errors.is_empty(), "timestamp {timestamp}: {errors:?}");
        }

        for (timestamp, expected) in [(99, "not valid before"), (200, "expired")] {
            let mut report = VerificationReport {
                checks: Vec::new(),
                evidence: EvidenceSummary::default(),
            };
            let mut errors = Vec::new();
            verify_azure_maa_jwt_binding(
                &mut report,
                &mut errors,
                &binding,
                &[maa_cert(trusted_key.clone())],
                "tdx",
                UNIX_EPOCH + std::time::Duration::from_secs(timestamp),
            );
            assert!(
                errors.iter().any(|error| error.detail.contains(expected)),
                "timestamp {timestamp}: {errors:?}"
            );
        }
    }

    #[test]
    fn azure_maa_jwt_rejects_future_issued_at_time() {
        let hcl_var_data = b"{\"keys\":[]}";
        let (jwt, trusted_key) = fake_azure_maa_jwt_with_times(hcl_var_data, "tdx", 151, 100, 200);
        let binding = AkBinding {
            kind: "azure-maa-jwt".into(),
            data: URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "jwt": jwt,
                    "hclVarData": URL_SAFE_NO_PAD.encode(hcl_var_data),
                }))
                .unwrap(),
            ),
        };
        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();

        verify_azure_maa_jwt_binding(
            &mut report,
            &mut errors,
            &binding,
            &[maa_cert(trusted_key.clone())],
            "tdx",
            UNIX_EPOCH + std::time::Duration::from_secs(150),
        );

        assert!(errors
            .iter()
            .any(|error| error.detail.contains("issued in the future")));
    }

    #[test]
    fn public_session_verifier_accepts_ff_report_id_ma_absence_sentinel() {
        use crate::session::{
            compute_key_fingerprint, compute_session_id, compute_session_qualifying_data,
            request_binding_digest, AkEvidence, BindingMode, CertificateTrust, RawEvidence,
            SessionAttestationMode, SessionBinding, SessionEventHashes, SessionEvidenceBundle,
            SessionKeyDelegation, SessionOwner, SessionPcrPolicy, SessionPcrValue, SessionPlatform,
            SessionPlatformTrust, SessionPolicy, SessionPublicKey, SessionRequestBinding,
            SessionTrust, SessionVerificationInputs, TpmCertifyEvidence, TpmQuoteEvidence,
            TrustedSessionPolicy,
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
            ak_signing_key.sign(tpms_attest_body(&quote).expect("Quote body"));
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
            ak_signing_key.sign(tpms_attest_body(&certify).expect("Certify body"));
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
        let (possession_signature, possession_recovery_id) = session_signing_key
            .sign_prehash_recoverable(&delegation_digest)
            .expect("session-key possession signature");
        let mut possession_signature = possession_signature.to_bytes().to_vec();
        possession_signature.push(possession_recovery_id.to_byte() + 27);

        let pcr4_policy = SessionPcrPolicy {
            pcr_index: 4,
            comparison: static_comparison256(pcr4),
        };
        let pcr15_policy = SessionPcrPolicy {
            pcr_index: 15,
            comparison: hex0x(
                &automata_tee_workload_measurement::pcr_comparison::encode_extend_from_zero256(
                    alloy::primitives::B256::from_slice(
                        &snp_report[SNP_REPORT_REPORT_ID_OFFSET..SNP_REPORT_REPORT_ID_OFFSET + 32],
                    ),
                ),
            ),
        };
        let bundle = SessionEvidenceBundle {
            format: 2,
            binding: SessionBinding {
                mode: BindingMode::Local,
                chain_id: 0,
                registry: hex0x(&registry),
                owner_nonce: hex0x(&owner_nonce),
                qualifying_data: hex0x(&qualifying_data),
            },
            platform: SessionPlatform {
                cloud: "gcp".into(),
                attestation_mode: SessionAttestationMode::Hardware,
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
                tpms_attest: URL_SAFE_NO_PAD.encode(&quote),
                tpm_signature: URL_SAFE_NO_PAD.encode(&quote_signature),
                signature_hash: hex0x(&quote_signature_hash),
                pcr0_startup_locality: 0,
            },
            tpm_certify: TpmCertifyEvidence {
                tpms_attest: URL_SAFE_NO_PAD.encode(&certify),
                tpm_signature: URL_SAFE_NO_PAD.encode(&certify_signature),
                tpmt_public: URL_SAFE_NO_PAD.encode(&tpmt_public),
            },
            pcr_values: vec![
                SessionPcrValue {
                    index: 4,
                    sha256: Some(hex0x(&pcr4)),
                    sha384: None,
                },
                SessionPcrValue {
                    index: 15,
                    sha256: Some(hex0x(&pcr15)),
                    sha384: None,
                },
            ],
            event_log_hashes: vec![
                SessionEventHashes {
                    pcr_index: 4,
                    sha256: Vec::new(),
                    sha384: Vec::new(),
                },
                SessionEventHashes {
                    pcr_index: 15,
                    sha256: Vec::new(),
                    sha384: Vec::new(),
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
                session_key_possession_signature: hex0x(&possession_signature),
            },
            session_id: hex0x(&session_id),
            policy: SessionPolicy {
                workload_id: hex0x(&workload_id),
                base_image_id: hex0x(&base_image_id),
                platform_profile_id: hex0x(&platform_profile_id),
                measurement_variant_id: hex0x(&measurement_variant_id),
                pcr_bank_selection: PcrBankSelection::Sha256,
                invariant_pcr_policy: SessionPcrPolicyBlock {
                    pcr_specs384: Vec::new(),
                    pcr_specs256: vec![pcr4_policy.clone()],
                },
                variant_pcr_policy: SessionPcrPolicyBlock::default(),
                workload_pcr_policy: SessionPcrPolicyBlock::default(),
                provider_pcr_policy: SessionPcrPolicyBlock {
                    pcr_specs384: Vec::new(),
                    pcr_specs256: vec![pcr15_policy],
                },
            },
            owner: SessionOwner {
                fingerprint: hex0x(&owner_fingerprint),
                contract_authorization: None,
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
        binding_signature.push(recovery_id.to_byte() + 27);

        let inputs = SessionVerificationInputs {
            bundle: serde_json::to_value(&bundle).unwrap(),
            request_binding: SessionRequestBinding {
                challenge: URL_SAFE_NO_PAD.encode(challenge),
                signature: hex0x(&binding_signature),
            },
            expected_challenge: challenge,
            trust: SessionTrust {
                platform: SessionPlatformTrust::GcpSnp {
                    gcp_ak_roots: CertificateTrust {
                        certificates: ak_roots,
                        hashes: Vec::new(),
                    },
                    amd_ark_roots: CertificateTrust {
                        certificates: vec![amd_ark],
                        hashes: Vec::new(),
                    },
                    amd_snp_collateral: AmdSnpVerificationCollateral::from_certificate_table(
                        &snp_cert_table,
                        vec![fixture_amd_milan_crl()],
                    )
                    .expect("AMD SNP verification collateral"),
                },
                policy: TrustedSessionPolicy {
                    workload_id,
                    base_image_id,
                    platform_profile_id,
                    measurement_variant_id,
                    pcr_bank_selection: PcrBankSelection::Sha256,
                    invariant_pcr_policy: SessionPcrPolicyBlock {
                        pcr_specs384: Vec::new(),
                        pcr_specs256: vec![pcr4_policy],
                    },
                    variant_pcr_policy: SessionPcrPolicyBlock::default(),
                    workload_pcr_policy: SessionPcrPolicyBlock::default(),
                    provider_pcr_policy: SessionPcrPolicyBlock::default(),
                    effective_attributes: Vec::new(),
                    attribute_requirements: Vec::new(),
                    amd_snp_security_policies: vec![AmdSnpSecurityPolicy {
                        cpuid: 0x190101,
                        minimum_tcb: [0; 32],
                        platform_info_policy: [0; 32],
                        required_launch_mitigation_vector: 0,
                        required_current_mitigation_vector: 0,
                    }],
                },
                binding: None,
            },
        };
        crate::session::verify_session_bundle_at(inputs.clone(), snp_fixture_time())
            .expect("all-0xff SNP REPORT_ID_MA must mean no migration-agent association");

        let mut no_possession = inputs.clone();
        no_possession.bundle["session_key_delegation"]["session_key_possession_signature"] =
            serde_json::json!("0x");
        let failure = crate::session::verify_session_bundle_at(no_possession, snp_fixture_time())
            .expect_err("the session key must prove possession of its private key");
        assert!(failure
            .errors
            .iter()
            .any(|error| error.contains("session-key-possession-signature")));

        let mut replayed = inputs.clone();
        replayed.expected_challenge = [0x56; 32];
        let failure = crate::session::verify_session_bundle_at(replayed, snp_fixture_time())
            .expect_err("a binding for an old challenge must not verify");
        assert!(failure
            .errors
            .iter()
            .any(|error| error.contains("request-challenge")));

        let mut mislabeled = inputs.clone();
        mislabeled.bundle["platform"]["attestation_mode"] = serde_json::json!("emulation");
        let failure = crate::session::verify_session_bundle_at(mislabeled, snp_fixture_time())
            .expect_err("emulation classification must not enter the production verifier");
        assert!(failure
            .errors
            .iter()
            .any(|error| error.contains("attestation_mode=hardware")));

        let mut untrusted = inputs;
        let SessionPlatformTrust::GcpSnp {
            gcp_ak_roots,
            amd_ark_roots,
            ..
        } = &mut untrusted.trust.platform
        else {
            unreachable!("test selected GCP SNP trust")
        };
        gcp_ak_roots.certificates.clear();
        amd_ark_roots.certificates.clear();
        let failure = crate::session::verify_session_bundle_at(untrusted, snp_fixture_time())
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(trusted_maa_key)],
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: Some(measurement_policy_for_cloud(
                &format!("0x{}", "aa".repeat(32)),
                "azure",
            )),
            trust_anchors: TrustAnchors {
                azure_maa_keys: vec![maa_cert(bad_trusted_maa_key)],
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: None,
            trust_anchors: TrustAnchors::default(),
        });
        let failure = result.unwrap_err();
        assert!(failure.errors.iter().any(|e| e.check == "nonce"));
        assert!(failure.errors.iter().any(|e| e.check == "live-cert-hash"));
    }

    #[test]
    fn verifier_enters_aws_nitrotpm_verification() {
        let nonce = [1u8; 32];
        let cert = b"cert";
        let response = response_for(nonce, cert, "aws");
        let result = verify_tls_attestation(VerificationInputs {
            nonce,
            live_peer_cert_der: cert.to_vec(),
            response,
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
            measurement_policy: None,
            trust_anchors: TrustAnchors::default(),
        });
        let failure = result.unwrap_err();
        assert!(failure
            .report
            .checks
            .iter()
            .any(|check| check.name == "platform-supported" && check.result == CheckResult::Pass));
        assert!(failure
            .errors
            .iter()
            .any(|error| error.check == "aws-nitrotpm-binding"));
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
            intel_tdx_dcap_collateral: None,
            amd_snp_collateral: None,
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
          "schema":"atakit.base_image_measurement_pack.v4",
          "revision":1,
          "published_at":1786000000,
          "subject":{"name":"automata-linux","version":"v0.5.0","id":"0x00","publisher":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
          "measurements":{"profiles":[]}
        }"#;
        let pack = parse_measurement_pack(bytes).unwrap();
        assert_eq!(pack.schema, BASE_IMAGE_MEASUREMENT_PACK_SCHEMA);
        assert_eq!(pack.subject.name, "automata-linux");
    }

    #[test]
    fn parse_measurement_pack_rejects_version_1() {
        let bytes = br#"{"measurements":{"profiles":[]},"published_at":1786000000,"revision":1,"schema":"atakit.measurement-pack.v1","subject":{"id":"0x00","name":"base","publisher":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"v1"}}"#;

        let err = parse_measurement_pack(bytes).unwrap_err();

        assert!(err
            .to_string()
            .contains("unsupported schema atakit.measurement-pack.v1"));
    }

    #[test]
    fn verify_measurement_pack_accepts_trusted_es256k_signature() {
        let bytes = br#"{"measurements":{"profiles":[]},"published_at":1786000000,"revision":1,"schema":"atakit.base_image_measurement_pack.v4","subject":{"id":"0x00","name":"base","publisher":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"v1"}}"#;
        let signing_key = K256SigningKey::from_slice(&[9u8; 32]).expect("test publisher key");
        let signature: K256Signature = signing_key.sign(bytes);
        let trusted_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let pack = verify_measurement_pack(bytes, &signature.to_bytes(), &[trusted_key]).unwrap();

        assert_eq!(pack.subject.name, "base");
    }

    #[test]
    fn verify_measurement_pack_rejects_missing_trusted_key() {
        let bytes = br#"{"measurements":{"profiles":[]},"published_at":1786000000,"revision":1,"schema":"atakit.base_image_measurement_pack.v4","subject":{"id":"0x00","name":"base","publisher":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"v1"}}"#;
        let signing_key = K256SigningKey::from_slice(&[9u8; 32]).expect("test publisher key");
        let signature: K256Signature = signing_key.sign(bytes);

        let err = verify_measurement_pack(bytes, &signature.to_bytes(), &[]).unwrap_err();

        assert!(err
            .to_string()
            .contains("no trusted measurement publisher keys"));
    }

    #[test]
    fn verify_measurement_pack_rejects_untrusted_signature() {
        let bytes = br#"{"measurements":{"profiles":[]},"published_at":1786000000,"revision":1,"schema":"atakit.base_image_measurement_pack.v4","subject":{"id":"0x00","name":"base","publisher":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"v1"}}"#;
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
        let bytes = br#"{"schema":"atakit.base_image_measurement_pack.v4","revision":1,"published_at":1786000000,"subject":{"name":"base","version":"v1","id":"0x00","publisher":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"measurements":{"profiles":[]}}"#;
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

    #[test]
    fn extracts_amd_snp_vcek_request_fields() {
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SNP_REPORT_REPORTED_TCB_OFFSET..SNP_REPORT_REPORTED_TCB_OFFSET + 8]
            .copy_from_slice(&[4, 0, 0, 0, 0, 0, 24, 219]);
        report[SNP_REPORT_REPORTED_TCB_OFFSET + 8] = 0x19;
        report[SNP_REPORT_REPORTED_TCB_OFFSET + 9] = 0x01;
        report[SNP_REPORT_CHIP_ID_OFFSET..SNP_REPORT_CHIP_ID_OFFSET + 64].fill(0xa5);

        let request = amd_snp_vcek_request(&report).expect("VCEK request");

        assert_eq!(request.chip_id, [0xa5; 64]);
        assert_eq!(request.bootloader, 4);
        assert_eq!(request.tee, 0);
        assert_eq!(request.snp, 24);
        assert_eq!(request.microcode, 219);
        assert_eq!(request.cpuid_family, 0x19);
        assert_eq!(request.cpuid_model, 0x01);
    }

    #[test]
    fn selects_vcek_and_vlek_certificate_chains_from_report_key_settings() {
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        assert_eq!(
            amd_snp_signing_key_type(&report).unwrap(),
            AmdSnpSigningKeyType::Vcek
        );
        assert_eq!(
            verification_core::snp_intermediate_ca_label(AmdSnpSigningKeyType::Vcek),
            "SNP ASK"
        );
        assert_eq!(
            verification_core::snp_intermediate_ca_common_names(
                AmdSnpSigningKeyType::Vcek,
                "Milan"
            ),
            ["SEV-Milan"]
        );

        report[SNP_REPORT_KEY_SETTINGS_OFFSET..SNP_REPORT_KEY_SETTINGS_OFFSET + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            amd_snp_signing_key_type(&report).unwrap(),
            AmdSnpSigningKeyType::Vlek
        );
        assert_eq!(
            verification_core::snp_intermediate_ca_label(AmdSnpSigningKeyType::Vlek),
            "SNP ASVK"
        );
        assert_eq!(
            verification_core::snp_intermediate_ca_common_names(
                AmdSnpSigningKeyType::Vlek,
                "Genoa"
            ),
            ["SEV-VLEK", "SEV-VLEK-Genoa"]
        );
        assert!(amd_snp_vcek_request(&report)
            .unwrap_err()
            .contains("cannot resolve a VLEK-signed SNP report"));
    }

    #[test]
    fn extracts_verified_snp_debug_and_migrate_ma_states() {
        let policy = (1u64 << 17) | (1u64 << 18) | (1u64 << 19);
        let report = synthetic_snp_security_report(policy);

        assert_eq!(
            verification_core::verified_snp_attribute_states(&report).unwrap(),
            (true, true)
        );
    }

    #[test]
    fn extracts_verified_snp_version_five_mitigation_vectors() {
        let mut report = synthetic_snp_security_report(1u64 << 17);
        report[SNP_REPORT_VERSION_OFFSET..SNP_REPORT_VERSION_OFFSET + 4]
            .copy_from_slice(&5u32.to_le_bytes());
        report[SNP_REPORT_LAUNCH_MITIGATION_VECTOR_OFFSET
            ..SNP_REPORT_LAUNCH_MITIGATION_VECTOR_OFFSET + 8]
            .copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        report[SNP_REPORT_CURRENT_MITIGATION_VECTOR_OFFSET
            ..SNP_REPORT_CURRENT_MITIGATION_VECTOR_OFFSET + 8]
            .copy_from_slice(&0x1112_1314_1516_1718u64.to_le_bytes());

        let state = amd_snp_security_state(&report).expect("version-5 security state");
        assert_eq!(state.report_version, 5);
        assert_eq!(state.launch_mitigation_vector, 0x0102_0304_0506_0708);
        assert_eq!(state.current_mitigation_vector, 0x1112_1314_1516_1718);

        let version_three = amd_snp_security_state(&synthetic_snp_security_report(1u64 << 17))
            .expect("version-3 security state");
        assert_eq!(version_three.report_version, 3);
        assert_eq!(version_three.launch_mitigation_vector, 0);
        assert_eq!(version_three.current_mitigation_vector, 0);
    }

    #[test]
    fn amd_snp_mitigation_policy_requires_version_five_and_required_bits() {
        let policy = AmdSnpSecurityPolicy {
            cpuid: 0x190000,
            minimum_tcb: [0; 32],
            platform_info_policy: [0; 32],
            required_launch_mitigation_vector: 0b0011,
            required_current_mitigation_vector: 0b1100,
        };

        let version_error = validate_amd_snp_mitigation_policy(3, 0b0011, 0b1100, &policy)
            .expect_err("a nonzero mitigation policy requires a version-5 report");
        assert!(
            version_error.contains("version 5 is required"),
            "{version_error}"
        );

        let future_version_error = validate_amd_snp_mitigation_policy(6, 0b0011, 0b1100, &policy)
            .expect_err("version-5 vector semantics must not apply to a future report version");
        assert!(
            future_version_error.contains("version 5 is required"),
            "{future_version_error}"
        );

        validate_amd_snp_mitigation_policy(5, 0b1011, 0b1110, &policy)
            .expect("required masks use bit inclusion");

        let launch_error = validate_amd_snp_mitigation_policy(5, 0b0010, 0b1100, &policy)
            .expect_err("the launch vector is missing a required bit");
        assert!(launch_error.contains("LAUNCH_MIT_VECTOR"), "{launch_error}");

        let current_error = validate_amd_snp_mitigation_policy(5, 0b0011, 0b1000, &policy)
            .expect_err("the current vector is missing a required bit");
        assert!(
            current_error.contains("CURRENT_MIT_VECTOR"),
            "{current_error}"
        );
    }

    #[test]
    fn rejects_invalid_verified_snp_report_fields() {
        let valid_report = || synthetic_snp_security_report(1u64 << 17);

        assert!(verification_core::verified_snp_attribute_states(&valid_report()[..1183]).is_err());

        let mut report = valid_report();
        report[SNP_REPORT_ID_MA_OFFSET..SNP_REPORT_ID_MA_OFFSET + SNP_REPORT_ID_MA_LEN].fill(0xff);
        verification_core::verified_snp_attribute_states(&report)
            .expect("all-0xff REPORT_ID_MA must mean no migration-agent association");

        let mut report = valid_report();
        report[SNP_REPORT_ID_MA_OFFSET..SNP_REPORT_ID_MA_OFFSET + SNP_REPORT_ID_MA_LEN].fill(1);
        assert!(verification_core::verified_snp_attribute_states(&report)
            .unwrap_err()
            .contains("REPORT_ID_MA"));

        let mut report = valid_report();
        report[SNP_REPORT_ID_MA_OFFSET..SNP_REPORT_ID_MA_OFFSET + SNP_REPORT_ID_MA_LEN].fill(0xff);
        report[SNP_REPORT_ID_MA_OFFSET] = 0;
        assert!(verification_core::verified_snp_attribute_states(&report)
            .unwrap_err()
            .contains("REPORT_ID_MA"));

        let mut report = valid_report();
        report[SNP_REPORT_VMPL_OFFSET..SNP_REPORT_VMPL_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        assert!(verification_core::verified_snp_attribute_states(&report)
            .unwrap_err()
            .contains("VMPL"));

        let mut report = valid_report();
        report[SNP_REPORT_POLICY_OFFSET..SNP_REPORT_POLICY_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        assert!(verification_core::verified_snp_attribute_states(&report)
            .unwrap_err()
            .contains("reserved"));

        let mut report = valid_report();
        report[SNP_REPORT_LAUNCH_TCB_OFFSET] = 1;
        assert!(verification_core::verified_snp_attribute_states(&report)
            .unwrap_err()
            .contains("launch_tcb"));
    }

    #[test]
    fn der_tlv_rejects_content_length_past_buffer() {
        let short = [0x30, 0x02, 0x00];
        assert!(verification_core::der_tlv(&short, 0x30, "test")
            .unwrap_err()
            .contains("exceeds buffer"));

        let long = [0x30, 0x82, 0x01, 0x00, 0x00];
        assert!(verification_core::der_tlv(&long, 0x30, "test")
            .unwrap_err()
            .contains("exceeds buffer"));
    }

    #[test]
    fn builds_amd_snp_vcek_cert_table() {
        let table = amd_snp_vcek_cert_table(b"ark", b"ask", b"vcek").expect("cert table");

        assert_eq!(amd_snp_ark_from_cert_table(&table).unwrap(), b"ark");
        let parsed = verification_core::parse_amd_snp_cert_table(&table).unwrap();
        assert_eq!(parsed.ask.as_deref(), Some(b"ask".as_slice()));
        assert_eq!(parsed.vcek.as_deref(), Some(b"vcek".as_slice()));
    }

    #[test]
    fn amd_snp_vcek_cert_table_builder_enforces_parser_limits() {
        assert!(amd_snp_vcek_cert_table(b"", b"ask", b"vcek")
            .unwrap_err()
            .contains("ARK certificate is empty"));

        let oversized_ark = vec![0u8; MAX_SNP_CERT_TABLE_BYTES];
        assert!(amd_snp_vcek_cert_table(&oversized_ark, b"ask", b"vcek")
            .unwrap_err()
            .contains("1048576-byte limit"));
    }

    #[test]
    fn measurement_attributes_accept_all_reserved_variant_policy_encodings() {
        let tcb = "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004";
        let platform_info = "0x0000000000000000000000000000000000000000000000010000000000000020";
        let readable = vec![
            serde_json::json!({
                "name": atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
                "value": ["ok", "configuration-needed"],
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_NAME,
                "value": tcb,
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
                "value": platform_info,
            }),
        ];
        let parsed = parse_measurement_attributes(&readable, "variant").unwrap();
        assert_eq!(
            parsed[&atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_KEY],
            atakit_core::tee_attributes::u16_value(0x9)
        );
        assert_eq!(
            parsed[&atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_KEY],
            atakit_core::tee_attributes::parse_bytes32_hex(tcb).unwrap()
        );
        assert_eq!(
            parsed[&atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY],
            atakit_core::tee_attributes::parse_bytes32_hex(platform_info).unwrap()
        );

        let hexadecimal = readable
            .iter()
            .map(|attribute| {
                let name = attribute["name"].as_str().unwrap();
                let reserved =
                    atakit_core::tee_attributes::VerifiedTeeAttribute::from_name(name).unwrap();
                let value = parsed[&reserved.key()];
                serde_json::json!({
                    "key": format!("0x{}", hex::encode(reserved.key())),
                    "value": format!("0x{}", hex::encode(value)),
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            parse_measurement_attributes(&hexadecimal, "variant").unwrap(),
            parsed
        );
    }

    #[test]
    fn selects_manual_azure_maa_key_with_live_jwt_metadata() {
        let quote = fake_tpm_quote(&[0u8; 32], &[(4, [0xaau8; 32])]);
        let (binding, _, trusted_key) = fake_azure_ak_binding_and_signature(&quote);

        let selected = select_azure_maa_manual_trust_key(
            &binding,
            &[maa_cert(vec![0]), maa_cert(trusted_key.clone())],
        )
        .expect("matching manual MAA key");

        assert_eq!(selected.kid, "test-maa-key");
        assert_eq!(selected.issuer, "https://sharedeus.eus.attest.azure.net");
        assert_eq!(selected.not_after, u64::MAX);
        assert_eq!(selected.public_key, trusted_key);
        assert!(select_azure_maa_manual_trust_key(&binding, &[maa_cert(vec![0])]).is_err());
    }

    /// A manually supplied Azure MAA certificate carries the expiry from its
    /// own validity period, so the downstream expiry check in
    /// `verify_azure_maa_session_binding` can actually fire. Before this, every
    /// manually supplied key was assigned `u64::MAX` and that check was
    /// unreachable for the manual path.
    #[test]
    fn manual_azure_maa_certificate_carries_its_own_expiry() {
        let quote = fake_tpm_quote(&[0u8; 32], &[(4, [0xaau8; 32])]);
        let (binding, _, trusted_key) = fake_azure_ak_binding_and_signature(&quote);

        let selected = select_azure_maa_manual_trust_key(
            &binding,
            &[AzureMaaTrustCertificate {
                public_key: trusted_key.clone(),
                not_after: 1_700_000_000,
            }],
        )
        .expect("matching manual MAA certificate");

        assert_eq!(
            selected.not_after, 1_700_000_000,
            "expiry must come from the certificate, never u64::MAX"
        );
        assert_ne!(selected.not_after, u64::MAX);
    }

    /// The portal TLS attestation path enforces the expiry too. It previously
    /// took bare key bytes and had no expiry check at all, so an expired Azure
    /// MAA signing key stayed trusted there indefinitely.
    #[test]
    fn tls_path_rejects_expired_azure_maa_certificate() {
        let quote = fake_tpm_quote(&[0u8; 32], &[(4, [0xaau8; 32])]);
        let (binding, _, trusted_key) = fake_azure_ak_binding_and_signature(&quote);

        let mut report = VerificationReport {
            checks: Vec::new(),
            evidence: EvidenceSummary::default(),
        };
        let mut errors = Vec::new();
        verification_core::verify_azure_maa_jwt_binding(
            &mut report,
            &mut errors,
            &binding,
            &[AzureMaaTrustCertificate {
                public_key: trusted_key,
                // Expired well before the verification time below.
                not_after: 1_000,
            }],
            "tdx",
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        );

        assert!(
            !errors.is_empty(),
            "an expired MAA signing certificate must fail the TLS attestation path"
        );
        assert!(
            errors.iter().any(|error| error.detail.contains("expired")),
            "failure must name expiry as the cause; got {errors:?}"
        );
    }
}
