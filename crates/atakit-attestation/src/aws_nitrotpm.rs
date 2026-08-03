use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value;
use p256::pkcs8::DecodePublicKey;

use super::*;

const PROTECTED_HEADER: &[u8] = &[0xa1, 0x01, 0x38, 0x22];
const PCR_COUNT: usize = 24;
const SNP_REPORT_DATA_OFFSET: usize = 0x50;

#[derive(Debug)]
struct CoseDocument {
    payload: Vec<u8>,
    signature: [u8; 96],
}

#[derive(Debug)]
struct NitroPayload {
    timestamp_millis: u64,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Vec<u8>,
    nonce: [u8; 32],
    pcrs: [[u8; 48]; PCR_COUNT],
}

pub fn aws_nitro_root_certificate(binding: &AkBinding) -> std::result::Result<Vec<u8>, String> {
    let document = decode_binding(binding)?;
    let cose = parse_cose_document(&document)?;
    let payload = parse_payload(&cose.payload)?;
    Ok(payload.cabundle[0].clone())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_aws_tls_attestation(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    binding: &AkBinding,
    evidence: &TeeEvidence,
    ak_public: &[u8],
    authenticated_pcrs: &[PcrEvidence],
    expected_qualifying_data: &[u8; 32],
    trust: &TrustAnchors,
    verification_time: SystemTime,
) {
    let result = verify_aws_tls_attestation_inner(
        binding,
        evidence,
        ak_public,
        authenticated_pcrs,
        expected_qualifying_data,
        trust,
        verification_time,
    );
    match result {
        Ok(()) => pass(report, "aws-nitrotpm-binding"),
        Err(detail) => fail(report, errors, "aws-nitrotpm-binding", detail),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_aws_tls_attestation_inner(
    binding: &AkBinding,
    evidence: &TeeEvidence,
    ak_public: &[u8],
    authenticated_pcrs: &[PcrEvidence],
    expected_qualifying_data: &[u8; 32],
    trust: &TrustAnchors,
    verification_time: SystemTime,
) -> std::result::Result<(), String> {
    if evidence.kind != "configfs-tsm" {
        return Err(format!(
            "AWS NitroTPM verification requires teeEvidence.kind=configfs-tsm, got {}",
            evidence.kind
        ));
    }
    let snp_report =
        decode_b64("teeEvidence.report", &evidence.report).map_err(|error| error.to_string())?;
    if snp_report.len() != SNP_REPORT_SIZE {
        return Err(format!(
            "AWS AMD SEV-SNP report has {} bytes, expected {SNP_REPORT_SIZE}",
            snp_report.len()
        ));
    }

    let document = decode_binding(binding)?;
    let cose = parse_cose_document(&document)?;
    let payload = parse_payload(&cose.payload)?;
    verify_certificate_chain(&payload, trust)?;
    verify_cose_signature(&payload.certificate, &cose)?;
    verify_document_freshness(payload.timestamp_millis, trust, verification_time)?;

    if payload.nonce != *expected_qualifying_data {
        return Err("NitroTPM document nonce does not match TLS qualifyingData".to_string());
    }

    let document_key = P256VerifyingKey::from_public_key_der(&payload.public_key)
        .map_err(|error| format!("parse NitroTPM doc.public_key as P-256 SPKI: {error}"))?;
    let tpm_key = verification_core::parse_tpmt_public_ecc_p256(ak_public)?;
    let document_sec1 = document_key.to_encoded_point(false);
    let tpm_sec1 = tpm_key.to_encoded_point(false);
    if document_sec1.as_bytes() != tpm_sec1.as_bytes() {
        return Err("NitroTPM doc.public_key does not match tpm.akPublic".to_string());
    }

    let ak_fingerprint = compute_key_fingerprint(2, document_sec1.as_bytes());
    if snp_report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 32] != ak_fingerprint {
        return Err(
            "AMD SEV-SNP REPORT_DATA does not contain the NitroTPM Attestation Key fingerprint"
                .to_string(),
        );
    }
    if snp_report[SNP_REPORT_DATA_OFFSET + 32..SNP_REPORT_DATA_OFFSET + 64]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err("AMD SEV-SNP REPORT_DATA suffix is not zero".to_string());
    }

    let report_id = &snp_report
        [SNP_REPORT_REPORT_ID_OFFSET..SNP_REPORT_REPORT_ID_OFFSET + SNP_REPORT_REPORT_ID_LEN];
    let mut pcr15_extend = [0u8; 96];
    pcr15_extend[64..].copy_from_slice(report_id);
    let expected_pcr15: [u8; 48] = Sha384::digest(pcr15_extend).into();
    if payload.pcrs[15] != expected_pcr15 {
        return Err("NitroTPM SHA-384 PCR15 does not bind AMD SEV-SNP REPORT_ID".to_string());
    }

    let mut saw_sha384_pcr15 = false;
    for pcr in authenticated_pcrs {
        let Some(value) = &pcr.sha384 else {
            continue;
        };
        let value =
            decode_hex_array::<48>("tpm.pcrs.sha384", value).map_err(|error| error.to_string())?;
        if usize::from(pcr.index) >= PCR_COUNT {
            return Err(format!(
                "TPM Quote contains unsupported SHA-384 PCR{}",
                pcr.index
            ));
        }
        if payload.pcrs[usize::from(pcr.index)] != value {
            return Err(format!(
                "NitroTPM document SHA-384 PCR{} does not match the authenticated TPM Quote value",
                pcr.index
            ));
        }
        saw_sha384_pcr15 |= pcr.index == 15;
    }
    if !saw_sha384_pcr15 {
        return Err("authenticated TPM Quote does not select SHA-384 PCR15".to_string());
    }
    Ok(())
}

fn decode_binding(binding: &AkBinding) -> std::result::Result<Vec<u8>, String> {
    if binding.kind != "aws-nitro-doc" {
        return Err(format!(
            "AWS NitroTPM verification requires akBinding.kind=aws-nitro-doc, got {}",
            binding.kind
        ));
    }
    decode_b64("akBinding.data", &binding.data).map_err(|error| error.to_string())
}

fn parse_cose_document(document: &[u8]) -> std::result::Result<CoseDocument, String> {
    let outer = decode_one(document).map_err(|error| format!("decode COSE_Sign1: {error}"))?;
    let Value::Array(mut fields) = outer else {
        return Err("COSE_Sign1 must be an untagged array".to_string());
    };
    if fields.len() != 4 {
        return Err("COSE_Sign1 must contain four fields".to_string());
    }
    let signature = expect_bytes(fields.pop().expect("four fields"), "signature")?;
    if signature.len() != 96 {
        return Err("COSE ES384 signature must be 96 bytes".to_string());
    }
    let payload = expect_bytes(fields.pop().expect("four fields"), "payload")?;
    let Value::Map(unprotected) = fields.pop().expect("four fields") else {
        return Err("COSE unprotected header must be a map".to_string());
    };
    if !unprotected.is_empty() {
        return Err("COSE unprotected header must be empty".to_string());
    }
    let protected = expect_bytes(fields.pop().expect("four fields"), "protected header")?;
    if protected != PROTECTED_HEADER {
        return Err("COSE protected header is not canonical ES384".to_string());
    }
    Ok(CoseDocument {
        payload,
        signature: signature.try_into().expect("checked signature length"),
    })
}

fn parse_payload(payload_bytes: &[u8]) -> std::result::Result<NitroPayload, String> {
    let payload =
        decode_one(payload_bytes).map_err(|error| format!("decode NitroTPM payload: {error}"))?;
    let Value::Map(fields) = payload else {
        return Err("NitroTPM payload must be a map".to_string());
    };
    let allowed = [
        "module_id",
        "digest",
        "timestamp",
        "certificate",
        "cabundle",
        "public_key",
        "user_data",
        "nitrotpm_pcrs",
        "nonce",
    ];
    let mut values = BTreeMap::new();
    for (key, value) in fields {
        let Value::Text(key) = key else {
            return Err("NitroTPM payload keys must be text".to_string());
        };
        if !allowed.contains(&key.as_str()) {
            return Err(format!("unknown NitroTPM payload key {key}"));
        }
        if values.insert(key.clone(), value).is_some() {
            return Err(format!("duplicate NitroTPM payload key {key}"));
        }
    }

    expect_text(take_required(&mut values, "module_id")?, "module_id")?;
    if expect_text(take_required(&mut values, "digest")?, "digest")? != "SHA384" {
        return Err("NitroTPM digest must equal SHA384".to_string());
    }
    let timestamp_millis = expect_u64(take_required(&mut values, "timestamp")?, "timestamp")?;
    let certificate = expect_bytes(take_required(&mut values, "certificate")?, "certificate")?;
    if certificate.is_empty() {
        return Err("NitroTPM leaf certificate is empty".to_string());
    }

    let Value::Array(bundle_values) = take_required(&mut values, "cabundle")? else {
        return Err("cabundle must be an array".to_string());
    };
    if bundle_values.is_empty() {
        return Err("cabundle must contain a root certificate".to_string());
    }
    let cabundle = bundle_values
        .into_iter()
        .map(|value| expect_bytes(value, "cabundle certificate"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if cabundle.iter().any(Vec::is_empty) {
        return Err("cabundle contains an empty certificate".to_string());
    }

    let public_key = expect_bytes(take_required(&mut values, "public_key")?, "public_key")?;
    let nonce = expect_bytes(take_required(&mut values, "nonce")?, "nonce")?;
    if nonce.len() != 32 {
        return Err("NitroTPM nonce must be exactly 32 bytes".to_string());
    }
    if let Some(user_data) = values.remove("user_data") {
        if !matches!(user_data, Value::Bytes(_) | Value::Null) {
            return Err("user_data must be a byte string or null".to_string());
        }
    }

    let Value::Map(pcr_values) = take_required(&mut values, "nitrotpm_pcrs")? else {
        return Err("nitrotpm_pcrs must be a map".to_string());
    };
    if pcr_values.len() != PCR_COUNT {
        return Err("nitrotpm_pcrs must contain PCR0 through PCR23".to_string());
    }
    let mut pcrs = [[0u8; 48]; PCR_COUNT];
    let mut seen = [false; PCR_COUNT];
    for (key, value) in pcr_values {
        let index = expect_u64(key, "nitrotpm_pcrs key")?;
        if index >= PCR_COUNT as u64 {
            return Err(format!("NitroTPM PCR index {index} is unsupported"));
        }
        let index = index as usize;
        if seen[index] {
            return Err(format!("duplicate NitroTPM PCR index {index}"));
        }
        let bytes = expect_bytes(value, "nitrotpm_pcrs value")?;
        if bytes.len() != 48 {
            return Err(format!("NitroTPM PCR{index} must contain 48 bytes"));
        }
        pcrs[index].copy_from_slice(&bytes);
        seen[index] = true;
    }
    if seen.iter().any(|seen| !seen) {
        return Err("nitrotpm_pcrs is incomplete".to_string());
    }
    if !values.is_empty() {
        return Err("unconsumed NitroTPM payload fields".to_string());
    }
    Ok(NitroPayload {
        timestamp_millis,
        certificate,
        cabundle,
        public_key,
        nonce: nonce.try_into().expect("checked nonce length"),
        pcrs,
    })
}

fn verify_certificate_chain(
    payload: &NitroPayload,
    trust: &TrustAnchors,
) -> std::result::Result<(), String> {
    let timestamp_seconds = payload.timestamp_millis / 1_000;
    let timestamp = ASN1Time::from_timestamp(timestamp_seconds as i64)
        .map_err(|error| format!("NitroTPM document timestamp is invalid: {error}"))?;
    let root_der = &payload.cabundle[0];
    let root_hash: [u8; 32] = Keccak256::digest(root_der).into();
    if !trust.aws_nitro_roots.iter().any(|root| root == root_der)
        && !trust
            .aws_nitro_root_hashes
            .iter()
            .any(|trusted| trusted == &root_hash)
    {
        return Err(format!(
            "AWS Nitro root is not trusted; keccak256(root_der)=0x{}",
            hex::encode(root_hash)
        ));
    }

    let mut certificates = payload.cabundle.iter().collect::<Vec<_>>();
    certificates.push(&payload.certificate);
    let mut parsed = Vec::with_capacity(certificates.len());
    for (index, certificate) in certificates.iter().enumerate() {
        let (remaining, certificate) = X509Certificate::from_der(certificate)
            .map_err(|error| format!("NitroTPM certificate {index} did not parse: {error}"))?;
        if !remaining.is_empty() {
            return Err(format!("NitroTPM certificate {index} has trailing bytes"));
        }
        if !certificate.validity().is_valid_at(timestamp) {
            return Err(format!(
                "NitroTPM certificate {index} is not valid at the signed document timestamp"
            ));
        }
        parsed.push(certificate);
    }

    for index in 0..parsed.len() - 1 {
        let parent = &parsed[index];
        let child = &parsed[index + 1];
        if child.issuer() != parent.subject() {
            return Err(format!(
                "NitroTPM certificate issuer and subject do not link at certificate {index}"
            ));
        }
        let ca_certificates_below = parsed.len().saturating_sub(index + 2);
        verification_core::verify_ca_certificate_role(
            parent,
            "NitroTPM CA",
            ca_certificates_below,
        )?;
        child
            .verify_signature(Some(&parent.tbs_certificate.subject_pki))
            .map_err(|error| format!("NitroTPM certificate signature failed: {error}"))?;
    }
    let root = &parsed[0];
    if root.subject() != root.issuer() {
        return Err("NitroTPM root certificate is not self-issued".to_string());
    }
    root.verify_signature(None)
        .map_err(|error| format!("NitroTPM root self-signature failed: {error}"))?;
    verification_core::verify_end_entity_certificate_role(
        parsed.last().expect("leaf certificate exists"),
        "NitroTPM leaf",
    )?;
    Ok(())
}

fn verify_cose_signature(
    leaf_der: &[u8],
    document: &CoseDocument,
) -> std::result::Result<(), String> {
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|error| format!("NitroTPM leaf certificate did not parse: {error}"))?;
    let public_key = P384VerifyingKey::from_sec1_bytes(
        leaf.tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
    )
    .map_err(|error| format!("NitroTPM leaf public key is not P-384: {error}"))?;
    let signature = P384Signature::from_slice(&document.signature)
        .map_err(|error| format!("NitroTPM COSE signature is invalid: {error}"))?;
    public_key
        .verify(&signature_structure(&document.payload), &signature)
        .map_err(|error| format!("NitroTPM COSE signature did not verify: {error}"))
}

fn verify_document_freshness(
    timestamp_millis: u64,
    trust: &TrustAnchors,
    verification_time: SystemTime,
) -> std::result::Result<(), String> {
    let maximum_age = trust.aws_document_maximum_age_seconds.ok_or_else(|| {
        "AWS NitroTPM document maximum age is not configured by the verifier".to_string()
    })?;
    let allowed_future = trust
        .aws_document_allowed_future_clock_difference_seconds
        .ok_or_else(|| {
            "AWS NitroTPM allowed future clock difference is not configured by the verifier"
                .to_string()
        })?;
    let document_time = timestamp_millis / 1_000;
    let current_time = verification_time
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("verification time is before Unix epoch: {error}"))?
        .as_secs();
    if document_time > current_time.saturating_add(allowed_future) {
        return Err(format!(
            "NitroTPM document timestamp {document_time} is more than {allowed_future} seconds in the future"
        ));
    }
    if current_time > document_time.saturating_add(maximum_age) {
        return Err(format!(
            "NitroTPM document timestamp {document_time} is more than {maximum_age} seconds old"
        ));
    }
    Ok(())
}

fn signature_structure(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len() + 24);
    output.extend_from_slice(&[0x84, 0x6a]);
    output.extend_from_slice(b"Signature1");
    output.push(0x44);
    output.extend_from_slice(PROTECTED_HEADER);
    output.push(0x40);
    encode_byte_string(payload, &mut output);
    output
}

fn encode_byte_string(bytes: &[u8], output: &mut Vec<u8>) {
    match bytes.len() {
        length @ 0..=23 => output.push(0x40 | length as u8),
        length @ 24..=0xff => output.extend_from_slice(&[0x58, length as u8]),
        length @ 0x100..=0xffff => {
            output.push(0x59);
            output.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length @ 0x1_0000..=0xffff_ffff => {
            output.push(0x5a);
            output.extend_from_slice(&(length as u32).to_be_bytes());
        }
        length => {
            output.push(0x5b);
            output.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    output.extend_from_slice(bytes);
}

fn decode_one(bytes: &[u8]) -> std::result::Result<Value, String> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|error| format!("CBOR decode failed: {error}"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err("CBOR value has trailing bytes".to_string());
    }
    Ok(value)
}

fn take_required(
    values: &mut BTreeMap<String, Value>,
    name: &str,
) -> std::result::Result<Value, String> {
    values
        .remove(name)
        .ok_or_else(|| format!("NitroTPM payload lacks {name}"))
}

fn expect_bytes(value: Value, name: &str) -> std::result::Result<Vec<u8>, String> {
    let Value::Bytes(bytes) = value else {
        return Err(format!("{name} must be a byte string"));
    };
    Ok(bytes)
}

fn expect_text(value: Value, name: &str) -> std::result::Result<String, String> {
    let Value::Text(text) = value else {
        return Err(format!("{name} must be a text string"));
    };
    Ok(text)
}

fn expect_u64(value: Value, name: &str) -> std::result::Result<u64, String> {
    let Value::Integer(integer) = value else {
        return Err(format!("{name} must be an integer"));
    };
    u64::try_from(integer).map_err(|_| format!("{name} is outside uint64"))
}
