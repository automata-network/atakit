//! Provider-neutral attestation verification shared by TLS and session flows.

use super::*;

pub(super) fn verify_gcp_ak_cert_chain(
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
    let chain = match parse_gcp_cert_chain(binding) {
        Ok(chain) => chain,
        Err(detail) => {
            fail(report, errors, "gcp-ak-cert-chain", detail);
            return;
        }
    };
    verify_gcp_ak_cert_chain_der(
        report,
        errors,
        &chain,
        ak_public,
        trusted_roots,
        trusted_root_hashes,
    );
}

pub(super) fn verify_gcp_ak_cert_chain_der(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    chain: &[Vec<u8>],
    ak_public: &[u8],
    trusted_roots: &[Vec<u8>],
    trusted_root_hashes: &[[u8; 32]],
) {
    if trusted_roots.is_empty() && trusted_root_hashes.is_empty() {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            "no trusted GCP AK root certificates or root hashes configured".to_string(),
        );
        return;
    }
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
    if !leaf.validity().is_valid() {
        fail(
            report,
            errors,
            "gcp-ak-cert-chain",
            "GCP AK leaf certificate is not currently valid".to_string(),
        );
        return;
    }
    if let Err(detail) = verify_end_entity_certificate_role(&leaf, "GCP AK leaf") {
        fail(report, errors, "gcp-ak-cert-chain", detail);
        return;
    }
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
        if !child.validity().is_valid() || !parent.validity().is_valid() {
            fail(
                report,
                errors,
                "gcp-ak-cert-chain",
                format!("GCP AK chain certificate {idx} or its issuer is not currently valid"),
            );
            return;
        }
        if let Err(detail) = verify_ca_certificate_role(
            &parent,
            &format!("GCP AK chain certificate {}", idx + 1),
            idx,
        ) {
            fail(report, errors, "gcp-ak-cert-chain", detail);
            return;
        }
        let child_aki = child.extensions().iter().find_map(|extension| {
            if let x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) =
                extension.parsed_extension()
            {
                aki.key_identifier.as_ref().map(|identifier| identifier.0)
            } else {
                None
            }
        });
        let parent_ski = parent.extensions().iter().find_map(|extension| {
            if let x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(identifier) =
                extension.parsed_extension()
            {
                Some(identifier.0)
            } else {
                None
            }
        });
        if let (Some(child_aki), Some(parent_ski)) = (child_aki, parent_ski) {
            if child_aki != parent_ski {
                fail(
                    report,
                    errors,
                    "gcp-ak-cert-chain",
                    format!("GCP AK chain AKID/SKID mismatch at certificate {idx}"),
                );
                return;
            }
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

fn verify_ca_certificate_role(
    cert: &X509Certificate<'_>,
    label: &str,
    ca_certificates_below: usize,
) -> std::result::Result<(), String> {
    let constraints = cert
        .basic_constraints()
        .map_err(|error| format!("{label} Basic Constraints are invalid: {error}"))?
        .ok_or_else(|| format!("{label} is missing Basic Constraints"))?;
    if !constraints.value.ca {
        return Err(format!("{label} is not a certificate authority"));
    }
    if let Some(path_len) = constraints.value.path_len_constraint {
        let ca_certificates_below = u32::try_from(ca_certificates_below)
            .map_err(|_| format!("{label} certificate path is too long"))?;
        if ca_certificates_below > path_len {
            return Err(format!(
                "{label} Basic Constraints path length {path_len} is smaller than the {ca_certificates_below} intermediate certificate(s) below it"
            ));
        }
    }
    let key_usage = cert
        .key_usage()
        .map_err(|error| format!("{label} Key Usage is invalid: {error}"))?
        .ok_or_else(|| format!("{label} is missing Key Usage"))?;
    if !key_usage.value.key_cert_sign() {
        return Err(format!(
            "{label} Key Usage does not permit certificate signing"
        ));
    }
    Ok(())
}

fn verify_end_entity_certificate_role(
    cert: &X509Certificate<'_>,
    label: &str,
) -> std::result::Result<(), String> {
    if cert
        .basic_constraints()
        .map_err(|error| format!("{label} Basic Constraints are invalid: {error}"))?
        .is_some_and(|constraints| constraints.value.ca)
    {
        return Err(format!("{label} must not be a certificate authority"));
    }
    if cert
        .key_usage()
        .map_err(|error| format!("{label} Key Usage is invalid: {error}"))?
        .is_some_and(|key_usage| !key_usage.value.digital_signature())
    {
        return Err(format!(
            "{label} Key Usage does not permit digital signatures"
        ));
    }
    Ok(())
}

pub(super) fn parse_gcp_cert_chain(
    binding: &AkBinding,
) -> std::result::Result<Vec<Vec<u8>>, String> {
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

pub(super) fn verify_gcp_tee_vtpm_binding(
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

pub(super) fn expected_gcp_tdx_pcr15(
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

pub(super) fn gcp_tdx_report_start(quote: &[u8]) -> std::result::Result<usize, String> {
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

pub(super) fn read_le_u16_opt(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

pub(super) fn read_le_u32_opt(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub(super) fn expected_gcp_snp_pcr15(report: &[u8]) -> std::result::Result<[u8; 32], String> {
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

pub(super) fn verify_expected_pcr15(
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

pub(super) struct AmdSnpTrust<'a> {
    pub(super) ark_roots: &'a [Vec<u8>],
    pub(super) ark_root_hashes: &'a [[u8; 32]],
    pub(super) crls: &'a [Vec<u8>],
}

pub(super) fn verify_gcp_tee_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    tee: &str,
    collateral: &serde_json::Value,
    amd_snp_trust: AmdSnpTrust<'_>,
    current_time: SystemTime,
) -> Option<u16> {
    match tee {
        "sev-snp" => {
            verify_gcp_snp_vendor_report(
                report,
                errors,
                evidence,
                amd_snp_trust.ark_roots,
                amd_snp_trust.ark_root_hashes,
                amd_snp_trust.crls,
                current_time,
            );
            None
        }
        "tdx" => verify_gcp_tdx_vendor_report(report, errors, evidence, collateral),
        other => {
            fail(
                report,
                errors,
                "gcp-tee-vendor-report",
                format!("GCP raw TEE vendor verification is unsupported for tee={other}"),
            );
            None
        }
    }
}

pub(super) fn verify_gcp_tdx_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    collateral: &serde_json::Value,
) -> Option<u16> {
    verify_tdx_vendor_report(
        report,
        errors,
        evidence,
        collateral,
        "gcp-tee-vendor-report",
        "GCP",
    )
}

pub(super) fn verify_azure_tdx_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    collateral: &serde_json::Value,
) -> Option<u16> {
    verify_tdx_vendor_report(
        report,
        errors,
        evidence,
        collateral,
        "azure-tee-vendor-report",
        "Azure",
    )
}

fn verify_tdx_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    collateral: &serde_json::Value,
    check_name: &str,
    provider_name: &str,
) -> Option<u16> {
    let Some(evidence) = evidence else {
        fail(
            report,
            errors,
            check_name,
            format!("{provider_name} TDX TEE evidence is missing"),
        );
        return None;
    };
    let raw_quote = match decode_b64("teeEvidence.report", &evidence.report) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            fail(
                report,
                errors,
                check_name,
                format!("{provider_name} TDX quote is empty"),
            );
            return None;
        }
        Err(e) => {
            fail(report, errors, check_name, e.to_string());
            return None;
        }
    };
    const MAX_TDX_QUOTE_BYTES: usize = 16 * 1024;
    if raw_quote.len() > MAX_TDX_QUOTE_BYTES {
        fail(
            report,
            errors,
            check_name,
            format!("{provider_name} TDX quote exceeds {MAX_TDX_QUOTE_BYTES} bytes"),
        );
        return None;
    }
    let collateral = match parse_tdx_dcap_collateral(collateral) {
        Ok(collateral) => collateral,
        Err(detail) => {
            fail(report, errors, check_name, detail);
            return None;
        }
    };
    let mut quote_bytes = raw_quote.as_slice();
    let quote = match dcap_rs::types::quote::Quote::read(&mut quote_bytes) {
        Ok(quote) => quote,
        Err(error) => {
            fail(
                report,
                errors,
                check_name,
                format!("{provider_name} TDX DCAP quote did not parse: {error:#}"),
            );
            return None;
        }
    };
    if quote.header.tee_type != TDX_TEE_TYPE || !matches!(quote.header.version.get(), 4 | 5) {
        fail(
            report,
            errors,
            check_name,
            format!(
                "{provider_name} TDX evidence must contain a TDX quote with version 4 or 5; got tee_type 0x{:x} and version {}",
                quote.header.tee_type,
                quote.header.version.get()
            ),
        );
        return None;
    }
    if quote_bytes.iter().any(|byte| *byte != 0) {
        fail(
            report,
            errors,
            check_name,
            format!(
                "{provider_name} TDX DCAP quote has {} non-zero trailing bytes",
                quote_bytes.len()
            ),
        );
        return None;
    }
    let collateral = match collateral.to_automata_collateral() {
        Ok(collateral) => collateral,
        Err(error) => {
            fail(report, errors, check_name, error);
            return None;
        }
    };
    match dcap_rs::verify_dcap_quote_with_policy(
        SystemTime::now(),
        collateral,
        quote,
        &tdx_dcap_verification_policy(),
    ) {
        Ok(output) if matches!(output.tcb_status, 0..=5 | 8 | 9) => {
            pass(report, check_name);
            Some(1u16 << output.tcb_status)
        }
        Ok(output) => {
            fail(
                report,
                errors,
                check_name,
                format!(
                    "{provider_name} TDX trusted computing base status {} cannot be configured",
                    output.tcb_status
                ),
            );
            None
        }
        Err(e) => {
            fail(
                report,
                errors,
                check_name,
                format!("{provider_name} TDX DCAP quote verification failed: {e:#}"),
            );
            None
        }
    }
}

fn tdx_dcap_verification_policy() -> dcap_rs::DcapVerificationPolicy {
    let mut policy = dcap_rs::DcapVerificationPolicy::production();
    policy.allow_debug = true;
    policy.with_tdx_tcb_revocation_policy(
        dcap_rs::TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch,
    )
}

pub(super) fn parse_tdx_dcap_collateral(
    collateral: &serde_json::Value,
) -> std::result::Result<TdxDcapCollateral, String> {
    let value = collateral.get("gcpTdxDcap").unwrap_or(collateral);
    if value.is_null() || value.as_object().is_some_and(|object| object.is_empty()) {
        return Err("TDX DCAP collateral is missing; expected collateral.gcpTdxDcap".to_string());
    }
    serde_json::from_value(value.clone())
        .map_err(|e| format!("TDX DCAP collateral did not parse: {e}"))
}

pub(super) fn verify_gcp_snp_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    trusted_amd_ark_roots: &[Vec<u8>],
    trusted_amd_ark_root_hashes: &[[u8; 32]],
    trusted_amd_snp_crls: &[Vec<u8>],
    current_time: SystemTime,
) {
    let auxiliary = evidence.and_then(|evidence| evidence.auxiliary.as_deref());
    verify_snp_vendor_report(
        report,
        errors,
        evidence,
        auxiliary,
        trusted_amd_ark_roots,
        trusted_amd_ark_root_hashes,
        trusted_amd_snp_crls,
        current_time,
        "gcp-tee-vendor-report",
        "GCP",
    );
}

pub(super) fn verify_azure_snp_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    collateral: &serde_json::Value,
    amd_snp_trust: AmdSnpTrust<'_>,
    current_time: SystemTime,
) {
    let cert_table = collateral
        .get("azureSnpCertTable")
        .and_then(serde_json::Value::as_str);
    verify_snp_vendor_report(
        report,
        errors,
        evidence,
        cert_table,
        amd_snp_trust.ark_roots,
        amd_snp_trust.ark_root_hashes,
        amd_snp_trust.crls,
        current_time,
        "azure-tee-vendor-report",
        "Azure",
    );
}

#[allow(clippy::too_many_arguments)]
fn verify_snp_vendor_report(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: Option<&TeeEvidence>,
    encoded_cert_table: Option<&str>,
    trusted_amd_ark_roots: &[Vec<u8>],
    trusted_amd_ark_root_hashes: &[[u8; 32]],
    trusted_amd_snp_crls: &[Vec<u8>],
    current_time: SystemTime,
    check_name: &str,
    provider_name: &str,
) {
    let Some(evidence) = evidence else {
        fail(
            report,
            errors,
            check_name,
            format!("{provider_name} SNP TEE evidence is missing"),
        );
        return;
    };
    let snp_report = match decode_b64("teeEvidence.report", &evidence.report) {
        Ok(bytes) => bytes,
        Err(e) => {
            fail(report, errors, check_name, e.to_string());
            return;
        }
    };
    let Some(encoded_cert_table) = encoded_cert_table else {
        fail(
            report,
            errors,
            check_name,
            format!("{provider_name} SNP certificate table is missing"),
        );
        return;
    };
    let auxblob = match decode_b64("SNP certificate table", encoded_cert_table) {
        Ok(bytes) => bytes,
        Err(e) => {
            fail(report, errors, check_name, e.to_string());
            return;
        }
    };
    if trusted_amd_ark_roots.is_empty() && trusted_amd_ark_root_hashes.is_empty() {
        fail(
            report,
            errors,
            check_name,
            "no trusted AMD SEV-SNP ARK root certificates or root hashes configured".to_string(),
        );
        return;
    }
    match verify_snp_report_with_aux_certs(
        current_time,
        &snp_report,
        &auxblob,
        trusted_amd_ark_roots,
        trusted_amd_ark_root_hashes,
        trusted_amd_snp_crls,
    ) {
        Ok(()) => match verified_snp_attribute_states(&snp_report) {
            Ok(_) => pass(report, check_name),
            Err(detail) => fail(report, errors, check_name, detail),
        },
        Err(detail) => fail(report, errors, check_name, detail),
    }
}

pub(super) fn verify_snp_report_with_aux_certs(
    current_time: SystemTime,
    report: &[u8],
    auxblob: &[u8],
    trusted_amd_ark_roots: &[Vec<u8>],
    trusted_amd_ark_root_hashes: &[[u8; 32]],
    trusted_amd_snp_crls: &[Vec<u8>],
) -> std::result::Result<(), String> {
    if report.len() != SNP_REPORT_SIZE {
        return Err(format!(
            "GCP SNP report has invalid size: got {}, expected {SNP_REPORT_SIZE}",
            report.len()
        ));
    }
    let sig_algo = read_le_u32(report, SNP_REPORT_SIG_ALGO_OFFSET, "SNP sig_algo")?;
    if sig_algo != SNP_SIG_ALGO_ECDSA_P384_SHA384 {
        return Err(format!(
            "GCP SNP report sig_algo is {sig_algo}, expected ECDSA P-384 SHA-384 ({SNP_SIG_ALGO_ECDSA_P384_SHA384})"
        ));
    }
    verify_snp_report_policy(report)?;
    let expected_product = amd_snp_kds_product(report)?;

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
        current_time,
        ark,
        ask,
        vek,
        signer,
        expected_product,
        AmdSnpTrust {
            ark_roots: trusted_amd_ark_roots,
            ark_root_hashes: trusted_amd_ark_root_hashes,
            crls: trusted_amd_snp_crls,
        },
    )?;
    verify_snp_vek_extensions(vek, report, signer)?;
    verify_snp_report_signature(vek, report)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnpSigningKeyType {
    Vcek,
    Vlek,
}

pub(super) fn snp_signing_key_type(
    report: &[u8],
) -> std::result::Result<SnpSigningKeyType, String> {
    let key_settings = read_le_u32(report, SNP_REPORT_KEY_SETTINGS_OFFSET, "SNP key_settings")?;
    match key_settings & 0b11100 {
        0b000 => Ok(SnpSigningKeyType::Vcek),
        0b100 => Ok(SnpSigningKeyType::Vlek),
        value => Err(format!("unknown SNP signing key type bits 0x{value:x}")),
    }
}

pub(super) fn verify_snp_report_policy(report: &[u8]) -> std::result::Result<(), String> {
    let version = read_le_u32(report, SNP_REPORT_VERSION_OFFSET, "SNP report version")?;
    if !(2..=5).contains(&version) {
        return Err(format!(
            "unsupported SNP report version {version}; expected a version from 2 through 5"
        ));
    }
    let policy = read_le_u64(report, SNP_REPORT_POLICY_OFFSET, "SNP policy")?;
    if policy & (1 << 17) == 0 || policy >> 26 != 0 {
        return Err(format!(
            "SNP policy reserved bits are invalid: 0x{policy:016x}"
        ));
    }
    let vmpl = read_le_u32(report, SNP_REPORT_VMPL_OFFSET, "SNP VMPL")?;
    if vmpl != 0 {
        return Err(format!("SNP report VMPL is {vmpl}, expected VMPL 0"));
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct AmdSnpCertTable {
    pub(super) ark: Option<Vec<u8>>,
    pub(super) ask: Option<Vec<u8>>,
    pub(super) vcek: Option<Vec<u8>>,
    pub(super) vlek: Option<Vec<u8>>,
}

pub(super) fn parse_amd_snp_cert_table(
    auxblob: &[u8],
) -> std::result::Result<AmdSnpCertTable, String> {
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

pub(super) fn verify_amd_snp_cert_chain(
    current_time: SystemTime,
    ark_der: &[u8],
    ask_der: &[u8],
    vek_der: &[u8],
    signer: SnpSigningKeyType,
    expected_product: &str,
    trust: AmdSnpTrust<'_>,
) -> std::result::Result<(), String> {
    let ark_hash: [u8; 32] = Sha256::digest(ark_der).into();
    if !trust
        .ark_roots
        .iter()
        .any(|trusted| trusted.as_slice() == ark_der)
        && !trust.ark_root_hashes.contains(&ark_hash)
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
    let validation_time = asn1_time(current_time)?;
    for (label, cert) in [("SNP ARK", &ark), ("SNP ASK", &ask), ("SNP VEK", &vek)] {
        if cert.version() != X509Version::V3 {
            return Err(format!("{label} certificate is not X.509 version 3"));
        }
        if !cert.validity().is_valid_at(validation_time) {
            return Err(format!(
                "{label} certificate is not valid at the verification time"
            ));
        }
    }

    if ark.subject() != ark.issuer() {
        return Err("SNP ARK trusted root is not self-issued".to_string());
    }
    let ark_common_name = certificate_common_name(&ark, "SNP ARK")?;
    let expected_ark_common_name = format!("ARK-{expected_product}");
    if ark_common_name != expected_ark_common_name {
        return Err(format!(
            "SNP ARK common name is {ark_common_name:?}, expected {expected_ark_common_name:?}"
        ));
    }
    verify_ca_certificate_role(&ark, "SNP ARK", 1)?;
    let ark_key_usage = ark
        .key_usage()
        .map_err(|error| format!("SNP ARK Key Usage is invalid: {error}"))?
        .ok_or_else(|| "SNP ARK is missing Key Usage".to_string())?;
    if !ark_key_usage.value.crl_sign() {
        return Err("SNP ARK Key Usage does not permit CRL signing".to_string());
    }
    verify_amd_snp_cert_signature(ark_der, &ark, &ark, "SNP ARK self-signature")?;
    if ask.issuer() != ark.subject() {
        return Err("SNP ASK issuer does not match ARK subject".to_string());
    }
    let ask_common_name = certificate_common_name(&ask, "SNP ASK")?;
    let expected_ask_common_name = format!("SEV-{expected_product}");
    if ask_common_name != expected_ask_common_name {
        return Err(format!(
            "SNP ASK common name is {ask_common_name:?}, expected {expected_ask_common_name:?}"
        ));
    }
    verify_ca_certificate_role(&ask, "SNP ASK", 0)?;
    verify_amd_snp_cert_signature(ask_der, &ask, &ark, "SNP ASK signature")?;
    verify_amd_snp_crls(&ark, &ask, trust.crls, validation_time)?;
    if vek.issuer() != ask.subject() {
        return Err("SNP VEK issuer does not match ASK subject".to_string());
    }
    verify_end_entity_certificate_role(&vek, "SNP VEK")?;
    let expected_common_name = match signer {
        SnpSigningKeyType::Vcek => "SEV-VCEK",
        SnpSigningKeyType::Vlek => "SEV-VLEK",
    };
    let actual_common_name = certificate_common_name(&vek, "SNP VEK")?;
    if actual_common_name != expected_common_name {
        return Err(format!(
            "SNP VEK common name is {actual_common_name:?}, expected {expected_common_name:?}"
        ));
    }
    verify_amd_snp_cert_signature(vek_der, &vek, &ask, "SNP VEK signature")?;
    Ok(())
}

fn asn1_time(time: SystemTime) -> std::result::Result<ASN1Time, String> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "verification time is before the Unix epoch".to_string())?
        .as_secs();
    let seconds = i64::try_from(seconds)
        .map_err(|_| "verification time does not fit an X.509 timestamp".to_string())?;
    ASN1Time::from_timestamp(seconds)
        .map_err(|error| format!("verification time is not a valid X.509 timestamp: {error}"))
}

fn certificate_common_name<'a>(
    cert: &'a X509Certificate<'_>,
    label: &str,
) -> std::result::Result<&'a str, String> {
    let mut names = cert.subject().iter_common_name();
    let common_name = names
        .next()
        .ok_or_else(|| format!("{label} subject is missing a common name"))?
        .as_str()
        .map_err(|error| format!("{label} common name is not a string: {error}"))?;
    if names.next().is_some() {
        return Err(format!("{label} subject contains multiple common names"));
    }
    Ok(common_name)
}

fn verify_amd_snp_crls(
    ark: &X509Certificate<'_>,
    ask: &X509Certificate<'_>,
    crl_der_values: &[Vec<u8>],
    current_time: ASN1Time,
) -> std::result::Result<(), String> {
    if crl_der_values.is_empty() {
        return Err("no AMD SNP certificate revocation list was supplied".to_string());
    }
    let public_key = ParsedRsaPublicKey::new(
        &RSA_PSS_2048_8192_SHA384,
        ark.tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
    )
    .map_err(|error| format!("SNP ARK key is not RSA PKCS#1: {error}"))?;
    let mut matching_errors = Vec::new();
    for crl_der in crl_der_values {
        let (_, crl) = match parse_x509_crl(crl_der) {
            Ok(parsed) => parsed,
            Err(error) => {
                matching_errors.push(format!("AMD SNP CRL did not parse: {error}"));
                continue;
            }
        };
        if crl.issuer() != ark.subject() {
            continue;
        }
        if crl.signature_algorithm.algorithm.to_id_string() != "1.2.840.113549.1.1.10"
            || crl.tbs_cert_list.signature.algorithm.to_id_string() != "1.2.840.113549.1.1.10"
        {
            matching_errors.push("AMD SNP CRL does not declare RSA-PSS".to_string());
            continue;
        }
        if crl.last_update() > current_time {
            matching_errors.push("AMD SNP CRL is not valid yet".to_string());
            continue;
        }
        let Some(next_update) = crl.next_update() else {
            matching_errors.push("AMD SNP CRL is missing nextUpdate".to_string());
            continue;
        };
        if current_time > next_update {
            matching_errors.push("AMD SNP CRL is stale".to_string());
            continue;
        }
        if let Err(error) = public_key.verify_sig(
            crl.tbs_cert_list.as_ref(),
            crl.signature_value.data.as_ref(),
        ) {
            matching_errors.push(format!(
                "AMD SNP CRL signature verification failed: {error}"
            ));
            continue;
        }
        if crl
            .iter_revoked_certificates()
            .any(|revoked| revoked.serial() == &ask.tbs_certificate.serial)
        {
            return Err(format!(
                "SNP ASK certificate serial {} is revoked",
                ask.raw_serial_as_string()
            ));
        }
        return Ok(());
    }
    let detail = if matching_errors.is_empty() {
        "no supplied AMD SNP CRL was issued by the trusted ARK".to_string()
    } else {
        matching_errors.join("; ")
    };
    Err(format!(
        "no valid AMD SNP CRL matched the trusted ARK: {detail}"
    ))
}

pub(super) fn verify_amd_snp_cert_signature(
    cert_der: &[u8],
    cert: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    label: &str,
) -> std::result::Result<(), String> {
    const RSA_PSS_OID: &str = "1.2.840.113549.1.1.10";
    if cert.signature_algorithm.algorithm.to_id_string() != RSA_PSS_OID
        || cert.tbs_certificate.signature.algorithm.to_id_string() != RSA_PSS_OID
    {
        return Err(format!("{label} does not declare RSA-PSS"));
    }
    // This AWS-LC parameter requires SHA-384 for both the message and MGF1,
    // with a salt equal to the 48-byte SHA-384 output. That preserves the AMD
    // certificate-chain checks previously configured explicitly below.
    let public_key = ParsedRsaPublicKey::new(
        &RSA_PSS_2048_8192_SHA384,
        issuer
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
    )
    .map_err(|e| format!("{label} issuer key is not RSA PKCS#1: {e}"))?;
    let tbs_der = tbs_certificate_der(cert_der).map_err(|e| format!("{label}: {e}"))?;
    public_key
        .verify_sig(tbs_der, cert.signature_value.data.as_ref())
        .map_err(|e| format!("{label} failed: {e}"))
}

pub(super) fn tbs_certificate_der(cert_der: &[u8]) -> std::result::Result<&[u8], String> {
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

pub(super) fn der_tlv(
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

pub(super) fn verify_snp_vek_extensions(
    vek_der: &[u8],
    report: &[u8],
    signer: SnpSigningKeyType,
) -> std::result::Result<(), String> {
    let (_, vek) = X509Certificate::from_der(vek_der)
        .map_err(|e| format!("SNP VEK certificate did not parse: {e}"))?;
    let product = amd_snp_kds_product(report)?;
    check_snp_product_extension(&vek, product)?;
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

pub(super) struct SnpTcb {
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

impl SnpTcb {
    pub(super) fn from_report(report: &[u8]) -> std::result::Result<Self, String> {
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

pub(super) fn check_snp_tcb_extension(
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
        return Err(format!("SNP VEK is missing required {name} extension"));
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

pub(super) fn check_snp_octet_extension(
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
        return Err(format!("SNP VEK is missing required {name} extension"));
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

fn check_snp_product_extension(
    cert: &X509Certificate<'_>,
    expected_product: &str,
) -> std::result::Result<(), String> {
    let ext = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == "1.3.6.1.4.1.3704.1.2")
        .ok_or_else(|| "SNP VEK is missing required productName extension".to_string())?;
    let value = match ext.value {
        [tag @ (0x0c | 0x16), length, value @ ..]
            if *tag != 0 && usize::from(*length) == value.len() =>
        {
            value
        }
        raw => {
            return Err(format!(
                "SNP VEK productName extension has unsupported encoding: 0x{}",
                hex::encode(raw)
            ))
        }
    };
    let product = std::str::from_utf8(value)
        .map_err(|error| format!("SNP VEK productName is not UTF-8: {error}"))?;
    if product != expected_product && !product.starts_with(&format!("{expected_product}-")) {
        return Err(format!(
            "SNP VEK productName {product:?} does not match report product {expected_product:?}"
        ));
    }
    Ok(())
}

pub(super) fn verify_snp_report_signature(
    vek_der: &[u8],
    report: &[u8],
) -> std::result::Result<(), String> {
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

pub(super) fn parse_snp_report_signature(
    report: &[u8],
) -> std::result::Result<P384Signature, String> {
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

pub(super) fn le_72_to_be_48(value: &[u8]) -> [u8; 48] {
    debug_assert_eq!(value.len(), 72);
    let mut out = [0u8; 48];
    for idx in 0..48 {
        out[47 - idx] = value[idx];
    }
    out
}

pub(super) fn read_le_u32(
    data: &[u8],
    offset: usize,
    field: &str,
) -> std::result::Result<u32, String> {
    let bytes = read_exact_at(data, offset, 4, field)?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("slice length")))
}

pub(super) fn read_le_u64(
    data: &[u8],
    offset: usize,
    field: &str,
) -> std::result::Result<u64, String> {
    let bytes = read_exact_at(data, offset, 8, field)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("slice length")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerifiedAmdSnpSecurityState {
    pub(super) debug: bool,
    pub(super) migrate_ma: bool,
    pub(super) tcb_values: [u8; 32],
    pub(super) platform_info: u64,
    pub(super) cpuid: u32,
}

pub(super) fn verified_snp_security_state(
    report: &[u8],
) -> std::result::Result<VerifiedAmdSnpSecurityState, String> {
    if report.len() != SNP_REPORT_SIZE {
        return Err(format!(
            "SNP report has invalid size: got {}, expected {SNP_REPORT_SIZE}",
            report.len()
        ));
    }
    let version = read_le_u32(report, SNP_REPORT_VERSION_OFFSET, "SNP version")?;
    if !(3..=5).contains(&version) {
        return Err(format!(
            "SNP report version {version} is unsupported; expected a version from 3 through 5"
        ));
    }
    let policy = read_le_u64(report, SNP_REPORT_POLICY_OFFSET, "SNP policy")?;
    if policy & (1 << 17) == 0 || policy >> 26 != 0 {
        return Err(format!(
            "SNP policy reserved bits are invalid: 0x{policy:016x}"
        ));
    }
    let vmpl = read_le_u32(report, SNP_REPORT_VMPL_OFFSET, "SNP VMPL")?;
    if vmpl != 0 {
        return Err(format!("SNP VMPL {vmpl} is unsupported; expected 0"));
    }
    let signature_algorithm = read_le_u32(
        report,
        SNP_REPORT_SIG_ALGO_OFFSET,
        "SNP signature algorithm",
    )?;
    if signature_algorithm != SNP_SIG_ALGO_ECDSA_P384_SHA384 {
        return Err(format!(
            "SNP signature algorithm is {signature_algorithm}, expected {SNP_SIG_ALGO_ECDSA_P384_SHA384}"
        ));
    }
    let key_settings = read_le_u32(report, SNP_REPORT_KEY_SETTINGS_OFFSET, "SNP key settings")?;
    let signing_key = (key_settings >> 2) & 7;
    if key_settings >> 5 != 0 || signing_key > 1 || key_settings & 2 != 0 {
        return Err(format!(
            "SNP key settings contain unsupported bits: 0x{key_settings:08x}"
        ));
    }
    require_zero_bytes(report, SNP_REPORT_RESERVED_1_OFFSET, 4, "SNP reserved1")?;

    let report_id_ma = read_exact_at(
        report,
        SNP_REPORT_ID_MA_OFFSET,
        SNP_REPORT_ID_MA_LEN,
        "SNP report_id_ma",
    )?;
    if report_id_ma.iter().any(|byte| *byte != 0) {
        return Err(
            "SNP REPORT_ID_MA is nonzero; migration-agent association is unsupported".into(),
        );
    }

    let platform_info = read_le_u64(report, SNP_REPORT_PLATFORM_INFO_OFFSET, "SNP platform_info")?;
    if platform_info & !atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_SUPPORTED_MASK != 0 {
        return Err(format!(
            "SNP PLATFORM_INFO contains unsupported bits: 0x{platform_info:016x}"
        ));
    }

    let cpuid_bytes = read_exact_at(report, SNP_REPORT_CPUID_OFFSET, 3, "SNP CPUID")?;
    let cpuid = (u32::from(cpuid_bytes[0]) << 16)
        | (u32::from(cpuid_bytes[1]) << 8)
        | u32::from(cpuid_bytes[2]);
    if cpuid_bytes[0] != 0x19 || cpuid_bytes[1] > 0x1f {
        return Err(format!(
            "SNP CPUID 0x{cpuid:06x} is not a supported Milan or Genoa processor"
        ));
    }
    require_zero_bytes(
        report,
        SNP_REPORT_CPUID_RESERVED_OFFSET,
        SNP_REPORT_CPUID_RESERVED_LEN,
        "SNP CPUID reserved field",
    )?;
    require_zero_bytes(
        report,
        SNP_REPORT_CURRENT_VERSION_RESERVED_OFFSET,
        1,
        "SNP current version reserved field",
    )?;
    require_zero_bytes(
        report,
        SNP_REPORT_COMMITTED_VERSION_RESERVED_OFFSET,
        1,
        "SNP committed version reserved field",
    )?;

    let current = normalized_snp_tcb(report, SNP_REPORT_CURRENT_TCB_OFFSET, "current_tcb")?;
    let reported = normalized_snp_tcb(report, SNP_REPORT_REPORTED_TCB_OFFSET, "reported_tcb")?;
    let committed = normalized_snp_tcb(report, SNP_REPORT_COMMITTED_TCB_OFFSET, "committed_tcb")?;
    let launch = normalized_snp_tcb(report, SNP_REPORT_LAUNCH_TCB_OFFSET, "launch_tcb")?;
    if !snp_tcb_lane_meets(committed, reported) {
        return Err(format!(
            "SNP reported_tcb 0x{reported:08x} exceeds committed_tcb 0x{committed:08x}"
        ));
    }
    if !snp_tcb_lane_meets(current, committed) {
        return Err(format!(
            "SNP committed_tcb 0x{committed:08x} exceeds current_tcb 0x{current:08x}"
        ));
    }
    let mut tcb_values = [0u8; 32];
    for (index, value) in [current, reported, committed, launch]
        .into_iter()
        .enumerate()
    {
        tcb_values[index * 8..index * 8 + 8].copy_from_slice(&value.to_be_bytes());
    }

    let reserved_offset = if version < 5 {
        SNP_REPORT_LAUNCH_MITIGATION_VECTOR_OFFSET
    } else {
        SNP_REPORT_CURRENT_MITIGATION_VECTOR_END
    };
    require_zero_bytes(
        report,
        reserved_offset,
        SNP_REPORT_SIGNATURE_OFFSET - reserved_offset,
        "SNP mitigation-vector reserved field",
    )?;

    Ok(VerifiedAmdSnpSecurityState {
        debug: policy & SNP_POLICY_DEBUG != 0,
        migrate_ma: policy & SNP_POLICY_MIGRATE_MA != 0,
        tcb_values,
        platform_info,
        cpuid,
    })
}

fn normalized_snp_tcb(
    report: &[u8],
    offset: usize,
    field: &str,
) -> std::result::Result<u64, String> {
    let raw = read_exact_at(report, offset, 8, field)?;
    if raw[2..6].iter().any(|byte| *byte != 0) {
        return Err(format!(
            "SNP {field} contains nonzero reserved or unsupported fields: 0x{}",
            hex::encode(raw)
        ));
    }
    Ok(u64::from(raw[0])
        | (u64::from(raw[1]) << 8)
        | (u64::from(raw[6]) << 16)
        | (u64::from(raw[7]) << 24))
}

fn snp_tcb_lane_meets(actual: u64, minimum: u64) -> bool {
    (0..4).all(|index| ((actual >> (index * 8)) & 0xff) >= ((minimum >> (index * 8)) & 0xff))
}

fn require_zero_bytes(
    report: &[u8],
    offset: usize,
    len: usize,
    field: &str,
) -> std::result::Result<(), String> {
    let value = read_exact_at(report, offset, len, field)?;
    if value.iter().any(|byte| *byte != 0) {
        return Err(format!("{field} contains nonzero bytes"));
    }
    Ok(())
}

pub(super) fn verified_snp_attribute_states(
    report: &[u8],
) -> std::result::Result<(bool, bool), String> {
    let state = verified_snp_security_state(report)?;
    Ok((state.debug, state.migrate_ma))
}

pub(super) fn verified_tee_attribute_states(
    tee: &str,
    report: &[u8],
) -> std::result::Result<[bool; 3], String> {
    match tee {
        "tdx" => {
            let report_start = gcp_tdx_report_start(report)?;
            let attributes = read_exact_at(
                report,
                report_start + TDX_REPORT_ATTRIBUTES_OFFSET,
                8,
                "TDX TD_ATTRIBUTES",
            )?;
            if attributes[0] & !0x01 != 0
                || attributes[1] != 0
                || attributes[2] != 0
                || attributes[3] & 0x2f != 0
                || attributes[4] != 0
                || attributes[5] != 0
                || attributes[6] != 0
                || attributes[7] & 0x7f != 0
            {
                return Err("TDX TD_ATTRIBUTES has reserved bits set".into());
            }
            if attributes[3] & 0x10 == 0 {
                return Err("TDX TD_ATTRIBUTES.SEPT_VE_DISABLE is not set".into());
            }
            let version = read_le_u16_opt(report, 0);
            let body_type = read_le_u16_opt(report, TDX_QUOTE_HEADER_LEN);
            let td15 = matches!(
                (version, body_type),
                (Some(5), Some(TDX_BODY_TD_REPORT15_TYPE))
            ) || (!matches!(version, Some(4 | 5)) && report.len() >= 648);
            if td15 {
                let mr_service_td = read_exact_at(
                    report,
                    report_start + TDX_REPORT15_MR_SERVICETD_OFFSET,
                    48,
                    "TDX MR_SERVICETD",
                )?;
                if mr_service_td.iter().any(|byte| *byte != 0) {
                    return Err("TDX MR_SERVICETD is nonzero; migration is unsupported".into());
                }
            }
            Ok([attributes[0] & 0x01 != 0, false, false])
        }
        "sev-snp" => {
            let (debug, migrate_ma) = verified_snp_attribute_states(report)?;
            Ok([false, debug, migrate_ma])
        }
        "emulation" | "none" => Ok([false; 3]),
        other => Err(format!(
            "verified TEE attribute extraction is unsupported for tee={other}"
        )),
    }
}

pub(super) fn read_exact_at<'a>(
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

pub(super) fn verify_azure_maa_jwt_binding(
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

    let mut key_errors = Vec::new();
    for key_bytes in trusted_maa_keys {
        let key = match parse_rsa_public_key(key_bytes) {
            Ok(key) => key,
            Err(detail) => {
                key_errors.push(detail);
                continue;
            }
        };
        if key.verify_sig(signing_input.as_bytes(), &signature).is_ok() {
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

pub(super) fn verify_azure_maa_session_binding(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    binding: &AkBinding,
    trusted_keys: &[AzureMaaTrustKey],
    tee: &str,
) {
    let parsed_binding = match parse_azure_maa_binding(binding) {
        Ok(binding) => binding,
        Err(detail) => {
            fail(report, errors, "azure-maa-trust-selection", detail);
            return;
        }
    };
    let (_, header, claims, _) = match parse_azure_maa_jwt(&parsed_binding.jwt) {
        Ok(parsed) => parsed,
        Err(detail) => {
            fail(report, errors, "azure-maa-trust-selection", detail);
            return;
        }
    };
    let Some(kid) = header.kid.as_deref() else {
        fail(
            report,
            errors,
            "azure-maa-trust-selection",
            "MAA JWT kid is missing".to_string(),
        );
        return;
    };
    let matching_keys = trusted_keys
        .iter()
        .filter(|key| key.kid == kid && key.issuer == claims.iss)
        .collect::<Vec<_>>();
    if matching_keys.is_empty() {
        fail(
            report,
            errors,
            "azure-maa-trust-selection",
            format!(
                "no trusted MAA key matches kid={kid} and issuer={}",
                claims.iss
            ),
        );
        return;
    }
    if matching_keys.len() != 1 {
        fail(
            report,
            errors,
            "azure-maa-trust-selection",
            format!(
                "{} trusted MAA keys match kid={kid} and issuer={}; expected exactly one",
                matching_keys.len(),
                claims.iss
            ),
        );
        return;
    }
    let key = matching_keys[0];
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(error) => {
            fail(
                report,
                errors,
                "azure-maa-trust-selection",
                format!("system clock is before Unix epoch: {error}"),
            );
            return;
        }
    };
    if now > key.not_after {
        fail(
            report,
            errors,
            "azure-maa-trust-selection",
            format!("trusted MAA key kid={kid} expired at {}", key.not_after),
        );
        return;
    }
    pass(report, "azure-maa-trust-selection");
    verify_azure_maa_jwt_binding(
        report,
        errors,
        binding,
        std::slice::from_ref(&key.public_key),
        tee,
    );
}

pub(super) fn verify_azure_tee_var_data_binding(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: &TeeEvidence,
    tee: &str,
) {
    let raw_report = match decode_b64("teeEvidence.report", &evidence.report) {
        Ok(report) => report,
        Err(error) => {
            fail(
                report,
                errors,
                "azure-tee-var-data-binding",
                error.to_string(),
            );
            return;
        }
    };
    let Some(auxiliary) = evidence.auxiliary.as_deref() else {
        fail(
            report,
            errors,
            "azure-tee-var-data-binding",
            "Azure HCL var_data is missing".to_string(),
        );
        return;
    };
    let var_data = match decode_b64("teeEvidence.auxiliary", auxiliary) {
        Ok(value) => value,
        Err(error) => {
            fail(
                report,
                errors,
                "azure-tee-var-data-binding",
                error.to_string(),
            );
            return;
        }
    };
    let report_data = match tee {
        "tdx" => gcp_tdx_report_start(&raw_report).and_then(|start| {
            read_exact_at(
                &raw_report,
                start + TDX_REPORT_REPORT_DATA_OFFSET,
                64,
                "TDX report_data",
            )
            .map(|value| value.to_vec())
        }),
        "sev-snp" => {
            read_exact_at(&raw_report, 0x50, 64, "SNP report_data").map(|value| value.to_vec())
        }
        other => Err(format!("unsupported Azure TEE type {other}")),
    };
    let report_data = match report_data {
        Ok(value) => value,
        Err(detail) => {
            fail(report, errors, "azure-tee-var-data-binding", detail);
            return;
        }
    };
    let expected: [u8; 32] = Sha256::digest(&var_data).into();
    let valid = report_data[..32] == expected && report_data[32..] == [0u8; 32];
    check(
        report,
        errors,
        "azure-tee-var-data-binding",
        valid,
        "raw TEE report_data does not equal sha256(HCL var_data) followed by 32 zero bytes"
            .to_string(),
    );
}

pub(super) fn verify_azure_tee_ak_binding(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    evidence: &TeeEvidence,
    binding: &AkBinding,
    tee: &str,
) {
    let parsed_binding = match parse_azure_maa_binding(binding) {
        Ok(binding) => binding,
        Err(detail) => {
            fail(report, errors, "azure-tee-ak-binding", detail);
            return;
        }
    };
    let Some(auxiliary) = evidence.auxiliary.as_deref() else {
        fail(
            report,
            errors,
            "azure-tee-ak-binding",
            "Azure TEE evidence is missing HCL var_data".to_string(),
        );
        return;
    };
    let auxiliary = match decode_b64("teeEvidence.auxiliary", auxiliary) {
        Ok(auxiliary) => auxiliary,
        Err(error) => {
            fail(report, errors, "azure-tee-ak-binding", error.to_string());
            return;
        }
    };
    let binding_hcl_var_data =
        match decode_b64("akBinding.hclVarData", &parsed_binding.hcl_var_data) {
            Ok(hcl_var_data) => hcl_var_data,
            Err(error) => {
                fail(report, errors, "azure-tee-ak-binding", error.to_string());
                return;
            }
        };
    if auxiliary != binding_hcl_var_data {
        fail(
            report,
            errors,
            "azure-tee-ak-binding",
            "teeEvidence.auxiliary differs from akBinding HCL var_data".to_string(),
        );
        return;
    }
    pass(report, "azure-tee-ak-binding");
    verify_azure_tee_var_data_binding(report, errors, evidence, tee);
}

pub(super) fn parse_azure_maa_binding(
    binding: &AkBinding,
) -> std::result::Result<AzureMaaAkBinding, String> {
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

pub(super) fn parse_azure_maa_jwt(
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

pub(super) fn azure_report_data_claim(
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

pub(super) fn parse_rsa_public_key(
    key_bytes: &[u8],
) -> std::result::Result<ParsedRsaPublicKey, String> {
    if let Ok(key) = ParsedRsaPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key_bytes) {
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

pub(super) fn verify_azure_hclak_quote_signature(
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

    match public_key.verify_sig(body, &signature) {
        Ok(()) => pass(report, "tpm-quote-signature"),
        Err(e) => fail(
            report,
            errors,
            "tpm-quote-signature",
            format!("TPM quote signature did not verify under Azure HCLAkPub: {e}"),
        ),
    }
}

pub(super) fn verify_azure_hclak_certify_signature(
    report: &mut VerificationReport,
    errors: &mut Vec<VerificationError>,
    binding: &AkBinding,
    tpm2b_attest: &[u8],
    tpm_signature: &[u8],
) {
    let body = match tpm2b_attest_body(tpm2b_attest) {
        Ok(body) => body,
        Err(detail) => {
            fail(report, errors, "tpm-certify-signature", detail);
            return;
        }
    };
    let public_key = match parse_azure_hclak_public_key(binding) {
        Ok(key) => key,
        Err(detail) => {
            fail(report, errors, "tpm-certify-signature", detail);
            return;
        }
    };
    let signature = match parse_tpmt_signature_rsassa_sha256(tpm_signature) {
        Ok(signature) => signature,
        Err(detail) => {
            fail(report, errors, "tpm-certify-signature", detail);
            return;
        }
    };
    match public_key.verify_sig(body, &signature) {
        Ok(()) => pass(report, "tpm-certify-signature"),
        Err(error) => fail(
            report,
            errors,
            "tpm-certify-signature",
            format!("TPM Certify signature did not verify under Azure HCLAkPub: {error}"),
        ),
    }
}

pub(super) fn parse_azure_hclak_public_key(
    binding: &AkBinding,
) -> std::result::Result<ParsedRsaPublicKey, String> {
    let binding = parse_azure_maa_binding(binding)?;
    let hcl_var_data =
        decode_b64("akBinding.hclVarData", &binding.hcl_var_data).map_err(|e| e.to_string())?;
    let var_data: AzureHclVarData = serde_json::from_slice(&hcl_var_data)
        .map_err(|e| format!("Azure hclVarData JSON did not parse: {e}"))?;
    let matching_keys = var_data
        .keys
        .iter()
        .filter(|key| key.kid.as_deref() == Some("HCLAkPub"))
        .collect::<Vec<_>>();
    if matching_keys.len() != 1 {
        return Err(format!(
            "Azure hclVarData contains {} HCLAkPub entries; expected exactly one",
            matching_keys.len()
        ));
    }
    let hcl_ak = matching_keys[0];
    if hcl_ak.kty.as_deref() != Some("RSA") {
        return Err(format!(
            "Azure HCLAkPub kty is {}, expected RSA",
            hcl_ak.kty.as_deref().unwrap_or("<missing>")
        ));
    }
    rsa_public_key_from_jwk(hcl_ak, "Azure HCLAkPub")
}

pub(super) fn rsa_public_key_from_jwk(
    jwk: &AzureJwk,
    label: &str,
) -> std::result::Result<ParsedRsaPublicKey, String> {
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
    RsaPublicKeyComponents { n, e }
        .to_parsed_public_key(&RSA_PKCS1_2048_8192_SHA256)
        .map_err(|e| format!("{label} RSA key is invalid: {e}"))
}

pub(super) fn verify_tpm_quote(
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

    let supplied_indices = pcrs.iter().map(|pcr| pcr.index).collect::<Vec<_>>();
    let supplied_indices_valid = supplied_indices.iter().all(|index| *index <= 23)
        && supplied_indices.windows(2).all(|pair| pair[0] < pair[1]);
    if !supplied_indices_valid {
        fail(
            report,
            errors,
            "tpm-quote-pcr-selection",
            "supplied PCR values must have unique, strictly increasing indices in 0..=23"
                .to_string(),
        );
        return;
    }
    if supplied_indices != parsed.sha256_pcr_indices {
        fail(
            report,
            errors,
            "tpm-quote-pcr-selection",
            format!(
                "supplied PCR indices {supplied_indices:?} differ from Quote SHA-256 selection {:?}",
                parsed.sha256_pcr_indices
            ),
        );
        return;
    }
    pass(report, "tpm-quote-pcr-selection");

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

pub(super) fn verify_tpm_quote_signature(
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

pub(super) fn tpm2b_attest_body(tpm2b_attest: &[u8]) -> std::result::Result<&[u8], String> {
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

pub(super) fn parse_tpmt_public_ecc_p256(
    tpmt_public: &[u8],
) -> std::result::Result<P256VerifyingKey, String> {
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

pub(super) fn read_tpmt_sym_def_object(
    reader: &mut ByteReader<'_>,
) -> std::result::Result<(), String> {
    let alg = reader.read_u16("TPMT_SYM_DEF_OBJECT.algorithm")?;
    if alg != TPM_ALG_NULL {
        reader.read_u16("TPMT_SYM_DEF_OBJECT.keyBits")?;
        reader.read_u16("TPMT_SYM_DEF_OBJECT.mode")?;
    }
    Ok(())
}

pub(super) fn read_tpmt_scheme(
    reader: &mut ByteReader<'_>,
    field: &'static str,
) -> std::result::Result<(), String> {
    let scheme = reader.read_u16(field)?;
    if scheme != TPM_ALG_NULL {
        reader.read_u16(field)?;
    }
    Ok(())
}

pub(super) fn parse_tpmt_signature_ecdsa_sha256(
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

pub(super) fn parse_tpmt_signature_rsassa_sha256(
    tpm_signature: &[u8],
) -> std::result::Result<Vec<u8>, String> {
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
    if sig.is_empty() {
        return Err("RSA signature is empty".to_string());
    }
    Ok(sig.to_vec())
}

#[derive(Debug)]
pub(super) struct ParsedTpmQuote {
    extra_data: Vec<u8>,
    sha256_pcr_indices: Vec<u8>,
    pcr_digest: Vec<u8>,
}

pub(super) fn parse_tpm_quote(tpm2b_attest: &[u8]) -> std::result::Result<ParsedTpmQuote, String> {
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

pub(super) struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub(super) fn read_u8(&mut self, field: &'static str) -> std::result::Result<u8, String> {
        let bytes = self.read_exact(field, 1)?;
        Ok(bytes[0])
    }

    pub(super) fn read_u16(&mut self, field: &'static str) -> std::result::Result<u16, String> {
        let bytes = self.read_exact(field, 2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn read_u32(&mut self, field: &'static str) -> std::result::Result<u32, String> {
        let bytes = self.read_exact(field, 4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn read_tpm2b(
        &mut self,
        field: &'static str,
    ) -> std::result::Result<&'a [u8], String> {
        let len = self.read_u16(field)? as usize;
        self.read_exact(field, len)
    }

    pub(super) fn read_exact(
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
pub(super) fn evaluate_pcr_policy(
    policy: &SessionPcrPolicy,
    measured_value: [u8; 32],
    measured_events: &[[u8; 32]],
) -> std::result::Result<(), String> {
    let expected = policy
        .match_data
        .iter()
        .map(|value| decode_policy_hash(value))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    match policy.verify_type {
        SessionPcrVerifyType::Static => {
            let Some(value) = expected.first() else {
                return Err("STATIC policy has no match_data".into());
            };
            if measured_value != *value {
                return Err("STATIC PCR value mismatch".into());
            }
        }
        SessionPcrVerifyType::DynamicSubset => {
            if expected.is_empty() {
                return Err("DYNAMIC_SUBSET policy has no required landmarks".into());
            }
            if measured_events.is_empty() {
                return Err("DYNAMIC_SUBSET measured event log is empty".into());
            }
            if let Some((index, _)) = expected
                .iter()
                .enumerate()
                .find(|(_, required)| !measured_events.contains(required))
            {
                return Err(format!(
                    "DYNAMIC_SUBSET required landmark {index} is missing"
                ));
            }
            verify_event_replay(measured_value, measured_events)?;
        }
        SessionPcrVerifyType::DynamicSubsequence => {
            if expected.is_empty() {
                return Err("DYNAMIC_SUBSEQUENCE policy has no required landmarks".into());
            }
            if measured_events.is_empty() {
                return Err("DYNAMIC_SUBSEQUENCE measured event log is empty".into());
            }
            let mut landmark = 0;
            for event in measured_events {
                if expected.get(landmark) == Some(event) {
                    landmark += 1;
                }
            }
            if landmark != expected.len() {
                return Err(format!(
                    "DYNAMIC_SUBSEQUENCE matched {landmark} of {} landmarks",
                    expected.len()
                ));
            }
            verify_event_replay(measured_value, measured_events)?;
        }
    }
    Ok(())
}

fn verify_event_replay(
    final_value: [u8; 32],
    events: &[[u8; 32]],
) -> std::result::Result<(), String> {
    let mut pcr = [0u8; 32];
    for event in events {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&pcr);
        input[32..].copy_from_slice(event);
        pcr = Sha256::digest(input).into();
    }
    if pcr != final_value {
        return Err("event replay does not produce the measured PCR value".into());
    }
    Ok(())
}

fn decode_policy_hash(value: &str) -> std::result::Result<[u8; 32], String> {
    let raw = value.strip_prefix("0x").ok_or("missing 0x prefix")?;
    let bytes = hex::decode(raw).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcp_tdx_verification_rejects_revoked_sgx_pce_partial_matches() {
        assert_eq!(
            tdx_dcap_verification_policy().tdx_tcb_revocation_policy,
            dcap_rs::TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch
        );
    }
}
