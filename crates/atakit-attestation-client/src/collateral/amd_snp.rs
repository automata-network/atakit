//! AMD SEV-SNP verification collateral: the GCP `teeEvidence.auxiliary`
//! certificate-table parse and the AMD Key Distribution Service fetches.

use std::time::Duration;

use atakit_attestation::{
    amd_snp_kds_product, amd_snp_signing_key_type, amd_snp_vcek_request,
    amd_snp_vlek_from_certificate_table, AmdSnpSigningKeyType, AmdSnpVerificationCollateral,
    SessionEvidenceBundle, TlsAttestationResponse,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::http::read_response_bytes_limited;
use crate::trust::files::parse_pem_certificates;

const MAX_AMD_COLLATERAL_BYTES: usize = 1024 * 1024;
const MAX_AMD_REPORT_BYTES: usize = 64 * 1024;

pub(crate) async fn resolve_amd_snp_collateral(
    response: &TlsAttestationResponse,
    configured_crls: Vec<Vec<u8>>,
) -> Result<Option<AmdSnpVerificationCollateral>, String> {
    if !response.platform.tee.eq_ignore_ascii_case("sev-snp") {
        return Ok(None);
    }
    let is_azure = response.platform.cloud.eq_ignore_ascii_case("azure");
    let is_gcp = response.platform.cloud.eq_ignore_ascii_case("gcp");
    let is_aws = response.platform.cloud.eq_ignore_ascii_case("aws");
    if !is_azure && !is_gcp && !is_aws {
        return Ok(None);
    }
    let crls = resolve_amd_snp_crls(response, configured_crls).await?;
    if is_azure {
        return fetch_azure_snp_collateral(response, crls).await.map(Some);
    }
    if is_gcp {
        let evidence = response
            .tee_evidence
            .as_ref()
            .ok_or_else(|| "SNP response is missing teeEvidence".to_string())?;
        let auxiliary = evidence
            .auxiliary
            .as_ref()
            .ok_or_else(|| "SNP response is missing teeEvidence.auxiliary".to_string())?;
        let certificate_table = decode_base64url_limited(
            auxiliary,
            "SNP auxiliary certificate table",
            MAX_AMD_COLLATERAL_BYTES,
        )?;
        return AmdSnpVerificationCollateral::from_certificate_table(&certificate_table, crls)
            .map(Some)
            .map_err(|error| error.to_string());
    }
    if is_aws {
        return fetch_aws_snp_collateral(response, crls).await.map(Some);
    }
    unreachable!("supported AMD SEV-SNP cloud checked above")
}

/// Resolve AMD SEV-SNP collateral for a committed session evidence bundle.
///
/// The collateral resolver consumes only the platform and raw TEE evidence.
/// Projecting those fields into its existing input keeps the network and
/// certificate handling identical to portal TLS verification.
pub(crate) async fn resolve_amd_snp_collateral_for_session_bundle(
    bundle: &SessionEvidenceBundle,
    configured_crls: Vec<Vec<u8>>,
) -> Result<Option<AmdSnpVerificationCollateral>, String> {
    let response = TlsAttestationResponse {
        format: bundle.format,
        nonce: String::new(),
        tls_cert_der: String::new(),
        tls_cert_sha256: String::new(),
        qualifying_data: String::new(),
        platform: atakit_attestation::PlatformEvidence {
            cloud: bundle.platform.cloud.clone(),
            tee: bundle.platform.tee.clone(),
            machine_type: bundle.platform.machine_type.clone(),
        },
        tpm: atakit_attestation::TpmEvidence {
            ak_public: String::new(),
            quote: String::new(),
            signature: String::new(),
            pcr0_startup_locality: 0,
            pcrs: Vec::new(),
            event_log_hashes: Vec::new(),
        },
        tee_evidence: Some(atakit_attestation::TeeEvidence {
            kind: bundle.tee_evidence.kind.clone(),
            report: bundle.tee_evidence.report.clone(),
            auxiliary: bundle.tee_evidence.auxiliary.clone(),
        }),
        ak_binding: None,
        collateral: serde_json::Value::Null,
    };
    resolve_amd_snp_collateral(&response, configured_crls).await
}

async fn fetch_aws_snp_collateral(
    response: &TlsAttestationResponse,
    crls: Vec<Vec<u8>>,
) -> Result<AmdSnpVerificationCollateral, String> {
    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "AWS SNP response is missing teeEvidence".to_string())?;
    let report =
        decode_base64url_limited(&evidence.report, "AWS SNP report", MAX_AMD_REPORT_BYTES)?;
    let auxiliary = evidence
        .auxiliary
        .as_ref()
        .ok_or_else(|| "AWS SNP response is missing teeEvidence.auxiliary".to_string())?;
    let certificate_table = decode_base64url_limited(
        auxiliary,
        "AWS SNP auxiliary certificate table",
        MAX_AMD_COLLATERAL_BYTES,
    )?;
    let vlek = amd_snp_vlek_from_certificate_table(&certificate_table)
        .map_err(|error| error.to_string())?;
    let product = amd_snp_kds_product(&report)?;
    let chain_url = format!("https://kdsintf.amd.com/vlek/v1/{product}/cert_chain");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("build AMD KDS client: {error}"))?;
    let chain_response = client
        .get(&chain_url)
        .send()
        .await
        .map_err(|error| format!("fetch AMD {product} VLEK certificate chain: {error}"))?
        .error_for_status()
        .map_err(|error| format!("fetch AMD {product} VLEK certificate chain: {error}"))?;
    let chain = read_response_bytes_limited(
        chain_response,
        MAX_AMD_COLLATERAL_BYTES,
        &format!("AMD {product} VLEK certificate chain"),
    )
    .await?;
    let certs = parse_pem_certificates(&chain)
        .map_err(|error| format!("AMD {product} VLEK certificate chain: {error}"))?;
    let [asvk, ark] = certs.as_slice() else {
        return Err(format!(
            "AMD {product} VLEK certificate chain contains {} certificates, expected ASVK then ARK",
            certs.len()
        ));
    };
    Ok(AmdSnpVerificationCollateral::from_vlek_chain(
        ark.clone(),
        asvk.clone(),
        vlek,
        crls,
    ))
}

async fn fetch_azure_snp_collateral(
    response: &TlsAttestationResponse,
    crls: Vec<Vec<u8>>,
) -> Result<AmdSnpVerificationCollateral, String> {
    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "Azure SNP response is missing teeEvidence".to_string())?;
    let report =
        decode_base64url_limited(&evidence.report, "Azure SNP report", MAX_AMD_REPORT_BYTES)?;
    let request = amd_snp_vcek_request(&report)?;
    let product = amd_snp_kds_product(&report)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("build AMD KDS client: {error}"))?;
    let chip_id = hex::encode(request.chip_id);
    let vcek_url = format!("https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}");
    let vcek_response = client
        .get(&vcek_url)
        .query(&[
            ("blSPL", request.bootloader),
            ("teeSPL", request.tee),
            ("snpSPL", request.snp),
            ("ucodeSPL", request.microcode),
        ])
        .send()
        .await
        .map_err(|error| format!("fetch AMD {product} VCEK: {error}"))?
        .error_for_status()
        .map_err(|error| format!("fetch AMD {product} VCEK: {error}"))?;
    let vcek = read_response_bytes_limited(
        vcek_response,
        MAX_AMD_COLLATERAL_BYTES,
        &format!("AMD {product} VCEK"),
    )
    .await?;
    let chain_url = format!("https://kdsintf.amd.com/vcek/v1/{product}/cert_chain");
    let chain_response = client
        .get(&chain_url)
        .send()
        .await
        .map_err(|error| format!("fetch AMD {product} certificate chain: {error}"))?
        .error_for_status()
        .map_err(|error| format!("fetch AMD {product} certificate chain: {error}"))?;
    let chain = read_response_bytes_limited(
        chain_response,
        MAX_AMD_COLLATERAL_BYTES,
        &format!("AMD {product} certificate chain"),
    )
    .await?;
    let certs = parse_pem_certificates(&chain)
        .map_err(|error| format!("AMD {product} certificate chain: {error}"))?;
    let [ask, ark] = certs.as_slice() else {
        return Err(format!(
            "AMD {product} certificate chain contains {} certificates, expected ASK then ARK",
            certs.len()
        ));
    };
    Ok(AmdSnpVerificationCollateral::from_vcek_chain(
        ark.clone(),
        ask.clone(),
        vcek,
        crls,
    ))
}

async fn resolve_amd_snp_crls(
    response: &TlsAttestationResponse,
    configured_crls: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, String> {
    if !configured_crls.is_empty() {
        return Ok(configured_crls);
    }
    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "SNP response is missing teeEvidence".to_string())?;
    let report = decode_base64url_limited(
        &evidence.report,
        "SNP report for AMD CRL lookup",
        MAX_AMD_REPORT_BYTES,
    )?;
    let product = amd_snp_kds_product(&report)?;
    let signing_key_type = amd_snp_signing_key_type(&report)?;
    let (url, signing_key_name) = amd_snp_crl_endpoint(product, signing_key_type);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("build AMD KDS client: {error}"))?;
    let crl_response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| {
            format!("fetch AMD {product} {signing_key_name} certificate revocation list: {error}")
        })?
        .error_for_status()
        .map_err(|error| {
            format!("fetch AMD {product} {signing_key_name} certificate revocation list: {error}")
        })?;
    let crl = read_response_bytes_limited(
        crl_response,
        MAX_AMD_COLLATERAL_BYTES,
        &format!("AMD {product} {signing_key_name} certificate revocation list"),
    )
    .await?;
    Ok(vec![crl])
}

fn decode_base64url_limited(
    encoded: &str,
    label: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, String> {
    let maximum_encoded_length = maximum_bytes
        .checked_mul(4)
        .map(|length| length.div_ceil(3))
        .unwrap_or(usize::MAX);
    if encoded.len() > maximum_encoded_length {
        return Err(format!(
            "decode {label}: encoded value exceeds the {maximum_bytes}-byte decoded limit"
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| format!("decode {label}: {error}"))?;
    if decoded.len() > maximum_bytes {
        return Err(format!(
            "decode {label}: decoded value exceeds the {maximum_bytes}-byte limit"
        ));
    }
    Ok(decoded)
}

fn amd_snp_crl_endpoint(
    product: &str,
    signing_key_type: AmdSnpSigningKeyType,
) -> (String, &'static str) {
    let (path, signing_key_name) = match signing_key_type {
        AmdSnpSigningKeyType::Vcek => ("vcek", "VCEK"),
        AmdSnpSigningKeyType::Vlek => ("vlek", "VLEK"),
    };
    (
        format!("https://kdsintf.amd.com/{path}/v1/{product}/crl"),
        signing_key_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_snp_verification_collateral_stays_separate_from_portal_collateral() {
        let response = TlsAttestationResponse {
            format: 2,
            nonce: String::new(),
            tls_cert_der: String::new(),
            tls_cert_sha256: String::new(),
            qualifying_data: String::new(),
            platform: atakit_attestation::PlatformEvidence {
                cloud: "azure".to_string(),
                tee: "sev-snp".to_string(),
                machine_type: String::new(),
            },
            tpm: atakit_attestation::TpmEvidence {
                ak_public: String::new(),
                quote: String::new(),
                signature: String::new(),
                pcr0_startup_locality: 0,
                pcrs: vec![],
                event_log_hashes: vec![],
            },
            tee_evidence: None,
            ak_binding: None,
            collateral: serde_json::json!({
                "existing": true
            }),
        };

        let collateral = AmdSnpVerificationCollateral::from_vcek_chain(
            b"ark".to_vec(),
            b"ask".to_vec(),
            b"vcek".to_vec(),
            vec![b"crl".to_vec()],
        );

        assert_eq!(response.collateral["existing"], true);
        assert!(response.collateral.get("azureSnpCertTable").is_none());
        assert_eq!(collateral.ark_der(), b"ark");
        assert_eq!(collateral.crls_der(), &[b"crl".to_vec()]);
    }

    #[test]
    fn selects_amd_kds_product_for_supported_cpuid() {
        let mut report = vec![0u8; 0x4a0];
        report[0x188] = 0x19;
        report[0x189] = 0x01;
        assert_eq!(amd_snp_kds_product(&report).unwrap(), "Milan");
        report[0x189] = 0x11;
        assert_eq!(amd_snp_kds_product(&report).unwrap(), "Genoa");
        report[0x188] = 0x1a;
        assert!(amd_snp_kds_product(&report).is_err());
    }

    #[test]
    fn selects_amd_kds_crl_endpoint_for_report_signing_key() {
        assert_eq!(
            amd_snp_crl_endpoint("Milan", AmdSnpSigningKeyType::Vcek),
            (
                "https://kdsintf.amd.com/vcek/v1/Milan/crl".to_string(),
                "VCEK"
            )
        );
        assert_eq!(
            amd_snp_crl_endpoint("Genoa", AmdSnpSigningKeyType::Vlek),
            (
                "https://kdsintf.amd.com/vlek/v1/Genoa/crl".to_string(),
                "VLEK"
            )
        );
    }
}
