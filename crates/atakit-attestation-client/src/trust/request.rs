//! The typed request a trust source resolves against.
//!
//! Resolution is driven by the TLS attestation response, because which inputs
//! a verification requires is known only after that response arrives. An
//! earlier design had resolution take `PlatformEvidence`, which cannot work:
//! that type is three strings, and resolution also needs the GCP attestation
//! key root from the response, the AWS NitroTPM root reached through
//! `akBinding`, the AMD family-model-stepping value parsed out of the signed
//! report, and the resolved AMD ARK.
//!
//! Deriving the request in one place also makes "which inputs does this
//! platform require" a testable function rather than a shape implied by the
//! resolution code.

use atakit_attestation::{
    amd_snp_security_state, aws_nitro_root_certificate, AkBinding, AmdSnpVerificationCollateral,
    TlsAttestationResponse,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Everything a trust source needs to resolve anchors for one verification.
#[derive(Debug, Clone)]
pub struct CollateralRequest {
    pub cloud: String,
    pub tee: String,
    pub machine_type: String,
    /// Present only when `akBinding.kind` is `azure-maa-jwt`. Its absence is
    /// what distinguishes an Azure response needing a MAA signing certificate
    /// from one that does not — the distinction `required_trust_inputs` cannot
    /// make from the platform pair alone.
    pub azure_maa_jwt: Option<AzureMaaJwtInfo>,
    /// The GCP attestation key chain root, present for GCP responses.
    pub gcp_ak_root: Option<Vec<u8>>,
    /// The AWS NitroTPM root reached through `akBinding`.
    pub aws_nitro_root: Option<Vec<u8>>,
    /// The exact family-model-stepping value in the signed AMD SEV-SNP report.
    /// A security policy must match this value; a policy for any other CPUID
    /// does not satisfy the requirement.
    pub amd_snp_cpuid: Option<u32>,
    /// The AMD root key certificate from resolved collateral.
    pub amd_ark: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureMaaJwtInfo {
    pub kid: String,
    pub issuer: String,
}

impl CollateralRequest {
    /// Derive the request from a complete TLS attestation response and the
    /// AMD SEV-SNP collateral already resolved for it.
    ///
    /// Extraction is attempted only for the platform actually presented, so a
    /// response that legitimately lacks a field is not an error.
    pub fn from_response(
        response: &TlsAttestationResponse,
        amd_snp_collateral: Option<&AmdSnpVerificationCollateral>,
    ) -> Result<Self, String> {
        let cloud = response.platform.cloud.clone();
        let tee = response.platform.tee.clone();
        let is_gcp = cloud.eq_ignore_ascii_case("gcp");
        let is_aws = cloud.eq_ignore_ascii_case("aws");
        let is_snp = tee.eq_ignore_ascii_case("sev-snp");

        let azure_maa_jwt = if is_azure_maa_response(response) {
            Some(extract_azure_maa_jwt_info(response)?)
        } else {
            None
        };

        let gcp_ak_root = if is_gcp {
            Some(extract_gcp_ak_root_cert(response)?)
        } else {
            None
        };

        let aws_nitro_root = if is_aws {
            let binding = response
                .ak_binding
                .as_ref()
                .ok_or_else(|| "AWS response is missing akBinding".to_string())?;
            Some(aws_nitro_root_certificate(binding)?)
        } else {
            None
        };

        let amd_snp_cpuid = if is_snp {
            let evidence = response
                .tee_evidence
                .as_ref()
                .ok_or_else(|| "SNP response is missing teeEvidence".to_string())?;
            let report = URL_SAFE_NO_PAD.decode(&evidence.report).map_err(|error| {
                format!("decode SNP report for security policy lookup: {error}")
            })?;
            Some(amd_snp_security_state(&report)?.cpuid)
        } else {
            None
        };

        let amd_ark = if is_snp {
            Some(
                amd_snp_collateral
                    .ok_or_else(|| "SNP response is missing resolved AMD collateral".to_string())?
                    .ark_der()
                    .to_vec(),
            )
        } else {
            None
        };

        Ok(Self {
            cloud,
            tee,
            machine_type: response.platform.machine_type.clone(),
            azure_maa_jwt,
            gcp_ak_root,
            aws_nitro_root,
            amd_snp_cpuid,
            amd_ark,
        })
    }
}

pub(crate) fn is_azure_maa_response(response: &TlsAttestationResponse) -> bool {
    response.platform.cloud.eq_ignore_ascii_case("azure")
        && response
            .ak_binding
            .as_ref()
            .is_some_and(|binding| binding.kind.eq_ignore_ascii_case("azure-maa-jwt"))
}

fn extract_azure_maa_jwt_info(
    response: &TlsAttestationResponse,
) -> Result<AzureMaaJwtInfo, String> {
    let binding = response
        .ak_binding
        .as_ref()
        .ok_or_else(|| "Azure response is missing akBinding".to_string())?;
    extract_azure_maa_jwt_info_from_binding(binding)
}

pub(crate) fn extract_azure_maa_jwt_info_from_binding(
    binding: &AkBinding,
) -> Result<AzureMaaJwtInfo, String> {
    if !binding.kind.eq_ignore_ascii_case("azure-maa-jwt") {
        return Err(format!(
            "Azure response akBinding kind is {}, expected azure-maa-jwt",
            binding.kind
        ));
    }
    let binding_bytes = URL_SAFE_NO_PAD
        .decode(&binding.data)
        .map_err(|e| format!("decode Azure MAA akBinding data: {e}"))?;
    let binding_json: serde_json::Value = serde_json::from_slice(&binding_bytes)
        .map_err(|e| format!("parse Azure MAA akBinding JSON: {e}"))?;
    let jwt = binding_json
        .get("jwt")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Azure MAA akBinding JSON is missing non-empty jwt".to_string())?;

    let mut parts = jwt.split('.');
    let header = parts
        .next()
        .ok_or_else(|| "Azure MAA JWT is missing header".to_string())?;
    let claims = parts
        .next()
        .ok_or_else(|| "Azure MAA JWT is missing claims".to_string())?;
    let signature = parts
        .next()
        .ok_or_else(|| "Azure MAA JWT is missing signature".to_string())?;
    if parts.next().is_some() || signature.is_empty() {
        return Err("Azure MAA JWT must have exactly three non-empty parts".to_string());
    }

    let header_json = decode_jwt_json(header, "Azure MAA JWT header")?;
    let claims_json = decode_jwt_json(claims, "Azure MAA JWT claims")?;
    let kid = header_json
        .get("kid")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Azure MAA JWT header is missing non-empty kid".to_string())?;
    let issuer = claims_json
        .get("iss")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Azure MAA JWT claims are missing non-empty iss".to_string())?;

    Ok(AzureMaaJwtInfo {
        kid: kid.to_string(),
        issuer: issuer.to_string(),
    })
}

fn extract_gcp_ak_root_cert(response: &TlsAttestationResponse) -> Result<Vec<u8>, String> {
    let binding = response
        .ak_binding
        .as_ref()
        .ok_or_else(|| "GCP response is missing akBinding".to_string())?;
    if !binding.kind.eq_ignore_ascii_case("gcp-cert-chain") {
        return Err(format!(
            "GCP response akBinding kind is {}, expected gcp-cert-chain",
            binding.kind
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(&binding.data)
        .map_err(|e| format!("decode GCP AK cert-chain binding: {e}"))?;
    let encoded_chain: Vec<String> = serde_json::from_slice(&raw)
        .map_err(|e| format!("parse GCP AK cert-chain binding JSON: {e}"))?;
    let mut chain = Vec::with_capacity(encoded_chain.len());
    for (index, encoded) in encoded_chain.iter().enumerate() {
        chain.push(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|e| format!("decode GCP AK cert-chain certificate {index}: {e}"))?,
        );
    }
    chain
        .pop()
        .ok_or_else(|| "GCP AK cert-chain binding is empty".to_string())
}

fn decode_jwt_json(segment: &str, label: &str) -> Result<serde_json::Value, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("decode {label}: {e}"))?;
    serde_json::from_slice(&raw).map_err(|e| format!("parse {label} JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(cloud: &str, tee: &str, binding: Option<AkBinding>) -> TlsAttestationResponse {
        TlsAttestationResponse {
            format: 2,
            nonce: String::new(),
            tls_cert_der: String::new(),
            tls_cert_sha256: String::new(),
            qualifying_data: String::new(),
            platform: atakit_attestation::PlatformEvidence {
                cloud: cloud.to_string(),
                tee: tee.to_string(),
                machine_type: "test".to_string(),
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
            ak_binding: binding,
            collateral: serde_json::Value::Null,
        }
    }

    fn azure_maa_binding() -> AkBinding {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"kid-1"}"#);
        let claims = URL_SAFE_NO_PAD.encode(r#"{"iss":"https://issuer.example"}"#);
        let jwt = format!("{header}.{claims}.signature");
        AkBinding {
            kind: "azure-maa-jwt".to_string(),
            data: URL_SAFE_NO_PAD
                .encode(serde_json::json!({ "jwt": jwt, "hclVarData": "" }).to_string()),
        }
    }

    #[test]
    fn azure_maa_identity_is_carried_into_the_request() {
        let request = CollateralRequest::from_response(
            &response("azure", "tdx", Some(azure_maa_binding())),
            None,
        )
        .expect("derive request");
        let jwt = request.azure_maa_jwt.expect("Azure MAA identity");
        assert_eq!(jwt.kid, "kid-1");
        assert_eq!(jwt.issuer, "https://issuer.example");
    }

    /// The request carries the binding kind, which the platform pair alone
    /// cannot express. An Azure response with a different binding kind needs
    /// no MAA signing certificate.
    #[test]
    fn an_azure_response_without_a_maa_binding_carries_no_maa_identity() {
        let binding = AkBinding {
            kind: "something-else".to_string(),
            data: String::new(),
        };
        let request =
            CollateralRequest::from_response(&response("azure", "tdx", Some(binding)), None)
                .expect("derive request");
        assert!(request.azure_maa_jwt.is_none());
    }

    /// Extraction is attempted only for the presented platform, so a response
    /// that legitimately lacks a field is not an error.
    #[test]
    fn unrelated_platform_fields_stay_absent_without_erroring() {
        let request = CollateralRequest::from_response(
            &response("azure", "tdx", Some(azure_maa_binding())),
            None,
        )
        .expect("derive request");
        assert!(request.gcp_ak_root.is_none());
        assert!(request.aws_nitro_root.is_none());
        assert!(request.amd_snp_cpuid.is_none());
        assert!(request.amd_ark.is_none());
    }

    #[test]
    fn a_gcp_response_without_a_cert_chain_binding_is_rejected() {
        let error = CollateralRequest::from_response(&response("gcp", "tdx", None), None)
            .expect_err("GCP responses must carry an akBinding");
        assert!(error.contains("akBinding"), "{error}");
    }
}
