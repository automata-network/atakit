//! Trust anchors resolved from verifier-selected registry state.
//!
//! Every function here reads the chain. The platform branching is attestation
//! logic, not cloud deployment: it reads `response.platform.cloud` and
//! `response.platform.tee` to decide which anchors a given piece of evidence
//! needs, and touches no provider SDK, credential, or deployment module.

use atakit_attestation::{
    amd_snp_security_state, aws_nitro_root_certificate, select_azure_maa_manual_trust_key,
    AkBinding, AmdSnpVerificationCollateral, AzureMaaTrustCertificate, AzureMaaTrustKey,
    TlsAttestationResponse, TrustAnchors,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::chain::{AttestationClient, AttestationClientConfig};
use crate::error::PortalVerificationError;
use crate::trust::files::{AzureMaaTrustConfig, AzureMaaTrustSource};

pub(crate) async fn resolve_azure_maa_trust(
    response: &TlsAttestationResponse,
    config: &AzureMaaTrustConfig,
    trust_anchors: &mut TrustAnchors,
) -> Result<Vec<AzureMaaTrustKey>, String> {
    if !is_azure_maa_response(response) {
        return Ok(Vec::new());
    }
    if !trust_anchors.azure_maa_keys.is_empty() {
        let binding = response
            .ak_binding
            .as_ref()
            .ok_or_else(|| "Azure response is missing akBinding".to_string())?;
        return select_azure_maa_manual_trust_key(binding, &trust_anchors.azure_maa_keys)
            .map(|key| vec![key]);
    }
    let AzureMaaTrustSource::OnchainRegistry {
        rpc_url,
        session_registry,
    } = &config.source
    else {
        return Ok(Vec::new());
    };

    let jwt = extract_azure_maa_jwt_info(response)?;
    let client = connect_attestation_client(rpc_url, session_registry).await?;
    let key = client
        .resolve_azure_maa_signing_key(&jwt.kid, &jwt.issuer)
        .await
        .map_err(|error| error.to_string())?;
    // Carry the registry's notAfter into the TLS-path anchors. Previously only
    // the key bytes were pushed, so the expiry the registry publishes was
    // dropped before the portal TLS attestation check could apply it.
    trust_anchors.azure_maa_keys.push(AzureMaaTrustCertificate {
        public_key: key.public_key.clone(),
        not_after: key.not_after,
    });
    Ok(vec![key])
}

pub(crate) async fn resolve_chain_trust_anchors(
    response: &TlsAttestationResponse,
    config: &AzureMaaTrustConfig,
    trust_anchors: &mut TrustAnchors,
    amd_snp_collateral: Option<&AmdSnpVerificationCollateral>,
) -> Result<(), String> {
    let AzureMaaTrustSource::OnchainRegistry {
        rpc_url,
        session_registry,
    } = &config.source
    else {
        return Ok(());
    };
    let client = connect_attestation_client(rpc_url, session_registry).await?;

    if response.platform.cloud.eq_ignore_ascii_case("gcp")
        && trust_anchors.gcp_roots.is_empty()
        && trust_anchors.gcp_root_hashes.is_empty()
    {
        let root = extract_gcp_ak_root_cert(response)?;
        let root_hash = client
            .resolve_gcp_ak_root(&root)
            .await
            .map_err(|error| error.to_string())?;
        trust_anchors.gcp_root_hashes.push(root_hash);
    }

    if response.platform.tee.eq_ignore_ascii_case("sev-snp")
        && trust_anchors.amd_ark_roots.is_empty()
        && trust_anchors.amd_ark_root_hashes.is_empty()
    {
        if !response.platform.cloud.eq_ignore_ascii_case("gcp")
            && !response.platform.cloud.eq_ignore_ascii_case("azure")
            && !response.platform.cloud.eq_ignore_ascii_case("aws")
        {
            return Ok(());
        }
        let ark = amd_snp_collateral
            .ok_or_else(|| "SNP response is missing resolved AMD collateral".to_string())?
            .ark_der();
        let ark_hash = client
            .resolve_amd_ark_root(ark)
            .await
            .map_err(|error| error.to_string())?;
        trust_anchors.amd_ark_root_hashes.push(ark_hash);
    }

    if response.platform.cloud.eq_ignore_ascii_case("aws") {
        let binding = response
            .ak_binding
            .as_ref()
            .ok_or_else(|| "AWS response is missing akBinding".to_string())?;
        if trust_anchors.aws_nitro_roots.is_empty()
            && trust_anchors.aws_nitro_root_hashes.is_empty()
        {
            let root = aws_nitro_root_certificate(binding)?;
            let root_hash = client
                .resolve_aws_nitro_root(&root)
                .await
                .map_err(|error| error.to_string())?;
            trust_anchors.aws_nitro_root_hashes.push(root_hash);
        }
        if trust_anchors.aws_document_maximum_age_seconds.is_none()
            || trust_anchors
                .aws_document_allowed_future_clock_difference_seconds
                .is_none()
        {
            let (maximum_age, allowed_future) = client
                .resolve_aws_document_freshness_limits()
                .await
                .map_err(|error| error.to_string())?;
            trust_anchors.aws_document_maximum_age_seconds = Some(maximum_age);
            trust_anchors.aws_document_allowed_future_clock_difference_seconds =
                Some(allowed_future);
        }
    }

    if response.platform.tee.eq_ignore_ascii_case("sev-snp") {
        let evidence = response
            .tee_evidence
            .as_ref()
            .ok_or_else(|| "SNP response is missing teeEvidence".to_string())?;
        let report = URL_SAFE_NO_PAD
            .decode(&evidence.report)
            .map_err(|error| format!("decode SNP report for registry default lookup: {error}"))?;
        let state = amd_snp_security_state(&report)?;
        if !trust_anchors
            .amd_snp_security_policies
            .iter()
            .any(|policy| policy.cpuid == state.cpuid)
        {
            let policy = client
                .resolve_amd_snp_security_policy(state.cpuid)
                .await
                .map_err(|error| error.to_string())?;
            trust_anchors.amd_snp_security_policies.push(policy);
        }
    }

    Ok(())
}

async fn connect_attestation_client(
    rpc_url: &str,
    session_registry: &str,
) -> Result<AttestationClient, String> {
    AttestationClient::connect(AttestationClientConfig {
        rpc_url: rpc_url.to_string(),
        session_registry: session_registry.to_string(),
        expected_chain_id: None,
        expected_base_image_registry: None,
        expected_workload_registry: None,
    })
    .await
    .map_err(|error| error.to_string())
}

pub(crate) async fn session_attestation_client(
    config: &AzureMaaTrustConfig,
) -> Result<Option<AttestationClient>, PortalVerificationError> {
    let AzureMaaTrustSource::OnchainRegistry {
        rpc_url,
        session_registry,
    } = &config.source
    else {
        return Ok(None);
    };
    connect_attestation_client(rpc_url, session_registry)
        .await
        .map(Some)
        .map_err(|message| PortalVerificationError::PortalTlsAttestationFailed { message })
}

#[derive(Debug, Clone)]
struct AzureMaaJwtInfo {
    kid: String,
    issuer: String,
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

fn extract_azure_maa_jwt_info_from_binding(binding: &AkBinding) -> Result<AzureMaaJwtInfo, String> {
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

fn is_azure_maa_response(response: &TlsAttestationResponse) -> bool {
    response.platform.cloud.eq_ignore_ascii_case("azure")
        && response
            .ak_binding
            .as_ref()
            .is_some_and(|binding| binding.kind.eq_ignore_ascii_case("azure-maa-jwt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_maa_jwt_info_is_extracted_from_binding() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"kid-1"}"#);
        let claims = URL_SAFE_NO_PAD.encode(r#"{"iss":"https://issuer.example"}"#);
        let jwt = format!("{header}.{claims}.signature");
        let binding = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "jwt": jwt,
                "hclVarData": ""
            })
            .to_string(),
        );
        let response = TlsAttestationResponse {
            format: 2,
            nonce: String::new(),
            tls_cert_der: String::new(),
            tls_cert_sha256: String::new(),
            qualifying_data: String::new(),
            platform: atakit_attestation::PlatformEvidence {
                cloud: "azure".to_string(),
                tee: "tdx".to_string(),
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
            ak_binding: Some(atakit_attestation::AkBinding {
                kind: "azure-maa-jwt".to_string(),
                data: binding,
            }),
            collateral: serde_json::Value::Null,
        };

        let info = extract_azure_maa_jwt_info(&response).unwrap();
        assert_eq!(info.kid, "kid-1");
        assert_eq!(info.issuer, "https://issuer.example");
    }
}
