use std::collections::{BTreeMap, BTreeSet};

use atakit_attestation::{
    azure_maa_binding_from_session_bundle, verify_session_bundle, AzureMaaTrustKey, BindingMode,
    CertificateTrust, SessionAttribute, SessionAttributeRequirement, SessionEvidenceBundle,
    SessionPcrPolicy, SessionPcrVerifyType, SessionPlatformTrust, SessionRequestBinding,
    SessionTrust, SessionVerificationInputs, TrustedSessionBinding, TrustedSessionPolicy,
    VerifiedSession,
};
use atakit_attestation::{
    MeasurementPolicy, MeasurementProfile, MeasurementVariant, PlatformEvidence, TrustAnchors,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::error::CloudError;
use crate::init::{AzureMaaTrustConfig, VerifiedPortalTls};

#[derive(Debug, Clone)]
pub struct PortalSessionVerificationContext {
    pub platform: PlatformEvidence,
    pub measurement_policy: MeasurementPolicy,
    pub trust_anchors: TrustAnchors,
    pub azure_maa_trust: AzureMaaTrustConfig,
    pub manual_azure_maa_keys: Vec<Vec<u8>>,
    pub azure_snp_cert_table: Option<Vec<u8>>,
    pub tdx_dcap_collateral: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct TrustedWorkloadSessionPolicy {
    pub workload_id: [u8; 32],
    pub pcr_specs: Vec<SessionPcrPolicy>,
    pub attribute_requirements: Vec<SessionAttributeRequirement>,
}

#[derive(Deserialize)]
struct EvidenceBundleResponse {
    evidence_bundle: serde_json::Value,
    request_binding: SessionRequestBinding,
}

/// Fetch and verify the current portal session using only caller-selected
/// policy and trust material. Registry state is not read and no transaction is
/// created or submitted.
pub async fn verify_current_session(
    verified_tls: &VerifiedPortalTls,
    host: &str,
    status_port: u16,
    workload: TrustedWorkloadSessionPolicy,
    required_binding: Option<BindingMode>,
    trusted_binding: Option<TrustedSessionBinding>,
) -> Result<VerifiedSession, CloudError> {
    if verified_tls.manual_override.is_some() {
        return Err(session_error(
            "session verification is unavailable after a manual TLS certificate override",
        ));
    }
    let context = verified_tls
        .session_verification
        .as_ref()
        .ok_or_else(|| session_error("verified TLS context did not retain session trust inputs"))?;
    let challenge = crate::init::random_nonce()?;
    let challenge_text = URL_SAFE_NO_PAD.encode(challenge);
    let url =
        format!("https://{host}:{status_port}/session/evidence-bundle?challenge={challenge_text}");
    let response = verified_tls
        .client
        .get(url)
        .send()
        .await
        .map_err(|error| session_error(format!("request evidence bundle: {error}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(session_error(format!(
            "evidence bundle endpoint returned {status}: {body}"
        )));
    }
    let response: EvidenceBundleResponse = response
        .json()
        .await
        .map_err(|error| session_error(format!("decode evidence bundle response: {error}")))?;
    let bundle: SessionEvidenceBundle = serde_json::from_value(response.evidence_bundle.clone())
        .map_err(|error| session_error(format!("decode session evidence bundle: {error}")))?;
    let committed_maa_keys = committed_session_maa_keys(context, &bundle).await?;
    let trust = build_session_trust(
        context,
        &verified_tls.identity,
        &bundle,
        workload,
        committed_maa_keys,
        trusted_binding,
    )?;
    let verified = verify_session_bundle(SessionVerificationInputs {
        bundle: response.evidence_bundle,
        request_binding: response.request_binding,
        expected_challenge: challenge,
        trust,
    })
    .map_err(|failure| {
        session_error(
            serde_json::to_string_pretty(&failure).unwrap_or_else(|_| failure.errors.join("; ")),
        )
    })?;
    enforce_required_binding(verified.binding_mode, required_binding)?;
    Ok(verified)
}

async fn committed_session_maa_keys(
    context: &PortalSessionVerificationContext,
    bundle: &SessionEvidenceBundle,
) -> Result<Vec<AzureMaaTrustKey>, CloudError> {
    if bundle.platform.cloud != "azure" {
        return Ok(Vec::new());
    }
    let binding = azure_maa_binding_from_session_bundle(bundle).map_err(session_error)?;
    crate::init::resolve_committed_session_azure_maa_key(
        &binding,
        &context.azure_maa_trust,
        &context.manual_azure_maa_keys,
    )
    .await
    .map(|key| vec![key])
}

fn enforce_required_binding(
    actual: BindingMode,
    required: Option<BindingMode>,
) -> Result<(), CloudError> {
    if let Some(required) = required {
        if actual != required {
            return Err(session_error(format!(
                "expected {required:?} binding, got {actual:?}"
            )));
        }
    }
    Ok(())
}

fn build_session_trust(
    context: &PortalSessionVerificationContext,
    identity: &atakit_attestation::VerifiedTlsIdentity,
    bundle: &SessionEvidenceBundle,
    workload: TrustedWorkloadSessionPolicy,
    committed_maa_keys: Vec<AzureMaaTrustKey>,
    binding: Option<TrustedSessionBinding>,
) -> Result<SessionTrust, CloudError> {
    if context.platform.cloud != bundle.platform.cloud
        || context.platform.tee != bundle.platform.tee
        || context.platform.machine_type != bundle.platform.machine_type
    {
        return Err(session_error(format!(
            "session platform differs from the TLS-attested platform: TLS={}/{}/{} session={}/{}/{}",
            context.platform.cloud,
            context.platform.tee,
            context.platform.machine_type,
            bundle.platform.cloud,
            bundle.platform.tee,
            bundle.platform.machine_type,
        )));
    }

    let platform = match (bundle.platform.cloud.as_str(), bundle.platform.tee.as_str()) {
        ("gcp", "tdx") => SessionPlatformTrust::GcpTdx {
            gcp_ak_roots: certificate_trust(
                &context.trust_anchors.gcp_roots,
                &context.trust_anchors.gcp_root_hashes,
            ),
            dcap_collateral: context.tdx_dcap_collateral.clone().ok_or_else(|| {
                session_error("verified TLS context has no GCP TDX DCAP collateral")
            })?,
        },
        ("gcp", "sev-snp") => SessionPlatformTrust::GcpSnp {
            gcp_ak_roots: certificate_trust(
                &context.trust_anchors.gcp_roots,
                &context.trust_anchors.gcp_root_hashes,
            ),
            amd_ark_roots: certificate_trust(
                &context.trust_anchors.amd_ark_roots,
                &context.trust_anchors.amd_ark_root_hashes,
            ),
        },
        ("azure", "tdx") => SessionPlatformTrust::AzureTdx {
            maa_signing_keys: committed_maa_keys,
            dcap_collateral: context.tdx_dcap_collateral.clone().ok_or_else(|| {
                session_error("verified TLS context has no Azure TDX DCAP collateral")
            })?,
        },
        ("azure", "sev-snp") => SessionPlatformTrust::AzureSnp {
            maa_signing_keys: committed_maa_keys,
            amd_ark_roots: certificate_trust(
                &context.trust_anchors.amd_ark_roots,
                &context.trust_anchors.amd_ark_root_hashes,
            ),
            snp_cert_table: context.azure_snp_cert_table.clone().ok_or_else(|| {
                session_error("verified TLS context has no Azure SNP certificate table")
            })?,
        },
        (cloud, tee) => {
            return Err(session_error(format!(
                "CLI session verification is not yet wired for cloud={cloud}, tee={tee}"
            )))
        }
    };

    Ok(SessionTrust {
        platform,
        policy: trusted_policy(context, identity, bundle, workload)?,
        binding,
    })
}

fn trusted_policy(
    context: &PortalSessionVerificationContext,
    identity: &atakit_attestation::VerifiedTlsIdentity,
    bundle: &SessionEvidenceBundle,
    workload: TrustedWorkloadSessionPolicy,
) -> Result<TrustedSessionPolicy, CloudError> {
    let base_image_id = required_identity_id(identity.base_image_id, "base image")?;
    let platform_profile_id =
        required_identity_id(identity.platform_profile_id, "platform profile")?;
    let measurement_variant_id = required_identity_id(identity.variant_id, "measurement variant")?;
    let profile = select_profile(&context.measurement_policy, platform_profile_id)?;
    let variant = select_variant(
        profile,
        measurement_variant_id,
        &bundle.platform.machine_type,
    )?;

    let pcr_specs = combined_pcr_specs(effective_pcr_specs(profile, variant)?, workload.pcr_specs);

    Ok(TrustedSessionPolicy {
        workload_id: workload.workload_id,
        base_image_id,
        platform_profile_id,
        measurement_variant_id,
        pcr_specs,
        effective_attributes: effective_attributes(profile, variant)?,
        attribute_requirements: workload.attribute_requirements,
    })
}

fn combined_pcr_specs(
    mut base_image: Vec<SessionPcrPolicy>,
    workload: Vec<SessionPcrPolicy>,
) -> Vec<SessionPcrPolicy> {
    base_image.extend(workload);
    base_image
}

fn required_identity_id(value: Option<[u8; 32]>, label: &str) -> Result<[u8; 32], CloudError> {
    value.ok_or_else(|| session_error(format!("TLS verification did not select a {label} ID")))
}

fn select_profile(
    policy: &MeasurementPolicy,
    expected_id: [u8; 32],
) -> Result<&MeasurementProfile, CloudError> {
    let matches = policy
        .pack
        .profiles
        .iter()
        .filter(|profile| decode_hex_32(&profile.id).ok() == Some(expected_id))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [profile] => Ok(*profile),
        [] => Err(session_error(
            "signed measurement policy has no TLS-selected profile",
        )),
        _ => Err(session_error(
            "signed measurement policy has duplicate TLS-selected profiles",
        )),
    }
}

fn select_variant<'a>(
    profile: &'a MeasurementProfile,
    expected_id: [u8; 32],
    machine_type: &str,
) -> Result<&'a MeasurementVariant, CloudError> {
    let matches = profile
        .variants
        .iter()
        .filter(|variant| {
            decode_hex_32(&variant.id).ok() == Some(expected_id)
                && variant
                    .machine_types
                    .iter()
                    .any(|value| value == machine_type)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [variant] => Ok(*variant),
        [] => Err(session_error(format!(
            "signed measurement policy has no TLS-selected variant for machine type {machine_type}"
        ))),
        _ => Err(session_error(
            "signed measurement policy has duplicate TLS-selected variants",
        )),
    }
}

fn effective_pcr_specs(
    profile: &MeasurementProfile,
    variant: &MeasurementVariant,
) -> Result<Vec<SessionPcrPolicy>, CloudError> {
    let mut specs = BTreeMap::new();
    for spec in &profile.invariants {
        if specs.insert(spec.pcr_index, spec).is_some() {
            return Err(session_error(format!(
                "duplicate PCR {} in profile {}",
                spec.pcr_index, profile.name
            )));
        }
    }
    let mut overrides = BTreeSet::new();
    for spec in &variant.override_pcrs {
        if !overrides.insert(spec.pcr_index) {
            return Err(session_error(format!(
                "duplicate PCR {} in variant {}",
                spec.pcr_index, variant.name
            )));
        }
        specs.insert(spec.pcr_index, spec);
    }
    if specs.is_empty() {
        return Err(session_error("trusted session PCR policy is empty"));
    }
    specs
        .into_values()
        .map(|spec| {
            Ok(SessionPcrPolicy {
                pcr_index: spec.pcr_index,
                verify_type: parse_verify_type(&spec.verify_type)?,
                match_data: spec.match_data.clone(),
            })
        })
        .collect()
}

fn parse_verify_type(value: &str) -> Result<SessionPcrVerifyType, CloudError> {
    let normalized = value
        .chars()
        .filter(|ch| !matches!(ch, '_' | '-'))
        .flat_map(char::to_uppercase)
        .collect::<String>();
    match normalized.as_str() {
        "STATIC" => Ok(SessionPcrVerifyType::Static),
        "DYNAMICSUBSET" => Ok(SessionPcrVerifyType::DynamicSubset),
        "DYNAMICSUBSEQUENCE" => Ok(SessionPcrVerifyType::DynamicSubsequence),
        _ => Err(session_error(format!(
            "unsupported PCR verify type {value:?}"
        ))),
    }
}

fn effective_attributes(
    profile: &MeasurementProfile,
    variant: &MeasurementVariant,
) -> Result<Vec<SessionAttribute>, CloudError> {
    let profile = parse_attributes(&profile.attributes, "profile")?;
    let variant = parse_attributes(&variant.attributes, "variant")?;
    let variant_keys = variant.iter().map(|item| item.key).collect::<BTreeSet<_>>();
    Ok(profile
        .into_iter()
        .filter(|item| !variant_keys.contains(&item.key))
        .chain(variant)
        .collect())
}

fn parse_attributes(
    values: &[serde_json::Value],
    owner: &str,
) -> Result<Vec<SessionAttribute>, CloudError> {
    let mut out = Vec::with_capacity(values.len());
    let mut keys = BTreeSet::new();
    for value in values {
        let key = value
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| session_error(format!("{owner} attribute is missing string key")))?;
        let item = SessionAttribute {
            key: decode_hex_32(key)?,
            value: decode_hex_32(
                value
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        session_error(format!("{owner} attribute is missing string value"))
                    })?,
            )?,
        };
        if !keys.insert(item.key) {
            return Err(session_error(format!(
                "{owner} attributes contain a duplicate key 0x{}",
                hex::encode(item.key)
            )));
        }
        out.push(item);
    }
    Ok(out)
}

fn certificate_trust(certificates: &[Vec<u8>], hashes: &[[u8; 32]]) -> CertificateTrust {
    CertificateTrust {
        certificates: certificates.to_vec(),
        keccak256_hashes: hashes.to_vec(),
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], CloudError> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(raw)
        .map_err(|error| session_error(format!("invalid bytes32 hex {value:?}: {error}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        session_error(format!("expected 32-byte hex, got {} bytes", bytes.len()))
    })
}

fn session_error(message: impl Into<String>) -> CloudError {
    CloudError::PortalSessionVerificationFailed {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atakit_attestation::{BaseImage, MeasurementPack, PcrSpec};

    fn profile() -> MeasurementProfile {
        MeasurementProfile {
            name: "gcp-tdx".into(),
            id: format!("0x{}", "11".repeat(32)),
            cloud: "gcp".into(),
            tee: "tdx".into(),
            invariants: vec![PcrSpec {
                pcr_index: 4,
                verify_type: "dynamicSubsequence".into(),
                match_data: vec![format!("0x{}", "aa".repeat(32))],
                event_indices: Vec::new(),
                total_events: None,
            }],
            variants: vec![MeasurementVariant {
                name: "c3-standard-4".into(),
                id: format!("0x{}", "22".repeat(32)),
                machine_types: vec!["c3-standard-4".into()],
                override_pcrs: Vec::new(),
                attributes: Vec::new(),
            }],
            attributes: Vec::new(),
        }
    }

    #[test]
    fn session_policy_uses_tls_selected_profile_and_variant() {
        let profile = profile();
        let policy = MeasurementPolicy {
            source: "test".into(),
            pack: MeasurementPack {
                schema: "atakit.measurement-pack.v1".into(),
                revision: 1,
                published_at: "2026-07-17T00:00:00Z".into(),
                base_image: BaseImage {
                    name: "automata-linux".into(),
                    version: "v0.2.7-debug".into(),
                    id: format!("0x{}", "33".repeat(32)),
                    uri: None,
                    archive_sha256: None,
                },
                profiles: vec![profile],
            },
        };
        let selected = select_profile(&policy, [0x11; 32]).unwrap();
        let variant = select_variant(selected, [0x22; 32], "c3-standard-4").unwrap();
        let pcrs = effective_pcr_specs(selected, variant).unwrap();
        assert_eq!(pcrs.len(), 1);
        assert_eq!(
            pcrs[0].verify_type,
            SessionPcrVerifyType::DynamicSubsequence
        );
    }

    #[test]
    fn required_and_off_binding_policies_reject_the_opposite_binding() {
        assert!(enforce_required_binding(BindingMode::Local, Some(BindingMode::Chain)).is_err());
        assert!(enforce_required_binding(BindingMode::Chain, Some(BindingMode::Local)).is_err());
        enforce_required_binding(BindingMode::Chain, Some(BindingMode::Chain)).unwrap();
        enforce_required_binding(BindingMode::Local, Some(BindingMode::Local)).unwrap();
    }

    #[test]
    fn optional_binding_policy_accepts_local_and_chain() {
        enforce_required_binding(BindingMode::Local, None).unwrap();
        enforce_required_binding(BindingMode::Chain, None).unwrap();
    }

    #[test]
    fn workload_pcr_rule_does_not_replace_base_image_rule_for_same_pcr() {
        let base_image_rule = SessionPcrPolicy {
            pcr_index: 23,
            verify_type: SessionPcrVerifyType::DynamicSubsequence,
            match_data: vec![format!("0x{}", hex::encode([0x11; 32]))],
        };
        let workload_rule = SessionPcrPolicy {
            pcr_index: 23,
            verify_type: SessionPcrVerifyType::Static,
            match_data: vec![format!("0x{}", hex::encode([0x22; 32]))],
        };
        let combined =
            combined_pcr_specs(vec![base_image_rule.clone()], vec![workload_rule.clone()]);

        assert_eq!(combined, [base_image_rule, workload_rule]);
    }
}
