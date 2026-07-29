use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;

pub use crate::TrustedWorkloadSessionPolicy;
use atakit_attestation::{
    azure_maa_binding_from_session_bundle, select_azure_maa_manual_trust_key,
    verify_session_bundle, AmdSnpVerificationCollateral, AzureMaaTrustKey, BindingMode,
    CertificateTrust, IntelTdxDcapCollateral, SessionAttribute, SessionEvidenceBundle,
    SessionPcrPolicy, SessionPcrVerifyType, SessionPlatformTrust, SessionRequestBinding,
    SessionTrust, SessionVerificationInputs, TrustedSessionBinding, TrustedSessionPolicy,
    VerificationReport, VerifiedSession, VerifiedTlsIdentity,
};
use atakit_attestation::{
    MeasurementPolicy, MeasurementProfile, MeasurementVariant, PlatformEvidence, TrustAnchors,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::{AttestationClient, AttestationClientError};

#[derive(Debug, Clone)]
pub struct PortalSessionVerificationContext {
    pub platform: PlatformEvidence,
    pub measurement_policy: MeasurementPolicy,
    pub trust_anchors: TrustAnchors,
    /// Verifier-selected chain client used for evidence-specific collateral.
    /// This is optional only when manual platform trust is supplied.
    pub chain_client: Option<AttestationClient>,
    pub manual_azure_maa_keys: Vec<Vec<u8>>,
    /// Collateral resolved during this portal TLS bootstrap. Session
    /// verification rechecks its certificate and revocation validity against
    /// the session verification time. No process-wide cache stores this value.
    pub amd_snp_collateral: Option<AmdSnpVerificationCollateral>,
    pub intel_tdx_dcap_collateral: Option<IntelTdxDcapCollateral>,
}

/// Portal TLS connection and the independently verified identity bound to it.
#[derive(Debug, Clone)]
pub struct VerifiedPortalTls {
    pub client: reqwest::Client,
    pub identity: VerifiedTlsIdentity,
    pub manual_override: Option<TlsManualOverride>,
    pub session_verification: Option<PortalSessionVerificationContext>,
}

#[derive(Debug, Clone)]
pub struct TlsManualOverride {
    pub live_cert_sha256: String,
    pub report: VerificationReport,
    pub report_path: Option<PathBuf>,
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
) -> Result<VerifiedSession, AttestationClientError> {
    if verified_tls.manual_override.is_some() {
        return Err(session_error(
            "session verification is unavailable after a manual TLS certificate override",
        ));
    }
    let context = verified_tls
        .session_verification
        .as_ref()
        .ok_or_else(|| session_error("verified TLS context did not retain session trust inputs"))?;
    let challenge = random_challenge()?;
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
) -> Result<Vec<AzureMaaTrustKey>, AttestationClientError> {
    if bundle.platform.cloud != "azure" {
        return Ok(Vec::new());
    }
    let binding = azure_maa_binding_from_session_bundle(bundle).map_err(|detail| {
        session_error(format!("committed_session_maa_signature_invalid: {detail}"))
    })?;
    if !context.manual_azure_maa_keys.is_empty() {
        return select_azure_maa_manual_trust_key(&binding, &context.manual_azure_maa_keys)
            .map(|key| vec![key])
            .map_err(|detail| {
                session_error(format!("committed_session_maa_signature_invalid: {detail}"))
            });
    }
    let client = context.chain_client.as_ref().ok_or_else(|| {
        session_error("no verifier-selected chain is available for committed Azure MAA trust")
    })?;
    client
        .resolve_azure_maa_signing_key_from_binding(&binding)
        .await
        .map(|key| vec![key])
        .map_err(committed_session_maa_error)
}

fn committed_session_maa_error(error: AttestationClientError) -> AttestationClientError {
    let code = match &error {
        AttestationClientError::AzureMaaKeyNotRegistered { .. } => {
            "committed_session_maa_key_not_registered"
        }
        AttestationClientError::AzureMaaKeyRevoked { .. } => "committed_session_maa_key_revoked",
        AttestationClientError::AzureMaaKeyExpired { .. } => "committed_session_maa_key_expired",
        AttestationClientError::AzureMaaIssuerMismatch { .. } => {
            "committed_session_maa_issuer_mismatch"
        }
        _ => "committed_session_maa_key_resolution_failed",
    };
    session_error(format!("{code}: {error}"))
}

fn enforce_required_binding(
    actual: BindingMode,
    required: Option<BindingMode>,
) -> Result<(), AttestationClientError> {
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
) -> Result<SessionTrust, AttestationClientError> {
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
            dcap_collateral: context.intel_tdx_dcap_collateral.clone().ok_or_else(|| {
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
            amd_snp_collateral: context.amd_snp_collateral.clone().ok_or_else(|| {
                session_error("verified TLS context has no GCP SNP verification collateral")
            })?,
        },
        ("azure", "tdx") => SessionPlatformTrust::AzureTdx {
            maa_signing_keys: committed_maa_keys,
            dcap_collateral: context.intel_tdx_dcap_collateral.clone().ok_or_else(|| {
                session_error("verified TLS context has no Azure TDX DCAP collateral")
            })?,
        },
        ("azure", "sev-snp") => SessionPlatformTrust::AzureSnp {
            maa_signing_keys: committed_maa_keys,
            amd_ark_roots: certificate_trust(
                &context.trust_anchors.amd_ark_roots,
                &context.trust_anchors.amd_ark_root_hashes,
            ),
            amd_snp_collateral: context.amd_snp_collateral.clone().ok_or_else(|| {
                session_error("verified TLS context has no Azure SNP verification collateral")
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
) -> Result<TrustedSessionPolicy, AttestationClientError> {
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
        amd_snp_security_policies: context.trust_anchors.amd_snp_security_policies.clone(),
    })
}

fn combined_pcr_specs(
    mut base_image: Vec<SessionPcrPolicy>,
    workload: Vec<SessionPcrPolicy>,
) -> Vec<SessionPcrPolicy> {
    base_image.extend(workload);
    base_image
}

fn required_identity_id(
    value: Option<[u8; 32]>,
    label: &str,
) -> Result<[u8; 32], AttestationClientError> {
    value.ok_or_else(|| session_error(format!("TLS verification did not select a {label} ID")))
}

fn select_profile(
    policy: &MeasurementPolicy,
    expected_id: [u8; 32],
) -> Result<&MeasurementProfile, AttestationClientError> {
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
) -> Result<&'a MeasurementVariant, AttestationClientError> {
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
) -> Result<Vec<SessionPcrPolicy>, AttestationClientError> {
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
        // A profile invariant always holds. `override_pcrs` is a historical field name: its
        // entries must be disjoint from `profile.invariants`. Overwriting here would accept a
        // committed session that on-chain registration rejects
        // (SessionRegistry.PcrVariantOverridesInvariant).
        if specs.contains_key(&spec.pcr_index) {
            return Err(session_error(format!(
                "variant {} pins PCR {} that profile {} declares invariant; \
                 profile invariants always hold and cannot be overridden",
                variant.name, spec.pcr_index, profile.name
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
            let verify_type = parse_verify_type(&spec.verify_type)?;
            if verify_type == SessionPcrVerifyType::Static && spec.match_data.len() != 1 {
                return Err(session_error(format!(
                    "STATIC PCR {} in the effective session policy requires exactly one matchData entry, got {}",
                    spec.pcr_index,
                    spec.match_data.len()
                )));
            }
            Ok(SessionPcrPolicy {
                pcr_index: spec.pcr_index,
                verify_type,
                match_data: spec.match_data.clone(),
            })
        })
        .collect()
}

fn parse_verify_type(value: &str) -> Result<SessionPcrVerifyType, AttestationClientError> {
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
) -> Result<Vec<SessionAttribute>, AttestationClientError> {
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
) -> Result<Vec<SessionAttribute>, AttestationClientError> {
    let mut out = Vec::with_capacity(values.len());
    let mut keys = BTreeSet::new();
    for value in values {
        let item = if let Some(name) = value.get("name").and_then(serde_json::Value::as_str) {
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
                            session_error(format!(
                                "{owner} readable reserved attribute {name} is missing Boolean value"
                            ))
                        })?;
                    SessionAttribute {
                        key: attribute.key(),
                        value: atakit_core::tee_attributes::bool_value(enabled),
                    }
                }
                Some(VerifiedTeeAttribute::IntelTdxTcbStatusAllowed) => {
                    let names = value
                        .get("value")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| {
                            session_error(format!(
                                "{owner} readable reserved attribute {name} value must be a status-name array"
                            ))
                        })?
                        .iter()
                        .map(|value| {
                            value.as_str().ok_or_else(|| {
                                session_error(format!(
                                    "{owner} readable reserved attribute {name} status names must be strings"
                                ))
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let mask = atakit_core::tee_attributes::tdx_tcb_status_mask(names)
                        .ok_or_else(|| {
                            session_error(format!(
                                "{owner} readable reserved attribute {name} must contain unique supported status names and include ok"
                            ))
                        })?;
                    SessionAttribute {
                        key: atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_KEY,
                        value: atakit_core::tee_attributes::u16_value(mask),
                    }
                }
                Some(attribute) => {
                    let packed = value
                        .get("value")
                        .and_then(serde_json::Value::as_str)
                        .and_then(atakit_core::tee_attributes::parse_bytes32_hex)
                        .ok_or_else(|| {
                            session_error(format!(
                                "{owner} readable reserved attribute {name} value must be a 0x-prefixed bytes32 string"
                            ))
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
                        return Err(session_error(format!(
                            "{owner} readable reserved attribute {name} value is invalid"
                        )));
                    }
                    SessionAttribute {
                        key: attribute.key(),
                        value: packed,
                    }
                }
                None if name.starts_with(TEE_ATTRIBUTE_NAMESPACE) => {
                    return Err(session_error(format!(
                        "{owner} attribute has unknown reserved name {name}"
                    )));
                }
                None => {
                    let string_value = value
                        .get("value")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            session_error(format!(
                                "{owner} custom readable attribute {name} value must be a string"
                            ))
                        })?;
                    SessionAttribute {
                        key: atakit_core::tee_attributes::attribute_key(name),
                        value: atakit_core::tee_attributes::attribute_string_value(string_value),
                    }
                }
            }
        } else {
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
            if let Some(attribute) =
                atakit_core::tee_attributes::VerifiedTeeAttribute::from_key(&item.key)
            {
                use atakit_core::tee_attributes::ReservedAttributeValueKind;
                match attribute.value_kind() {
                    ReservedAttributeValueKind::Boolean
                        if item.value != atakit_core::tee_attributes::ATTRIBUTE_FALSE
                            && item.value != atakit_core::tee_attributes::ATTRIBUTE_TRUE =>
                    {
                        return Err(session_error(format!(
                            "{owner} reserved Boolean attribute {} has invalid value",
                            attribute.name()
                        )));
                    }
                    ReservedAttributeValueKind::IntelTdxTcbStatusMask => {
                        let mask = u16::from_be_bytes([item.value[30], item.value[31]]);
                        if item.value[..30].iter().any(|byte| *byte != 0)
                            || atakit_core::tee_attributes::tdx_tcb_status_names(mask).is_none()
                        {
                            return Err(session_error(format!(
                                "{owner} Intel TDX TCB status mask is invalid"
                            )));
                        }
                    }
                    ReservedAttributeValueKind::AmdSevSnpTcb
                        if !atakit_core::tee_attributes::valid_amd_sev_snp_tcb(&item.value) =>
                    {
                        return Err(session_error(format!(
                            "{owner} AMD SEV-SNP TCB minimum is invalid"
                        )));
                    }
                    ReservedAttributeValueKind::AmdSevSnpPlatformInfoPolicy
                        if !atakit_core::tee_attributes::valid_amd_sev_snp_platform_info_policy(
                            &item.value,
                        ) =>
                    {
                        return Err(session_error(format!(
                            "{owner} AMD SEV-SNP PLATFORM_INFO policy is invalid"
                        )));
                    }
                    _ => {}
                }
            }
            item
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

fn decode_hex_32(value: &str) -> Result<[u8; 32], AttestationClientError> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(raw)
        .map_err(|error| session_error(format!("invalid bytes32 hex {value:?}: {error}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        session_error(format!("expected 32-byte hex, got {} bytes", bytes.len()))
    })
}

fn session_error(message: impl Into<String>) -> AttestationClientError {
    AttestationClientError::Verification(message.into())
}

fn random_challenge() -> Result<[u8; 32], AttestationClientError> {
    let mut challenge = [0u8; 32];
    let mut source = std::fs::File::open("/dev/urandom")
        .map_err(|error| AttestationClientError::Challenge(error.to_string()))?;
    source
        .read_exact(&mut challenge)
        .map_err(|error| AttestationClientError::Challenge(error.to_string()))?;
    Ok(challenge)
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

    /// A profile invariant always holds. A committed-session policy whose variant pins an index
    /// the profile declares invariant must fail closed here, otherwise offline verification would
    /// accept a session that on-chain `registerSession` rejects with
    /// `PcrVariantOverridesInvariant`.
    #[test]
    fn effective_pcr_specs_rejects_variant_pinning_an_invariant() {
        let mut profile = profile();
        profile.variants[0].override_pcrs = vec![PcrSpec {
            pcr_index: 4,
            verify_type: "static".into(),
            match_data: vec![format!("0x{}", "bb".repeat(32))],
            event_indices: Vec::new(),
            total_events: None,
        }];

        let error = effective_pcr_specs(&profile, &profile.variants[0])
            .expect_err("overlap with a profile invariant must be rejected");
        assert!(
            error.to_string().contains("declares invariant"),
            "unexpected: {error}"
        );
    }

    /// A variant pinning an index the profile leaves unpinned still resolves.
    #[test]
    fn effective_pcr_specs_allows_disjoint_variant() {
        let mut profile = profile();
        profile.variants[0].override_pcrs = vec![PcrSpec {
            pcr_index: 10,
            verify_type: "static".into(),
            match_data: vec![format!("0x{}", "cc".repeat(32))],
            event_indices: Vec::new(),
            total_events: None,
        }];

        let pcrs = effective_pcr_specs(&profile, &profile.variants[0])
            .expect("disjoint variant is allowed");
        let indices: Vec<u8> = pcrs.iter().map(|spec| spec.pcr_index).collect();
        assert_eq!(indices, vec![4, 10]);
    }

    #[test]
    fn effective_pcr_specs_rejects_static_without_exactly_one_match_data_entry() {
        let mut profile = profile();
        profile.invariants[0].verify_type = "static".into();
        profile.invariants[0].match_data = vec![
            format!("0x{}", "aa".repeat(32)),
            format!("0x{}", "bb".repeat(32)),
        ];

        let error = effective_pcr_specs(&profile, &profile.variants[0])
            .expect_err("STATIC with two matchData entries must be rejected");
        assert!(
            error
                .to_string()
                .contains("requires exactly one matchData entry, got 2"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn readable_reserved_attributes_merge_with_variant_override() {
        let mut profile = profile();
        profile.attributes = vec![
            serde_json::json!({
                "name": atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME,
                "value": false
            }),
            serde_json::json!({
                "key": format!("0x{}", "44".repeat(32)),
                "value": format!("0x{}", "55".repeat(32))
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_NAME,
                "value": "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004"
            }),
        ];
        profile.variants[0].attributes = vec![serde_json::json!({
            "name": atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME,
            "value": true
        })];

        let attributes = effective_attributes(&profile, &profile.variants[0]).unwrap();

        assert_eq!(
            attributes,
            [
                SessionAttribute {
                    key: [0x44; 32],
                    value: [0x55; 32]
                },
                SessionAttribute {
                    key: atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_KEY,
                    value: atakit_core::tee_attributes::parse_bytes32_hex(
                        "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004"
                    )
                    .unwrap()
                },
                SessionAttribute {
                    key: atakit_core::tee_attributes::INTEL_TDX_DEBUG_KEY,
                    value: atakit_core::tee_attributes::ATTRIBUTE_TRUE
                }
            ]
        );
    }

    #[test]
    fn reserved_policies_are_measurement_variant_overrides() {
        let mut value = profile();
        value.attributes = vec![
            serde_json::json!({
                "name": atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
                "value": ["ok"],
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_NAME,
                "value": "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
                "value": "0x0000000000000000000000000000000000000000000000010000000000000000",
            }),
        ];
        let stronger = "0x00000000df1e000500000000de1d000400000000de1d000400000000de1d0004";
        let platform_info = "0x0000000000000000000000000000000000000000000000000000000000000020";
        value.variants[0].attributes = vec![
            serde_json::json!({
                "name": atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
                "value": ["ok", "configuration-needed"],
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_NAME,
                "value": stronger,
            }),
            serde_json::json!({
                "name": atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
                "value": platform_info,
            }),
        ];
        let attributes = effective_attributes(&value, &value.variants[0]).unwrap();
        assert_eq!(
            attributes
                .iter()
                .find(|attribute| {
                    attribute.key == atakit_core::tee_attributes::INTEL_TDX_TCB_STATUS_ALLOWED_KEY
                })
                .unwrap()
                .value,
            atakit_core::tee_attributes::u16_value(0x9)
        );
        assert_eq!(
            attributes
                .iter()
                .find(|attribute| {
                    attribute.key == atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_KEY
                })
                .unwrap()
                .value,
            atakit_core::tee_attributes::parse_bytes32_hex(stronger).unwrap()
        );
        assert_eq!(
            attributes
                .iter()
                .find(|attribute| {
                    attribute.key
                        == atakit_core::tee_attributes::AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY
                })
                .unwrap()
                .value,
            atakit_core::tee_attributes::parse_bytes32_hex(platform_info).unwrap()
        );

        let hexadecimal = serde_json::json!({
            "key": format!(
                "0x{}",
                hex::encode(atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_KEY)
            ),
            "value": stronger,
        });
        value.variants[0].attributes = vec![hexadecimal];
        assert_eq!(
            effective_attributes(&value, &value.variants[0])
                .unwrap()
                .iter()
                .find(|attribute| {
                    attribute.key == atakit_core::tee_attributes::AMD_SEV_SNP_TCB_MINIMUM_KEY
                })
                .unwrap()
                .value,
            atakit_core::tee_attributes::parse_bytes32_hex(stronger).unwrap()
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
    fn committed_maa_registry_errors_keep_stable_verification_codes() {
        let cases = [
            (
                AttestationClientError::AzureMaaKeyNotRegistered { kid: "key".into() },
                "committed_session_maa_key_not_registered",
            ),
            (
                AttestationClientError::AzureMaaKeyRevoked { kid: "key".into() },
                "committed_session_maa_key_revoked",
            ),
            (
                AttestationClientError::AzureMaaKeyExpired {
                    kid: "key".into(),
                    not_after: 1,
                },
                "committed_session_maa_key_expired",
            ),
            (
                AttestationClientError::AzureMaaIssuerMismatch { kid: "key".into() },
                "committed_session_maa_issuer_mismatch",
            ),
        ];

        for (error, expected_code) in cases {
            let mapped = committed_session_maa_error(error).to_string();
            assert!(mapped.contains(expected_code), "{mapped}");
        }
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
