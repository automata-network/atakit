//! Verification of a caller-supplied, challenge-bound session evidence bundle.
//!
//! This path performs no portal network request. The caller owns the transport
//! and supplies the exact response returned by `GET /session/evidence-bundle`.
//! The selected verification mode still owns every trust anchor and policy.

use atakit_attestation::{
    verify_session_bundle_at, BindingMode, SessionEvidenceBundle, SessionRequestBinding,
    SessionVerificationInputs, VerifiedSession,
};
use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

use crate::collateral::amd_snp::resolve_amd_snp_collateral_for_session_bundle;
use crate::collateral::intel_tdx::tdx_collateral_quote_from_session_bundle;
use crate::portal::session::{
    build_supplied_session_trust, committed_session_maa_keys, enforce_required_binding,
    PortalSessionVerificationContext,
};
use crate::portal::tls::{resolve_tdx_dcap_for_source_quote, session_authority};
use crate::trust::builder::TrustAnchorsBuilder;
use crate::trust::request::CollateralRequest;
use crate::trust::source::{TrustProvenance, TrustSource};
use crate::{AttestationClientError, PortalVerificationError, SessionVerificationMode};

/// The exact response returned by `GET /session/evidence-bundle`.
#[derive(Debug, Clone)]
pub struct ChallengeBoundSessionEvidence {
    evidence_bundle: SessionEvidenceBundle,
    signed_evidence_bundle: serde_json::Value,
    request_binding: SessionRequestBinding,
}

impl ChallengeBoundSessionEvidence {
    /// Validate an exact portal evidence-bundle value without changing the
    /// value that `request_binding.signature` covers.
    pub fn from_parts(
        evidence_bundle: serde_json::Value,
        request_binding: SessionRequestBinding,
    ) -> Result<Self, serde_json::Error> {
        let typed_bundle = serde_json::from_value(evidence_bundle.clone())?;
        Ok(Self {
            evidence_bundle: typed_bundle,
            signed_evidence_bundle: evidence_bundle,
            request_binding,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SessionEvidenceBundle,
        serde_json::Value,
        SessionRequestBinding,
    ) {
        (
            self.evidence_bundle,
            self.signed_evidence_bundle,
            self.request_binding,
        )
    }
}

impl<'de> Deserialize<'de> for ChallengeBoundSessionEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireEvidence {
            evidence_bundle: Box<RawValue>,
            request_binding: SessionRequestBinding,
        }

        let wire = WireEvidence::deserialize(deserializer)?;
        let evidence_bundle =
            serde_json::from_str::<SessionEvidenceBundle>(wire.evidence_bundle.get())
                .map_err(D::Error::custom)?;
        let signed_evidence_bundle =
            serde_json::from_str(wire.evidence_bundle.get()).map_err(D::Error::custom)?;
        Ok(Self {
            evidence_bundle,
            signed_evidence_bundle,
            request_binding: wire.request_binding,
        })
    }
}

impl Serialize for ChallengeBoundSessionEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ChallengeBoundSessionEvidence", 2)?;
        state.serialize_field("evidence_bundle", &self.signed_evidence_bundle)?;
        state.serialize_field("request_binding", &self.request_binding)?;
        state.end()
    }
}

/// Inputs for verifying a session evidence bundle supplied over a transport
/// owned by the caller.
#[derive(Debug, Clone)]
pub struct SuppliedSessionBundleVerificationRequest {
    pub session_evidence: ChallengeBoundSessionEvidence,
    pub expected_challenge: [u8; 32],
    pub mode: SessionVerificationMode,
    /// Optional caller policy for the verified session's actual binding mode.
    /// This is independent of the selected trust authority.
    pub required_binding: Option<BindingMode>,
}

/// A verified session plus the source of every trust input used.
#[derive(Debug, Clone)]
pub struct VerifiedSuppliedSessionBundle {
    pub session: VerifiedSession,
    pub trust_provenance: TrustProvenance,
}

/// A supplied session bundle with every policy, trust anchor, and collateral
/// input resolved. The remaining work is synchronous cryptographic
/// verification and can run on a bounded blocking worker.
#[derive(Debug)]
pub struct PreparedSuppliedSessionBundleVerification {
    signed_bundle: serde_json::Value,
    request_binding: SessionRequestBinding,
    expected_challenge: [u8; 32],
    trust: atakit_attestation::SessionTrust,
    required_binding: Option<BindingMode>,
    trust_provenance: TrustProvenance,
}

impl PreparedSuppliedSessionBundleVerification {
    /// Complete synchronous cryptographic and policy verification.
    pub fn verify(self) -> Result<VerifiedSuppliedSessionBundle, PortalVerificationError> {
        self.verify_at(std::time::SystemTime::now())
    }

    fn verify_at(
        self,
        verification_time: std::time::SystemTime,
    ) -> Result<VerifiedSuppliedSessionBundle, PortalVerificationError> {
        let verified = verify_session_bundle_at(
            SessionVerificationInputs {
                bundle: self.signed_bundle,
                request_binding: self.request_binding,
                expected_challenge: self.expected_challenge,
                trust: self.trust,
            },
            verification_time,
        )
        .map_err(|failure| PortalVerificationError::SessionVerification {
            failure: Box::new(failure),
        })?;
        enforce_required_binding(verified.binding_mode, self.required_binding)
            .map_err(client_error)?;

        Ok(VerifiedSuppliedSessionBundle {
            session: verified,
            trust_provenance: self.trust_provenance,
        })
    }
}

/// Resolve every asynchronous input for a caller-supplied session bundle
/// without contacting a peer portal.
pub async fn prepare_supplied_session_bundle(
    request: SuppliedSessionBundleVerificationRequest,
) -> Result<PreparedSuppliedSessionBundleVerification, PortalVerificationError> {
    let SuppliedSessionBundleVerificationRequest {
        session_evidence,
        expected_challenge,
        mode,
        required_binding,
    } = request;
    let (typed_bundle, signed_bundle, request_binding) = session_evidence.into_parts();

    let measurement_policy = mode.measurement_policy().await?;
    let base_image_id = decode_bytes32(&measurement_policy.pack.subject.id).map_err(|message| {
        PortalVerificationError::Config {
            message: format!("trusted measurement policy subject.id: {message}"),
        }
    })?;
    let workload_policy = resolve_workload_policy(&mode, base_image_id).await?;
    let trusted_binding = trusted_binding(&mode);
    let trust_source = mode.trust_source();
    if let TrustSource::Packs(source) = &trust_source {
        source.ensure_valid_now()?;
    }

    let tdx_quote =
        tdx_collateral_quote_from_session_bundle(&typed_bundle).map_err(bundle_resolution_error)?;
    let intel_tdx_dcap_collateral = resolve_tdx_dcap_for_source_quote(tdx_quote, &trust_source)
        .await
        .map_err(bundle_resolution_error)?;
    let amd_snp_collateral =
        resolve_amd_snp_collateral_for_session_bundle(&typed_bundle, trust_source.amd_snp_crls())
            .await
            .map_err(bundle_resolution_error)?;
    let collateral_request =
        CollateralRequest::from_session_bundle(&typed_bundle, amd_snp_collateral.as_ref())
            .map_err(bundle_resolution_error)?;
    let (trust_anchors, trust_provenance) = TrustAnchorsBuilder::new(trust_source.clone())
        .resolve(&collateral_request)
        .await?;
    let authority = session_authority(&trust_source, &trust_anchors);
    let context = PortalSessionVerificationContext {
        platform: atakit_attestation::PlatformEvidence {
            cloud: typed_bundle.platform.cloud.clone(),
            tee: typed_bundle.platform.tee.clone(),
            machine_type: typed_bundle.platform.machine_type.clone(),
        },
        measurement_policy,
        trust_anchors,
        authority,
        amd_snp_collateral,
        intel_tdx_dcap_collateral,
    };
    let committed_maa_keys = committed_session_maa_keys(&context, &typed_bundle)
        .await
        .map_err(client_error)?;
    let trust = build_supplied_session_trust(
        &context,
        &typed_bundle,
        workload_policy,
        committed_maa_keys,
        trusted_binding,
        base_image_id,
    )
    .map_err(client_error)?;

    Ok(PreparedSuppliedSessionBundleVerification {
        signed_bundle,
        request_binding,
        expected_challenge,
        trust,
        required_binding,
        trust_provenance,
    })
}

/// Verify a caller-supplied session bundle without contacting a peer portal.
pub async fn verify_supplied_session_bundle(
    request: SuppliedSessionBundleVerificationRequest,
) -> Result<VerifiedSuppliedSessionBundle, PortalVerificationError> {
    let prepared = prepare_supplied_session_bundle(request).await?;
    tokio::task::spawn_blocking(move || prepared.verify())
        .await
        .map_err(
            |error| PortalVerificationError::PortalSessionVerificationFailed {
                message: format!("session bundle verification worker failed: {error}"),
            },
        )?
}

async fn resolve_workload_policy(
    mode: &SessionVerificationMode,
    base_image_id: [u8; 32],
) -> Result<crate::TrustedWorkloadSessionPolicy, PortalVerificationError> {
    match mode {
        SessionVerificationMode::Chain {
            source, workload, ..
        } => source
            .client()
            .resolve_workload_policy(&workload.to_string(), base_image_id)
            .await
            .map_err(client_error),
        SessionVerificationMode::Packs {
            source, workload, ..
        } => crate::pack::workload::packed_workload_policy(
            source.workload_pack()?,
            workload,
            base_image_id,
        )
        .map_err(|error| bundle_resolution_error(error.to_string())),
        SessionVerificationMode::Explicit {
            workload_policy, ..
        } => Ok(workload_policy.clone()),
    }
}

fn trusted_binding(
    mode: &SessionVerificationMode,
) -> Option<atakit_attestation::TrustedSessionBinding> {
    match mode {
        SessionVerificationMode::Chain { source, .. } => Some(source.binding()),
        SessionVerificationMode::Packs { .. } | SessionVerificationMode::Explicit { .. } => None,
    }
}

fn decode_bytes32(value: &str) -> Result<[u8; 32], String> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| "missing 0x prefix".to_string())?;
    let bytes = hex::decode(raw).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, got {}", bytes.len()))
}

fn client_error(error: AttestationClientError) -> PortalVerificationError {
    match error {
        AttestationClientError::SessionVerification(failure) => {
            PortalVerificationError::SessionVerification { failure }
        }
        error => bundle_resolution_error(error.to_string()),
    }
}

fn bundle_resolution_error(message: impl Into<String>) -> PortalVerificationError {
    PortalVerificationError::PortalSessionVerificationFailed {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atakit_attestation::{
        amd_snp_security_state, AmdSnpSecurityPolicy, BaseImageMeasurements, MeasurementPack,
        MeasurementPolicy, MeasurementProfile, MeasurementVariant, PcrBankSelection, PcrSpec256,
        Subject, TrustAnchors,
    };
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;

    use crate::collateral::intel_tdx::IntelTdxDcapCollateralConfig;
    use crate::trust::files::TlsVerificationTrust;
    use crate::trust::source::{ExplicitTrustSource, TrustInputSource};

    /// Read-only replay against a caller-selected registry and AMD collateral.
    /// No live VM or transaction is needed. The time is fixed to capture time.
    #[tokio::test]
    #[ignore = "requires ATAKIT_AWS_ROTATION_RPC_URL and ATAKIT_AWS_ROTATION_SESSION_REGISTRY"]
    async fn aws_rotation_saved_evidence_chain_replay() {
        let raw: serde_json::Value = serde_json::from_str(include_str!(
            "../../atakit-attestation/testdata/aws-rotation/evidence.json"
        ))
        .unwrap();
        let expected_challenge: [u8; 32] = URL_SAFE_NO_PAD
            .decode(raw["request_binding"]["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let source = crate::trust::source::ChainTrustSource::connect(
            std::env::var("ATAKIT_AWS_ROTATION_RPC_URL").unwrap(),
            std::env::var("ATAKIT_AWS_ROTATION_SESSION_REGISTRY").unwrap(),
            IntelTdxDcapCollateralConfig::default(),
        )
        .await
        .unwrap();
        let publisher = "0xaef8fc89416f01494ec6534de68d30aab26d7598db8a05967b0ba7d3ecb259d2";
        let prepared = prepare_supplied_session_bundle(SuppliedSessionBundleVerificationRequest {
            session_evidence: serde_json::from_value(raw).unwrap(),
            expected_challenge,
            mode: SessionVerificationMode::Chain {
                source,
                base_image: format!("{publisher}/automata-linux:v0.3.1-debug")
                    .parse()
                    .unwrap(),
                workload: format!("{publisher}/fedora-oci:v0.0.17").parse().unwrap(),
            },
            required_binding: Some(BindingMode::Chain),
        })
        .await
        .unwrap();
        let verified = prepared
            .verify_at(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1789198200))
            .unwrap();
        assert!(verified.session.checks.iter().all(|check| check.valid));
        println!(
            "Saved AWS rotation passed {} full-session checks",
            verified.session.checks.len()
        );
    }

    fn fixture(encoded: &str) -> Vec<u8> {
        STANDARD
            .decode(encoded.lines().collect::<String>())
            .expect("embedded fixture must be valid base64")
    }

    #[derive(Deserialize)]
    struct SuppliedBundleFixture {
        evidence_bundle: serde_json::Value,
        request_binding: SessionRequestBinding,
        gcp_ak_roots: Vec<String>,
    }

    #[test]
    fn normal_chain_bound_portal_shape_preserves_the_exact_signed_bundle() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/supplied-session-bundle-gcp-snp.json"
        ))
        .expect("parse supplied-session fixture");
        let mut evidence_bundle = fixture["evidence_bundle"].clone();
        evidence_bundle["binding"]["mode"] = serde_json::json!("chain");
        evidence_bundle["binding"]["chain_id"] = serde_json::json!(1);
        evidence_bundle["binding"]["registry"] =
            serde_json::json!(format!("0x{}", "22".repeat(20)));
        evidence_bundle["owner"]["contract_authorization"] = serde_json::json!({
            "op_expires_at": 1_900_000_000u64,
            "payload": format!("0x{}", "33".repeat(32)),
            "signature": format!("0x{}", "44".repeat(65))
        });
        let canonical_signed = serde_json_canonicalizer::to_vec(&evidence_bundle)
            .expect("canonicalize exact portal bundle");

        let parsed: ChallengeBoundSessionEvidence = serde_json::from_value(serde_json::json!({
            "evidence_bundle": evidence_bundle,
            "request_binding": fixture["request_binding"].clone()
        }))
        .expect("parse normal chain-bound portal response");
        let (_, preserved, _) = parsed.into_parts();

        assert!(preserved["owner"]["contract_authorization"]
            .get("calldata_hash")
            .is_none());
        assert_eq!(
            serde_json_canonicalizer::to_vec(&preserved)
                .expect("canonicalize preserved portal bundle"),
            canonical_signed
        );
    }

    #[tokio::test]
    async fn supplied_bundle_carries_optional_binding_policy_without_skipping_verification() {
        let supplied_fixture: SuppliedBundleFixture = serde_json::from_str(include_str!(
            "../testdata/supplied-session-bundle-gcp-snp.json"
        ))
        .expect("parse supplied-session fixture");
        let report = fixture(include_str!(
            "../../atakit-attestation/testdata/fedora-oci-gcp-n2d-standard-4/report.bin.b64"
        ));
        let ark = fixture(include_str!(
            "../../atakit-attestation/testdata/fedora-oci-gcp-n2d-standard-4/ark.der.b64"
        ));
        let crl = fixture(include_str!(
            "../../atakit-attestation/testdata/fedora-oci-gcp-n2d-standard-4/milan.crl.der.b64"
        ));
        let security_state = amd_snp_security_state(&report).expect("read SNP security state");
        let gcp_ak_roots = supplied_fixture
            .gcp_ak_roots
            .iter()
            .map(|root| URL_SAFE_NO_PAD.decode(root).expect("decode GCP AK root"))
            .collect::<Vec<_>>();
        let base_image_id = [0x32; 32];
        let workload_id = [0x31; 32];
        let profile_name = "gcp-sev-snp";
        let variant_name = "n2d-standard-4";
        let profile_id = atakit_cvm_encoding::platform_profile_id(base_image_id, profile_name);
        let variant_id = atakit_cvm_encoding::variant_id(profile_id, variant_name);
        let comparison = format!(
            "0x{}",
            hex::encode(atakit_cvm_encoding::pcr_comparison::encode_static256(
                [0xaa; 32]
            ))
        );
        let measurement_policy = MeasurementPolicy {
            source: "test explicit policy".to_string(),
            pack: MeasurementPack {
                schema: atakit_attestation::BASE_IMAGE_MEASUREMENT_PACK_SCHEMA.to_string(),
                revision: 1,
                published_at: 1_786_000_000,
                subject: Subject {
                    publisher: format!("0x{}", "11".repeat(32)),
                    name: "automata-linux".to_string(),
                    version: "v1".to_string(),
                    id: format!("0x{}", hex::encode(base_image_id)),
                    uri: None,
                    archive_sha256: None,
                },
                measurements: serde_json::to_value(BaseImageMeasurements {
                    profiles: vec![MeasurementProfile {
                        name: profile_name.to_string(),
                        id: format!("0x{}", hex::encode(profile_id)),
                        cloud: "gcp".to_string(),
                        tee: "sev-snp".to_string(),
                        pcr_bank_selection: PcrBankSelection::Sha256,
                        invariant_pcrs256: vec![PcrSpec256 {
                            pcr_index: 4,
                            comparison,
                        }],
                        invariant_pcrs384: Vec::new(),
                        variants: vec![MeasurementVariant {
                            name: variant_name.to_string(),
                            id: format!("0x{}", hex::encode(variant_id)),
                            machine_types: vec![variant_name.to_string()],
                            variant_pcrs256: Vec::new(),
                            variant_pcrs384: Vec::new(),
                            attributes: Vec::new(),
                        }],
                        attributes: Vec::new(),
                    }],
                })
                .expect("serialize measurement policy"),
            },
        };
        let anchors = TrustAnchors {
            gcp_roots: gcp_ak_roots,
            amd_ark_roots: vec![ark],
            amd_snp_security_policies: vec![AmdSnpSecurityPolicy {
                cpuid: security_state.cpuid,
                minimum_tcb: [0; 32],
                platform_info_policy: [0; 32],
                required_launch_mitigation_vector: 0,
                required_current_mitigation_vector: 0,
            }],
            ..TrustAnchors::default()
        };
        let mode = SessionVerificationMode::Explicit {
            source: ExplicitTrustSource::new(
                TlsVerificationTrust {
                    trust_anchors: anchors,
                    amd_snp_crls: vec![crl],
                    sources: Default::default(),
                },
                IntelTdxDcapCollateralConfig::default(),
            )
            .expect("construct explicit trust source"),
            measurement_policy: Box::new(measurement_policy),
            workload_policy: crate::TrustedWorkloadSessionPolicy {
                workload_id,
                pcr_specs256: Vec::new(),
                pcr_specs384: Vec::new(),
                attribute_requirements: Vec::new(),
            },
        };
        let expected_challenge = [0x55; 32];
        let session_evidence = ChallengeBoundSessionEvidence::from_parts(
            supplied_fixture.evidence_bundle,
            supplied_fixture.request_binding,
        )
        .expect("validate supplied session evidence");

        for required_binding in [Some(BindingMode::Local), Some(BindingMode::Chain)] {
            let prepared =
                prepare_supplied_session_bundle(SuppliedSessionBundleVerificationRequest {
                    session_evidence: session_evidence.clone(),
                    expected_challenge,
                    mode: mode.clone(),
                    required_binding,
                })
                .await
                .expect("prepare supplied bundle with a caller binding policy");
            assert_eq!(prepared.required_binding, required_binding);
        }

        let prepared = prepare_supplied_session_bundle(SuppliedSessionBundleVerificationRequest {
            session_evidence,
            expected_challenge,
            mode,
            required_binding: None,
        })
        .await
        .expect("prepare the supplied GCP SNP bundle");

        assert_eq!(prepared.required_binding, None);
        assert!(!prepared.trust_provenance.inputs.is_empty());
        assert!(prepared
            .trust_provenance
            .inputs
            .values()
            .all(|source| matches!(source, TrustInputSource::File { .. })));
        let error = prepared
            .verify_at(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_784_851_200))
            .expect_err("no binding policy must not skip normal bundle verification");
        let PortalVerificationError::SessionVerification { failure } = error else {
            panic!("expected a session verification failure, got {error:?}");
        };
        assert_eq!(
            failure.errors,
            ["request-binding: request-binding signature mismatch"]
        );
        assert!(failure
            .checks
            .iter()
            .filter(|check| check.name != "request-binding")
            .all(|check| check.valid));
    }
}
