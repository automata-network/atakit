//! Resolve every trust input for one verification from one selected source.
//!
//! The builder does not overlay one source's values onto another's and there
//! is no precedence rule, because there is nothing to order. A required input
//! the selected source cannot supply fails closed naming the input; it never
//! falls through to another source.
//!
//! This replaces the per-field `if trust_anchors.<field>.is_empty()` gap
//! filling that used to sit inside the chain resolution path, interleaved with
//! the platform checks that decided whether a field was needed at all. Those
//! branches implemented "verifier-supplied wins, chain fills the rest", a rule
//! withdrawn on 2026-08-07: an operator who believed they had pinned a value
//! could not tell from the result whether the pinned value was used or whether
//! a chain value had quietly replaced a missing one.

use atakit_attestation::{AzureMaaTrustCertificate, TrustAnchors};

use crate::error::PortalVerificationError;
use crate::trust::request::CollateralRequest;
use crate::trust::requirements::{required_trust_inputs_for_request, RequiredTrustInput};
use crate::trust::source::{
    ChainTrustSource, ExplicitTrustSource, TrustInputSource, TrustProvenance, TrustSource,
};

/// Resolves trust anchors from exactly one source.
#[derive(Debug, Clone)]
pub struct TrustAnchorsBuilder {
    source: TrustSource,
}

impl TrustAnchorsBuilder {
    pub fn new(source: TrustSource) -> Self {
        Self { source }
    }

    pub fn source(&self) -> &TrustSource {
        &self.source
    }

    /// Resolve every input the presented platform requires, and report where
    /// each one came from.
    pub async fn resolve(
        &self,
        request: &CollateralRequest,
    ) -> Result<(TrustAnchors, TrustProvenance), PortalVerificationError> {
        match &self.source {
            TrustSource::Chain(source) => resolve_from_chain(source, request).await,
            TrustSource::Explicit(source) => resolve_from_explicit(source, request),
        }
    }
}

/// Chain mode. Every required input is read from the registry graph rooted at
/// the verifier-selected `SessionRegistry`; nothing is taken from operator
/// files, and no input is conditionally skipped because something was already
/// supplied.
async fn resolve_from_chain(
    source: &ChainTrustSource,
    request: &CollateralRequest,
) -> Result<(TrustAnchors, TrustProvenance), PortalVerificationError> {
    let client = source.client();
    let registry = source.session_registry().to_string();
    let mut anchors = TrustAnchors::default();
    let mut provenance = TrustProvenance::default();
    let chain_source = || TrustInputSource::Chain {
        registry: registry.clone(),
    };

    for input in required_trust_inputs_for_request(request) {
        match input {
            RequiredTrustInput::GcpAkRoot => {
                let root = request.gcp_ak_root.as_ref().ok_or_else(|| missing(input))?;
                let hash = client
                    .resolve_gcp_ak_root(root)
                    .await
                    .map_err(chain_failure)?;
                anchors.gcp_root_hashes.push(hash);
            }
            RequiredTrustInput::AzureMaaSigningCertificate => {
                let jwt = request
                    .azure_maa_jwt
                    .as_ref()
                    .ok_or_else(|| missing(input))?;
                let key = client
                    .resolve_azure_maa_signing_key(&jwt.kid, &jwt.issuer)
                    .await
                    .map_err(chain_failure)?;
                anchors.azure_maa_keys.push(AzureMaaTrustCertificate {
                    public_key: key.public_key,
                    not_after: key.not_after,
                });
            }
            RequiredTrustInput::AmdArkRoot => {
                let ark = request.amd_ark.as_ref().ok_or_else(|| missing(input))?;
                let hash = client
                    .resolve_amd_ark_root(ark)
                    .await
                    .map_err(chain_failure)?;
                anchors.amd_ark_root_hashes.push(hash);
            }
            RequiredTrustInput::AmdSnpSecurityPolicy => {
                let cpuid = request.amd_snp_cpuid.ok_or_else(|| missing(input))?;
                let policy = client
                    .resolve_amd_snp_security_policy(cpuid)
                    .await
                    .map_err(chain_failure)?;
                anchors.amd_snp_security_policies.push(policy);
            }
            RequiredTrustInput::AwsNitroRoot => {
                let root = request
                    .aws_nitro_root
                    .as_ref()
                    .ok_or_else(|| missing(input))?;
                let hash = client
                    .resolve_aws_nitro_root(root)
                    .await
                    .map_err(chain_failure)?;
                anchors.aws_nitro_root_hashes.push(hash);
            }
            RequiredTrustInput::AwsDocumentLimits => {
                let (maximum_age, allowed_future) = client
                    .resolve_aws_document_freshness_limits()
                    .await
                    .map_err(chain_failure)?;
                anchors.aws_document_maximum_age_seconds = Some(maximum_age);
                anchors.aws_document_allowed_future_clock_difference_seconds = Some(allowed_future);
            }
        }
        provenance.record(input.name(), chain_source());
    }

    Ok((anchors, provenance))
}

/// Explicit mode. The operator supplied the inputs and is the authority.
/// Nothing is read from a chain, and a required input the operator did not
/// supply fails closed naming both the input and the flag that supplies it.
fn resolve_from_explicit(
    source: &ExplicitTrustSource,
    request: &CollateralRequest,
) -> Result<(TrustAnchors, TrustProvenance), PortalVerificationError> {
    let anchors = source.anchors().clone();
    let mut provenance = TrustProvenance::default();

    for input in required_trust_inputs_for_request(request) {
        if !input.is_satisfied_by(&anchors, request) {
            return Err(PortalVerificationError::Config {
                message: format!(
                    "explicit trust mode is missing {} for {}/{}; supply it with {}",
                    input.name(),
                    request.cloud,
                    request.tee,
                    input.explicit_source()
                ),
            });
        }
        provenance.record(input.name(), source.provenance_for(input));
    }

    Ok((anchors, provenance))
}

fn missing(input: RequiredTrustInput) -> PortalVerificationError {
    PortalVerificationError::PortalTlsAttestationFailed {
        message: format!(
            "the attestation response does not carry the material needed to resolve {}",
            input.name()
        ),
    }
}

fn chain_failure(error: crate::chain::AttestationClientError) -> PortalVerificationError {
    PortalVerificationError::PortalTlsAttestationFailed {
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::intel_tdx::IntelTdxDcapCollateralConfig;
    use crate::trust::files::TlsVerificationTrust;
    use crate::trust::request::AzureMaaJwtInfo;
    use atakit_attestation::AmdSnpSecurityPolicy;

    pub(super) const SUPPORTED_PLATFORMS: &[(&str, &str)] = &[
        ("gcp", "tdx"),
        ("gcp", "sev-snp"),
        ("azure", "tdx"),
        ("azure", "sev-snp"),
        ("aws", "sev-snp"),
    ];

    const REPORT_CPUID: u32 = 0x0019_1101;

    pub(super) fn request(cloud: &str, tee: &str) -> CollateralRequest {
        let is_snp = tee == "sev-snp";
        CollateralRequest {
            cloud: cloud.to_string(),
            tee: tee.to_string(),
            machine_type: "test".to_string(),
            azure_maa_jwt: (cloud == "azure").then(|| AzureMaaJwtInfo {
                kid: "kid-1".to_string(),
                issuer: "https://issuer.example".to_string(),
            }),
            gcp_ak_root: (cloud == "gcp").then(|| vec![0x01; 16]),
            aws_nitro_root: (cloud == "aws").then(|| vec![0x03; 16]),
            amd_snp_cpuid: is_snp.then_some(REPORT_CPUID),
            amd_ark: is_snp.then(|| vec![0x02; 16]),
        }
    }

    /// Anchors satisfying exactly what this request requires, and nothing more.
    pub(super) fn complete_anchors(request: &CollateralRequest) -> TrustAnchors {
        let mut anchors = TrustAnchors::default();
        for input in required_trust_inputs_for_request(request) {
            match input {
                RequiredTrustInput::GcpAkRoot => anchors.gcp_roots.push(vec![0x01; 16]),
                RequiredTrustInput::AzureMaaSigningCertificate => {
                    anchors.azure_maa_keys.push(AzureMaaTrustCertificate {
                        public_key: vec![0xaa; 32],
                        not_after: u64::MAX,
                    })
                }
                RequiredTrustInput::AmdArkRoot => anchors.amd_ark_roots.push(vec![0x02; 16]),
                RequiredTrustInput::AmdSnpSecurityPolicy => {
                    anchors
                        .amd_snp_security_policies
                        .push(AmdSnpSecurityPolicy {
                            cpuid: REPORT_CPUID,
                            minimum_tcb: [0u8; 32],
                            platform_info_policy: [0u8; 32],
                            required_launch_mitigation_vector: 0,
                            required_current_mitigation_vector: 0,
                        })
                }
                RequiredTrustInput::AwsNitroRoot => anchors.aws_nitro_roots.push(vec![0x03; 16]),
                RequiredTrustInput::AwsDocumentLimits => {
                    anchors.aws_document_maximum_age_seconds = Some(300);
                    anchors.aws_document_allowed_future_clock_difference_seconds = Some(60);
                }
            }
        }
        anchors
    }

    pub(super) fn explicit(anchors: TrustAnchors) -> TrustAnchorsBuilder {
        let trust = TlsVerificationTrust {
            trust_anchors: anchors,
            ..TlsVerificationTrust::default()
        };
        TrustAnchorsBuilder::new(TrustSource::Explicit(
            ExplicitTrustSource::new(trust, IntelTdxDcapCollateralConfig::default())
                .expect("explicit source"),
        ))
    }

    /// Explicit mode resolves every required input from the supplied anchors,
    /// and every resolved input reports the operator as its authority.
    #[tokio::test]
    async fn complete_explicit_input_resolves_with_operator_provenance() {
        for (cloud, tee) in SUPPORTED_PLATFORMS {
            let request = request(cloud, tee);
            let (anchors, provenance) = explicit(complete_anchors(&request))
                .resolve(&request)
                .await
                .unwrap_or_else(|error| panic!("{cloud}/{tee}: {error}"));

            assert!(!provenance.inputs.is_empty(), "{cloud}/{tee}");
            for (input, source) in &provenance.inputs {
                assert!(
                    matches!(source, TrustInputSource::File { .. }),
                    "{cloud}/{tee}: {input} must report the operator as its authority, got {source:?}"
                );
            }
            assert!(required_trust_inputs_for_request(&request)
                .into_iter()
                .all(|input| input.is_satisfied_by(&anchors, &request)));
        }
    }

    /// Test 9 of the exclusive-mode set. Withholding any single required input
    /// fails closed and names both the input and the flag that supplies it. A
    /// generic "no trusted collateral available" is a failure of this test.
    #[tokio::test]
    async fn incomplete_explicit_input_fails_closed_naming_the_input() {
        for (cloud, tee) in SUPPORTED_PLATFORMS {
            let request = request(cloud, tee);
            for withheld in required_trust_inputs_for_request(&request) {
                let mut anchors = complete_anchors(&request);
                match withheld {
                    RequiredTrustInput::GcpAkRoot => {
                        anchors.gcp_roots.clear();
                        anchors.gcp_root_hashes.clear();
                    }
                    RequiredTrustInput::AzureMaaSigningCertificate => {
                        anchors.azure_maa_keys.clear()
                    }
                    RequiredTrustInput::AmdArkRoot => {
                        anchors.amd_ark_roots.clear();
                        anchors.amd_ark_root_hashes.clear();
                    }
                    RequiredTrustInput::AmdSnpSecurityPolicy => {
                        anchors.amd_snp_security_policies.clear()
                    }
                    RequiredTrustInput::AwsNitroRoot => {
                        anchors.aws_nitro_roots.clear();
                        anchors.aws_nitro_root_hashes.clear();
                    }
                    RequiredTrustInput::AwsDocumentLimits => {
                        anchors.aws_document_maximum_age_seconds = None;
                        anchors.aws_document_allowed_future_clock_difference_seconds = None;
                    }
                }

                let error = explicit(anchors)
                    .resolve(&request)
                    .await
                    .expect_err("withholding a required input must fail closed");
                let message = error.to_string();
                assert!(
                    message.contains(withheld.name()),
                    "{cloud}/{tee}: the failure must name {}; got {message}",
                    withheld.name()
                );
                assert!(
                    message.contains(withheld.explicit_source()),
                    "{cloud}/{tee}: the failure must name the supplying flag; got {message}"
                );
            }
        }
    }

    /// An AMD SEV-SNP policy for a different CPUID does not satisfy the
    /// requirement. The platform-pair matrix cannot see the report, so this is
    /// only checkable once the request carries the value.
    #[tokio::test]
    async fn a_policy_for_another_cpuid_does_not_satisfy_the_requirement() {
        let request = request("aws", "sev-snp");
        let mut anchors = complete_anchors(&request);
        anchors.amd_snp_security_policies = vec![AmdSnpSecurityPolicy {
            cpuid: 0xdead_beef,
            minimum_tcb: [0u8; 32],
            platform_info_policy: [0u8; 32],
            required_launch_mitigation_vector: 0,
            required_current_mitigation_vector: 0,
        }];

        let error = explicit(anchors)
            .resolve(&request)
            .await
            .expect_err("a wrong-CPUID policy must not satisfy the requirement");
        assert!(error.to_string().contains("amd-snp-security-policy"));
    }

    /// An Azure response whose binding is not an Azure MAA token needs no MAA
    /// signing certificate, so resolution succeeds without one.
    #[tokio::test]
    async fn azure_without_a_maa_binding_needs_no_signing_certificate() {
        let mut request = request("azure", "tdx");
        request.azure_maa_jwt = None;
        let (_, provenance) = explicit(TrustAnchors::default())
            .resolve(&request)
            .await
            .expect("no inputs are required");
        assert!(provenance.inputs.is_empty());
    }
}

/// Transport-level proof that explicit mode never reads a chain.
///
/// These assert on what reached the network, not on what a verification
/// returned. A verification that wrongly consulted a chain and then succeeded
/// is indistinguishable from one that never consulted it by return value alone,
/// which is why the exclusive-mode test list calls for a call counter.
#[cfg(test)]
mod no_chain_read_outside_chain_mode {
    use super::tests::{complete_anchors, explicit, request, SUPPORTED_PLATFORMS};
    use crate::chain::{AttestationClient, AttestationClientConfig};
    use crate::test_support::CountingRpcEndpoint;

    const SESSION_REGISTRY: &str = "0x1111111111111111111111111111111111111111";

    async fn connect(endpoint: &CountingRpcEndpoint) -> AttestationClient {
        AttestationClient::connect(AttestationClientConfig {
            rpc_url: endpoint.url().to_string(),
            session_registry: SESSION_REGISTRY.to_string(),
            expected_chain_id: None,
            expected_base_image_registry: None,
            expected_workload_registry: None,
        })
        .await
        .expect("connect against the counting endpoint")
    }

    /// Positive control. Without it the two zero-count assertions below could
    /// pass because the endpoint never worked, rather than because nothing
    /// reached it.
    #[tokio::test]
    async fn the_counting_endpoint_records_chain_reads() {
        let endpoint = CountingRpcEndpoint::start().await;
        connect(&endpoint).await;
        assert!(
            endpoint.requests() > 0,
            "connecting must reach the endpoint, or the zero-count tests prove nothing"
        );
    }

    /// Test 8. A complete explicit resolution, for every supported platform,
    /// performs no chain read at all.
    #[tokio::test]
    async fn explicit_mode_performs_no_chain_rpc() {
        let endpoint = CountingRpcEndpoint::start().await;

        for (cloud, tee) in SUPPORTED_PLATFORMS {
            let request = request(cloud, tee);
            explicit(complete_anchors(&request))
                .resolve(&request)
                .await
                .unwrap_or_else(|error| panic!("{cloud}/{tee}: {error}"));
        }

        assert_eq!(
            endpoint.requests(),
            0,
            "explicit resolution reached a chain endpoint"
        );
    }

    /// Test 10. A chain client reachable in the same process must be left
    /// untouched by an explicit verification.
    ///
    /// The type change makes a mixed binding unrepresentable, so this is not
    /// proving that `None` was assigned — it is proving that nothing reaches
    /// for a chain client by another route. The type stops one path; this
    /// covers the rest.
    #[tokio::test]
    async fn a_reachable_chain_client_is_untouched_by_an_explicit_verification() {
        let endpoint = CountingRpcEndpoint::start().await;
        let client = connect(&endpoint).await;
        let after_connect = endpoint.requests();
        assert!(after_connect > 0, "the client must be genuinely connected");

        for (cloud, tee) in SUPPORTED_PLATFORMS {
            let request = request(cloud, tee);
            explicit(complete_anchors(&request))
                .resolve(&request)
                .await
                .unwrap_or_else(|error| panic!("{cloud}/{tee}: {error}"));
        }

        assert_eq!(
            endpoint.requests(),
            after_connect,
            "an explicit verification reached the chain client's endpoint"
        );
        // The client is still usable, so the count above is not zero because
        // the endpoint died partway through.
        assert_eq!(client.context().session_registry, SESSION_REGISTRY);
    }
}
