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
    ChainTrustSource, ExplicitTrustSource, PackTrustSource, TrustInputSource, TrustProvenance,
    TrustSource,
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
            TrustSource::Packs(source) => resolve_from_packs(source, request),
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

/// Trust-pack mode. The configured packs' publishers are the authority.
///
/// Structurally the same as explicit mode, and deliberately so: both resolve
/// from inputs already in hand, neither reads a chain, and a required input the
/// source cannot supply fails closed naming the input rather than being filled
/// from somewhere else. Only the authority differs, and only the message says
/// so.
fn resolve_from_packs(
    source: &PackTrustSource,
    request: &CollateralRequest,
) -> Result<(TrustAnchors, TrustProvenance), PortalVerificationError> {
    // `TrustAnchorsBuilder::resolve` is public, so a caller holding a source
    // past `not_after` reaches trust anchors through here without going near
    // `bootstrap_portal_tls`. Every public path that hands out packed material
    // checks the window.
    source.ensure_valid_now()?;

    let anchors = source.anchors().clone();
    let mut provenance = TrustProvenance::default();

    for input in required_trust_inputs_for_request(request) {
        if !input.is_satisfied_by(&anchors, request) {
            return Err(PortalVerificationError::Config {
                message: format!(
                    "trust-pack mode is missing {} for {}/{}; the configured collateral-trust \
                     packs do not cover this platform, and there is no chain to fill it from",
                    input.name(),
                    request.cloud,
                    request.tee
                ),
            });
        }
        provenance.record(input.name(), source.provenance());
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

    /// A trust-pack source carrying the roots and policy an AWS AMD SEV-SNP
    /// request requires.
    ///
    /// Built through the real writer and reader rather than by constructing
    /// `PackTrustSource` from anchors directly, so what this resolves from is
    /// an actual signed archive.
    pub(super) fn packs() -> TrustAnchorsBuilder {
        use crate::pack::fixture::{
            amd_snp_policy_document, certificate_pem, collateral_builder, round_trip, Publisher,
        };
        use crate::pack::TrustPackKind;

        let publisher = Publisher::new(0x51);
        let mut builder = collateral_builder("example-publisher");
        builder
            .insert(
                "payload/roots/aws-nitro-root.pem",
                certificate_pem("aws-nitro"),
            )
            .unwrap();
        builder
            .insert(
                "payload/roots/amd-ark-milan.pem",
                certificate_pem("amd-ark-milan"),
            )
            .unwrap();
        builder
            .insert(
                "payload/amd-snp-security-policy/milan.json",
                amd_snp_policy_document("0x191101"),
            )
            .unwrap();
        let pack = round_trip(&builder, TrustPackKind::CollateralTrust, &publisher)
            .expect("a readable collateral pack");

        TrustAnchorsBuilder::new(TrustSource::Packs(
            crate::trust::source::PackTrustSource::new(
                vec![pack],
                Vec::new(),
                IntelTdxDcapCollateralConfig::default(),
            )
            .expect("pack source"),
        ))
    }

    pub(super) fn aws_snp_request() -> CollateralRequest {
        let mut request = request("aws", "sev-snp");
        request.amd_snp_cpuid = Some(0x0019_1101);
        request
    }

    /// An expired pack must not supply trust anchors through the public
    /// resolver either. `TrustAnchorsBuilder::resolve` is its own consuming
    /// boundary: a daemon holding a source past `not_after` reaches anchors
    /// here without going near `bootstrap_portal_tls`.
    #[tokio::test]
    async fn resolve_refuses_packs_that_are_outside_their_validity_window() {
        use crate::collateral::intel_tdx::IntelTdxDcapCollateralConfig;
        use crate::pack::fixture::Publisher;
        use crate::pack::read::{read_trust_pack, TrustPackReadOptions};
        use crate::pack::TrustPackKind;
        use crate::trust::source::PackTrustSource;

        // A window that closed in 2020, read inside itself so the source is one
        // that became invalid rather than one that never verified.
        let publisher = Publisher::new(0x61);
        let mut builder = crate::pack::write::TrustPackBuilder::new(
            TrustPackKind::CollateralTrust,
            "example-publisher",
            1,
            1_600_000_000,
            1_600_100_000,
        );
        builder
            .insert(
                "payload/roots/gcp-ak-root.pem",
                crate::pack::fixture::certificate_pem("gcp-ak"),
            )
            .unwrap();
        let archive = builder
            .build(|bytes| Ok::<_, std::convert::Infallible>(publisher.sign(bytes)))
            .unwrap();
        let pack = read_trust_pack(
            &archive,
            &TrustPackReadOptions::new(
                TrustPackKind::CollateralTrust,
                publisher.public_key.clone(),
                1_600_000_001,
            ),
        )
        .expect("the pack verifies inside its own window");

        let source = PackTrustSource::new(
            vec![pack],
            Vec::new(),
            IntelTdxDcapCollateralConfig::default(),
        )
        .expect("pack source");
        let builder = TrustAnchorsBuilder::new(TrustSource::Packs(source));

        let error = builder
            .resolve(&request("gcp", "tdx"))
            .await
            .expect_err("an expired pack must not supply anchors");
        assert!(
            error.to_string().contains("validity"),
            "the failure must be the window, not a missing input; got {error}"
        );
    }

    /// Trust-pack mode resolves from the packs and reports their publishers as
    /// the authority — not the operator, and not a registry.
    #[tokio::test]
    async fn a_complete_pack_set_resolves_with_pack_provenance() {
        let request = aws_snp_request();
        let (_, provenance) = packs().resolve(&request).await.expect("pack resolution");

        assert!(!provenance.inputs.is_empty());
        for (input, source) in &provenance.inputs {
            let TrustInputSource::Pack { issuers, digests } = source else {
                panic!("{input} must report a pack as its authority, got {source:?}");
            };
            assert_eq!(issuers, &["example-publisher".to_string()]);
            assert_eq!(digests.len(), 1, "the pack digest is what a pin names");
        }
    }

    /// A platform the configured packs do not cover fails closed naming the
    /// input, and says there is no chain to fill it from — the distinction an
    /// operator needs in order to fix it.
    #[tokio::test]
    async fn a_platform_the_packs_do_not_cover_fails_closed() {
        // The pack set carries no Azure MAA signing certificate, so an Azure
        // response bound by a MAA token has no trust anchor for that token.
        let request = request("azure", "tdx");
        let error = packs()
            .resolve(&request)
            .await
            .expect_err("an uncovered platform must fail closed");
        let message = error.to_string();
        assert!(
            message.contains("azure-maa-signing-certificate"),
            "the failure must name the missing input; got {message}"
        );
        assert!(
            message.contains("no chain to fill it from"),
            "the failure must say why it cannot be resolved elsewhere; got {message}"
        );
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

/// Transport-level proof that explicit and trust-pack policy resolution never
/// reads a registry.
///
/// These assert on what reached the network, not on what a verification
/// returned. A verification that wrongly consulted a registry and then
/// succeeded is indistinguishable from one that never consulted it by return
/// value alone, which is why the exclusive-mode test list calls for a call
/// counter. Automata on-chain PCCS is a separate collateral query and is
/// tested at the portal TLS boundary instead.
#[cfg(test)]
mod no_registry_policy_read_outside_chain_mode {
    use super::tests::{
        aws_snp_request, complete_anchors, explicit, packs, request, SUPPORTED_PLATFORMS,
    };
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

    /// A complete explicit trust-anchor resolution, for every supported
    /// platform, performs no registry read.
    #[tokio::test]
    async fn explicit_mode_performs_no_registry_rpc() {
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
            "explicit resolution reached a registry endpoint"
        );
    }

    /// A registry client reachable in the same process must be left untouched
    /// by explicit trust-anchor resolution.
    ///
    /// Explicit trust does not contain verifier-selected chain coordinates, so
    /// this is not proving that `None` was assigned — it is proving that
    /// nothing reaches for a chain client by another route. The type stops one
    /// path; this covers the rest.
    #[tokio::test]
    async fn a_reachable_registry_client_is_untouched_by_explicit_resolution() {
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
            "explicit resolution reached the registry client's endpoint"
        );
        // The client is still usable, so the count above is not zero because
        // the endpoint died partway through.
        assert_eq!(client.context().session_registry, SESSION_REGISTRY);
    }

    /// The same proof for trust-pack trust-anchor resolution. The mode may use
    /// Automata on-chain PCCS for Intel collateral, but it must not read trust
    /// anchors or policies from registry contracts.
    #[tokio::test]
    async fn trust_pack_mode_performs_no_registry_rpc() {
        let endpoint = CountingRpcEndpoint::start().await;
        let client = connect(&endpoint).await;
        let after_connect = endpoint.requests();
        assert!(after_connect > 0, "the client must be genuinely connected");

        packs()
            .resolve(&aws_snp_request())
            .await
            .expect("pack resolution");

        assert_eq!(
            endpoint.requests(),
            after_connect,
            "trust-pack resolution reached a registry endpoint"
        );
        assert_eq!(client.context().session_registry, SESSION_REGISTRY);
    }
}
