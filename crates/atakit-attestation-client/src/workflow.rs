//! Complete portal TLS and current-session verification workflow.

use std::path::PathBuf;

use atakit_attestation::{BindingMode, MeasurementPolicy, VerifiedSession};
use atakit_cvm_types::AppRef;

use crate::chain::TrustedWorkloadSessionPolicy;
use crate::error::PortalVerificationError;
use crate::portal::session::{verify_current_session, SessionWorkloadSelector, VerifiedPortalTls};
use crate::portal::tls::{ChainBaseImage, PortalTlsVerificationMode};
use crate::trust::source::{ChainTrustSource, ExplicitTrustSource, PackTrustSource, TrustSource};

/// One complete verification: its trust authority, and every policy that
/// authority supplies.
///
/// This replaced three independent choices — trust source, workload policy
/// source, measurement policy source — whose legal combinations had to be
/// checked at run time. Three enums meant most combinations were constructible
/// and wrong, so the workflow's first job was rejecting states its own types
/// had allowed. Worse, one variant meant two different things: a "supplied"
/// measurement policy covered both a chain-resolved policy and an
/// operator-supplied one, so `chain` mode paired with an operator's
/// `--measurements` still compiled and the exclusive-source rule was enforced
/// for exactly one of the three modes.
///
/// Here each variant carries only what its own authority provides, and the
/// policies each mode owns are resolved through that mode. An invalid
/// combination has no representation, so there is nothing left to validate.
#[derive(Debug, Clone)]
pub enum SessionVerificationMode {
    /// The registry graph rooted at the verifier-selected `SessionRegistry` is
    /// the authority, and supplies both policies.
    ///
    /// References rather than resolved policies: resolving them here is what
    /// makes "chain mode reads its policy from the chain" a property of the
    /// type instead of a convention the caller has to honour.
    Chain {
        source: ChainTrustSource,
        base_image: AppRef,
        workload: AppRef,
    },
    /// The operator is the authority and supplies both policies directly.
    Explicit {
        source: ExplicitTrustSource,
        measurement_policy: Box<MeasurementPolicy>,
        workload_policy: TrustedWorkloadSessionPolicy,
    },
    /// The configured `.atatp` publishers are the authority, and the
    /// `workload-trust` pack supplies both policies.
    Packs {
        source: PackTrustSource,
        base_image_id: [u8; 32],
        workload: AppRef,
    },
}

impl SessionVerificationMode {
    /// The portal TLS half of this mode.
    ///
    /// Built rather than duplicated, so a mode cannot describe one authority
    /// for TLS verification and another for the session that follows it.
    pub fn tls_mode(&self) -> PortalTlsVerificationMode {
        match self {
            Self::Chain {
                source, base_image, ..
            } => PortalTlsVerificationMode::Chain {
                source: source.clone(),
                base_image: ChainBaseImage::Reference(base_image.clone()),
            },
            Self::Explicit {
                source,
                measurement_policy,
                ..
            } => PortalTlsVerificationMode::Explicit {
                source: source.clone(),
                measurement_policy: measurement_policy.clone(),
            },
            Self::Packs {
                source,
                base_image_id,
                ..
            } => PortalTlsVerificationMode::Packs {
                source: source.clone(),
                base_image_id: *base_image_id,
            },
        }
    }

    /// The trust-anchor source for this mode.
    pub fn trust_source(&self) -> TrustSource {
        self.tls_mode().trust_source()
    }

    pub fn name(&self) -> &'static str {
        self.tls_mode().name()
    }

    /// The base-image measurement policy, from this mode's own authority.
    pub async fn measurement_policy(&self) -> Result<MeasurementPolicy, PortalVerificationError> {
        self.tls_mode().measurement_policy().await
    }
}

/// Complete inputs for portal TLS and current-session verification.
#[derive(Debug, Clone)]
pub struct PortalSessionVerificationRequest {
    pub host: String,
    pub status_port: u16,
    /// One address resolved and checked by a caller that accepts dynamic
    /// destinations. Both portal TLS and current-session verification use it,
    /// so DNS cannot select a different socket after attestation.
    pub resolved_address: Option<std::net::SocketAddr>,
    pub mode: SessionVerificationMode,
    pub report_path: Option<PathBuf>,
    pub required_binding: Option<BindingMode>,
}

/// Verified portal TLS identity and the current session verified through that
/// pinned connection.
#[derive(Debug, Clone)]
pub struct VerifiedPortalSession {
    pub portal_tls: VerifiedPortalTls,
    pub session: VerifiedSession,
}

/// Verify portal TLS, then verify a fresh challenge-bound current-session
/// evidence bundle through the pinned TLS connection.
pub async fn verify_portal_session(
    request: PortalSessionVerificationRequest,
) -> Result<VerifiedPortalSession, PortalVerificationError> {
    let PortalSessionVerificationRequest {
        host,
        status_port,
        resolved_address,
        mode,
        report_path,
        required_binding,
    } = request;

    let portal_tls = crate::portal::tls::bootstrap_portal_tls_at_address(
        &host,
        status_port,
        resolved_address,
        &mode.tls_mode(),
        None,
        None,
        report_path.as_deref(),
    )
    .await?;

    // The workload policy is resolved after portal TLS, by the authority that
    // verified it, against the base image TLS actually selected.
    let selector = match &mode {
        SessionVerificationMode::Chain { workload, .. }
        | SessionVerificationMode::Packs { workload, .. } => {
            SessionWorkloadSelector::Reference(workload.clone())
        }
        SessionVerificationMode::Explicit {
            workload_policy, ..
        } => SessionWorkloadSelector::OperatorPolicy(workload_policy.clone()),
    };
    let session =
        verify_current_session(&portal_tls, &host, status_port, &selector, required_binding)
            .await
            .map_err(|error| match error {
                crate::AttestationClientError::SessionVerification(failure) => {
                    PortalVerificationError::SessionVerification { failure }
                }
                error => PortalVerificationError::PortalSessionVerificationFailed {
                    message: error.to_string(),
                },
            })?;

    Ok(VerifiedPortalSession {
        portal_tls,
        session,
    })
}

/// Tests over the paths a verification actually takes, rather than over the
/// helpers those paths call.
///
/// An earlier round of tests asserted on helper return values — that a selector
/// matched, that `ensure_valid_at` rejected a time — which said nothing about
/// whether any verification reached them. Two of the defects that review found
/// were exactly that: a value produced and asserted on, never consumed.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::intel_tdx::{
        IntelTdxDcapCollateralConfig, IntelTdxDcapCollateralSource, TdxDcapAutomataReadStrategy,
    };
    use crate::pack::fixture::Publisher;
    use crate::pack::TrustPackKind;
    use crate::portal::tls::bootstrap_portal_tls;
    use crate::test_support::CountingRpcEndpoint;

    /// A port nothing listens on. Reaching a connection attempt at all means
    /// the check under test did not run first.
    const CLOSED_PORT: u16 = 1;

    /// A window that ended in 2020, so the wall clock is outside it however
    /// long this code lives.
    const EXPIRED_NOT_BEFORE: u64 = 1_600_000_000;
    const EXPIRED_NOT_AFTER: u64 = 1_600_100_000;

    fn packs_mode_with_tdx(
        expired: bool,
        tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    ) -> SessionVerificationMode {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let (not_before, not_after, read_at) = if expired {
            (
                EXPIRED_NOT_BEFORE,
                EXPIRED_NOT_AFTER,
                EXPIRED_NOT_BEFORE + 1,
            )
        } else {
            (
                crate::pack::fixture::NOT_BEFORE,
                crate::pack::fixture::NOT_AFTER,
                crate::pack::fixture::NOW,
            )
        };
        let (builder, base_image_id) = crate::pack::fixture::workload_builder_in_window(
            &workload_publisher,
            &base_publisher,
            "peer-attestation-demo",
            "v1.0.0",
            not_before,
            not_after,
        );

        // Read inside the window, so an expired source is one that *became*
        // invalid rather than one that never verified.
        let archive = builder
            .build(|bytes| Ok::<_, std::convert::Infallible>(workload_publisher.sign(bytes)))
            .expect("build archive");
        let options = crate::pack::read::TrustPackReadOptions::new(
            TrustPackKind::WorkloadTrust,
            workload_publisher.public_key.clone(),
            read_at,
        );
        let pack = crate::pack::read::read_trust_pack(&archive, &options)
            .expect("the pack verifies inside its own window");

        let source =
            PackTrustSource::new(Vec::new(), vec![pack], tdx_dcap_collateral).expect("pack source");
        SessionVerificationMode::Packs {
            source,
            base_image_id,
            workload: AppRef::new(
                workload_publisher.fingerprint(),
                "peer-attestation-demo",
                "v1.0.0",
            ),
        }
    }

    fn packs_mode(expired: bool) -> SessionVerificationMode {
        packs_mode_with_tdx(expired, IntelTdxDcapCollateralConfig::default())
    }

    fn automata_onchain(rpc_url: &str) -> IntelTdxDcapCollateralConfig {
        IntelTdxDcapCollateralConfig {
            source: IntelTdxDcapCollateralSource::AutomataOnchainPccs {
                chain: Some("hoodi".to_string()),
                rpc_url: Some(rpc_url.to_string()),
                pcs_dao: None,
                pck_dao: None,
                fmspc_tcb_dao: None,
                enclave_identity_dao: None,
                read_strategy: TdxDcapAutomataReadStrategy::DirectConcurrent,
            },
        }
    }

    /// Trust-pack mode resolves its measurement policy from the pack, through
    /// the same call `verify_portal_session` makes.
    #[tokio::test]
    async fn trust_pack_mode_resolves_its_measurement_policy_from_the_pack() {
        let mode = packs_mode(false);
        let policy = mode
            .measurement_policy()
            .await
            .expect("the pack supplies the policy");
        assert!(
            policy.source.starts_with("trust pack "),
            "the policy must come from the pack, got {}",
            policy.source
        );
        assert_eq!(mode.name(), "trust-pack");
        assert_eq!(mode.trust_source().mode(), "trust-pack");
    }

    /// Explicit mode returns the operator's policy unchanged, and chain mode is
    /// the only variant that can reach a registry — there is no variant that
    /// pairs one authority's anchors with another's policy, which is what
    /// collapsing the three enums into one bought.
    #[tokio::test]
    async fn each_mode_supplies_its_own_measurement_policy() {
        let mode = packs_mode(false);
        let SessionVerificationMode::Packs { source, .. } = &mode else {
            unreachable!()
        };
        let packed = mode.measurement_policy().await.unwrap();

        let explicit = SessionVerificationMode::Explicit {
            source: crate::trust::source::ExplicitTrustSource::new(
                Default::default(),
                IntelTdxDcapCollateralConfig::default(),
            )
            .unwrap(),
            measurement_policy: Box::new(packed.clone()),
            workload_policy: TrustedWorkloadSessionPolicy {
                workload_id: [0u8; 32],
                pcr_specs256: Vec::new(),
                pcr_specs384: Vec::new(),
                attribute_requirements: Vec::new(),
            },
        };
        assert_eq!(explicit.name(), "explicit");
        assert_eq!(
            explicit.measurement_policy().await.unwrap().pack.subject.id,
            packed.pack.subject.id
        );
        let _ = source;
    }

    /// An Automata on-chain PCCS endpoint is a collateral endpoint, not a
    /// registry policy endpoint. Explicit mode keeps the operator's
    /// measurement and workload policies and does not query that endpoint
    /// while resolving either policy.
    #[tokio::test]
    async fn explicit_policy_with_automata_onchain_pccs_stays_explicit() {
        let endpoint = CountingRpcEndpoint::start().await;
        let packed = packs_mode(false).measurement_policy().await.unwrap();
        let workload_policy = TrustedWorkloadSessionPolicy {
            workload_id: [0x44; 32],
            pcr_specs256: Vec::new(),
            pcr_specs384: Vec::new(),
            attribute_requirements: Vec::new(),
        };
        let mode = SessionVerificationMode::Explicit {
            source: crate::trust::source::ExplicitTrustSource::new(
                Default::default(),
                automata_onchain(endpoint.url()),
            )
            .expect("explicit policy and Automata PCCS collateral are compatible"),
            measurement_policy: Box::new(packed.clone()),
            workload_policy: workload_policy.clone(),
        };

        let resolved = mode
            .measurement_policy()
            .await
            .expect("explicit measurement policy");
        assert_eq!(resolved.pack.subject.id, packed.pack.subject.id);
        let SessionVerificationMode::Explicit {
            workload_policy: resolved_workload,
            ..
        } = &mode
        else {
            unreachable!()
        };
        assert_eq!(resolved_workload.workload_id, workload_policy.workload_id);
        assert_eq!(
            endpoint.requests(),
            0,
            "policy resolution must not treat the Automata PCCS endpoint as a registry"
        );
    }

    /// Trust-pack mode keeps both policies in its signed workload pack while
    /// allowing an independent Automata on-chain PCCS collateral endpoint.
    /// Resolving either policy must not query that endpoint as a registry.
    #[tokio::test]
    async fn trust_pack_policy_with_automata_onchain_pccs_stays_in_the_pack() {
        let endpoint = CountingRpcEndpoint::start().await;
        let mode = packs_mode_with_tdx(false, automata_onchain(endpoint.url()));
        let measurement_policy = mode
            .measurement_policy()
            .await
            .expect("packed measurement policy");
        assert!(measurement_policy.source.starts_with("trust pack "));

        let SessionVerificationMode::Packs {
            source,
            base_image_id,
            workload,
        } = &mode
        else {
            unreachable!()
        };
        let workload_policy = crate::pack::workload::packed_workload_policy(
            source.workload_pack().expect("workload pack"),
            workload,
            *base_image_id,
        )
        .expect("packed workload policy");
        assert_eq!(
            workload_policy.workload_id,
            atakit_cvm_encoding::workload_id(workload)
        );
        assert_eq!(
            endpoint.requests(),
            0,
            "pack policy resolution must not treat the Automata PCCS endpoint as a registry"
        );
    }

    /// `bootstrap_portal_tls` is public and takes a `TrustSource` directly, so
    /// it is its own pack-consuming boundary. An expired pack must stop it
    /// before it contacts anything — proven by pointing it at a closed port and
    /// requiring the validity error rather than a connection error.
    #[tokio::test]
    async fn expired_packs_stop_portal_tls_before_it_connects() {
        let SessionVerificationMode::Packs {
            source,
            base_image_id,
            ..
        } = packs_mode(true)
        else {
            unreachable!()
        };

        let error = bootstrap_portal_tls(
            "127.0.0.1",
            CLOSED_PORT,
            &PortalTlsVerificationMode::Packs {
                source,
                base_image_id,
            },
            None,
            None,
            None,
        )
        .await
        .expect_err("an expired pack must refuse before connecting");
        let message = error.to_string();
        assert!(
            message.contains("validity") && message.contains("verification time"),
            "the failure must be the validity window, not a connection error; got {message}"
        );
    }

    /// The control for the test above: an unexpired pack reaches the network,
    /// so the refusal there is the window and not something that refuses
    /// always.
    #[tokio::test]
    async fn an_unexpired_pack_gets_past_the_validity_check() {
        let SessionVerificationMode::Packs {
            source,
            base_image_id,
            ..
        } = packs_mode(false)
        else {
            unreachable!()
        };

        let error = bootstrap_portal_tls(
            "127.0.0.1",
            CLOSED_PORT,
            &PortalTlsVerificationMode::Packs {
                source,
                base_image_id,
            },
            None,
            None,
            None,
        )
        .await
        .expect_err("nothing is listening on the closed port");
        let message = error.to_string();
        assert!(
            !message.contains("validity"),
            "a valid pack must not fail the window check; got {message}"
        );
    }

    /// A pack that expires while a source is held stops working, which is what
    /// separates bounding the verification from bounding the process.
    #[tokio::test]
    async fn a_held_source_stops_being_usable_when_its_packs_expire() {
        let SessionVerificationMode::Packs { source, .. } = packs_mode(false) else {
            unreachable!()
        };
        assert!(source.ensure_valid_at(crate::pack::fixture::NOW).is_ok());
        let error = source
            .ensure_valid_at(crate::pack::fixture::NOT_AFTER)
            .expect_err("the same held source must refuse once the window closes");
        assert!(error.to_string().contains("validity"), "got {error}");
    }
}
