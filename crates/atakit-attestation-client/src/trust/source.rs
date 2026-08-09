//! The trust source a verification resolves everything from, and the
//! provenance it reports afterwards.
//!
//! A verification selects exactly one source. There is no default, no
//! precedence rule, and no operation that merges one source's inputs into
//! another's. The type is a sum rather than a struct of optional fields
//! precisely so a configuration naming two sources cannot be constructed —
//! a shape that cannot express two sources cannot be misconfigured into two.
//!
//! `TrustSource::Packs` arrived on 2026-08-09, once `.atatp` could complete a
//! verification. It was deliberately absent before then: the `workload-trust`
//! namespace was blocked on the base-image publisher authority defect, and a
//! variant that always failed would have been a mode in name only. Adding it
//! changed nothing about the exclusivity above, which never depended on how
//! many variants exist.

use atakit_attestation::{TrustAnchors, TrustedSessionBinding};

use crate::chain::{AttestationClient, AttestationClientConfig};
use crate::collateral::intel_tdx::{IntelTdxDcapCollateralConfig, IntelTdxDcapCollateralSource};
use crate::error::PortalVerificationError;
use crate::pack::collateral::{collateral_trust_inputs_from_all, CollateralTrustInputs};
use crate::pack::read::TrustPack;
use crate::pack::{TrustPackError, TrustPackKind};
use crate::trust::files::TlsVerificationTrust;
use crate::trust::requirements::RequiredTrustInput;

/// The single authority for one verification.
#[derive(Debug, Clone)]
pub enum TrustSource {
    /// A verifier-selected registry graph supplies every trust input.
    Chain(ChainTrustSource),
    /// The operator supplies every trust input directly and is the authority.
    Explicit(ExplicitTrustSource),
    /// Signed `.atatp` trust packs supply every trust input, and the packs'
    /// publishers are the authority.
    Packs(PackTrustSource),
}

impl TrustSource {
    /// The mode name used in operator-facing errors.
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Chain(_) => "chain",
            Self::Explicit(_) => "explicit",
            Self::Packs(_) => "trust-pack",
        }
    }

    pub(crate) fn tdx_dcap_collateral(&self) -> &IntelTdxDcapCollateralConfig {
        match self {
            Self::Chain(source) => &source.tdx_dcap_collateral,
            Self::Explicit(source) => &source.tdx_dcap_collateral,
            Self::Packs(source) => &source.tdx_dcap_collateral,
        }
    }
}

/// Trust-pack mode: the configured packs' publishers are the authority.
///
/// Every pack is verified before this value exists, so holding one means the
/// signature, validity window, namespace, and hashes already passed. A pack
/// that exists but cannot be used is fatal rather than a fallback, which is why
/// construction fails rather than leaving an unusable source in place.
#[derive(Debug, Clone)]
pub struct PackTrustSource {
    collateral: CollateralTrustInputs,
    workload_packs: Vec<TrustPack>,
    tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
}

impl PackTrustSource {
    /// Build from already-verified packs.
    ///
    /// Rejects the Automata on-chain Provisioning Certificate Caching Service
    /// for the reason explicit mode does: reading it is a chain query, and this
    /// mode issues none. Off-chain HTTP PCCS and the AMD Key Distribution
    /// Service stay permitted, because vendor-signed collateral is
    /// self-authenticating and is validated against the anchors these packs
    /// supply — an availability choice, not a trust one.
    pub fn new(
        collateral_packs: Vec<TrustPack>,
        workload_packs: Vec<TrustPack>,
        tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    ) -> Result<Self, PortalVerificationError> {
        if let IntelTdxDcapCollateralSource::AutomataOnchainPccs { .. } = tdx_dcap_collateral.source
        {
            return Err(PortalVerificationError::Config {
                message: "trust-pack mode cannot read the Automata on-chain Provisioning \
                          Certificate Caching Service, because reading it is a chain query; \
                          supply --tdx-dcap-collateral or --tdx-dcap-pccs-url instead"
                    .to_string(),
            });
        }
        for pack in &workload_packs {
            if pack.kind != TrustPackKind::WorkloadTrust {
                return Err(TrustPackError::KindMismatch {
                    expected: TrustPackKind::WorkloadTrust.as_str(),
                    found: pack.kind.as_str().to_string(),
                }
                .into());
            }
        }
        Ok(Self {
            collateral: collateral_trust_inputs_from_all(&collateral_packs)?,
            workload_packs,
            tdx_dcap_collateral,
        })
    }

    pub(crate) fn anchors(&self) -> &TrustAnchors {
        &self.collateral.trust_anchors
    }

    pub(crate) fn amd_snp_crls(&self) -> &[Vec<u8>] {
        &self.collateral.amd_snp_crls
    }

    /// The one workload-trust pack, or a failure naming why there is not
    /// exactly one.
    ///
    /// Two packs could each answer for the same workload with different policy,
    /// and choosing between them silently would make the winner invisible —
    /// the rule duplicate claims follow everywhere else in this format.
    pub fn workload_pack(&self) -> Result<&TrustPack, PortalVerificationError> {
        match self.workload_packs.as_slice() {
            [pack] => Ok(pack),
            [] => Err(PortalVerificationError::Config {
                message: "trust-pack mode has no workload-trust pack, so there is no workload \
                          policy or base-image measurement policy to verify against"
                    .to_string(),
            }),
            packs => Err(PortalVerificationError::Config {
                message: format!(
                    "trust-pack mode has {} workload-trust packs; supply exactly one, because \
                     choosing between them silently would make the winner invisible",
                    packs.len()
                ),
            }),
        }
    }

    /// Which packs supplied the collateral inputs.
    ///
    /// Uniform within a run by construction, which is the point of an
    /// exclusive mode. It stays worth reporting because `Vendor` can appear
    /// beside it when self-authenticating collateral was fetched rather than
    /// packed.
    pub(crate) fn provenance(&self) -> TrustInputSource {
        TrustInputSource::Pack {
            issuers: self
                .collateral
                .issuers
                .iter()
                .map(|provenance| provenance.issuer.clone())
                .collect(),
            digests: self
                .collateral
                .issuers
                .iter()
                .map(|provenance| provenance.digest.clone())
                .collect(),
        }
    }
}

/// Chain mode: the registry graph rooted at a verifier-selected
/// `SessionRegistry` is the authority.
///
/// The connected client is held rather than reconnected per input, and the
/// session binding is reachable **only** through this variant. That is the
/// point: operator-supplied policy combined with a chain-derived `chain_id`
/// and `SessionRegistry` address is mixed trust even though both values are
/// well-formed, so no other source has anywhere to put one.
#[derive(Debug, Clone)]
pub struct ChainTrustSource {
    client: AttestationClient,
    tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
}

impl ChainTrustSource {
    /// Connect to the verifier-selected RPC endpoint and `SessionRegistry`.
    pub async fn connect(
        rpc_url: impl Into<String>,
        session_registry: impl Into<String>,
        tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    ) -> Result<Self, PortalVerificationError> {
        let client = AttestationClient::connect(AttestationClientConfig {
            rpc_url: rpc_url.into(),
            session_registry: session_registry.into(),
            expected_chain_id: None,
            expected_base_image_registry: None,
            expected_workload_registry: None,
        })
        .await
        .map_err(
            |error| PortalVerificationError::PortalTlsAttestationFailed {
                message: error.to_string(),
            },
        )?;
        Ok(Self {
            client,
            tdx_dcap_collateral,
        })
    }

    /// Build from a client the caller already connected.
    pub fn from_client(
        client: AttestationClient,
        tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    ) -> Self {
        Self {
            client,
            tdx_dcap_collateral,
        }
    }

    pub fn client(&self) -> &AttestationClient {
        &self.client
    }

    /// The chain context this verification is bound to. Only chain mode has
    /// one, which is what makes a mixed binding unrepresentable.
    pub fn binding(&self) -> TrustedSessionBinding {
        self.client.trusted_session_binding()
    }

    pub fn session_registry(&self) -> &str {
        &self.client.context().session_registry
    }
}

/// Explicit mode: the operator supplies the inputs and is the authority.
///
/// This is a third trust model, not a compatibility shim. It is what offline
/// verification, tests, and measurement campaigns need: nothing is filled from
/// a chain, and a required input the operator did not supply fails closed
/// naming the input rather than being resolved from somewhere else.
#[derive(Debug, Clone)]
pub struct ExplicitTrustSource {
    anchors: TrustAnchors,
    amd_snp_crls: Vec<Vec<u8>>,
    sources: std::collections::BTreeMap<String, Vec<String>>,
    tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
}

impl ExplicitTrustSource {
    /// Build an explicit source from operator-supplied trust material.
    ///
    /// Rejects the Automata on-chain Provisioning Certificate Caching Service
    /// here rather than at request time: reading it is a chain query, so
    /// selecting it alongside explicit trust is a configuration error, not a
    /// runtime condition to skip. Off-chain HTTP PCCS and the AMD Key
    /// Distribution Service stay permitted — vendor-signed collateral is
    /// self-authenticating and is validated against the anchors supplied here.
    pub fn new(
        trust: TlsVerificationTrust,
        tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    ) -> Result<Self, PortalVerificationError> {
        if let IntelTdxDcapCollateralSource::AutomataOnchainPccs { .. } = tdx_dcap_collateral.source
        {
            return Err(PortalVerificationError::Config {
                message: "explicit trust mode cannot read the Automata on-chain Provisioning \
                          Certificate Caching Service, because reading it is a chain query; \
                          supply --tdx-dcap-collateral or --tdx-dcap-pccs-url instead"
                    .to_string(),
            });
        }
        let TlsVerificationTrust {
            trust_anchors,
            amd_snp_crls,
            sources,
        } = trust;
        Ok(Self {
            anchors: trust_anchors,
            amd_snp_crls,
            sources,
            tdx_dcap_collateral,
        })
    }

    pub(crate) fn anchors(&self) -> &TrustAnchors {
        &self.anchors
    }

    pub(crate) fn amd_snp_crls(&self) -> &[Vec<u8>] {
        &self.amd_snp_crls
    }

    /// Where an explicitly supplied input came from.
    ///
    /// The flag is always known; the paths are known when the input was read
    /// from files rather than assembled by a caller that built `TrustAnchors`
    /// directly, which tests and library consumers do.
    pub(crate) fn provenance_for(&self, input: RequiredTrustInput) -> TrustInputSource {
        let flag = input.explicit_source();
        TrustInputSource::File {
            flag: flag.to_string(),
            paths: self.sources.get(flag).cloned().unwrap_or_default(),
        }
    }
}

/// Where one resolved trust input came from.
///
/// Under exclusive modes this is mostly uniform within a run, which is the
/// point. It stays worth reporting because `Vendor` can appear beside `File`
/// when self-authenticating collateral was fetched rather than supplied.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TrustInputSource {
    /// Read from the registry graph rooted at this `SessionRegistry`.
    Chain { registry: String },
    /// Supplied by the operator through this flag, from these paths.
    File { flag: String, paths: Vec<String> },
    /// Supplied by these `.atatp` publishers, from packs with these digests.
    ///
    /// The digest is the value a pin names, so a reader can tell which exact
    /// artifact was used without re-deriving it from the archive.
    Pack {
        issuers: Vec<String>,
        digests: Vec<String>,
    },
    /// Fetched from a vendor endpoint and validated against source anchors.
    Vendor { endpoint: String },
}

/// Per-input provenance for one verification.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TrustProvenance {
    /// Ordered by input name so the report is deterministic.
    pub inputs: std::collections::BTreeMap<String, TrustInputSource>,
}

impl TrustProvenance {
    pub(crate) fn record(&mut self, input: impl Into<String>, source: TrustInputSource) {
        self.inputs.insert(input.into(), source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn automata_onchain() -> IntelTdxDcapCollateralConfig {
        IntelTdxDcapCollateralConfig {
            source: IntelTdxDcapCollateralSource::AutomataOnchainPccs {
                chain: Some("hoodi".to_string()),
                rpc_url: Some("https://rpc.example.invalid".to_string()),
                pcs_dao: None,
                pck_dao: None,
                fmspc_tcb_dao: None,
                enclave_identity_dao: None,
                read_strategy: Default::default(),
            },
        }
    }

    /// Test 6 of the exclusive-mode set: the Automata on-chain Provisioning
    /// Certificate Caching Service is rejected outside chain mode, and it is
    /// rejected while the configuration is being built rather than skipped
    /// later.
    #[test]
    fn explicit_mode_rejects_the_automata_onchain_pccs_at_construction() {
        let error = ExplicitTrustSource::new(TlsVerificationTrust::default(), automata_onchain())
            .expect_err("explicit mode must refuse a chain-read collateral source");
        let message = error.to_string();
        assert!(
            message.contains("Automata on-chain"),
            "the failure must name the rejected source; got {message}"
        );
        assert!(
            message.contains("chain query"),
            "the failure must say why it is refused; got {message}"
        );
    }

    /// Off-chain vendor endpoints stay available: self-authenticating
    /// collateral is not a trust source, so fetching it is not a fallback.
    #[test]
    fn explicit_mode_accepts_off_chain_collateral_sources() {
        for source in [
            IntelTdxDcapCollateralSource::None,
            IntelTdxDcapCollateralSource::File("/tmp/collateral.json".into()),
            IntelTdxDcapCollateralSource::HttpPccs {
                url: "https://pccs.example.invalid".to_string(),
            },
        ] {
            let config = IntelTdxDcapCollateralConfig { source };
            assert!(
                ExplicitTrustSource::new(TlsVerificationTrust::default(), config).is_ok(),
                "off-chain collateral sources must remain available in explicit mode"
            );
        }
    }

    #[test]
    fn mode_names_are_the_operator_facing_ones() {
        let explicit = TrustSource::Explicit(
            ExplicitTrustSource::new(
                TlsVerificationTrust::default(),
                IntelTdxDcapCollateralConfig::default(),
            )
            .unwrap(),
        );
        assert_eq!(explicit.mode(), "explicit");
    }
}
