//! The authority that supplies a verification's trust anchors and policies,
//! and the provenance reported afterwards.
//!
//! A verification selects exactly one policy authority. There is no default,
//! no precedence rule, and no operation that merges one authority's
//! measurement or workload policy with another's. Vendor-authenticated
//! attestation collateral is separate: it may come from a file, an HTTP
//! service, a trust pack, or the Automata on-chain Provisioning Certificate
//! Caching Service without changing the selected policy authority.
//!
//! `TrustSource::Packs` arrived on 2026-08-09, once `.atatp` could complete a
//! verification. It was deliberately absent before then: the `workload-trust`
//! namespace was blocked on the base-image publisher authority defect, and a
//! variant that always failed would have been a mode in name only. Adding it
//! changed nothing about the exclusivity above, which never depended on how
//! many variants exist.

use atakit_attestation::{IntelTdxQuoteCollateralIdentity, TrustAnchors, TrustedSessionBinding};

use crate::chain::{AttestationClient, AttestationClientConfig};
use crate::collateral::intel_tdx::IntelTdxDcapCollateralConfig;
use crate::error::PortalVerificationError;
use crate::pack::collateral::{collateral_trust_inputs_from_all, CollateralTrustInputs};
use crate::pack::read::TrustPack;
use crate::pack::{now_unix, TrustPackError, TrustPackKind};
use crate::trust::files::TlsVerificationTrust;
use crate::trust::requirements::RequiredTrustInput;

/// The single authority for one verification.
#[derive(Debug, Clone)]
pub enum TrustSource {
    /// A verifier-selected registry graph supplies trust anchors and policies.
    Chain(ChainTrustSource),
    /// The operator supplies trust anchors and policies directly.
    Explicit(ExplicitTrustSource),
    /// Signed `.atatp` trust packs supply trust anchors and policies, and the
    /// packs' publishers are the authority.
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

    pub(crate) fn amd_snp_crls(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Chain(_) => Vec::new(),
            Self::Explicit(source) => source.amd_snp_crls().to_vec(),
            Self::Packs(source) => source.amd_snp_crls().to_vec(),
        }
    }
}

/// Trust-pack mode: the configured packs' publishers are the authority.
///
/// Every pack is verified before this value exists, so holding one means the
/// signature, validity window, namespace, and hashes already passed. A pack
/// that exists but cannot be used is fatal rather than a fallback, which is why
/// construction fails rather than leaving an unusable source in place.
/// Everything behind one `Arc`, so a mode value can be cloned per verification
/// without copying pack payloads. A daemon holds one source and serves many
/// verifications from it.
#[derive(Debug, Clone)]
pub struct PackTrustSource {
    #[cfg(test)]
    verification_time: Option<u64>,
    inner: std::sync::Arc<PackTrustSourceInner>,
    tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
}

#[derive(Debug)]
struct PackTrustSourceInner {
    collateral: CollateralTrustInputs,
    collateral_packs: Vec<TrustPack>,
    workload_packs: Vec<TrustPack>,
    /// Packed Intel TDX DCAP collateral, indexed by the identity its own
    /// selector declares.
    ///
    /// Built and validated at construction rather than searched per
    /// verification. Scanning at verification time had to treat a malformed
    /// selector as "does not claim this identity", which is indistinguishable
    /// from a genuine miss — and a miss is allowed to fetch, so a corrupt entry
    /// silently became a fetch. Indexing up front turns that into a
    /// construction failure, and leaves the verification-time question as a
    /// map lookup with only two answers.
    tdx_dcap_by_identity: std::collections::HashMap<IntelTdxQuoteCollateralIdentity, PackedEntry>,
}

#[derive(Debug, Clone)]
struct PackedEntry {
    path: String,
    document: Vec<u8>,
}

impl PackTrustSource {
    /// Build from already-verified packs.
    ///
    /// The Intel TDX collateral source is independent of the packs' policy
    /// authority. Automata on-chain PCCS is permitted here because it returns
    /// vendor-signed collateral that is verified locally; it does not supply a
    /// measurement policy or workload policy.
    pub fn new(
        collateral_packs: Vec<TrustPack>,
        workload_packs: Vec<TrustPack>,
        tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    ) -> Result<Self, PortalVerificationError> {
        for pack in &workload_packs {
            if pack.kind != TrustPackKind::WorkloadTrust {
                return Err(TrustPackError::KindMismatch {
                    expected: TrustPackKind::WorkloadTrust.as_str(),
                    found: pack.kind.as_str().to_string(),
                }
                .into());
            }
        }
        let collateral = collateral_trust_inputs_from_all(&collateral_packs)?;

        // Index and validate every packed Intel TDX selector now. A malformed
        // selector or two entries claiming one identity are configuration
        // errors, and a configuration error must stop the verifier starting
        // rather than surface as a per-quote surprise.
        let mut tdx_dcap_by_identity = std::collections::HashMap::new();
        for (path, document) in &collateral.tdx_dcap_documents {
            let identity = crate::pack::collateral::parse_collateral_selector(document).map_err(
                |message| PortalVerificationError::Config {
                    message: format!("trust pack entry {path}: {message}"),
                },
            )?;
            if let Some(existing) = tdx_dcap_by_identity.insert(
                identity,
                PackedEntry {
                    path: path.clone(),
                    document: document.clone(),
                },
            ) {
                return Err(PortalVerificationError::Config {
                    message: format!(
                        "trust pack entries {} and {path} both claim the same Intel TDX \
                         collateral identity; duplicate claims are fatal, because silently \
                         choosing one would make the winner invisible",
                        existing.path
                    ),
                });
            }
        }

        Ok(Self {
            #[cfg(test)]
            verification_time: None,
            inner: std::sync::Arc::new(PackTrustSourceInner {
                collateral,
                collateral_packs,
                workload_packs,
                tdx_dcap_by_identity,
            }),
            tdx_dcap_collateral,
        })
    }

    pub(crate) fn anchors(&self) -> &TrustAnchors {
        &self.inner.collateral.trust_anchors
    }

    pub(crate) fn amd_snp_crls(&self) -> &[Vec<u8>] {
        &self.inner.collateral.amd_snp_crls
    }

    /// Re-check every configured pack's validity window.
    ///
    /// Called per verification rather than only at load. A source built once
    /// and held by a long-running daemon would otherwise keep serving packs
    /// past `not_after`, making the derived expiry bound the process instead of
    /// the verification it was derived for.
    pub fn ensure_valid_at(&self, now_unix: u64) -> Result<(), PortalVerificationError> {
        for pack in self
            .inner
            .collateral_packs
            .iter()
            .chain(&self.inner.workload_packs)
        {
            pack.ensure_valid_at(now_unix)?;
        }
        Ok(())
    }

    /// The same check against the wall clock.
    ///
    /// Every public path that consumes a pack calls this, rather than one
    /// workflow calling it once. A pack validated only where the caller
    /// remembered to ask would leave `bootstrap_portal_tls` — which is public
    /// and takes a `TrustSource` directly — using expired packs.
    pub(crate) fn ensure_valid_now(&self) -> Result<(), PortalVerificationError> {
        #[cfg(test)]
        if let Some(now) = self.verification_time {
            return self.ensure_valid_at(now);
        }
        self.ensure_valid_at(now_unix())
    }

    /// Set this test source's clock without affecting concurrent tests or production callers.
    #[cfg(test)]
    pub(crate) fn with_verification_time(mut self, now: u64) -> Self {
        self.verification_time = Some(now);
        self
    }

    /// Select the packed Intel TDX DCAP collateral covering this quote.
    ///
    /// Three outcomes, and the difference between the last two is the
    /// no-fallback rule. `Ok(Some)` is a covered quote. `Err` is an entry that
    /// claims this quote's identity but cannot be used — fatal, and explicitly
    /// not a reason to fetch, because fetching past a broken pinned entry would
    /// make pinning advisory. `Ok(None)` is a genuine miss, where the pack
    /// simply does not cover that hardware, and only then may the caller reach
    /// a configured HTTP or Automata on-chain PCCS collateral source.
    pub(crate) fn select_tdx_dcap_collateral(
        &self,
        quote: &[u8],
    ) -> Result<Option<atakit_attestation::IntelTdxDcapCollateral>, PortalVerificationError> {
        let identity =
            atakit_attestation::intel_tdx_quote_collateral_identity(quote).map_err(|error| {
                PortalVerificationError::PortalTlsAttestationFailed {
                    message: format!("read the quote's collateral identity: {error}"),
                }
            })?;

        // A lookup, with exactly two answers. Every entry's selector was parsed
        // at construction, so "not in the map" means no pack covers this
        // hardware — never that some entry was too malformed to read.
        let Some(entry) = self.inner.tdx_dcap_by_identity.get(&identity) else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&entry.document).map_err(|error| {
            PortalVerificationError::Config {
                message: format!("trust pack entry {} is not UTF-8: {error}", entry.path),
            }
        })?;
        atakit_attestation::IntelTdxDcapCollateral::from_file_json(text, quote)
            .map(Some)
            .map_err(|error| PortalVerificationError::Config {
                message: format!(
                    "trust pack entry {} covers this quote's collateral identity but cannot be \
                     used: {error}; a packed entry that is present and unusable fails the \
                     verification rather than falling through to a vendor endpoint",
                    entry.path
                ),
            })
    }

    /// Whether any pack carries Intel TDX DCAP collateral at all.
    ///
    /// Distinguishes "this pack set does not cover Intel TDX" from "it covers
    /// Intel TDX but not this stepping", which need different operator action.
    pub(crate) fn carries_tdx_dcap_collateral(&self) -> bool {
        !self.inner.tdx_dcap_by_identity.is_empty()
    }

    /// The one workload-trust pack, or a failure naming why there is not
    /// exactly one.
    ///
    /// Two packs could each answer for the same workload with different policy,
    /// and choosing between them silently would make the winner invisible —
    /// the rule duplicate claims follow everywhere else in this format.
    /// Validity is re-checked here because this is the accessor every workload
    /// and measurement policy path goes through.
    pub fn workload_pack(&self) -> Result<&TrustPack, PortalVerificationError> {
        self.ensure_valid_now()?;
        match self.inner.workload_packs.as_slice() {
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

    /// Platform pairs for which this source currently carries every coarse
    /// trust input. Exact AMD CPUID and Azure token-key selection still occur
    /// per verification.
    pub fn supported_platforms(&self) -> Vec<String> {
        supported_platforms_for_anchors(&self.inner.collateral.trust_anchors)
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
                .inner
                .collateral
                .issuers
                .iter()
                .map(|provenance| provenance.issuer.clone())
                .collect(),
            digests: self
                .inner
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
/// verifier-selected chain coordinates used to authenticate a chain-bound
/// session are reachable only through this variant. Other sources currently
/// have no trusted coordinates and therefore fail closed for chain-bound
/// evidence. A local-bound session does not use these coordinates.
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

    /// Verifier-selected chain coordinates. A chain-bound session is checked
    /// against them. A local-bound session does not use them.
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
    /// The Intel TDX collateral source is independent of the operator's policy
    /// authority. Automata on-chain PCCS is permitted here because it returns
    /// vendor-signed collateral that is verified locally; it does not supply a
    /// measurement policy or workload policy.
    pub fn new(
        trust: TlsVerificationTrust,
        tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    ) -> Result<Self, PortalVerificationError> {
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

    /// Platform pairs for which the configured files currently carry every
    /// coarse trust input. Exact AMD CPUID and Azure token-key selection still
    /// occur per verification.
    pub fn supported_platforms(&self) -> Vec<String> {
        supported_platforms_for_anchors(&self.anchors)
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

fn supported_platforms_for_anchors(anchors: &TrustAnchors) -> Vec<String> {
    const PAIRS: &[(&str, &str)] = &[
        ("gcp", "tdx"),
        ("gcp", "sev-snp"),
        ("azure", "tdx"),
        ("azure", "sev-snp"),
        ("aws", "sev-snp"),
    ];
    PAIRS
        .iter()
        .filter(|(cloud, tee)| {
            crate::trust::requirements::unsatisfied_trust_inputs(cloud, tee, anchors).is_empty()
        })
        .map(|(cloud, tee)| format!("{cloud}-{tee}"))
        .collect()
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
    use crate::collateral::intel_tdx::IntelTdxDcapCollateralSource;

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

    #[test]
    fn explicit_mode_accepts_automata_onchain_pccs_collateral() {
        let source = ExplicitTrustSource::new(TlsVerificationTrust::default(), automata_onchain())
            .expect("Automata on-chain PCCS is collateral, not the policy authority");
        assert!(matches!(
            source.tdx_dcap_collateral.source,
            IntelTdxDcapCollateralSource::AutomataOnchainPccs { .. }
        ));
    }

    #[test]
    fn trust_pack_mode_accepts_automata_onchain_pccs_collateral() {
        let source = PackTrustSource::new(Vec::new(), Vec::new(), automata_onchain())
            .expect("Automata on-chain PCCS is collateral, not the pack authority");
        assert!(matches!(
            source.tdx_dcap_collateral.source,
            IntelTdxDcapCollateralSource::AutomataOnchainPccs { .. }
        ));
    }

    /// Off-chain vendor endpoints stay available: self-authenticating
    /// collateral is not a trust source, so fetching it is not a fallback.
    #[test]
    fn explicit_mode_accepts_file_http_and_no_collateral_sources() {
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
                "file, HTTP, and no-collateral configurations must remain available in explicit mode"
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
