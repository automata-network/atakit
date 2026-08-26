//! `.atatp` trust packs: signed verification trust inputs for an offline
//! verifier.
//!
//! A trust pack supplies **inputs**. It carries no evidence, changes no check,
//! and selects no endpoint or registry. Its contents convert into the same
//! typed values a chain-resolved verifier would produce, and the conversion
//! must not weaken any check.
//!
//! The format is `docs/specs/atatp-archive-spec.md`. Modules follow what the
//! specification separates:
//!
//! - [`write`] produces an archive and derives its validity window.
//! - [`read`] performs the nine-step verification procedure over one archive.
//! - [`collateral`] converts a `collateral-trust` pack into trust anchors.
//! - [`workload`] converts a `workload-trust` pack into measurement and
//!   workload session policy.
//!
//! `write` came first deliberately: a producer surfaces format problems a
//! reader does not, because a reader can be written to accept whatever some
//! hand-made fixture happens to contain.

pub mod collateral;
#[cfg(test)]
pub(crate) mod fixture;
pub mod read;
pub mod workload;
pub mod write;

use std::collections::BTreeMap;

use crate::error::PortalVerificationError;

/// Current `trust-pack.json` schema version. There is no other accepted value
/// and no migration path.
pub const TRUST_PACK_FORMAT: u32 = 1;

/// Wall-clock seconds, for re-checking a pack's validity window.
///
/// A pack that was valid when it was read is not necessarily valid now, and a
/// daemon holds its packs for as long as it runs.
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        // Before the epoch no pack can be valid, so refuse them all rather than
        // treat a broken clock as a verification time.
        .unwrap_or(0)
}

/// Which payload namespace a pack occupies, and therefore which configured
/// publisher key must have signed it.
///
/// `kind` binds authority *between* kinds: without it, a workload publisher's
/// key could sign a pack containing `payload/roots/` and silently become a
/// trust root authority. Authority *within* `workload-trust` is bound
/// separately, by identifier derivation — see [`workload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustPackKind {
    /// Trust roots, Azure MAA signing certificates, AMD SEV-SNP security
    /// policy, AWS document limits, and optional vendor collateral.
    CollateralTrust,
    /// A workload specification and the base-image measurement packs its
    /// `base_image_ids` name.
    WorkloadTrust,
}

impl TrustPackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CollateralTrust => "collateral-trust",
            Self::WorkloadTrust => "workload-trust",
        }
    }

    pub fn parse(value: &str) -> Result<Self, TrustPackError> {
        match value {
            "collateral-trust" => Ok(Self::CollateralTrust),
            "workload-trust" => Ok(Self::WorkloadTrust),
            other => Err(TrustPackError::UnknownKind {
                kind: other.to_string(),
            }),
        }
    }

    /// Whether `path` is inside this kind's payload namespace.
    ///
    /// A pack containing any path outside its namespace is rejected whole,
    /// before any entry is used.
    pub fn allows(self, path: &str) -> bool {
        match self {
            Self::CollateralTrust => match path {
                "payload/roots/gcp-ak-root.pem"
                | "payload/roots/aws-nitro-root.pem"
                | "payload/aws-document-limits.json" => true,
                _ => {
                    matches_segment(path, "payload/roots/", "amd-ark-", ".pem")
                        || matches_segment(path, "payload/azure-maa/", "", ".pem")
                        || matches_segment(path, "payload/amd-snp-security-policy/", "", ".json")
                        || matches_segment(path, "payload/amd-snp-crl/", "", ".der")
                        || matches_segment(path, "payload/tdx-dcap/", "", ".json")
                }
            },
            Self::WorkloadTrust => {
                path == "payload/workload-spec.json"
                    || matches_segment(path, "payload/measurement-packs/", "", ".json")
                    || matches_segment(path, "payload/measurement-packs/", "", ".sig")
                    || matches_segment(path, "payload/measurement-packs/", "", ".pubkey")
            }
        }
    }
}

/// Whether `path` is `<prefix><stem_prefix><name><suffix>` with a non-empty
/// `name` containing no further path separator.
///
/// `name` must be non-empty rather than merely present: `amd-ark-.pem` names
/// no product line, and accepting it would put a root certificate at a path
/// that addresses nothing.
///
/// The separator rule is what keeps `*` a single segment. Without it
/// `payload/tdx-dcap/../../etc/passwd.json` would match the namespace even
/// though the traversal check rejects it for a different reason; two
/// independent rules rejecting the same input is deliberate.
fn matches_segment(path: &str, prefix: &str, stem_prefix: &str, suffix: &str) -> bool {
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    let Some(stem) = rest.strip_suffix(suffix) else {
        return false;
    };
    let Some(name) = stem.strip_prefix(stem_prefix) else {
        return false;
    };
    !name.is_empty() && !stem.contains('/')
}

/// `trust-pack.json`: identity, validity, and the SHA-256 of every payload
/// entry.
///
/// Unknown fields are rejected. One signature over this canonical index covers
/// the whole pack, because the index hashes every payload entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPackIndex {
    pub format: u32,
    pub kind: String,
    /// Human label identifying the publisher. **Never** used in a trust
    /// decision — the configured key for `kind` is what decides that.
    pub issuer: String,
    /// Monotonic per issuer and kind, and **informational only**. A reader must
    /// not reject a pack on it and no verifier tracks the highest seen:
    /// enforcement would need persistent per-issuer state this design
    /// deliberately lacks, so an enforced-looking counter would be a security
    /// property existing only in the field's name. Rollback control is digest
    /// pinning bounded by `not_after`.
    pub revision: u64,
    /// Unix seconds.
    pub not_before: u64,
    /// Unix seconds. Derived by the writer as the minimum of its intended value
    /// and the earliest expiry of every artifact the pack contains, so a pack
    /// cannot advertise a longer life than its shortest-lived content.
    pub not_after: u64,
    /// Payload path to `sha256:<lowercase hex>`. Every payload entry appears
    /// exactly once.
    pub hashes: BTreeMap<String, String>,
}

impl TrustPackIndex {
    pub fn kind(&self) -> Result<TrustPackKind, TrustPackError> {
        TrustPackKind::parse(&self.kind)
    }
}

/// Bounds a conforming reader applies before parsing anything.
///
/// Exceeding a bound is a rejection, never a truncation: a reader that
/// silently stopped early would report success over a partial archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_entry_bytes: u64,
    pub max_entries: usize,
    pub max_total_bytes: u64,
    pub max_compression_ratio: u64,
}

impl Default for ArchiveLimits {
    /// The specification's values.
    ///
    /// `max_entry_bytes` is fixed, not provisional: it is
    /// `MAX_COLLATERAL_COMPONENT_BYTES` in `atakit-attestation`, and an
    /// embedded Intel TDX DCAP collateral component accepted here but rejected
    /// there would be a wasted parse. The other three are provisional pending
    /// measurement against a produced `collateral-trust` pack carrying a full
    /// Provisioning Certificate Caching Service snapshot.
    fn default() -> Self {
        Self {
            max_entry_bytes: 4 * 1024 * 1024,
            max_entries: 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_compression_ratio: 100,
        }
    }
}

/// Why a trust pack was refused.
///
/// A pack that exists but cannot be used is fatal, never a fallback: falling
/// back to another source would mean an operator believes they pinned
/// something and silently did not. Every variant names the specific input, so
/// a failure is actionable without re-reading the archive.
#[derive(Debug, thiserror::Error)]
pub enum TrustPackError {
    #[error("trust pack archive is malformed: {message}")]
    Archive { message: String },

    #[error(
        "trust pack entry {path} is {kind}; only regular files with relative, \
         non-traversing, unique paths are accepted"
    )]
    UnacceptableEntry { path: String, kind: String },

    #[error("trust pack exceeds the {limit} limit of {allowed}, at {actual}")]
    LimitExceeded {
        limit: &'static str,
        allowed: u64,
        actual: u64,
    },

    #[error("trust pack is missing {path}")]
    MissingEntry { path: String },

    #[error("trust-pack.json is not valid: {message}")]
    Index { message: String },

    #[error(
        "trust-pack.json format is {found}; this reader accepts {TRUST_PACK_FORMAT} only, and \
         there is no migration path"
    )]
    UnsupportedFormat { found: u32 },

    #[error("trust-pack.json kind {kind:?} is not collateral-trust or workload-trust")]
    UnknownKind { kind: String },

    #[error(
        "trust-pack.json bytes are not their RFC 8785 canonical encoding; the signature covers \
         the bytes as they appear in the archive, so a non-canonical index would let two \
         byte-different archives carry identical content under two different pinning digests"
    )]
    NonCanonicalIndex,

    #[error(
        "trust pack signature does not verify under the configured {kind} publisher key: {message}"
    )]
    Signature { kind: String, message: String },

    #[error(
        "trust pack is a {found} pack; the caller requires {expected}, and a pack cannot select \
         which configured key verifies it"
    )]
    KindMismatch {
        expected: &'static str,
        found: String,
    },

    #[error(
        "trust pack validity is [{not_before}, {not_after}) and the verification time is {now}"
    )]
    OutsideValidity {
        not_before: u64,
        not_after: u64,
        now: u64,
    },

    #[error("trust pack validity window is empty: not_before {not_before} is not before not_after {not_after}")]
    EmptyValidity { not_before: u64, not_after: u64 },

    #[error("trust pack entry {path} is outside the {kind} payload namespace")]
    OutsideNamespace { path: String, kind: &'static str },

    #[error("trust pack payload entry {path} has no entry in hashes")]
    UnhashedEntry { path: String },

    #[error("trust pack hashes name {path}, which the archive does not contain")]
    HashWithoutEntry { path: String },

    #[error("trust pack entry {path} hashes to {actual}, but hashes declares {declared}")]
    HashMismatch {
        path: String,
        declared: String,
        actual: String,
    },

    #[error("trust pack hash for {path} is {value:?}; expected 'sha256:' and 64 lowercase hexadecimal characters")]
    MalformedHash { path: String, value: String },

    #[error("trust pack digest is {actual}, but the configured pin is {pinned}")]
    PinMismatch { pinned: String, actual: String },

    #[error("trust pack entry {path} could not be parsed: {message}")]
    Payload { path: String, message: String },

    #[error("{message}")]
    Authority { message: String },
}

impl From<TrustPackError> for PortalVerificationError {
    /// A refused pack is a configuration error, not a runtime condition. The
    /// verifier declines to start rather than resolving the input elsewhere.
    fn from(error: TrustPackError) -> Self {
        PortalVerificationError::Config {
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_round_trips_through_its_wire_name() {
        for kind in [TrustPackKind::CollateralTrust, TrustPackKind::WorkloadTrust] {
            assert_eq!(TrustPackKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(TrustPackKind::parse("root-trust").is_err());
    }

    #[test]
    fn collateral_namespace_admits_exactly_the_specified_paths() {
        let kind = TrustPackKind::CollateralTrust;
        for path in [
            "payload/roots/gcp-ak-root.pem",
            "payload/roots/aws-nitro-root.pem",
            "payload/roots/amd-ark-milan.pem",
            "payload/azure-maa/sharedeus.pem",
            "payload/amd-snp-security-policy/0x00190100.json",
            "payload/aws-document-limits.json",
            "payload/amd-snp-crl/milan.der",
            "payload/tdx-dcap/00806f050000.json",
        ] {
            assert!(kind.allows(path), "{path} must be inside the namespace");
        }
    }

    /// The Intel SGX Root CA has no runtime governance anywhere in the stack —
    /// it is a compile-time constant in `dcap_rs` and in
    /// `PcsDao.ROOT_CA_PUBKEY_HASH` — so a pack must not appear to provide one.
    #[test]
    fn collateral_namespace_refuses_an_intel_root_and_foreign_paths() {
        let kind = TrustPackKind::CollateralTrust;
        for path in [
            "payload/roots/intel-sgx-root.pem",
            "payload/roots/gcp-ak-root.der",
            "payload/roots/nested/amd-ark-milan.pem",
            "payload/workload-spec.json",
            "payload/measurement-packs/base.json",
            "payload/roots/amd-ark-.pem",
            "payload/roots/.pem",
            "trust-pack.json",
            "payload/tdx-dcap/",
        ] {
            assert!(!kind.allows(path), "{path} must be outside the namespace");
        }
    }

    #[test]
    fn workload_namespace_admits_the_triple_and_refuses_the_removed_key_file() {
        let kind = TrustPackKind::WorkloadTrust;
        for path in [
            "payload/workload-spec.json",
            "payload/measurement-packs/automata-linux.json",
            "payload/measurement-packs/automata-linux.sig",
            "payload/measurement-packs/automata-linux.pubkey",
        ] {
            assert!(kind.allows(path), "{path} must be inside the namespace");
        }
        // Removed by the publisher-qualified identifier change: one
        // archive-wide key that decided what every base image measured.
        assert!(!kind.allows("payload/measurement-publisher-pubkey.pem"));
        assert!(!kind.allows("payload/roots/gcp-ak-root.pem"));
    }

    /// A namespace match must not be reachable through a traversing path, even
    /// though entry filtering rejects it independently.
    #[test]
    fn namespace_matching_never_crosses_a_path_separator() {
        assert!(!TrustPackKind::CollateralTrust.allows("payload/tdx-dcap/../../secrets.json"));
        assert!(
            !TrustPackKind::WorkloadTrust.allows("payload/measurement-packs/../workload-spec.json")
        );
    }

    #[test]
    fn the_default_entry_limit_matches_the_attestation_collateral_bound() {
        assert_eq!(
            ArchiveLimits::default().max_entry_bytes as usize,
            atakit_attestation::MAX_COLLATERAL_COMPONENT_BYTES,
            "changing one of these requires changing the other"
        );
    }
}
