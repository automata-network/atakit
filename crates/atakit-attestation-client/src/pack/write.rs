//! Producing a `.atatp` archive.
//!
//! Written before the reader on purpose. A reader can be made to accept
//! whatever a hand-built fixture happens to contain; a producer has to decide
//! what the bytes actually are, which is where format problems surface.
//!
//! The builder owns no key material. Signing is a caller-supplied closure, so
//! the private key stays with whatever already resolves `[keys]` and this crate
//! keeps handling public inputs only.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::pack::{
    ArchiveLimits, TrustPackError, TrustPackIndex, TrustPackKind, TRUST_PACK_FORMAT,
};

/// Assembles the payload, derives the validity window, and emits a signed
/// archive.
#[derive(Debug, Clone)]
pub struct TrustPackBuilder {
    kind: TrustPackKind,
    issuer: String,
    revision: u64,
    not_before: u64,
    intended_not_after: u64,
    payload: BTreeMap<String, Vec<u8>>,
    limits: ArchiveLimits,
}

impl TrustPackBuilder {
    /// `intended_not_after` is the publisher's wish, not the result.
    /// [`TrustPackBuilder::build`] lowers it to the earliest expiry among the
    /// contents, so a pack cannot advertise a longer life than the
    /// shortest-lived thing inside it.
    pub fn new(
        kind: TrustPackKind,
        issuer: impl Into<String>,
        revision: u64,
        not_before: u64,
        intended_not_after: u64,
    ) -> Self {
        Self {
            kind,
            issuer: issuer.into(),
            revision,
            not_before,
            intended_not_after,
            payload: BTreeMap::new(),
            limits: ArchiveLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: ArchiveLimits) -> Self {
        self.limits = limits;
        self
    }

    /// What this builder will ship, by payload path.
    pub fn payload(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.payload
    }

    /// Add one payload entry, rejecting a path outside the kind's namespace.
    ///
    /// Rejecting here rather than at build time means a producer cannot
    /// assemble an archive that only a reader will refuse.
    pub fn insert(
        &mut self,
        path: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<(), TrustPackError> {
        let path = path.into();
        if !self.kind.allows(&path) {
            return Err(TrustPackError::OutsideNamespace {
                path,
                kind: self.kind.as_str(),
            });
        }
        if bytes.len() as u64 > self.limits.max_entry_bytes {
            return Err(TrustPackError::LimitExceeded {
                limit: "single entry size",
                allowed: self.limits.max_entry_bytes,
                actual: bytes.len() as u64,
            });
        }
        if self.payload.contains_key(&path) {
            return Err(TrustPackError::UnacceptableEntry {
                path,
                kind: "a duplicate path".to_string(),
            });
        }
        self.payload.insert(path, bytes);
        Ok(())
    }

    /// The canonical `trust-pack.json` bytes this payload produces.
    ///
    /// Separate from [`TrustPackBuilder::build`] because these are exactly the
    /// bytes the signature covers and exactly the bytes a digest pin is taken
    /// over, so a caller signing out of process needs them on their own.
    pub fn index_bytes(&self) -> Result<Vec<u8>, TrustPackError> {
        self.check_namespace_shape()?;
        let not_after = self.derived_not_after()?;
        if self.not_before >= not_after {
            return Err(TrustPackError::EmptyValidity {
                not_before: self.not_before,
                not_after,
            });
        }
        let index = TrustPackIndex {
            format: TRUST_PACK_FORMAT,
            kind: self.kind.as_str().to_string(),
            issuer: self.issuer.clone(),
            revision: self.revision,
            not_before: self.not_before,
            not_after,
            hashes: self
                .payload
                .iter()
                .map(|(path, bytes)| (path.clone(), sha256_hex(bytes)))
                .collect(),
        };
        canonical_json(&index)
    }

    /// Emit the complete archive.
    ///
    /// `sign` receives the canonical index bytes and returns a detached ES256K
    /// signature over them.
    pub fn build<E: std::fmt::Display>(
        &self,
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    ) -> Result<Vec<u8>, TrustPackError> {
        let index = self.index_bytes()?;
        let signature = sign(&index).map_err(|error| TrustPackError::Signature {
            kind: self.kind.as_str().to_string(),
            message: format!("signing failed: {error}"),
        })?;
        if signature.is_empty() {
            return Err(TrustPackError::Signature {
                kind: self.kind.as_str().to_string(),
                message: "signer produced an empty signature".to_string(),
            });
        }

        let mut entries: Vec<(&str, &[u8])> =
            vec![("trust-pack.json", &index), ("trust-pack.sig", &signature)];
        entries.extend(
            self.payload
                .iter()
                .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
        );
        if entries.len() > self.limits.max_entries {
            return Err(TrustPackError::LimitExceeded {
                limit: "entry count",
                allowed: self.limits.max_entries as u64,
                actual: entries.len() as u64,
            });
        }

        let tar = build_tar(&entries)?;
        // The reader bounds total decompressed size and compression ratio, so
        // the writer must too. Producing an archive that this crate's own
        // reader refuses would turn a producer-side mistake into a failure that
        // only shows up at the verifier, which is the worst place to find it.
        if tar.len() as u64 > self.limits.max_total_bytes {
            return Err(TrustPackError::LimitExceeded {
                limit: "total decompressed size",
                allowed: self.limits.max_total_bytes,
                actual: tar.len() as u64,
            });
        }
        let archive = zstd::stream::encode_all(tar.as_slice(), 19).map_err(|error| {
            TrustPackError::Archive {
                message: format!("zstd compression failed: {error}"),
            }
        })?;
        let ratio = tar.len() as u64 / archive.len().max(1) as u64;
        if ratio > self.limits.max_compression_ratio {
            return Err(TrustPackError::LimitExceeded {
                limit: "compression ratio",
                allowed: self.limits.max_compression_ratio,
                actual: ratio,
            });
        }
        Ok(archive)
    }

    /// Structural rules a kind imposes beyond per-path namespace membership.
    fn check_namespace_shape(&self) -> Result<(), TrustPackError> {
        if self.kind != TrustPackKind::WorkloadTrust {
            return Ok(());
        }
        if !self.payload.contains_key("payload/workload-spec.json") {
            return Err(TrustPackError::MissingEntry {
                path: "payload/workload-spec.json".to_string(),
            });
        }
        check_measurement_pack_triples(self.payload.keys().map(String::as_str))
    }

    /// The minimum of the intended value and the earliest expiry inside.
    fn derived_not_after(&self) -> Result<u64, TrustPackError> {
        let mut earliest = self.intended_not_after;
        for (path, bytes) in &self.payload {
            if let Some(expiry) = entry_expiry(path, bytes)? {
                earliest = earliest.min(expiry);
            }
        }
        Ok(earliest)
    }
}

/// Every `<stem>.json` must have a `<stem>.sig` and a `<stem>.pubkey`, and
/// neither may stand alone.
///
/// A `.sig` without its `.json` is not merely untidy: it is the shape a
/// producer ends up with after replacing a measurement pack and forgetting one
/// member of the triple, and the reader would then select a different entry
/// than the producer believed it shipped.
pub(crate) fn check_measurement_pack_triples<'a>(
    paths: impl Iterator<Item = &'a str>,
) -> Result<(), TrustPackError> {
    const PREFIX: &str = "payload/measurement-packs/";
    let mut json = std::collections::BTreeSet::new();
    let mut sig = std::collections::BTreeSet::new();
    let mut pubkey = std::collections::BTreeSet::new();
    for path in paths {
        let Some(rest) = path.strip_prefix(PREFIX) else {
            continue;
        };
        if let Some(stem) = rest.strip_suffix(".json") {
            json.insert(stem.to_string());
        } else if let Some(stem) = rest.strip_suffix(".sig") {
            sig.insert(stem.to_string());
        } else if let Some(stem) = rest.strip_suffix(".pubkey") {
            pubkey.insert(stem.to_string());
        }
    }
    for stem in &json {
        for (set, suffix) in [(&sig, ".sig"), (&pubkey, ".pubkey")] {
            if !set.contains(stem) {
                return Err(TrustPackError::MissingEntry {
                    path: format!("{PREFIX}{stem}{suffix}"),
                });
            }
        }
    }
    for (set, suffix) in [(&sig, ".sig"), (&pubkey, ".pubkey")] {
        for stem in set.iter() {
            if !json.contains(stem) {
                return Err(TrustPackError::MissingEntry {
                    path: format!("{PREFIX}{stem}.json (required by {stem}{suffix})"),
                });
            }
        }
    }
    Ok(())
}

/// The expiry one payload entry contributes to `not_after`, if it has one.
///
/// Only the three artifact classes the specification names carry an expiry
/// here: Azure MAA signing certificates, AMD SEV-SNP certificate revocation
/// lists, and the signed TCB Info and QE Identity inside Intel TDX DCAP
/// collateral. Trust roots are deliberately not included — a root CA outlives
/// every pack that would carry it, and folding it in would pin `not_after` to a
/// value that says nothing about the pack's freshness.
fn entry_expiry(path: &str, bytes: &[u8]) -> Result<Option<u64>, TrustPackError> {
    if path.starts_with("payload/azure-maa/") {
        return Ok(Some(certificate_not_after(path, bytes)?));
    }
    if path.starts_with("payload/amd-snp-crl/") {
        return Ok(Some(crl_next_update(path, bytes)?));
    }
    if path.starts_with("payload/tdx-dcap/") {
        return Ok(Some(collateral_next_update(path, bytes)?));
    }
    Ok(None)
}

fn certificate_not_after(path: &str, bytes: &[u8]) -> Result<u64, TrustPackError> {
    use x509_cert::der::Decode;

    let der = single_pem_certificate(path, bytes)?;
    let certificate =
        x509_cert::Certificate::from_der(&der).map_err(|error| TrustPackError::Payload {
            path: path.to_string(),
            message: format!("not an X.509 certificate: {error}"),
        })?;
    Ok(certificate
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs())
}

fn crl_next_update(path: &str, bytes: &[u8]) -> Result<u64, TrustPackError> {
    use x509_cert::der::Decode;

    let list = x509_cert::crl::CertificateList::from_der(bytes).map_err(|error| {
        TrustPackError::Payload {
            path: path.to_string(),
            message: format!("not a DER certificate revocation list: {error}"),
        }
    })?;
    let next_update = list
        .tbs_cert_list
        .next_update
        .ok_or_else(|| TrustPackError::Payload {
            path: path.to_string(),
            message: "certificate revocation list has no nextUpdate, so the pack cannot derive \
                      an expiry from it"
                .to_string(),
        })?;
    Ok(next_update.to_unix_duration().as_secs())
}

/// The earlier of the signed TCB Info and QE Identity `nextUpdate` values.
///
/// Read out of the signed JSON rather than a selector field so the derived
/// expiry comes from the same bytes Intel signed.
fn collateral_next_update(path: &str, bytes: &[u8]) -> Result<u64, TrustPackError> {
    let document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| TrustPackError::Payload {
            path: path.to_string(),
            message: format!("not JSON: {error}"),
        })?;
    let payload = document
        .get("payload")
        .ok_or_else(|| TrustPackError::Payload {
            path: path.to_string(),
            message: "no payload object".to_string(),
        })?;

    let mut earliest = None;
    for (field, container, key) in [
        ("tcbInfoSignedJson", "tcbInfo", "nextUpdate"),
        ("qeIdentitySignedJson", "enclaveIdentity", "nextUpdate"),
    ] {
        let signed = payload
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| TrustPackError::Payload {
                path: path.to_string(),
                message: format!("payload.{field} is missing or not a string"),
            })?;
        let parsed: serde_json::Value =
            serde_json::from_str(signed).map_err(|error| TrustPackError::Payload {
                path: path.to_string(),
                message: format!("payload.{field} is not JSON: {error}"),
            })?;
        let text = parsed
            .get(container)
            .and_then(|value| value.get(key))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| TrustPackError::Payload {
                path: path.to_string(),
                message: format!("payload.{field} has no {container}.{key}"),
            })?;
        let seconds = chrono::DateTime::parse_from_rfc3339(text)
            .map_err(|error| TrustPackError::Payload {
                path: path.to_string(),
                message: format!("{container}.{key} {text:?} is not RFC 3339: {error}"),
            })?
            .timestamp();
        let seconds = u64::try_from(seconds).map_err(|_| TrustPackError::Payload {
            path: path.to_string(),
            message: format!("{container}.{key} {text:?} predates the Unix epoch"),
        })?;
        earliest = Some(earliest.map_or(seconds, |current: u64| current.min(seconds)));
    }
    earliest.ok_or_else(|| TrustPackError::Payload {
        path: path.to_string(),
        message: "no signed TCB Info or QE Identity validity to derive an expiry from".to_string(),
    })
}

fn single_pem_certificate(path: &str, bytes: &[u8]) -> Result<Vec<u8>, TrustPackError> {
    let mut certificates =
        crate::trust::files::parse_pem_certificates(bytes).map_err(|message| {
            TrustPackError::Payload {
                path: path.to_string(),
                message,
            }
        })?;
    if certificates.len() != 1 {
        return Err(TrustPackError::Payload {
            path: path.to_string(),
            message: format!(
                "expected exactly one PEM certificate, found {}; content selects entries, so a \
                 bundle would leave which certificate this path names undefined",
                certificates.len()
            ),
        });
    }
    Ok(certificates.remove(0))
}

/// A tar with fixed metadata, so the same inputs produce the same archive.
///
/// The signature covers the index rather than the archive bytes precisely
/// because tar is not canonical, but determinism still makes two builds
/// comparable and keeps a rebuild from looking like a content change.
fn build_tar(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, TrustPackError> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, path, *bytes)
            .map_err(|error| TrustPackError::Archive {
                message: format!("append {path}: {error}"),
            })?;
    }
    builder
        .into_inner()
        .map_err(|error| TrustPackError::Archive {
            message: format!("finish tar: {error}"),
        })
}

pub(crate) fn canonical_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, TrustPackError> {
    serde_json_canonicalizer::to_vec(value).map_err(|error| TrustPackError::Index {
        message: format!("canonicalization failed: {error}"),
    })
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_rejects_duplicate_payload_paths() {
        let mut builder =
            TrustPackBuilder::new(TrustPackKind::CollateralTrust, "publisher", 1, 1, 2);
        builder
            .insert("payload/roots/gcp-ak-root.pem", b"first".to_vec())
            .unwrap();

        let error = builder
            .insert("payload/roots/gcp-ak-root.pem", b"second".to_vec())
            .expect_err("a second entry must not silently replace the first");

        assert!(matches!(error, TrustPackError::UnacceptableEntry { .. }));
        assert_eq!(builder.payload()["payload/roots/gcp-ak-root.pem"], b"first");
    }
}
