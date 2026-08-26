//! Reading and verifying one `.atatp` archive.
//!
//! The nine steps below are the specification's verification procedure, in
//! order, stopping at the first failure. A pack that fails any step is rejected
//! **whole**; partial acceptance is not defined, and there is no fallback to
//! another trust source.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read};
use std::path::Path;

use crate::pack::write::{canonical_json, check_measurement_pack_triples, sha256, sha256_hex};
use crate::pack::{
    ArchiveLimits, TrustPackError, TrustPackIndex, TrustPackKind, TRUST_PACK_FORMAT,
};

/// What the verifier's configuration says about one role's packs.
#[derive(Debug, Clone)]
pub struct TrustPackReadOptions {
    /// The role this pack must occupy. A pack cannot select which configured
    /// key verifies it, so the caller states the kind and the key together.
    pub kind: TrustPackKind,
    /// Uncompressed SEC1 secp256k1 public key for that role, from the
    /// verifier's configuration and never from the pack.
    pub publisher_key: Vec<u8>,
    /// Verification time in Unix seconds. Taken as an argument rather than
    /// read from the clock so a test can pin it, matching
    /// `verify_tls_attestation_at`.
    pub now_unix: u64,
    /// SHA-256 of `trust-pack.json` bytes, when the operator pinned one.
    /// Pinning is the only rollback control; `revision` is informational and
    /// bounds nothing.
    pub pinned_digest: Option<[u8; 32]>,
    pub limits: ArchiveLimits,
}

impl TrustPackReadOptions {
    pub fn new(kind: TrustPackKind, publisher_key: Vec<u8>, now_unix: u64) -> Self {
        Self {
            kind,
            publisher_key,
            now_unix,
            pinned_digest: None,
            limits: ArchiveLimits::default(),
        }
    }

    pub fn pinned(mut self, digest: [u8; 32]) -> Self {
        self.pinned_digest = Some(digest);
        self
    }
}

/// A verified trust pack, ready for conversion into typed trust inputs.
#[derive(Debug, Clone)]
pub struct TrustPack {
    pub index: TrustPackIndex,
    pub kind: TrustPackKind,
    /// SHA-256 of the `trust-pack.json` bytes — the value a digest pin uses.
    /// Because that file is canonical and hashes every payload entry, pinning
    /// it pins the complete contents regardless of how the archive was built.
    pub digest: [u8; 32],
    /// The configured key this pack verified under, retained so downstream
    /// authority checks compare against the same key rather than being handed
    /// one a second time.
    pub publisher_key: Vec<u8>,
    pub payload: BTreeMap<String, Vec<u8>>,
}

impl TrustPack {
    pub fn entry(&self, path: &str) -> Result<&[u8], TrustPackError> {
        self.payload
            .get(path)
            .map(Vec::as_slice)
            .ok_or_else(|| TrustPackError::MissingEntry {
                path: path.to_string(),
            })
    }

    /// Payload entries under `prefix`, in path order.
    pub fn entries_under<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a [u8])> {
        self.payload
            .iter()
            .filter(move |(path, _)| path.starts_with(prefix))
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    pub fn digest_hex(&self) -> String {
        format!("0x{}", hex::encode(self.digest))
    }

    /// Re-check the validity window.
    ///
    /// Reading a pack checks it once, which is enough for a command that exits
    /// but not for a daemon: `atakit-verifierd` loads its packs at startup and
    /// then runs, so a pack validated at load would otherwise keep answering
    /// verifications indefinitely past `not_after`. Every verification calls
    /// this, so expiry bounds the verification rather than the process.
    pub fn ensure_valid_at(&self, now_unix: u64) -> Result<(), TrustPackError> {
        if now_unix < self.index.not_before || now_unix >= self.index.not_after {
            return Err(TrustPackError::OutsideValidity {
                not_before: self.index.not_before,
                not_after: self.index.not_after,
                now: now_unix,
            });
        }
        Ok(())
    }
}

pub fn read_trust_pack_file(
    path: &Path,
    options: &TrustPackReadOptions,
) -> Result<TrustPack, TrustPackError> {
    let file = std::fs::File::open(path).map_err(|error| TrustPackError::Archive {
        message: format!("read {}: {error}", path.display()),
    })?;
    let compressed_bytes = file
        .metadata()
        .map_err(|error| TrustPackError::Archive {
            message: format!("read metadata for {}: {error}", path.display()),
        })?
        .len();
    let tar = decompress_reader(BufReader::new(file), compressed_bytes, &options.limits).map_err(
        |error| match error {
            TrustPackError::Archive { message } => TrustPackError::Archive {
                message: format!("{}: {message}", path.display()),
            },
            other => other,
        },
    )?;
    read_trust_pack_tar(&tar, options).map_err(|error| match error {
        // Keep the archive that failed identifiable when several are
        // configured; every other variant already names an entry.
        TrustPackError::Archive { message } => TrustPackError::Archive {
            message: format!("{}: {message}", path.display()),
        },
        other => other,
    })
}

pub fn read_trust_pack(
    archive: &[u8],
    options: &TrustPackReadOptions,
) -> Result<TrustPack, TrustPackError> {
    // Step 1: decompress within limits.
    let tar = decompress(archive, &options.limits)?;

    read_trust_pack_tar(&tar, options)
}

fn read_trust_pack_tar(
    tar: &[u8],
    options: &TrustPackReadOptions,
) -> Result<TrustPack, TrustPackError> {
    // Step 2: accept only regular files with relative, non-traversing, unique
    // paths.
    let mut entries = read_tar_entries(tar, &options.limits)?;

    let index_bytes =
        entries
            .remove("trust-pack.json")
            .ok_or_else(|| TrustPackError::MissingEntry {
                path: "trust-pack.json".to_string(),
            })?;
    let signature =
        entries
            .remove("trust-pack.sig")
            .ok_or_else(|| TrustPackError::MissingEntry {
                path: "trust-pack.sig".to_string(),
            })?;

    // The pin is over exactly these bytes and nothing about parsing them can
    // change it, so it is checked as soon as they exist. An operator who
    // pinned a digest wants "this is not the artifact you pinned" ahead of any
    // other complaint about it.
    let digest = sha256(&index_bytes);
    if let Some(pinned) = options.pinned_digest {
        if pinned != digest {
            return Err(TrustPackError::PinMismatch {
                pinned: format!("0x{}", hex::encode(pinned)),
                actual: format!("0x{}", hex::encode(digest)),
            });
        }
    }

    // Step 3: parse the index, rejecting unknown fields and any other format.
    let index: TrustPackIndex =
        serde_json::from_slice(&index_bytes).map_err(|error| TrustPackError::Index {
            message: error.to_string(),
        })?;
    if index.format != TRUST_PACK_FORMAT {
        return Err(TrustPackError::UnsupportedFormat {
            found: index.format,
        });
    }
    let kind = index.kind()?;

    // Step 4: the bytes in the archive must already be their canonical
    // encoding. This precedes the signature check: the signature covers the
    // bytes as they appear, so a producer could otherwise ship non-canonical
    // bytes that still verify, and two byte-different archives carrying
    // identical parsed content would pin to two different digests.
    if canonical_json(&index)? != index_bytes {
        return Err(TrustPackError::NonCanonicalIndex);
    }

    // Step 5: verify under the configured key for the role named by `kind`.
    // The kind is checked first so a mismatched pack is reported as the wrong
    // role rather than as a signature failure, which would send an operator
    // looking at the wrong thing.
    if kind != options.kind {
        return Err(TrustPackError::KindMismatch {
            expected: options.kind.as_str(),
            found: index.kind.clone(),
        });
    }
    atakit_attestation::verify_es256k_detached(&index_bytes, &signature, &options.publisher_key)
        .map_err(|error| TrustPackError::Signature {
            kind: kind.as_str().to_string(),
            message: error.to_string(),
        })?;

    // Step 6: the current time must fall within [not_before, not_after).
    if index.not_before >= index.not_after {
        return Err(TrustPackError::EmptyValidity {
            not_before: index.not_before,
            not_after: index.not_after,
        });
    }
    if options.now_unix < index.not_before || options.now_unix >= index.not_after {
        return Err(TrustPackError::OutsideValidity {
            not_before: index.not_before,
            not_after: index.not_after,
            now: options.now_unix,
        });
    }

    // Step 7: no payload path outside the namespace for `kind`.
    for path in entries.keys() {
        if !kind.allows(path) {
            return Err(TrustPackError::OutsideNamespace {
                path: path.clone(),
                kind: kind.as_str(),
            });
        }
    }

    // Step 8: the payload entry set and the `hashes` key set must be identical,
    // and every entry's SHA-256 must match.
    let declared: BTreeSet<&String> = index.hashes.keys().collect();
    for path in entries.keys() {
        if !declared.contains(path) {
            return Err(TrustPackError::UnhashedEntry { path: path.clone() });
        }
    }
    for path in &declared {
        if !entries.contains_key(*path) {
            return Err(TrustPackError::HashWithoutEntry {
                path: (*path).clone(),
            });
        }
    }
    for (path, bytes) in &entries {
        let declared = &index.hashes[path];
        if !is_well_formed_hash(declared) {
            return Err(TrustPackError::MalformedHash {
                path: path.clone(),
                value: declared.clone(),
            });
        }
        let actual = sha256_hex(bytes);
        if &actual != declared {
            return Err(TrustPackError::HashMismatch {
                path: path.clone(),
                declared: declared.clone(),
                actual,
            });
        }
    }

    // Step 9: structural rules the kind imposes on its entries. Parsing each
    // entry into its declared format happens in the converting module, which
    // is where the selection inputs live.
    if kind == TrustPackKind::WorkloadTrust {
        if !entries.contains_key("payload/workload-spec.json") {
            return Err(TrustPackError::MissingEntry {
                path: "payload/workload-spec.json".to_string(),
            });
        }
        check_measurement_pack_triples(entries.keys().map(String::as_str))?;
    }

    Ok(TrustPack {
        index,
        kind,
        digest,
        publisher_key: options.publisher_key.clone(),
        payload: entries,
    })
}

/// `sha256:` followed by exactly 64 lowercase hexadecimal characters.
///
/// Checked rather than assumed because a `hashes` value that is merely
/// unparseable must be a rejection, not a comparison that happens to fail with
/// a confusing message.
fn is_well_formed_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decompress with a hard ceiling, so a decompression bomb is refused rather
/// than absorbed.
fn decompress(archive: &[u8], limits: &ArchiveLimits) -> Result<Vec<u8>, TrustPackError> {
    if archive.is_empty() {
        return Err(TrustPackError::Archive {
            message: "archive is empty".to_string(),
        });
    }
    decompress_reader(archive, archive.len() as u64, limits)
}

fn decompress_reader(
    reader: impl Read,
    compressed_bytes: u64,
    limits: &ArchiveLimits,
) -> Result<Vec<u8>, TrustPackError> {
    if compressed_bytes == 0 {
        return Err(TrustPackError::Archive {
            message: "archive is empty".to_string(),
        });
    }
    let mut decoder =
        zstd::stream::Decoder::new(reader).map_err(|error| TrustPackError::Archive {
            message: format!("not a zstd stream: {error}"),
        })?;
    let mut out = Vec::new();
    // One byte past the limit is read deliberately: reading exactly the limit
    // cannot distinguish "fits" from "was truncated at the boundary".
    decoder
        .by_ref()
        .take(limits.max_total_bytes.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|error| TrustPackError::Archive {
            message: format!("zstd decompression failed: {error}"),
        })?;
    if out.len() as u64 > limits.max_total_bytes {
        return Err(TrustPackError::LimitExceeded {
            limit: "total decompressed size",
            allowed: limits.max_total_bytes,
            actual: out.len() as u64,
        });
    }
    let ratio = out.len() as u64 / compressed_bytes.max(1);
    if ratio > limits.max_compression_ratio {
        return Err(TrustPackError::LimitExceeded {
            limit: "compression ratio",
            allowed: limits.max_compression_ratio,
            actual: ratio,
        });
    }
    Ok(out)
}

/// Read tar entries, rejecting anything that is not a plain file at a plain
/// relative path.
///
/// Symbolic and hard links, devices, FIFOs, sockets, directories, absolute
/// paths, traversal, and duplicates are all refused. A duplicate path is
/// refused rather than last-wins because the index hashes a path once, so two
/// entries at one path would leave which bytes were signed undefined.
fn read_tar_entries(
    tar: &[u8],
    limits: &ArchiveLimits,
) -> Result<BTreeMap<String, Vec<u8>>, TrustPackError> {
    let mut archive = tar::Archive::new(tar);
    let mut entries = BTreeMap::new();
    let iterator = archive.entries().map_err(|error| TrustPackError::Archive {
        message: format!("not a tar archive: {error}"),
    })?;

    for entry in iterator {
        let mut entry = entry.map_err(|error| TrustPackError::Archive {
            message: format!("read tar entry: {error}"),
        })?;

        let raw = entry.path_bytes().to_vec();
        let path = String::from_utf8(raw).map_err(|_| TrustPackError::UnacceptableEntry {
            path: "<non-UTF-8>".to_string(),
            kind: "a non-UTF-8 path".to_string(),
        })?;

        let entry_type = entry.header().entry_type();
        if !matches!(entry_type, tar::EntryType::Regular) {
            return Err(TrustPackError::UnacceptableEntry {
                path,
                kind: describe_entry_type(entry_type),
            });
        }
        if let Some(kind) = unacceptable_path(&path) {
            return Err(TrustPackError::UnacceptableEntry { path, kind });
        }
        if entries.len() >= limits.max_entries {
            return Err(TrustPackError::LimitExceeded {
                limit: "entry count",
                allowed: limits.max_entries as u64,
                actual: (entries.len() + 1) as u64,
            });
        }

        let declared = entry
            .header()
            .size()
            .map_err(|error| TrustPackError::Archive {
                message: format!("{path}: unreadable size: {error}"),
            })?;
        if declared > limits.max_entry_bytes {
            return Err(TrustPackError::LimitExceeded {
                limit: "single entry size",
                allowed: limits.max_entry_bytes,
                actual: declared,
            });
        }

        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(limits.max_entry_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| TrustPackError::Archive {
                message: format!("{path}: {error}"),
            })?;
        if bytes.len() as u64 > limits.max_entry_bytes {
            return Err(TrustPackError::LimitExceeded {
                limit: "single entry size",
                allowed: limits.max_entry_bytes,
                actual: bytes.len() as u64,
            });
        }

        if entries.insert(path.clone(), bytes).is_some() {
            return Err(TrustPackError::UnacceptableEntry {
                path,
                kind: "a duplicate path".to_string(),
            });
        }
    }

    Ok(entries)
}

fn describe_entry_type(entry_type: tar::EntryType) -> String {
    let name = match entry_type {
        tar::EntryType::Directory => "a directory",
        tar::EntryType::Symlink => "a symbolic link",
        tar::EntryType::Link => "a hard link",
        tar::EntryType::Char => "a character device",
        tar::EntryType::Block => "a block device",
        tar::EntryType::Fifo => "a FIFO",
        tar::EntryType::Continuous => "a continuous entry",
        _ => "not a regular file",
    };
    name.to_string()
}

fn unacceptable_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return Some("an empty path".to_string());
    }
    if path.starts_with('/') {
        return Some("an absolute path".to_string());
    }
    if path.contains('\0') {
        return Some("a path containing a NUL byte".to_string());
    }
    if path.ends_with('/') {
        return Some("a directory path".to_string());
    }
    for segment in path.split('/') {
        match segment {
            "" => return Some("a path with an empty component".to_string()),
            "." | ".." => return Some("a traversing path".to_string()),
            _ => {}
        }
    }
    // A drive-letter or UNC prefix cannot appear in a conforming archive and
    // would be an absolute path on a reader that later joined it onto a
    // directory.
    if path.contains('\\') {
        return Some("a path containing a backslash".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::fixture::{
        certificate_pem, certificate_pem_expiring, collateral_builder, options, round_trip,
        Publisher, EARLY_EXPIRY, NOT_AFTER, NOT_BEFORE,
    };
    use crate::pack::write::TrustPackBuilder;

    /// Build an archive from raw entries, bypassing every rule the builder
    /// enforces.
    ///
    /// The negative tests need archives a conforming producer cannot make. A
    /// reader tested only against its own writer's output is tested against
    /// the writer's assumptions, not against the format.
    use crate::pack::fixture::raw_archive;

    /// The entries of a valid, correctly signed collateral archive.
    ///
    /// Returned unpacked so a test can corrupt exactly one thing and leave
    /// everything else genuinely valid. A test that broke two things at once
    /// could pass for the wrong reason.
    fn signed_entries(publisher: &Publisher) -> Vec<(String, Vec<u8>)> {
        signed_entries_from(&collateral_builder("example-publisher"), publisher)
    }

    fn signed_entries_from(
        builder: &TrustPackBuilder,
        publisher: &Publisher,
    ) -> Vec<(String, Vec<u8>)> {
        let index = builder.index_bytes().expect("index");
        let signature = publisher.sign(&index);
        let mut entries = vec![
            ("trust-pack.json".to_string(), index),
            ("trust-pack.sig".to_string(), signature),
        ];
        entries.extend(
            builder
                .payload()
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.clone())),
        );
        entries
    }

    fn pack_from(entries: Vec<(String, Vec<u8>)>) -> Vec<u8> {
        let raw: Vec<(String, Vec<u8>, tar::EntryType)> = entries
            .into_iter()
            .map(|(path, bytes)| (path, bytes, tar::EntryType::Regular))
            .collect();
        raw_archive(&raw)
    }

    /// Replace the index and re-sign it, so only the property under test is
    /// wrong.
    fn reindex(
        entries: &mut [(String, Vec<u8>)],
        publisher: &Publisher,
        mutate: impl FnOnce(&mut TrustPackIndex),
    ) {
        let mut index: TrustPackIndex = serde_json::from_slice(&entries[0].1).unwrap();
        mutate(&mut index);
        let bytes = serde_json_canonicalizer::to_vec(&index).unwrap();
        entries[0].1 = bytes.clone();
        entries[1].1 = publisher.sign(&bytes);
    }

    #[test]
    fn a_written_pack_reads_back_with_its_payload_and_index_intact() {
        let publisher = Publisher::new(0x11);
        let pack = round_trip(
            &collateral_builder("example-publisher"),
            TrustPackKind::CollateralTrust,
            &publisher,
        )
        .expect("round trip");

        assert_eq!(pack.index.format, TRUST_PACK_FORMAT);
        assert_eq!(pack.index.issuer, "example-publisher");
        assert_eq!(pack.index.revision, 7);
        assert_eq!(pack.kind, TrustPackKind::CollateralTrust);
        assert_eq!(pack.payload.len(), 2);
        assert!(pack.entry("payload/roots/gcp-ak-root.pem").is_ok());
        assert_eq!(pack.index.hashes.len(), pack.payload.len());
    }

    /// The digest a pin names is the SHA-256 of the index bytes, which is what
    /// makes pinning independent of how the archive was produced.
    #[test]
    fn the_digest_is_the_hash_of_the_index_bytes_and_pinning_uses_it() {
        let publisher = Publisher::new(0x11);
        let builder = collateral_builder("example-publisher");
        let index = builder.index_bytes().unwrap();
        let pack = round_trip(&builder, TrustPackKind::CollateralTrust, &publisher).unwrap();
        assert_eq!(pack.digest, crate::pack::write::sha256(&index));

        let archive = builder
            .build(|bytes| Ok::<_, std::convert::Infallible>(publisher.sign(bytes)))
            .unwrap();
        let pinned = options(TrustPackKind::CollateralTrust, &publisher).pinned(pack.digest);
        assert!(read_trust_pack(&archive, &pinned).is_ok());

        let wrong = options(TrustPackKind::CollateralTrust, &publisher).pinned([0xab; 32]);
        let error = read_trust_pack(&archive, &wrong).expect_err("a wrong pin must be refused");
        assert!(
            matches!(error, TrustPackError::PinMismatch { .. }),
            "got {error}"
        );
    }

    /// `not_after` is derived, not declared: a pack cannot outlive its
    /// shortest-lived content.
    #[test]
    fn the_validity_window_shortens_to_the_earliest_expiry_inside() {
        let publisher = Publisher::new(0x11);
        let mut builder = collateral_builder("example-publisher");
        builder
            .insert(
                "payload/azure-maa/sharedeus.pem",
                certificate_pem_expiring("maa", 2026, 9, 1),
            )
            .unwrap();

        let pack = round_trip(&builder, TrustPackKind::CollateralTrust, &publisher).unwrap();
        assert_eq!(
            pack.index.not_after, EARLY_EXPIRY,
            "the MAA certificate expires before the requested window ends, so it must win"
        );
        assert!(pack.index.not_after < NOT_AFTER);

        // Without that certificate the requested value stands, so the
        // assertion above is about derivation rather than about the fixture
        // always producing this number.
        let plain = round_trip(
            &collateral_builder("example-publisher"),
            TrustPackKind::CollateralTrust,
            &publisher,
        )
        .unwrap();
        assert_eq!(plain.index.not_after, NOT_AFTER);
    }

    /// A pack cannot select which configured key verifies it. Presenting a
    /// collateral pack where a workload pack is required is refused as the
    /// wrong role, not reported as a signature failure.
    #[test]
    fn a_pack_cannot_be_read_as_the_other_kind() {
        let publisher = Publisher::new(0x11);
        let archive = collateral_builder("example-publisher")
            .build(|bytes| Ok::<_, std::convert::Infallible>(publisher.sign(bytes)))
            .unwrap();

        let error = read_trust_pack(&archive, &options(TrustPackKind::WorkloadTrust, &publisher))
            .expect_err("a collateral pack must not satisfy a workload-trust requirement");
        assert!(
            matches!(error, TrustPackError::KindMismatch { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_signature_from_another_publisher_is_refused() {
        let publisher = Publisher::new(0x11);
        let impostor = Publisher::new(0x22);
        let archive = collateral_builder("example-publisher")
            .build(|bytes| Ok::<_, std::convert::Infallible>(impostor.sign(bytes)))
            .unwrap();

        let error = read_trust_pack(
            &archive,
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("another publisher's signature must not verify");
        assert!(
            matches!(error, TrustPackError::Signature { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_pack_outside_its_validity_window_is_refused_at_both_ends() {
        let publisher = Publisher::new(0x11);
        let archive = collateral_builder("example-publisher")
            .build(|bytes| Ok::<_, std::convert::Infallible>(publisher.sign(bytes)))
            .unwrap();

        for (now, why) in [
            (NOT_BEFORE - 1, "before not_before"),
            // The window is half-open, so not_after itself is already outside.
            (NOT_AFTER, "at not_after"),
        ] {
            let mut read = options(TrustPackKind::CollateralTrust, &publisher);
            read.now_unix = now;
            let Err(error) = read_trust_pack(&archive, &read) else {
                panic!("a pack must be refused {why}");
            };
            assert!(
                matches!(error, TrustPackError::OutsideValidity { .. }),
                "{why}: got {error}"
            );
        }

        // The boundaries that must still be accepted, so the two rejections
        // above are about the window rather than about rejecting everything.
        for now in [NOT_BEFORE, NOT_AFTER - 1] {
            let mut read = options(TrustPackKind::CollateralTrust, &publisher);
            read.now_unix = now;
            assert!(read_trust_pack(&archive, &read).is_ok(), "{now} is inside");
        }
    }

    #[test]
    fn a_namespace_violation_rejects_the_whole_pack() {
        let publisher = Publisher::new(0x11);
        let mut entries = signed_entries(&publisher);
        // A workload-trust path inside a collateral-trust pack: the rule that
        // stops one role's key becoming another role's authority.
        entries.push(("payload/workload-spec.json".to_string(), b"{}".to_vec()));
        let error = read_trust_pack(
            &pack_from(entries),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("a foreign path must reject the pack");
        assert!(
            matches!(error, TrustPackError::OutsideNamespace { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_payload_entry_whose_bytes_changed_is_refused() {
        let publisher = Publisher::new(0x11);
        let mut entries = signed_entries(&publisher);
        for entry in &mut entries {
            if entry.0 == "payload/roots/gcp-ak-root.pem" {
                entry.1 = certificate_pem("substituted");
            }
        }
        let error = read_trust_pack(
            &pack_from(entries),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("a substituted payload entry must be refused");
        assert!(
            matches!(error, TrustPackError::HashMismatch { .. }),
            "got {error}"
        );
    }

    /// The entry set and the hash key set must be identical in both
    /// directions. An extra entry is unsigned content; a missing one is a
    /// hash covering nothing.
    #[test]
    fn the_entry_set_and_the_hash_set_must_match_in_both_directions() {
        let publisher = Publisher::new(0x11);

        let mut extra = signed_entries(&publisher);
        extra.push((
            "payload/amd-snp-crl/extra.der".to_string(),
            vec![0x30, 0x00],
        ));
        let error = read_trust_pack(
            &pack_from(extra),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("an unhashed entry must be refused");
        assert!(
            matches!(error, TrustPackError::UnhashedEntry { .. }),
            "got {error}"
        );

        let missing: Vec<(String, Vec<u8>)> = signed_entries(&publisher)
            .into_iter()
            .filter(|(path, _)| path != "payload/roots/gcp-ak-root.pem")
            .collect();
        let error = read_trust_pack(
            &pack_from(missing),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("a hash without its entry must be refused");
        assert!(
            matches!(error, TrustPackError::HashWithoutEntry { .. }),
            "got {error}"
        );
    }

    /// Canonical form is checked before the signature. Without that ordering a
    /// producer could ship non-canonical bytes that still verify, and two
    /// byte-different archives carrying identical content would pin to two
    /// different digests.
    #[test]
    fn a_non_canonical_index_is_refused_and_is_refused_before_the_signature() {
        let publisher = Publisher::new(0x11);
        let mut entries = signed_entries(&publisher);
        let canonical = entries[0].1.clone();
        // Same parsed value, different bytes: re-serialised with serde_json,
        // which writes struct order rather than sorted keys.
        let value: TrustPackIndex = serde_json::from_slice(&canonical).unwrap();
        let non_canonical = serde_json::to_vec(&value).unwrap();
        assert_ne!(non_canonical, canonical, "the fixture must differ in bytes");
        entries[0].1 = non_canonical.clone();
        // Signed correctly over the non-canonical bytes, so only the canonical
        // rule can reject this.
        entries[1].1 = publisher.sign(&non_canonical);

        let error = read_trust_pack(
            &pack_from(entries),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("non-canonical index bytes must be refused");
        assert!(
            matches!(error, TrustPackError::NonCanonicalIndex),
            "a validly signed non-canonical index must fail the canonical check, got {error}"
        );
    }

    /// An unknown field is refused rather than ignored, and it is refused as
    /// an unknown field: a mutation that produced a duplicate key would also
    /// fail to parse, and would make this test pass without the
    /// `deny_unknown_fields` rule it is here to cover.
    #[test]
    fn an_unknown_index_field_is_refused() {
        let publisher = Publisher::new(0x11);
        let mut entries = signed_entries(&publisher);

        let mut value: serde_json::Value = serde_json::from_slice(&entries[0].1).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        entries[0].1 = bytes.clone();
        entries[1].1 = publisher.sign(&bytes);

        let error = read_trust_pack(
            &pack_from(entries),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("an unknown index field must be refused");
        let TrustPackError::Index { message } = &error else {
            panic!("got {error}");
        };
        assert!(
            message.contains("unexpected"),
            "the failure must name the field; got {message}"
        );
    }

    /// There is no migration path, so any other format is refused outright
    /// rather than read on a best-effort basis.
    #[test]
    fn any_format_other_than_one_is_refused() {
        let publisher = Publisher::new(0x11);
        for format in [0, 2, 99] {
            let mut entries = signed_entries(&publisher);
            reindex(&mut entries, &publisher, |index| index.format = format);

            let error = read_trust_pack(
                &pack_from(entries),
                &options(TrustPackKind::CollateralTrust, &publisher),
            )
            .expect_err("an unsupported format must be refused");
            assert!(
                matches!(error, TrustPackError::UnsupportedFormat { found } if found == format),
                "got {error}"
            );
        }
    }

    /// `kind` selects the payload namespace and the required publisher key, so
    /// an unrecognised value cannot be treated as a pack of some default kind.
    #[test]
    fn an_unknown_kind_is_refused() {
        let publisher = Publisher::new(0x11);
        let mut entries = signed_entries(&publisher);
        reindex(&mut entries, &publisher, |index| {
            index.kind = "root-trust".to_string()
        });

        let error = read_trust_pack(
            &pack_from(entries),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("an unknown kind must be refused");
        assert!(
            matches!(error, TrustPackError::UnknownKind { .. }),
            "got {error}"
        );
    }

    #[test]
    fn traversing_absolute_and_duplicate_paths_are_refused() {
        let publisher = Publisher::new(0x11);

        for path in [
            "../escape.json",
            "/etc/passwd",
            "payload/roots/../../escape.pem",
            "./payload/roots/gcp-ak-root.pem",
        ] {
            let mut entries = signed_entries(&publisher);
            entries.push((path.to_string(), b"x".to_vec()));
            let Err(error) = read_trust_pack(
                &pack_from(entries),
                &options(TrustPackKind::CollateralTrust, &publisher),
            ) else {
                panic!("{path} must be refused");
            };
            assert!(
                matches!(error, TrustPackError::UnacceptableEntry { .. }),
                "{path}: got {error}"
            );
        }
    }

    /// A duplicate path leaves which bytes the index signed undefined, so it
    /// is refused rather than resolved last-wins.
    #[test]
    fn a_duplicate_path_is_refused_rather_than_resolved() {
        let publisher = Publisher::new(0x11);
        let mut entries = signed_entries(&publisher);
        entries.push((
            "payload/roots/gcp-ak-root.pem".to_string(),
            certificate_pem("second"),
        ));
        let error = read_trust_pack(
            &pack_from(entries),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("a duplicate path must be refused");
        assert!(
            matches!(error, TrustPackError::UnacceptableEntry { .. }),
            "got {error}"
        );
    }

    #[test]
    fn only_regular_files_are_accepted() {
        let publisher = Publisher::new(0x11);
        for entry_type in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Directory,
            tar::EntryType::Fifo,
            tar::EntryType::Char,
        ] {
            let mut raw: Vec<(String, Vec<u8>, tar::EntryType)> = signed_entries(&publisher)
                .into_iter()
                .map(|(path, bytes)| (path, bytes, tar::EntryType::Regular))
                .collect();
            raw.push(("payload/roots/link.pem".to_string(), Vec::new(), entry_type));

            let Err(error) = read_trust_pack(
                &raw_archive(&raw),
                &options(TrustPackKind::CollateralTrust, &publisher),
            ) else {
                panic!("{entry_type:?} must be refused");
            };
            assert!(
                matches!(error, TrustPackError::UnacceptableEntry { .. }),
                "{entry_type:?}: got {error}"
            );
        }
    }

    #[test]
    fn a_missing_index_or_signature_is_refused() {
        let publisher = Publisher::new(0x11);
        for dropped in ["trust-pack.json", "trust-pack.sig"] {
            let entries: Vec<(String, Vec<u8>)> = signed_entries(&publisher)
                .into_iter()
                .filter(|(path, _)| path != dropped)
                .collect();
            let error = read_trust_pack(
                &pack_from(entries),
                &options(TrustPackKind::CollateralTrust, &publisher),
            )
            .expect_err("a pack without its index or signature must be refused");
            assert!(
                matches!(&error, TrustPackError::MissingEntry { path } if path == dropped),
                "got {error}"
            );
        }
    }

    /// A decompression bomb is refused rather than absorbed. Both the total
    /// size and the ratio bound are exercised, because a payload can breach
    /// one without the other.
    #[test]
    fn decompression_bounds_reject_rather_than_truncate() {
        let publisher = Publisher::new(0x11);
        let mut entries = signed_entries(&publisher);
        entries.push((
            "payload/amd-snp-crl/bomb.der".to_string(),
            vec![0u8; 1024 * 1024],
        ));
        let archive = pack_from(entries);

        let mut small_total = options(TrustPackKind::CollateralTrust, &publisher);
        small_total.limits.max_total_bytes = 64 * 1024;
        let error = read_trust_pack(&archive, &small_total).expect_err("total size must bound");
        assert!(
            matches!(
                error,
                TrustPackError::LimitExceeded {
                    limit: "total decompressed size",
                    ..
                }
            ),
            "got {error}"
        );

        let error = read_trust_pack(
            &archive,
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("a megabyte of zeros exceeds the 100:1 ratio bound");
        assert!(
            matches!(
                error,
                TrustPackError::LimitExceeded {
                    limit: "compression ratio",
                    ..
                }
            ),
            "got {error}"
        );
    }

    #[test]
    fn file_reader_enforces_the_decompression_bound_while_streaming() {
        let publisher = Publisher::new(0x11);
        let archive = pack_from(signed_entries(&publisher));
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("pack.atatp");
        std::fs::write(&path, archive).expect("write pack");
        let mut read = options(TrustPackKind::CollateralTrust, &publisher);
        read.limits.max_total_bytes = 512;

        let error = read_trust_pack_file(&path, &read)
            .expect_err("the file reader must stop after the decompression bound");
        assert!(
            matches!(
                error,
                TrustPackError::LimitExceeded {
                    limit: "total decompressed size",
                    ..
                }
            ),
            "got {error}"
        );
    }

    #[test]
    fn the_entry_count_bound_rejects() {
        let publisher = Publisher::new(0x11);
        let mut read = options(TrustPackKind::CollateralTrust, &publisher);
        read.limits.max_entries = 2;
        let archive = pack_from(signed_entries(&publisher));
        let error = read_trust_pack(&archive, &read).expect_err("four entries exceed a bound of 2");
        assert!(
            matches!(
                error,
                TrustPackError::LimitExceeded {
                    limit: "entry count",
                    ..
                }
            ),
            "got {error}"
        );
    }

    #[test]
    fn a_malformed_hash_value_is_refused_rather_than_compared() {
        let publisher = Publisher::new(0x11);
        let mut entries = signed_entries(&publisher);
        reindex(&mut entries, &publisher, |index| {
            index.hashes.insert(
                "payload/roots/gcp-ak-root.pem".to_string(),
                "SHA256:NOTHEX".to_string(),
            );
        });

        let error = read_trust_pack(
            &pack_from(entries),
            &options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect_err("a malformed hash must be refused");
        assert!(
            matches!(error, TrustPackError::MalformedHash { .. }),
            "got {error}"
        );
    }

    /// A pack validated at read time must not keep answering forever. A
    /// daemon loads packs once and runs, so expiry has to bound each
    /// verification rather than the process.
    #[test]
    fn a_read_pack_re_checks_its_validity_window() {
        let publisher = Publisher::new(0x11);
        let pack = round_trip(
            &collateral_builder("example-publisher"),
            TrustPackKind::CollateralTrust,
            &publisher,
        )
        .expect("round trip");

        assert!(pack.ensure_valid_at(NOT_BEFORE).is_ok());
        assert!(pack.ensure_valid_at(NOT_AFTER - 1).is_ok());
        for outside in [NOT_BEFORE - 1, NOT_AFTER] {
            let error = pack
                .ensure_valid_at(outside)
                .expect_err("a pack held past its window must stop being usable");
            assert!(
                matches!(error, TrustPackError::OutsideValidity { .. }),
                "got {error}"
            );
        }
    }

    /// The writer enforces the bounds the reader enforces. An archive this
    /// crate produces and its own reader refuses would turn a producer-side
    /// mistake into a failure discovered at the verifier.
    #[test]
    fn the_writer_refuses_what_the_reader_would_refuse() {
        let publisher = Publisher::new(0x11);
        // A root entry, because the writer does not parse those for an expiry.
        // The bounds are about bytes, so the content only has to be large and
        // compressible.
        let mut builder = collateral_builder("example-publisher");
        builder
            .insert("payload/roots/amd-ark-bomb.pem", vec![0x41; 1024 * 1024])
            .expect("within the per-entry bound");

        let error = builder
            .build(|bytes| Ok::<_, std::convert::Infallible>(publisher.sign(bytes)))
            .expect_err("a megabyte of one repeated byte exceeds the 100:1 ratio bound");
        assert!(
            matches!(
                error,
                TrustPackError::LimitExceeded {
                    limit: "compression ratio",
                    ..
                }
            ),
            "got {error}"
        );

        let mut small = collateral_builder("example-publisher").with_limits(ArchiveLimits {
            max_total_bytes: 4096,
            ..ArchiveLimits::default()
        });
        small
            .insert("payload/roots/amd-ark-big.pem", vec![0x41; 8192])
            .expect("within the per-entry bound");
        let error = small
            .build(|bytes| Ok::<_, std::convert::Infallible>(publisher.sign(bytes)))
            .expect_err("the total decompressed bound must apply to the writer too");
        assert!(
            matches!(
                error,
                TrustPackError::LimitExceeded {
                    limit: "total decompressed size",
                    ..
                }
            ),
            "got {error}"
        );
    }

    #[test]
    fn an_empty_or_non_zstd_archive_is_refused() {
        let publisher = Publisher::new(0x11);
        for bytes in [Vec::new(), b"not a zstd stream".to_vec()] {
            let error =
                read_trust_pack(&bytes, &options(TrustPackKind::CollateralTrust, &publisher))
                    .expect_err("a non-archive must be refused");
            assert!(
                matches!(error, TrustPackError::Archive { .. }),
                "got {error}"
            );
        }
    }
}
