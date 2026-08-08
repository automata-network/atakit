use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::WorkloadError;

/// Format of `meta.json` in the local workload store.
///
/// The older PCR policy cache used unversioned `verify_type` and
/// `match_data` fields. Format 1 starts with the opaque `comparison` field.
/// Format 2 keys entries by publisher-qualified workload identifier and
/// records the publisher. Format 1 metadata cannot be upgraded in place — the
/// identifier itself changed — so it is reported as unsupported rather than
/// silently reinterpreted.
pub const WORKLOAD_META_FORMAT_VERSION: u32 = 2;

/// Check that a workload identifier is the machine-generated form.
///
/// Entries are keyed by identifier rather than by name and version. The
/// identifier is `0x` followed by 64 lowercase hexadecimal characters, so it is
/// path-safe by construction: there is nothing to escape, no `.`, `..`, or
/// separator to neutralise, and no encoding to keep reversible. It is also
/// publisher-qualified, so two publishers holding the same name and version get
/// separate entries instead of colliding.
///
/// Rejecting here is safe in a way that rejecting a *name* was not: this value
/// is derived, never typed by an operator, so a legitimate published workload
/// can never fail to map to a path.
fn validate_workload_id(workload_id: &str) -> Result<(), WorkloadError> {
    if !atakit_core::is_canonical_id(workload_id) {
        return Err(WorkloadError::StorePathTraversal {
            path: PathBuf::from(format!("workload id: {workload_id}")),
        });
    }
    Ok(())
}

/// Cached on-chain workload spec data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedChainSpec {
    /// Renamed from `ttl` in an earlier schema. The alias keeps pre-rename
    /// `meta.json` files loadable so `workload ls` doesn't error out on an
    /// older local cache.
    #[serde(alias = "ttl")]
    pub session_ttl: u64,
    pub base_image_mode: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_image_ids: Vec<String>,
    pub pcrs: Vec<CachedPcrSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPcrSpec {
    pub pcr_index: u8,
    pub comparison: String,
}

/// Per-workload metadata stored as `meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadMeta {
    #[serde(default = "current_workload_meta_format")]
    pub metadata_format: u32,
    pub workload_id: String,
    /// Owner fingerprint of the publisher, as `0x` plus 64 lowercase hex.
    /// Required: the identifier is derived from it, so an entry without one
    /// could not have produced its own key.
    pub publisher: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr23: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_chain_spec: Option<CachedChainSpec>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub revoked: bool,
    /// Repository URIs this archive has been pulled from or pushed to.
    /// HTTP repos use `https://...`; github repos use `github://owner/repo`.
    /// `#[serde(alias = "registries")]` keeps existing `meta.json` files
    /// loadable after the rename.
    #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "registries")]
    pub repositories: Vec<String>,
    pub added_at: String,
}

fn current_workload_meta_format() -> u32 {
    WORKLOAD_META_FORMAT_VERSION
}

fn is_false(b: &bool) -> bool {
    !b
}

/// A rebuildable lookup from publisher-qualified reference to identifier.
///
/// Entries are keyed on disk by identifier, which answers "give me this exact
/// workload" directly but not "what do I have" or "which identifier is
/// `automata/app:v1`". The index answers those without opening every entry.
///
/// It is a cache, not the source of truth. Each entry's `meta.json` remains
/// authoritative, and a missing, unreadable, or stale index is rebuilt by
/// scanning rather than being an error — so losing it costs time, never data.
#[derive(Debug, Default, Serialize, Deserialize)]
struct WorkloadIndex {
    #[serde(default)]
    entries: BTreeMap<String, IndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexEntry {
    publisher: String,
    name: String,
    version: String,
}

/// A workload entry with computed local state.
pub struct WorkloadEntry {
    pub meta: WorkloadMeta,
    pub has_blob: bool,
}

/// Local workload store at `~/.local/share/atakit/workloads/`.
///
/// Layout: `base_dir/<name>/<version>/meta.json` + `archive.atawl`
pub struct WorkloadStore {
    base_dir: PathBuf,
}

impl WorkloadStore {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            base_dir: base_dir.to_path_buf(),
        }
    }

    // ── Paths ──────────────────────────────────────────

    fn entry_dir(&self, workload_id: &str) -> Result<PathBuf, WorkloadError> {
        validate_workload_id(workload_id)?;

        // Canonicalize base_dir for containment checks (must exist).
        let canon_base = if self.base_dir.exists() {
            Some(
                self.base_dir
                    .canonicalize()
                    .map_err(|e| WorkloadError::ReadStoreDir {
                        path: self.base_dir.clone(),
                        reason: e.to_string(),
                    })?,
            )
        } else {
            None
        };

        // Containment stays as defence in depth: a symlink planted at the
        // entry directory could still redirect writes outside the store.
        let path = self.base_dir.join(workload_id);
        if let Some(ref canon_base) = canon_base {
            if path.exists() {
                let canon = path
                    .canonicalize()
                    .map_err(|e| WorkloadError::ReadStoreDir {
                        path: path.clone(),
                        reason: e.to_string(),
                    })?;
                if !canon.starts_with(canon_base) {
                    return Err(WorkloadError::StorePathTraversal { path });
                }
            }
        }

        Ok(path)
    }

    pub fn meta_path(&self, workload_id: &str) -> Result<PathBuf, WorkloadError> {
        Ok(self.entry_dir(workload_id)?.join("meta.json"))
    }

    pub fn blob_path(&self, workload_id: &str) -> Result<PathBuf, WorkloadError> {
        Ok(self.entry_dir(workload_id)?.join("archive.atawl"))
    }

    fn index_path(&self) -> PathBuf {
        self.base_dir.join("index.json")
    }

    /// Read the index, rebuilding it from a scan when it is absent or
    /// unreadable. The index is a cache; failing to read it must never fail an
    /// operation the entries themselves can satisfy.
    fn read_index(&self) -> Result<WorkloadIndex, WorkloadError> {
        let path = self.index_path();
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(index) = serde_json::from_slice::<WorkloadIndex>(&bytes) {
                return Ok(index);
            }
        }
        self.rebuild_index()
    }

    /// Rebuild the index by scanning entries and reading their metadata.
    fn rebuild_index(&self) -> Result<WorkloadIndex, WorkloadError> {
        let mut index = WorkloadIndex::default();
        for entry in self.scan_entries()? {
            index.entries.insert(
                entry.meta.workload_id.clone(),
                IndexEntry {
                    publisher: entry.meta.publisher.clone(),
                    name: entry.meta.name.clone(),
                    version: entry.meta.version.clone(),
                },
            );
        }
        self.write_index(&index)?;
        Ok(index)
    }

    fn write_index(&self, index: &WorkloadIndex) -> Result<(), WorkloadError> {
        if !self.base_dir.exists() {
            return Ok(());
        }
        let encoded =
            serde_json::to_vec_pretty(index).map_err(|e| WorkloadError::ReadStoreDir {
                path: self.index_path(),
                reason: e.to_string(),
            })?;
        fs::write(self.index_path(), encoded).map_err(|e| WorkloadError::ReadStoreDir {
            path: self.index_path(),
            reason: e.to_string(),
        })
    }

    /// Read every entry directly, ignoring the index. This is the authority.
    fn scan_entries(&self) -> Result<Vec<WorkloadEntry>, WorkloadError> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        let dirs = fs::read_dir(&self.base_dir).map_err(|e| WorkloadError::ReadStoreDir {
            path: self.base_dir.clone(),
            reason: e.to_string(),
        })?;
        for dir in dirs {
            let dir = dir.map_err(|e| WorkloadError::ReadStoreDir {
                path: self.base_dir.clone(),
                reason: e.to_string(),
            })?;
            if !dir.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let entry_path = dir.path();
            let meta_path = entry_path.join("meta.json");
            if !meta_path.exists() {
                continue;
            }
            let meta = self.read_meta(&meta_path)?;
            let has_blob = entry_path.join("archive.atawl").exists();
            entries.push(WorkloadEntry { meta, has_blob });
        }
        entries.sort_by(|a, b| {
            a.meta
                .name
                .cmp(&b.meta.name)
                .then_with(|| a.meta.version.cmp(&b.meta.version))
        });
        Ok(entries)
    }

    pub fn list(&self) -> Result<Vec<WorkloadEntry>, WorkloadError> {
        self.scan_entries()
    }

    /// Get a specific workload entry by identifier.
    pub fn get(&self, workload_id: &str) -> Result<Option<WorkloadEntry>, WorkloadError> {
        let meta_path = self.meta_path(workload_id)?;
        if !meta_path.exists() {
            return Ok(None);
        }
        let meta = self.read_meta(&meta_path)?;
        let has_blob = self.blob_path(workload_id)?.exists();
        Ok(Some(WorkloadEntry { meta, has_blob }))
    }

    /// Identifiers matching a name and version, across all publishers.
    ///
    /// Returns every match rather than one: with publisher-qualified
    /// identifiers a bare name and version is genuinely ambiguous, and hiding
    /// that by picking one would resolve to an arbitrary publisher.
    pub fn resolve(&self, name: &str, version: &str) -> Result<Vec<String>, WorkloadError> {
        let index = self.read_index()?;
        let mut matches: Vec<String> = index
            .entries
            .iter()
            .filter(|(_, entry)| entry.name == name && entry.version == version)
            .map(|(id, _)| id.clone())
            .collect();
        matches.sort();
        Ok(matches)
    }

    /// Load metadata for a workload, if it exists.
    pub fn load_meta(&self, workload_id: &str) -> Result<Option<WorkloadMeta>, WorkloadError> {
        let path = self.meta_path(workload_id)?;
        if !path.exists() {
            return Ok(None);
        }
        self.read_meta(&path).map(Some)
    }

    // ── Write ──────────────────────────────────────────

    /// Save metadata for a workload. Creates directories as needed.
    /// Uses temp-file + atomic rename to prevent corruption and symlink following.
    pub fn save_meta(&self, meta: &WorkloadMeta) -> Result<(), WorkloadError> {
        let dir = self.entry_dir(&meta.workload_id)?;
        fs::create_dir_all(&dir).map_err(|e| WorkloadError::CreateDir {
            path: dir.clone(),
            source: e,
        })?;

        let json =
            serde_json::to_string_pretty(meta).map_err(|e| WorkloadError::Json(e.to_string()))?;
        let meta_path = dir.join("meta.json");
        let tmp_path = dir.join("meta.json.tmp");
        fs::write(&tmp_path, json).map_err(|e| WorkloadError::WriteFile {
            path: tmp_path.clone(),
            source: e,
        })?;
        fs::rename(&tmp_path, &meta_path).map_err(|e| WorkloadError::WriteFile {
            path: meta_path,
            source: e,
        })?;

        // Keep the index current. It is a cache, so a failure here would be
        // recoverable by a rebuild, but writing it now keeps lookups cheap.
        let mut index = self.read_index()?;
        index.entries.insert(
            meta.workload_id.clone(),
            IndexEntry {
                publisher: meta.publisher.clone(),
                name: meta.name.clone(),
                version: meta.version.clone(),
            },
        );
        self.write_index(&index)?;

        Ok(())
    }

    /// Copy an archive file into the store. Returns the file size.
    /// Uses temp-file + atomic rename to prevent corruption and symlink following.
    pub fn import_blob(&self, workload_id: &str, src: &Path) -> Result<u64, WorkloadError> {
        let dir = self.entry_dir(workload_id)?;
        fs::create_dir_all(&dir).map_err(|e| WorkloadError::CreateDir {
            path: dir.clone(),
            source: e,
        })?;

        let tmp = dir.join("archive.atawl.tmp");
        let dest = dir.join("archive.atawl");
        let size = fs::copy(src, &tmp).map_err(|e| WorkloadError::CopyFile {
            from: src.to_path_buf(),
            to: tmp.clone(),
            source: e,
        })?;
        fs::rename(&tmp, &dest).map_err(|e| WorkloadError::WriteFile {
            path: dest,
            source: e,
        })?;
        Ok(size)
    }

    /// Write raw bytes as an archive blob (for pull).
    /// Uses temp-file + atomic rename to prevent corruption and symlink following.
    pub fn save_blob(&self, workload_id: &str, data: &[u8]) -> Result<(), WorkloadError> {
        let dir = self.entry_dir(workload_id)?;
        fs::create_dir_all(&dir).map_err(|e| WorkloadError::CreateDir {
            path: dir.clone(),
            source: e,
        })?;

        let tmp = dir.join("archive.atawl.tmp");
        let dest = dir.join("archive.atawl");
        fs::write(&tmp, data).map_err(|e| WorkloadError::WriteFile {
            path: tmp.clone(),
            source: e,
        })?;
        fs::rename(&tmp, &dest).map_err(|e| WorkloadError::WriteFile {
            path: dest,
            source: e,
        })?;

        Ok(())
    }

    // ── Delete ─────────────────────────────────────────

    /// Remove an entire workload entry (metadata + blob) and its index row.
    pub fn remove(&self, workload_id: &str) -> Result<(), WorkloadError> {
        let dir = self.entry_dir(workload_id)?;
        if !dir.exists() {
            return Err(WorkloadError::StoreNotFound {
                workload_id: workload_id.to_string(),
            });
        }

        fs::remove_dir_all(&dir).map_err(WorkloadError::from)?;

        // The layout is flat, so there is no parent directory to tidy up.
        let mut index = self.read_index()?;
        index.entries.remove(workload_id);
        self.write_index(&index)?;

        Ok(())
    }

    /// Remove only the archive blob, keeping metadata.
    pub fn remove_blob(&self, workload_id: &str) -> Result<(), WorkloadError> {
        let blob = self.blob_path(workload_id)?;
        if !blob.exists() {
            return Err(WorkloadError::NoBlobInStore {
                workload_id: workload_id.to_string(),
            });
        }
        fs::remove_file(&blob).map_err(WorkloadError::from)?;
        Ok(())
    }

    // ── Query ──────────────────────────────────────────

    pub fn has_blob(&self, workload_id: &str) -> bool {
        self.blob_path(workload_id)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    pub fn exists(&self, workload_id: &str) -> bool {
        self.meta_path(workload_id)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    // ── Internal ───────────────────────────────────────

    fn read_meta(&self, path: &Path) -> Result<WorkloadMeta, WorkloadError> {
        let content = fs::read_to_string(path).map_err(|e| WorkloadError::ReadFile {
            path: path.to_path_buf(),
            source: e,
        })?;
        let value: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| WorkloadError::ParseMeta {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
        self.validate_meta_format(path, &value)?;
        serde_json::from_value(value).map_err(|e| WorkloadError::ParseMeta {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
    }

    fn validate_meta_format(
        &self,
        path: &Path,
        value: &serde_json::Value,
    ) -> Result<(), WorkloadError> {
        let declared_format = value.get("metadata_format");
        if let Some(format_value) = declared_format {
            let Some(format) = format_value.as_u64() else {
                return Err(
                    self.unsupported_meta(path, "metadata_format is not an integer".to_string())
                );
            };
            if format == u64::from(WORKLOAD_META_FORMAT_VERSION) {
                return Ok(());
            }
            if format > u64::from(WORKLOAD_META_FORMAT_VERSION) {
                return Err(WorkloadError::UnsupportedMeta {
                    path: path.to_path_buf(),
                    reason: format!(
                        "metadata format {format} is newer than supported format {}",
                        WORKLOAD_META_FORMAT_VERSION
                    ),
                    recovery: format!(
                        "upgrade atakit to a version that supports local workload metadata format {format}"
                    ),
                });
            }
            return Err(self.unsupported_meta(
                path,
                format!(
                    "metadata format {format} is older than supported format {}",
                    WORKLOAD_META_FORMAT_VERSION
                ),
            ));
        }

        if uses_retired_pcr_rule_fields(value) {
            return Err(self.unsupported_meta(
                path,
                "the unversioned metadata uses the retired verify_type and match_data PCR-rule fields"
                    .to_string(),
            ));
        }

        // Unversioned metadata was briefly written by the opaque-comparison
        // implementation. It predates publisher-qualified identifiers, so it
        // cannot be accepted: the publisher is required and is not derivable
        // from a name and version.
        Err(self.unsupported_meta(
            path,
            "the unversioned metadata predates publisher-qualified workload identifiers"
                .to_string(),
        ))
    }

    fn unsupported_meta(&self, path: &Path, reason: String) -> WorkloadError {
        let archive_path = path.with_file_name("archive.atawl");
        let recovery = if archive_path.exists() {
            format!(
                "rebuild the cached metadata from its stored archive with `atakit workload import --force {}`; rebuild the workload from source with `atakit workload build <workload-directory>` if the archive manifest is also unsupported",
                archive_path.display()
            )
        } else {
            // The entry directory is named by workload identifier, so the
            // identifier is recoverable even when the metadata inside is not.
            let workload_id = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|part| part.to_str());
            match workload_id {
                Some(workload_id) => format!(
                    "refresh the cached metadata from the configured chain with `atakit workload add --force --chain <chain> {workload_id}`, or rebuild the workload from source with `atakit workload build <workload-directory>`"
                ),
                None => "rebuild the workload from source with `atakit workload build <workload-directory>`"
                    .to_string(),
            }
        };
        WorkloadError::UnsupportedMeta {
            path: path.to_path_buf(),
            reason,
            recovery,
        }
    }
}

fn uses_retired_pcr_rule_fields(value: &serde_json::Value) -> bool {
    value
        .get("on_chain_spec")
        .and_then(|spec| spec.get("pcrs"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|pcrs| {
            pcrs.iter()
                .any(|pcr| pcr.get("verify_type").is_some() || pcr.get("match_data").is_some())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct identifier per entry. Entries are keyed by identifier, so a
    /// shared one would make every fixture the same entry.
    fn test_id(name: &str, version: &str) -> String {
        let mut digest = [0u8; 32];
        for (index, byte) in format!("{name}:{version}").bytes().enumerate() {
            digest[index % 32] ^= byte;
        }
        format!("0x{}", hex::encode(digest))
    }

    fn test_meta(name: &str, version: &str) -> WorkloadMeta {
        WorkloadMeta {
            metadata_format: WORKLOAD_META_FORMAT_VERSION,
            workload_id: test_id(name, version),
            publisher: PUBLISHER.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            sha256: None,
            pcr23: None,
            owner: None,
            archive_size: None,
            on_chain_spec: None,
            revoked: false,
            repositories: Vec::new(),
            added_at: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    const PUBLISHER: &str = "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f";
    const TEST_ID: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_ID: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Entries are keyed by identifier, which is path-safe by construction, so
    /// there is nothing to escape and nothing that could escape the store.
    #[test]
    fn an_identifier_maps_to_one_segment_inside_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir(TEST_ID).unwrap();
        assert_eq!(dir, tmp.path().join(TEST_ID));
    }

    /// Anything that is not the machine-generated form is refused. Rejecting is
    /// safe here in a way that rejecting a name was not: the value is derived,
    /// never typed, so a legitimate workload can never fail to map to a path.
    #[test]
    fn anything_but_an_identifier_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        for bad in [
            "my-app",
            "..",
            ".",
            "",
            "foo/bar",
            "../../etc/passwd",
            "0xshort",
            &TEST_ID.to_uppercase(),
        ] {
            assert!(
                matches!(
                    store.entry_dir(bad),
                    Err(WorkloadError::StorePathTraversal { .. })
                ),
                "must refuse {bad:?}"
            );
        }
    }

    /// Two publishers holding the same name and version get separate entries,
    /// which is the collision the identifier exists to remove.
    #[test]
    fn distinct_identifiers_get_distinct_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert_ne!(
            store.entry_dir(TEST_ID).unwrap(),
            store.entry_dir(OTHER_ID).unwrap()
        );
    }

    #[test]
    fn save_and_load_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let meta = test_meta("my-app", "v0.0.1");
        store.save_meta(&meta).unwrap();

        let loaded = store
            .load_meta(&test_id("my-app", "v0.0.1"))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.workload_id, test_id("my-app", "v0.0.1"));
        assert_eq!(loaded.name, "my-app");
        assert_eq!(loaded.version, "v0.0.1");
        assert_eq!(loaded.metadata_format, WORKLOAD_META_FORMAT_VERSION);

        let saved: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(store.meta_path(&test_id("my-app", "v0.0.1")).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(saved["metadata_format"], WORKLOAD_META_FORMAT_VERSION);
    }

    #[test]
    fn retired_pcr_rule_metadata_reports_archive_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir(TEST_ID).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("archive.atawl"), b"archive").unwrap();
        fs::write(
            dir.join("meta.json"),
            r#"{
                "workload_id": "0xtest",
                "publisher": "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f",
                "name": "old-app",
                "version": "v1",
                "on_chain_spec": {
                    "session_ttl": 0,
                    "base_image_mode": 2,
                    "base_image_ids": [],
                    "pcrs": [{"pcr_index": 23, "verify_type": 0, "match_data": []}]
                },
                "added_at": "2025-01-01T00:00:00Z"
            }"#,
        )
        .unwrap();

        let error = store.load_meta(TEST_ID).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("retired verify_type and match_data"));
        assert!(message.contains("atakit workload import --force"));
        assert!(message.contains("archive.atawl"));
    }

    #[test]
    fn retired_pcr_rule_metadata_without_archive_reports_chain_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir(TEST_ID).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("meta.json"),
            r#"{
                "workload_id": "0xtest",
                "publisher": "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f",
                "name": "old-app",
                "version": "v1",
                "on_chain_spec": {
                    "session_ttl": 0,
                    "base_image_mode": 2,
                    "base_image_ids": [],
                    "pcrs": [{"pcr_index": 23, "verify_type": 0, "match_data": []}]
                },
                "added_at": "2025-01-01T00:00:00Z"
            }"#,
        )
        .unwrap();

        let error = store.load_meta(TEST_ID).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(&format!(
            "atakit workload add --force --chain <chain> {TEST_ID}"
        )));
    }

    #[test]
    fn newer_metadata_format_reports_atakit_upgrade() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir(TEST_ID).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("meta.json"),
            r#"{
                "metadata_format": 99,
                "workload_id": "0xtest",
                "publisher": "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f",
                "name": "future-app",
                "version": "v1",
                "added_at": "2025-01-01T00:00:00Z"
            }"#,
        )
        .unwrap();

        let error = store.load_meta(TEST_ID).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("newer than supported format 2"),
            "{message}"
        );
        assert!(message.contains("upgrade atakit"));
    }

    #[test]
    fn unversioned_metadata_is_refused_with_a_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir(TEST_ID).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("meta.json"),
            r#"{
                "workload_id": "0xtest",
                "name": "current-app",
                "version": "v1",
                "on_chain_spec": {
                    "session_ttl": 0,
                    "base_image_mode": 2,
                    "base_image_ids": [],
                    "pcrs": [{"pcr_index": 23, "comparison": "0x00"}]
                },
                "added_at": "2025-01-01T00:00:00Z"
            }"#,
        )
        .unwrap();

        let error = store.load_meta(TEST_ID).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("publisher-qualified"), "{message}");
    }

    #[test]
    fn load_meta_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert!(store
            .load_meta(&test_id("my-app", "v0.0.1"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn exists_and_has_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());

        let id = test_id("app", "v1");
        assert!(!store.exists(&id));

        store.save_meta(&test_meta("app", "v1")).unwrap();
        assert!(store.exists(&id));
        assert!(!store.has_blob(&id));

        store.save_blob(&id, b"fake archive").unwrap();
        assert!(store.has_blob(&id));
    }

    #[test]
    fn remove_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());

        let id = test_id("app", "v1");
        store.save_meta(&test_meta("app", "v1")).unwrap();
        store.save_blob(&id, b"data").unwrap();
        assert!(store.exists(&id));

        store.remove(&id).unwrap();
        assert!(!store.exists(&id));
        // The layout is flat, so the entry directory is all there is.
        assert!(!tmp.path().join(&id).exists());
    }

    #[test]
    fn remove_blob_keeps_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());

        let id = test_id("app", "v1");
        store.save_meta(&test_meta("app", "v1")).unwrap();
        store.save_blob(&id, b"data").unwrap();
        assert!(store.has_blob(&id));

        store.remove_blob(&id).unwrap();
        assert!(!store.has_blob(&id));
        assert!(store.exists(&id));
    }

    #[test]
    fn list_returns_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());

        store.save_meta(&test_meta("bravo", "v0.0.1")).unwrap();
        store.save_meta(&test_meta("alpha", "v0.0.2")).unwrap();
        store.save_meta(&test_meta("alpha", "v0.0.1")).unwrap();

        let entries = store.list().unwrap();
        let keys: Vec<_> = entries
            .iter()
            .map(|e| format!("{}:{}", e.meta.name, e.meta.version))
            .collect();
        assert_eq!(keys, vec!["alpha:v0.0.1", "alpha:v0.0.2", "bravo:v0.0.1"]);
    }

    #[test]
    fn symlink_parent_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join("store");
        fs::create_dir(&store_dir).unwrap();
        let store = WorkloadStore::new(&store_dir);

        // Plant the symlink at the escaped segment the store actually uses;
        // containment is now defence in depth behind the encoding, so this is
        // the path an attacker would have to target.
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, store_dir.join(TEST_ID)).unwrap();

        // Trying to write via the symlink should fail containment check
        let result = store.entry_dir(TEST_ID);
        assert!(
            matches!(result, Err(WorkloadError::StorePathTraversal { .. })),
            "expected StorePathTraversal, got {result:?}"
        );
    }
}
