use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::WorkloadError;

/// Format of `meta.json` in the local workload store.
///
/// The older PCR policy cache used unversioned `verify_type` and
/// `match_data` fields. Format 1 starts with the opaque `comparison` field.
pub const WORKLOAD_META_FORMAT_VERSION: u32 = 1;

/// Validate that a name or version component is safe for use as a path segment.
/// Rejects empty strings, path separators, `..`, and `.`.
fn validate_path_component(s: &str, label: &str) -> Result<(), WorkloadError> {
    if s.is_empty()
        || s == "."
        || s == ".."
        || s.contains('/')
        || s.contains('\\')
        || Path::new(s)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(WorkloadError::StorePathTraversal {
            path: PathBuf::from(format!("{label}: {s}")),
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

    fn entry_dir(&self, name: &str, version: &str) -> Result<PathBuf, WorkloadError> {
        validate_path_component(name, "name")?;
        validate_path_component(version, "version")?;

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

        // Check the parent <base>/<name> if it exists. A symlink here could
        // redirect writes outside base_dir when <version> doesn't exist yet.
        let parent = self.base_dir.join(name);
        if let Some(ref canon_base) = canon_base {
            if parent.exists() {
                let canon_parent =
                    parent
                        .canonicalize()
                        .map_err(|e| WorkloadError::ReadStoreDir {
                            path: parent.clone(),
                            reason: e.to_string(),
                        })?;
                if !canon_parent.starts_with(canon_base) {
                    return Err(WorkloadError::StorePathTraversal { path: parent });
                }
            }
        }

        // Check the full path if it exists.
        let path = parent.join(version);
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

    pub fn meta_path(&self, name: &str, version: &str) -> Result<PathBuf, WorkloadError> {
        Ok(self.entry_dir(name, version)?.join("meta.json"))
    }

    pub fn blob_path(&self, name: &str, version: &str) -> Result<PathBuf, WorkloadError> {
        Ok(self.entry_dir(name, version)?.join("archive.atawl"))
    }

    // ── Read ───────────────────────────────────────────

    /// List all workload entries in the store.
    /// Returns empty vec if the base directory doesn't exist.
    pub fn list(&self) -> Result<Vec<WorkloadEntry>, WorkloadError> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let name_dirs = fs::read_dir(&self.base_dir).map_err(|e| WorkloadError::ReadStoreDir {
            path: self.base_dir.clone(),
            reason: e.to_string(),
        })?;

        for name_entry in name_dirs {
            let name_entry = name_entry.map_err(|e| WorkloadError::ReadStoreDir {
                path: self.base_dir.clone(),
                reason: e.to_string(),
            })?;
            if !name_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }

            let name_path = name_entry.path();
            let version_dirs =
                fs::read_dir(&name_path).map_err(|e| WorkloadError::ReadStoreDir {
                    path: name_path.clone(),
                    reason: e.to_string(),
                })?;

            for version_entry in version_dirs {
                let version_entry = version_entry.map_err(|e| WorkloadError::ReadStoreDir {
                    path: name_path.clone(),
                    reason: e.to_string(),
                })?;
                if !version_entry
                    .file_type()
                    .map(|t| t.is_dir())
                    .unwrap_or(false)
                {
                    continue;
                }

                let version_path = version_entry.path();
                let meta_path = version_path.join("meta.json");
                if !meta_path.exists() {
                    continue;
                }

                let meta = self.read_meta(&meta_path)?;
                let has_blob = version_path.join("archive.atawl").exists();
                entries.push(WorkloadEntry { meta, has_blob });
            }
        }

        // Sort by name, then version
        entries.sort_by(|a, b| {
            a.meta
                .name
                .cmp(&b.meta.name)
                .then_with(|| a.meta.version.cmp(&b.meta.version))
        });

        Ok(entries)
    }

    /// Get a specific workload entry by name and version.
    pub fn get(&self, name: &str, version: &str) -> Result<Option<WorkloadEntry>, WorkloadError> {
        let meta_path = self.meta_path(name, version)?;
        if !meta_path.exists() {
            return Ok(None);
        }
        let meta = self.read_meta(&meta_path)?;
        let has_blob = self.blob_path(name, version)?.exists();
        Ok(Some(WorkloadEntry { meta, has_blob }))
    }

    /// Find a workload entry by workload ID (hex string).
    pub fn get_by_id(&self, workload_id: &str) -> Result<Option<WorkloadEntry>, WorkloadError> {
        let entries = self.list()?;
        Ok(entries
            .into_iter()
            .find(|e| e.meta.workload_id == workload_id))
    }

    /// Load metadata for a workload, if it exists.
    pub fn load_meta(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<WorkloadMeta>, WorkloadError> {
        let path = self.meta_path(name, version)?;
        if !path.exists() {
            return Ok(None);
        }
        self.read_meta(&path).map(Some)
    }

    // ── Write ──────────────────────────────────────────

    /// Save metadata for a workload. Creates directories as needed.
    /// Uses temp-file + atomic rename to prevent corruption and symlink following.
    pub fn save_meta(&self, meta: &WorkloadMeta) -> Result<(), WorkloadError> {
        let dir = self.entry_dir(&meta.name, &meta.version)?;
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

        Ok(())
    }

    /// Copy an archive file into the store. Returns the file size.
    /// Uses temp-file + atomic rename to prevent corruption and symlink following.
    pub fn import_blob(&self, name: &str, version: &str, src: &Path) -> Result<u64, WorkloadError> {
        let dir = self.entry_dir(name, version)?;
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
    pub fn save_blob(&self, name: &str, version: &str, data: &[u8]) -> Result<(), WorkloadError> {
        let dir = self.entry_dir(name, version)?;
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

    /// Remove an entire workload entry (metadata + blob).
    /// Cleans up the name directory if empty afterward.
    pub fn remove(&self, name: &str, version: &str) -> Result<(), WorkloadError> {
        let dir = self.entry_dir(name, version)?;
        if !dir.exists() {
            return Err(WorkloadError::StoreNotFound {
                name: name.to_string(),
                version: version.to_string(),
            });
        }

        fs::remove_dir_all(&dir).map_err(WorkloadError::from)?;

        // Clean up parent name dir if empty
        let name_dir = self.base_dir.join(name);
        if name_dir.exists() {
            if let Ok(mut entries) = fs::read_dir(&name_dir) {
                if entries.next().is_none() {
                    let _ = fs::remove_dir(&name_dir);
                }
            }
        }

        Ok(())
    }

    /// Remove only the archive blob, keeping metadata.
    pub fn remove_blob(&self, name: &str, version: &str) -> Result<(), WorkloadError> {
        let blob = self.blob_path(name, version)?;
        if !blob.exists() {
            return Err(WorkloadError::NoBlobInStore {
                name: name.to_string(),
                version: version.to_string(),
            });
        }
        fs::remove_file(&blob).map_err(WorkloadError::from)?;
        Ok(())
    }

    // ── Query ──────────────────────────────────────────

    pub fn has_blob(&self, name: &str, version: &str) -> bool {
        self.blob_path(name, version)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    pub fn exists(&self, name: &str, version: &str) -> bool {
        self.meta_path(name, version)
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

        // The opaque-comparison implementation briefly wrote unversioned
        // metadata. It already has the format-1 shape, so accept it. The next
        // save writes `metadata_format: 1`.
        Ok(())
    }

    fn unsupported_meta(&self, path: &Path, reason: String) -> WorkloadError {
        let archive_path = path.with_file_name("archive.atawl");
        let recovery = if archive_path.exists() {
            format!(
                "rebuild the cached metadata from its stored archive with `atakit workload import --force {}`; rebuild the workload from source with `atakit workload build <workload-directory>` if the archive manifest is also unsupported",
                archive_path.display()
            )
        } else {
            let version = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|part| part.to_str());
            let name = path
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .and_then(|part| part.to_str());
            match (name, version) {
                (Some(name), Some(version)) => format!(
                    "refresh the cached metadata from the configured chain with `atakit workload add --force --chain <chain> {name}:{version}`, or rebuild the workload from source with `atakit workload build <workload-directory>`"
                ),
                _ => "rebuild the workload from source with `atakit workload build <workload-directory>`"
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

    fn test_meta(name: &str, version: &str) -> WorkloadMeta {
        WorkloadMeta {
            metadata_format: WORKLOAD_META_FORMAT_VERSION,
            workload_id: "0xtest".to_string(),
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

    #[test]
    fn rejects_dotdot_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert!(matches!(
            store.entry_dir("..", "v0.0.1"),
            Err(WorkloadError::StorePathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_dotdot_version() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert!(matches!(
            store.entry_dir("app", ".."),
            Err(WorkloadError::StorePathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_slash_in_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert!(matches!(
            store.entry_dir("foo/bar", "v0.0.1"),
            Err(WorkloadError::StorePathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_slash_in_version() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert!(matches!(
            store.entry_dir("app", "v0/../etc"),
            Err(WorkloadError::StorePathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_empty_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert!(matches!(
            store.entry_dir("", "v0.0.1"),
            Err(WorkloadError::StorePathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_dot_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert!(matches!(
            store.entry_dir(".", "v0.0.1"),
            Err(WorkloadError::StorePathTraversal { .. })
        ));
    }

    #[test]
    fn accepts_valid_components() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir("my-app", "v0.0.1").unwrap();
        assert_eq!(dir, tmp.path().join("my-app").join("v0.0.1"));
    }

    #[test]
    fn save_and_load_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let meta = test_meta("my-app", "v0.0.1");
        store.save_meta(&meta).unwrap();

        let loaded = store.load_meta("my-app", "v0.0.1").unwrap().unwrap();
        assert_eq!(loaded.workload_id, "0xtest");
        assert_eq!(loaded.name, "my-app");
        assert_eq!(loaded.version, "v0.0.1");
        assert_eq!(loaded.metadata_format, WORKLOAD_META_FORMAT_VERSION);

        let saved: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(store.meta_path("my-app", "v0.0.1").unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(saved["metadata_format"], WORKLOAD_META_FORMAT_VERSION);
    }

    #[test]
    fn retired_pcr_rule_metadata_reports_archive_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir("old-app", "v1").unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("archive.atawl"), b"archive").unwrap();
        fs::write(
            dir.join("meta.json"),
            r#"{
                "workload_id": "0xtest",
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

        let error = store.load_meta("old-app", "v1").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("retired verify_type and match_data"));
        assert!(message.contains("atakit workload import --force"));
        assert!(message.contains("archive.atawl"));
    }

    #[test]
    fn retired_pcr_rule_metadata_without_archive_reports_chain_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir("old-app", "v1").unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("meta.json"),
            r#"{
                "workload_id": "0xtest",
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

        let error = store.load_meta("old-app", "v1").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("atakit workload add --force --chain <chain> old-app:v1"));
    }

    #[test]
    fn newer_metadata_format_reports_atakit_upgrade() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir("future-app", "v1").unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("meta.json"),
            r#"{
                "metadata_format": 2,
                "workload_id": "0xtest",
                "name": "future-app",
                "version": "v1",
                "added_at": "2025-01-01T00:00:00Z"
            }"#,
        )
        .unwrap();

        let error = store.load_meta("future-app", "v1").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("metadata format 2 is newer than supported format 1"));
        assert!(message.contains("upgrade atakit"));
    }

    #[test]
    fn unversioned_opaque_comparison_metadata_is_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        let dir = store.entry_dir("current-app", "v1").unwrap();
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

        let meta = store.load_meta("current-app", "v1").unwrap().unwrap();
        assert_eq!(meta.metadata_format, WORKLOAD_META_FORMAT_VERSION);
        assert_eq!(meta.on_chain_spec.unwrap().pcrs[0].comparison, "0x00");
    }

    #[test]
    fn load_meta_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());
        assert!(store.load_meta("no-such", "v0.0.1").unwrap().is_none());
    }

    #[test]
    fn exists_and_has_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());

        assert!(!store.exists("app", "v1"));

        store.save_meta(&test_meta("app", "v1")).unwrap();
        assert!(store.exists("app", "v1"));
        assert!(!store.has_blob("app", "v1"));

        store.save_blob("app", "v1", b"fake archive").unwrap();
        assert!(store.has_blob("app", "v1"));
    }

    #[test]
    fn remove_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());

        store.save_meta(&test_meta("app", "v1")).unwrap();
        store.save_blob("app", "v1", b"data").unwrap();
        assert!(store.exists("app", "v1"));

        store.remove("app", "v1").unwrap();
        assert!(!store.exists("app", "v1"));
        // Parent name dir should be cleaned up too
        assert!(!tmp.path().join("app").exists());
    }

    #[test]
    fn remove_blob_keeps_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(tmp.path());

        store.save_meta(&test_meta("app", "v1")).unwrap();
        store.save_blob("app", "v1", b"data").unwrap();
        assert!(store.has_blob("app", "v1"));

        store.remove_blob("app", "v1").unwrap();
        assert!(!store.has_blob("app", "v1"));
        assert!(store.exists("app", "v1"));
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

        // Create a symlink <store>/evil -> /tmp (outside store)
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, store_dir.join("evil")).unwrap();

        // Trying to write via the symlink should fail containment check
        let result = store.entry_dir("evil", "v1");
        assert!(
            matches!(result, Err(WorkloadError::StorePathTraversal { .. })),
            "expected StorePathTraversal, got {result:?}"
        );
    }
}
