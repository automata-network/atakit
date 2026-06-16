//! Workload repository abstraction.
//!
//! A workload repository is a remote source of `.atawl` archives, identified
//! by their on-chain workload ID. This module abstracts over the two backends:
//!
//! * `Http` -- the in-house HTTP service defined in
//!   `docs/workload-registry-spec.md`.
//! * `Github` -- a GitHub repository whose releases hold workload archives.
//!
//! Both kinds expose the same operations (resolve, get_meta, download, list,
//! upload) so the CLI commands can dispatch uniformly.

mod github;
mod http;

use std::path::Path;

use atakit_core::ProgressReporter;
use serde::{Deserialize, Serialize};

use crate::WorkloadError;

pub use github::GithubWorkloadRepository;
pub use http::HttpWorkloadRepository;

/// Compare two SHA-256 hex strings tolerantly. Strips a `0x` or
/// `sha256:` prefix from either side and lowercases before comparing.
/// Returns false if either side has non-hex content (so a malformed
/// value never falsely matches another malformed value).
///
/// Used for identity checks that may see either prefix style: HTTP
/// repositories often return `sha256:<hex>`, while on-chain data and
/// the GitHub sidecar convention use `0x<hex>`.
pub fn hex_equal(a: &str, b: &str) -> bool {
    fn normalize(s: &str) -> Option<String> {
        let trimmed = s.trim();
        let stripped = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .or_else(|| trimmed.strip_prefix("sha256:"))
            .unwrap_or(trimmed);
        if stripped.is_empty() || !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(stripped.to_ascii_lowercase())
    }
    match (normalize(a), normalize(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_equal_prefixes() {
        assert!(hex_equal("0xabcd", "abcd"));
        assert!(hex_equal("sha256:abcd", "0xabcd"));
        assert!(hex_equal("0XABCD", "abcd"));
        assert!(hex_equal("  0xabcd  ", "abcd"));
    }

    #[test]
    fn hex_equal_mismatch() {
        assert!(!hex_equal("0xabcd", "0xabce"));
    }

    #[test]
    fn hex_equal_invalid() {
        assert!(!hex_equal("0xnothex", "0xnothex"));
        assert!(!hex_equal("", ""));
    }
}

/// Metadata describing one archive stored in a repository.
///
/// Wire-compatible with the HTTP service's `RegistryMeta` JSON shape: same
/// camelCase field names. The github repository serialises the same struct
/// as a sidecar `.meta.json` asset alongside each `.atawl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryArchiveMeta {
    pub workload_id: String,
    pub name: String,
    pub version: String,
    /// Owner public-key fingerprint as `0x<hex>`. Empty string if unknown
    /// (the github backend cannot populate this without a chain query).
    #[serde(default)]
    pub owner: String,
    /// SHA-256 of `manifest.toml` -- the integrity event hash.
    pub sha256: String,
    pub archive_size: u64,
    pub archive_hash: String,
    pub uploaded_at: String,
}

/// Filters for listing archives in a repository.
#[derive(Debug, Default, Clone)]
pub struct RepositoryFilters {
    pub owner: Option<String>,
    pub name: Option<String>,
    pub name_prefix: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Identifying tuple for a workload archive.
///
/// All three fields are required because each repository backend needs a
/// different combination: the HTTP backend keys on `workload_id` only, while
/// the GitHub backend uses `name`/`version` to construct the release tag and
/// `workload_id` to verify the body.
#[derive(Debug, Clone)]
pub struct WorkloadCoords {
    /// Lowercase `0x` + 64 hex chars.
    pub workload_id: String,
    pub name: String,
    pub version: String,
}

impl WorkloadCoords {
    /// Asset filename used both for `.atawl` archives and sidecar `.meta.json`
    /// files: `{name}-{version}`.
    pub fn asset_stem(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }
}

/// Inputs needed to upload a workload to a repository.
#[derive(Debug)]
pub struct UploadContext<'a> {
    pub coords: WorkloadCoords,
    pub archive_path: &'a Path,
    /// SHA-256 of `manifest.toml` (event hash).
    pub manifest_sha256: String,
    /// Final PCR23 register value.
    pub pcr23: String,
}

/// One of the supported workload repository backends.
pub enum WorkloadRepository {
    Http(HttpWorkloadRepository),
    Github(GithubWorkloadRepository),
}

impl WorkloadRepository {
    /// A short identifier suitable for storing in `WorkloadMeta.repositories`.
    ///
    /// HTTP: the base URL.
    /// GitHub: `github://owner/repo`.
    pub fn display_uri(&self) -> String {
        match self {
            Self::Http(h) => h.base_url().to_string(),
            Self::Github(g) => format!("github://{}", g.repo()),
        }
    }

    /// Whether this repository accepts uploads.
    pub fn supports_upload(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::Github(g) => g.has_token(),
        }
    }

    /// Resolve a workload ID into full coordinates plus metadata.
    /// Used when the user supplied only `0x<id>` and we need name+version.
    ///
    /// Returns `Ok(None)` when the workload is not present in this
    /// repository (a clean negative, not an error). `Err` is reserved
    /// for transport failures, auth errors, and other real faults.
    pub async fn resolve(
        &self,
        workload_id: &str,
    ) -> Result<Option<(WorkloadCoords, RepositoryArchiveMeta)>, WorkloadError> {
        match self {
            Self::Http(h) => h.resolve(workload_id).await,
            Self::Github(g) => g.resolve(workload_id).await,
        }
    }

    /// Get metadata for a known set of coordinates.
    ///
    /// Returns `Ok(None)` when the workload is not present in this
    /// repository. See [`resolve`] for the error semantics.
    pub async fn get_meta(
        &self,
        coords: &WorkloadCoords,
    ) -> Result<Option<RepositoryArchiveMeta>, WorkloadError> {
        match self {
            Self::Http(h) => h.get_meta(coords).await,
            Self::Github(g) => g.get_meta(coords).await,
        }
    }

    /// Stream-download an archive into `dest`, ticking the supplied
    /// progress reporter as bytes arrive. Returns bytes written.
    pub async fn download_to_file(
        &self,
        coords: &WorkloadCoords,
        dest: &Path,
        progress: &dyn ProgressReporter,
    ) -> Result<u64, WorkloadError> {
        match self {
            Self::Http(h) => h.download_to_file(coords, dest, progress).await,
            Self::Github(g) => g.download_to_file(coords, dest, progress).await,
        }
    }

    /// List archives matching the filters.
    pub async fn list(
        &self,
        filters: &RepositoryFilters,
    ) -> Result<Vec<RepositoryArchiveMeta>, WorkloadError> {
        match self {
            Self::Http(h) => h.list(filters).await,
            Self::Github(g) => g.list(filters).await,
        }
    }

    /// Upload an archive. Errors if the backend is read-only.
    pub async fn upload(
        &self,
        ctx: &UploadContext<'_>,
    ) -> Result<RepositoryArchiveMeta, WorkloadError> {
        match self {
            Self::Http(h) => h.upload(ctx).await,
            Self::Github(g) => g.upload(ctx).await,
        }
    }
}
