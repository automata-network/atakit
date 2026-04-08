//! GitHub-backed workload repository.
//!
//! Each workload version maps to one GitHub release on the configured
//! `owner/repo`. The release exposes:
//!
//! * tag           = `<name>/<version>` -- git ref forbids `:`, so we use `/`.
//! * release name  = `<name>:<version>` -- free-form display heading.
//! * body          = newline-delimited `key: value` lines including
//!   `Workload ID`, `Manifest SHA256`, `PCR23`.
//! * `<name>-<version>.atawl`        asset = the archive blob.
//! * `<name>-<version>.meta.json`    asset = sidecar [`RepositoryArchiveMeta`].
//!
//! Hex-only lookups (`workload pull 0x<id>`) are served by listing the most
//! recent releases and grepping bodies for `Workload ID: <id>`. The list
//! endpoint already returns release bodies, so this requires no per-release
//! follow-up.

use std::path::Path;

use atakit_core::ProgressReporter;
use atakit_github::{
    download_asset_bytes, download_asset_to_path, upload_release_asset,
    upload_release_asset_bytes, Asset as GhAsset, CreateReleaseRequest, Release,
    ReleasesClient,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::WorkloadError;

use super::{RepositoryArchiveMeta, RepositoryFilters, UploadContext, WorkloadCoords};

const ATAWL_EXT: &str = ".atawl";
const META_EXT: &str = ".meta.json";
const LIST_PAGE_SIZE: u32 = 100;
/// Upper bound on the bytes we're willing to download for a sidecar
/// `*.meta.json`. The asset's reported size is attacker-controlled
/// (whoever owns the release decides what to upload), so a malicious
/// repo could otherwise publish a huge sidecar to OOM the client
/// during `ls` / `pull`. Real metadata files are typically <1 KiB;
/// 1 MiB is far more than any legitimate sidecar should need.
const MAX_SIDECAR_SIZE: u64 = 1024 * 1024;

/// GitHub releases-backed workload repository.
pub struct GithubWorkloadRepository {
    client: ReleasesClient,
    repo: String,
    has_token: bool,
}

impl GithubWorkloadRepository {
    /// Construct a repository for `owner/repo`. The token, if any, is read
    /// from `GITHUB_TOKEN` and is required for uploads and for accessing
    /// private repos.
    pub fn new(repo: impl Into<String>, token: Option<String>) -> Self {
        let has_token = token.as_ref().map(|t| !t.is_empty()).unwrap_or(false);
        let mut client = ReleasesClient::new();
        if let Some(t) = token {
            if !t.is_empty() {
                client = client.with_token(t);
            }
        }
        Self {
            client,
            repo: repo.into(),
            has_token,
        }
    }

    pub fn repo(&self) -> &str {
        &self.repo
    }

    pub fn has_token(&self) -> bool {
        self.has_token
    }

    /// Resolve a hex workload ID by listing recent releases and matching
    /// against the body line `Workload ID: <id>`.
    ///
    /// Returns `Ok(None)` when no release matches -- this is the
    /// expected "not in this repository" signal during multi-repo
    /// discovery, not an error.
    pub async fn resolve(
        &self,
        workload_id: &str,
    ) -> Result<Option<(WorkloadCoords, RepositoryArchiveMeta)>, WorkloadError> {
        let target = workload_id.to_ascii_lowercase();
        let releases = self.list_releases_paged().await?;
        for release in releases {
            if let Some(body) = release.body.as_deref() {
                if let Some(found) = parse_body_field(body, "Workload ID") {
                    if found.to_ascii_lowercase() == target {
                        let coords = parse_coords_from_release(&release)?;
                        let meta = self.meta_from_release(&release, &coords).await?;
                        return Ok(Some((coords, meta)));
                    }
                }
            }
        }
        Ok(None)
    }

    pub async fn get_meta(
        &self,
        coords: &WorkloadCoords,
    ) -> Result<Option<RepositoryArchiveMeta>, WorkloadError> {
        let Some(release) = self.try_fetch_release(coords).await? else {
            return Ok(None);
        };
        self.meta_from_release(&release, coords).await.map(Some)
    }

    /// Download the `.atawl` asset of the matching release into `dest`,
    /// streaming progress through `progress`.
    pub async fn download_to_file(
        &self,
        coords: &WorkloadCoords,
        dest: &Path,
        progress: &dyn ProgressReporter,
    ) -> Result<u64, WorkloadError> {
        let release = self.fetch_release_for(coords).await?;
        let asset = find_atawl_asset(&release, coords)?;

        // Optional: cross-check the body's workload_id matches what we asked for.
        if let Some(body) = release.body.as_deref() {
            if let Some(body_id) = parse_body_field(body, "Workload ID") {
                if !body_id.eq_ignore_ascii_case(&coords.workload_id) {
                    return Err(WorkloadError::Repository {
                        message: format!(
                            "release tag {tag} body advertises workload id {body_id} \
                             but request expected {expected}",
                            tag = release.tag_name,
                            body_id = body_id,
                            expected = coords.workload_id,
                        ),
                    });
                }
            }
        }

        let written = download_asset_to_path(&self.client, asset, dest, progress)
            .await
            .map_err(WorkloadError::from)?;
        Ok(written)
    }

    pub async fn list(
        &self,
        filters: &RepositoryFilters,
    ) -> Result<Vec<RepositoryArchiveMeta>, WorkloadError> {
        let limit = filters.limit.unwrap_or(LIST_PAGE_SIZE);
        let releases = self
            .client
            .list_releases(&self.repo, limit.min(LIST_PAGE_SIZE))
            .await
            .map_err(WorkloadError::from)?;

        let mut out = Vec::new();
        for release in releases {
            let Ok(coords) = parse_coords_from_release(&release) else {
                continue;
            };
            let Some(asset) = release.assets.iter().find(|a| {
                a.name == format!("{}{ATAWL_EXT}", coords.asset_stem())
                    || a.name.ends_with(ATAWL_EXT)
            }) else {
                continue;
            };

            // Apply filters.
            if let Some(ref name_substr) = filters.name {
                if !coords.name.contains(name_substr.as_str()) {
                    continue;
                }
            }
            if let Some(ref prefix) = filters.name_prefix {
                if !coords.name.starts_with(prefix.as_str()) {
                    continue;
                }
            }

            let meta = self
                .build_meta(&release, &coords, asset.size, asset.id)
                .await;

            if let Some(ref owner_filter) = filters.owner {
                if meta.owner != *owner_filter {
                    continue;
                }
            }

            out.push(meta);
        }
        Ok(out)
    }

    pub async fn upload(
        &self,
        ctx: &UploadContext<'_>,
    ) -> Result<RepositoryArchiveMeta, WorkloadError> {
        if !self.has_token {
            return Err(WorkloadError::Repository {
                message: format!(
                    "github://{} requires GITHUB_TOKEN with `contents: write` to push",
                    self.repo
                ),
            });
        }

        let tag = format_tag(&ctx.coords);
        let display = format!("{}:{}", ctx.coords.name, ctx.coords.version);

        // Refuse if the release already exists.
        if self
            .client
            .try_get_release_by_tag(&self.repo, &tag)
            .await
            .map_err(WorkloadError::from)?
            .is_some()
        {
            return Err(WorkloadError::Repository {
                message: format!("release {tag} already exists in github://{}", self.repo),
            });
        }

        // Compute archive hash and size up front so the sidecar reflects
        // exactly what was uploaded.
        let (archive_size, archive_hash) = hash_archive_file(ctx.archive_path).await?;
        let uploaded_at = Utc::now().to_rfc3339();

        let body = format_release_body(&ctx.coords, &ctx.manifest_sha256, &ctx.pcr23, archive_size);

        debug!(%tag, "creating github release");
        let release = self
            .client
            .create_release(
                &self.repo,
                &CreateReleaseRequest {
                    tag_name: tag.clone(),
                    name: Some(display.clone()),
                    body: Some(body),
                    draft: None,
                    prerelease: None,
                    target_commitish: None,
                },
            )
            .await
            .map_err(WorkloadError::from)?;

        let upload_url = match release.upload_url.clone() {
            Some(u) => u,
            None => {
                self.try_rollback_release(&release, &tag).await;
                return Err(WorkloadError::Repository {
                    message: format!("github release {tag} response missing upload_url"),
                });
            }
        };

        // Helper to delete the release on asset upload failure so the
        // tag doesn't get stuck in a half-uploaded state and block
        // future retries.
        let archive_name = format!("{}{ATAWL_EXT}", ctx.coords.asset_stem());
        if let Err(e) = upload_release_asset(
            &self.client,
            &upload_url,
            &archive_name,
            ctx.archive_path,
            "application/octet-stream",
        )
        .await
        {
            self.try_rollback_release(&release, &tag).await;
            return Err(WorkloadError::from(e));
        }

        let meta = RepositoryArchiveMeta {
            workload_id: ctx.coords.workload_id.clone(),
            name: ctx.coords.name.clone(),
            version: ctx.coords.version.clone(),
            owner: String::new(),
            sha256: ctx.manifest_sha256.clone(),
            archive_size,
            archive_hash,
            uploaded_at,
        };
        let meta_bytes = match serde_json::to_vec_pretty(&meta) {
            Ok(b) => b,
            Err(e) => {
                self.try_rollback_release(&release, &tag).await;
                return Err(WorkloadError::Json(e.to_string()));
            }
        };

        let meta_name = format!("{}{META_EXT}", ctx.coords.asset_stem());
        if let Err(e) = upload_release_asset_bytes(
            &self.client,
            &upload_url,
            &meta_name,
            meta_bytes,
            "application/json",
        )
        .await
        {
            self.try_rollback_release(&release, &tag).await;
            return Err(WorkloadError::from(e));
        }

        Ok(meta)
    }

    /// Best-effort cleanup after a failed upload. We just created the
    /// release so the tag exists on the remote, but one of the asset
    /// uploads failed; if we leave the release in place, future push
    /// attempts will hit the "release already exists" guard and refuse
    /// to retry. A failed delete is logged but swallowed -- we want the
    /// original upload error to be what the caller sees, not a
    /// secondary cleanup failure.
    async fn try_rollback_release(&self, release: &Release, tag: &str) {
        let Some(id) = release.id else {
            warn!(
                repo = %self.repo,
                %tag,
                "cannot rollback orphan release: github response did not include a release id"
            );
            return;
        };
        debug!(%tag, release_id = id, "rolling back orphan github release after upload failure");
        if let Err(e) = self.client.delete_release(&self.repo, id).await {
            warn!(
                repo = %self.repo,
                %tag,
                release_id = id,
                error = %e,
                "failed to rollback orphan github release; tag may block future pushes until deleted manually"
            );
        }
    }

    // ── internals ──────────────────────────────────────────────

    /// Fetch the release for `coords`, erroring if it doesn't exist.
    /// Used by `download_to_file` which is called after discovery has
    /// already picked this specific repository.
    async fn fetch_release_for(&self, coords: &WorkloadCoords) -> Result<Release, WorkloadError> {
        let tag = format_tag(coords);
        match self
            .client
            .try_get_release_by_tag(&self.repo, &tag)
            .await
            .map_err(WorkloadError::from)?
        {
            Some(r) => Ok(r),
            None => Err(WorkloadError::Repository {
                message: format!(
                    "no release tagged {tag} in github://{}",
                    self.repo
                ),
            }),
        }
    }

    /// Fetch the release for `coords`, returning `None` if it doesn't
    /// exist. Used by lookup methods that treat "not found in this
    /// repository" as a clean negative during discovery.
    async fn try_fetch_release(
        &self,
        coords: &WorkloadCoords,
    ) -> Result<Option<Release>, WorkloadError> {
        let tag = format_tag(coords);
        self.client
            .try_get_release_by_tag(&self.repo, &tag)
            .await
            .map_err(WorkloadError::from)
    }

    async fn meta_from_release(
        &self,
        release: &Release,
        coords: &WorkloadCoords,
    ) -> Result<RepositoryArchiveMeta, WorkloadError> {
        let asset = find_atawl_asset(release, coords)?;
        Ok(self
            .build_meta(release, coords, asset.size, asset.id)
            .await)
    }

    /// Build a metadata record for a release.
    ///
    /// If a sidecar `<stem>.meta.json` asset exists and its `name` /
    /// `version` / `workload_id` agree with what we derived from the
    /// release's tag and body, we trust and return its values. If the
    /// sidecar disagrees (malicious or stale), or is unparseable, we
    /// ignore it, emit a warning, and fall back to values derived from
    /// the tag / body / asset metadata only.
    ///
    /// This matters because `build_meta` feeds the integrity comparison
    /// in `workload pull`: if we trusted a lying sidecar, an attacker
    /// could adjust both the sidecar and the archive so the repo-level
    /// checks pass, defeating them. On-chain PCR23 would still catch it
    /// when configured, but the repo-level check is our first line of
    /// defence for workloads that aren't on-chain yet.
    async fn build_meta(
        &self,
        release: &Release,
        coords: &WorkloadCoords,
        archive_size: u64,
        _archive_asset_id: Option<u64>,
    ) -> RepositoryArchiveMeta {
        let stem = coords.asset_stem();
        let meta_name = format!("{stem}{META_EXT}");

        if let Some(meta_asset) = release.assets.iter().find(|a| a.name == meta_name) {
            // Refuse to download absurdly large sidecars. The asset
            // size is attacker-controlled (whoever publishes the
            // release decides), so without a cap a malicious repo
            // could OOM the client by uploading a huge `.meta.json`.
            // Real sidecars are typically <1 KiB; anything over
            // MAX_SIDECAR_SIZE is either buggy or hostile.
            if meta_asset.size > MAX_SIDECAR_SIZE {
                warn!(
                    repo = %self.repo,
                    asset = %meta_name,
                    size = meta_asset.size,
                    limit = MAX_SIDECAR_SIZE,
                    "sidecar exceeds size cap; ignoring and falling back to derived metadata"
                );
            } else {
                match download_asset_bytes(&self.client, meta_asset).await {
                    Ok(bytes) => match serde_json::from_slice::<RepositoryArchiveMeta>(&bytes) {
                        Ok(parsed) => {
                            if sidecar_matches_coords(&parsed, coords, release) {
                                return parsed;
                            }
                            warn!(
                                repo = %self.repo,
                                asset = %meta_name,
                                "sidecar disagrees with release tag/body; ignoring and falling back to derived metadata"
                            );
                        }
                        Err(e) => warn!(
                            repo = %self.repo,
                            asset = %meta_name,
                            error = %e,
                            "failed to parse sidecar; falling back to derived metadata"
                        ),
                    },
                    Err(e) => warn!(
                        repo = %self.repo,
                        asset = %meta_name,
                        error = %e,
                        "failed to download sidecar; falling back to derived metadata"
                    ),
                }
            }
        }

        // Sidecar missing or rejected: derive what we can.
        let body = release.body.as_deref().unwrap_or("");
        let workload_id = parse_body_field(body, "Workload ID")
            .unwrap_or_else(|| coords.workload_id.clone());
        let sha256 = parse_body_field(body, "Manifest SHA256").unwrap_or_default();
        let uploaded_at = release.published_at.clone().unwrap_or_default();

        RepositoryArchiveMeta {
            workload_id,
            name: coords.name.clone(),
            version: coords.version.clone(),
            owner: String::new(),
            sha256,
            archive_size,
            archive_hash: String::new(),
            uploaded_at,
        }
    }

    /// List up to LIST_PAGE_SIZE most recent releases.
    async fn list_releases_paged(&self) -> Result<Vec<Release>, WorkloadError> {
        self.client
            .list_releases(&self.repo, LIST_PAGE_SIZE)
            .await
            .map_err(WorkloadError::from)
    }
}

// ── free helpers ───────────────────────────────────────────────

/// Build the git tag for a workload: `<name>/<version>`.
fn format_tag(coords: &WorkloadCoords) -> String {
    format!("{}/{}", coords.name, coords.version)
}

/// Format the release body with one `key: value` per line.
fn format_release_body(
    coords: &WorkloadCoords,
    manifest_sha256: &str,
    pcr23: &str,
    archive_size: u64,
) -> String {
    format!(
        "{name} {version}\n\n\
         Workload ID: {id}\n\
         Manifest SHA256: {sha256}\n\
         PCR23: {pcr23}\n\
         Archive size: {size} bytes\n",
        name = coords.name,
        version = coords.version,
        id = coords.workload_id,
        sha256 = manifest_sha256,
        pcr23 = pcr23,
        size = archive_size,
    )
}

/// Pull a `Key: value` field out of the release body.
fn parse_body_field(body: &str, key: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(rest) = rest.strip_prefix(':') {
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}

/// Decide whether a sidecar `meta.json` asset is trustworthy enough to
/// return verbatim. We require:
///
/// 1. Its `name` and `version` match the tag-derived coords exactly.
/// 2. Its `workload_id` matches what we expect for those coords, either
///    (a) equal to `coords.workload_id`, or (b) equal to whatever the
///    release body's `Workload ID` line advertises (both should be the
///    same in practice -- if they differ the sidecar is suspect).
///
/// If the sidecar disagrees, the caller falls back to derived values
/// and emits a warning. This is defence in depth: a tampered sidecar
/// that lies about `workload_id`/`sha256`/`archive_hash` could otherwise
/// slip past the repo-level integrity check in `workload pull` when
/// on-chain verification is not configured.
fn sidecar_matches_coords(
    sidecar: &RepositoryArchiveMeta,
    coords: &WorkloadCoords,
    release: &Release,
) -> bool {
    if sidecar.name != coords.name || sidecar.version != coords.version {
        return false;
    }
    if !sidecar.workload_id.eq_ignore_ascii_case(&coords.workload_id) {
        return false;
    }
    // Optional: cross-check against the body line too.
    if let Some(body) = release.body.as_deref() {
        if let Some(body_id) = parse_body_field(body, "Workload ID") {
            if !body_id.eq_ignore_ascii_case(&sidecar.workload_id) {
                return false;
            }
        }
    }
    true
}

/// Parse `<name>/<version>` out of the release tag.
fn parse_tag(tag: &str) -> Option<(String, String)> {
    let (name, version) = tag.split_once('/')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn parse_coords_from_release(release: &Release) -> Result<WorkloadCoords, WorkloadError> {
    let (name, version) =
        parse_tag(&release.tag_name).ok_or_else(|| WorkloadError::Repository {
            message: format!(
                "release tag '{}' is not in '<name>/<version>' format",
                release.tag_name
            ),
        })?;
    let workload_id = release
        .body
        .as_deref()
        .and_then(|b| parse_body_field(b, "Workload ID"))
        .unwrap_or_default();
    Ok(WorkloadCoords {
        workload_id,
        name,
        version,
    })
}

fn find_atawl_asset<'a>(
    release: &'a Release,
    coords: &WorkloadCoords,
) -> Result<&'a GhAsset, WorkloadError> {
    let canonical = format!("{}{ATAWL_EXT}", coords.asset_stem());
    if let Some(a) = release.assets.iter().find(|a| a.name == canonical) {
        return Ok(a);
    }
    if let Some(a) = release.assets.iter().find(|a| a.name.ends_with(ATAWL_EXT)) {
        return Ok(a);
    }
    Err(WorkloadError::Repository {
        message: format!(
            "release {tag} has no .atawl asset",
            tag = release.tag_name
        ),
    })
}

async fn hash_archive_file(path: &Path) -> Result<(u64, String), WorkloadError> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| WorkloadError::ReadFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf).await.map_err(|e| WorkloadError::ReadFile {
            path: path.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let hash = format!("0x{}", hex::encode(hasher.finalize()));
    Ok((total, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coords() -> WorkloadCoords {
        WorkloadCoords {
            workload_id: "0xabc".into(),
            name: "secure-signer".into(),
            version: "v0.0.1".into(),
        }
    }

    #[test]
    fn tag_format() {
        assert_eq!(format_tag(&coords()), "secure-signer/v0.0.1");
    }

    #[test]
    fn asset_stem() {
        assert_eq!(coords().asset_stem(), "secure-signer-v0.0.1");
    }

    #[test]
    fn parse_tag_basic() {
        assert_eq!(
            parse_tag("secure-signer/v0.0.1"),
            Some(("secure-signer".into(), "v0.0.1".into()))
        );
    }

    #[test]
    fn parse_tag_version_with_slash_keeps_first_split() {
        // Versions shouldn't contain `/` but if they do, we still split on
        // first `/` so the version captures everything after.
        assert_eq!(
            parse_tag("name/v1.0/extra"),
            Some(("name".into(), "v1.0/extra".into()))
        );
    }

    #[test]
    fn parse_tag_invalid() {
        assert_eq!(parse_tag("nameonly"), None);
        assert_eq!(parse_tag("/v1"), None);
        assert_eq!(parse_tag("name/"), None);
    }

    #[test]
    fn parse_body_field_extracts_value() {
        let body = "secure-signer v0.0.1\n\nWorkload ID: 0xabc\nManifest SHA256: 0xdef\nPCR23: 0xfeed\n";
        assert_eq!(
            parse_body_field(body, "Workload ID"),
            Some("0xabc".to_string())
        );
        assert_eq!(
            parse_body_field(body, "Manifest SHA256"),
            Some("0xdef".to_string())
        );
        assert_eq!(parse_body_field(body, "Missing"), None);
    }

    #[test]
    fn format_release_body_round_trips() {
        let body = format_release_body(&coords(), "0xdead", "0xbeef", 1234);
        assert_eq!(parse_body_field(&body, "Workload ID"), Some("0xabc".into()));
        assert_eq!(
            parse_body_field(&body, "Manifest SHA256"),
            Some("0xdead".into())
        );
        assert_eq!(parse_body_field(&body, "PCR23"), Some("0xbeef".into()));
    }
}
