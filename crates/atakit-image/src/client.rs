use atakit_github::ReleasesClient as InnerClient;
use tracing::debug;

use crate::error::{ImageError, Result};
use crate::types::{Platform, Release, VersionSelector};

/// Async client for the GitHub Releases API, specialised for image releases.
///
/// Wraps the generic [`atakit_github::ReleasesClient`] with image-specific
/// helpers (filtering for `.atabi` archives, platform lookups, etc).
pub struct ReleasesClient {
    inner: InnerClient,
}

impl ReleasesClient {
    /// Create a new client.
    pub fn new() -> Self {
        Self {
            inner: InnerClient::new(),
        }
    }

    /// Authenticate with a GitHub token (required for private repos).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.inner = self.inner.with_token(token);
        self
    }

    /// Borrow the underlying generic client (used by the download module).
    pub(crate) fn inner(&self) -> &InnerClient {
        &self.inner
    }

    // ── low-level API ──────────────────────────────────────────────

    /// List the most recent releases (up to `per_page`, max 100).
    pub async fn list_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>> {
        let raw = self.inner.list_releases(repo, per_page).await?;
        Ok(raw.into_iter().map(Release::from).collect())
    }

    /// Fetch a specific release by its Git tag.
    pub async fn get_release_by_tag(&self, repo: &str, tag: &str) -> Result<Release> {
        Ok(self.inner.get_release_by_tag(repo, tag).await?.into())
    }

    /// Fetch the release marked as "latest" by GitHub.
    pub async fn get_latest_release(&self, repo: &str) -> Result<Release> {
        Ok(self.inner.get_latest_release(repo).await?.into())
    }

    // ── high-level (image-specific) API ────────────────────────────

    /// Find the most recent release that contains at least one `.atabi` archive.
    pub async fn find_latest_image_release(&self, repo: &str) -> Result<Release> {
        debug!("scanning recent releases for .atabi archives");
        let releases = self.list_releases(repo, 20).await?;

        releases
            .into_iter()
            .find(|r| r.has_archives())
            .ok_or(ImageError::NoDiskImages(20))
    }

    /// Find the most recent release that contains an `.atabi` archive for the
    /// given platform.
    pub async fn find_latest_release_for(&self, repo: &str, platform: Platform) -> Result<Release> {
        debug!(?platform, "scanning recent releases for platform archive");
        let releases = self.list_releases(repo, 20).await?;

        releases
            .into_iter()
            .find(|r| r.archive_for_platform(platform).is_some())
            .ok_or(ImageError::NoPlatformImage {
                platform: platform.to_string(),
                count: 20,
            })
    }

    /// Resolve a [`VersionSelector`] into a concrete [`Release`].
    pub async fn resolve(&self, repo: &str, selector: &VersionSelector) -> Result<Release> {
        match selector {
            VersionSelector::Latest => self.get_latest_release(repo).await,
            VersionSelector::LatestImage => self.find_latest_image_release(repo).await,
            VersionSelector::LatestImageFor(p) => self.find_latest_release_for(repo, *p).await,
            VersionSelector::Tag(image_ref) => self.get_release_by_tag(repo, &image_ref.tag).await,
        }
    }

    /// List recent releases that contain at least one `.atabi` archive.
    pub async fn list_image_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>> {
        let all = self.list_releases(repo, per_page).await?;
        Ok(all.into_iter().filter(|r| r.has_archives()).collect())
    }
}

impl Default for ReleasesClient {
    fn default() -> Self {
        Self::new()
    }
}
