use std::env;

use reqwest::header::{self, HeaderMap, HeaderValue};
use tracing::debug;

use crate::error::{ImageError, Result};
use crate::types::{Platform, Release, VersionSelector};

/// Async client for the GitHub Releases API.
pub struct ReleasesClient {
    token: Option<String>,
    http: reqwest::Client,
}

impl ReleasesClient {
    /// Create a new client.
    pub fn new() -> Self {
        Self {
            token: None,
            http: reqwest::Client::new(),
        }
    }

    /// Authenticate with a GitHub token (required for private repos).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Read authentication token from the `GITHUB_TOKEN` environment variable.
    ///
    /// No-op if the variable is unset or empty.
    pub fn with_token_from_env(mut self) -> Self {
        if let Ok(t) = env::var("GITHUB_TOKEN") {
            if !t.is_empty() {
                self.token = Some(t);
            }
        }
        self
    }

    // ── low-level API ──────────────────────────────────────────────

    /// List the most recent releases (up to `per_page`, max 100).
    ///
    /// `repo` must be the full GitHub `owner/repo` path.
    pub async fn list_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>> {
        let url = format!(
            "https://api.github.com/repos/{}/releases?per_page={}",
            repo,
            per_page.min(100),
        );
        self.get_json(&url).await
    }

    /// Fetch a specific release by its Git tag.
    ///
    /// `repo` must be the full GitHub `owner/repo` path.
    pub async fn get_release(&self, repo: &str, tag: &str) -> Result<Release> {
        let url = format!(
            "https://api.github.com/repos/{}/releases/tags/{}",
            repo, tag,
        );
        self.get_json(&url).await
    }

    /// Fetch the release marked as "latest" by GitHub.
    ///
    /// `repo` must be the full GitHub `owner/repo` path.
    pub async fn get_latest_release(&self, repo: &str) -> Result<Release> {
        let url = format!(
            "https://api.github.com/repos/{}/releases/latest",
            repo
        );
        self.get_json(&url).await
    }

    // ── high-level API ─────────────────────────────────────────────

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
    pub async fn find_latest_release_for(
        &self,
        repo: &str,
        platform: Platform,
    ) -> Result<Release> {
        debug!(
            ?platform,
            "scanning recent releases for platform archive"
        );
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
            VersionSelector::Tag(image_ref) => {
                self.get_release(repo, &image_ref.tag).await
            }
        }
    }

    /// List recent releases that contain at least one `.atabi` archive.
    pub async fn list_image_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>> {
        let all = self.list_releases(repo, per_page).await?;
        Ok(all.into_iter().filter(|r| r.has_archives()).collect())
    }

    // ── crate-internal accessors (used by download.rs) ────────────

    pub(crate) fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    // ── internals ──────────────────────────────────────────────────

    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("atakit"));
        if let Some(ref token) = self.token {
            if let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(header::AUTHORIZATION, val);
            }
        }
        headers
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        debug!(%url, "GET");
        let resp = self
            .http
            .get(url)
            .headers(self.auth_headers())
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ImageError::Api {
                status: status.as_u16(),
                body,
            });
        }

        Ok(resp.json().await?)
    }
}

impl Default for ReleasesClient {
    fn default() -> Self {
        Self::new()
    }
}
