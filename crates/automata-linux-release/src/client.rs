use std::env;

use anyhow::{Context, Result, bail};
use reqwest::header::{self, HeaderMap, HeaderValue};
use tracing::debug;

use crate::{
    REPO,
    types::{ImageRef, Platform, Release, VersionSelector},
};

/// Async client for the GitHub Releases API.
///
/// Works with any `owner/repo`, not tied to a specific repository.
pub struct ReleasesClient {
    token: Option<String>,
    http: reqwest::Client,
}

impl ReleasesClient {
    /// Create a new client for the given repository.
    ///
    /// `repo` must be in `"owner/repo"` format.
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

    fn map_repo<'a>(&self, repo: &'a str) -> &'a str {
        if repo == "automata-linux" { REPO } else { repo }
    }

    /// List the most recent releases (up to `per_page`, max 100).
    pub async fn list_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>> {
        let url = format!(
            "https://api.github.com/repos/{}/releases?per_page={}",
            self.map_repo(repo),
            per_page.min(100),
        );
        self.get_json(&url).await
    }

    /// Fetch a specific release by its Git tag.
    pub async fn get_release(&self, image_ref: &ImageRef) -> Result<Release> {
        let url = format!(
            "https://api.github.com/repos/{}/releases/tags/{}",
            self.map_repo(&image_ref.repository),
            image_ref.tag,
        );
        self.get_json(&url).await
    }

    /// Fetch the release marked as "latest" by GitHub.
    pub async fn get_latest_release(&self, repo: &str) -> Result<Release> {
        let url = format!("https://api.github.com/repos/{}/releases/latest", self.map_repo(&repo));
        self.get_json(&url).await
    }

    // ── high-level API ─────────────────────────────────────────────

    /// Find the most recent release that contains at least one disk image.
    ///
    /// Scans up to 20 recent releases and returns the first one with disk
    /// image assets.
    pub async fn find_latest_image_release(&self, repo: &str) -> Result<Release> {
        debug!("scanning recent releases for disk images");
        let releases = self.list_releases(repo, 20).await?;

        releases
            .into_iter()
            .find(|r| r.has_disk_images())
            .context("no release containing disk images found in the last 20 releases")
    }

    /// Find the most recent release that contains a disk image for the given
    /// platform.
    pub async fn find_latest_release_for(&self, repo: &str, platform: Platform) -> Result<Release> {
        debug!(
            ?platform,
            "scanning recent releases for platform disk image"
        );
        let releases = self.list_releases(repo, 20).await?;

        releases
            .into_iter()
            .find(|r| r.disk_image(platform).is_some())
            .with_context(|| {
                format!(
                    "no release containing a {platform:?} disk image found in the last 20 releases",
                )
            })
    }

    /// Resolve a [`VersionSelector`] into a concrete [`Release`].
    ///
    /// This is the primary entry-point for "select a version": callers
    /// describe *what* they want and this method figures out how to get it.
    pub async fn resolve(&self, repo: &str, selector: &VersionSelector) -> Result<Release> {
        match selector {
            VersionSelector::Latest => self.get_latest_release(repo).await,
            VersionSelector::LatestImage => self.find_latest_image_release(repo).await,
            VersionSelector::LatestImageFor(p) => self.find_latest_release_for(repo, *p).await,
            VersionSelector::Tag(image_ref) => self.get_release(image_ref).await,
        }
    }

    /// List recent releases that contain at least one disk image.
    pub async fn list_image_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>> {
        let all = self.list_releases(repo, per_page).await?;
        Ok(all.into_iter().filter(|r| r.has_disk_images()).collect())
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
        headers.insert(header::USER_AGENT, HeaderValue::from_static("ata-releases"));
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
            .await
            .context("HTTP request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("GitHub API returned {status}: {body}");
        }

        resp.json()
            .await
            .context("failed to parse GitHub API response")
    }
}
