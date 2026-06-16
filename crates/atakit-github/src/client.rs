use reqwest::header::{self, HeaderMap, HeaderValue};
use tracing::debug;

use crate::error::{GithubError, Result};
use crate::types::{CreateReleaseRequest, Release};

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

    /// Authenticate with a GitHub token (required for private repos and writes).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    // ── reads ──────────────────────────────────────────────

    /// List the most recent releases (up to `per_page`, max 100).
    ///
    /// `repo` must be the full GitHub `owner/repo` path.
    pub async fn list_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>> {
        validate_repo(repo)?;
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
    pub async fn get_release_by_tag(&self, repo: &str, tag: &str) -> Result<Release> {
        validate_repo(repo)?;
        let url = format!(
            "https://api.github.com/repos/{}/releases/tags/{}",
            repo,
            urlencode_path_segment(tag),
        );
        self.get_json(&url).await
    }

    /// Try to fetch a release by tag, returning `None` on 404.
    pub async fn try_get_release_by_tag(&self, repo: &str, tag: &str) -> Result<Option<Release>> {
        match self.get_release_by_tag(repo, tag).await {
            Ok(r) => Ok(Some(r)),
            Err(GithubError::Api { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Fetch the release marked as "latest" by GitHub.
    pub async fn get_latest_release(&self, repo: &str) -> Result<Release> {
        validate_repo(repo)?;
        let url = format!("https://api.github.com/repos/{}/releases/latest", repo);
        self.get_json(&url).await
    }

    // ── writes ─────────────────────────────────────────────

    /// Create a new release. Requires a token with `contents: write`.
    pub async fn create_release(&self, repo: &str, req: &CreateReleaseRequest) -> Result<Release> {
        validate_repo(repo)?;
        let url = format!("https://api.github.com/repos/{}/releases", repo);
        debug!(%url, tag = %req.tag_name, "creating GitHub release");

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .header(header::ACCEPT, "application/vnd.github+json")
            .json(req)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GithubError::Api {
                status: status.as_u16(),
                body,
            });
        }

        Ok(resp.json().await?)
    }

    /// Delete a release by its numeric ID. Requires `contents: write`.
    pub async fn delete_release(&self, repo: &str, release_id: u64) -> Result<()> {
        validate_repo(repo)?;
        let url = format!(
            "https://api.github.com/repos/{}/releases/{}",
            repo, release_id
        );
        let resp = self
            .http
            .delete(&url)
            .headers(self.auth_headers())
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GithubError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    /// Build the upload URL for an asset, given the release's `upload_url` template.
    ///
    /// GitHub returns the template like
    /// `https://uploads.github.com/repos/o/r/releases/123/assets{?name,label}`.
    /// We strip the template suffix and append `?name=<asset>`.
    pub fn build_asset_upload_url(upload_url_template: &str, asset_name: &str) -> String {
        let base = match upload_url_template.find('{') {
            Some(idx) => &upload_url_template[..idx],
            None => upload_url_template,
        };
        format!(
            "{}?name={}",
            base.trim_end_matches('/'),
            urlencode_query_value(asset_name)
        )
    }

    // ── crate-internal accessors (used by download.rs) ────────────

    pub(crate) fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("atakit"));
        if let Some(ref token) = self.token {
            if let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(header::AUTHORIZATION, val);
            }
        }
        headers
    }

    // ── internals ──────────────────────────────────────────────────

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
            return Err(GithubError::Api {
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

/// Validate that `repo` looks like `owner/name` (one slash, non-empty halves).
fn validate_repo(repo: &str) -> Result<()> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if owner.is_empty() || name.is_empty() || parts.next().is_some() {
        return Err(GithubError::InvalidRepo(repo.to_string()));
    }
    Ok(())
}

/// Percent-encode a path segment following RFC 3986 unreserved rules.
/// `/` is encoded as `%2F` so that multi-segment tags like
/// `release/v1.0.0` are treated as a single path parameter by the
/// GitHub API instead of splitting into two segments.
fn urlencode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn urlencode_query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_upload_url_strips_template() {
        let template = "https://uploads.github.com/repos/o/r/releases/123/assets{?name,label}";
        assert_eq!(
            ReleasesClient::build_asset_upload_url(template, "foo-v0.0.1.atawl"),
            "https://uploads.github.com/repos/o/r/releases/123/assets?name=foo-v0.0.1.atawl"
        );
    }

    #[test]
    fn build_upload_url_no_template() {
        let plain = "https://uploads.github.com/repos/o/r/releases/123/assets";
        assert_eq!(
            ReleasesClient::build_asset_upload_url(plain, "x"),
            "https://uploads.github.com/repos/o/r/releases/123/assets?name=x"
        );
    }

    #[test]
    fn validate_repo_ok() {
        assert!(validate_repo("owner/repo").is_ok());
        assert!(validate_repo("a/b").is_ok());
    }

    #[test]
    fn validate_repo_bad() {
        assert!(validate_repo("ownerrepo").is_err());
        assert!(validate_repo("owner/").is_err());
        assert!(validate_repo("/repo").is_err());
        assert!(validate_repo("owner/repo/extra").is_err());
    }

    #[test]
    fn urlencode_path_segment_escapes_slash() {
        // Slashes in workload tags (`<name>/<version>`) must be
        // percent-encoded or GitHub's URL matcher may treat them as
        // path segments and return 404.
        assert_eq!(
            urlencode_path_segment("secure-signer/v0.0.1"),
            "secure-signer%2Fv0.0.1"
        );
    }

    #[test]
    fn urlencode_path_segment_keeps_unreserved() {
        assert_eq!(urlencode_path_segment("abc-123_v0.0.1"), "abc-123_v0.0.1");
    }

    #[test]
    fn urlencode_path_segment_escapes_special() {
        assert_eq!(urlencode_path_segment("foo bar"), "foo%20bar");
        assert_eq!(urlencode_path_segment("a@b"), "a%40b");
    }
}
