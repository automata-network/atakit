use serde::{Deserialize, Serialize};

/// A GitHub release.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub assets: Vec<Asset>,
    /// Upload URL template for attaching assets, e.g.
    /// `https://uploads.github.com/repos/owner/repo/releases/{id}/assets{?name,label}`.
    #[serde(default)]
    pub upload_url: Option<String>,
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(default)]
    pub html_url: Option<String>,
}

/// A single asset attached to a release.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
    /// API URL used for authenticated downloads.
    pub url: String,
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub id: Option<u64>,
}

/// Body for `POST /repos/{owner}/{repo}/releases`.
#[derive(Clone, Debug, Serialize)]
pub struct CreateReleaseRequest {
    pub tag_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prerelease: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_commitish: Option<String>,
}
