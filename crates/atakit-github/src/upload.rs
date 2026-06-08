use std::path::Path;

use reqwest::header::{self, HeaderValue};
use tracing::debug;

use crate::client::ReleasesClient;
use crate::error::{GithubError, Result};
use crate::types::Asset;

/// Upload a file as an asset on a release.
///
/// `release_upload_url` is the `upload_url` template returned by the create
/// release endpoint, e.g.
/// `https://uploads.github.com/repos/owner/repo/releases/123/assets{?name,label}`.
///
/// `asset_name` is the filename to publish on GitHub.
///
/// Streams the file body so large archives don't have to fit in memory.
pub async fn upload_release_asset(
    client: &ReleasesClient,
    release_upload_url: &str,
    asset_name: &str,
    file_path: &Path,
    content_type: &str,
) -> Result<Asset> {
    let file = tokio::fs::File::open(file_path)
        .await
        .map_err(|e| GithubError::ReadFile {
            path: file_path.to_path_buf(),
            source: e,
        })?;
    let metadata = file.metadata().await.map_err(|e| GithubError::ReadFile {
        path: file_path.to_path_buf(),
        source: e,
    })?;
    let total = metadata.len();

    let url = ReleasesClient::build_asset_upload_url(release_upload_url, asset_name);
    debug!(%url, asset_name, total, "uploading release asset");

    let body = reqwest::Body::from(file);

    let mut headers = client.auth_headers();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(total));
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );

    let resp = client
        .http()
        .post(&url)
        .headers(headers)
        .body(body)
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

    let asset: Asset = resp.json().await?;
    Ok(asset)
}

/// Upload a small in-memory body (e.g. a JSON sidecar) as a release asset.
pub async fn upload_release_asset_bytes(
    client: &ReleasesClient,
    release_upload_url: &str,
    asset_name: &str,
    body: Vec<u8>,
    content_type: &str,
) -> Result<Asset> {
    let url = ReleasesClient::build_asset_upload_url(release_upload_url, asset_name);
    let total = body.len() as u64;
    debug!(%url, asset_name, total, "uploading release asset (bytes)");

    let mut headers = client.auth_headers();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(total));
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );

    let resp = client
        .http()
        .post(&url)
        .headers(headers)
        .body(body)
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

    let asset: Asset = resp.json().await?;
    Ok(asset)
}
