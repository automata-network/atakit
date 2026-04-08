use std::path::{Path, PathBuf};

use atakit_core::ProgressReporter;
use futures_util::StreamExt;
use reqwest::header::{self, HeaderValue};
use tokio::io::{AsyncWriteExt, BufWriter};
use tracing::{debug, info};

use crate::client::ReleasesClient;
use crate::error::{GithubError, Result};
use crate::types::Asset;

/// Options controlling how assets are downloaded.
pub struct DownloadOptions {
    /// Directory to save files into.
    pub dest_dir: PathBuf,
    /// Skip the download if the target file already exists.
    pub skip_existing: bool,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            dest_dir: PathBuf::from("."),
            skip_existing: true,
        }
    }
}

impl DownloadOptions {
    pub fn dest_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dest_dir = dir.into();
        self
    }

    pub fn skip_existing(mut self, yes: bool) -> Self {
        self.skip_existing = yes;
        self
    }
}

/// Download a release asset to the local filesystem under `opts.dest_dir`,
/// using the asset's `name` as the filename.
///
/// Returns the path to the downloaded file.
pub async fn download_asset(
    client: &ReleasesClient,
    asset: &Asset,
    opts: &DownloadOptions,
    progress: &dyn ProgressReporter,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(&opts.dest_dir)
        .await
        .map_err(|e| GithubError::CreateDir {
            path: opts.dest_dir.clone(),
            source: e,
        })?;

    let dest = opts.dest_dir.join(&asset.name);

    if opts.skip_existing && dest.exists() {
        info!(path = %dest.display(), "file already exists, skipping download");
        return Ok(dest);
    }

    download_asset_to_path(client, asset, &dest, progress).await?;

    Ok(dest)
}

/// Stream-download a single asset to a specific path, reporting progress.
///
/// Unlike [`download_asset`], the caller controls the destination filename.
pub async fn download_asset_to_path(
    client: &ReleasesClient,
    asset: &Asset,
    dest: &Path,
    progress: &dyn ProgressReporter,
) -> Result<u64> {
    let url = asset_download_url(client, asset);
    debug!(%url, dest = %dest.display(), "downloading asset");

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("atakit"));
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Some(token) = client.token() {
        if let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(header::AUTHORIZATION, val);
        }
    }

    let resp = client.http().get(&url).headers(headers).send().await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(GithubError::DownloadFailed {
            status: status.as_u16(),
            body,
        });
    }

    let total = resp.content_length().unwrap_or(asset.size);

    let handle = progress.create(&asset.name, total);

    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| GithubError::CreateDir {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
        }
    }

    let file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| GithubError::CreateFile {
            path: dest.to_path_buf(),
            source: e,
        })?;
    let mut writer = BufWriter::with_capacity(512 * 1024, file);

    let mut written: u64 = 0;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        writer
            .write_all(&chunk)
            .await
            .map_err(|e| GithubError::WriteFile {
                path: dest.to_path_buf(),
                source: e,
            })?;
        written += chunk.len() as u64;
        handle.inc(chunk.len() as u64);
    }

    writer.flush().await.map_err(|e| GithubError::WriteFile {
        path: dest.to_path_buf(),
        source: e,
    })?;
    handle.finish();

    info!(path = %dest.display(), "download complete");
    Ok(written)
}

/// Download an asset's full body into memory. Useful for small sidecar files
/// like a JSON metadata blob; do not use for large archives.
pub async fn download_asset_bytes(
    client: &ReleasesClient,
    asset: &Asset,
) -> Result<Vec<u8>> {
    let url = asset_download_url(client, asset);
    debug!(%url, "downloading asset bytes");

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("atakit"));
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Some(token) = client.token() {
        if let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(header::AUTHORIZATION, val);
        }
    }

    let resp = client.http().get(&url).headers(headers).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(GithubError::DownloadFailed {
            status: status.as_u16(),
            body,
        });
    }
    Ok(resp.bytes().await?.to_vec())
}

/// Choose the right URL for downloading: API url (authenticated) or
/// browser_download_url (public).
fn asset_download_url(client: &ReleasesClient, asset: &Asset) -> String {
    if client.token().is_some() {
        asset.url.clone()
    } else {
        asset.browser_download_url.clone()
    }
}
