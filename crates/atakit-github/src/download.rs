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

/// Download an asset's full body into memory with a hard size cap.
///
/// Useful for small sidecar files like a JSON metadata blob. The
/// `max_bytes` parameter bounds the total bytes read from the
/// response body so a malicious server (or compromised release)
/// cannot OOM the client by sending an arbitrarily large payload.
///
/// Defence in depth:
/// 1. If the response carries a `Content-Length` header that exceeds
///    `max_bytes`, the download is rejected immediately without
///    reading the body.
/// 2. Even if `Content-Length` is absent or lies (claims small but
///    sends big), the streaming read loop aborts as soon as the
///    running byte count passes `max_bytes`.
pub async fn download_asset_bytes(
    client: &ReleasesClient,
    asset: &Asset,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let url = asset_download_url(client, asset);
    debug!(%url, max_bytes, "downloading asset bytes");

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
        // Truncate error bodies too -- a malicious server could
        // send a huge error response.
        let body = if body.len() > max_bytes as usize {
            let mut truncated = body[..max_bytes as usize].to_string();
            truncated.push_str("...(truncated)");
            truncated
        } else {
            body
        };
        return Err(GithubError::DownloadFailed {
            status: status.as_u16(),
            body,
        });
    }

    // Early rejection: if Content-Length exceeds the cap, don't
    // start reading.
    if let Some(len) = resp.content_length() {
        if len > max_bytes {
            return Err(GithubError::DownloadTooLarge { limit: max_bytes });
        }
    }

    // Stream with running cap. Content-Length can be absent or lie
    // (claims small, sends big), so we enforce the cap on actual
    // bytes received regardless.
    let hint = resp.content_length().unwrap_or(0).min(max_bytes) as usize;
    let mut buf = Vec::with_capacity(hint);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > max_bytes as usize {
            return Err(GithubError::DownloadTooLarge { limit: max_bytes });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
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
