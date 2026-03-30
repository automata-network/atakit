use std::path::{Path, PathBuf};

use atakit_core::ProgressReporter;
use futures_util::StreamExt;
use reqwest::header::{self, HeaderValue};
use tokio::io::{AsyncWriteExt, BufWriter};
use tracing::{debug, info};

use crate::client::ReleasesClient;
use crate::error::{ImageError, Result};
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

/// Download a release asset to the local filesystem.
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
        .map_err(|e| ImageError::CreateDir {
            path: opts.dest_dir.clone(),
            source: e,
        })?;

    let dest = opts.dest_dir.join(&asset.name);

    if opts.skip_existing && dest.exists() {
        info!(path = %dest.display(), "file already exists, skipping download");
        return Ok(dest);
    }

    download_raw(client, asset, &dest, progress).await?;

    Ok(dest)
}

/// Stream-download a single asset to `dest`, reporting progress via the trait.
async fn download_raw(
    client: &ReleasesClient,
    asset: &Asset,
    dest: &Path,
    progress: &dyn ProgressReporter,
) -> Result<()> {
    let url = asset_download_url(client, asset);
    debug!(%url, dest = %dest.display(), "downloading asset");

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("atakit"),
    );
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Some(token) = client.token() {
        if let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(header::AUTHORIZATION, val);
        }
    }

    let resp = client
        .http()
        .get(&url)
        .headers(headers)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ImageError::DownloadFailed {
            status: status.as_u16(),
            body,
        });
    }

    let total = resp.content_length().unwrap_or(asset.size);

    let handle = progress.create(&asset.name, total);

    let file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| ImageError::CreateFile {
            path: dest.to_path_buf(),
            source: e,
        })?;
    let mut writer = BufWriter::with_capacity(512 * 1024, file);

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        writer
            .write_all(&chunk)
            .await
            .map_err(|e| ImageError::WriteFile {
                path: dest.to_path_buf(),
                source: e,
            })?;
        handle.inc(chunk.len() as u64);
    }

    writer.flush().await.map_err(|e| ImageError::WriteFile {
        path: dest.to_path_buf(),
        source: e,
    })?;
    handle.finish();

    info!(
        path = %dest.display(),
        "download complete",
    );
    Ok(())
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

