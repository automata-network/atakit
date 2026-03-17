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
    /// Automatically decompress `.xz` and `.zip` assets after download.
    pub auto_decompress: bool,
    /// Skip the download if the target file already exists.
    pub skip_existing: bool,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            dest_dir: PathBuf::from("."),
            auto_decompress: true,
            skip_existing: true,
        }
    }
}

impl DownloadOptions {
    pub fn dest_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dest_dir = dir.into();
        self
    }

    pub fn auto_decompress(mut self, yes: bool) -> Self {
        self.auto_decompress = yes;
        self
    }

    pub fn skip_existing(mut self, yes: bool) -> Self {
        self.skip_existing = yes;
        self
    }
}

/// Download a release asset to the local filesystem.
///
/// Returns the path to the final file (after any decompression).
///
/// When `auto_decompress` is enabled:
/// - `.vhd.xz` files are decompressed to `.vhd` via the `xz` CLI
/// - `.zip` files are extracted into the destination directory via the `unzip` CLI
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
    let final_path = if opts.auto_decompress {
        decompressed_name(&dest)
    } else {
        dest.clone()
    };

    if opts.skip_existing && final_path.exists() {
        info!(path = %final_path.display(), "file already exists, skipping download");
        return Ok(final_path);
    }

    download_raw(client, asset, &dest, progress).await?;

    if opts.auto_decompress {
        maybe_decompress(&dest).await?;
    }

    Ok(final_path)
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

/// Determine the final filename after decompression.
fn decompressed_name(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    if name.ends_with(".vhd.xz") {
        path.with_file_name(name.trim_end_matches(".xz"))
    } else if name.ends_with(".zip") {
        // zip extracts to the same directory, return the directory
        path.parent().unwrap_or(path).to_path_buf()
    } else {
        path.to_path_buf()
    }
}

/// Decompress the downloaded file if it has a known compressed extension.
async fn maybe_decompress(path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    if name.ends_with(".xz") {
        decompress_xz(path).await?;
    } else if name.ends_with(".zip") {
        let dest_dir = path.parent().unwrap_or(Path::new("."));
        extract_zip(path, dest_dir).await?;
    }
    Ok(())
}

/// Decompress an `.xz` file using the system `xz` command.
///
/// The compressed file is removed after successful decompression.
pub async fn decompress_xz(src: &Path) -> Result<()> {
    info!(src = %src.display(), "decompressing xz");
    let status = tokio::process::Command::new("xz")
        .args(["-d", "-v"])
        .arg(src)
        .status()
        .await
        .map_err(|e| ImageError::Decompress(format!("failed to run xz: {e}")))?;

    if !status.success() {
        return Err(ImageError::Decompress(format!(
            "xz decompression failed with {status}"
        )));
    }
    Ok(())
}

/// Extract a `.zip` archive into `dest_dir` using the system `unzip` command.
///
/// The zip file is removed after successful extraction.
pub async fn extract_zip(src: &Path, dest_dir: &Path) -> Result<()> {
    info!(src = %src.display(), dest = %dest_dir.display(), "extracting zip");
    let status = tokio::process::Command::new("unzip")
        .args(["-o"])
        .arg(src)
        .arg("-d")
        .arg(dest_dir)
        .status()
        .await
        .map_err(|e| ImageError::Decompress(format!("failed to run unzip: {e}")))?;

    if !status.success() {
        return Err(ImageError::Decompress(format!(
            "zip extraction failed with {status}"
        )));
    }

    tokio::fs::remove_file(src).await.map_err(|e| ImageError::Remove {
        path: src.to_path_buf(),
        source: e,
    })?;

    Ok(())
}
