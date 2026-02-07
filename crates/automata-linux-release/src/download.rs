use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::header::{self, HeaderValue};
use tokio::io::{AsyncWriteExt, BufWriter};
use tracing::{debug, info};

use crate::client::ReleasesClient;
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
    /// Set the destination directory (builder-style).
    pub fn dest_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dest_dir = dir.into();
        self
    }

    /// Set auto-decompress behaviour (builder-style).
    pub fn auto_decompress(mut self, yes: bool) -> Self {
        self.auto_decompress = yes;
        self
    }

    /// Set skip-existing behaviour (builder-style).
    pub fn skip_existing(mut self, yes: bool) -> Self {
        self.skip_existing = yes;
        self
    }
}

impl ReleasesClient {
    /// Download a release asset to the local filesystem.
    ///
    /// Returns the path to the final file (after any decompression).
    ///
    /// When `auto_decompress` is enabled:
    /// - `.vhd.xz` files are decompressed to `.vhd` via the `xz` CLI
    /// - `.zip` files are extracted into the destination directory via the `unzip` CLI
    pub async fn download_asset(
        &self,
        asset: &Asset,
        opts: &DownloadOptions,
    ) -> Result<PathBuf> {
        tokio::fs::create_dir_all(&opts.dest_dir)
            .await
            .context("failed to create destination directory")?;

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

        self.download_raw(asset, &dest).await?;

        if opts.auto_decompress {
            maybe_decompress(&dest).await?;
        }

        Ok(final_path)
    }

    /// Stream-download a single asset to `dest`, showing a progress bar.
    async fn download_raw(&self, asset: &Asset, dest: &Path) -> Result<()> {
        let url = self.asset_download_url(asset);
        debug!(%url, dest = %dest.display(), "downloading asset");

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("ata-releases"),
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(ref token) = self.token() {
            if let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(header::AUTHORIZATION, val);
            }
        }

        let resp = self
            .http()
            .get(&url)
            .headers(headers)
            .send()
            .await
            .context("download request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("download failed with {status}: {body}");
        }

        let total = resp
            .content_length()
            .unwrap_or(asset.size);

        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n  [{bar:40.cyan/dim}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                .expect("valid template")
                .progress_chars("=> "),
        );
        pb.set_message(asset.name.clone());

        let file = tokio::fs::File::create(dest)
            .await
            .context("failed to create destination file")?;
        let mut writer = BufWriter::with_capacity(512 * 1024, file);

        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("error reading response stream")?;
            writer.write_all(&chunk)
                .await
                .context("failed to write file")?;
            pb.inc(chunk.len() as u64);
        }

        writer.flush().await?;
        pb.finish_and_clear();

        info!(
            path = %dest.display(),
            size = pb.position(),
            "download complete",
        );
        Ok(())
    }

    /// Choose the right URL for downloading: API url (authenticated) or
    /// browser_download_url (public).
    fn asset_download_url(&self, asset: &Asset) -> String {
        if self.token().is_some() {
            asset.url.clone()
        } else {
            asset.browser_download_url.clone()
        }
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
        .context("failed to run xz")?;

    if !status.success() {
        bail!("xz decompression failed with {status}");
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
        .context("failed to run unzip")?;

    if !status.success() {
        bail!("zip extraction failed with {status}");
    }

    tokio::fs::remove_file(src)
        .await
        .context("failed to remove zip after extraction")?;

    Ok(())
}
