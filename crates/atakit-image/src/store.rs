use std::fmt;
use std::path::{Path, PathBuf};

use atakit_core::ProgressReporter;
use tracing::info;

use crate::client::ReleasesClient;
use crate::download::{self, DownloadOptions};
use crate::error::{ImageError, Result};
use crate::types::{ImageRef, Platform, Release};

/// Manages local disk image storage for automata-linux releases.
///
/// Images are organised under `base_dir/<repository>/<tag>/`:
///
/// ```text
/// base_dir/
///   automata-linux/
///     v0.5.0/
///       disk_images/
///         gcp_disk.tar.gz
///         aws_disk.vmdk
///         azure_disk.vhd
///       secure_boot_certs/
///         PK.crt
///         KEK.crt
///         db.crt
///         kernel.crt
/// ```
///
/// Key design: does NOT own a `ReleasesClient`. Client is passed as a
/// parameter to methods that need network access. Purely local ops
/// (`list_local`, `delete`) need no client.
pub struct ImageStore {
    base_dir: PathBuf,
}

/// A remote release annotated with local download status.
pub struct ReleaseStatus {
    pub release: Release,
    /// Platforms whose disk images exist locally.
    pub local_platforms: Vec<Platform>,
    /// Whether the `secure_boot_certs/` directory exists locally.
    pub local_certs: bool,
}

impl fmt::Display for ReleaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.release)?;

        if !self.local_platforms.is_empty() {
            let names: Vec<_> = self.local_platforms.iter().map(|p| p.to_string()).collect();
            write!(f, "  (local: {}", names.join(", "))?;
            if self.local_certs {
                write!(f, " +certs")?;
            }
            write!(f, ")")?;
        } else if self.local_certs {
            write!(f, "  (local: +certs)")?;
        }

        Ok(())
    }
}

impl ImageStore {
    /// Create a new store rooted at `base_dir`.
    ///
    /// The directory is created lazily on first download.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Root directory of the image store.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    // ── paths ──────────────────────────────────────────────────────

    /// Directory for a specific release tag.
    ///
    /// Structure: `base_dir/<repository>/<tag>/`
    pub fn tag_dir(&self, image_ref: &ImageRef) -> PathBuf {
        self.base_dir
            .join(&image_ref.repository)
            .join(&image_ref.tag)
    }

    /// Directory containing disk image files for a tag.
    pub fn disk_images_dir(&self, image_ref: &ImageRef) -> PathBuf {
        self.tag_dir(image_ref).join("disk_images")
    }

    /// Expected path of a disk image file (after decompression).
    pub fn image_path(&self, image_ref: &ImageRef, platform: Platform) -> PathBuf {
        self.disk_images_dir(image_ref).join(disk_filename(platform))
    }

    /// Directory containing secure-boot certificates for a tag.
    pub fn certs_dir(&self, image_ref: &ImageRef) -> PathBuf {
        self.tag_dir(image_ref).join("secure_boot_certs")
    }

    // ── list ───────────────────────────────────────────────────────

    /// Query remote image releases and annotate each with local status.
    pub async fn list(
        &self,
        client: &ReleasesClient,
        repo: &str,
        per_page: u32,
    ) -> Result<Vec<ReleaseStatus>> {
        let releases = client.list_image_releases(repo, per_page).await?;
        Ok(releases
            .into_iter()
            .map(|r| self.annotate(repo, r))
            .collect())
    }

    /// List images that have been downloaded locally (by scanning `base_dir`).
    ///
    /// Scans the two-level directory structure: `base_dir/<repository>/<tag>/`
    /// Returns an empty vec if `base_dir` does not exist.
    pub fn list_local(&self) -> Result<Vec<ImageRef>> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }

        let mut images = Vec::new();

        for repo_entry in std::fs::read_dir(&self.base_dir).map_err(|e| ImageError::ReadDir {
            path: self.base_dir.clone(),
            source: e,
        })? {
            let repo_entry = repo_entry?;
            if !repo_entry.file_type()?.is_dir() {
                continue;
            }
            let Some(repository) = repo_entry.file_name().to_str().map(|s| s.to_string()) else {
                continue;
            };

            let repo_path = repo_entry.path();
            for tag_entry in std::fs::read_dir(&repo_path).map_err(|e| ImageError::ReadDir {
                path: repo_path.clone(),
                source: e,
            })? {
                let tag_entry = tag_entry?;
                if !tag_entry.file_type()?.is_dir() {
                    continue;
                }
                let Some(tag) = tag_entry.file_name().to_str().map(|s| s.to_string()) else {
                    continue;
                };

                images.push(ImageRef {
                    repository: repository.clone(),
                    tag,
                });
            }
        }

        images.sort_by(|a, b| (&a.repository, &a.tag).cmp(&(&b.repository, &b.tag)));
        Ok(images)
    }

    // ── download ───────────────────────────────────────────────────

    /// Download disk images for the given release tag and platforms.
    ///
    /// Fetches the release metadata once, downloads each platform's disk
    /// image, then downloads secure-boot certificates once at the end.
    /// Returns the paths to all downloaded disk image files.
    pub async fn download(
        &self,
        client: &ReleasesClient,
        image_ref: &ImageRef,
        platforms: &[Platform],
        progress: &dyn ProgressReporter,
    ) -> Result<Vec<PathBuf>> {
        let release = client.get_release(image_ref).await?;
        let disk_dir = self.disk_images_dir(image_ref);
        let opts = DownloadOptions::default()
            .dest_dir(&disk_dir)
            .skip_existing(true);

        let mut paths = Vec::new();
        for &platform in platforms {
            let asset =
                release
                    .disk_image(platform)
                    .ok_or_else(|| ImageError::MissingPlatformAsset {
                        image_ref: image_ref.to_string(),
                        platform: platform.to_string(),
                    })?;

            let path = download::download_asset(client, asset, &opts, progress).await?;
            info!(?image_ref, %platform, path = %path.display(), "image ready");
            paths.push(path);
        }

        // Download secure-boot certs into secure_boot_certs/ subdirectory.
        if let Some(certs) = release.secure_boot_certs() {
            let certs_dir = self.certs_dir(image_ref);
            let certs_opts = DownloadOptions::default()
                .dest_dir(&certs_dir)
                .skip_existing(false);
            download::download_asset(client, certs, &certs_opts, progress).await?;
        }

        Ok(paths)
    }

    // ── query ──────────────────────────────────────────────────

    /// List which platform disk images exist locally for a given ref.
    pub fn local_platforms(&self, image_ref: &ImageRef) -> Vec<Platform> {
        Platform::ALL
            .iter()
            .copied()
            .filter(|&p| self.image_path(image_ref, p).exists())
            .collect()
    }

    /// Whether secure_boot_certs/ directory exists for a given ref.
    pub fn has_certs(&self, image_ref: &ImageRef) -> bool {
        self.certs_dir(image_ref).exists()
    }

    /// Whether any content (disk images or certs) exists for a given ref.
    pub fn exists(&self, image_ref: &ImageRef) -> bool {
        !self.local_platforms(image_ref).is_empty() || self.has_certs(image_ref)
    }

    // ── delete ─────────────────────────────────────────────────────

    /// Delete all locally downloaded files for a release tag.
    pub async fn delete(&self, image_ref: &ImageRef) -> Result<()> {
        let dir = self.tag_dir(image_ref);
        if dir.exists() {
            tokio::fs::remove_dir_all(&dir)
                .await
                .map_err(|e| ImageError::Remove {
                    path: dir.clone(),
                    source: e,
                })?;
            info!(%image_ref, dir = %dir.display(), "deleted local images");
        }
        Ok(())
    }

    /// Delete only a specific platform's disk image for a tag.
    pub async fn delete_platform(
        &self,
        image_ref: &ImageRef,
        platform: Platform,
    ) -> Result<()> {
        let path = self.image_path(image_ref, platform);
        if path.exists() {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| ImageError::Remove {
                    path: path.clone(),
                    source: e,
                })?;
            info!(%image_ref, %platform, path = %path.display(), "deleted image");
        }
        Ok(())
    }

    // ── internal ───────────────────────────────────────────────────

    fn annotate(&self, repo: &str, release: Release) -> ReleaseStatus {
        let image_ref = ImageRef {
            repository: repo.to_string(),
            tag: release.tag_name.clone(),
        };

        let local_platforms = Platform::ALL
            .iter()
            .copied()
            .filter(|&p| self.image_path(&image_ref, p).exists())
            .collect();

        let local_certs = self.certs_dir(&image_ref).exists();

        ReleaseStatus {
            release,
            local_platforms,
            local_certs,
        }
    }
}

/// Final (decompressed) disk image filename for each platform.
fn disk_filename(platform: Platform) -> &'static str {
    match platform {
        Platform::Gcp => "gcp_disk.tar.gz",
        Platform::Aws => "aws_disk.vmdk",
        Platform::Azure => "azure_disk.vhd",
    }
}
