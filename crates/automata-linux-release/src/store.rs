use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::info;

use crate::client::ReleasesClient;
use crate::download::DownloadOptions;
use crate::types::{ImageRef, Platform, Release};

pub const REPO: &str = "automata-network/automata-linux";

/// Manages local disk image storage for automata-linux releases.
///
/// Images are organised under `base_dir/<tag>/`:
///
/// ```text
/// base_dir/
///   v0.5.0/
///     gcp_disk.tar.gz
///     aws_disk.vmdk
///     azure_disk.vhd
///     secure_boot/
///       PK.crt
///       KEK.crt
///       db.crt
///       kernel.crt
/// ```
pub struct ImageStore {
    client: ReleasesClient,
    base_dir: PathBuf,
}

/// A remote release annotated with local download status.
pub struct ReleaseStatus {
    pub release: Release,
    /// Platforms whose disk images exist locally.
    pub local_platforms: Vec<Platform>,
    /// Whether the `secure_boot/` directory exists locally.
    pub local_certs: bool,
}

impl fmt::Display for ReleaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to Release's Display for the base line.
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
            client: ReleasesClient::new(),
            base_dir: base_dir.into(),
        }
    }

    /// Authenticate with a GitHub token (required for private repos).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.client = self.client.with_token(token);
        self
    }

    /// Read authentication token from the `GITHUB_TOKEN` environment variable.
    pub fn with_token_from_env(mut self) -> Self {
        self.client = self.client.with_token_from_env();
        self
    }

    /// Access the underlying API client.
    pub fn client(&self) -> &ReleasesClient {
        &self.client
    }

    /// Root directory of the image store.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    // ── paths ──────────────────────────────────────────────────────

    /// Directory for a specific release tag.
    ///
    /// Structure: `base_dir/<repository>/<tag>/`
    /// e.g. `base_dir/automata-linux/v0.5.0/`
    pub fn tag_dir(&self, image_ref: &ImageRef) -> PathBuf {
        self.base_dir
            .join(&image_ref.repository)
            .join(&image_ref.tag)
    }

    /// Expected path of a disk image file (after decompression).
    pub fn image_path(&self, image_ref: &ImageRef, platform: Platform) -> PathBuf {
        self.tag_dir(image_ref).join(disk_filename(platform))
    }

    /// Return the container platform string for an image (e.g., "linux/amd64").
    pub fn container_platform(&self, _image_ref: &ImageRef) -> &str {
        "linux/amd64"
    }

    /// Expected path of the `secure_boot/` directory for a tag.
    pub fn certs_dir(&self, image_ref: &ImageRef) -> PathBuf {
        self.tag_dir(image_ref).join("secure_boot")
    }

    // ── 1. list ────────────────────────────────────────────────────

    /// Query remote image releases and annotate each with local status.
    pub async fn list(&self, repo: &str, per_page: u32) -> Result<Vec<ReleaseStatus>> {
        let releases = self.client.list_image_releases(repo, per_page).await?;
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

        // Scan repository directories
        for repo_entry in
            std::fs::read_dir(&self.base_dir).context("failed to read image store directory")?
        {
            let repo_entry = repo_entry?;
            if !repo_entry.file_type()?.is_dir() {
                continue;
            }
            let Some(repository) = repo_entry.file_name().to_str().map(|s| s.to_string()) else {
                continue;
            };

            // Scan tag directories within each repository
            let repo_path = repo_entry.path();
            for tag_entry in
                std::fs::read_dir(&repo_path).context("failed to read repository directory")?
            {
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

        // Sort by repository, then by tag
        images.sort_by(|a, b| (&a.repository, &a.tag).cmp(&(&b.repository, &b.tag)));
        Ok(images)
    }

    // ── 2. download ────────────────────────────────────────────────

    /// Download disk images for the given release tag and platforms.
    ///
    /// Fetches the release metadata once, downloads each platform's disk
    /// image, then downloads secure-boot certificates once at the end.
    /// Returns the paths to all downloaded disk image files.
    pub async fn download(
        &self,
        image_ref: &ImageRef,
        platforms: &[Platform],
    ) -> Result<Vec<PathBuf>> {
        let release = self.client.get_release(image_ref).await?;
        let dir = self.tag_dir(image_ref);
        let opts = DownloadOptions::default()
            .dest_dir(&dir)
            .skip_existing(true);

        let mut paths = Vec::new();
        for &platform in platforms {
            let asset = release
                .disk_image(platform)
                .with_context(|| format!("release {image_ref:?} has no {platform} disk image"))?;

            let path = self.client.download_asset(asset, &opts).await?;
            info!(?image_ref, %platform, path = %path.display(), "image ready");
            paths.push(path);
        }

        // Download secure-boot certs once into a secure_boot/ subdirectory.
        if let Some(certs) = release.secure_boot_certs() {
            let certs_dir = self.certs_dir(image_ref);
            let certs_opts = DownloadOptions::default()
                .dest_dir(&certs_dir)
                .skip_existing(false);
            self.client.download_asset(certs, &certs_opts).await?;
        }

        Ok(paths)
    }

    // ── 3. delete ──────────────────────────────────────────────────

    /// Delete all locally downloaded files for a release tag.
    pub async fn delete(&self, image_ref: &ImageRef) -> Result<()> {
        let dir = self.tag_dir(image_ref);
        if dir.exists() {
            tokio::fs::remove_dir_all(&dir)
                .await
                .with_context(|| format!("failed to remove {}", dir.display()))?;
            info!(%image_ref, dir = %dir.display(), "deleted local images");
        }
        Ok(())
    }

    /// Delete only a specific platform's disk image for a tag.
    pub async fn delete_platform(&self, image_ref: &ImageRef, platform: Platform) -> Result<()> {
        let path = self.image_path(image_ref, platform);
        if path.exists() {
            tokio::fs::remove_file(&path)
                .await
                .with_context(|| format!("failed to remove {}", path.display()))?;
            info!(%image_ref, %platform, path = %path.display(), "deleted image");
        }
        Ok(())
    }

    // ── internal ───────────────────────────────────────────────────

    fn annotate(&self, repo: &str, release: Release) -> ReleaseStatus {
        let tag = &release.tag_name;
        let image_ref = ImageRef {
            repository: repo.to_string(),
            tag: tag.clone(),
        };

        let mut local_platforms = Vec::new();
        for p in [Platform::Gcp, Platform::Aws, Platform::Azure] {
            if self.image_path(&image_ref, p).exists() {
                local_platforms.push(p);
            }
        }

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
