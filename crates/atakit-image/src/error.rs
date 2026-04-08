use std::path::PathBuf;

/// Errors produced by image operations.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("invalid image reference '{0}': expected format 'repository:tag'")]
    InvalidImageRef(String),

    #[error("invalid repository '{0}': must not contain '/'")]
    InvalidRepository(String),

    #[error("unsupported platform '{0}', expected: gcp, aws, azure")]
    UnsupportedPlatform(String),

    #[error("GitHub API returned {status}: {body}")]
    Api { status: u16, body: String },

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Github(#[from] atakit_github::GithubError),

    #[error("no release containing disk images found in the last {0} releases")]
    NoDiskImages(u32),

    #[error("no release containing a {platform} disk image found in the last {count} releases")]
    NoPlatformImage { platform: String, count: u32 },

    #[error("release {image_ref} has no {platform} disk image")]
    MissingPlatformAsset {
        image_ref: String,
        platform: String,
    },

    #[error("download failed with {status}: {body}")]
    DownloadFailed { status: u16, body: String },

    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to create file {path}: {source}")]
    CreateFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to write file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to remove {path}: {source}")]
    Remove {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("decompression failed: {0}")]
    Decompress(String),

    #[error("failed to read archive {path}: {source}")]
    ArchiveRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("archive {path} is missing manifest.toml")]
    ArchiveMissingManifest { path: PathBuf },

    #[error("invalid archive {path}: {message}")]
    ArchiveInvalid { path: PathBuf, message: String },

    #[error("failed to parse manifest in {path}: {reason}")]
    ParseManifest { path: PathBuf, reason: String },

    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ImageError>;
