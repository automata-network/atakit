use std::path::PathBuf;

/// Errors produced by the GitHub releases client.
#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("GitHub API returned {status}: {body}")]
    Api { status: u16, body: String },

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

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

    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("invalid GitHub repo path '{0}': expected 'owner/repo'")]
    InvalidRepo(String),

    #[error("download too large: response exceeds {limit} byte limit")]
    DownloadTooLarge { limit: u64 },
}

pub type Result<T> = std::result::Result<T, GithubError>;
