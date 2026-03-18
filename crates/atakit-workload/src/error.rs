use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum WorkloadError {
    #[error("workload directory already exists: {0}")]
    AlreadyExists(PathBuf),

    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to write file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("invalid workload name: {0}")]
    InvalidName(String),
}
