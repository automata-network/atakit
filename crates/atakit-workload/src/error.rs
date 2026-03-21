use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum WorkloadError {
    // ── scaffold ──────────────────────────────────────────
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

    // ── config parsing ────────────────────────────────────
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse {path}: {source}")]
    ParseConfig {
        path: PathBuf,
        source: toml::de::Error,
    },

    // ── validation ────────────────────────────────────────
    #[error("validation error: {0}")]
    Validation(String),

    #[error("measured-data path does not exist: {0}")]
    MeasuredDataMissing(PathBuf),

    #[error("signing file does not exist: {0}")]
    SigningFileMissing(PathBuf),

    #[error("env_file does not exist: {0}")]
    EnvFileMissing(PathBuf),

    #[error("env_file parse error in {path} line {line}: {message}")]
    EnvFileParse {
        path: PathBuf,
        line: usize,
        message: String,
    },

    #[error("image file does not exist: {0}")]
    ImageFileMissing(PathBuf),

    // ── container engine ──────────────────────────────────
    #[error("no container engine found (install docker or podman)")]
    NoContainerEngine,

    #[error("{command}: {stderr}")]
    ContainerCommand { command: String, stderr: String },

    // ── build / archive ───────────────────────────────────
    #[error("failed to copy {from} to {to}: {source}")]
    CopyFile {
        from: PathBuf,
        to: PathBuf,
        source: std::io::Error,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to serialize manifest: {0}")]
    SerializeManifest(#[from] toml::ser::Error),

    // ── store ────────────────────────────────────────────
    #[error("workload not found in store: {name}:{version}")]
    StoreNotFound { name: String, version: String },

    #[error("workload already exists in store: {name}:{version}")]
    StoreExists { name: String, version: String },

    #[error("no archive blob for workload: {name}:{version}")]
    NoBlobInStore { name: String, version: String },

    #[error("store path escapes base directory: {path}")]
    StorePathTraversal { path: PathBuf },

    #[error("failed to read store directory {path}: {reason}")]
    ReadStoreDir { path: PathBuf, reason: String },

    #[error("failed to parse metadata {path}: {reason}")]
    ParseMeta { path: PathBuf, reason: String },

    // ── registry ─────────────────────────────────────────
    #[error("registry error: {message}")]
    Registry { message: String },

    #[error("registry request failed: {reason}")]
    RegistryRequest { reason: String },

    #[error("JSON serialization error: {0}")]
    Json(String),
}
