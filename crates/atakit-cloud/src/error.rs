use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("config error: {message}")]
    Config { message: String },

    #[error("target not found: {name}")]
    TargetNotFound { name: String },

    #[error("state error: {message}")]
    State { message: String },

    #[error("deployment not found: {instance}")]
    StateNotFound { instance: String },

    #[error("ambiguous instance '{instance}', matches: {}", matches.join(", "))]
    AmbiguousInstance {
        instance: String,
        matches: Vec<String>,
    },

    #[error("deployment already exists: {instance}")]
    AlreadyExists { instance: String },

    #[error("{program} failed (exit {code:?}): {stderr}")]
    CommandFailed {
        program: String,
        args: String,
        stderr: String,
        code: Option<i32>,
    },

    #[error("{program} not found on PATH")]
    CommandNotFound { program: String },

    #[error("missing dependency: {tool} ({install_hint})")]
    DependencyMissing { tool: String, install_hint: String },

    #[error("image upload failed: {message}")]
    ImageUploadFailed { message: String },

    #[error("firewall error: {message}")]
    FirewallError { message: String },

    #[error("disk error: {message}")]
    DiskError { message: String },

    #[error("instance error: {message}")]
    InstanceError { message: String },

    #[error("portal at {address} did not respond within {timeout_secs}s")]
    PortalTimeout { address: String, timeout_secs: u64 },

    #[error("portal initialization failed: {message}")]
    PortalInitFailed { message: String },

    #[error("deploy failed at step '{step}': {message}")]
    DeployFailed { step: String, message: String },

    #[error("destroy failed for resource '{resource}': {message}")]
    DestroyFailed { resource: String, message: String },

    #[error("invalid name '{name}': {message}")]
    InvalidName { name: String, message: String },

    #[error("archive not found: {path}")]
    ArchiveNotFound { path: String },

    #[error("workload error: {message}")]
    WorkloadError { message: String },

    #[error("HTTP error: {message}")]
    Http { message: String },

    #[error("I/O error: {path}")]
    IoPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
