use std::env;
use std::path::PathBuf;

/// Runtime context shared across all commands.
///
/// Holds paths under `~/.atakit`. Only global state — no project-scoped config.
pub struct Env {
    /// Base atakit directory (`~/.atakit`).
    pub atakit_dir: PathBuf,
    /// Local directory for storing downloaded CVM base images (`~/.atakit/images`).
    pub image_dir: PathBuf,
}

impl Env {
    /// Build context from environment.
    ///
    /// - `atakit_dir` defaults to `$HOME/.atakit`.
    /// - `image_dir` defaults to `$HOME/.atakit/images`.
    pub fn from_env() -> Self {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let atakit_dir = home.join(".atakit");
        let image_dir = atakit_dir.join("images");
        Self {
            atakit_dir,
            image_dir,
        }
    }
}
