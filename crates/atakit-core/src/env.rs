use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Info about a detected legacy `~/.atakit/images/` directory that should be migrated.
pub struct LegacyImageStore {
    /// Path to the legacy image directory (`~/.atakit/images`).
    pub legacy_dir: PathBuf,
    /// Path to the legacy parent directory (`~/.atakit`).
    pub legacy_parent: PathBuf,
    /// Path to the new XDG image directory.
    pub new_dir: PathBuf,
    /// Whether the new XDG image directory already exists.
    pub new_dir_exists: bool,
}

/// Runtime context shared across all commands.
///
/// Holds XDG-compliant paths for atakit state. Only global state — no project-scoped config.
pub struct Env {
    /// Data directory (`$XDG_DATA_HOME/atakit`).
    pub data_dir: PathBuf,
    /// Config directory (`$XDG_CONFIG_HOME/atakit`).
    pub config_dir: PathBuf,
    /// Cache directory (`$XDG_CACHE_HOME/atakit`).
    pub cache_dir: PathBuf,
    /// Local directory for storing downloaded CVM base images (`data_dir/images`).
    pub image_dir: PathBuf,
}

/// Resolve a directory path using 3-tier priority:
/// 1. App-specific override (`ATAKIT_*_DIR`)
/// 2. XDG variable (`XDG_*_HOME`) + `/atakit`
/// 3. Home directory default (`$HOME/<default_suffix>/atakit`)
fn resolve_dir(
    atakit_override: Option<OsString>,
    xdg_var: Option<OsString>,
    home: &Path,
    default_suffix: &str,
) -> PathBuf {
    if let Some(val) = atakit_override {
        return PathBuf::from(val);
    }
    if let Some(val) = xdg_var {
        let p = PathBuf::from(val);
        if p.is_absolute() {
            return p.join("atakit");
        }
    }
    home.join(default_suffix).join("atakit")
}

impl Env {
    /// Build context from environment.
    ///
    /// Resolution order per directory:
    /// `ATAKIT_*_DIR` > `XDG_*_HOME/atakit` > `$HOME/<default>/atakit`
    pub fn from_env() -> Self {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));

        let data_dir = resolve_dir(
            env::var_os("ATAKIT_DATA_DIR"),
            env::var_os("XDG_DATA_HOME"),
            &home,
            ".local/share",
        );
        let config_dir = resolve_dir(
            env::var_os("ATAKIT_CONFIG_DIR"),
            env::var_os("XDG_CONFIG_HOME"),
            &home,
            ".config",
        );
        let cache_dir = resolve_dir(
            env::var_os("ATAKIT_CACHE_DIR"),
            env::var_os("XDG_CACHE_HOME"),
            &home,
            ".cache",
        );
        let image_dir = data_dir.join("images");

        let env = Self {
            data_dir,
            config_dir,
            cache_dir,
            image_dir,
        };
        env.ensure_dirs();
        env
    }

    /// Create data, config, cache, and image directories if they don't exist.
    fn ensure_dirs(&self) {
        for dir in [&self.data_dir, &self.config_dir, &self.cache_dir, &self.image_dir] {
            let _ = std::fs::create_dir_all(dir);
        }
    }

    /// Check if the legacy `~/.atakit/images/` directory exists and differs from
    /// the current `image_dir`. Returns migration info if so.
    pub fn check_legacy_dir(&self) -> Option<LegacyImageStore> {
        let home = env::var_os("HOME").map(PathBuf::from)?;
        let legacy_parent = home.join(".atakit");
        let legacy_dir = legacy_parent.join("images");
        if legacy_dir.is_dir() && legacy_dir != self.image_dir {
            Some(LegacyImageStore {
                legacy_dir,
                legacy_parent,
                new_dir: self.image_dir.clone(),
                new_dir_exists: self.image_dir.is_dir(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn resolve_dir_atakit_override_wins() {
        let home = PathBuf::from("/home/user");
        let result = resolve_dir(
            Some(OsString::from("/custom/data")),
            Some(OsString::from("/xdg/data")),
            &home,
            ".local/share",
        );
        assert_eq!(result, PathBuf::from("/custom/data"));
    }

    #[test]
    fn resolve_dir_xdg_second_priority() {
        let home = PathBuf::from("/home/user");
        let result = resolve_dir(
            None,
            Some(OsString::from("/xdg/data")),
            &home,
            ".local/share",
        );
        assert_eq!(result, PathBuf::from("/xdg/data/atakit"));
    }

    #[test]
    fn resolve_dir_home_default_fallback() {
        let home = PathBuf::from("/home/user");
        let result = resolve_dir(None, None, &home, ".local/share");
        assert_eq!(result, PathBuf::from("/home/user/.local/share/atakit"));
    }

    #[test]
    fn resolve_dir_ignores_relative_xdg() {
        let home = PathBuf::from("/home/user");
        let result = resolve_dir(
            None,
            Some(OsString::from("relative/path")),
            &home,
            ".cache",
        );
        // Relative XDG paths are invalid per spec, fall back to default
        assert_eq!(result, PathBuf::from("/home/user/.cache/atakit"));
    }
}
