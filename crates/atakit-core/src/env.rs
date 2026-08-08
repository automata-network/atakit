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
    /// Local directory for storing workload archives and metadata (`data_dir/workloads`).
    pub workload_dir: PathBuf,
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

/// Deny group and other every access to `path`: `0700` for a directory, `0600`
/// for a file.
///
/// Both `create_dir_all` and `fs::write` apply the umask rather than an explicit
/// mode, so on a default `022` they produce world-readable paths. That is wrong
/// for anything holding a private key.
///
/// Only ever tightens. A path that already denies group and other is left
/// untouched, so this is a no-op on every run after the first and can never
/// widen what an operator has deliberately restricted further.
#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)?;
    if metadata.permissions().mode() & 0o077 == 0 {
        return Ok(());
    }
    let owner_only = if metadata.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(owner_only))
}

/// Non-Unix platforms have no mode bits to set.
#[cfg(not(unix))]
pub fn restrict_to_owner(_path: &Path) -> std::io::Result<()> {
    Ok(())
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
        let workload_dir = data_dir.join("workloads");

        let env = Self {
            data_dir,
            config_dir,
            cache_dir,
            image_dir,
            workload_dir,
        };
        env.ensure_dirs();
        env
    }

    /// Create data, config, cache, and image directories if they don't exist,
    /// and restrict the config directory to its owner.
    ///
    /// Returns a list of (path, error) pairs for any directory that could not be
    /// created or restricted.
    pub fn ensure_dirs(&self) -> Vec<(std::path::PathBuf, std::io::Error)> {
        let mut failures = Vec::new();
        for dir in [
            &self.data_dir,
            &self.config_dir,
            &self.cache_dir,
            &self.image_dir,
            &self.workload_dir,
        ] {
            if let Err(e) = std::fs::create_dir_all(dir) {
                failures.push((dir.clone(), e));
            }
        }
        // The config directory is the documented home for private keys, and
        // `create_dir_all` applies the umask — a default 022 leaves it readable
        // by everyone. Skipped when creation failed, so one broken path is
        // reported once.
        if self.config_dir.is_dir() {
            if let Err(e) = restrict_to_owner(&self.config_dir) {
                failures.push((self.config_dir.clone(), e));
            }
        }
        failures
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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

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
        let result = resolve_dir(None, Some(OsString::from("relative/path")), &home, ".cache");
        // Relative XDG paths are invalid per spec, fall back to default
        assert_eq!(result, PathBuf::from("/home/user/.cache/atakit"));
    }

    // ── restrict_to_owner ────────────────────────────────────────

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    #[cfg(unix)]
    fn restrict_to_owner_tightens_a_world_readable_directory() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("config");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        restrict_to_owner(&dir).unwrap();

        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    #[cfg(unix)]
    fn restrict_to_owner_tightens_a_world_readable_file() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("config.toml");
        std::fs::write(&file, "").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        restrict_to_owner(&file).unwrap();

        assert_eq!(mode_of(&file), 0o600);
    }

    /// The guard only ever removes access. An operator who has restricted a
    /// path further than `0700` keeps that, rather than having it widened back
    /// on the next run.
    #[test]
    #[cfg(unix)]
    fn restrict_to_owner_never_widens() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("config");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        restrict_to_owner(&dir).unwrap();

        assert_eq!(mode_of(&dir), 0o500);
    }

    #[test]
    #[cfg(unix)]
    fn ensure_dirs_creates_an_owner_only_config_dir() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env {
            data_dir: temp.path().join("data"),
            config_dir: temp.path().join("config"),
            cache_dir: temp.path().join("cache"),
            image_dir: temp.path().join("data/images"),
            workload_dir: temp.path().join("data/workloads"),
        };

        let failures = env.ensure_dirs();

        assert!(failures.is_empty(), "unexpected failures: {failures:?}");
        assert_eq!(mode_of(&env.config_dir), 0o700);
    }
}
