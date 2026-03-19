use std::path::{Component, Path};
use std::{env, fs};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Application configuration loaded from `config.toml`.
///
/// All fields are optional with serde defaults matching hardcoded behavior.
/// Precedence: CLI args > env vars > config file > defaults.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub image: ImageConfig,
    pub github: GithubConfig,
    pub build: BuildConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ImageConfig {
    /// Default repository for image commands.
    pub repository: String,
    /// Default platforms for `image pull`.
    pub platforms: Option<Vec<String>>,
    /// Default limit for `image ls`.
    pub list_limit: u32,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            repository: "automata-linux".to_string(),
            platforms: None,
            list_limit: 10,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct GithubConfig {
    /// GitHub API token.
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct BuildConfig {
    /// Container engine preference: "docker", "podman", or "auto".
    pub container_engine: String,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            container_engine: "auto".to_string(),
        }
    }
}

impl Config {
    /// Load config from `config_dir/config.toml`, then apply env var overrides.
    ///
    /// Returns `Config::default()` if the file is missing.
    /// Returns an error if the file exists but is malformed.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("config.toml");

        let mut config: Config = match fs::read_to_string(&path) {
            Ok(contents) => toml::from_str(&contents)
                .with_context(|| format!("failed to parse {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to read {}", path.display()));
            }
        };

        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    /// Returns the GitHub token, if set (from config file or `GITHUB_TOKEN` env var).
    pub fn github_token(&self) -> Option<&str> {
        self.github.token.as_deref()
    }

    fn validate(&self) -> Result<()> {
        let repo = &self.image.repository;
        if repo.is_empty()
            || repo.contains('/')
            || repo.contains('\\')
            || Path::new(repo).is_absolute()
            || Path::new(repo)
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            bail!(
                "invalid image.repository {:?}: must be a plain name without path separators",
                repo,
            );
        }
        Ok(())
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = env::var("ATAKIT_DEFAULT_REPO") {
            if !v.is_empty() {
                self.image.repository = v;
            }
        }
        if let Ok(v) = env::var("ATAKIT_DEFAULT_PLATFORMS") {
            if !v.is_empty() {
                let parsed: Vec<String> = v
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !parsed.is_empty() {
                    self.image.platforms = Some(parsed);
                }
            }
        }
        if let Ok(v) = env::var("ATAKIT_LIST_LIMIT") {
            if let Ok(n) = v.parse::<u32>() {
                self.image.list_limit = n;
            }
        }
        if let Ok(v) = env::var("GITHUB_TOKEN") {
            if !v.is_empty() {
                self.github.token = Some(v);
            }
        }
        if let Ok(v) = env::var("ATAKIT_CONTAINER_ENGINE") {
            if !v.is_empty() {
                self.build.container_engine = v;
            }
        }
    }
}
