use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::{env, fs};

use anyhow::{Context, Result, bail};
use atakit_cloud::CloudConfig;
use serde::{Deserialize, de};

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
    pub publish: PublishConfig,
    pub registry: RegistryConfig,
    pub cloud: CloudConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ImageConfig {
    /// GitHub repositories (`owner/repo`) for image commands.
    /// Accepts a single string or an array in config.
    /// The first entry is the default for `image pull`.
    #[serde(
        alias = "repository",
        deserialize_with = "deserialize_string_or_vec"
    )]
    pub repositories: Vec<String>,
    /// Default platforms for `image pull`.
    pub platforms: Option<Vec<String>>,
    /// Default limit for `image ls`.
    pub list_limit: u32,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            repositories: vec!["automata-network/automata-linux".to_string()],
            platforms: None,
            list_limit: 10,
        }
    }
}

impl ImageConfig {
    /// All configured GitHub repositories.
    pub fn repos(&self) -> Vec<&str> {
        self.repositories.iter().map(|s| s.as_str()).collect()
    }

    /// The primary (first) repository, used as default for `image pull`.
    pub fn primary_repo(&self) -> &str {
        self.repositories.first().map_or("", |s| s.as_str())
    }
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: de::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        Single(String),
        Array(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::Single(s) => Ok(vec![s]),
        StringOrVec::Array(v) => Ok(v),
    }
}

/// Extract the local image name from a GitHub `owner/repo` string.
///
/// Returns the part after the last `/`, or the whole string if no `/`.
pub fn repo_local_name(repo: &str) -> &str {
    repo.rsplit_once('/').map_or(repo, |(_, name)| name)
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

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PublishConfig {
    /// Default RPC URL for publish commands.
    pub rpc_url: Option<String>,
    /// Default session registry contract address.
    pub session_registry: Option<String>,
    /// Path to file containing the owner private key (hex).
    pub owner_key_file: Option<String>,
    /// Path to file containing the relay private key (hex).
    pub relay_key_file: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RegistryConfig {
    /// Default registry remote name.
    pub default: Option<String>,
    /// Named registry remotes.
    #[serde(default)]
    pub remotes: BTreeMap<String, RemoteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteConfig {
    pub url: String,
}

impl RegistryConfig {
    /// Resolve registry URL from CLI arg, default remote, or error.
    ///
    /// `cli_arg` accepts either a remote name or a raw URL (starts with http).
    pub fn resolve_url(&self, cli_arg: Option<&str>) -> Result<String> {
        if let Some(arg) = cli_arg {
            // If it looks like a URL, use it directly
            if arg.starts_with("http://") || arg.starts_with("https://") {
                return Ok(arg.to_string());
            }
            // Otherwise look up as a remote name
            if let Some(remote) = self.remotes.get(arg) {
                return Ok(remote.url.clone());
            }
            bail!("unknown registry remote: {arg}");
        }

        // Fall back to default remote
        if let Some(ref default_name) = self.default {
            if let Some(remote) = self.remotes.get(default_name) {
                return Ok(remote.url.clone());
            }
            bail!(
                "default registry remote '{}' not found in config",
                default_name
            );
        }

        bail!("no registry configured: use --registry or set [registry] in config")
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
        if self.image.repositories.is_empty() {
            bail!("image.repositories must contain at least one entry");
        }
        for repo in &self.image.repositories {
            Self::validate_repo(repo)?;
        }
        Ok(())
    }

    fn validate_repo(repo: &str) -> Result<()> {
        if repo.is_empty() {
            bail!("invalid image repository: must not be empty");
        }
        if repo.contains('\\') {
            bail!(
                "invalid image repository {:?}: must not contain backslashes",
                repo,
            );
        }
        if Path::new(repo).is_absolute() {
            bail!(
                "invalid image repository {:?}: must not be an absolute path",
                repo,
            );
        }
        if Path::new(repo)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            bail!(
                "invalid image repository {:?}: must not contain path traversal",
                repo,
            );
        }
        // Each segment must be non-empty (reject leading/trailing/double slashes).
        if repo.split('/').any(|s| s.is_empty()) {
            bail!(
                "invalid image repository {:?}: contains empty path segment",
                repo,
            );
        }
        Ok(())
    }

    #[cfg(test)]
    fn load_from_str(toml_content: &str) -> Result<Self> {
        let mut config: Config =
            toml::from_str(toml_content).context("failed to parse config")?;
        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = env::var("ATAKIT_DEFAULT_REPO") {
            if !v.is_empty() {
                self.image.repositories = vec![v];
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
        if let Ok(v) = env::var("ATAKIT_RPC_URL") {
            if !v.is_empty() {
                self.publish.rpc_url = Some(v);
            }
        }
        if let Ok(v) = env::var("ATAKIT_SESSION_REGISTRY") {
            if !v.is_empty() {
                self.publish.session_registry = Some(v);
            }
        }
        if let Ok(v) = env::var("ATAKIT_REGISTRY_URL") {
            if !v.is_empty() {
                // If a default remote is configured, update its URL.
                // Otherwise create a "default" remote and set it as default.
                let remote_name = self
                    .registry
                    .default
                    .clone()
                    .unwrap_or_else(|| "default".to_string());
                self.registry
                    .remotes
                    .insert(remote_name.clone(), RemoteConfig { url: v });
                if self.registry.default.is_none() {
                    self.registry.default = Some(remote_name);
                }
            }
        }
        if let Ok(v) = env::var("ATAKIT_GCP_PROJECT") {
            if !v.is_empty() {
                for target in self.cloud.targets.values_mut() {
                    if matches!(target.platform, atakit_cloud::PlatformKind::Gcp)
                        && target.project.is_none()
                    {
                        target.project = Some(v.clone());
                    }
                }
            }
        }
    }
}

/// Read a hex key from a file, trimming whitespace.
pub fn read_key_file(path: &str) -> Result<String> {
    let expanded = if path.starts_with("~/") {
        let home = env::var("HOME").context("HOME not set")?;
        format!("{}{}", home, &path[1..])
    } else {
        path.to_string()
    };
    let content = fs::read_to_string(&expanded)
        .with_context(|| format!("failed to read key file {}", expanded))?;
    Ok(content.trim().to_string())
}

/// Write a template `config.toml` if one doesn't exist yet.
pub fn ensure_template(config_dir: &Path) {
    let path = config_dir.join("config.toml");
    if !path.exists() {
        let _ = fs::write(&path, include_str!("config_template.toml"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn missing_file_returns_defaults() {
        let dir = TempDir::new().unwrap();
        let config = Config::load(dir.path()).unwrap();
        assert_eq!(
            config.image.repositories,
            vec!["automata-network/automata-linux"],
        );
        assert_eq!(config.image.list_limit, 10);
        assert!(config.image.platforms.is_none());
        assert!(config.github.token.is_none());
        assert_eq!(config.build.container_engine, "auto");
    }

    #[test]
    fn parses_full_config() {
        let config = Config::load_from_str(
            r#"
            [image]
            repository = "my-images"
            platforms = ["gcp", "aws"]
            list_limit = 25

            [github]
            token = "ghp_test123"

            [build]
            container_engine = "podman"
            "#,
        )
        .unwrap();

        assert_eq!(config.image.repositories, vec!["my-images"]);
        assert_eq!(
            config.image.platforms.as_deref(),
            Some(&["gcp".to_string(), "aws".to_string()][..])
        );
        assert_eq!(config.image.list_limit, 25);
        assert_eq!(config.github_token(), Some("ghp_test123"));
        assert_eq!(config.build.container_engine, "podman");
    }

    #[test]
    fn partial_config_fills_defaults() {
        let config = Config::load_from_str(
            r#"
            [image]
            list_limit = 5
            "#,
        )
        .unwrap();

        assert_eq!(
            config.image.repositories,
            vec!["automata-network/automata-linux"],
        );
        assert_eq!(config.image.list_limit, 5);
        assert!(config.image.platforms.is_none());
        assert_eq!(config.build.container_engine, "auto");
    }

    #[test]
    fn empty_config_returns_defaults() {
        let config = Config::load_from_str("").unwrap();
        assert_eq!(
            config.image.repositories,
            vec!["automata-network/automata-linux"],
        );
        assert_eq!(config.image.list_limit, 10);
    }

    #[test]
    fn accepts_singular_repository() {
        let config = Config::load_from_str(
            r#"
            [image]
            repository = "automata-network/debug-linux"
            "#,
        )
        .unwrap();
        assert_eq!(
            config.image.repositories,
            vec!["automata-network/debug-linux"],
        );
    }

    #[test]
    fn accepts_multiple_repositories() {
        let config = Config::load_from_str(
            r#"
            [image]
            repositories = ["automata-network/automata-linux", "automata-network/debug-linux"]
            "#,
        )
        .unwrap();
        assert_eq!(
            config.image.repos(),
            vec!["automata-network/automata-linux", "automata-network/debug-linux"],
        );
    }

    #[test]
    fn rejects_backslash_in_repository() {
        let err = Config::load_from_str(
            r#"
            [image]
            repository = 'owner\repo'
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("backslash"));
    }

    #[test]
    fn rejects_dotdot_in_repository() {
        let err = Config::load_from_str(
            r#"
            [image]
            repository = ".."
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("traversal"));
    }

    #[test]
    fn rejects_empty_repository() {
        let err = Config::load_from_str(
            r#"
            [image]
            repositories = [""]
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_trailing_slash_in_repository() {
        let err = Config::load_from_str(
            r#"
            [image]
            repository = "owner/"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty path segment"));
    }

    #[test]
    fn rejects_empty_repositories_list() {
        let err = Config::load_from_str(
            r#"
            [image]
            repositories = []
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn malformed_toml_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let mut f = fs::File::create(&path).unwrap();
        write!(f, "not valid [[ toml").unwrap();

        let err = Config::load(dir.path()).unwrap_err();
        assert!(err.to_string().contains("failed to parse"));
    }

    #[test]
    fn load_from_real_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            r#"
            [image]
            repository = "custom-images"
            list_limit = 3
            "#,
        )
        .unwrap();

        let config = Config::load(dir.path()).unwrap();
        assert_eq!(config.image.repositories, vec!["custom-images"]);
        assert_eq!(config.image.list_limit, 3);
    }
}
