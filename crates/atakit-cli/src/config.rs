use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::{env, fs};

use anyhow::{Context, Result, bail};
use atakit_cloud::CloudConfig;
use atakit_workload::{
    GithubWorkloadRepository, HttpWorkloadRepository, WorkloadRepository,
};
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
    pub workload: WorkloadConfig,
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

    /// Find a configured GitHub repository whose local name (portion after
    /// the last `/`) matches `name`. Used by `image pull` to resolve the
    /// repository component of an image reference back to a full
    /// `owner/repo` path.
    pub fn find_repo_by_local_name(&self, name: &str) -> Option<&str> {
        self.repositories
            .iter()
            .map(|s| s.as_str())
            .find(|r| repo_local_name(r) == name)
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

/// `[workload]` section: where to find and store workload archives.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WorkloadConfig {
    /// Name of the default repository (must be a key in `repositories`).
    pub default_repository: Option<String>,
    /// Named workload repositories. Each entry is one of [`WorkloadRepositorySpec`].
    #[serde(default)]
    pub repositories: BTreeMap<String, WorkloadRepositorySpec>,
}

/// One configured workload repository.
///
/// TOML form is a tagged enum keyed on `type`:
///
/// ```toml
/// [workload.repositories.main]
/// type = "http"
/// url = "https://registry.example.com"
///
/// [workload.repositories.gh-fallback]
/// type = "github"
/// repo = "automata-network/workload-archives"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WorkloadRepositorySpec {
    Http {
        url: String,
    },
    Github {
        /// Full GitHub `owner/repo` path.
        repo: String,
    },
}

impl WorkloadConfig {
    /// Resolve a CLI argument into a [`WorkloadRepositorySpec`].
    ///
    /// `cli_arg` accepts:
    /// * a configured remote name (e.g. `main`),
    /// * an `http(s)://...` URL (treated as an HTTP repository),
    /// * an `owner/repo` path (treated as a GitHub repository).
    ///
    /// If `cli_arg` is `None`, the default repository is used.
    pub fn resolve(&self, cli_arg: Option<&str>) -> Result<WorkloadRepositorySpec> {
        if let Some(arg) = cli_arg {
            if arg.starts_with("http://") || arg.starts_with("https://") {
                return Ok(WorkloadRepositorySpec::Http {
                    url: arg.to_string(),
                });
            }
            if let Some(spec) = self.repositories.get(arg) {
                return Ok(spec.clone());
            }
            // owner/repo with no other slashes -> github
            if looks_like_owner_repo(arg) {
                return Ok(WorkloadRepositorySpec::Github {
                    repo: arg.to_string(),
                });
            }
            bail!("unknown workload repository: {arg}");
        }

        if let Some(ref default_name) = self.default_repository {
            if let Some(spec) = self.repositories.get(default_name) {
                return Ok(spec.clone());
            }
            bail!(
                "default workload repository '{}' not found in [workload.repositories]",
                default_name
            );
        }

        bail!(
            "no workload repository configured: pass --repository or add a \
             [workload.repositories] entry in config"
        )
    }

    /// Return the set of repositories to query.
    ///
    /// * If `cli_arg` is provided, returns exactly one entry (honouring
    ///   configured name / raw URL / `owner/repo` forms the same way as
    ///   [`resolve`]).
    /// * If `cli_arg` is `None`, returns every entry in
    ///   `[workload.repositories]` in iteration order (BTreeMap -> sorted
    ///   by name).
    ///
    /// Used by `workload pull` and `workload ls` to fan out across all
    /// configured repositories. Unlike [`resolve`] this does NOT fall back
    /// to `default_repository` -- `default_repository` only matters for
    /// commands with a single-target (push).
    ///
    /// Errors only when `cli_arg` is `None` and zero repositories are
    /// configured.
    pub fn all_repositories(
        &self,
        cli_arg: Option<&str>,
    ) -> Result<Vec<(String, WorkloadRepositorySpec)>> {
        if let Some(arg) = cli_arg {
            let spec = self.resolve(Some(arg))?;
            // Display name: if `arg` matches a configured entry, use
            // that key; otherwise (raw URL / owner-repo shortcut) show
            // the argument verbatim. Both paths currently produce the
            // same string, but keep the distinction explicit for
            // future differentiation.
            let name = arg.to_string();
            return Ok(vec![(name, spec)]);
        }

        if self.repositories.is_empty() {
            bail!(
                "no workload repositories configured: pass --repository or add a \
                 [workload.repositories] entry in config"
            );
        }

        Ok(self
            .repositories
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    /// Build a runtime [`WorkloadRepository`] from the resolved spec.
    /// `github_token` is forwarded to GitHub-backed repositories.
    pub fn build_repository(
        &self,
        spec: WorkloadRepositorySpec,
        github_token: Option<String>,
    ) -> WorkloadRepository {
        match spec {
            WorkloadRepositorySpec::Http { url } => {
                WorkloadRepository::Http(HttpWorkloadRepository::new(&url))
            }
            WorkloadRepositorySpec::Github { repo } => WorkloadRepository::Github(
                GithubWorkloadRepository::new(repo, github_token),
            ),
        }
    }
}

fn looks_like_owner_repo(s: &str) -> bool {
    let mut parts = s.split('/');
    let owner = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    !owner.is_empty()
        && !name.is_empty()
        && parts.next().is_none()
        && !owner.contains(':')
        && !name.contains(':')
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
        if let Ok(v) = env::var("ATAKIT_WORKLOAD_REPOSITORY_URL") {
            if !v.is_empty() {
                // Create or replace a `default` HTTP repository entry.
                let name = self
                    .workload
                    .default_repository
                    .clone()
                    .unwrap_or_else(|| "default".to_string());
                self.workload
                    .repositories
                    .insert(name.clone(), WorkloadRepositorySpec::Http { url: v });
                if self.workload.default_repository.is_none() {
                    self.workload.default_repository = Some(name);
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
    fn find_repo_by_local_name_matches_configured() {
        let config = Config::load_from_str(
            r#"
            [image]
            repositories = [
                "automata-network/automata-linux",
                "automata-network/dev-baseimage",
            ]
            "#,
        )
        .unwrap();
        assert_eq!(
            config.image.find_repo_by_local_name("automata-linux"),
            Some("automata-network/automata-linux"),
        );
        assert_eq!(
            config.image.find_repo_by_local_name("dev-baseimage"),
            Some("automata-network/dev-baseimage"),
        );
        assert_eq!(
            config.image.find_repo_by_local_name("nonexistent"),
            None,
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

    #[test]
    fn parses_workload_repositories_http_and_github() {
        let config = Config::load_from_str(
            r#"
            [workload]
            default_repository = "main"

            [workload.repositories.main]
            type = "http"
            url = "https://registry.example.com"

            [workload.repositories.gh]
            type = "github"
            repo = "automata-network/workload-archives"
            "#,
        )
        .unwrap();
        assert_eq!(
            config.workload.default_repository.as_deref(),
            Some("main")
        );
        assert_eq!(config.workload.repositories.len(), 2);

        match config.workload.resolve(None).unwrap() {
            WorkloadRepositorySpec::Http { url } => {
                assert_eq!(url, "https://registry.example.com");
            }
            _ => panic!("expected http"),
        }

        match config.workload.resolve(Some("gh")).unwrap() {
            WorkloadRepositorySpec::Github { repo } => {
                assert_eq!(repo, "automata-network/workload-archives");
            }
            _ => panic!("expected github"),
        }
    }

    #[test]
    fn workload_resolve_accepts_raw_url() {
        let config = Config::load_from_str("").unwrap();
        match config
            .workload
            .resolve(Some("https://example.com"))
            .unwrap()
        {
            WorkloadRepositorySpec::Http { url } => {
                assert_eq!(url, "https://example.com");
            }
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn workload_resolve_accepts_owner_repo_path() {
        let config = Config::load_from_str("").unwrap();
        match config.workload.resolve(Some("owner/repo")).unwrap() {
            WorkloadRepositorySpec::Github { repo } => assert_eq!(repo, "owner/repo"),
            _ => panic!("expected github"),
        }
    }

    #[test]
    fn workload_resolve_errors_when_no_default_and_no_arg() {
        let config = Config::load_from_str("").unwrap();
        let err = config.workload.resolve(None).unwrap_err();
        assert!(err.to_string().contains("no workload repository"));
    }

    #[test]
    fn workload_resolve_errors_for_unknown_name() {
        let config = Config::load_from_str(
            r#"
            [workload]
            [workload.repositories.main]
            type = "http"
            url = "https://example.com"
            "#,
        )
        .unwrap();
        let err = config.workload.resolve(Some("unknown")).unwrap_err();
        assert!(err.to_string().contains("unknown workload repository"));
    }

    #[test]
    fn all_repositories_returns_every_entry_when_no_arg() {
        let config = Config::load_from_str(
            r#"
            [workload]
            default_repository = "main"

            [workload.repositories.main]
            type = "http"
            url = "https://main.example.com"

            [workload.repositories.staging]
            type = "http"
            url = "https://staging.example.com"

            [workload.repositories.gh]
            type = "github"
            repo = "owner/repo"
            "#,
        )
        .unwrap();
        let all = config.workload.all_repositories(None).unwrap();
        // BTreeMap iteration order: alphabetical.
        assert_eq!(all.len(), 3);
        let names: Vec<_> = all.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["gh", "main", "staging"]);
    }

    #[test]
    fn all_repositories_with_cli_arg_returns_single() {
        let config = Config::load_from_str(
            r#"
            [workload]
            [workload.repositories.main]
            type = "http"
            url = "https://main.example.com"
            [workload.repositories.staging]
            type = "http"
            url = "https://staging.example.com"
            "#,
        )
        .unwrap();
        let only = config
            .workload
            .all_repositories(Some("staging"))
            .unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].0, "staging");
    }

    #[test]
    fn all_repositories_with_owner_repo_arg_synthesises_github_entry() {
        let config = Config::load_from_str("").unwrap();
        let only = config
            .workload
            .all_repositories(Some("owner/some-repo"))
            .unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].0, "owner/some-repo");
        match &only[0].1 {
            WorkloadRepositorySpec::Github { repo } => assert_eq!(repo, "owner/some-repo"),
            _ => panic!("expected github"),
        }
    }

    #[test]
    fn all_repositories_errors_when_empty_and_no_arg() {
        let config = Config::load_from_str("").unwrap();
        let err = config.workload.all_repositories(None).unwrap_err();
        assert!(err.to_string().contains("no workload repositories"));
    }

    #[test]
    fn workload_resolve_rejects_invalid_type() {
        let err = Config::load_from_str(
            r#"
            [workload]
            [workload.repositories.x]
            type = "invalid"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("failed to parse"));
    }
}
