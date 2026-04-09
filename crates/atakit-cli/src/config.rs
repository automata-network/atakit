use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::Duration;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use atakit_cloud::CloudConfig;
use atakit_workload::{
    GithubWorkloadRepository, HttpWorkloadRepository, WorkloadRepository,
};
use indexmap::IndexMap;
use serde::Deserialize;
use wait_timeout::ChildExt;

const COMMAND_DEFAULT_TIMEOUT_SECS: u64 = 30;

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

// ── [image] section ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ImageConfig {
    /// Named image repositories. Each entry points at a GitHub
    /// `owner/repo`, optionally referencing a credential and/or
    /// overriding `list_limit`.
    ///
    /// Declaration order is preserved by `IndexMap`; the first entry is
    /// the implicit default for `image pull` when no image ref is
    /// given.
    pub repositories: IndexMap<String, ImageRepositorySpec>,
    /// Default platforms for `image pull`.
    pub platforms: Option<Vec<String>>,
    /// Global default limit for `image ls`. Overridable per-repo via
    /// `ImageRepositorySpec::list_limit` and per-invocation via
    /// `--limit`. Precedence: `--limit` > per-repo > global.
    pub list_limit: u32,
}

impl Default for ImageConfig {
    fn default() -> Self {
        let mut repositories = IndexMap::new();
        repositories.insert(
            "automata".to_string(),
            ImageRepositorySpec {
                repo: "automata-network/automata-linux".to_string(),
                credential: None,
                list_limit: None,
            },
        );
        Self {
            repositories,
            platforms: None,
            list_limit: 10,
        }
    }
}

impl ImageConfig {
    /// The primary (first-declared) entry -- both the config name and
    /// the full spec -- so callers can read its credential and
    /// `list_limit` override.
    pub fn primary_entry(&self) -> Option<(&str, &ImageRepositorySpec)> {
        self.repositories
            .first()
            .map(|(k, v)| (k.as_str(), v))
    }

    /// Find a configured GitHub repository whose local name (portion
    /// after the last `/`) matches `name`. Returns the entry name and
    /// its spec so callers can resolve the credential and list_limit
    /// override for that entry.
    pub fn find_by_local_name(
        &self,
        name: &str,
    ) -> Option<(&str, &ImageRepositorySpec)> {
        self.repositories
            .iter()
            .find(|(_, s)| repo_local_name(&s.repo) == name)
            .map(|(k, v)| (k.as_str(), v))
    }
}

/// One configured image repository.
///
/// TOML form (canonical inline):
///
/// ```toml
/// [image.repositories]
/// automata = { repo = "automata-network/automata-linux" }
/// private  = { repo = "myorg/private-images", credential = "private" }
/// fast-dev = { repo = "myorg/dev-mirror", list_limit = 3 }
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRepositorySpec {
    /// GitHub `owner/repo` path.
    pub repo: String,
    /// Name of the credential under `[github.credentials]` to use when
    /// talking to this repository. `None` = anonymous requests
    /// (public repos only).
    pub credential: Option<String>,
    /// Per-repo override for `image ls` page size. Precedence at the
    /// call site: `--limit` > per-repo `list_limit` > `[image]
    /// list_limit`.
    pub list_limit: Option<u32>,
}

/// Extract the local image name from a GitHub `owner/repo` string.
///
/// Returns the part after the last `/`, or the whole string if no `/`.
pub fn repo_local_name(repo: &str) -> &str {
    repo.rsplit_once('/').map_or(repo, |(_, name)| name)
}

// ── [github] section ───────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct GithubConfig {
    /// Named credentials. Each entry sets exactly one of `file` /
    /// `command` / `env`. Referenced per-repo via `credential =
    /// "<name>"` on image or workload repository entries.
    pub credentials: IndexMap<String, CredentialSpec>,
}

/// One credential source.
///
/// Exactly one of `file` / `command` / `env` must be set. `timeout_secs`
/// is only valid alongside `command`; setting it on a `file` or `env`
/// credential is a config error (caught at load time).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    /// Path to a file containing the token. `~/` is expanded via
    /// `HOME`. Whitespace is trimmed. Reuse of the same path pattern as
    /// `[publish] owner_key_file` / `relay_key_file`.
    pub file: Option<String>,
    /// Command to exec (no shell) whose stdout yields the token.
    /// Vec-of-strings form avoids shell-escaping bugs.
    pub command: Option<Vec<String>>,
    /// Name of an environment variable holding the token.
    pub env: Option<String>,
    /// Optional timeout for `command` credentials, in seconds.
    /// Defaults to 30s when unset. Only valid with `command`.
    pub timeout_secs: Option<u64>,
}

impl CredentialSpec {
    /// Eager validation at config-load time.
    ///
    /// 1. Exactly one of `file` / `command` / `env` must be set.
    /// 2. `timeout_secs` is only valid with `command`.
    /// 3. `timeout_secs`, when set, must be > 0.
    pub fn validate(&self, name: &str) -> Result<()> {
        let set_count = [self.file.is_some(), self.command.is_some(), self.env.is_some()]
            .into_iter()
            .filter(|b| *b)
            .count();
        match set_count {
            0 => bail!(
                "credential '{name}': must set exactly one of `file`, `command`, `env`"
            ),
            1 => {}
            _ => bail!(
                "credential '{name}': sets more than one of `file` / `command` / `env`; pick one"
            ),
        }

        if self.timeout_secs.is_some() && self.command.is_none() {
            bail!(
                "credential '{name}': `timeout_secs` is only valid with `command`; \
                 `file` and `env` do not spawn subprocesses"
            );
        }
        if let Some(0) = self.timeout_secs {
            bail!("credential '{name}': `timeout_secs` must be greater than 0");
        }
        if let Some(ref cmd) = self.command {
            if cmd.is_empty() {
                bail!("credential '{name}': `command` must not be empty");
            }
        }

        Ok(())
    }

    /// Lazily resolve this credential to a token string.
    ///
    /// Errors always name the credential so users can find the
    /// offending entry immediately.
    pub fn resolve(&self, name: &str) -> Result<String> {
        if let Some(ref path) = self.file {
            return read_key_file(path).with_context(|| {
                format!("credential '{name}': failed to read token from `{path}`")
            });
        }
        if let Some(ref env_name) = self.env {
            return env::var(env_name).map_err(|_| {
                anyhow::anyhow!(
                    "credential '{name}': env var '{env_name}' is not set"
                )
            });
        }
        if let Some(ref argv) = self.command {
            return resolve_command(name, argv, self.timeout_secs);
        }
        // `validate` runs at config load so this is unreachable in
        // practice. Guard against misuse if someone constructs a spec
        // programmatically without validating first.
        bail!("credential '{name}': no source set (internal error: validate not called)")
    }
}

fn resolve_command(
    cred_name: &str,
    argv: &[String],
    timeout_secs: Option<u64>,
) -> Result<String> {
    let timeout_secs = timeout_secs.unwrap_or(COMMAND_DEFAULT_TIMEOUT_SECS);
    let program = argv
        .first()
        .ok_or_else(|| anyhow::anyhow!("credential '{cred_name}': command is empty"))?;

    let mut child = Command::new(program)
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "credential '{cred_name}': failed to spawn `{}`",
                program,
            )
        })?;

    let status = match child.wait_timeout(Duration::from_secs(timeout_secs))? {
        Some(status) => status,
        None => {
            // Best-effort cleanup; we're already erroring so ignore
            // secondary failures.
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "credential '{cred_name}': token_command timed out after {timeout_secs}s \
                 (command: `{}`)",
                program
            );
        }
    };

    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }

    if !status.success() {
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        bail!(
            "credential '{cred_name}': token_command exited with status {code} \
             (command: `{}`): {}",
            program,
            stderr.trim()
        );
    }

    let token = stdout.trim_end_matches(['\n', '\r']).to_string();
    if token.is_empty() {
        bail!("credential '{cred_name}': token_command produced no output");
    }
    Ok(token)
}

// ── [build] section ────────────────────────────────────────────────

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

// ── [publish] section ──────────────────────────────────────────────

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

// ── [workload] section ─────────────────────────────────────────────

/// `[workload]` section: where to find and store workload archives.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WorkloadConfig {
    /// Named workload repositories, in declaration order. First entry
    /// is the implicit default for single-target commands like
    /// `workload push`.
    pub repositories: IndexMap<String, WorkloadRepositorySpec>,
}

/// One configured workload repository.
///
/// TOML form (canonical inline):
///
/// ```toml
/// [workload.repositories]
/// main       = { type = "http",   url  = "https://registry.example.com" }
/// gh-public  = { type = "github", repo = "owner/public-archives" }
/// gh-private = { type = "github", repo = "owner/private-archives", credential = "private" }
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
        /// Name of a credential under `[github.credentials]`. `None` =
        /// anonymous requests (public-read only; pushes will error).
        #[serde(default)]
        credential: Option<String>,
    },
}

impl WorkloadConfig {
    /// Resolve a CLI argument into a [`WorkloadRepositorySpec`].
    ///
    /// `cli_arg` accepts:
    /// * a configured remote name (e.g. `main`),
    /// * an `http(s)://...` URL (treated as an HTTP repository),
    /// * an `owner/repo` path (treated as a GitHub repository with no credential).
    ///
    /// If `cli_arg` is `None`, the first declared repository is used.
    pub fn resolve(
        &self,
        cli_arg: Option<&str>,
    ) -> Result<(String, WorkloadRepositorySpec)> {
        if let Some(arg) = cli_arg {
            if arg.starts_with("http://") || arg.starts_with("https://") {
                return Ok((
                    arg.to_string(),
                    WorkloadRepositorySpec::Http {
                        url: arg.to_string(),
                    },
                ));
            }
            if let Some(spec) = self.repositories.get(arg) {
                return Ok((arg.to_string(), spec.clone()));
            }
            if looks_like_owner_repo(arg) {
                return Ok((
                    arg.to_string(),
                    WorkloadRepositorySpec::Github {
                        repo: arg.to_string(),
                        credential: None,
                    },
                ));
            }
            bail!("unknown workload repository: {arg}");
        }

        if let Some((name, spec)) = self.repositories.first() {
            return Ok((name.clone(), spec.clone()));
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
    ///   `[workload.repositories]` in declaration order (`IndexMap`).
    ///
    /// Used by `workload pull` and `workload ls` to fan out across all
    /// configured repositories. Unlike [`resolve`], this does not fall
    /// back to "first entry only" when `cli_arg` is `None` -- it
    /// returns every entry so discovery can visit all of them.
    pub fn all_repositories(
        &self,
        cli_arg: Option<&str>,
    ) -> Result<Vec<(String, WorkloadRepositorySpec)>> {
        if let Some(arg) = cli_arg {
            let (name, spec) = self.resolve(Some(arg))?;
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
    /// `resolved_token` is the token already produced by
    /// [`Config::resolve_credential`] (or `None` for anonymous access).
    pub fn build_repository(
        &self,
        spec: WorkloadRepositorySpec,
        resolved_token: Option<String>,
    ) -> WorkloadRepository {
        match spec {
            WorkloadRepositorySpec::Http { url } => {
                WorkloadRepository::Http(HttpWorkloadRepository::new(&url))
            }
            WorkloadRepositorySpec::Github { repo, .. } => WorkloadRepository::Github(
                GithubWorkloadRepository::new(repo, resolved_token),
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

// ── Config impl ────────────────────────────────────────────────────

impl Config {
    /// Load config from `config_dir/config.toml`, then apply env var overrides.
    ///
    /// Returns `Config::default()` if the file is missing.
    /// Returns an error if the file exists but is malformed, references
    /// deprecated fields, or fails cross-field validation.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("config.toml");

        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut config = Config::default();
                config.apply_env_overrides();
                config.validate()?;
                return Ok(config);
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to read {}", path.display()));
            }
        };

        Self::load_from_str(&contents)
            .with_context(|| format!("failed to load {}", path.display()))
    }

    /// Parse a config from a TOML string, apply env overrides, and
    /// validate. Used by both [`Config::load`] and the test suite.
    pub fn load_from_str(content: &str) -> Result<Self> {
        check_legacy_fields(content)?;
        let mut config: Config = toml::from_str(content).context("failed to parse config")?;
        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    /// Resolve a single credential by name. Returns an error if the
    /// credential is not defined or if its source fails to produce a
    /// token.
    pub fn resolve_credential(&self, name: &str) -> Result<String> {
        match self.github.credentials.get(name) {
            Some(spec) => spec.resolve(name),
            None => {
                let defined: Vec<&str> = self
                    .github
                    .credentials
                    .keys()
                    .map(|k| k.as_str())
                    .collect();
                bail!(
                    "unknown credential '{name}'; defined: [{}]",
                    defined.join(", ")
                )
            }
        }
    }

    /// Deduplicating batch resolver. Call this once with every
    /// credential name a command will touch, then look up per-repo
    /// tokens in the returned map. Avoids re-running the same
    /// `token_command` N times during a multi-repo fan-out.
    ///
    /// Errors if any named credential is unknown or fails to resolve.
    pub fn resolve_credentials_for(
        &self,
        names: &[&str],
    ) -> Result<HashMap<String, String>> {
        let mut out = HashMap::new();
        for name in names {
            if out.contains_key(*name) {
                continue;
            }
            let token = self.resolve_credential(name)?;
            out.insert((*name).to_string(), token);
        }
        Ok(out)
    }

    fn validate(&self) -> Result<()> {
        // Image repositories must be non-empty and each entry must be
        // a well-formed `owner/repo` path.
        if self.image.repositories.is_empty() {
            bail!("image.repositories must contain at least one entry");
        }
        for (name, spec) in &self.image.repositories {
            validate_repo_path(name, &spec.repo)?;
        }

        // Every credential must pass its own xor / timeout checks.
        for (name, spec) in &self.github.credentials {
            spec.validate(name)?;
        }

        // Every repository `credential` reference must name a defined
        // credential.
        let defined: Vec<&str> = self
            .github
            .credentials
            .keys()
            .map(|k| k.as_str())
            .collect();
        for (name, spec) in &self.image.repositories {
            if let Some(ref cred) = spec.credential {
                if !self.github.credentials.contains_key(cred) {
                    bail!(
                        "image repository '{name}' references unknown credential \
                         '{cred}'; defined: [{}]",
                        defined.join(", ")
                    );
                }
            }
        }
        for (name, spec) in &self.workload.repositories {
            if let WorkloadRepositorySpec::Github { credential: Some(cred), .. } = spec {
                if !self.github.credentials.contains_key(cred) {
                    bail!(
                        "workload repository '{name}' references unknown credential \
                         '{cred}'; defined: [{}]",
                        defined.join(", ")
                    );
                }
            }
        }

        Ok(())
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = env::var("ATAKIT_DEFAULT_REPO") {
            if !v.is_empty() {
                let mut repos = IndexMap::new();
                repos.insert(
                    "default".to_string(),
                    ImageRepositorySpec {
                        repo: v,
                        credential: None,
                        list_limit: None,
                    },
                );
                self.image.repositories = repos;
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

fn validate_repo_path(entry_name: &str, repo: &str) -> Result<()> {
    if repo.is_empty() {
        bail!(
            "invalid image repository '{entry_name}': `repo` must not be empty"
        );
    }
    if repo.contains('\\') {
        bail!(
            "invalid image repository '{entry_name}': `repo = {:?}` must not contain backslashes",
            repo,
        );
    }
    if Path::new(repo).is_absolute() {
        bail!(
            "invalid image repository '{entry_name}': `repo = {:?}` must not be an absolute path",
            repo,
        );
    }
    if Path::new(repo)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        bail!(
            "invalid image repository '{entry_name}': `repo = {:?}` must not contain path traversal",
            repo,
        );
    }
    if repo.split('/').any(|s| s.is_empty()) {
        bail!(
            "invalid image repository '{entry_name}': `repo = {:?}` contains empty path segment",
            repo,
        );
    }
    Ok(())
}

/// Walk the parsed TOML looking for deprecated fields and emit a clear
/// migration hint. Runs before the "real" deserialization so the error
/// is pinned to the legacy form rather than a confusing "unknown field"
/// message.
fn check_legacy_fields(content: &str) -> Result<()> {
    let value: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        // Malformed TOML: defer to the main parser which will produce
        // a better error message.
        Err(_) => return Ok(()),
    };

    if let Some(github) = value.get("github").and_then(|v| v.as_table()) {
        if github.contains_key("token") {
            bail!(
                "`[github] token` is no longer supported. Define a named credential \
                 under `[github.credentials]` and reference it from each repository \
                 entry via `credential = \"<name>\"`. See config_template.toml for \
                 examples."
            );
        }
    }

    if let Some(workload) = value.get("workload").and_then(|v| v.as_table()) {
        if workload.contains_key("default_repository") {
            bail!(
                "`[workload] default_repository` is no longer supported. The first \
                 entry declared in `[workload.repositories]` is the implicit default \
                 for `workload push`; reorder entries if the default should change."
            );
        }
    }

    if let Some(image) = value.get("image").and_then(|v| v.as_table()) {
        if image.contains_key("repository") {
            bail!(
                "`[image] repository = ...` (singular) is no longer supported. Define \
                 each entry as a typed inline table under `[image.repositories]`, \
                 e.g. `automata = {{ repo = \"automata-network/automata-linux\" }}`. \
                 See config_template.toml for examples."
            );
        }
        if let Some(repos) = image.get("repositories") {
            if repos.is_str() || repos.is_array() {
                bail!(
                    "`image.repositories = [\"owner/repo\", ...]` (bare string/array \
                     form) is no longer supported. Define each entry as a typed inline \
                     table under `[image.repositories]`, e.g. \
                     `automata = {{ repo = \"automata-network/automata-linux\" }}`. \
                     See config_template.toml for examples."
                );
            }
        }
    }

    // GITHUB_TOKEN env magic override is gone; warn if the environment
    // sets it so users don't silently lose behavior. We surface this as
    // a stderr warning (non-fatal) because unsetting GITHUB_TOKEN in CI
    // is extra friction and some users may have it set for reasons
    // unrelated to atakit (e.g. gh CLI).
    // Note: the warning lives here rather than in apply_env_overrides
    // because `check_legacy_fields` runs once at load, whereas
    // apply_env_overrides runs after parse and we only want one warning
    // per invocation.
    // Intentionally no action -- just don't auto-consume it any more.
    Ok(())
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

// ═══════════════════════════════════════════════════════════════════
//                              tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // ── baseline / parsing ───────────────────────────────────────

    fn repo_paths(config: &Config) -> Vec<&str> {
        config
            .image
            .repositories
            .values()
            .map(|s| s.repo.as_str())
            .collect()
    }

    #[test]
    fn missing_file_returns_defaults() {
        let dir = TempDir::new().unwrap();
        let config = Config::load(dir.path()).unwrap();
        assert_eq!(repo_paths(&config), vec!["automata-network/automata-linux"]);
        assert_eq!(config.image.list_limit, 10);
        assert!(config.image.platforms.is_none());
        assert!(config.github.credentials.is_empty());
        assert_eq!(config.build.container_engine, "auto");
    }

    #[test]
    fn empty_config_returns_defaults() {
        let config = Config::load_from_str("").unwrap();
        assert_eq!(repo_paths(&config), vec!["automata-network/automata-linux"]);
        assert_eq!(config.image.list_limit, 10);
    }

    #[test]
    fn parses_full_config() {
        let config = Config::load_from_str(
            r#"
            [image]
            platforms = ["gcp", "aws"]
            list_limit = 25

            [image.repositories]
            mine = { repo = "owner/my-images" }

            [github.credentials]
            pub = { env = "MY_TOKEN" }

            [build]
            container_engine = "podman"
            "#,
        )
        .unwrap();

        assert_eq!(repo_paths(&config), vec!["owner/my-images"]);
        assert_eq!(
            config.image.platforms.as_deref(),
            Some(&["gcp".to_string(), "aws".to_string()][..])
        );
        assert_eq!(config.image.list_limit, 25);
        assert_eq!(config.github.credentials.len(), 1);
        assert_eq!(config.build.container_engine, "podman");
    }

    #[test]
    fn parses_multiple_image_repositories_in_declaration_order() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            automata = { repo = "automata-network/automata-linux" }
            debug    = { repo = "automata-network/debug-linux" }
            "#,
        )
        .unwrap();
        assert_eq!(
            repo_paths(&config),
            vec![
                "automata-network/automata-linux",
                "automata-network/debug-linux"
            ]
        );
        let (first_name, first_spec) = config.image.primary_entry().unwrap();
        assert_eq!(first_name, "automata");
        assert_eq!(first_spec.repo, "automata-network/automata-linux");
    }

    #[test]
    fn find_by_local_name_matches_configured() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            automata = { repo = "automata-network/automata-linux" }
            baseimg  = { repo = "automata-network/dev-baseimage" }
            "#,
        )
        .unwrap();
        let (name, spec) = config.image.find_by_local_name("automata-linux").unwrap();
        assert_eq!(name, "automata");
        assert_eq!(spec.repo, "automata-network/automata-linux");

        let (name, spec) = config.image.find_by_local_name("dev-baseimage").unwrap();
        assert_eq!(name, "baseimg");
        assert_eq!(spec.repo, "automata-network/dev-baseimage");

        assert!(config.image.find_by_local_name("nonexistent").is_none());
    }

    // ── legacy field rejection ───────────────────────────────────

    #[test]
    fn legacy_github_token_field_errors_with_migration_hint() {
        let err = Config::load_from_str(
            r#"
            [github]
            token = "ghp_test123"
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("[github] token"), "got: {msg}");
        assert!(msg.contains("[github.credentials]"), "got: {msg}");
    }

    #[test]
    fn legacy_workload_default_repository_field_errors_with_migration_hint() {
        let err = Config::load_from_str(
            r#"
            [workload]
            default_repository = "main"
            [workload.repositories]
            main = { type = "http", url = "https://example.com" }
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("default_repository"), "got: {msg}");
        assert!(msg.contains("first"), "got: {msg}");
    }

    #[test]
    fn legacy_bare_string_image_repositories_errors_with_migration_hint() {
        let err = Config::load_from_str(
            r#"
            [image]
            repositories = ["owner/images"]
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bare string/array form"), "got: {msg}");
        assert!(msg.contains("inline table"), "got: {msg}");
    }

    #[test]
    fn legacy_singular_image_repository_field_errors_with_migration_hint() {
        let err = Config::load_from_str(
            r#"
            [image]
            repository = "owner/images"
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("repository"), "got: {msg}");
        assert!(msg.contains("inline table"), "got: {msg}");
    }

    // ── image repository validation ──────────────────────────────

    #[test]
    fn rejects_backslash_in_repo_path() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            bad = { repo = 'owner\repo' }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("backslash"));
    }

    #[test]
    fn rejects_dotdot_in_repo_path() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            bad = { repo = ".." }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("traversal"));
    }

    #[test]
    fn rejects_empty_repo_path() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            bad = { repo = "" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_trailing_slash_in_repo_path() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            bad = { repo = "owner/" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty path segment"));
    }

    #[test]
    fn rejects_empty_image_repositories() {
        // Have to explicitly define an empty map -- default seeds one.
        let err = Config::load_from_str(
            r#"
            [image]
            list_limit = 5
            [image.repositories]
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    // ── credentials: xor + timeout validation ────────────────────

    #[test]
    fn credential_xor_zero_fields_errors() {
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            bad = {}
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn credential_xor_two_fields_errors() {
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            bad = { file = "/tmp/x", env = "Y" }
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("more than one") || msg.contains("pick one"), "got: {msg}");
    }

    #[test]
    fn credential_xor_one_field_ok() {
        let config = Config::load_from_str(
            r#"
            [github.credentials]
            one = { env = "GH_TOKEN" }
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap();
        assert_eq!(config.github.credentials.len(), 1);
    }

    #[test]
    fn credential_timeout_on_file_errors_at_load_time() {
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            bad = { file = "/tmp/x", timeout_secs = 5 }
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("timeout_secs"), "got: {msg}");
        assert!(msg.contains("only valid with `command`"), "got: {msg}");
    }

    #[test]
    fn credential_timeout_on_env_errors_at_load_time() {
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            bad = { env = "X", timeout_secs = 5 }
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("only valid with `command`"));
    }

    #[test]
    fn credential_timeout_zero_errors_at_load_time() {
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            bad = { command = ["echo", "x"], timeout_secs = 0 }
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("greater than 0"));
    }

    #[test]
    fn credential_empty_command_errors_at_load_time() {
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            bad = { command = [] }
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    // ── credential reference integrity ───────────────────────────

    #[test]
    fn image_repo_with_unknown_credential_reference_errors() {
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            pub = { env = "PUB_TOKEN" }
            [image.repositories]
            x = { repo = "a/b", credential = "missing" }
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown credential 'missing'"), "got: {msg}");
    }

    #[test]
    fn workload_repo_with_unknown_credential_reference_errors() {
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            pub = { env = "PUB_TOKEN" }
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            gh = { type = "github", repo = "a/b", credential = "missing" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown credential 'missing'"));
    }

    // ── credential resolution ────────────────────────────────────

    #[test]
    fn credential_env_reads_named_var() {
        // Use a process-unique env var so concurrent tests don't race.
        let var = "ATAKIT_TEST_TOKEN_ENV_READS";
        unsafe { env::set_var(var, "token-xyz") };
        let spec = CredentialSpec {
            file: None,
            command: None,
            env: Some(var.to_string()),
            timeout_secs: None,
        };
        let token = spec.resolve("pub").unwrap();
        assert_eq!(token, "token-xyz");
        unsafe { env::remove_var(var) };
    }

    #[test]
    fn credential_env_errors_when_var_unset() {
        let var = "ATAKIT_TEST_TOKEN_ENV_UNSET";
        unsafe { env::remove_var(var) };
        let spec = CredentialSpec {
            file: None,
            command: None,
            env: Some(var.to_string()),
            timeout_secs: None,
        };
        let err = spec.resolve("pub").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pub"), "got: {msg}");
        assert!(msg.contains("is not set"), "got: {msg}");
    }

    #[test]
    fn credential_file_reads_and_trims() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("token");
        let mut f = fs::File::create(&path).unwrap();
        writeln!(f, "  ghp_test  ").unwrap();
        let spec = CredentialSpec {
            file: Some(path.to_string_lossy().into_owned()),
            command: None,
            env: None,
            timeout_secs: None,
        };
        assert_eq!(spec.resolve("pub").unwrap(), "ghp_test");
    }

    #[test]
    fn credential_command_runs_and_trims_output() {
        let spec = CredentialSpec {
            file: None,
            command: Some(vec!["echo".into(), "token-abc".into()]),
            env: None,
            timeout_secs: None,
        };
        assert_eq!(spec.resolve("pub").unwrap(), "token-abc");
    }

    #[test]
    fn credential_command_errors_on_nonzero_exit() {
        let spec = CredentialSpec {
            file: None,
            command: Some(vec!["false".into()]),
            env: None,
            timeout_secs: None,
        };
        let err = spec.resolve("bad").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bad"), "got: {msg}");
        assert!(msg.contains("exited with status"), "got: {msg}");
    }

    #[test]
    fn credential_command_errors_on_empty_output() {
        let spec = CredentialSpec {
            file: None,
            command: Some(vec!["true".into()]),
            env: None,
            timeout_secs: None,
        };
        let err = spec.resolve("empty").unwrap_err();
        assert!(err.to_string().contains("no output"));
    }

    #[test]
    fn credential_command_respects_custom_timeout_override() {
        // Sleep for 5 seconds with a 1-second timeout -> must fire.
        let spec = CredentialSpec {
            file: None,
            command: Some(vec!["sleep".into(), "5".into()]),
            env: None,
            timeout_secs: Some(1),
        };
        let start = std::time::Instant::now();
        let err = spec.resolve("slow").unwrap_err();
        let elapsed = start.elapsed();
        let msg = err.to_string();
        assert!(msg.contains("slow"), "got: {msg}");
        assert!(msg.contains("timed out after 1s"), "got: {msg}");
        // Sanity: we didn't actually wait 5 seconds.
        assert!(elapsed < Duration::from_secs(3), "elapsed: {:?}", elapsed);
    }

    // ── Config::resolve_credential ───────────────────────────────

    #[test]
    fn resolve_credential_looks_up_by_name() {
        let var = "ATAKIT_TEST_RESOLVE_CREDENTIAL";
        unsafe { env::set_var(var, "tok") };
        let config = Config::load_from_str(&format!(
            r#"
            [github.credentials]
            pub = {{ env = "{var}" }}
            [image.repositories]
            x = {{ repo = "a/b" }}
            "#,
        ))
        .unwrap();
        assert_eq!(config.resolve_credential("pub").unwrap(), "tok");
        unsafe { env::remove_var(var) };
    }

    #[test]
    fn resolve_credential_errors_on_unknown_name() {
        let config = Config::load_from_str(
            r#"
            [github.credentials]
            pub = { env = "DUMMY" }
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap();
        let err = config.resolve_credential("nope").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown credential 'nope'"), "got: {msg}");
        assert!(msg.contains("pub"), "got: {msg}");
    }

    #[test]
    fn resolves_credentials_for_batches_and_dedupes() {
        let var = "ATAKIT_TEST_BATCH_RESOLVE";
        unsafe { env::set_var(var, "batched") };
        let config = Config::load_from_str(&format!(
            r#"
            [github.credentials]
            pub = {{ env = "{var}" }}
            [image.repositories]
            x = {{ repo = "a/b" }}
            "#,
        ))
        .unwrap();
        let resolved = config.resolve_credentials_for(&["pub", "pub"]).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get("pub").map(String::as_str), Some("batched"));
        unsafe { env::remove_var(var) };
    }

    // ── workload repositories ────────────────────────────────────

    #[test]
    fn parses_workload_repositories_http_and_github() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            main = { type = "http",   url = "https://registry.example.com" }
            gh   = { type = "github", repo = "owner/workload-archives", credential = "pub" }
            [github.credentials]
            pub = { env = "GH_PUB" }
            "#,
        )
        .unwrap();
        assert_eq!(config.workload.repositories.len(), 2);

        let (name, spec) = config.workload.resolve(None).unwrap();
        assert_eq!(name, "main");
        match spec {
            WorkloadRepositorySpec::Http { url } => {
                assert_eq!(url, "https://registry.example.com")
            }
            _ => panic!("expected http"),
        }

        match config.workload.resolve(Some("gh")).unwrap().1 {
            WorkloadRepositorySpec::Github { repo, credential } => {
                assert_eq!(repo, "owner/workload-archives");
                assert_eq!(credential.as_deref(), Some("pub"));
            }
            _ => panic!("expected github"),
        }
    }

    #[test]
    fn workload_resolve_accepts_raw_url() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap();
        let (name, spec) = config.workload.resolve(Some("https://example.com")).unwrap();
        assert_eq!(name, "https://example.com");
        match spec {
            WorkloadRepositorySpec::Http { url } => assert_eq!(url, "https://example.com"),
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn workload_resolve_accepts_owner_repo_path() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap();
        let (_, spec) = config.workload.resolve(Some("owner/repo")).unwrap();
        match spec {
            WorkloadRepositorySpec::Github { repo, credential } => {
                assert_eq!(repo, "owner/repo");
                assert!(credential.is_none());
            }
            _ => panic!("expected github"),
        }
    }

    #[test]
    fn workload_resolve_errors_when_empty() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap();
        let err = config.workload.resolve(None).unwrap_err();
        assert!(err.to_string().contains("no workload repository"));
    }

    #[test]
    fn workload_resolve_picks_first_declared_when_no_arg() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            main    = { type = "http", url = "https://main.example.com" }
            staging = { type = "http", url = "https://staging.example.com" }
            "#,
        )
        .unwrap();
        let (name, _) = config.workload.resolve(None).unwrap();
        assert_eq!(name, "main");
    }

    #[test]
    fn workload_declaration_order_preserved() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            zulu    = { type = "http", url = "https://z.example.com" }
            alpha   = { type = "http", url = "https://a.example.com" }
            bravo   = { type = "http", url = "https://b.example.com" }
            "#,
        )
        .unwrap();
        let names: Vec<&str> = config
            .workload
            .repositories
            .keys()
            .map(String::as_str)
            .collect();
        // Insertion order, not alphabetical.
        assert_eq!(names, vec!["zulu", "alpha", "bravo"]);
        let (first, _) = config.workload.resolve(None).unwrap();
        assert_eq!(first, "zulu");
    }

    #[test]
    fn image_declaration_order_preserved() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            zulu  = { repo = "z/z" }
            alpha = { repo = "a/a" }
            bravo = { repo = "b/b" }
            "#,
        )
        .unwrap();
        let names: Vec<&str> = config
            .image
            .repositories
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(names, vec!["zulu", "alpha", "bravo"]);
        assert_eq!(
            config.image.primary_entry().map(|(_, s)| s.repo.as_str()),
            Some("z/z")
        );
    }

    #[test]
    fn all_repositories_returns_every_entry_when_no_arg() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            main    = { type = "http", url = "https://main.example.com" }
            staging = { type = "http", url = "https://staging.example.com" }
            gh      = { type = "github", repo = "owner/repo" }
            "#,
        )
        .unwrap();
        let all = config.workload.all_repositories(None).unwrap();
        assert_eq!(all.len(), 3);
        let names: Vec<_> = all.iter().map(|(n, _)| n.as_str()).collect();
        // Declaration order.
        assert_eq!(names, vec!["main", "staging", "gh"]);
    }

    #[test]
    fn all_repositories_with_cli_arg_returns_single() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            main    = { type = "http", url = "https://main.example.com" }
            staging = { type = "http", url = "https://staging.example.com" }
            "#,
        )
        .unwrap();
        let only = config.workload.all_repositories(Some("staging")).unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].0, "staging");
    }

    #[test]
    fn all_repositories_errors_when_empty_and_no_arg() {
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap();
        let err = config.workload.all_repositories(None).unwrap_err();
        assert!(err.to_string().contains("no workload repositories"));
    }

    #[test]
    fn workload_resolve_rejects_invalid_type() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            bad = { type = "invalid" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("failed to parse"));
    }

    // ── list_limit precedence ────────────────────────────────────

    // The precedence rule lives at the call sites in
    // commands/image/ls.rs (args.limit > spec.list_limit > config
    // global). Tests here verify the underlying config types expose
    // the right values for those call sites to use.

    #[test]
    fn per_repo_list_limit_override_beats_global() {
        let config = Config::load_from_str(
            r#"
            [image]
            list_limit = 10
            [image.repositories]
            fast = { repo = "a/b", list_limit = 3 }
            "#,
        )
        .unwrap();
        let (_, spec) = config.image.primary_entry().unwrap();
        assert_eq!(spec.list_limit, Some(3));
        assert_eq!(config.image.list_limit, 10);
        // Simulate the resolution that the call site performs.
        let effective = spec.list_limit.unwrap_or(config.image.list_limit);
        assert_eq!(effective, 3);
    }

    #[test]
    fn missing_per_repo_list_limit_falls_back_to_global() {
        let config = Config::load_from_str(
            r#"
            [image]
            list_limit = 10
            [image.repositories]
            main = { repo = "a/b" }
            "#,
        )
        .unwrap();
        let (_, spec) = config.image.primary_entry().unwrap();
        assert!(spec.list_limit.is_none());
        assert_eq!(config.image.list_limit, 10);
        let effective = spec.list_limit.unwrap_or(config.image.list_limit);
        assert_eq!(effective, 10);
    }

    #[test]
    fn cli_limit_flag_beats_per_repo_override() {
        let config = Config::load_from_str(
            r#"
            [image]
            list_limit = 10
            [image.repositories]
            fast = { repo = "a/b", list_limit = 3 }
            "#,
        )
        .unwrap();
        let (_, spec) = config.image.primary_entry().unwrap();
        // Simulate `--limit 5` passed on the CLI.
        let cli_limit = Some(5u32);
        let effective = cli_limit
            .or(spec.list_limit)
            .unwrap_or(config.image.list_limit);
        assert_eq!(effective, 5);
    }

    // ── misc ─────────────────────────────────────────────────────

    #[test]
    fn malformed_toml_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let mut f = fs::File::create(&path).unwrap();
        write!(f, "not valid [[ toml").unwrap();

        let err = Config::load(dir.path()).unwrap_err();
        assert!(err.to_string().contains("failed to"));
    }

    #[test]
    fn load_from_real_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            r#"
            [image]
            list_limit = 3
            [image.repositories]
            custom = { repo = "owner/custom-images" }
            "#,
        )
        .unwrap();

        let config = Config::load(dir.path()).unwrap();
        assert_eq!(repo_paths(&config), vec!["owner/custom-images"]);
        assert_eq!(config.image.list_limit, 3);
    }
}
