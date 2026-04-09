use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs};

use anyhow::{Context, Result, bail};
use atakit_cloud::CloudConfig;
use atakit_workload::{
    GithubWorkloadRepository, HttpWorkloadRepository, WorkloadRepository,
};
use indexmap::IndexMap;
use serde::Deserialize;

const COMMAND_DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Poll interval for the credential-command timeout loop. Chosen so
/// that short-lived helpers finish within one or two ticks and the
/// observed wall-time overhead is < 100 ms while the timeout bound
/// is still tight (user-facing `timeout_secs` is in seconds anyway).
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);

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
        // No hardcoded default repository. Symmetric with
        // `[workload.repositories]`, which also defaults to empty.
        // Commands that need a repository (`image pull`,
        // `image ls --remote`, etc.) error at their own call site
        // when the map is empty; `image ls` (local-only) works fine
        // against an empty map.
        Self {
            repositories: IndexMap::new(),
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
    ///
    /// Rejects ambiguity: if multiple configured entries share the
    /// same local name suffix (e.g. `owner-a/debug-linux` and
    /// `owner-b/debug-linux`), returns an error instead of silently
    /// picking the first match. Matches the "prefer canonical /
    /// accept one non-canonical / error on multiple" pattern used
    /// for release asset lookup in `find_atawl_asset`.
    pub fn find_by_local_name(
        &self,
        name: &str,
    ) -> Result<Option<(&str, &ImageRepositorySpec)>> {
        let matches: Vec<(&str, &ImageRepositorySpec)> = self
            .repositories
            .iter()
            .filter(|(_, s)| repo_local_name(&s.repo) == name)
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        match matches.as_slice() {
            [] => Ok(None),
            [single] => Ok(Some(*single)),
            many => {
                let entries: Vec<String> = many
                    .iter()
                    .map(|(k, s)| format!("{k} ({})", s.repo))
                    .collect();
                bail!(
                    "local name '{name}' matches multiple configured image \
                     repositories: [{}]; pass `--repo <owner/repo>` or rename \
                     one of the entries to disambiguate",
                    entries.join(", ")
                )
            }
        }
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
    /// All three source kinds apply identical whitespace handling:
    /// the raw value is `.trim()`-ed and a whitespace-only result is
    /// rejected as empty. This keeps behavior consistent across
    /// `file` (which already trimmed via [`read_key_file`]), `env`
    /// (which previously let `GH_TOKEN=""` slip through and fail at
    /// the API with a cryptic 401), and `command` (which previously
    /// only trimmed trailing newlines, so leading whitespace from a
    /// `pass show` output would leak into the Bearer header).
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
            return match env::var(env_name) {
                Ok(v) => {
                    let trimmed = v.trim().to_string();
                    if trimmed.is_empty() {
                        Err(anyhow::anyhow!(
                            "credential '{name}': env var '{env_name}' is set but \
                             empty or whitespace-only"
                        ))
                    } else {
                        Ok(trimmed)
                    }
                }
                Err(_) => Err(anyhow::anyhow!(
                    "credential '{name}': env var '{env_name}' is not set"
                )),
            };
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

    // Drain stdout and stderr on background threads CONCURRENTLY
    // with the wait loop. Reading pipes only after the child has
    // exited (the obvious approach) deadlocks when the helper
    // writes more than the kernel pipe buffer can hold (~64 KiB on
    // Linux): the child blocks on write() waiting for a reader,
    // never exits, and the timeout fires -- so a helper that
    // spews debug output to stderr before printing the token would
    // look like a timeout when the real problem is backpressure.
    // Spawning drainers up front prevents the deadlock.
    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("credential '{cred_name}': child stdout unavailable"))?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("credential '{cred_name}': child stderr unavailable"))?;
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut pipe = stdout_pipe;
        let _ = pipe.read_to_string(&mut buf);
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_string(&mut buf);
        buf
    });

    // Bound the child's lifetime via a polling loop on `try_wait`.
    // We previously used the `wait-timeout` crate, but its
    // SIGCHLD + self-pipe machinery panics in sandboxed /
    // seccomp-restricted Linux environments with "bad error on
    // write fd: Operation not permitted", which aborts the whole
    // process instead of surfacing a clean credential error. A
    // plain `waitpid(pid, WNOHANG)` poll loop touches none of that
    // machinery and works everywhere `kill(pid, SIGKILL)` does.
    //
    // Overhead is negligible: ~20 wakeups/sec during the wait, and
    // credential resolution happens once per CLI invocation.
    let timeout = Duration::from_secs(timeout_secs);
    let start = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= timeout {
                    // Best-effort cleanup; we're already erroring
                    // so ignore secondary failures. The kill
                    // closes the child's pipe ends, which
                    // releases the drainer threads from their
                    // blocking reads.
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    bail!(
                        "credential '{cred_name}': command timed out after {timeout_secs}s \
                         (command: `{}`)",
                        program
                    );
                }
                std::thread::sleep(COMMAND_POLL_INTERVAL);
            }
        }
    };

    // Child exited; its pipe ends are closed, so the drainers have
    // already seen EOF. Joining gives us whatever they buffered.
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    if !status.success() {
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        bail!(
            "credential '{cred_name}': command exited with status {code} \
             (command: `{}`): {}",
            program,
            stderr.trim()
        );
    }

    // Full whitespace trim (not just trailing newlines) so that
    // `pass show` output with a leading blank line or helpers that
    // wrap the token in `echo "  $TOKEN  "` don't leak whitespace
    // into the Bearer header. Matches the behavior of the `file`
    // source, which has always used `read_key_file`'s `.trim()`.
    let token = stdout.trim().to_string();
    if token.is_empty() {
        bail!(
            "credential '{cred_name}': command produced no token \
             (empty or whitespace-only output)"
        );
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
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
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
                // If the user has one or more configured github
                // entries pointing at the same `owner/repo`, inherit
                // their credential. Otherwise the shorthand would
                // dead-end for private repos: push refuses to run
                // without a credential, so `--repository owner/repo`
                // would silently lose the credential that a named
                // entry would have carried.
                let credential = inherit_github_credential(&self.repositories, arg)?;
                return Ok((
                    arg.to_string(),
                    WorkloadRepositorySpec::Github {
                        repo: arg.to_string(),
                        credential,
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

/// Look for any configured `[workload.repositories.*]` github entry
/// whose `repo` path equals `arg`, and return its credential so the
/// raw `owner/repo` shorthand can inherit it.
///
/// If multiple configured entries share the same `repo` path but
/// disagree on credential, refuse to guess -- force the user to pass
/// the specific entry name.
///
/// Returns `Ok(None)` when no entry matches; the caller proceeds
/// with an anonymous github spec (public repos still work).
fn inherit_github_credential(
    repositories: &IndexMap<String, WorkloadRepositorySpec>,
    arg: &str,
) -> Result<Option<String>> {
    let matches: Vec<&Option<String>> = repositories
        .values()
        .filter_map(|spec| match spec {
            WorkloadRepositorySpec::Github { repo, credential } if repo == arg => {
                Some(credential)
            }
            _ => None,
        })
        .collect();

    match matches.as_slice() {
        [] => Ok(None),
        [single] => Ok((*single).clone()),
        many => {
            let distinct: std::collections::BTreeSet<&str> = many
                .iter()
                .map(|c| c.as_deref().unwrap_or("(none)"))
                .collect();
            if distinct.len() > 1 {
                bail!(
                    "multiple [workload.repositories] entries point at `{arg}` \
                     with different credentials ({:?}); pass the specific \
                     entry name instead of the raw owner/repo path",
                    distinct
                );
            }
            Ok(many[0].clone())
        }
    }
}

/// Build the single-entry image repository spec produced by the
/// `ATAKIT_DEFAULT_REPO` env override.
///
/// If any already-configured entry has the same `repo` path, inherit
/// its credential and `list_limit` so users who set the env var to
/// steer image commands at a private mirror don't silently lose
/// their auth. Otherwise synthesize an anonymous entry (public repos
/// still work, private repos will fail at the API with a clear 401
/// the same way they would without the env override).
///
/// Factored out of `apply_env_overrides` so it can be unit-tested
/// without mutating process env vars (which would race with other
/// tests running in parallel via `Config::load_from_str`).
fn default_repo_entry(
    repositories: &IndexMap<String, ImageRepositorySpec>,
    repo_path: &str,
) -> ImageRepositorySpec {
    repositories
        .values()
        .find(|s| s.repo == repo_path)
        .cloned()
        .unwrap_or_else(|| ImageRepositorySpec {
            repo: repo_path.to_string(),
            credential: None,
            list_limit: None,
        })
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

    /// Deduplicating batch resolver (strict). Call this once with
    /// every credential name a single-target command will touch, then
    /// look up per-repo tokens in the returned map. Avoids re-running
    /// the same `command` credential N times.
    ///
    /// Errors if any named credential is unknown or fails to resolve.
    /// Callers in multi-repo fan-out paths (`image ls`, `workload ls`,
    /// `workload pull` in discovery mode) must use
    /// [`resolve_credentials_best_effort`] instead so one broken
    /// credential doesn't abort discovery for every other repository.
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

    /// Deduplicating batch resolver (best-effort). Like
    /// [`resolve_credentials_for`] but collects per-credential failures
    /// instead of aborting on the first one.
    ///
    /// Returns `(successes, failures)` where `failures` maps each
    /// credential name that failed to its error message. Callers
    /// should warn on every failure and skip any repository whose
    /// `credential` field is in the failures map.
    ///
    /// Used by multi-repo fan-out commands (`image ls`, `workload ls`,
    /// `workload pull` in discovery mode) so a single broken
    /// credential (stale file, missing env var, dead helper)
    /// doesn't swallow the entire listing / pull.
    pub fn resolve_credentials_best_effort(
        &self,
        names: &[&str],
    ) -> (HashMap<String, String>, HashMap<String, String>) {
        let mut ok = HashMap::new();
        let mut err = HashMap::new();
        for name in names {
            let key = *name;
            if ok.contains_key(key) || err.contains_key(key) {
                continue;
            }
            match self.resolve_credential(key) {
                Ok(t) => {
                    ok.insert(key.to_string(), t);
                }
                Err(e) => {
                    // anyhow's alternate formatter includes the full
                    // cause chain. Without this, a `file` credential
                    // pointing at a missing path would surface as
                    // "credential 'x': failed to read token from `/p`"
                    // with the underlying ENOENT / EACCES hidden.
                    // Using `{e:#}` preserves the distinction so the
                    // user can tell "file missing" from "permission
                    // denied".
                    err.insert(key.to_string(), format!("{e:#}"));
                }
            }
        }
        (ok, err)
    }

    fn validate(&self) -> Result<()> {
        // Image repositories must be non-empty and each entry must be
        // a well-formed `owner/repo` path.
        // Empty `[image.repositories]` is allowed: `image ls`
        // (local-only) doesn't need any configured remote, and
        // commands that DO need one (`pull`, `ls --remote`, etc.)
        // error at their own call sites with "no image repositories
        // configured" when the map is empty. This is symmetric with
        // `[workload.repositories]`, which is also empty by default.
        for (name, spec) in &self.image.repositories {
            validate_repo_path("image", name, &spec.repo)?;
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
            if let WorkloadRepositorySpec::Github { repo, credential } = spec {
                // Apply the same path sanity checks to workload
                // github repos that image repos get -- empty,
                // backslash, path traversal, leading/trailing or
                // internal empty segment. Otherwise a typo like
                // `repo = "owner/"` silently loads and only fails
                // much later with a confusing GitHub API error.
                validate_repo_path("workload", name, repo)?;
                if let Some(cred) = credential {
                    if !self.github.credentials.contains_key(cred) {
                        bail!(
                            "workload repository '{name}' references unknown credential \
                             '{cred}'; defined: [{}]",
                            defined.join(", ")
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = env::var("ATAKIT_DEFAULT_REPO") {
            if !v.is_empty() {
                let spec = default_repo_entry(&self.image.repositories, &v);
                let mut repos = IndexMap::new();
                repos.insert("default".to_string(), spec);
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

fn validate_repo_path(section: &str, entry_name: &str, repo: &str) -> Result<()> {
    if repo.is_empty() {
        bail!(
            "invalid {section} repository '{entry_name}': `repo` must not be empty"
        );
    }
    if repo.contains('\\') {
        bail!(
            "invalid {section} repository '{entry_name}': `repo = {:?}` must not contain backslashes",
            repo,
        );
    }
    if Path::new(repo).is_absolute() {
        bail!(
            "invalid {section} repository '{entry_name}': `repo = {:?}` must not be an absolute path",
            repo,
        );
    }
    if Path::new(repo)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        bail!(
            "invalid {section} repository '{entry_name}': `repo = {:?}` must not contain path traversal",
            repo,
        );
    }
    if repo.split('/').any(|s| s.is_empty()) {
        bail!(
            "invalid {section} repository '{entry_name}': `repo = {:?}` contains empty path segment",
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

    // The old `[registry]` section (pre-redesign http-registry-only
    // config) silently dropped through serde's default skipping,
    // leaving users staring at a working config that ignored their
    // actual settings. Catch it explicitly so the migration error is
    // actionable.
    if value.get("registry").is_some() {
        bail!(
            "`[registry]` is no longer supported. Move the URL into \
             `[workload.repositories]`, e.g. \
             `main = {{ type = \"http\", url = \"https://...\" }}`. \
             See config_template.toml for examples."
        );
    }

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
        // No hardcoded default repository; the map is empty until
        // the user configures one. Symmetric with
        // `workload.repositories`.
        assert!(config.image.repositories.is_empty());
        assert_eq!(config.image.list_limit, 10);
        assert!(config.image.platforms.is_none());
        assert!(config.github.credentials.is_empty());
        assert_eq!(config.build.container_engine, "auto");
    }

    #[test]
    fn empty_config_returns_defaults() {
        let config = Config::load_from_str("").unwrap();
        assert!(config.image.repositories.is_empty());
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
        let (name, spec) = config
            .image
            .find_by_local_name("automata-linux")
            .unwrap()
            .unwrap();
        assert_eq!(name, "automata");
        assert_eq!(spec.repo, "automata-network/automata-linux");

        let (name, spec) = config
            .image
            .find_by_local_name("dev-baseimage")
            .unwrap()
            .unwrap();
        assert_eq!(name, "baseimg");
        assert_eq!(spec.repo, "automata-network/dev-baseimage");

        assert!(
            config
                .image
                .find_by_local_name("nonexistent")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn find_by_local_name_rejects_ambiguous_matches() {
        // Two configured image entries point at different owners
        // but share the same local name suffix. The old behavior
        // silently returned the first match, which meant
        // `image pull debug-linux:v0.5` would pull from whichever
        // owner happened to be first in the file -- an identity-
        // confusion footgun. Require the user to pass
        // `--repo <owner/repo>` or rename one of the entries.
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            owner-a = { repo = "owner-a/debug-linux" }
            owner-b = { repo = "owner-b/debug-linux" }
            "#,
        )
        .unwrap();
        let err = config
            .image
            .find_by_local_name("debug-linux")
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("multiple"), "got: {msg}");
        assert!(msg.contains("owner-a"), "got: {msg}");
        assert!(msg.contains("owner-b"), "got: {msg}");
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
    fn legacy_registry_section_errors_with_migration_hint() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [registry]
            url = "https://old-registry.example.com"
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("[registry]"), "got: {msg}");
        assert!(msg.contains("workload.repositories"), "got: {msg}");
    }

    #[test]
    fn workload_github_repo_with_empty_path_errors_at_load_time() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            bad = { type = "github", repo = "" }
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("workload repository"), "got: {msg}");
        assert!(msg.contains("empty"), "got: {msg}");
    }

    #[test]
    fn workload_github_repo_with_traversal_errors_at_load_time() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            bad = { type = "github", repo = ".." }
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("workload repository"), "got: {msg}");
        assert!(msg.contains("traversal"), "got: {msg}");
    }

    #[test]
    fn workload_github_repo_with_trailing_slash_errors_at_load_time() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            bad = { type = "github", repo = "owner/" }
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("workload repository"), "got: {msg}");
        assert!(msg.contains("empty path segment"), "got: {msg}");
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
    fn empty_image_repositories_is_allowed() {
        // Symmetric with `[workload.repositories]`. Commands that
        // actually need a repository error at their own call
        // sites; `image ls` (local-only) works fine against an
        // empty map.
        let config = Config::load_from_str(
            r#"
            [image]
            list_limit = 5
            [image.repositories]
            "#,
        )
        .unwrap();
        assert!(config.image.repositories.is_empty());
        assert_eq!(config.image.list_limit, 5);
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
        let msg = err.to_string();
        assert!(msg.contains("no token"), "got: {msg}");
        assert!(msg.contains("empty or whitespace-only"), "got: {msg}");
    }

    #[test]
    fn credential_command_errors_on_whitespace_only_output() {
        // Whitespace-only output (spaces, tabs, newlines) must be
        // rejected as empty, not passed through as a literal
        // whitespace token into the Bearer header.
        let spec = CredentialSpec {
            file: None,
            command: Some(vec![
                "sh".into(),
                "-c".into(),
                "printf '   \\n\\t  \\n'".into(),
            ]),
            env: None,
            timeout_secs: None,
        };
        let err = spec.resolve("ws").unwrap_err();
        assert!(err.to_string().contains("empty or whitespace-only"));
    }

    #[test]
    fn credential_command_trims_leading_and_trailing_whitespace() {
        // A helper that outputs "  ghp_xxx  \n" should produce
        // "ghp_xxx" -- full trim, not just trailing newlines. The old
        // behavior leaked the leading spaces into the Bearer header,
        // which GitHub rejects with a cryptic 401.
        let spec = CredentialSpec {
            file: None,
            command: Some(vec![
                "sh".into(),
                "-c".into(),
                "printf '   ghp_xyz  \\n'".into(),
            ]),
            env: None,
            timeout_secs: None,
        };
        let token = spec.resolve("trim").unwrap();
        assert_eq!(token, "ghp_xyz");
    }

    #[test]
    fn credential_env_rejects_empty_string() {
        // `GH_TOKEN=""` in CI must be treated as "not set", not
        // silently passed through as an empty Bearer header that
        // later produces a cryptic 401 from the API.
        let var = "ATAKIT_TEST_EMPTY_ENV_VAR";
        unsafe { env::set_var(var, "") };
        let spec = CredentialSpec {
            file: None,
            command: None,
            env: Some(var.to_string()),
            timeout_secs: None,
        };
        let err = spec.resolve("empty").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"), "got: {msg}");
        unsafe { env::remove_var(var) };
    }

    #[test]
    fn credential_env_rejects_whitespace_only() {
        let var = "ATAKIT_TEST_WHITESPACE_ENV_VAR";
        unsafe { env::set_var(var, "   \t\n  ") };
        let spec = CredentialSpec {
            file: None,
            command: None,
            env: Some(var.to_string()),
            timeout_secs: None,
        };
        let err = spec.resolve("ws").unwrap_err();
        assert!(err.to_string().contains("empty or whitespace-only"));
        unsafe { env::remove_var(var) };
    }

    #[test]
    fn credential_env_trims_surrounding_whitespace() {
        // Accidentally-padded env var values (copy-paste with
        // trailing newline, leading tab) should still produce the
        // clean token, matching file-source behavior.
        let var = "ATAKIT_TEST_PADDED_ENV_VAR";
        unsafe { env::set_var(var, "  ghp_abc\n") };
        let spec = CredentialSpec {
            file: None,
            command: None,
            env: Some(var.to_string()),
            timeout_secs: None,
        };
        assert_eq!(spec.resolve("pad").unwrap(), "ghp_abc");
        unsafe { env::remove_var(var) };
    }

    #[test]
    fn best_effort_resolver_preserves_error_cause_chain() {
        // A `file` credential pointing at a missing path must
        // surface the underlying io error (ENOENT) in the stored
        // error string, not just the outer "failed to read token"
        // message. Without `format!("{e:#}")` the caller can't tell
        // "file doesn't exist" from "permission denied".
        let config = Config::load_from_str(
            r#"
            [github.credentials]
            missing = { file = "/nonexistent/atakit-test-path/token" }
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap();
        let (_, err) = config.resolve_credentials_best_effort(&["missing"]);
        let msg = err.get("missing").expect("missing credential failure");
        // Outer context (from `with_context` in `resolve`).
        assert!(msg.contains("credential 'missing'"), "got: {msg}");
        // Inner root cause (the io error from fs::read_to_string).
        // On unix this is "No such file or directory".
        assert!(
            msg.contains("No such file or directory") || msg.contains("cannot find"),
            "expected underlying io error in chain, got: {msg}"
        );
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

    #[test]
    fn credential_command_does_not_deadlock_on_large_stderr_output() {
        // Regression: writing more than the kernel pipe buffer (~64
        // KiB on Linux) to stderr would block the helper because
        // the parent only read pipes AFTER `wait_timeout` returned.
        // The child blocked on write(), never exited, and the
        // command was misreported as a timeout.
        //
        // Drainer threads now read both pipes concurrently with
        // wait, so a helper that dumps 200 KiB of debug to stderr
        // and then prints a small token must succeed cleanly.
        let spec = CredentialSpec {
            file: None,
            command: Some(vec![
                "sh".into(),
                "-c".into(),
                // 200 KiB of stderr, then a token on stdout.
                "yes 'noisy debug line that fills the pipe buffer' | head -c 200000 >&2; \
                 echo ghp_real_token"
                    .into(),
            ]),
            env: None,
            // Bound the timeout so a regression manifests as a
            // failed test rather than a CI hang.
            timeout_secs: Some(10),
        };
        let token = spec
            .resolve("noisy")
            .expect("large stderr output must not deadlock or time out");
        assert_eq!(token, "ghp_real_token");
    }

    #[test]
    fn credential_command_does_not_deadlock_on_large_stdout_output() {
        // Same regression in the other direction: a helper that
        // emits a giant stdout payload (which we'll then trim to
        // get a token from) must not deadlock.
        let spec = CredentialSpec {
            file: None,
            command: Some(vec![
                "sh".into(),
                "-c".into(),
                "head -c 200000 /dev/zero | tr '\\0' x".into(),
            ]),
            env: None,
            timeout_secs: Some(10),
        };
        let token = spec
            .resolve("big")
            .expect("large stdout output must not deadlock or time out");
        // Sanity: we got the full 200 KiB back, not a truncated read.
        assert_eq!(token.len(), 200_000);
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
    fn workload_resolve_shorthand_inherits_credential_from_matching_entry() {
        // Raw `owner/repo` shorthand should inherit the credential of
        // any configured `[workload.repositories]` github entry with
        // the same `repo` path. Otherwise push would silently fail at
        // the upload gate because the synthesised spec has no
        // credential attached.
        let config = Config::load_from_str(
            r#"
            [github.credentials]
            private = { env = "PRIVATE_TOKEN" }
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            gh-private = { type = "github", repo = "owner/private", credential = "private" }
            "#,
        )
        .unwrap();
        let (_, spec) = config.workload.resolve(Some("owner/private")).unwrap();
        match spec {
            WorkloadRepositorySpec::Github { repo, credential } => {
                assert_eq!(repo, "owner/private");
                assert_eq!(credential.as_deref(), Some("private"));
            }
            _ => panic!("expected github"),
        }
    }

    #[test]
    fn workload_resolve_shorthand_stays_anonymous_when_no_matching_entry() {
        // No configured entry points at `owner/public`, so the
        // synthesised spec keeps `credential = None`. Public repos
        // still work anonymously.
        let config = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            "#,
        )
        .unwrap();
        let (_, spec) = config.workload.resolve(Some("owner/public")).unwrap();
        match spec {
            WorkloadRepositorySpec::Github { credential, .. } => {
                assert!(credential.is_none());
            }
            _ => panic!("expected github"),
        }
    }

    #[test]
    fn workload_resolve_shorthand_errors_on_ambiguous_credential_match() {
        // Two configured entries point at the same `owner/repo` path
        // but reference different credentials. Refuse to guess.
        let config = Config::load_from_str(
            r#"
            [github.credentials]
            one = { env = "ONE_TOKEN" }
            two = { env = "TWO_TOKEN" }
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            first  = { type = "github", repo = "owner/same", credential = "one" }
            second = { type = "github", repo = "owner/same", credential = "two" }
            "#,
        )
        .unwrap();
        let err = config.workload.resolve(Some("owner/same")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("different credentials"), "got: {msg}");
        assert!(msg.contains("owner/same"), "got: {msg}");
    }

    #[test]
    fn resolve_credentials_best_effort_collects_failures() {
        // Two credentials: one readable env var, one pointing at an
        // unset env var. The batch resolver must return both the
        // success AND the failure without aborting.
        let ok_var = "ATAKIT_TEST_BEST_EFFORT_OK";
        let bad_var = "ATAKIT_TEST_BEST_EFFORT_BAD_THAT_DOES_NOT_EXIST";
        unsafe {
            env::set_var(ok_var, "tok");
            env::remove_var(bad_var);
        }
        let config = Config::load_from_str(&format!(
            r#"
            [github.credentials]
            good = {{ env = "{ok_var}" }}
            bad  = {{ env = "{bad_var}" }}
            [image.repositories]
            x = {{ repo = "a/b" }}
            "#,
        ))
        .unwrap();
        let (ok, err) = config.resolve_credentials_best_effort(&["good", "bad"]);
        assert_eq!(ok.len(), 1);
        assert_eq!(ok.get("good").map(String::as_str), Some("tok"));
        assert_eq!(err.len(), 1);
        assert!(err.contains_key("bad"));
        unsafe { env::remove_var(ok_var) };
    }

    #[test]
    fn resolve_credentials_best_effort_dedupes_names() {
        let var = "ATAKIT_TEST_BEST_EFFORT_DEDUPE";
        unsafe { env::set_var(var, "x") };
        let config = Config::load_from_str(&format!(
            r#"
            [github.credentials]
            pub = {{ env = "{var}" }}
            [image.repositories]
            x = {{ repo = "a/b" }}
            "#,
        ))
        .unwrap();
        let (ok, err) = config.resolve_credentials_best_effort(&["pub", "pub", "pub"]);
        assert_eq!(ok.len(), 1);
        assert!(err.is_empty());
        unsafe { env::remove_var(var) };
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

    #[test]
    fn workload_repository_rejects_typo_in_credential_field_name() {
        // Regression: before adding `deny_unknown_fields`, a typo
        // like `credentail = "private"` was silently accepted. The
        // repo deserialized as `{ repo, credential: None }` and
        // the command ran as anonymous, so a user who thought they
        // were authenticating a private repo would quietly hit
        // rate limits or 404s with no indication that their
        // credential reference was even parsed.
        let err = Config::load_from_str(
            r#"
            [github.credentials]
            private = { env = "GH_PRIVATE" }
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            gh = { type = "github", repo = "owner/repo", credentail = "private" }
            "#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unknown field") || msg.contains("credentail"),
            "expected unknown-field rejection, got: {msg}"
        );
    }

    #[test]
    fn workload_repository_rejects_unknown_field_on_http_variant() {
        let err = Config::load_from_str(
            r#"
            [image.repositories]
            x = { repo = "a/b" }
            [workload.repositories]
            main = { type = "http", url = "https://example.com", foo = "bar" }
            "#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unknown field") || msg.contains("foo"),
            "expected unknown-field rejection, got: {msg}"
        );
    }

    // ── ATAKIT_DEFAULT_REPO env override ─────────────────────────
    //
    // These test the pure helper `default_repo_entry` rather than
    // setting `ATAKIT_DEFAULT_REPO` via `env::set_var` and calling
    // `Config::load_from_str`, because unit tests run in parallel
    // and process env mutation races with any other test that
    // reads env inside `apply_env_overrides`. The helper is the
    // only logic the env branch actually owns; everything else is
    // the one-line IndexMap insertion.

    fn spec(repo: &str, credential: Option<&str>, list_limit: Option<u32>) -> ImageRepositorySpec {
        ImageRepositorySpec {
            repo: repo.to_string(),
            credential: credential.map(str::to_string),
            list_limit,
        }
    }

    #[test]
    fn atakit_default_repo_inherits_credential_and_list_limit_from_matching_entry() {
        let mut repositories = IndexMap::new();
        repositories.insert("automata".to_string(), spec("automata-network/automata-linux", None, None));
        repositories.insert(
            "private".to_string(),
            spec("myorg/private-images", Some("private"), Some(3)),
        );
        let result = default_repo_entry(&repositories, "myorg/private-images");
        assert_eq!(result.repo, "myorg/private-images");
        assert_eq!(result.credential.as_deref(), Some("private"));
        assert_eq!(result.list_limit, Some(3));
    }

    #[test]
    fn atakit_default_repo_synthesizes_anonymous_when_no_match() {
        let mut repositories = IndexMap::new();
        repositories.insert("automata".to_string(), spec("automata-network/automata-linux", None, None));
        let result = default_repo_entry(&repositories, "unconfigured/public");
        assert_eq!(result.repo, "unconfigured/public");
        assert!(result.credential.is_none());
        assert!(result.list_limit.is_none());
    }

    #[test]
    fn atakit_default_repo_inherits_from_public_entry_keeps_credential_none() {
        // An entry without a credential (public repo) is also a
        // valid inheritance target: the helper preserves the None
        // rather than "re-synthesizing" a new anonymous spec. This
        // matters for the `list_limit` inheritance edge case where
        // a public entry wants its limit respected even though it
        // has no credential.
        let mut repositories = IndexMap::new();
        repositories.insert(
            "fast-public".to_string(),
            spec("automata-network/automata-linux", None, Some(5)),
        );
        let result = default_repo_entry(&repositories, "automata-network/automata-linux");
        assert!(result.credential.is_none());
        assert_eq!(result.list_limit, Some(5));
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
