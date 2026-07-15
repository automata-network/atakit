//! Shared operator configuration schema used by atakit command-line tools.
//!
//! This crate owns sections of `config.toml` that are consumed by more than
//! one binary. Consumers still define their own top-level configuration so a
//! focused tool can ignore sections it does not use.

use std::env;
use std::io::Read;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const COMMAND_DEFAULT_TIMEOUT_SECS: u64 = 30;
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Errors produced while validating or resolving shared configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),

    #[error("{source_kind} '{name}': HOME is not set while expanding `{path}`")]
    HomeNotSet {
        source_kind: &'static str,
        name: String,
        path: String,
    },

    #[error("{source_kind} '{name}': failed to read {value_kind} from `{path}`")]
    ReadSecret {
        source_kind: &'static str,
        value_kind: &'static str,
        name: String,
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{source_kind} '{name}': failed to spawn `{program}`")]
    SpawnCommand {
        source_kind: &'static str,
        name: String,
        program: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{source_kind} '{name}': child {stream} unavailable")]
    MissingPipe {
        source_kind: &'static str,
        name: String,
        stream: &'static str,
    },

    #[error("{source_kind} '{name}': failed waiting for command `{program}`")]
    WaitCommand {
        source_kind: &'static str,
        name: String,
        program: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "{source_kind} '{name}': command timed out after {timeout_secs}s (command: `{program}`)"
    )]
    CommandTimeout {
        source_kind: &'static str,
        name: String,
        timeout_secs: u64,
        program: String,
    },

    #[error(
        "{source_kind} '{name}': command exited with status {status} (command: `{program}`){stderr}"
    )]
    CommandFailed {
        source_kind: &'static str,
        name: String,
        status: String,
        program: String,
        stderr: String,
    },

    #[error("{source_kind} '{name}': command produced no token (empty or whitespace-only output)")]
    EmptyCommandOutput {
        source_kind: &'static str,
        name: String,
    },
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

// ── [image] ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ImageConfig {
    pub repositories: IndexMap<String, ImageRepositorySpec>,
    pub platforms: Option<Vec<String>>,
    pub list_limit: u32,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            repositories: IndexMap::new(),
            platforms: None,
            list_limit: 10,
        }
    }
}

impl ImageConfig {
    pub fn primary_entry(&self) -> Option<(&str, &ImageRepositorySpec)> {
        self.repositories.first().map(|(k, v)| (k.as_str(), v))
    }

    pub fn find_by_local_name(
        &self,
        name: &str,
    ) -> Result<Option<(&str, &ImageRepositorySpec)>, ConfigError> {
        let matches: Vec<(&str, &ImageRepositorySpec)> = self
            .repositories
            .iter()
            .filter(|(_, spec)| repo_local_name(&spec.repo) == name)
            .map(|(key, value)| (key.as_str(), value))
            .collect();

        match matches.as_slice() {
            [] => Ok(None),
            [single] => Ok(Some(*single)),
            many => {
                let entries = many
                    .iter()
                    .map(|(key, spec)| format!("{key} ({})", spec.repo))
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(invalid(format!(
                    "local name '{name}' matches multiple configured image repositories: \
                     [{entries}]; pass `--repo <owner/repo>` or rename one of the entries \
                     to disambiguate"
                )))
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRepositorySpec {
    pub repo: String,
    pub credential: Option<String>,
    pub list_limit: Option<u32>,
}

pub fn repo_local_name(repo: &str) -> &str {
    repo.rsplit_once('/').map_or(repo, |(_, name)| name)
}

// ── [github] ──────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct GithubConfig {
    pub credentials: IndexMap<String, CredentialSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    pub file: Option<String>,
    pub command: Option<Vec<String>>,
    pub env: Option<String>,
    pub timeout_secs: Option<u64>,
}

impl CredentialSpec {
    pub fn validate(&self, name: &str) -> Result<(), ConfigError> {
        validate_source_fields(
            "credential",
            name,
            self.file.is_some(),
            self.command.as_deref(),
            self.env.is_some(),
            self.timeout_secs,
        )
    }

    pub fn resolve(&self, name: &str) -> Result<String, ConfigError> {
        resolve_source(
            "credential",
            "token",
            name,
            self.file.as_deref(),
            self.command.as_deref(),
            self.env.as_deref(),
            self.timeout_secs,
        )
    }
}

// ── [chains] and [provers] ────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub session_registry: String,
    pub workload_registry: Option<String>,
    pub base_image_registry: Option<String>,
    #[serde(default = "default_expire_offset")]
    pub expire_offset: u64,
    #[serde(default)]
    pub chain_id: Option<u64>,
    #[serde(default = "default_tee_backend")]
    pub tee_backend: String,
    #[serde(default)]
    pub prover: Option<String>,
    #[serde(default)]
    pub proving_strategy: Option<String>,
}

fn default_tee_backend() -> String {
    "auto".to_string()
}

fn default_expire_offset() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProverSpec {
    pub backend: String,
    #[serde(default = "default_prover_execution")]
    pub execution: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub credential: Option<String>,
    #[serde(default)]
    pub options: IndexMap<String, String>,
}

fn default_prover_execution() -> String {
    "network".to_string()
}

// ── [keys] ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Es256k,
    Es256,
    Rs256,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Es256k => write!(f, "es256k"),
            Self::Es256 => write!(f, "es256"),
            Self::Rs256 => write!(f, "rs256"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyMode {
    Provisioned,
    SelfGenerated,
}

impl std::fmt::Display for KeyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provisioned => write!(f, "provisioned"),
            Self::SelfGenerated => write!(f, "self_generated"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySpec {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub mode: KeyMode,
    pub file: Option<String>,
    pub command: Option<Vec<String>>,
    pub env: Option<String>,
    pub timeout_secs: Option<u64>,
}

impl KeySpec {
    pub fn validate(&self, name: &str) -> Result<(), ConfigError> {
        let source_count = [
            self.file.is_some(),
            self.command.is_some(),
            self.env.is_some(),
        ]
        .into_iter()
        .filter(|is_set| *is_set)
        .count();

        match self.mode {
            KeyMode::Provisioned if source_count == 0 => {
                return Err(invalid(format!(
                    "key '{name}': mode = \"provisioned\" requires exactly one of \
                     `file`, `command`, `env`"
                )));
            }
            KeyMode::Provisioned if source_count > 1 => {
                return Err(invalid(format!(
                    "key '{name}': sets more than one of `file` / `command` / `env`; pick one"
                )));
            }
            KeyMode::SelfGenerated if source_count > 0 => {
                return Err(invalid(format!(
                    "key '{name}': mode = \"self_generated\" must not set \
                     `file`, `command`, or `env`"
                )));
            }
            _ => {}
        }

        if self.mode == KeyMode::SelfGenerated && self.timeout_secs.is_some() {
            return Err(invalid(format!(
                "key '{name}': mode = \"self_generated\" must not set `timeout_secs`"
            )));
        }

        validate_timeout_and_command("key", name, self.command.as_deref(), self.timeout_secs)
    }

    pub fn resolve(&self, name: &str) -> Result<String, ConfigError> {
        if self.mode != KeyMode::Provisioned {
            return Err(invalid(format!(
                "key '{name}': cannot resolve a self_generated key; it must be \
                 mode = \"provisioned\" with a file/command/env source"
            )));
        }

        resolve_source(
            "key",
            "key",
            name,
            self.file.as_deref(),
            self.command.as_deref(),
            self.env.as_deref(),
            self.timeout_secs,
        )
    }
}

// ── [build] and [publish] ─────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerEngine {
    #[default]
    Auto,
    Docker,
    Podman,
}

impl ContainerEngine {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

impl std::fmt::Display for ContainerEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ContainerEngine {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            _ => Err(invalid(format!(
                "invalid container engine '{value}'; expected auto, docker, or podman"
            ))),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct BuildConfig {
    pub container_engine: ContainerEngine,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PublishConfig {
    pub chain: Option<String>,
    pub owner_key: Option<String>,
    pub relay_key: Option<String>,
}

// ── secret source helpers ─────────────────────────────────────────

fn validate_source_fields(
    source_kind: &'static str,
    name: &str,
    has_file: bool,
    command: Option<&[String]>,
    has_env: bool,
    timeout_secs: Option<u64>,
) -> Result<(), ConfigError> {
    let source_count = [has_file, command.is_some(), has_env]
        .into_iter()
        .filter(|is_set| *is_set)
        .count();

    match source_count {
        0 => {
            return Err(invalid(format!(
                "{source_kind} '{name}': must set exactly one of `file`, `command`, `env`"
            )));
        }
        1 => {}
        _ => {
            return Err(invalid(format!(
                "{source_kind} '{name}': sets more than one of `file` / `command` / `env`; \
                 pick one"
            )));
        }
    }

    validate_timeout_and_command(source_kind, name, command, timeout_secs)
}

fn validate_timeout_and_command(
    source_kind: &'static str,
    name: &str,
    command: Option<&[String]>,
    timeout_secs: Option<u64>,
) -> Result<(), ConfigError> {
    if timeout_secs.is_some() && command.is_none() {
        return Err(invalid(format!(
            "{source_kind} '{name}': `timeout_secs` is only valid with `command`"
        )));
    }
    if timeout_secs == Some(0) {
        return Err(invalid(format!(
            "{source_kind} '{name}': `timeout_secs` must be greater than 0"
        )));
    }
    if command.is_some_and(<[String]>::is_empty) {
        return Err(invalid(format!(
            "{source_kind} '{name}': `command` must not be empty"
        )));
    }
    Ok(())
}

fn resolve_source(
    source_kind: &'static str,
    value_kind: &'static str,
    name: &str,
    file: Option<&str>,
    command: Option<&[String]>,
    env_name: Option<&str>,
    timeout_secs: Option<u64>,
) -> Result<String, ConfigError> {
    if let Some(path) = file {
        return read_secret_file(source_kind, value_kind, name, path);
    }
    if let Some(env_name) = env_name {
        let value = env::var(env_name).map_err(|_| {
            invalid(format!(
                "{source_kind} '{name}': env var '{env_name}' is not set"
            ))
        })?;
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err(invalid(format!(
                "{source_kind} '{name}': env var '{env_name}' is set but empty or \
                 whitespace-only"
            )));
        }
        return Ok(value);
    }
    if let Some(command) = command {
        return resolve_command(source_kind, name, command, timeout_secs);
    }

    Err(invalid(format!(
        "{source_kind} '{name}': no source set (internal error: validate not called)"
    )))
}

fn read_secret_file(
    source_kind: &'static str,
    value_kind: &'static str,
    name: &str,
    path: &str,
) -> Result<String, ConfigError> {
    let expanded = if path.starts_with("~/") {
        let home = env::var("HOME").map_err(|_| ConfigError::HomeNotSet {
            source_kind,
            name: name.to_string(),
            path: path.to_string(),
        })?;
        format!("{}{}", home, &path[1..])
    } else {
        path.to_string()
    };

    let value = std::fs::read_to_string(&expanded).map_err(|source| ConfigError::ReadSecret {
        source_kind,
        value_kind,
        name: name.to_string(),
        path: expanded.clone(),
        source,
    })?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(invalid(format!(
            "{source_kind} '{name}': file `{expanded}` is empty or whitespace-only"
        )));
    }
    Ok(value)
}

fn resolve_command(
    source_kind: &'static str,
    name: &str,
    argv: &[String],
    timeout_secs: Option<u64>,
) -> Result<String, ConfigError> {
    let timeout_secs = timeout_secs.unwrap_or(COMMAND_DEFAULT_TIMEOUT_SECS);
    let program = argv
        .first()
        .ok_or_else(|| invalid(format!("{source_kind} '{name}': command is empty")))?;

    let mut child = Command::new(program)
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ConfigError::SpawnCommand {
            source_kind,
            name: name.to_string(),
            program: program.clone(),
            source,
        })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ConfigError::MissingPipe {
            source_kind,
            name: name.to_string(),
            stream: "stdout",
        })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ConfigError::MissingPipe {
            source_kind,
            name: name.to_string(),
            stream: "stderr",
        })?;

    let stdout_thread = std::thread::spawn(move || {
        let mut output = String::new();
        let mut stdout = stdout;
        let _ = stdout.read_to_string(&mut output);
        output
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut output = String::new();
        let mut stderr = stderr;
        let _ = stderr.read_to_string(&mut output);
        output
    });

    let timeout = Duration::from_secs(timeout_secs);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(ConfigError::CommandTimeout {
                    source_kind,
                    name: name.to_string(),
                    timeout_secs,
                    program: program.clone(),
                });
            }
            Ok(None) => std::thread::sleep(COMMAND_POLL_INTERVAL),
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(ConfigError::WaitCommand {
                    source_kind,
                    name: name.to_string(),
                    program: program.clone(),
                    source,
                });
            }
        }
    };

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    if !status.success() {
        return Err(ConfigError::CommandFailed {
            source_kind,
            name: name.to_string(),
            status: status
                .code()
                .map_or_else(|| "signal".to_string(), |code| code.to_string()),
            program: program.clone(),
            stderr: if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(
                    " (stderr: {})",
                    stderr.trim().chars().take(200).collect::<String>()
                )
            },
        });
    }

    let value = stdout.trim().to_string();
    if value.is_empty() {
        return Err(ConfigError::EmptyCommandOutput {
            source_kind,
            name: name.to_string(),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(default)]
    struct SharedConfigFixture {
        chains: IndexMap<String, ChainConfig>,
        provers: IndexMap<String, ProverSpec>,
        keys: IndexMap<String, KeySpec>,
        image: ImageConfig,
        github: GithubConfig,
        build: BuildConfig,
        publish: PublishConfig,
    }

    impl Default for SharedConfigFixture {
        fn default() -> Self {
            Self {
                chains: IndexMap::new(),
                provers: IndexMap::new(),
                keys: IndexMap::new(),
                image: ImageConfig::default(),
                github: GithubConfig::default(),
                build: BuildConfig::default(),
                publish: PublishConfig::default(),
            }
        }
    }

    #[test]
    fn representative_shared_config_parses() {
        let config: SharedConfigFixture = toml::from_str(
            r#"
            [chains.hoodi]
            rpc_url = "https://rpc.example"
            session_registry = "0x0000000000000000000000000000000000000001"
            tee_backend = "zk"
            prover = "sp1-network"

            [provers.sp1-network]
            backend = "sp1"
            execution = "network"

            [keys.owner]
            type = "es256k"
            mode = "provisioned"
            env = "OWNER_KEY"

            [image.repositories]
            base = { repo = "example/base-images", credential = "github" }

            [github.credentials]
            github = { env = "GITHUB_TOKEN" }

            [build]
            container_engine = "podman"

            [publish]
            chain = "hoodi"
            owner_key = "owner"
            "#,
        )
        .unwrap();

        assert_eq!(config.chains["hoodi"].tee_backend, "zk");
        assert_eq!(
            config.chains["hoodi"].prover.as_deref(),
            Some("sp1-network")
        );
        assert_eq!(config.provers["sp1-network"].backend, "sp1");
        assert_eq!(config.keys["owner"].mode, KeyMode::Provisioned);
        assert_eq!(
            config.image.repositories["base"].repo,
            "example/base-images"
        );
        assert!(config.github.credentials.contains_key("github"));
        assert_eq!(config.build.container_engine, ContainerEngine::Podman);
        assert_eq!(config.publish.chain.as_deref(), Some("hoodi"));
    }

    #[test]
    fn chain_schema_rejects_unknown_fields() {
        let error = toml::from_str::<ChainConfig>(
            r#"
            rpc_url = "https://rpc.example"
            session_registry = "0x1"
            future_field = true
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("future_field"));
    }

    #[test]
    fn container_engine_is_typed() {
        assert_eq!(
            "docker".parse::<ContainerEngine>().unwrap(),
            ContainerEngine::Docker
        );
        assert!("dockr".parse::<ContainerEngine>().is_err());
    }
}
