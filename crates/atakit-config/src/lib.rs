//! Shared operator configuration schema used by atakit command-line tools.
//!
//! This crate owns sections of `config.toml` that are consumed by more than
//! one binary. Consumers still define their own top-level configuration so a
//! focused tool can ignore sections it does not use.

use std::env;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::str::FromStr;
#[cfg(unix)]
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(unix)]
const COMMAND_DEFAULT_TIMEOUT_SECS: u64 = 30;
#[cfg(unix)]
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(unix)]
const COMMAND_OUTPUT_LIMIT_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const COMMAND_READ_CHUNK_BYTES: usize = 8 * 1024;
#[cfg(unix)]
const COMMAND_READS_PER_POLL: usize = 16;

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

    #[error("{source_kind} '{name}': failed to {action} child {stream} for command `{program}`")]
    CommandPipe {
        source_kind: &'static str,
        name: String,
        program: String,
        stream: &'static str,
        action: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "{source_kind} '{name}': failed to {action} for command `{program}` on the controlling terminal"
    )]
    CommandTerminal {
        source_kind: &'static str,
        name: String,
        program: String,
        action: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("{source_kind} '{name}': failed to {action} for command `{program}`")]
    CommandSignal {
        source_kind: &'static str,
        name: String,
        program: String,
        action: &'static str,
        #[source]
        source: std::io::Error,
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

    #[error(
        "{source_kind} '{name}': command `{program}` produced more than {limit_bytes} bytes on stdout"
    )]
    CommandOutputTooLarge {
        source_kind: &'static str,
        name: String,
        program: String,
        limit_bytes: usize,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    #[serde(default)]
    pub chain_id: Option<u64>,
    #[serde(default = "default_tee_backend")]
    pub tee_backend: String,
    #[serde(default)]
    pub prover: Option<String>,
}

fn default_tee_backend() -> String {
    "auto".to_string()
}

/// Global limits for owner-authorized portal and registry operations.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OwnerOperationsConfig {
    pub op_expiry_seconds: u64,
    pub challenge_expiry_seconds: u64,
    pub max_request_body_bytes: usize,
    pub max_waiting_requests: usize,
    pub max_completed_request_statuses: usize,
    pub request_status_retention_seconds: u64,
}

impl Default for OwnerOperationsConfig {
    fn default() -> Self {
        Self {
            op_expiry_seconds: 300,
            challenge_expiry_seconds: 60,
            max_request_body_bytes: 1_048_576,
            max_waiting_requests: 64,
            max_completed_request_statuses: 256,
            request_status_retention_seconds: 3_600,
        }
    }
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
#[serde(default, deny_unknown_fields)]
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

#[cfg(not(unix))]
fn resolve_command(
    source_kind: &'static str,
    name: &str,
    argv: &[String],
    _timeout_secs: Option<u64>,
) -> Result<String, ConfigError> {
    let program = argv
        .first()
        .ok_or_else(|| invalid(format!("{source_kind} '{name}': command is empty")))?;
    Err(invalid(format!(
        "{source_kind} '{name}': command secret source `{program}` is unsupported on this platform"
    )))
}

#[cfg(unix)]
#[derive(Default)]
struct CapturedCommandOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

#[cfg(unix)]
impl CapturedCommandOutput {
    fn append(&mut self, bytes: &[u8]) {
        let remaining = COMMAND_OUTPUT_LIMIT_BYTES.saturating_sub(self.bytes.len());
        let stored = remaining.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..stored]);
        self.truncated |= stored < bytes.len();
    }

    fn into_string(self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

#[cfg(unix)]
struct ForegroundTerminal {
    tty: Option<std::fs::File>,
    original_process_group: libc::pid_t,
    has_controlling_terminal: bool,
}

#[cfg(unix)]
impl ForegroundTerminal {
    fn assign_to(process_group: u32) -> std::io::Result<Self> {
        let tty = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        {
            Ok(tty) => tty,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENXIO | libc::ENODEV | libc::ENOTTY | libc::ENOENT)
                ) =>
            {
                return Ok(Self {
                    tty: None,
                    original_process_group: 0,
                    has_controlling_terminal: false,
                });
            }
            Err(error) => return Err(error),
        };
        let fd = std::os::fd::AsRawFd::as_raw_fd(&tty);
        // SAFETY: fd is a live descriptor for /dev/tty.
        let original_process_group = unsafe { libc::tcgetpgrp(fd) };
        if original_process_group == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // Only a foreground atakit invocation should transfer ownership. A
        // shell that launched atakit in the background retains normal job
        // control over whether that job may read from the terminal.
        // SAFETY: getpgrp has no preconditions.
        if original_process_group != unsafe { libc::getpgrp() } {
            return Ok(Self {
                tty: None,
                original_process_group: 0,
                has_controlling_terminal: true,
            });
        }

        let child_process_group = i32::try_from(process_group).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "child process group does not fit pid_t",
            )
        })?;
        let mut foreground = Self {
            tty: Some(tty),
            original_process_group,
            has_controlling_terminal: true,
        };
        if let Err(error) = set_terminal_process_group(fd, child_process_group) {
            let _ = foreground.restore();
            return Err(error);
        }
        // The child may have raced into a /dev/tty read before tcsetpgrp and
        // stopped on SIGTTIN. Once foreground ownership is transferred,
        // continue the whole helper group.
        // SAFETY: a negative PID addresses the process group created for the
        // helper. SIGCONT has its standard job-control meaning.
        if unsafe { libc::kill(-child_process_group, libc::SIGCONT) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                let _ = foreground.restore();
                return Err(error);
            }
        }
        Ok(foreground)
    }

    fn is_assigned(&self) -> bool {
        self.tty.is_some()
    }

    fn has_controlling_terminal(&self) -> bool {
        self.has_controlling_terminal
    }

    fn restore(&mut self) -> std::io::Result<()> {
        let Some(tty) = self.tty.as_ref() else {
            return Ok(());
        };
        let fd = std::os::fd::AsRawFd::as_raw_fd(tty);
        set_terminal_process_group(fd, self.original_process_group)?;
        self.tty = None;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ForegroundTerminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(unix)]
fn set_terminal_process_group(
    tty_fd: std::os::fd::RawFd,
    process_group: libc::pid_t,
) -> std::io::Result<()> {
    // tcsetpgrp is called once while atakit is foreground and again while the
    // helper owns the foreground. Block SIGTTOU in this thread so the restore
    // operation cannot suspend atakit for performing background terminal I/O.
    // SAFETY: sigset_t is initialized through sigemptyset before use, and all
    // pointers remain valid for the duration of these libc calls.
    let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigemptyset(&mut blocked) } == -1
        || unsafe { libc::sigaddset(&mut blocked, libc::SIGTTOU) } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    let mask_result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) };
    if mask_result != 0 {
        return Err(std::io::Error::from_raw_os_error(mask_result));
    }

    // SAFETY: tty_fd refers to the caller's controlling terminal and
    // process_group is either its original foreground group or the helper's
    // live process group.
    let set_result = unsafe { libc::tcsetpgrp(tty_fd, process_group) };
    let set_error = (set_result == -1).then(std::io::Error::last_os_error);
    // SAFETY: previous was populated by pthread_sigmask above.
    let restore_result =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };

    if let Some(error) = set_error {
        return Err(error);
    }
    if restore_result != 0 {
        return Err(std::io::Error::from_raw_os_error(restore_result));
    }
    Ok(())
}

#[cfg(unix)]
fn set_pipe_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fd is owned by the live ChildStdout/ChildStderr passed by
    // reference. fcntl only reads or updates its file status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptor remains live for this call and the existing
    // flags are preserved while O_NONBLOCK is added.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn drain_command_pipe(
    pipe: &mut impl Read,
    output: &mut CapturedCommandOutput,
) -> std::io::Result<bool> {
    let mut chunk = [0_u8; COMMAND_READ_CHUNK_BYTES];
    for _ in 0..COMMAND_READS_PER_POLL {
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(read) => output.append(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn drain_command_pipe_after_exit(
    pipe: &mut impl Read,
    output: &mut CapturedCommandOutput,
) -> std::io::Result<bool> {
    let mut chunk = [0_u8; COMMAND_READ_CHUNK_BYTES];
    loop {
        // Once the cap has been exceeded, the caller already has a bounded,
        // explicit error. Stop reading so an escaped continuous writer cannot
        // turn exit cleanup into an unbounded loop.
        if output.truncated {
            return Ok(false);
        }
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(read) => output.append(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn drain_command_pipe_or_terminate(
    child: &mut std::process::Child,
    pipe: &mut impl Read,
    output: &mut CapturedCommandOutput,
    source_kind: &'static str,
    name: &str,
    program: &str,
    stream: &'static str,
) -> Result<bool, ConfigError> {
    drain_command_pipe(pipe, output).map_err(|source| {
        terminate_command_tree(child);
        ConfigError::CommandPipe {
            source_kind,
            name: name.to_string(),
            program: program.to_string(),
            stream,
            action: "read",
            source,
        }
    })
}

#[cfg(unix)]
fn drain_command_pipe_after_exit_or_terminate(
    child: &mut std::process::Child,
    pipe: &mut impl Read,
    output: &mut CapturedCommandOutput,
    source_kind: &'static str,
    name: &str,
    program: &str,
    stream: &'static str,
) -> Result<bool, ConfigError> {
    drain_command_pipe_after_exit(pipe, output).map_err(|source| {
        terminate_command_tree(child);
        ConfigError::CommandPipe {
            source_kind,
            name: name.to_string(),
            program: program.to_string(),
            stream,
            action: "read after command exit",
            source,
        }
    })
}

#[cfg(unix)]
fn restore_command_terminal(
    foreground: &mut ForegroundTerminal,
    source_kind: &'static str,
    name: &str,
    program: &str,
) -> Result<(), ConfigError> {
    foreground
        .restore()
        .map_err(|source| ConfigError::CommandTerminal {
            source_kind,
            name: name.to_string(),
            program: program.to_string(),
            action: "restore foreground ownership",
            source,
        })
}

#[cfg(unix)]
enum CommandChildState {
    Running,
    Stopped,
    Exited(std::process::ExitStatus),
}

#[cfg(unix)]
fn poll_command_child(child: &std::process::Child) -> std::io::Result<CommandChildState> {
    use std::os::unix::process::ExitStatusExt;

    let child_pid = i32::try_from(child.id()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "child process ID does not fit pid_t",
        )
    })?;
    let mut raw_status = 0;
    // SAFETY: child_pid names the live child created by resolve_command and
    // raw_status is a valid output pointer. WUNTRACED reports job-control
    // stops that Child::try_wait intentionally omits.
    let waited =
        unsafe { libc::waitpid(child_pid, &mut raw_status, libc::WNOHANG | libc::WUNTRACED) };
    if waited == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if waited == 0 {
        return Ok(CommandChildState::Running);
    }
    if libc::WIFSTOPPED(raw_status) {
        return Ok(CommandChildState::Stopped);
    }
    if libc::WIFEXITED(raw_status) || libc::WIFSIGNALED(raw_status) {
        return Ok(CommandChildState::Exited(
            std::process::ExitStatus::from_raw(raw_status),
        ));
    }
    Ok(CommandChildState::Running)
}

#[cfg(unix)]
fn signal_process_group(process_group: u32, signal: libc::c_int) -> std::io::Result<()> {
    let process_group = i32::try_from(process_group).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process group does not fit pid_t",
        )
    })?;
    // SAFETY: a negative PID addresses the isolated helper process group.
    if unsafe { libc::kill(-process_group, signal) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn suspend_for_stopped_command(
    child: &mut std::process::Child,
    foreground: &mut ForegroundTerminal,
    source_kind: &'static str,
    name: &str,
    program: &str,
) -> Result<(), ConfigError> {
    if let Err(error) = restore_command_terminal(foreground, source_kind, name, program) {
        terminate_command_tree(child);
        return Err(error);
    }

    loop {
        // The terminal delivered the stop only to the isolated helper group.
        // Stop atakit's original job group as well so the invoking shell can
        // regain the terminal. SIGSTOP cannot be caught or ignored.
        // SAFETY: getpgrp has no preconditions and returns this process's
        // existing job-control group.
        let parent_process_group = unsafe { libc::getpgrp() };
        // SAFETY: a negative PID addresses atakit's process group. This call
        // returns only after the shell or another supervisor sends SIGCONT.
        if unsafe { libc::kill(-parent_process_group, libc::SIGSTOP) } == -1 {
            let source = std::io::Error::last_os_error();
            terminate_command_tree(child);
            return Err(ConfigError::CommandSignal {
                source_kind,
                name: name.to_string(),
                program: program.to_string(),
                action: "suspend parent process group",
                source,
            });
        }

        let resumed_foreground = ForegroundTerminal::assign_to(child.id()).map_err(|source| {
            terminate_command_tree(child);
            ConfigError::CommandTerminal {
                source_kind,
                name: name.to_string(),
                program: program.to_string(),
                action: "transfer foreground ownership after resume",
                source,
            }
        })?;
        if resumed_foreground.is_assigned() {
            *foreground = resumed_foreground;
            return Ok(());
        }
        if resumed_foreground.has_controlling_terminal() {
            // `bg` resumes atakit without giving it terminal ownership. Keep
            // the helper stopped and immediately suspend the parent job again;
            // a later `fg` will re-enter here with foreground ownership.
            *foreground = resumed_foreground;
            continue;
        }

        // The controlling terminal disappeared while the job was suspended.
        // Resume the helper so it can observe that condition instead of
        // leaving an untracked stopped process behind.
        match signal_process_group(child.id(), libc::SIGCONT) {
            Ok(()) => {
                *foreground = resumed_foreground;
                return Ok(());
            }
            Err(source) if source.raw_os_error() == Some(libc::ESRCH) => {
                *foreground = resumed_foreground;
                return Ok(());
            }
            Err(source) => {
                terminate_command_tree(child);
                return Err(ConfigError::CommandSignal {
                    source_kind,
                    name: name.to_string(),
                    program: program.to_string(),
                    action: "resume helper process group",
                    source,
                });
            }
        }
    }
}

#[cfg(unix)]
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

    let mut command = Command::new(program);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    use std::os::unix::process::CommandExt;
    command.process_group(0);

    let mut child = command
        .spawn()
        .map_err(|source| ConfigError::SpawnCommand {
            source_kind,
            name: name.to_string(),
            program: program.clone(),
            source,
        })?;

    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_command_tree(&mut child);
            return Err(ConfigError::MissingPipe {
                source_kind,
                name: name.to_string(),
                stream: "stdout",
            });
        }
    };
    let mut stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_command_tree(&mut child);
            return Err(ConfigError::MissingPipe {
                source_kind,
                name: name.to_string(),
                stream: "stderr",
            });
        }
    };

    for (stream, result) in [
        ("stdout", set_pipe_nonblocking(&stdout)),
        ("stderr", set_pipe_nonblocking(&stderr)),
    ] {
        if let Err(source) = result {
            terminate_command_tree(&mut child);
            return Err(ConfigError::CommandPipe {
                source_kind,
                name: name.to_string(),
                program: program.clone(),
                stream,
                action: "configure nonblocking",
                source,
            });
        }
    }

    let mut foreground = match ForegroundTerminal::assign_to(child.id()) {
        Ok(foreground) => foreground,
        Err(source) => {
            terminate_command_tree(&mut child);
            return Err(ConfigError::CommandTerminal {
                source_kind,
                name: name.to_string(),
                program: program.clone(),
                action: "transfer foreground ownership",
                source,
            });
        }
    };

    let timeout = Duration::from_secs(timeout_secs);
    let started = Instant::now();
    let mut stdout_output = CapturedCommandOutput::default();
    let mut stderr_output = CapturedCommandOutput::default();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let status = loop {
        if !stdout_eof {
            stdout_eof = drain_command_pipe_or_terminate(
                &mut child,
                &mut stdout,
                &mut stdout_output,
                source_kind,
                name,
                program,
                "stdout",
            )?;
        }
        if !stderr_eof {
            stderr_eof = drain_command_pipe_or_terminate(
                &mut child,
                &mut stderr,
                &mut stderr_output,
                source_kind,
                name,
                program,
                "stderr",
            )?;
        }

        match poll_command_child(&child) {
            Ok(CommandChildState::Exited(status)) => {
                // The leader has exited and was reaped. Kill its remaining
                // process-group members first so normal descendants close
                // their inherited writers, then drain everything already
                // buffered up to EOF/idle or the configured output cap.
                terminate_process_group(child.id());
                if !stdout_eof {
                    let _ = drain_command_pipe_after_exit_or_terminate(
                        &mut child,
                        &mut stdout,
                        &mut stdout_output,
                        source_kind,
                        name,
                        program,
                        "stdout",
                    )?;
                }
                if !stderr_eof {
                    let _ = drain_command_pipe_after_exit_or_terminate(
                        &mut child,
                        &mut stderr,
                        &mut stderr_output,
                        source_kind,
                        name,
                        program,
                        "stderr",
                    )?;
                }
                restore_command_terminal(&mut foreground, source_kind, name, program)?;
                break status;
            }
            Ok(CommandChildState::Stopped) => {
                if foreground.has_controlling_terminal() {
                    suspend_for_stopped_command(
                        &mut child,
                        &mut foreground,
                        source_kind,
                        name,
                        program,
                    )?;
                } else {
                    // Without a controlling terminal there is no job-control
                    // shell that can resume atakit. Keep the parent alive so
                    // the hard command deadline remains enforceable for CI
                    // and services.
                    std::thread::sleep(COMMAND_POLL_INTERVAL);
                }
            }
            Ok(CommandChildState::Running) if started.elapsed() >= timeout => {
                terminate_command_tree(&mut child);
                restore_command_terminal(&mut foreground, source_kind, name, program)?;
                // No reader threads exist. Dropping these descriptors closes
                // the parent's pipe ends immediately, even if an escaped
                // descendant retained the corresponding writers.
                drop(stdout);
                drop(stderr);
                return Err(ConfigError::CommandTimeout {
                    source_kind,
                    name: name.to_string(),
                    timeout_secs,
                    program: program.clone(),
                });
            }
            Ok(CommandChildState::Running) => std::thread::sleep(COMMAND_POLL_INTERVAL),
            Err(source) => {
                terminate_command_tree(&mut child);
                restore_command_terminal(&mut foreground, source_kind, name, program)?;
                drop(stdout);
                drop(stderr);
                return Err(ConfigError::WaitCommand {
                    source_kind,
                    name: name.to_string(),
                    program: program.clone(),
                    source,
                });
            }
        }
    };

    drop(stdout);
    drop(stderr);

    let stdout_truncated = stdout_output.truncated;
    let stdout = stdout_output.into_string();
    let stderr = stderr_output.into_string();

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

    if stdout_truncated {
        return Err(ConfigError::CommandOutputTooLarge {
            source_kind,
            name: name.to_string(),
            program: program.clone(),
            limit_bytes: COMMAND_OUTPUT_LIMIT_BYTES,
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

#[cfg(unix)]
fn terminate_process_group(process_group: u32) {
    if let Ok(process_group) = i32::try_from(process_group) {
        // SAFETY: the child was placed in a new process group whose ID is its
        // PID. A negative PID asks kill(2) to signal that entire group.
        let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    }
}

#[cfg(unix)]
fn terminate_command_tree(child: &mut std::process::Child) {
    terminate_process_group(child.id());
    // Cover a failed group signal and reap the helper leader.
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(default)]
    struct SharedConfigFixture {
        chains: IndexMap<String, ChainConfig>,
        owner_operations: OwnerOperationsConfig,
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
                owner_operations: OwnerOperationsConfig::default(),
                provers: IndexMap::new(),
                keys: IndexMap::new(),
                image: ImageConfig::default(),
                github: GithubConfig::default(),
                build: BuildConfig::default(),
                publish: PublishConfig::default(),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn wait_for_process_exit(pid: i32) -> bool {
        (0..20).any(|_| {
            // SAFETY: signal 0 performs an existence check without sending a
            // signal. The caller obtained pid from the helper process.
            let result = unsafe { libc::kill(pid, 0) };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                true
            } else {
                std::thread::sleep(Duration::from_millis(50));
                false
            }
        })
    }

    #[cfg(target_os = "linux")]
    fn kill_process_for_failed_test(pid: i32) {
        // SAFETY: best-effort cleanup for a failed process-lifecycle test.
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    }

    #[cfg(target_os = "linux")]
    fn wait_for_process_stop(pid: i32) -> bool {
        let status_path = format!("/proc/{pid}/status");
        (0..80).any(|_| {
            let stopped = std::fs::read_to_string(&status_path).is_ok_and(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("State:"))
                    .is_some_and(|line| line.contains("\tT") || line.contains("\tt"))
            });
            if !stopped {
                std::thread::sleep(Duration::from_millis(25));
            }
            stopped
        })
    }

    #[cfg(target_os = "linux")]
    fn wait_for_process_resume(pid: i32) -> bool {
        let status_path = format!("/proc/{pid}/status");
        (0..80).any(|_| {
            let resumed = std::fs::read_to_string(&status_path).is_ok_and(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("State:"))
                    .is_some_and(|line| !line.contains("\tT") && !line.contains("\tt"))
            });
            if !resumed {
                std::thread::sleep(Duration::from_millis(25));
            }
            resumed
        })
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

            [owner_operations]
            op_expiry_seconds = 900

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
        assert_eq!(config.owner_operations.op_expiry_seconds, 900);
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
    fn transaction_submitter_is_rejected() {
        let error = toml::from_str::<ChainConfig>(
            r#"
            rpc_url = "https://rpc.example"
            session_registry = "0x0000000000000000000000000000000000000001"
            transaction_submitter = "atakit-cli"
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("transaction_submitter"));
    }

    #[test]
    fn proving_strategy_is_rejected() {
        let error = toml::from_str::<ChainConfig>(
            r#"
            rpc_url = "https://rpc.example"
            session_registry = "0x0000000000000000000000000000000000000001"
            proving_strategy = "network"
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("proving_strategy"));
    }

    #[test]
    fn publish_schema_rejects_unknown_fields() {
        let error = toml::from_str::<PublishConfig>(r#"chnain = "hoodi""#).unwrap_err();

        assert!(error.to_string().contains("chnain"));
    }

    #[cfg(unix)]
    #[test]
    fn command_timeout_does_not_wait_for_descendant_pipe_holders() {
        let spec = CredentialSpec {
            file: None,
            command: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 5 & wait".to_string(),
            ]),
            env: None,
            timeout_secs: Some(1),
        };
        let started = Instant::now();

        let error = spec.resolve("descendant").unwrap_err();

        assert!(matches!(error, ConfigError::CommandTimeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn noninteractive_stopped_command_respects_timeout() {
        const CHILD_ENV: &str = "ATAKIT_CONFIG_STOPPED_NO_TTY_TEST_CHILD";

        if std::env::var_os(CHILD_ENV).is_some() {
            assert!(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/tty")
                    .is_err(),
                "detached test child unexpectedly has a controlling terminal"
            );
            let spec = CredentialSpec {
                file: None,
                command: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "kill -STOP $$".to_string(),
                ]),
                env: None,
                timeout_secs: Some(1),
            };
            let started = Instant::now();

            let error = spec.resolve("stopped-no-tty").unwrap_err();

            assert!(matches!(error, ConfigError::CommandTimeout { .. }));
            assert!(started.elapsed() < Duration::from_secs(3));
            return;
        }

        let current_exe = std::env::current_exe().expect("test executable path should resolve");
        let mut detached = std::process::Command::new("setsid")
            .arg(current_exe)
            .args([
                "--exact",
                "tests::noninteractive_stopped_command_respects_timeout",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("detached test child should start");

        let deadline = Instant::now() + Duration::from_secs(6);
        let status = loop {
            if let Some(status) = detached
                .try_wait()
                .expect("detached test child wait should succeed")
            {
                break status;
            }
            if Instant::now() >= deadline {
                terminate_command_tree(&mut detached);
                panic!("noninteractive stopped helper bypassed its timeout");
            }
            std::thread::sleep(Duration::from_millis(25));
        };

        assert!(
            status.success(),
            "detached stopped-helper regression child failed"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn command_timeout_closes_pipe_for_escaped_writer() {
        let pid_path = std::env::temp_dir().join(format!(
            "atakit-config-escaped-writer-{}.pid",
            std::process::id()
        ));
        let script = format!(
            "setsid sh -c 'echo $$ > {}; exec yes escaped' & wait",
            pid_path.display()
        );
        let spec = CredentialSpec {
            file: None,
            command: Some(vec!["/bin/sh".to_string(), "-c".to_string(), script]),
            env: None,
            timeout_secs: Some(1),
        };

        let error = spec.resolve("escaped-writer").unwrap_err();
        assert!(matches!(error, ConfigError::CommandTimeout { .. }));

        let escaped_pid: i32 = std::fs::read_to_string(&pid_path)
            .expect("escaped writer should record its pid")
            .trim()
            .parse()
            .expect("escaped writer pid should be numeric");
        let exited = wait_for_process_exit(escaped_pid);
        if !exited {
            kill_process_for_failed_test(escaped_pid);
        }
        let _ = std::fs::remove_file(pid_path);

        assert!(exited, "escaped writer retained the parent's pipe reader");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_command_kills_quiet_background_descendants() {
        let pid_path = std::env::temp_dir().join(format!(
            "atakit-config-quiet-descendant-{}.pid",
            std::process::id()
        ));
        let script = format!(
            "sleep 300 </dev/null >/dev/null 2>&1 & echo $! > {}; echo token",
            pid_path.display()
        );
        let spec = CredentialSpec {
            file: None,
            command: Some(vec!["/bin/sh".to_string(), "-c".to_string(), script]),
            env: None,
            timeout_secs: Some(5),
        };

        assert_eq!(spec.resolve("quiet-descendant").unwrap(), "token");

        let descendant_pid: i32 = std::fs::read_to_string(&pid_path)
            .expect("quiet descendant should record its pid")
            .trim()
            .parse()
            .expect("quiet descendant pid should be numeric");
        let exited = wait_for_process_exit(descendant_pid);
        if !exited {
            kill_process_for_failed_test(descendant_pid);
        }
        let _ = std::fs::remove_file(pid_path);

        assert!(exited, "quiet helper descendant survived leader exit");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interactive_command_helper_stays_in_terminal_foreground() {
        const CHILD_ENV: &str = "ATAKIT_CONFIG_INTERACTIVE_HELPER_TEST_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let spec = CredentialSpec {
                file: None,
                command: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "printf 'helper prompt: ' >/dev/tty; \
                     IFS= read -r token </dev/tty; printf '%s\\n' \"$token\""
                        .to_string(),
                ]),
                env: None,
                timeout_secs: Some(3),
            };

            assert_eq!(spec.resolve("interactive").unwrap(), "tty-secret");
            return;
        }

        use std::io::Write;
        use std::os::unix::process::CommandExt;

        let current_exe = std::env::current_exe().expect("test executable path should resolve");
        let command = format!(
            "{} --exact tests::interactive_command_helper_stays_in_terminal_foreground --nocapture",
            current_exe.display()
        );
        let mut script = std::process::Command::new("script");
        script
            .args(["-q", "-e", "-c", &command, "/dev/null"])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut session = script.spawn().expect("util-linux script should start");
        session
            .stdin
            .take()
            .expect("script stdin should be piped")
            .write_all(b"tty-secret\n")
            .expect("pseudo-terminal input should be written");

        let deadline = Instant::now() + Duration::from_secs(8);
        let status = loop {
            if let Some(status) = session.try_wait().expect("script wait should succeed") {
                break status;
            }
            if Instant::now() >= deadline {
                terminate_command_tree(&mut session);
                panic!("interactive helper pseudo-terminal test timed out");
            }
            std::thread::sleep(Duration::from_millis(25));
        };

        assert!(status.success(), "interactive helper failed under a pty");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interactive_command_ctrl_z_suspends_parent_job() {
        const CHILD_ENV: &str = "ATAKIT_CONFIG_CTRL_Z_HELPER_TEST_CHILD";
        const STATE_ENV: &str = "ATAKIT_CONFIG_CTRL_Z_STATE_PATH";
        const READY_ENV: &str = "ATAKIT_CONFIG_CTRL_Z_READY_PATH";
        const DONE_ENV: &str = "ATAKIT_CONFIG_CTRL_Z_DONE_PATH";

        if std::env::var_os(CHILD_ENV).is_some() {
            let state_path = std::env::var_os(STATE_ENV).expect("state path should be provided");
            let ready_path = std::env::var_os(READY_ENV).expect("ready path should be provided");
            let done_path = std::env::var_os(DONE_ENV).expect("done path should be provided");
            // SAFETY: getpid and getpgrp have no preconditions.
            let (pid, process_group) = unsafe { (libc::getpid(), libc::getpgrp()) };
            std::fs::write(&state_path, format!("{pid} {process_group}\n"))
                .expect("parent job state should be recorded");

            let helper = format!(
                "IFS= read -r armed </dev/tty; echo ready > {}; \
                 IFS= read -r token </dev/tty; printf '%s\\n' \"$token\"",
                std::path::Path::new(&ready_path).display()
            );
            let spec = CredentialSpec {
                file: None,
                command: Some(vec!["/bin/sh".to_string(), "-c".to_string(), helper]),
                env: None,
                timeout_secs: Some(10),
            };

            assert_eq!(spec.resolve("ctrl-z-interactive").unwrap(), "tty-secret");
            std::fs::write(done_path, "done\n").expect("completion should be recorded");
            return;
        }

        use std::io::Write;
        use std::os::unix::process::CommandExt;

        let state_path =
            std::env::temp_dir().join(format!("atakit-config-ctrl-z-state-{}", std::process::id()));
        let ready_path =
            std::env::temp_dir().join(format!("atakit-config-ctrl-z-ready-{}", std::process::id()));
        let done_path =
            std::env::temp_dir().join(format!("atakit-config-ctrl-z-done-{}", std::process::id()));
        let current_exe = std::env::current_exe().expect("test executable path should resolve");
        let command = format!(
            "{} --exact tests::interactive_command_ctrl_z_suspends_parent_job --nocapture\n",
            current_exe.display()
        );
        let mut script = std::process::Command::new("script");
        script
            .args([
                "-q",
                "-e",
                "-c",
                "/bin/bash --noprofile --norc -i",
                "/dev/null",
            ])
            .env(CHILD_ENV, "1")
            .env(STATE_ENV, &state_path)
            .env(READY_ENV, &ready_path)
            .env(DONE_ENV, &done_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let mut session = script.spawn().expect("util-linux script should start");
        let mut input = session.stdin.take().expect("script stdin should be piped");
        input
            .write_all(command.as_bytes())
            .expect("interactive test command should be started");

        let state_deadline = Instant::now() + Duration::from_secs(3);
        while !state_path.exists() && Instant::now() < state_deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        if !state_path.exists() {
            terminate_command_tree(&mut session);
            let _ = std::fs::remove_file(&ready_path);
            let _ = std::fs::remove_file(&done_path);
            panic!("interactive child did not record its process state");
        }
        let state = std::fs::read_to_string(&state_path)
            .expect("interactive child state should be readable");
        let mut state = state.split_whitespace();
        let child_pid: i32 = state
            .next()
            .expect("child pid should be recorded")
            .parse()
            .expect("child pid should be numeric");
        let child_process_group: i32 = state
            .next()
            .expect("child process group should be recorded")
            .parse()
            .expect("child process group should be numeric");
        input
            .write_all(b"armed\n")
            .expect("helper should be armed through the pseudo-terminal");

        let ready_deadline = Instant::now() + Duration::from_secs(3);
        while !ready_path.exists() && Instant::now() < ready_deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        if !ready_path.exists() {
            // SAFETY: the child recorded its own isolated process group.
            let _ = unsafe { libc::kill(-child_process_group, libc::SIGKILL) };
            terminate_command_tree(&mut session);
            let _ = std::fs::remove_file(&state_path);
            let _ = std::fs::remove_file(&done_path);
            panic!("interactive helper did not become ready");
        }

        input
            .write_all(b"\x1a")
            .expect("Ctrl-Z should be sent through the pseudo-terminal");
        let stopped = wait_for_process_stop(child_pid);
        if stopped {
            input
                .write_all(b"fg\n")
                .expect("the interactive shell should foreground the atakit job");
            if !wait_for_process_resume(child_pid) {
                // SAFETY: the child recorded its own isolated process group.
                let _ = unsafe { libc::kill(-child_process_group, libc::SIGKILL) };
                terminate_command_tree(&mut session);
                let _ = std::fs::remove_file(&state_path);
                let _ = std::fs::remove_file(&ready_path);
                let _ = std::fs::remove_file(&done_path);
                panic!("the shell did not resume the atakit job");
            }
            input
                .write_all(b"tty-secret\n")
                .expect("helper token should be sent after resume");
        } else {
            // SAFETY: best-effort cleanup for a failed lifecycle test.
            let _ = unsafe { libc::kill(-child_process_group, libc::SIGKILL) };
        }

        let done_deadline = Instant::now() + Duration::from_secs(5);
        while !done_path.exists() && Instant::now() < done_deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        if done_path.exists() {
            input
                .write_all(b"exit\n")
                .expect("interactive test shell should exit");
        }
        drop(input);

        let deadline = Instant::now() + Duration::from_secs(8);
        let status = loop {
            if let Some(status) = session.try_wait().expect("script wait should succeed") {
                break status;
            }
            if Instant::now() >= deadline {
                // SAFETY: best-effort cleanup for a failed lifecycle test.
                let _ = unsafe { libc::kill(-child_process_group, libc::SIGKILL) };
                terminate_command_tree(&mut session);
                panic!("Ctrl-Z helper pseudo-terminal test timed out");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        let mut transcript = String::new();
        session
            .stdout
            .take()
            .expect("script stdout should be piped")
            .read_to_string(&mut transcript)
            .expect("pseudo-terminal transcript should be readable");
        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(ready_path);
        let _ = std::fs::remove_file(done_path);

        assert!(
            stopped,
            "Ctrl-Z did not suspend the parent atakit job; transcript: {transcript:?}"
        );
        assert!(
            status.success(),
            "interactive helper did not complete after `fg`"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn command_captures_all_buffered_stdout_after_exit() {
        const CHILD_ENV: &str = "ATAKIT_CONFIG_EXIT_DRAIN_TEST_CHILD";
        const PIPE_BYTES: libc::c_int = 512 * 1024;
        const BURST_BYTES: usize = 384 * 1024;
        const MARKER: &str = "exit-drain-marker";

        if std::env::var_os(CHILD_ENV).is_some() {
            use std::io::Write;

            // SAFETY: stdout is the live pipe installed by resolve_command.
            let pipe_size =
                unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_SETPIPE_SZ, PIPE_BYTES) };
            assert!(
                pipe_size >= PIPE_BYTES,
                "stdout pipe could not be enlarged: {}",
                std::io::Error::last_os_error()
            );
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(&vec![b'x'; BURST_BYTES])
                .expect("buffered burst should be written");
            writeln!(stdout, "\n{MARKER}").expect("exit marker should be written");
            stdout.flush().expect("buffered burst should be flushed");
            return;
        }

        let current_exe = std::env::current_exe().expect("test executable path should resolve");
        let spec = CredentialSpec {
            file: None,
            command: Some(vec![
                "/usr/bin/env".to_string(),
                format!("{CHILD_ENV}=1"),
                current_exe.display().to_string(),
                "--exact".to_string(),
                "tests::command_captures_all_buffered_stdout_after_exit".to_string(),
                "--nocapture".to_string(),
            ]),
            env: None,
            timeout_secs: Some(10),
        };

        let output = spec.resolve("exit-drain").unwrap();

        assert!(output.contains(MARKER), "exit-time output was truncated");
        assert!(
            output.bytes().filter(|byte| *byte == b'x').count() >= BURST_BYTES,
            "the buffered burst was not captured in full"
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_stdout_capture_is_bounded() {
        let spec = CredentialSpec {
            file: None,
            command: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!("head -c {} /dev/zero", COMMAND_OUTPUT_LIMIT_BYTES + 1),
            ]),
            env: None,
            timeout_secs: Some(10),
        };

        let error = spec.resolve("oversized").unwrap_err();

        assert!(matches!(
            error,
            ConfigError::CommandOutputTooLarge {
                limit_bytes: COMMAND_OUTPUT_LIMIT_BYTES,
                ..
            }
        ));
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

// ── [alias] ──────────────────────────────────────────────────────

/// A publisher's owner fingerprint, as `0x` followed by 64 lowercase
/// hexadecimal characters.
///
/// Validated on the way in so a malformed entry fails while reading
/// configuration rather than at the point a reference is parsed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PublisherFingerprint(String);

impl PublisherFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PublisherFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for PublisherFingerprint {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !atakit_core::is_canonical_id(&value) {
            return Err(format!(
                "publisher fingerprint must be '0x' followed by 64 lowercase hexadecimal \
                 characters, got '{value}'"
            ));
        }
        Ok(Self(value))
    }
}

/// Operator-facing aliases, so a command line need not carry 66 hexadecimal
/// characters.
///
/// Two tables, because the two positions in a reference mean different things:
/// `publishers` names a fingerprint, and `apps` says which publisher owns a
/// bare application name. Splitting them means a key's meaning follows from
/// where it appears rather than from guessing at the name.
///
/// `apps` covers base images and workloads together. A name that is both, under
/// different publishers, has to be written in full — that case resolves to one
/// of them and fails closed against the registry rather than silently binding
/// to the wrong one.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AliasConfig {
    pub publishers: indexmap::IndexMap<String, PublisherFingerprint>,
    pub apps: indexmap::IndexMap<String, String>,
}

/// How far an alias chain may be followed before it is treated as a loop.
const MAX_ALIAS_DEPTH: usize = 8;

impl AliasConfig {
    /// Resolve a publisher name to its fingerprint.
    ///
    /// A value that is already a fingerprint is the answer; anything else names
    /// another entry and is resolved again, so one fingerprint can be written
    /// once and referred to by many application names.
    ///
    /// An unresolved name is an error naming it. It is never a fallthrough to
    /// treating the name as literal, which would bind a reference to a
    /// publisher the operator never named.
    pub fn resolve_publisher(&self, name: &str) -> Result<String, ConfigError> {
        if atakit_core::is_canonical_id(name) {
            return Ok(name.to_string());
        }
        let mut current = name.to_string();
        for _ in 0..MAX_ALIAS_DEPTH {
            let Some(next) = self.publishers.get(&current) else {
                let known: Vec<&str> = self.publishers.keys().map(String::as_str).collect();
                let known = if known.is_empty() {
                    "[alias.publishers] is empty".to_string()
                } else {
                    format!("known publishers: {}", known.join(", "))
                };
                return Err(ConfigError::Invalid(format!(
                    "unknown publisher '{current}'; {known}"
                )));
            };
            if atakit_core::is_canonical_id(next.as_str()) {
                return Ok(next.to_string());
            }
            current = next.to_string();
        }
        Err(ConfigError::Invalid(format!(
            "publisher alias '{name}' does not resolve to a fingerprint within \
             {MAX_ALIAS_DEPTH} steps; check [alias.publishers] for a loop"
        )))
    }

    /// Expand a reference into canonical `<publisher>/<name>:<version>` form.
    ///
    /// A reference already naming a publisher resolves that publisher; a bare
    /// `name:version` is looked up in `apps` first. Expansion happens here, in
    /// the configuration layer, and never inside `AppRef::from_str`: that type
    /// has no business reading operator configuration, and it has no
    /// representation for an unresolved name, so an alias cannot reach anything
    /// measured or persisted.
    pub fn expand(&self, reference: &str) -> Result<String, ConfigError> {
        if let Some((publisher, rest)) = reference.split_once('/') {
            let fingerprint = self.resolve_publisher(publisher)?;
            return Ok(format!("{fingerprint}/{rest}"));
        }
        let Some((name, _)) = reference.split_once(':') else {
            return Err(ConfigError::Invalid(format!(
                "reference '{reference}' is not '<publisher>/<name>:<version>' or 'name:version'"
            )));
        };
        let Some(publisher) = self.apps.get(name) else {
            let known: Vec<&str> = self.apps.keys().map(String::as_str).collect();
            let known = if known.is_empty() {
                "[alias.apps] is empty".to_string()
            } else {
                format!("known applications: {}", known.join(", "))
            };
            return Err(ConfigError::Invalid(format!(
                "'{reference}' does not name a publisher and '{name}' is not in [alias.apps]; \
                 write '<publisher>/{reference}' or add an entry. {known}"
            )));
        };
        let fingerprint = self.resolve_publisher(publisher)?;
        Ok(format!("{fingerprint}/{reference}"))
    }
}

#[cfg(test)]
mod alias_tests {
    use super::*;

    const FINGERPRINT: &str = "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f";

    fn aliases() -> AliasConfig {
        let mut config = AliasConfig::default();
        config.publishers.insert(
            "automata".to_string(),
            PublisherFingerprint::try_from(FINGERPRINT.to_string()).unwrap(),
        );
        config
            .apps
            .insert("fedora-oci".to_string(), "automata".to_string());
        config
    }

    #[test]
    fn a_named_publisher_expands_to_its_fingerprint() {
        assert_eq!(
            aliases().expand("automata/fedora-oci:v0.0.16").unwrap(),
            format!("{FINGERPRINT}/fedora-oci:v0.0.16")
        );
    }

    /// One fingerprint written once, referred to by any number of application
    /// names.
    #[test]
    fn a_bare_name_resolves_through_its_application_entry() {
        assert_eq!(
            aliases().expand("fedora-oci:v0.0.16").unwrap(),
            format!("{FINGERPRINT}/fedora-oci:v0.0.16")
        );
    }

    #[test]
    fn a_canonical_reference_passes_through_unchanged() {
        let canonical = format!("{FINGERPRINT}/fedora-oci:v0.0.16");
        assert_eq!(aliases().expand(&canonical).unwrap(), canonical);
    }

    /// Never a fallthrough to literal: that would bind the reference to a
    /// publisher the operator did not name.
    #[test]
    fn an_unknown_name_is_an_error_naming_it() {
        let error = aliases()
            .expand("typo:v1")
            .expect_err("an unknown application must not fall through");
        let message = error.to_string();
        assert!(message.contains("typo"), "{message}");
        assert!(message.contains("[alias.apps]"), "{message}");

        let error = aliases()
            .expand("nobody/thing:v1")
            .expect_err("an unknown publisher must not fall through");
        assert!(error.to_string().contains("nobody"));
    }

    #[test]
    fn an_alias_loop_is_reported_rather_than_hanging() {
        let mut config = AliasConfig::default();
        config
            .apps
            .insert("looping".to_string(), "circular".to_string());
        // `circular` is absent, so the chain terminates with an unknown name
        // rather than spinning.
        let error = config.expand("looping:v1").expect_err("must not hang");
        assert!(error.to_string().contains("circular"));
    }

    #[test]
    fn a_malformed_fingerprint_is_rejected_while_reading_configuration() {
        for bad in ["0x9f2c", FINGERPRINT.to_uppercase().as_str(), "9f2c1d3e"] {
            assert!(
                PublisherFingerprint::try_from(bad.to_string()).is_err(),
                "must reject {bad}"
            );
        }
    }
}
