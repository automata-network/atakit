use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::{NamedValue, UpArgs, WorkloadInput};

fn default_hardfork() -> String {
    "osaka".into()
}

const WORKLOAD_CONFIG: &str = "atakit-workload.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub chain: Option<String>,
    pub fork_url: String,
    pub fork_block: Option<u64>,
    pub anvil_port: u16,
    #[serde(default = "default_hardfork")]
    pub hardfork: String,
    pub runtime_dir: PathBuf,
    pub foreground: bool,
    pub owner_key: Option<String>,
    pub workloads: Vec<ResolvedWorkload>,
}

pub type ResolvedConfig = LaunchConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedWorkload {
    pub name: String,
    pub config_file: PathBuf,
    pub workload_dir: PathBuf,
    pub output_socket: PathBuf,
    pub owner_key: Option<String>,
    pub platform_profile: Option<String>,
    pub measurement_variant: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct EmulatorFileConfig {
    pub target: Option<String>,
    pub chain: Option<String>,
    pub fork_url: Option<String>,
    pub fork_block: Option<u64>,
    pub anvil_port: Option<u16>,
    pub hardfork: Option<String>,
    pub runtime_dir: Option<PathBuf>,
    pub foreground: Option<bool>,
    pub owner_key: Option<String>,
    #[serde(default)]
    pub workloads: Vec<EmulatorFileWorkload>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct EmulatorFileWorkload {
    pub file: PathBuf,
    pub name: Option<String>,
    pub output_socket: Option<PathBuf>,
    pub owner_key: Option<String>,
    pub platform_profile: Option<String>,
    pub measurement_variant: Option<String>,
}

pub fn resolve_up(args: &UpArgs, cwd: &Path) -> Result<LaunchConfig> {
    for path in [args.config.as_deref(), args.runtime_dir.as_deref()]
        .into_iter()
        .flatten()
    {
        if path.as_os_str().is_empty() {
            bail!("configuration paths cannot be empty");
        }
    }
    let cwd = absolute_existing_dir(cwd)?;
    let (file, file_base) = load_file(args.config.as_deref(), &cwd)?;
    let file = file.unwrap_or_else(empty_file);

    for path in file
        .workloads
        .iter()
        .flat_map(|w| std::iter::once(&w.file).chain(w.output_socket.iter()))
        .chain(file.runtime_dir.iter())
    {
        if path.as_os_str().is_empty() {
            bail!("emulator file paths cannot be empty");
        }
    }
    let inputs: Vec<Input> = if args.workloads.is_empty() {
        file.workloads
            .iter()
            .map(|item| Input {
                workload: WorkloadInput {
                    name: item.name.clone(),
                    path: item.file.clone(),
                },
                base: file_base.clone(),
                socket: item
                    .output_socket
                    .as_ref()
                    .map(|path| anchor(path, &file_base)),
                owner_key: item.owner_key.clone(),
                platform_profile: item.platform_profile.clone(),
                measurement_variant: item.measurement_variant.clone(),
            })
            .collect()
    } else {
        args.workloads
            .iter()
            .cloned()
            .map(|workload| Input {
                workload,
                base: cwd.clone(),
                socket: None,
                owner_key: None,
                platform_profile: None,
                measurement_variant: None,
            })
            .collect()
    };
    if inputs.is_empty() {
        bail!("at least one workload must be specified with --workload, in atakit-emulator.toml, or in --config");
    }

    let (cli_shared_owner, cli_owner_by_name) = owner_overrides(&args.owner_keys)?;
    let mut socket_overrides = named_overrides(&args.output_sockets, "output socket")?;
    let bare_socket = socket_overrides.remove("");
    if bare_socket.is_some() && inputs.len() != 1 {
        bail!("output socket overrides for multiple workloads must include NAME=");
    }

    let mut profile_overrides = named_overrides(&args.platform_profiles, "platform profile")?;
    let mut variant_overrides = named_overrides(&args.measurement_variants, "measurement variant")?;
    let bare_profile = profile_overrides.remove("");
    let bare_variant = variant_overrides.remove("");
    if inputs.len() != 1 && (bare_profile.is_some() || bare_variant.is_some()) {
        bail!("platform selection for multiple workloads must include NAME=");
    }

    let runtime_dir = args
        .runtime_dir
        .as_ref()
        .map(|p| anchor(p, &cwd))
        .or_else(|| file.runtime_dir.as_ref().map(|p| anchor(p, &file_base)))
        .unwrap_or_else(|| cwd.join(".atakit-emulator"));
    let effective_shared_owner = cli_shared_owner.clone().or(file.owner_key.clone());
    let mut workloads = Vec::with_capacity(inputs.len());
    let mut names = HashSet::new();
    for input in inputs {
        let selected = anchor(&input.workload.path, &input.base);
        if selected.extension().is_some_and(|ext| ext == "atawl") {
            bail!("emulator does not yet support .atawl packages, including packages downloaded by `atakit workload pull`; pass the source project's atakit-workload.toml with workload.image.build instead");
        }
        let config_file = if selected.is_dir() {
            selected.join(WORKLOAD_CONFIG)
        } else {
            selected
        };
        let parsed = atakit_workload::config::WorkloadConfig::from_file(&config_file)
            .with_context(|| format!("failed to load workload config {}", config_file.display()))?;
        crate::environment::validate_features(&parsed)?;
        let config_file = std::fs::canonicalize(&config_file)?;
        let name = input.workload.name.unwrap_or(parsed.workload.name);
        validate_name(&name)?;
        if !names.insert(name.clone()) {
            bail!("duplicate workload name `{name}`");
        }
        let workload_dir = cwd.clone();
        let output_socket = socket_overrides
            .remove(&name)
            .or_else(|| bare_socket.clone())
            .map(|path| anchor(Path::new(&path), &cwd))
            .or(input.socket)
            .unwrap_or_else(|| runtime_dir.join(&name).join("root/run/atakit-portal.sock"));
        let owner_key = cli_owner_by_name
            .get(&name)
            .cloned()
            .or_else(|| cli_shared_owner.clone())
            .or(input.owner_key)
            .or_else(|| file.owner_key.clone());
        let platform_profile = profile_overrides
            .remove(&name)
            .or_else(|| bare_profile.clone())
            .or(input.platform_profile);
        let measurement_variant = variant_overrides
            .remove(&name)
            .or_else(|| bare_variant.clone())
            .or(input.measurement_variant);
        for (field, value) in [
            ("platform-profile", &platform_profile),
            ("measurement-variant", &measurement_variant),
        ] {
            if value.as_ref().is_some_and(|v| v.trim().is_empty()) {
                bail!("workload `{name}`: {field} cannot be empty");
            }
        }
        workloads.push(ResolvedWorkload {
            name,
            config_file,
            workload_dir,
            output_socket,
            owner_key,
            platform_profile,
            measurement_variant,
        });
    }
    reject_unknown_overrides(&socket_overrides, &cli_owner_by_name, &names)?;
    reject_unknown_overrides(&profile_overrides, &variant_overrides, &names)?;
    let mut sockets = HashSet::new();
    for workload in &workloads {
        if !sockets.insert(workload.output_socket.clone()) {
            bail!(
                "duplicate output socket path {}",
                workload.output_socket.display()
            );
        }
    }

    if args.anvil_port.or(file.anvil_port) == Some(0) {
        bail!("anvil-port must be between 1 and 65535");
    }
    let target = args.target.clone().or(file.target);
    if target.as_ref().is_some_and(|name| name.trim().is_empty()) {
        bail!("target cannot be empty");
    }
    Ok(LaunchConfig {
        target,
        chain: args.chain.clone().or(file.chain),
        fork_url: args
            .fork_url
            .clone()
            .or(file.fork_url)
            .unwrap_or_else(|| "http://127.0.0.1:8545".into()),
        fork_block: args.fork_block.or(file.fork_block),
        anvil_port: args.anvil_port.or(file.anvil_port).unwrap_or(8546),
        hardfork: args
            .hardfork
            .clone()
            .or(file.hardfork)
            .unwrap_or_else(default_hardfork),
        runtime_dir,
        foreground: args.foreground.or(file.foreground).unwrap_or(false),
        owner_key: effective_shared_owner,
        workloads,
    })
}

#[derive(Debug)]
struct Input {
    workload: WorkloadInput,
    base: PathBuf,
    socket: Option<PathBuf>,
    owner_key: Option<String>,
    pub platform_profile: Option<String>,
    pub measurement_variant: Option<String>,
}

fn load_file(path: Option<&Path>, cwd: &Path) -> Result<(Option<EmulatorFileConfig>, PathBuf)> {
    let explicit = path.is_some();
    let path = anchor(
        path.unwrap_or_else(|| Path::new("atakit-emulator.toml")),
        cwd,
    );
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if !explicit && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((None, cwd.to_path_buf()));
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read emulator config {}", path.display()));
        }
    };
    let parsed = toml::from_str(&text).map_err(|error: toml::de::Error| {
        let location = error
            .span()
            .map(|span| format!(" at byte {}", span.start))
            .unwrap_or_default();
        anyhow!(
            "failed to parse emulator config {}{location}: {}",
            path.display(),
            error.message()
        )
    })?;
    Ok((Some(parsed), path.parent().unwrap_or(cwd).to_path_buf()))
}

fn empty_file() -> EmulatorFileConfig {
    EmulatorFileConfig {
        target: None,
        chain: None,
        fork_url: None,
        fork_block: None,
        anvil_port: None,
        hardfork: None,
        runtime_dir: None,
        foreground: None,
        owner_key: None,
        workloads: vec![],
    }
}

fn named_overrides(values: &[NamedValue], kind: &str) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    for value in values {
        let key = value.name.clone().unwrap_or_default();
        if result.insert(key, value.value.clone()).is_some() {
            bail!("duplicate {kind} override");
        }
    }
    Ok(result)
}

fn owner_overrides(values: &[NamedValue]) -> Result<(Option<String>, HashMap<String, String>)> {
    let mut values = named_overrides(values, "owner key")?;
    Ok((values.remove(""), values))
}

fn reject_unknown_overrides(
    sockets: &HashMap<String, String>,
    owners: &HashMap<String, String>,
    names: &HashSet<String>,
) -> Result<()> {
    if let Some(name) = sockets
        .keys()
        .chain(owners.keys())
        .find(|name| !names.contains(*name))
    {
        return Err(anyhow!("override names unknown workload `{name}`"));
    }
    Ok(())
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if matches!(
        name,
        "data"
            | "bridges"
            | "compose"
            | "workloads"
            | "control.sock"
            | "runtime.lock"
            | "startup.lock"
            | "launch.private.json"
            | "checkpoint.json"
            | "checkpoint.previous.json"
            | "endpoints.json"
            | "sockets.private.json"
            | "workload-dirs.private.json"
            | "emulator.log"
            | "anvil.log"
            | "compose.yaml"
    ) {
        bail!("workload name `{name}` is reserved for emulator runtime files; choose another instance name");
    }
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains(char::from(92))
    {
        bail!("invalid workload name `{name}`");
    }
    Ok(())
}

fn absolute_existing_dir(path: &Path) -> Result<PathBuf> {
    if !path.is_dir() {
        bail!("invocation directory {} does not exist", path.display());
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn anchor(path: &Path, base: &Path) -> PathBuf {
    normalize(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    })
}

fn normalize(path: PathBuf) -> PathBuf {
    use std::path::Component;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}
