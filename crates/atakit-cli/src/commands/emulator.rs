use crate::config::Config;
use anyhow::{bail, Context, Result};
use atakit_emulator::{
    cli::{EmulatorCommand, SessionCommand},
    config::resolve_up,
    endpoints::{dotenv, EndpointInfo},
    runtime::{self, PreparedLaunch},
};
use fs2::FileExt;
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
fn directory(path: Option<PathBuf>) -> Result<PathBuf> {
    Ok(path.unwrap_or(std::env::current_dir()?.join(".atakit-emulator")))
}
fn secret(config: &Config, name: &str) -> Result<[u8; 32]> {
    let source = config
        .keys
        .get(name)
        .with_context(|| format!("missing signing source [keys.{name}]"))?;
    if source.key_type != crate::config::KeyType::Es256k {
        bail!("key `{name}` must have type es256k");
    }
    let raw = source.resolve(name)?;
    hex::decode(raw.trim().strip_prefix("0x").unwrap_or(raw.trim()))?
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!("key `{name}` must resolve to a 32-byte secp256k1 private key")
        })
}
fn print(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn startup_log(path: &Path, start: u64) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let end = file.metadata()?.len();
    file.seek(SeekFrom::Start(start.max(end.saturating_sub(65536))))?;
    let mut bytes = Vec::new();
    file.take(65536).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).trim().to_owned())
}
async fn endpoints(dir: &Path) -> Result<EndpointInfo> {
    Ok(serde_json::from_value(
        runtime::control(dir, "status", None).await?,
    )?)
}
/// Configuration is available even before the first emulator launch. Only expose
/// chain connection fields, never signing keys or prover credentials.
async fn status(dir: &Path, config: &Config) -> Result<serde_json::Value> {
    let mut value = match endpoints(dir).await {
        Ok(endpoints) => serde_json::to_value(endpoints)?,
        Err(error) => {
            let stopped = error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                )
            });
            if !stopped {
                return Err(error);
            }
            serde_json::json!({"state": "stopped", "workloads": {}})
        }
    };
    value["chains"] = config
        .chains
        .iter()
        .map(|(name, chain)| {
            (
                name.clone(),
                serde_json::json!({
                    "rpc_url": chain.rpc_url,
                    "chain_id": chain.chain_id,
                    "session_registry": chain.session_registry,
                    "workload_registry": chain.workload_registry,
                    "base_image_registry": chain.base_image_registry,
                }),
            )
        })
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();
    value["default_chain"] = serde_json::json!(config.publish.chain);
    Ok(value)
}

/// Resolve cloud metadata before loading keys or starting any runtime processes.
fn apply_cloud_target(
    launch: &mut atakit_emulator::config::LaunchConfig,
    cloud: &atakit_cloud::config::CloudConfig,
) -> Result<()> {
    use atakit_cloud::config::{validate_target, CcType, PlatformKind};

    let Some(name) = launch.target.as_deref() else {
        return Ok(());
    };
    let target = cloud.targets.get(name).with_context(|| {
        format!("unknown cloud target `{name}`; configure [cloud.targets.{name}] in the atakit global config")
    })?;
    let provider = cloud.providers.get(&target.provider).with_context(|| {
        format!(
            "cloud target `{name}` references unknown provider `{}`",
            target.provider
        )
    })?;
    if provider.platform != PlatformKind::Gcp {
        bail!(
            "cloud target `{name}` uses {}; emulator currently supports only GCP/TDX targets",
            provider.platform
        );
    }
    let cc_type = atakit_cloud::config::infer_cc_type(provider.platform, &target.vmtype)
        .with_context(|| format!("cloud target `{name}` has an invalid vmtype"))?;
    if cc_type != CcType::Tdx {
        bail!("cloud target `{name}` uses {cc_type}; emulator currently supports only GCP/TDX targets");
    }
    validate_target(target, provider, name)?;
    for workload in &mut launch.workloads {
        for (field, selected, expected) in [
            (
                "platform-profile",
                &mut workload.platform_profile,
                "gcp-tdx",
            ),
            (
                "measurement-variant",
                &mut workload.measurement_variant,
                target.vmtype.as_str(),
            ),
        ] {
            if let Some(value) = selected.as_deref() {
                if value != expected {
                    bail!("workload `{}`: {field} `{value}` conflicts with cloud target `{name}` (requires `{expected}`); remove the explicit selector or choose a matching target", workload.name);
                }
            }
            *selected = Some(expected.to_owned());
        }
        if workload.owner_key.is_none() {
            workload.owner_key = target
                .owner_key
                .clone()
                .or(cloud.defaults.owner_key.clone());
        }
    }
    if launch.chain.is_none() {
        launch.chain = target.chain.clone().or(cloud.defaults.chain.clone());
    }
    Ok(())
}

fn resolve_chain(
    launch: &atakit_emulator::config::LaunchConfig,
    config: &Config,
) -> Result<String> {
    let chain = launch
        .chain
        .clone()
        .or(config.publish.chain.clone())
        .or_else(|| {
            (config.chains.len() == 1).then(|| config.chains.keys().next().unwrap().clone())
        })
        .context("--chain is required when multiple chains have no publish.chain default")?;
    if !config.chains.contains_key(&chain) {
        bail!("unknown chain configuration `{chain}`");
    }
    Ok(chain)
}

fn choose_target(
    mut compatible: Vec<atakit_emulator::config::LaunchConfig>,
    rejected: Vec<String>,
) -> Result<atakit_emulator::config::LaunchConfig> {
    if compatible.len() == 1 {
        return Ok(compatible.remove(0));
    }
    if compatible.is_empty() {
        bail!("No compatible emulator cloud target:\n  - {}\nConfigure a GCP/TDX target whose machine measurements are allowed by every workload.", rejected.join("\n  - "));
    }
    let names = compatible
        .iter()
        .map(|c| format!("--target {}", c.target.as_deref().unwrap_or_default()))
        .collect::<Vec<_>>();
    bail!(
        "Multiple compatible emulator cloud targets; select one explicitly:\n  {}",
        names.join("\n  ")
    );
}

async fn infer_cloud_target(
    launch: &atakit_emulator::config::LaunchConfig,
    config: &Config,
) -> Result<atakit_emulator::config::LaunchConfig> {
    use atakit_emulator::fork::{AnvilFork, ForkOptions};
    let mut compatible = Vec::new();
    let mut rejected = Vec::new();
    let mut candidates = Vec::new();
    for name in config.cloud.targets.keys() {
        let mut candidate = launch.clone();
        candidate.target = Some(name.clone());
        match apply_cloud_target(&mut candidate, &config.cloud)
            .and_then(|()| resolve_chain(&candidate, config))
        {
            Ok(chain) => {
                candidate.chain = Some(chain);
                candidates.push(candidate);
            }
            Err(error) => rejected.push(format!("{name}: {error:#}")),
        }
    }
    if candidates.is_empty() {
        return choose_target(compatible, rejected);
    }
    let publisher_name = config
        .publish
        .owner_key
        .as_deref()
        .context("publish.owner_key is required")?;
    let publisher_secret = secret(config, publisher_name)?;
    let temporary = tempfile::tempdir()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let mut fork = AnvilFork::spawn(ForkOptions {
        upstream_url: launch.fork_url.clone(),
        block_number: launch.fork_block,
        port,
        log_path: temporary.path().join("anvil.log"),
        load_state: None,
    })
    .await
    .context("cannot inspect target compatibility on a temporary local fork")?;
    let result = async {
        for candidate in candidates {
            let name = candidate.target.as_deref().unwrap().to_owned();
            let chain = &config.chains[candidate.chain.as_ref().unwrap()];
            let prepared = PreparedLaunch {
                launch: candidate.clone(),
                session_registry: chain.session_registry.clone(),
                workload_registry: chain.workload_registry.clone(),
                base_image_registry: chain.base_image_registry.clone(),
                publisher_secret,
                owners: BTreeMap::new(),
            };
            // Isolate target probes from each other's development registrations.
            let snapshot = fork.rpc.request("evm_snapshot", serde_json::json!([])).await?;
            let probe: Result<()> = async {
                let engine = runtime::engine(&fork, &prepared).await?;
                for workload in &candidate.workloads {
                    let choices = engine.policy_candidates(workload, &publisher_secret).await
                        .with_context(|| format!("workload `{}`", workload.name))?;
                    if choices.len() != 1 {
                        bail!("workload `{}`: found {} compatible base-image policies for {} / {}; expected one unrevoked Registry policy allowed by the workload",
                            workload.name, choices.len(), workload.platform_profile.as_deref().unwrap(), workload.measurement_variant.as_deref().unwrap());
                    }
                }
                Ok(())
            }.await;
            if fork.rpc.request("evm_revert", serde_json::json!([snapshot])).await? != true {
                bail!("could not reset temporary target probe state");
            }
            match probe {
                Ok(()) => compatible.push(candidate),
                Err(error) => rejected.push(format!("{name}: {error:#}")),
            }
        }
        choose_target(compatible, rejected)
    }.await;
    fork.stop().await?;
    result
}

fn session_owner_name<'a>(
    workload: &str,
    selected: Option<&'a str>,
    default: Option<&'a str>,
) -> Result<&'a str> {
    selected.or(default).filter(|name| !name.is_empty()).with_context(|| {
        format!("session owner key is required for workload `{workload}`; set --owner-key, owner-key in emulator config, the target's owner_key, or [cloud.defaults].owner_key (publish.owner_key is only the workload publisher)")
    })
}

pub async fn run(command: EmulatorCommand, config: &Config) -> Result<()> {
    match command {
        EmulatorCommand::Up(args) => {
            let mut launch = resolve_up(&args, &std::env::current_dir()?)?;
            if launch.target.is_none()
                && !config.cloud.targets.is_empty()
                && launch
                    .workloads
                    .iter()
                    .any(|w| w.platform_profile.is_none() || w.measurement_variant.is_none())
            {
                launch = infer_cloud_target(&launch, config).await?;
                eprintln!(
                    "Automatically selected emulator cloud target `{}`",
                    launch.target.as_deref().unwrap()
                );
            }
            apply_cloud_target(&mut launch, &config.cloud)?;
            let chain = resolve_chain(&launch, config)?;
            let chain_config = &config.chains[&chain];
            launch.chain = Some(chain);
            let publisher_name = config
                .publish
                .owner_key
                .as_deref()
                .context("publish.owner_key is required")?;
            let publisher_secret = secret(config, publisher_name)?;
            let mut owners = BTreeMap::new();
            for w in &launch.workloads {
                let name = session_owner_name(
                    &w.name,
                    w.owner_key.as_deref(),
                    config.cloud.defaults.owner_key.as_deref(),
                )?;
                owners.insert(w.name.clone(), secret(config, name)?);
            }
            let prepared = PreparedLaunch {
                launch,
                session_registry: chain_config.session_registry.clone(),
                workload_registry: chain_config.workload_registry.clone(),
                base_image_registry: chain_config.base_image_registry.clone(),
                publisher_secret,
                owners,
            };
            let dir = &prepared.launch.runtime_dir;
            runtime::private_dir(dir)?;
            let startup_lock = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(dir.join("startup.lock"))?;
            startup_lock
                .try_lock_exclusive()
                .context("another up command is starting this environment")?;
            if let Ok(existing) = endpoints(dir).await {
                let mut old: PreparedLaunch =
                    serde_json::from_slice(&std::fs::read(dir.join("launch.private.json"))?)?;
                let mut next = prepared.clone();
                old.launch.foreground = false;
                next.launch.foreground = false;
                if serde_json::to_value(old)? != serde_json::to_value(next)? {
                    bail!("running environment has a different launch description; stop it first");
                }
                return print(&existing);
            }
            runtime::private_dir(dir)?;
            // A private launch envelope avoids putting any resolved secret in argv or exports.
            runtime::write_private(&dir.join("launch.private.json"), &prepared)?;
            if prepared.launch.foreground {
                return runtime::run_foreground_with_startup_lock(prepared, Some(startup_lock))
                    .await;
            }
            let log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(dir.join("emulator.log"))?;
            let log_start = log.metadata()?.len();
            let mut child = Command::new(std::env::current_exe()?)
                .args(["emulator", "serve", "--runtime-dir"])
                .arg(dir)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .process_group(0)
                .spawn()?;
            for _ in 0..900 {
                if let Some(status) = child.try_wait()? {
                    let path = dir.join("emulator.log");
                    bail!(
                        "emulator exited {status}:\n{}\nFull log: {}",
                        startup_log(&path, log_start)?,
                        path.display()
                    );
                }
                if let Ok(e) = endpoints(dir).await {
                    print(&e)?;
                    if e.state != "ready" {
                        bail!("emulator is running with failed instances; inspect status");
                    }
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            bail!(
                "emulator startup timed out; inspect {}",
                dir.join("emulator.log").display()
            )
        }
        EmulatorCommand::Serve { runtime_dir } => {
            let p =
                serde_json::from_slice(&std::fs::read(runtime_dir.join("launch.private.json"))?)?;
            runtime::run_foreground(p).await
        }
        EmulatorCommand::Status(args) => {
            let dir = directory(args.runtime_dir)?;
            print(&status(&dir, config).await?)
        }
        EmulatorCommand::Env(args) => {
            let e = endpoints(&directory(args.runtime_dir)?).await?;
            let (_, w) = e.select(args.workload.as_deref())?;
            match args.format.as_deref().unwrap_or("dotenv") {
                "dotenv" => {
                    print!("{}", dotenv(&w.env));
                    Ok(())
                }
                "json" => print(&w.env),
                other => bail!("unsupported env format `{other}`"),
            }
        }
        EmulatorCommand::Exec(args) => {
            let e = endpoints(&directory(args.target.runtime_dir)?).await?;
            let (_, w) = e.select(args.target.workload.as_deref())?;
            let mut command = Command::new(&args.command[0]);
            let mut overrides = Vec::new();
            for (name, value) in &w.env {
                match std::env::var_os(name) {
                    Some(external) => {
                        if external != std::ffi::OsStr::new(value) {
                            overrides.push(name.as_str());
                        }
                    }
                    None => {
                        command.env(name, value);
                    }
                }
            }
            if !overrides.is_empty() {
                eprintln!(
                    "warning: external environment overrides emulator values for: {} (this process only)",
                    overrides.join(", ")
                );
            }
            let error = command
                .args(&args.command[1..])
                .current_dir(&w.workload_dir)
                .exec();
            Err(error.into())
        }
        EmulatorCommand::Logs(args) => {
            let dir = directory(args.runtime_dir)?;
            let e = endpoints(&dir).await?;
            if let Some(name) = args.workload.as_deref() {
                e.select(Some(name))?;
            }
            let logs = std::fs::read_to_string(dir.join("emulator.log")).unwrap_or_default();
            if let Some(name) = args.workload.as_deref() {
                let marker = format!("workload={name} ");
                for line in logs.lines().filter(|l| l.contains(&marker)) {
                    println!("{line}");
                }
            } else {
                print!("{logs}");
                print!(
                    "{}",
                    std::fs::read_to_string(dir.join("anvil.log")).unwrap_or_default()
                );
            }
            Ok(())
        }
        EmulatorCommand::Session { command } => {
            let (op, args) = match command {
                SessionCommand::Rotate(a) => ("rotate", a),
                SessionCommand::Revoke(a) => ("revoke", a),
            };
            print(
                &runtime::control(&directory(args.runtime_dir)?, op, args.workload.as_deref())
                    .await?,
            )
        }
        EmulatorCommand::Stop(args) => print(
            &atakit_emulator::lifecycle::shutdown(&directory(args.runtime_dir)?, false, false)
                .await?,
        ),
        EmulatorCommand::Down(args) => print(
            &atakit_emulator::lifecycle::shutdown(
                &directory(args.runtime_dir)?,
                true,
                args.purge_data,
            )
            .await?,
        ),
        EmulatorCommand::Refresh(args) => {
            print(&runtime::control(&directory(args.runtime_dir)?, "refresh", None).await?)
        }
        EmulatorCommand::WorkloadCompose(args) => {
            let engine = match config.build.container_engine {
                crate::config::ContainerEngine::Auto => {
                    match atakit_workload::ContainerEngine::detect().await? {
                        atakit_workload::ContainerEngine::Docker => "docker",
                        atakit_workload::ContainerEngine::Podman => "podman",
                    }
                }
                configured => configured.as_str(),
            };
            let general_help = args.help || args.command.is_empty();
            let command_help = args.command.first().is_some_and(|arg| arg == "help")
                || (args.command.len() == 2
                    && (args.command[1] == "--help" || args.command[1] == "-h"));
            if general_help || command_help {
                let mut docker = Command::new(engine);
                docker.arg("compose");
                if general_help {
                    println!("Usage: atakit emulator workload-compose [ATAKIT OPTIONS] COMMAND [COMPOSE OPTIONS]\n\nAtakit options (before COMMAND):\n  --workload NAME            Select a workload; repeat for multiple workloads\n  --runtime-dir DIR          Emulator directory (default: .atakit-emulator)\n  --output PATH              Compose file (default: per workload or selected group)\n  --platform PLATFORM       Container platform for up, e.g. linux/amd64\n  --portal-transport MODE    native (default) or bridge\n  -h, --help                 Show this help\n\nup regenerates the Compose file before starting containers. log aliases logs.\n\nAvailable commands and options from {engine} compose:\n");
                    std::io::Write::flush(&mut std::io::stdout())?;
                    docker.arg("--help");
                } else {
                    let mut command = args.command;
                    if command[0] == "log" {
                        command[0] = "logs".into();
                    }
                    docker.args(command);
                }
                return Err(docker.exec()).with_context(|| {
                    format!("could not run {engine} compose --help; ensure {engine} is installed and available on PATH")
                });
            }
            let dir = directory(args.compose.runtime_dir)?;
            let mut command = args.command;
            if command[0] == "log" {
                command[0] = "logs".into();
            }
            if args.compose.platform.is_some() && command[0] != "up" {
                anyhow::bail!("--platform is only supported with up; other commands use the platform in the saved Compose file");
            }
            let path = if command[0] == "up" {
                atakit_emulator::compose::generate(
                    &dir,
                    &args.compose.workloads,
                    args.compose.output.as_deref(),
                    args.compose.portal_transport,
                    args.compose.platform.as_deref(),
                )
                .await
                .context("could not generate workload Compose configuration; ensure the emulator is running")?
            } else {
                atakit_emulator::compose::existing_output(
                    &dir,
                    &args.compose.workloads,
                    args.compose.output.as_deref(),
                )?
            };
            if !path.is_file() {
                bail!(
                    "Compose file {} does not exist; run `atakit emulator workload-compose up` first",
                    path.display()
                );
            }
            let error = Command::new(engine)
                .arg("compose")
                .arg("-f")
                .arg(&path)
                .args(command)
                .exec();
            Err(error).with_context(|| {
                format!("could not run {engine} compose; ensure {engine} is installed and available on PATH (selected by build.container_engine)")
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_error_uses_only_the_current_launch_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("emulator.log");
        let old = "Error: old RPC failure\nemulator state=ready\n";
        std::fs::write(&log, format!("{old}Error: new checkpoint conflict\n")).unwrap();
        assert_eq!(
            startup_log(&log, old.len() as u64).unwrap(),
            "Error: new checkpoint conflict"
        );
    }

    #[test]
    fn session_owner_requires_a_session_owner_setting() {
        assert_eq!(
            session_owner_name("app", Some("explicit"), Some("default")).unwrap(),
            "explicit"
        );
        assert_eq!(
            session_owner_name("app", None, Some("default")).unwrap(),
            "default"
        );
        let error = session_owner_name("app", None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("session owner key is required"));
        assert!(error.contains("publish.owner_key is only the workload publisher"));
        assert!(session_owner_name("app", Some(""), Some("default")).is_err());
        assert!(session_owner_name("app", None, Some("")).is_err());
    }

    fn target_launch(extra: &[&str]) -> atakit_emulator::config::LaunchConfig {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("atakit-workload.toml"),
            "format = 7\n[workload]\nname = \"signer\"\nversion = \"1\"\nbase-image-mode = \"locked\"\nimage = { build = \".\" }\n").unwrap();
        let cli = atakit_emulator::cli::EmulatorCli::try_parse_from(
            [
                "atakit-emulator",
                "up",
                "--workload",
                ".",
                "--target",
                "dev",
            ]
            .into_iter()
            .chain(extra.iter().copied()),
        )
        .unwrap();
        let EmulatorCommand::Up(args) = cli.command else {
            unreachable!()
        };
        resolve_up(&args, dir.path()).unwrap()
    }

    fn target_cloud() -> atakit_cloud::config::CloudConfig {
        toml::from_str(
            r#"
[providers.local-gcp]
platform = "gcp"
region = "asia-southeast1-b"
[targets.dev]
provider = "local-gcp"
vmtype = "c3-standard-4"
chain = "hoodi"
owner_key = "target-owner"
"#,
        )
        .unwrap()
    }

    #[test]
    fn cloud_target_selects_measurements_for_all_workloads() {
        let mut launch = target_launch(&[]);
        let mut second = launch.workloads[0].clone();
        second.name = "api".into();
        launch.workloads.push(second);
        apply_cloud_target(&mut launch, &target_cloud()).unwrap();
        assert_eq!(launch.chain.as_deref(), Some("hoodi"));
        for w in &launch.workloads {
            assert_eq!(w.platform_profile.as_deref(), Some("gcp-tdx"));
            assert_eq!(w.measurement_variant.as_deref(), Some("c3-standard-4"));
            assert_eq!(w.owner_key.as_deref(), Some("target-owner"));
        }
        assert_eq!(launch.fork_url, "http://127.0.0.1:8545");
    }

    #[test]
    fn cloud_target_preserves_explicit_chain_owner_and_matching_selectors() {
        let mut launch = target_launch(&[
            "--chain",
            "custom",
            "--owner-key",
            "custom-owner",
            "--platform-profile",
            "gcp-tdx",
            "--measurement-variant",
            "c3-standard-4",
        ]);
        apply_cloud_target(&mut launch, &target_cloud()).unwrap();
        assert_eq!(launch.chain.as_deref(), Some("custom"));
        assert_eq!(
            launch.workloads[0].owner_key.as_deref(),
            Some("custom-owner")
        );
    }

    #[test]
    fn cloud_target_inherits_cloud_defaults() {
        let mut launch = target_launch(&[]);
        let mut cloud = target_cloud();
        let target = cloud.targets.get_mut("dev").unwrap();
        target.chain = None;
        target.owner_key = None;
        cloud.defaults.chain = Some("default-chain".into());
        cloud.defaults.owner_key = Some("default-owner".into());
        apply_cloud_target(&mut launch, &cloud).unwrap();
        assert_eq!(launch.chain.as_deref(), Some("default-chain"));
        assert_eq!(
            launch.workloads[0].owner_key.as_deref(),
            Some("default-owner")
        );
    }

    #[test]
    fn cloud_target_rejects_conflicting_measurements() {
        for (flag, value) in [
            ("--platform-profile", "azure-sev-snp"),
            ("--measurement-variant", "c3-standard-8"),
        ] {
            let mut launch = target_launch(&[flag, value]);
            let error = apply_cloud_target(&mut launch, &target_cloud())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("dev") && error.contains("signer") && error.contains(value),
                "{error}"
            );
        }
    }

    #[test]
    fn cloud_target_rejects_missing_target_provider_and_unsupported_platform() {
        let cloud = target_cloud();
        let mut missing = cloud.clone();
        missing.targets.clear();
        let mut provider = cloud.clone();
        provider.providers.clear();
        let mut unsupported = cloud.clone();
        unsupported.providers.get_mut("local-gcp").unwrap().platform =
            atakit_cloud::config::PlatformKind::Azure;
        let mut snp = cloud.clone();
        snp.targets.get_mut("dev").unwrap().vmtype = "n2d-standard-2".into();
        let mut mismatch = cloud.clone();
        mismatch.targets.get_mut("dev").unwrap().cc_type =
            Some(atakit_cloud::config::CcType::SevSnp);
        for (config, needle) in [
            (missing, "unknown cloud target"),
            (provider, "provider"),
            (unsupported, "GCP/TDX"),
            (snp, "GCP/TDX"),
            (mismatch, "does not match"),
        ] {
            let error = apply_cloud_target(&mut target_launch(&[]), &config)
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{error}");
        }
    }
    #[test]
    fn automatic_target_requires_exactly_one_match_and_reports_rejections() {
        let dev = target_launch(&[]);
        assert_eq!(
            choose_target(vec![dev.clone()], vec!["other: unsupported".into()])
                .unwrap()
                .target
                .as_deref(),
            Some("dev")
        );
        let mut other = dev.clone();
        other.target = Some("other".into());
        let ambiguous = choose_target(vec![dev, other], vec![])
            .unwrap_err()
            .to_string();
        assert!(ambiguous.contains("--target dev") && ambiguous.contains("--target other"));
        let unavailable = choose_target(
            vec![],
            vec!["dev: workload api has no c3-standard-4 measurement".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(unavailable.contains("api") && unavailable.contains("c3-standard-4"));
    }

    #[test]
    fn automatic_target_does_not_ignore_other_workload_constraints() {
        let mut launch = target_launch(&[]);
        let mut other = launch.workloads[0].clone();
        other.name = "api".into();
        other.measurement_variant = Some("c3-standard-8".into());
        launch.workloads.push(other);
        let error = apply_cloud_target(&mut launch, &target_cloud())
            .unwrap_err()
            .to_string();
        assert!(error.contains("api") && error.contains("c3-standard-8"));
    }
}
