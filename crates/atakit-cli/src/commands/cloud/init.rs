use anyhow::{Result, bail};
use atakit_cloud::cli::InitArgs;
use atakit_cloud::init::{self, AgentConfig};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_core::Env;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::config::{self, Config};
use super::{resolve_instance, resolve_workload};

pub async fn run(args: InitArgs, env: &Env, config: &Config) -> Result<()> {
	// 1. Resolve instance.
	let (target_name, instance_name) =
		resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;

	// 2. Load state and verify status.
	let mut state = DeployState::load(&env.data_dir, &target_name, &instance_name)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	let ip = match &state.status {
		DeployStatus::Deployed { ip } => {
			if ip.is_empty() {
				bail!("deployment {target_name}/{instance_name} has no external IP");
			}
			ip.clone()
		}
		other => {
			let status_desc = match other {
				DeployStatus::Deploying { .. } => "still deploying",
				DeployStatus::Failed { .. } => "in failed state",
				DeployStatus::Destroying => "being destroyed",
				DeployStatus::Destroyed => "already destroyed",
				DeployStatus::Deployed { .. } => unreachable!(),
			};
			bail!(
				"cannot init {target_name}/{instance_name}: instance is {status_desc}. \
				 Only deployed instances can be initialized."
			);
		}
	};

	// 3. Resolve workload.
	let resolved = resolve_workload(&args.source, &args.dir, env)?;
	let archive_path = resolved.archive_path;
	let workload_name = resolved.name;
	let workload_version = resolved.version;

	// 4. Compute archive hash.
	let bytes = std::fs::read(&archive_path)
		.map_err(|e| anyhow::anyhow!("failed to read archive {}: {e}", archive_path.display()))?;
	let archive_hash = format!("{:x}", Sha256::digest(&bytes));

	// 5. Build agent config: CLI > persisted state > config file.
	let effective_rpc_url = args.rpc_url
		.or_else(|| state.agent_env.rpc_url.clone())
		.or_else(|| config.cloud.rpc_url.clone())
		.or_else(|| config.publish.rpc_url.clone());
	let effective_session_registry = args.session_registry
		.or_else(|| state.agent_env.session_registry.clone())
		.or_else(|| config.cloud.session_registry.clone())
		.or_else(|| config.publish.session_registry.clone());
	let effective_owner_key_file = args.owner_key
		.or_else(|| state.agent_env.owner_key_file.clone())
		.or_else(|| config.cloud.owner_key_file.clone())
		.or_else(|| config.publish.owner_key_file.clone());
	let effective_relay_key_file = args.relay_key
		.or_else(|| state.agent_env.relay_key_file.clone())
		.or_else(|| config.cloud.relay_key_file.clone())
		.or_else(|| config.publish.relay_key_file.clone());
	let effective_expire_offset = state.agent_env.expire_offset
		.or(config.cloud.expire_offset)
		.unwrap_or(3600);

	let rpc_url = effective_rpc_url
		.ok_or_else(|| anyhow::anyhow!("rpc_url is required (use --rpc-url or set in config)"))?;
	let session_registry = effective_session_registry
		.ok_or_else(|| anyhow::anyhow!("session_registry is required (use --session-registry or set in config)"))?;
	let owner_key_file = effective_owner_key_file
		.ok_or_else(|| anyhow::anyhow!("owner_key is required (use --owner-key or set in config)"))?;
	let relay_key_file = effective_relay_key_file
		.ok_or_else(|| anyhow::anyhow!("relay_key is required (use --relay-key or set in config)"))?;

	let owner_key = config::read_key_file(&owner_key_file)?;
	let relay_key = config::read_key_file(&relay_key_file)?;

	let agent_config = AgentConfig {
		rpc_url: rpc_url.clone(),
		session_registry: session_registry.clone(),
		owner_private_key: owner_key,
		relay_private_key: relay_key,
		expire_offset: effective_expire_offset,
	};

	// 6. Show plan and confirm.
	eprintln!("{}", "Plan:".dimmed());
	eprintln!("  1. Wait for CVM agent");
	eprintln!("  2. Initialize workload");
	eprintln!();
	eprintln!("{}", "Configuration:".dimmed());
	eprintln!("  {:<18}{}", "Instance:".dimmed(), format!("{target_name}/{instance_name}").bold());
	eprintln!("  {:<18}{}", "IP:".dimmed(), ip);
	eprintln!("  {:<18}{}:{}", "Workload:".dimmed(), workload_name, workload_version);
	eprintln!("  {:<18}{}", "Archive:".dimmed(), archive_path.display());
	eprintln!("  {:<18}{}", "SHA-256:".dimmed(), &archive_hash[..16]);
	eprintln!("  {:<18}{}s", "Timeout:".dimmed(), args.timeout);
	eprintln!();

	if !args.yes {
		eprint!("Proceed? [y/N] ");
		let mut input = String::new();
		std::io::stdin().read_line(&mut input)?;
		if !input.trim().eq_ignore_ascii_case("y") {
			eprintln!("Aborted.");
			return Ok(());
		}
	}

	// 7. Wait for agent.
	eprint!("  [1/2] Wait for CVM agent... ");
	init::wait_for_agent(&ip, args.timeout).await
		.map_err(|e| anyhow::anyhow!("{e}"))?;
	eprintln!("{}", "done".green());

	// 8. Initialize workload.
	eprint!("  [2/2] Initialize workload... ");
	init::post_init(&ip, &archive_path.display().to_string(), None, &agent_config).await
		.map_err(|e| anyhow::anyhow!("{e}"))?;
	eprintln!("{}", "done".green());

	// 9. Update state.
	state.workload_name = workload_name.clone();
	state.workload_version = workload_version.clone();
	state.archive_path = archive_path.display().to_string();
	state.archive_hash = archive_hash;
	state.agent_env = atakit_cloud::PersistedAgentEnv {
		rpc_url: Some(rpc_url),
		session_registry: Some(session_registry),
		owner_key_file: Some(owner_key_file),
		relay_key_file: Some(relay_key_file),
		expire_offset: Some(effective_expire_offset),
	};
	state.save(&env.data_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

	// 10. Summary.
	eprintln!();
	eprintln!("{}", "==> Workload initialized!".green().bold());
	eprintln!();
	eprintln!("    {:<12}{}", "Instance:".dimmed(), format!("{target_name}/{instance_name}").bold());
	eprintln!("    {:<12}{}", "IP:".dimmed(), ip);
	eprintln!("    {:<12}{}:{}", "Workload:".dimmed(), workload_name, workload_version);
	eprintln!();

	Ok(())
}
