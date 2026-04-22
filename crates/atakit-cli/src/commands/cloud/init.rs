use anyhow::{Result, bail};
use atakit_cloud::cli::InitArgs;
use atakit_cloud::init::{self, InitConfig, InitChainConfig, InitKeyConfig};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_core::Env;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::config::{Config, KeyMode};
use super::{InitEnvResolver, collect_unmeasured_tar, resolve_instance, resolve_workload};

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
	let resolved = resolve_workload(&args.source, &args.dir, env, args.skip_freshness_check)?;
	let archive_path = resolved.archive_path;
	let workload_name = resolved.name;
	let workload_version = resolved.version;

	// Collect unmeasured-data files: --unmeasured-data-dir takes precedence over workload dir.
	let unmeasured_tar = if !resolved.unmeasured_data.is_empty() {
		let base_dir = args.unmeasured_data_dir.as_ref()
			.or(resolved.workload_dir.as_ref());
		if let Some(dir) = base_dir {
			collect_unmeasured_tar(&resolved.unmeasured_data, dir)?
		} else {
			eprintln!(
				"  {}: workload declares unmeasured-data but no source directory available; \
				 use --unmeasured-data-dir to provide one",
				"warning".yellow(),
			);
			None
		}
	} else {
		None
	};

	// 4. Compute archive hash.
	let bytes = std::fs::read(&archive_path)
		.map_err(|e| anyhow::anyhow!("failed to read archive {}: {e}", archive_path.display()))?;
	let archive_hash = format!("{:x}", Sha256::digest(&bytes));

	// 5. Resolve init env: CLI > persisted state > target config.
	// Look up the target to use its defaults for missing CLI args.
	let target = config
		.cloud
		.targets
		.get(&target_name)
		.ok_or_else(|| anyhow::anyhow!("target '{target_name}' not found in config"))?;

	let resolver = InitEnvResolver {
		cli_chain: args.chain.as_deref(),
		cli_owner_key: args.owner_key.as_deref(),
		cli_gas_wallet: args.gas_wallet.as_deref(),
		target,
	};

	// Use persisted state as intermediate fallback: if CLI didn't override,
	// check the persisted init_env before falling back to target defaults.
	let chain_name = args.chain.as_deref()
		.map(String::from)
		.or_else(|| if !state.init_env.chain.is_empty() { Some(state.init_env.chain.clone()) } else { None })
		.unwrap_or_else(|| resolver.chain());
	let owner_key_name = args.owner_key.as_deref()
		.map(String::from)
		.or_else(|| if !state.init_env.owner_key.is_empty() { Some(state.init_env.owner_key.clone()) } else { None })
		.unwrap_or_else(|| resolver.owner_key());
	let gas_wallet_name = args.gas_wallet.as_deref()
		.map(String::from)
		.or_else(|| if !state.init_env.gas_wallet.is_empty() { Some(state.init_env.gas_wallet.clone()) } else { None })
		.unwrap_or_else(|| resolver.gas_wallet());

	// Resolve chain config.
	let chain = config.chains.get(&chain_name)
		.ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in [chains]"))?;

	// Resolve key specs.
	let owner_key_spec = config.keys.get(&owner_key_name)
		.ok_or_else(|| anyhow::anyhow!("key '{owner_key_name}' not found in [keys]"))?;
	let gas_wallet_spec = config.keys.get(&gas_wallet_name)
		.ok_or_else(|| anyhow::anyhow!("key '{gas_wallet_name}' not found in [keys]"))?;

	// Resolve provider platform for the InitConfig.
	let provider_config = config
		.cloud
		.providers
		.get(&target.provider)
		.ok_or_else(|| anyhow::anyhow!("provider '{}' not found in [cloud.providers]", target.provider))?;

	let init_config = InitConfig {
		platform: provider_config.platform,
		chain: InitChainConfig {
			rpc_url: chain.rpc_url.clone(),
			session_registry: chain.session_registry.clone(),
			workload_registry: chain.workload_registry.clone()
				.ok_or_else(|| anyhow::anyhow!("workload_registry required in chain '{chain_name}'"))?,
			base_image_registry: chain.base_image_registry.clone()
				.ok_or_else(|| anyhow::anyhow!("base_image_registry required in chain '{chain_name}'"))?,
			session_ttl_seconds: chain.session_ttl_seconds,
		},
		owner_key: InitKeyConfig {
			mode: owner_key_spec.mode.to_string(),
			key_type: owner_key_spec.key_type.to_string(),
			private_key: Some(owner_key_spec.resolve(&owner_key_name)?),
		},
		gas_wallet: InitKeyConfig {
			mode: gas_wallet_spec.mode.to_string(),
			key_type: gas_wallet_spec.key_type.to_string(),
			private_key: if gas_wallet_spec.mode == KeyMode::Provisioned {
				Some(gas_wallet_spec.resolve(&gas_wallet_name)?)
			} else {
				None
			},
		},
	};

	// 6. Show plan and confirm.
	eprintln!("{}", "Plan:".dimmed());
	eprintln!("  1. Wait for CVM portal");
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

	// 7. Wait for portal.
	eprint!("  [1/2] Wait for CVM portal... ");
	init::wait_for_portal(&ip, args.timeout).await
		.map_err(|e| anyhow::anyhow!("{e}"))?;
	eprintln!("{}", "done".green());

	// 8. Initialize workload.
	eprint!("  [2/2] Initialize workload... ");
	init::post_portal_init(&ip, &archive_path.display().to_string(), unmeasured_tar.as_deref(), &init_config).await
		.map_err(|e| anyhow::anyhow!("{e}"))?;
	eprintln!("{}", "done".green());

	// 9. Update state.
	state.workload_name = workload_name.clone();
	state.workload_version = workload_version.clone();
	state.archive_path = archive_path.display().to_string();
	state.archive_hash = archive_hash;
	state.init_env = atakit_cloud::PersistedInitEnv {
		chain: chain_name,
		owner_key: owner_key_name,
		gas_wallet: gas_wallet_name,
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
