use std::collections::BTreeMap;

use anyhow::{bail, Result};
use atakit_cloud::cli::InitArgs;
use atakit_cloud::init::{self, InitConfig};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_core::Env;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use super::{
    init_chain_from_config, init_key_from_config, registration_is_off, resolve_instance,
    resolve_unmeasured_tar, resolve_workload, synthesize_off_init_chain,
    synthesize_self_generated_key, InitEnvResolver,
};
use crate::config::Config;

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

    // Collect unmeasured-data files: --unmeasured-data-dir takes precedence over
    // workload dir. Errors if the manifest declares paths but none are available.
    let unmeasured_tar = resolve_unmeasured_tar(
        &resolved.unmeasured_data_paths,
        args.unmeasured_data_dir.as_ref(),
        resolved.workload_dir.as_ref(),
    )?;

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
    let chain_name = args
        .chain
        .as_deref()
        .map(String::from)
        .or_else(|| {
            if !state.init_env.chain.is_empty() {
                Some(state.init_env.chain.clone())
            } else {
                None
            }
        })
        .or_else(|| resolver.chain_optional());
    let owner_key_name = args
        .owner_key
        .as_deref()
        .map(String::from)
        .or_else(|| {
            if !state.init_env.owner_key.is_empty() {
                Some(state.init_env.owner_key.clone())
            } else {
                None
            }
        })
        .or_else(|| {
            resolver
                .target
                .owner_key
                .clone()
                .filter(|value| !value.is_empty())
        });
    let gas_wallet_name = args
        .gas_wallet
        .as_deref()
        .map(String::from)
        .or_else(|| {
            if !state.init_env.gas_wallet.is_empty() {
                Some(state.init_env.gas_wallet.clone())
            } else {
                None
            }
        })
        .or_else(|| {
            resolver
                .target
                .gas_wallet
                .clone()
                .filter(|value| !value.is_empty())
        });

    // Resolve chain config. Registration is target-owned. When it is off,
    // /init has no chain interaction and can omit chain entirely.
    let registration = target.registration.as_deref();
    let init_chain = match chain_name.as_deref() {
        Some(name) => match config.chains.get(name) {
            Some(chain) => init_chain_from_config(name, chain, registration)?,
            None if registration_is_off(registration) => synthesize_off_init_chain(),
            None => bail!("chain '{name}' not found in [chains]"),
        },
        None if registration_is_off(registration) => synthesize_off_init_chain(),
        None => {
            bail!(
                "chain must be set on target, in saved init env, or via --chain when /init is sent \
                 (set registration = \"off\" on the target to disable on-chain registration)"
            )
        }
    };

    // Resolve init keys. Active registration requires an owner-key reference.
    // Owner/gas/sp1 can be provisioned keys supplied by a relay/prover
    // operator or self-generated ephemeral keys.
    let registration_off = registration_is_off(registration);
    let owner_init = match owner_key_name.as_deref() {
        Some(name) if config.keys.contains_key(name) => {
            init_key_from_config(name, &config.keys[name], false)?
        }
        Some(_) if registration_off => synthesize_self_generated_key(),
        Some(name) => bail!("key '{name}' not found in [keys]"),
        None if registration_off => synthesize_self_generated_key(),
        None => bail!("owner_key must be set on target or via --owner-key"),
    };
    let gas_init = match gas_wallet_name.as_deref() {
        Some(name) => match config.keys.get(name) {
            Some(spec) => init_key_from_config(name, spec, false)?,
            None if registration_off => synthesize_self_generated_key(),
            None => bail!("key '{name}' not found in [keys]"),
        },
        None => synthesize_self_generated_key(),
    };
    let gas_wallet_name_ref = gas_wallet_name.as_deref().unwrap_or_default();
    // SP1 prover-network key: state override > target config > default to the
    // gas-wallet key. Missing gas/sp1 synthesizes an ephemeral self-generated
    // key; configured provisioned keys are also valid.
    let sp1_payer_name = state
        .init_env
        .sp1_payer
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| resolver.sp1_payer())
        .or_else(|| gas_wallet_name.clone());
    let sp1_payer_name_ref = sp1_payer_name.as_deref().unwrap_or(gas_wallet_name_ref);
    let sp1_init = match sp1_payer_name.as_deref() {
        Some(name) => match config.keys.get(name) {
            Some(spec) => init_key_from_config(name, spec, false)?,
            None if registration_off => synthesize_self_generated_key(),
            None => bail!("key '{sp1_payer_name_ref}' not found in [keys]"),
        },
        None => synthesize_self_generated_key(),
    };

    // Resolve provider platform for the InitConfig.
    let provider_config = config
        .cloud
        .providers
        .get(&target.provider)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider '{}' not found in [cloud.providers]",
                target.provider
            )
        })?;

    // Validate operator-supplied disk passphrases against what the workload
    // manifest declares (unknown / orphan / missing disks) before touching
    // the portal.
    let declared: BTreeMap<String, Vec<String>> = resolved
        .disks
        .iter()
        .map(|(name, (_, _, methods))| (name.clone(), methods.clone()))
        .collect();
    let disk_passphrases = init::parse_disk_passphrases(&args.disk_passphrase, &declared)?;

    let init_config = InitConfig {
        platform: provider_config.platform.to_string(),
        chain: init_chain,
        owner_key: owner_init,
        gas_wallet: gas_init,
        sp1_payer: sp1_init,
        disks: disk_passphrases,
    };

    // 6. Show plan and confirm.
    eprintln!("{}", "Plan:".dimmed());
    eprintln!("  1. Wait for CVM portal");
    eprintln!("  2. Initialize workload");
    eprintln!();
    eprintln!("{}", "Configuration:".dimmed());
    eprintln!(
        "  {:<18}{}",
        "Instance:".dimmed(),
        format!("{target_name}/{instance_name}").bold()
    );
    eprintln!("  {:<18}{}", "IP:".dimmed(), ip);
    eprintln!(
        "  {:<18}{}:{}",
        "Workload:".dimmed(),
        workload_name,
        workload_version
    );
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
    init::wait_for_portal(&ip, 2024, args.timeout)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("{}", "done".green());

    // 8. Initialize workload.
    eprint!("  [2/2] Initialize workload... ");
    init::post_portal_init(
        &ip,
        1024,
        &archive_path.display().to_string(),
        unmeasured_tar.as_deref(),
        &init_config,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("{}", "done".green());

    // 9. Update state.
    state.workload_name = workload_name.clone();
    state.workload_version = workload_version.clone();
    state.archive_path = archive_path.display().to_string();
    state.archive_hash = archive_hash;
    state.init_env = atakit_cloud::PersistedInitEnv {
        chain: chain_name.unwrap_or_default(),
        owner_key: owner_key_name.unwrap_or_default(),
        gas_wallet: gas_wallet_name.unwrap_or_default(),
        sp1_payer: sp1_payer_name,
    };
    state
        .save(&env.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // 10. Summary.
    eprintln!();
    eprintln!("{}", "==> Workload initialized!".green().bold());
    eprintln!();
    eprintln!(
        "    {:<12}{}",
        "Instance:".dimmed(),
        format!("{target_name}/{instance_name}").bold()
    );
    eprintln!("    {:<12}{}", "IP:".dimmed(), ip);
    eprintln!(
        "    {:<12}{}:{}",
        "Workload:".dimmed(),
        workload_name,
        workload_version
    );
    eprintln!();

    Ok(())
}
