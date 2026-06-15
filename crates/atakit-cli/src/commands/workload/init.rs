use std::collections::BTreeMap;

use anyhow::{bail, Result};
use atakit_cloud::init::{self, InitConfig};
use atakit_core::Env;
use atakit_workload::cli::InitArgs;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::commands::cloud::{
    init_chain_from_config, init_key_from_config, registration_is_off, resolve_unmeasured_tar,
    resolve_workload, synthesize_off_init_chain, synthesize_self_generated_key,
};
use crate::config::Config;

pub async fn run(args: InitArgs, env: &Env, config: &Config) -> Result<()> {
    // 1. Parse address into (host, init_port). Default port 1024; status = init + 1000.
    let (host, init_port) = parse_address(&args.address)?;
    let status_port = init_port
        .checked_add(1000)
        .ok_or_else(|| anyhow::anyhow!("init port {init_port} + 1000 overflows u16"))?;

    // 2. Resolve workload.
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

    // 3. Compute archive hash (display-only).
    let bytes = std::fs::read(&archive_path)
        .map_err(|e| anyhow::anyhow!("failed to read archive {}: {e}", archive_path.display()))?;
    let archive_hash = format!("{:x}", Sha256::digest(&bytes));

    // 4. Resolve init env. No target available, so fall back to [cloud.defaults] only.
    let defaults = &config.cloud.defaults;
    let chain_name = args.chain.clone().or_else(|| defaults.chain.clone());
    let owner_key_name = args
        .owner_key
        .clone()
        .or_else(|| defaults.owner_key.clone());
    let gas_wallet_name = args
        .gas_wallet
        .clone()
        .or_else(|| defaults.gas_wallet.clone());

    let registration = defaults.registration.as_deref();
    let init_chain = match chain_name.as_deref() {
        Some(name) => match config.chains.get(name) {
            Some(chain) => init_chain_from_config(name, chain, registration).await?,
            None if registration_is_off(registration) => synthesize_off_init_chain(),
            None => bail!("chain '{name}' not found in [chains]"),
        },
        None if registration_is_off(registration) => synthesize_off_init_chain(),
        None => {
            bail!(
                "chain required: pass --chain or set [cloud.defaults] chain \
                 (or set [cloud.defaults] registration = \"off\" to disable on-chain registration)"
            )
        }
    };
    let registration_off = registration_is_off(registration);
    let owner_init = match owner_key_name.as_deref() {
        Some(name) => match config.keys.get(name) {
            Some(spec) => init_key_from_config(name, spec, false)?,
            None if registration_off => synthesize_self_generated_key(),
            None => bail!("key '{name}' not found in [keys]"),
        },
        None if registration_off => synthesize_self_generated_key(),
        None => bail!("owner key required: pass --owner-key or set [cloud.defaults] owner_key"),
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
    // SP1 prover-network key: `[cloud.defaults] sp1_payer` if set, else default
    // to the gas-wallet key. Missing gas/sp1 synthesizes an ephemeral
    // self-generated key; configured provisioned keys are also valid.
    let sp1_payer_name = defaults
        .sp1_payer
        .clone()
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

    // Validate operator-supplied disk passphrases against what the workload
    // manifest declares (unknown / orphan / missing disks).
    let declared: BTreeMap<String, Vec<String>> = resolved
        .disks
        .iter()
        .map(|(name, (_, _, methods))| (name.clone(), methods.clone()))
        .collect();
    let disk_passphrases = init::parse_disk_passphrases(&args.disk_passphrase, &declared)?;

    let init_config = InitConfig {
        platform: args.platform.clone(),
        chain: init_chain,
        owner_key: owner_init,
        gas_wallet: gas_init,
        sp1_payer: sp1_init,
        disks: disk_passphrases,
    };

    // 5. Show plan and confirm.
    eprintln!("{}", "Plan:".dimmed());
    eprintln!("  1. Wait for CVM portal");
    eprintln!("  2. Initialize workload");
    eprintln!();
    eprintln!("{}", "Configuration:".dimmed());
    eprintln!("  {:<18}{}", "Host:".dimmed(), host.bold());
    eprintln!(
        "  {:<18}{} (init), {} (status)",
        "Ports:".dimmed(),
        init_port,
        status_port
    );
    eprintln!("  {:<18}{}", "Platform:".dimmed(), args.platform);
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

    // 6. Wait for portal.
    eprint!("  [1/2] Wait for CVM portal... ");
    init::wait_for_portal(&host, status_port, args.timeout)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("{}", "done".green());

    // 7. Initialize workload.
    eprint!("  [2/2] Initialize workload... ");
    init::post_portal_init(
        &host,
        init_port,
        &archive_path.display().to_string(),
        unmeasured_tar.as_deref(),
        &init_config,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("{}", "done".green());

    // 8. Summary.
    eprintln!();
    eprintln!("{}", "==> Workload initialized!".green().bold());
    eprintln!();
    eprintln!("    {:<12}{}:{}", "Portal:".dimmed(), host, init_port);
    eprintln!(
        "    {:<12}{}:{}",
        "Workload:".dimmed(),
        workload_name,
        workload_version
    );
    eprintln!();

    Ok(())
}

/// Parse `host` or `host:port` into `(host, port)`. Default port is 1024.
fn parse_address(s: &str) -> Result<(String, u16)> {
    if s.is_empty() {
        bail!("address cannot be empty");
    }
    match s.split_once(':') {
        None => Ok((s.to_string(), 1024)),
        Some((host, port_str)) => {
            if host.is_empty() {
                bail!("host cannot be empty in address '{s}'");
            }
            let port: u16 = port_str
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid port '{port_str}' in address '{s}': {e}"))?;
            Ok((host.to_string(), port))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_address_default_port() {
        let (host, port) = parse_address("127.0.0.1").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 1024);
    }

    #[test]
    fn parse_address_explicit_port() {
        let (host, port) = parse_address("localhost:5024").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 5024);
    }

    #[test]
    fn parse_address_rejects_empty() {
        assert!(parse_address("").is_err());
        assert!(parse_address(":1024").is_err());
    }

    #[test]
    fn parse_address_rejects_bad_port() {
        assert!(parse_address("host:notaport").is_err());
        assert!(parse_address("host:99999").is_err());
    }
}
