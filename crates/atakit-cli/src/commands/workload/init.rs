use anyhow::{bail, Result};
use atakit_cloud::init::{self, InitChainConfig, InitConfig, InitKeyConfig};
use atakit_core::Env;
use atakit_workload::cli::InitArgs;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::commands::cloud::{collect_unmeasured_tar, resolve_workload};
use crate::config::{Config, KeyMode};

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

    // Collect unmeasured-data files: --unmeasured-data-dir takes precedence over workload dir.
    let unmeasured_tar = if resolved.needs_unmeasured_data {
        let base_dir = args
            .unmeasured_data_dir
            .as_ref()
            .or(resolved.workload_dir.as_ref());
        if let Some(dir) = base_dir {
            if resolved.unmeasured_data_paths.is_empty() {
                eprintln!(
                    "  {}: workload needs unmeasured-data but no path list available; \
					 provide files in --unmeasured-data-dir",
                    "warning".yellow(),
                );
                None
            } else {
                collect_unmeasured_tar(&resolved.unmeasured_data_paths, dir)?
            }
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

    // 3. Compute archive hash (display-only).
    let bytes = std::fs::read(&archive_path)
        .map_err(|e| anyhow::anyhow!("failed to read archive {}: {e}", archive_path.display()))?;
    let archive_hash = format!("{:x}", Sha256::digest(&bytes));

    // 4. Resolve init env. No target available, so fall back to [cloud.defaults] only.
    let defaults = &config.cloud.defaults;
    let chain_name = args
        .chain
        .clone()
        .or_else(|| defaults.chain.clone())
        .ok_or_else(|| {
            anyhow::anyhow!("chain required: pass --chain or set [cloud.defaults] chain")
        })?;
    let owner_key_name = args
        .owner_key
        .clone()
        .or_else(|| defaults.owner_key.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "owner key required: pass --owner-key or set [cloud.defaults] owner_key"
            )
        })?;
    let gas_wallet_name = args
        .gas_wallet
        .clone()
        .or_else(|| defaults.gas_wallet.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "gas wallet required: pass --gas-wallet or set [cloud.defaults] gas_wallet"
            )
        })?;

    let chain = config
        .chains
        .get(&chain_name)
        .ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in [chains]"))?;
    let owner_key_spec = config
        .keys
        .get(&owner_key_name)
        .ok_or_else(|| anyhow::anyhow!("key '{owner_key_name}' not found in [keys]"))?;
    let gas_wallet_spec = config
        .keys
        .get(&gas_wallet_name)
        .ok_or_else(|| anyhow::anyhow!("key '{gas_wallet_name}' not found in [keys]"))?;

    let init_config = InitConfig {
        platform: args.platform.clone(),
        chain: InitChainConfig {
            rpc_url: chain.rpc_url.clone(),
            session_registry: chain.session_registry.clone(),
            workload_registry: chain.workload_registry.clone().ok_or_else(|| {
                anyhow::anyhow!("workload_registry required in chain '{chain_name}'")
            })?,
            base_image_registry: chain.base_image_registry.clone().ok_or_else(|| {
                anyhow::anyhow!("base_image_registry required in chain '{chain_name}'")
            })?,
            expire_offset: chain.expire_offset,
            registration: chain.registration.clone(),
            chain_id: chain.chain_id,
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
