use std::collections::BTreeMap;

use anyhow::{bail, Result};
use atakit_cloud::init::{self, InitConfig, PortalTerminalState};
use atakit_core::Env;
use atakit_workload::cli::InitArgs;
use owo_colors::OwoColorize;

use crate::commands::cloud::{
    effective_prover_credential, init_chain_from_config, init_key_from_config, registration_is_off,
    resolve_init_pcr_policy, resolve_tls_measurement_policy, resolve_unmeasured_tar,
    resolve_workload, synthesize_off_init_chain, synthesize_self_generated_key,
};
use crate::config::Config;
use crate::progress::IndicatifReporter;

pub async fn run(args: InitArgs, env: &Env, config: &Config) -> Result<()> {
    // 1. Parse address into (host, init_port). Default port 1024; status = init + 1000.
    let (host, init_port) = parse_address(&args.address)?;
    let status_port = init_port
        .checked_add(1000)
        .ok_or_else(|| anyhow::anyhow!("init port {init_port} + 1000 overflows u16"))?;

    // 2. Resolve workload.
    let resolved = resolve_workload(&args.source, &args.dir, env, args.skip_freshness_check)?;
    let archive_path = resolved.archive_path;
    let archive_sha256 = resolved.archive_sha256;
    let workload_name = resolved.name;
    let workload_version = resolved.version;
    let workload_attributes = resolved.attributes;

    // Collect unmeasured-data files. Explicit root flags take precedence over
    // the default <workload-dir>/unmeasured-data root.
    let unmeasured_root = crate::commands::cloud::effective_unmeasured_data_root(
        args.unmeasured_data_root.as_ref(),
        args.unmeasured_data_dir.as_ref(),
        resolved.workload_dir.as_ref(),
    )?;
    let unmeasured_tar =
        resolve_unmeasured_tar(&resolved.unmeasured_data_paths, unmeasured_root.as_ref())?;

    // 3. Display the hash of the exact archive snapshot inspected above.
    let archive_hash = hex::encode(archive_sha256);

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
            Some(chain) => {
                let prover = chain
                    .prover
                    .as_ref()
                    .and_then(|name| config.provers.get(name));
                init_chain_from_config(name, chain, registration, prover).await?
            }
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
    // The prover credential must be separate from the gas wallet.
    let prover_credential_name = effective_prover_credential(
        config,
        chain_name.as_deref(),
        defaults.prover_credential.clone(),
        registration_off,
    )?;
    let prover_init = if registration_off {
        None
    } else {
        match prover_credential_name.as_deref() {
            Some(name) => match config.keys.get(name) {
                Some(spec) => Some(init_key_from_config(name, spec, false)?),
                None => bail!("key '{name}' not found in [keys]"),
            },
            None => None,
        }
    };

    // Validate operator-supplied disk passphrases against what the workload
    // manifest declares (unknown / orphan / missing disks).
    let declared: BTreeMap<String, Vec<String>> = resolved
        .disks
        .iter()
        .map(|(name, (_, _, methods))| (name.clone(), methods.clone()))
        .collect();
    let disk_passphrases = init::parse_disk_passphrases(&args.disk_passphrase, &declared)?;

    let mut init_config = InitConfig {
        platform: args.platform.clone(),
        chain: init_chain,
        owner_operations: config.owner_operations.clone(),
        owner_key: owner_init,
        gas_wallet: gas_init,
        prover_credential: prover_init,
        pcr_policy: None,
        disks: disk_passphrases,
    };
    if !registration_off && args.pcr_policy.is_some() {
        bail!("--pcr-policy requires effective chain registration = \"off\"");
    }
    let initialization_timeout_secs = init::initialization_timeout_seconds(
        args.init_timeout,
        init_config.owner_operations.op_expiry_seconds,
    );

    // 5. Show plan and confirm.
    eprintln!("{}", "Plan:".dimmed());
    eprintln!("  1. Wait for CVM portal");
    eprintln!("  2. Initialize workload");
    if !registration_off {
        eprintln!("  3. Wait for session registration by atakit-portal");
    } else {
        eprintln!("  3. Wait for portal Running");
    }
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
    eprintln!(
        "  {:<18}{}s",
        "Initialization timeout:".dimmed(),
        initialization_timeout_secs
    );
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
    let step_count = 4;
    eprint!("  [1/{step_count}] Wait for CVM portal... ");
    init::wait_for_portal(&host, status_port, init::PORTAL_READINESS_TIMEOUT_SECONDS)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("{}", "done".green());

    eprint!("  [2/{step_count}] Verify portal TLS... ");
    let verified_tls = if args.unsafe_skip_tls_attestation {
        eprintln!("{}", "unsafe bypass".yellow());
        crate::commands::cloud::warn_unsafe_skip_tls_attestation();
        None
    } else {
        let untrusted_portal_base_image_id = if args.measurements.is_none() {
            Some(
                init::read_untrusted_portal_base_image_id(&host, status_port)
                    .await
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
            )
        } else {
            None
        };
        let measurement_policy = resolve_tls_measurement_policy(
            args.measurements.as_deref(),
            args.base_image.as_deref(),
            untrusted_portal_base_image_id,
            &args.measurement_publisher_key,
            &env.data_dir,
            &init_config.chain,
        )
        .await?;
        let tls_verification_trust = init::load_tls_verification_trust(
            &args.gcp_ak_root_cert,
            &args.azure_maa_key,
            &args.amd_ark_root_cert,
            &args.amd_snp_crl,
            args.amd_snp_security_policy.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let automata_read_strategy = init::tdx_dcap_automata_read_strategy(
            &args.tdx_dcap_automata_read_strategy,
            args.tdx_dcap_automata_multicall3_address.clone(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let tdx_dcap_collateral = init::tdx_dcap_collateral_config_with_read_strategy(
            args.tdx_dcap_collateral.clone(),
            args.tdx_dcap_pccs_url.clone(),
            args.tdx_dcap_automata_collateral_rpc_url.clone(),
            args.tdx_dcap_automata_pcs_dao.clone(),
            automata_read_strategy,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let verified_tls = init::bootstrap_portal_tls_with_trust_config(
            &host,
            status_port,
            Some(measurement_policy),
            Some(workload_attributes),
            tls_verification_trust,
            init::azure_maa_trust_config_from_init_chain(&init_config.chain),
            tdx_dcap_collateral,
            args.trust_tls_cert_sha256.as_deref(),
            Some(&init::workload_tls_attestation_report_path(
                &env.cache_dir,
                &host,
                status_port,
            )),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Some(message) = init::tls_manual_override_message(&verified_tls) {
            eprintln!("{}", "overridden".yellow());
            eprintln!("{message}");
        } else {
            eprintln!("{}", "done".green());
        }
        Some(verified_tls)
    };
    let portal_client = match &verified_tls {
        Some(verified) => verified.client.clone(),
        None => init::unsafe_portal_client(std::time::Duration::from_secs(
            init::PORTAL_READINESS_TIMEOUT_SECONDS,
        ))
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    };
    init_config.pcr_policy = resolve_init_pcr_policy(
        args.pcr_policy.as_deref(),
        &init_config,
        registration_off,
        verified_tls.as_ref(),
        &workload_name,
        &workload_version,
    )
    .await?;

    // 7. Initialize workload.
    eprintln!("  [3/{step_count}] Initialize workload...");
    init::post_portal_init_with_client(
        &portal_client,
        &host,
        status_port,
        init_port,
        &archive_path.display().to_string(),
        &archive_sha256,
        unmeasured_tar.as_deref(),
        &init_config,
        std::time::Duration::from_secs(args.init_upload_timeout),
        &IndicatifReporter,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("  {}", "done".green());

    eprint!("  [4/{step_count}] Wait for portal Running... ");
    match init::wait_for_portal_terminal_with_client(
        &portal_client,
        &host,
        status_port,
        initialization_timeout_secs,
        |_| {},
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?
    {
        PortalTerminalState::Running => eprintln!("{}", "done".green()),
        PortalTerminalState::Failed { detail } | PortalTerminalState::CleanHalt { detail } => {
            bail!("portal did not reach Running: {detail}")
        }
    }

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
