use std::collections::BTreeMap;

use anyhow::{bail, Result};
use atakit_cloud::cli::InitArgs;
use atakit_cloud::init::{self, InitConfig, PortalTerminalState};
use atakit_cloud::session::{self, TrustedWorkloadSessionPolicy};
use atakit_cloud::state::{DeployState, DeployStatus, PortalPorts};
use atakit_cloud::{PlatformKind, ProcessRunner};
use atakit_config::{KeyMode, KeyType, TransactionSubmitter};
use atakit_core::Env;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use super::{
    effective_prover_credential, init_chain_from_config, init_key_from_config, portal_endpoints,
    registration_is_off, resolve_instance, resolve_tls_measurement_policy, resolve_unmeasured_tar,
    resolve_workload, synthesize_off_init_chain, synthesize_self_generated_key, InitEnvResolver,
};
use crate::config::Config;
use crate::progress::IndicatifReporter;

pub async fn run(args: InitArgs, env: &Env, config: &Config) -> Result<()> {
    // 1. Resolve instance.
    let (target_name, instance_name) =
        resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;

    // 2. Load state and verify status.
    let mut state = DeployState::load(&env.data_dir, &target_name, &instance_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    match &state.status {
        DeployStatus::Deployed { ip } => {
            if ip.is_empty() {
                bail!("deployment {target_name}/{instance_name} has no external IP");
            }
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
    }
    let (portal_host, status_port, init_port) = portal_endpoints(&state)?;

    // 3. Resolve workload.
    let resolved = resolve_workload(&args.source, &args.dir, env, args.skip_freshness_check)?;
    let archive_path = resolved.archive_path;
    let workload_name = resolved.name;
    let workload_version = resolved.version;
    let workload_ports = resolved.ports;

    // Collect unmeasured-data files. Explicit root flags take precedence over
    // the default <workload-dir>/unmeasured-data root.
    let unmeasured_root = super::effective_unmeasured_data_root(
        args.unmeasured_data_root.as_ref(),
        args.unmeasured_data_dir.as_ref(),
        resolved.workload_dir.as_ref(),
    )?;
    let unmeasured_tar =
        resolve_unmeasured_tar(&resolved.unmeasured_data_paths, unmeasured_root.as_ref())?;

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
                "chain must be set on target, in saved init env, or via --chain when /init is sent \
                 (set registration = \"off\" on the target to disable on-chain registration)"
            )
        }
    };

    // Resolve init keys. Active registration requires an owner-key reference.
    // Owner/gas/sp1 can be provisioned keys supplied by a relay/prover
    // operator or self-generated ephemeral keys.
    let registration_off = registration_is_off(registration);
    let cli_submits =
        !registration_off && init_chain.transaction_submitter == TransactionSubmitter::AtakitCli;
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
    // Resolve an external signer only when the chain profile explicitly gives
    // transaction submission to atakit-cli. atakit-portal is the default.
    let external_gas_signer = if !cli_submits {
        None
    } else {
        let name = gas_wallet_name.as_deref().ok_or_else(|| {
            anyhow::anyhow!("gas_wallet must be set for external session registration")
        })?;
        let spec = config
            .keys
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("key '{name}' not found in [keys]"))?;
        if spec.key_type != KeyType::Es256k || spec.mode != KeyMode::Provisioned {
            bail!("gas wallet '{name}' must be a provisioned es256k key");
        }
        let private_key = gas_init.private_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("gas wallet '{name}' did not resolve to a private key")
        })?;
        Some(super::register::parse_gas_wallet_private_key(
            name,
            private_key,
        )?)
    };
    let gas_wallet_name_ref = gas_wallet_name.as_deref().unwrap_or_default();
    // Resolve with the same precedence as deploy. A selected chain profile
    // wins over persisted/target fallback, including under --chain recovery.
    let fallback_credential = state
        .init_env
        .sp1_payer
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| resolver.prover_credential());
    let sp1_payer_name = effective_prover_credential(
        config,
        chain_name.as_deref(),
        fallback_credential,
        gas_wallet_name.clone(),
        registration_off,
    );
    let sp1_payer_name_ref = sp1_payer_name.as_deref().unwrap_or(gas_wallet_name_ref);
    let prover_init = if registration_off {
        synthesize_self_generated_key()
    } else {
        match sp1_payer_name.as_deref() {
            Some(name) => match config.keys.get(name) {
                Some(spec) => init_key_from_config(name, spec, false)?,
                None => bail!("key '{sp1_payer_name_ref}' not found in [keys]"),
            },
            None => synthesize_self_generated_key(),
        }
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
    let verify_offchain_session =
        registration_off && !matches!(provider_config.platform, atakit_cloud::PlatformKind::Qemu);
    let reconcile_gcp_firewall = matches!(provider_config.platform, PlatformKind::Gcp);
    if registration_off
        && args.unsafe_skip_tls_attestation
        && !matches!(provider_config.platform, atakit_cloud::PlatformKind::Qemu)
    {
        bail!(
            "registration-off initialization requires full TLS attestation so the current session can be verified off-chain; remove --unsafe-skip-tls-attestation"
        );
    }

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
        owner_operations: config.owner_operations.clone(),
        owner_key: owner_init,
        gas_wallet: gas_init,
        prover_credential: prover_init,
        disks: disk_passphrases,
    };

    // 6. Show plan and confirm.
    eprintln!("{}", "Plan:".dimmed());
    if reconcile_gcp_firewall {
        eprintln!("  1. Open the workload ports on the existing firewall");
        eprintln!("  2. Wait for CVM portal");
        eprintln!("  3. Initialize workload");
    } else {
        eprintln!("  1. Wait for CVM portal");
        eprintln!("  2. Initialize workload");
    }
    if !registration_off {
        let owner = if cli_submits {
            "atakit-cli"
        } else {
            "atakit-portal"
        };
        eprintln!(
            "  {}. Wait for session registration by {owner}",
            if reconcile_gcp_firewall { 4 } else { 3 }
        );
    } else if verify_offchain_session {
        eprintln!(
            "  {}. Verify the local-bound session evidence off-chain",
            if reconcile_gcp_firewall { 4 } else { 3 }
        );
    }
    eprintln!();
    eprintln!("{}", "Configuration:".dimmed());
    eprintln!(
        "  {:<18}{}",
        "Instance:".dimmed(),
        format!("{target_name}/{instance_name}").bold()
    );
    eprintln!("  {:<18}{}", "IP:".dimmed(), portal_host);
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
    let mut step_count = if verify_offchain_session || !registration_off {
        4
    } else {
        3
    };
    if reconcile_gcp_firewall {
        step_count += 1;
    }
    let mut step = 1;
    if reconcile_gcp_firewall {
        eprint!("  [{step}/{step_count}] Update firewall... ");
        let gcp = state.resources.gcp.as_ref().ok_or_else(|| {
            anyhow::anyhow!("deployment has no saved GCP resources for firewall update")
        })?;
        let rule = gcp
            .firewall_rule
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("deployment has no saved GCP firewall rule"))?;
        let mut ports = state.portal_ports.firewall_entries();
        for port in &workload_ports {
            if PortalPorts::is_default_portal_entry(port) || ports.contains(port) {
                continue;
            }
            ports.push(port.clone());
        }
        atakit_cloud::gcp::firewall::update_firewall(
            &gcp.project,
            rule,
            &ports,
            &ProcessRunner::default(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        eprintln!("{}", "done".green());
        step += 1;
    }
    eprint!("  [{step}/{step_count}] Wait for CVM portal... ");
    init::wait_for_portal(&portal_host, status_port, args.timeout)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("{}", "done".green());
    step += 1;

    eprint!("  [{step}/{step_count}] Verify portal TLS... ");
    let verified_tls = if args.unsafe_skip_tls_attestation {
        eprintln!("{}", "unsafe bypass".yellow());
        super::warn_unsafe_skip_tls_attestation();
        None
    } else {
        let measurement_policy = resolve_tls_measurement_policy(
            args.measurements.as_deref(),
            args.base_image.as_deref(),
            &args.measurement_publisher_key,
            &env.data_dir,
            &init_config.chain,
        )
        .await?;
        let tls_trust_anchors = init::load_tls_trust_anchors(
            &args.gcp_ak_root_cert,
            &args.azure_maa_key,
            &args.amd_ark_root_cert,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let tdx_dcap_collateral = init::tdx_dcap_collateral_config(
            args.tdx_dcap_collateral.clone(),
            args.tdx_dcap_pccs_url.clone(),
            args.tdx_dcap_automata_collateral_rpc_url.clone(),
            args.tdx_dcap_automata_pcs_dao.clone(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let verified_tls = init::bootstrap_portal_tls_with_trust_config(
            &portal_host,
            status_port,
            measurement_policy,
            tls_trust_anchors,
            init::azure_maa_trust_config_from_init_chain(&init_config.chain),
            tdx_dcap_collateral,
            args.trust_tls_cert_sha256.as_deref(),
            Some(&init::cloud_tls_attestation_report_path(
                &env.data_dir,
                &target_name,
                &instance_name,
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
    step += 1;
    let portal_client = match &verified_tls {
        Some(verified) => verified.client.clone(),
        None => init::unsafe_portal_client(std::time::Duration::from_secs(300))
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    };

    // 8. Initialize workload.
    eprintln!("  [{step}/{step_count}] Initialize workload...");
    init::post_portal_init_with_client(
        &portal_client,
        &portal_host,
        init_port,
        &archive_path.display().to_string(),
        unmeasured_tar.as_deref(),
        &init_config,
        std::time::Duration::from_secs(args.init_upload_timeout),
        &IndicatifReporter,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("  {}", "done".green());
    step += 1;

    // 9. Save recovery inputs before the external transaction. If the CLI is
    // interrupted after /init, `cloud register` can safely resume.
    state.workload_name = workload_name.clone();
    state.workload_version = workload_version.clone();
    state.archive_path = archive_path.display().to_string();
    state.archive_hash = archive_hash;
    state.init_env = atakit_cloud::PersistedInitEnv {
        chain: chain_name.clone().unwrap_or_default(),
        owner_key: owner_key_name.unwrap_or_default(),
        gas_wallet: gas_wallet_name.unwrap_or_default(),
        sp1_payer: sp1_payer_name,
    };
    state
        .save(&env.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if verify_offchain_session {
        match init::wait_for_portal_terminal_with_client(
            &portal_client,
            &portal_host,
            status_port,
            args.timeout,
            |state| eprintln!("      state: {state}"),
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?
        {
            PortalTerminalState::Running => {}
            PortalTerminalState::Failed { detail } | PortalTerminalState::CleanHalt { detail } => {
                bail!("portal did not reach Running: {detail}")
            }
        }

        eprint!("  [{step}/{step_count}] Verify current session... ");
        let verified_tls = verified_tls.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "off-chain session verification requires full TLS attestation; remove --unsafe-skip-tls-attestation"
            )
        })?;
        let workload_id =
            crate::commands::workload::compute_workload_id(&workload_name, &workload_version);
        let verified = session::verify_current_session(
            verified_tls,
            &portal_host,
            status_port,
            TrustedWorkloadSessionPolicy {
                workload_id: workload_id.0,
                attribute_requirements: Vec::new(),
            },
            Some(atakit_attestation::BindingMode::Local),
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        let report_path =
            super::verify_session::session_report_path(&env.data_dir, &target_name, &instance_name);
        if let Some(parent) = report_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&report_path, serde_json::to_vec_pretty(&verified)?)?;
        eprintln!("{}", "done".green());
        eprintln!("      session: 0x{}", hex::encode(verified.session_id));
        eprintln!("      report:  {}", report_path.display());
    }

    // 10. atakit-cli submission is an explicit compatibility path.
    if let Some(signer) = external_gas_signer {
        eprint!("  [{step}/{step_count}] Register session... ");
        let chain_name = chain_name
            .as_deref()
            .expect("active registration resolved a chain name");
        let chain = config
            .chains
            .get(chain_name)
            .expect("active registration resolved a chain config");
        let result = super::register::submit_prepared_registration(
            &portal_client,
            &portal_host,
            status_port,
            chain,
            signer,
            args.timeout,
        )
        .await?;
        match result {
            super::register::RegistrationResult::LocalFallback { session_id } => {
                eprintln!(
                    "{} ({session_id})",
                    "local fallback; no transaction".yellow()
                );
            }
            super::register::RegistrationResult::AlreadyActive { session_id } => {
                eprintln!("{} ({session_id})", "already active".green());
            }
            super::register::RegistrationResult::Submitted {
                session_id,
                tx_hash,
            } => {
                eprintln!("{}", "confirmed".green());
                eprintln!("      Session: {session_id}");
                eprintln!("      Tx:      {tx_hash}");
            }
        }
        match init::wait_for_portal_terminal_with_client(
            &portal_client,
            &portal_host,
            status_port,
            args.timeout,
            |state| eprintln!("      state: {state}"),
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?
        {
            PortalTerminalState::Running => {}
            PortalTerminalState::Failed { detail } | PortalTerminalState::CleanHalt { detail } => {
                bail!("portal did not reach Running: {detail}")
            }
        }
    }

    if !registration_off && !cli_submits {
        match init::wait_for_portal_terminal_with_client(
            &portal_client,
            &portal_host,
            status_port,
            args.timeout,
            |state| eprintln!("      state: {state}"),
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?
        {
            PortalTerminalState::Running => {}
            PortalTerminalState::Failed { detail } | PortalTerminalState::CleanHalt { detail } => {
                bail!("portal did not reach Running: {detail}")
            }
        }
    }

    // 11. Summary.
    eprintln!();
    eprintln!("{}", "==> Workload initialized!".green().bold());
    eprintln!();
    eprintln!(
        "    {:<12}{}",
        "Instance:".dimmed(),
        format!("{target_name}/{instance_name}").bold()
    );
    eprintln!("    {:<12}{}", "IP:".dimmed(), portal_host);
    eprintln!(
        "    {:<12}{}:{}",
        "Workload:".dimmed(),
        workload_name,
        workload_version
    );
    eprintln!();

    Ok(())
}
