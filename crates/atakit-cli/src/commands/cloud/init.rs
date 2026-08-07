use std::collections::BTreeMap;

use anyhow::{bail, Result};
use atakit_cloud::cli::InitArgs;
use atakit_cloud::init::{self, InitConfig, PortalTerminalState};
use atakit_cloud::state::{DeployState, DeployStatus, PortalPorts};
use atakit_cloud::{PlatformKind, ProcessRunner};
use atakit_core::Env;
use owo_colors::OwoColorize;

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

    require_deployed_for_init(&state, &target_name, &instance_name)?;
    let (portal_host, status_port, init_port) = portal_endpoints(&state)?;

    // 3. Resolve workload.
    let resolved = resolve_workload(&args.source, &args.dir, env, args.skip_freshness_check)?;
    let archive_path = resolved.archive_path;
    let archive_sha256 = resolved.archive_sha256;
    let workload_name = resolved.name;
    let workload_version = resolved.version;
    let workload_ports = resolved.ports;
    let workload_attributes = resolved.attributes;

    // Collect unmeasured-data files. Explicit root flags take precedence over
    // the default <workload-dir>/unmeasured-data root.
    let unmeasured_root = super::effective_unmeasured_data_root(
        args.unmeasured_data_root.as_ref(),
        args.unmeasured_data_dir.as_ref(),
        resolved.workload_dir.as_ref(),
    )?;
    let unmeasured_tar =
        resolve_unmeasured_tar(&resolved.unmeasured_data_paths, unmeasured_root.as_ref())?;

    // 4. Display and persist the hash of the exact archive snapshot inspected above.
    let archive_hash = hex::encode(archive_sha256);

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
    // Owner, gas-wallet, and prover keys can be provisioned or self-generated.
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
    // Resolve with the same precedence as deploy. A selected chain profile
    // wins over persisted/target fallback, including under --chain recovery.
    let fallback_credential = state
        .init_env
        .prover_credential
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| resolver.prover_credential());
    let prover_credential_name = effective_prover_credential(
        config,
        chain_name.as_deref(),
        fallback_credential,
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
    let reconcile_gcp_firewall = matches!(provider_config.platform, PlatformKind::Gcp);
    if registration_off
        && args.unsafe_skip_tls_attestation
        && !matches!(provider_config.platform, atakit_cloud::PlatformKind::Qemu)
    {
        bail!(
            "registration-off initialization requires full TLS attestation; remove --unsafe-skip-tls-attestation"
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

    let mut init_config = InitConfig {
        platform: provider_config.platform.to_string(),
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
        eprintln!(
            "  {}. Wait for session registration by atakit-portal",
            if reconcile_gcp_firewall { 4 } else { 3 }
        );
    } else {
        eprintln!(
            "  {}. Wait for the local-bound session and workload",
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

    // 7. Wait for portal.
    let mut step_count = 4;
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
    init::wait_for_portal(
        &portal_host,
        status_port,
        init::PORTAL_READINESS_TIMEOUT_SECONDS,
    )
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
        let untrusted_portal_base_image_id = if args.measurements.is_none() {
            Some(
                init::read_untrusted_portal_base_image_id(&portal_host, status_port)
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
            &args.azure_maa_cert,
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
            &portal_host,
            status_port,
            Some(measurement_policy),
            Some(workload_attributes),
            tls_verification_trust,
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
        None => init::unsafe_portal_client(std::time::Duration::from_secs(
            init::PORTAL_READINESS_TIMEOUT_SECONDS,
        ))
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    };
    init_config.pcr_policy = super::resolve_init_pcr_policy(
        args.pcr_policy.as_deref(),
        &init_config,
        registration_off,
        verified_tls.as_ref(),
        &workload_name,
        &workload_version,
    )
    .await?;

    // Save the workload identity and configuration references before the
    // one-shot POST /init. A process exit after the portal accepts /init must
    // not leave the deployment record describing the previous workload.
    state.workload_name = workload_name.clone();
    state.workload_version = workload_version.clone();
    state.archive_path = archive_path.display().to_string();
    state.archive_hash = archive_hash;
    if let Some(base_image_ref) = &args.base_image {
        state.base_image_ref = Some(base_image_ref.clone());
    }
    state.init_env = atakit_cloud::PersistedInitEnv {
        chain: chain_name.clone().unwrap_or_default(),
        owner_key: owner_key_name.unwrap_or_default(),
        gas_wallet: gas_wallet_name.unwrap_or_default(),
        prover_credential: prover_credential_name,
    };
    state
        .save(&env.data_dir)
        .map_err(|e| anyhow::anyhow!("save deployment state before POST /init: {e}"))?;

    // 8. Initialize workload.
    eprintln!("  [{step}/{step_count}] Initialize workload...");
    init::post_portal_init_with_client(
        &portal_client,
        &portal_host,
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
    step += 1;

    eprint!("  [{step}/{step_count}] Wait for portal Running... ");
    match init::wait_for_portal_terminal_with_client(
        &portal_client,
        &portal_host,
        status_port,
        initialization_timeout_secs,
        |state| eprintln!("      state: {state}"),
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?
    {
        PortalTerminalState::Running => eprintln!("{}", "done".green()),
        terminal @ PortalTerminalState::Failed { .. }
        | terminal @ PortalTerminalState::CleanHalt { .. } => {
            eprintln!("{}", "failed".red());
            let error = super::persist_portal_terminal_failure(
                &mut state,
                &env.data_dir,
                &target_name,
                &instance_name,
                terminal,
            )?;
            return Err(error);
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

fn require_deployed_for_init(
    state: &DeployState,
    target_name: &str,
    instance_name: &str,
) -> Result<()> {
    match &state.status {
        DeployStatus::Deployed { ip } if !ip.is_empty() => Ok(()),
        DeployStatus::Deployed { .. } => {
            bail!("deployment {target_name}/{instance_name} has no external IP")
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
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use atakit_cloud::{GcpResources, NewDeployParams, PersistedInitEnv};
    use tempfile::TempDir;

    use super::*;

    fn deployed_state() -> DeployState {
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "test-instance".into(),
            workload_name: "updated-workload".into(),
            workload_version: "v2".into(),
            target_name: "gcp-tdx".into(),
            provider_name: "gcp-provider".into(),
            platform: PlatformKind::Gcp,
            image_ref: "automata-linux:v2".into(),
            base_image_ref: Some("automata-linux:v2".into()),
            archive_path: "/tmp/updated-workload-v2.atawl".into(),
            archive_hash: "updated-hash".into(),
            init_env: PersistedInitEnv {
                chain: "hoodi-fork".into(),
                owner_key: "owner".into(),
                gas_wallet: "gas-wallet".into(),
                prover_credential: Some("prover".into()),
            },
            portal_ports: PortalPorts::default(),
            total_steps: 7,
        });
        state.status = DeployStatus::Deployed {
            ip: "192.0.2.10".into(),
        };
        state.resources.gcp = Some(GcpResources {
            project: "project".into(),
            zone: "asia-southeast1-b".into(),
            firewall_rule: Some("test-firewall".into()),
            instance: Some("test-instance".into()),
            external_ip: Some("192.0.2.10".into()),
            ..Default::default()
        });
        state
    }

    #[test]
    fn portal_failed_state_is_saved_without_losing_recovery_data() {
        let data_dir = TempDir::new().unwrap();
        let mut state = deployed_state();
        state.save(data_dir.path()).unwrap();

        let error = super::super::persist_portal_terminal_failure(
            &mut state,
            data_dir.path(),
            "gcp-tdx",
            "test-instance",
            PortalTerminalState::Failed {
                detail: "registration transaction reverted".into(),
            },
        )
        .unwrap();
        assert!(error
            .to_string()
            .contains("registration transaction reverted"));
        assert!(error.to_string().contains("atakit cloud destroy"));
        assert!(error.to_string().contains("atakit cloud deploy"));

        let loaded = DeployState::load(data_dir.path(), "gcp-tdx", "test-instance").unwrap();
        match &loaded.status {
            DeployStatus::Failed { step, message } => {
                assert_eq!(step, super::super::WAIT_FOR_PORTAL_RUNNING_STEP);
                assert!(message.contains("terminal Failed state"));
            }
            status => panic!("expected Failed deployment status, got {status:?}"),
        }
        assert_eq!(loaded.workload_name, "updated-workload");
        assert_eq!(loaded.workload_version, "v2");
        assert_eq!(loaded.archive_path, "/tmp/updated-workload-v2.atawl");
        assert_eq!(loaded.init_env.gas_wallet, "gas-wallet");
        let gcp = loaded.resources.gcp.as_ref().unwrap();
        assert_eq!(gcp.project, "project");
        assert_eq!(gcp.instance.as_deref(), Some("test-instance"));

        let retry_error = require_deployed_for_init(&loaded, "gcp-tdx", "test-instance")
            .unwrap_err()
            .to_string();
        assert!(retry_error.contains("instance is in failed state"));

        DeployState::delete(data_dir.path(), "gcp-tdx", "test-instance").unwrap();
        assert!(DeployState::load(data_dir.path(), "gcp-tdx", "test-instance").is_err());
    }

    #[test]
    fn empty_clean_halt_detail_is_saved_with_a_clean_halt_message() {
        let data_dir = TempDir::new().unwrap();
        let mut state = deployed_state();
        state.save(data_dir.path()).unwrap();

        super::super::persist_portal_terminal_failure(
            &mut state,
            data_dir.path(),
            "gcp-tdx",
            "test-instance",
            PortalTerminalState::CleanHalt {
                detail: String::new(),
            },
        )
        .unwrap();

        let loaded = DeployState::load(data_dir.path(), "gcp-tdx", "test-instance").unwrap();
        let DeployStatus::Failed { step, message } = loaded.status else {
            panic!("expected Failed deployment status");
        };
        assert_eq!(step, super::super::WAIT_FOR_PORTAL_RUNNING_STEP);
        assert!(message.contains("terminal CleanHalt state"));
        assert!(!message.contains("terminal Failed state"));
    }
}
