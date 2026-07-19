use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use atakit_attestation::BindingMode;
use atakit_cloud::cli::VerifySessionArgs;
use atakit_cloud::init;
use atakit_cloud::session::{self, TrustedWorkloadSessionPolicy};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_core::Env;
use owo_colors::OwoColorize;

use super::{
    init_chain_from_config, portal_endpoints, registration_is_off, resolve_instance,
    resolve_tls_measurement_policy, synthesize_off_init_chain,
};
use crate::config::Config;

pub async fn run(args: VerifySessionArgs, env: &Env, config: &Config) -> Result<()> {
    let (target_name, instance_name) =
        resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;
    let state = DeployState::load(&env.data_dir, &target_name, &instance_name)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if !matches!(state.status, DeployStatus::Deployed { .. }) {
        bail!("deployment {target_name}/{instance_name} is not deployed");
    }
    if state.workload_name.is_empty() || state.workload_version.is_empty() {
        bail!("deployment {target_name}/{instance_name} has no initialized workload");
    }
    let target = config
        .cloud
        .targets
        .get(&target_name)
        .ok_or_else(|| anyhow::anyhow!("target '{target_name}' not found in config"))?;
    let (host, status_port, _) = portal_endpoints(&state)?;

    let chain_name = args
        .chain
        .as_deref()
        .or((!state.init_env.chain.is_empty()).then_some(state.init_env.chain.as_str()))
        .or(target.chain.as_deref());
    let init_chain = match chain_name {
        Some(name) => match config.chains.get(name) {
            Some(chain) => {
                let prover = chain
                    .prover
                    .as_ref()
                    .and_then(|prover| config.provers.get(prover));
                init_chain_from_config(name, chain, target.registration.as_deref(), prover).await?
            }
            None => bail!("chain '{name}' not found in [chains]"),
        },
        None if registration_is_off(target.registration.as_deref()) => synthesize_off_init_chain(),
        None => bail!("no chain config is available for verifier trust lookup"),
    };

    let base_image = args.base_image.as_deref().unwrap_or(&state.image_ref);
    let measurement_policy = resolve_tls_measurement_policy(
        args.measurements.as_deref(),
        Some(base_image),
        &args.measurement_publisher_key,
        &env.data_dir,
        &init_chain,
    )
    .await?;
    let trust_anchors = init::load_tls_trust_anchors(
        &args.gcp_ak_root_cert,
        &args.azure_maa_key,
        &args.amd_ark_root_cert,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let tdx_dcap = init::tdx_dcap_collateral_config(
        args.tdx_dcap_collateral,
        args.tdx_dcap_pccs_url,
        args.tdx_dcap_automata_collateral_rpc_url,
        args.tdx_dcap_automata_pcs_dao,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    eprint!("Verify portal TLS... ");
    let verified_tls = init::bootstrap_portal_tls_with_trust_config(
        &host,
        status_port,
        measurement_policy,
        trust_anchors,
        init::azure_maa_trust_config_from_init_chain(&init_chain),
        tdx_dcap,
        None,
        Some(&init::cloud_tls_attestation_report_path(
            &env.data_dir,
            &target_name,
            &instance_name,
        )),
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    eprintln!("{}", "done".green());

    let workload_id = crate::commands::workload::compute_workload_id(
        &state.workload_name,
        &state.workload_version,
    );
    let expected_binding =
        registration_is_off(target.registration.as_deref()).then_some(BindingMode::Local);
    eprint!("Verify current session... ");
    let verified = session::verify_current_session(
        &verified_tls,
        &host,
        status_port,
        TrustedWorkloadSessionPolicy {
            workload_id: workload_id.0,
            attribute_requirements: Vec::new(),
        },
        expected_binding,
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    eprintln!("{}", "done".green());

    let report_path = session_report_path(&env.data_dir, &target_name, &instance_name);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create report directory {}", parent.display()))?;
    }
    std::fs::write(&report_path, serde_json::to_vec_pretty(&verified)?)
        .with_context(|| format!("write session report {}", report_path.display()))?;

    println!();
    println!("{}", "==> Session verified off-chain".green().bold());
    println!("    Session:  0x{}", hex::encode(verified.session_id));
    println!("    Binding:  {:?}", verified.binding_mode);
    println!("    Checks:   {}", verified.checks.len());
    println!("    Report:   {}", report_path.display());
    Ok(())
}

pub(crate) fn session_report_path(
    data_dir: &std::path::Path,
    target_name: &str,
    instance_name: &str,
) -> PathBuf {
    data_dir
        .join("cloud")
        .join("deployments")
        .join(target_name)
        .join(format!("{instance_name}.session-verification-report.json"))
}
