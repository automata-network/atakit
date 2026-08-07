use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use atakit_attestation_client::{AttestationClient, TrustedWorkloadSessionPolicy};
use atakit_cloud::cli::VerifySessionArgs;
use atakit_cloud::init;
use atakit_cloud::session::{
    verify_portal_session, PortalSessionVerificationRequest, SessionWorkloadPolicySource,
};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::DEFAULT_PORTAL_STATUS_PORT;
use atakit_core::Env;
use owo_colors::OwoColorize;

use super::session_access::{connect_attestation_client, decode_hex_32, decode_hex_48};
use super::{resolve_instance, resolve_verifier_tls_measurement_policy, synthesize_off_init_chain};
use crate::config::Config;

struct VerificationSubject {
    host: String,
    status_port: u16,
    base_image_ref: String,
    workload_ref: String,
    report_path: PathBuf,
}

pub async fn run(args: VerifySessionArgs, env: &Env, config: &Config) -> Result<()> {
    let subject = resolve_subject(&args, env)?;
    let (init_chain, chain_client) = match args.verification.chain.as_deref() {
        Some(chain_name) => {
            let chain = config
                .chains
                .get(chain_name)
                .ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in config"))?;
            let client = connect_attestation_client(chain_name, chain).await?;
            let context = client.context();
            let init_chain = init::InitChainConfig {
                rpc_url: chain.rpc_url.clone(),
                session_registry: context.session_registry.clone(),
                workload_registry: context.workload_registry.clone(),
                base_image_registry: context.base_image_registry.clone(),
                registration: Some("required".to_string()),
                chain_id: Some(context.chain_id),
                tee_backend: chain.tee_backend.clone(),
                prover: None,
            };
            (init_chain, Some(client))
        }
        None => (synthesize_off_init_chain(), None),
    };

    let measurement_policy = resolve_verifier_tls_measurement_policy(
        args.verification.measurements.as_deref(),
        &subject.base_image_ref,
        &args.verification.measurement_publisher_key,
        &env.data_dir,
        chain_client.as_ref(),
    )
    .await?;
    let tls_verification_trust = init::load_tls_verification_trust(
        &args.verification.gcp_ak_root_cert,
        &args.verification.azure_maa_cert,
        &args.verification.amd_ark_root_cert,
        &args.verification.amd_snp_crl,
        args.verification.amd_snp_security_policy.as_deref(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let automata_read_strategy = init::tdx_dcap_automata_read_strategy(
        &args.verification.tdx_dcap_automata_read_strategy,
        args.verification
            .tdx_dcap_automata_multicall3_address
            .clone(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let tdx_dcap = init::tdx_dcap_collateral_config_with_read_strategy(
        args.verification.tdx_dcap_collateral.clone(),
        args.verification.tdx_dcap_pccs_url.clone(),
        args.verification
            .tdx_dcap_automata_collateral_rpc_url
            .clone(),
        args.verification.tdx_dcap_automata_pcs_dao.clone(),
        automata_read_strategy,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    let workload_policy = match (
        args.verification.trusted_workload_pcr23_sha256.as_deref(),
        args.verification.trusted_workload_pcr23_sha384.as_deref(),
    ) {
        (Some(sha256), Some(sha384)) => SessionWorkloadPolicySource::Explicit {
            policy: TrustedWorkloadSessionPolicy::from_manifest_pcr23(
                &subject.workload_ref,
                decode_hex_32(sha256, "--trusted-workload-pcr23-sha256")?,
                decode_hex_48(sha384, "--trusted-workload-pcr23-sha384")?,
            )?,
            trusted_binding: chain_client
                .as_ref()
                .map(AttestationClient::trusted_session_binding),
        },
        (None, None) => {
            let client = chain_client.ok_or_else(|| {
                anyhow::anyhow!(
                    "no trusted workload collateral is available; select a verifier chain with --chain or provide both --trusted-workload-pcr23-sha256 and --trusted-workload-pcr23-sha384"
                )
            })?;
            SessionWorkloadPolicySource::Registry {
                client,
                workload: subject.workload_ref.clone(),
            }
        }
        _ => bail!(
            "--trusted-workload-pcr23-sha256 and --trusted-workload-pcr23-sha384 must be supplied together"
        ),
    };

    eprint!("Verify portal TLS and current session... ");
    let verified = verify_portal_session(PortalSessionVerificationRequest {
        host: subject.host.clone(),
        status_port: subject.status_port,
        measurement_policy,
        tls_verification_trust,
        azure_maa_trust: init::azure_maa_trust_config_from_init_chain(&init_chain),
        tdx_dcap_collateral: tdx_dcap,
        report_path: None,
        workload_policy,
        required_binding: None,
    })
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?
    .session;
    eprintln!("{}", "done".green());

    if let Some(parent) = subject.report_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create report directory {}", parent.display()))?;
    }
    std::fs::write(&subject.report_path, serde_json::to_vec_pretty(&verified)?)
        .with_context(|| format!("write session report {}", subject.report_path.display()))?;

    println!();
    println!("{}", "==> Session verified off-chain".green().bold());
    println!("    Session:  0x{}", hex::encode(verified.session_id));
    println!("    Binding:  {:?}", verified.binding_mode);
    println!("    Checks:   {}", verified.checks.len());
    println!("    Report:   {}", subject.report_path.display());
    Ok(())
}

fn resolve_subject(args: &VerifySessionArgs, env: &Env) -> Result<VerificationSubject> {
    if args.instance.is_none() && args.target.is_some() {
        bail!("--target requires a local deployment instance");
    }
    let local = args
        .instance
        .as_deref()
        .map(|instance| load_local_subject(instance, args.target.as_deref(), env))
        .transpose()?;

    let host = args
        .host
        .clone()
        .or_else(|| local.as_ref().map(|value| value.host.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "instance identity is required; provide --host or a local target/instance shortcut"
            )
        })?;
    let status_port = args
        .status_port
        .or_else(|| local.as_ref().map(|value| value.status_port))
        .unwrap_or(DEFAULT_PORTAL_STATUS_PORT);
    let base_image_ref = args
        .verification
        .base_image
        .clone()
        .or_else(|| {
            local
                .as_ref()
                .and_then(|value| value.base_image_ref.clone())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "canonical base-image reference is required; provide --base-image because the local deployment has no unambiguous base_image_ref"
            )
        })?;
    let workload_ref = args
        .workload_ref
        .clone()
        .or_else(|| local.as_ref().map(|value| value.workload_ref.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "canonical workload reference is required; provide --workload-ref or a local deployment shortcut"
            )
        })?;
    validate_name_version(&base_image_ref, "--base-image")?;
    validate_name_version(&workload_ref, "--workload-ref")?;

    let report_path = args
        .report
        .clone()
        .or_else(|| local.as_ref().map(|value| value.report_path.clone()))
        .unwrap_or_else(|| PathBuf::from("session-verification-report.json"));

    Ok(VerificationSubject {
        host,
        status_port,
        base_image_ref,
        workload_ref,
        report_path,
    })
}

struct LocalSubjectDefaults {
    host: String,
    status_port: u16,
    base_image_ref: Option<String>,
    workload_ref: String,
    report_path: PathBuf,
}

fn load_local_subject(
    instance: &str,
    target_filter: Option<&str>,
    env: &Env,
) -> Result<LocalSubjectDefaults> {
    let (target_name, instance_name) = resolve_instance(&env.data_dir, instance, target_filter)?;
    let state = DeployState::load(&env.data_dir, &target_name, &instance_name)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if !matches!(state.status, DeployStatus::Deployed { .. }) {
        bail!("deployment {target_name}/{instance_name} is not deployed");
    }
    if state.workload_name.is_empty() || state.workload_version.is_empty() {
        bail!("deployment {target_name}/{instance_name} has no initialized workload");
    }
    let (host, status_port, _) = super::portal_endpoints(&state)?;
    Ok(LocalSubjectDefaults {
        host,
        status_port,
        base_image_ref: state.base_image_ref,
        workload_ref: format!("{}:{}", state.workload_name, state.workload_version),
        report_path: session_report_path(&env.data_dir, &target_name, &instance_name),
    })
}

fn validate_name_version(value: &str, flag: &str) -> Result<()> {
    let Some((name, version)) = value.split_once(':') else {
        bail!("{flag} requires NAME:VERSION, got {value:?}");
    };
    if name.is_empty() || version.is_empty() {
        bail!("{flag} requires NAME:VERSION, got {value:?}");
    }
    Ok(())
}

fn session_report_path(data_dir: &std::path::Path, target: &str, instance: &str) -> PathBuf {
    data_dir
        .join("cloud")
        .join("deployments")
        .join(target)
        .join(format!("{instance}.session-verification-report.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_references_require_name_and_version() {
        assert!(validate_name_version("automata-linux:v1", "--base-image").is_ok());
        assert!(validate_name_version("automata-linux", "--base-image").is_err());
        assert!(validate_name_version(":v1", "--base-image").is_err());
    }
}
