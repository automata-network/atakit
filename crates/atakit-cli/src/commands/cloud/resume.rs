use std::{path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use atakit_cloud::{
    cli::{ResumeArgs, SessionVerificationArgs},
    init::{self, InitConfig, VerifiedPortalTls},
    provider::CloudProvider,
    resume::{self, InitializationInputs, InitializationPhase, ResumeAction, Submission},
    DeployState, DeployStatus, PlatformKind, ProcessRunner,
};
use atakit_core::Env;
use sha2::Digest;

use crate::{config::Config, progress::IndicatifReporter};

pub(crate) fn saved_verification(
    args: &impl serde::Serialize,
    state: &DeployState,
) -> Result<serde_json::Value> {
    let mut verification: SessionVerificationArgs =
        serde_json::from_value(serde_json::to_value(args)?)?;
    verification.base_image = state.base_image_ref.clone();
    // Relative paths must keep pointing at the original files on reconnect.
    let cwd = std::env::current_dir()?;
    for path in verification
        .gcp_ak_root_cert
        .iter_mut()
        .chain(verification.azure_maa_cert.iter_mut())
        .chain(verification.aws_nitro_root_cert.iter_mut())
        .chain(verification.amd_ark_root_cert.iter_mut())
        .chain(verification.amd_snp_crl.iter_mut())
        .chain(verification.measurements.iter_mut())
        .chain(verification.amd_snp_security_policy.iter_mut())
        .chain(verification.tdx_dcap_collateral.iter_mut())
    {
        if path.is_relative() {
            *path = cwd.join(&*path);
        }
    }
    Ok(serde_json::to_value(verification)?)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_inputs(
    state: &mut DeployState,
    env: &Env,
    config: &InitConfig,
    remote_source: Option<&init::RemoteAtawlSource>,
    unmeasured_tar: Option<&atakit_core::unmeasured_data::Archive>,
    transfer_timeout: u64,
    init_timeout: u64,
    pcr_policy_path: Option<&Path>,
    verification: serde_json::Value,
) -> Result<()> {
    let archive_sha256: [u8; 32] = hex::decode(&state.archive_hash)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid saved workload archive hash"))?;
    let archive_path = std::fs::canonicalize(&state.archive_path)?;
    state.archive_path = archive_path.display().to_string();
    resume::prepare(
        state,
        &env.data_dir,
        InitializationInputs {
            config: config.clone(),
            config_sha256: String::new(),
            archive_path: state.archive_path.clone(),
            archive_sha256,
            remote_source: remote_source.cloned(),
            unmeasured_tar: unmeasured_tar.cloned(),
            transfer_timeout,
            init_timeout,
            pcr_policy_path: pcr_policy_path.map(std::fs::canonicalize).transpose()?,
            pcr_policy_sha256: pcr_policy_path
                .map(|path| {
                    std::fs::read(path).map(|bytes| hex::encode(sha2::Sha256::digest(&bytes)))
                })
                .transpose()?,
            verification,
        },
    )?;
    Ok(())
}

fn restore_keys(
    inputs: &mut InitializationInputs,
    state: &DeployState,
    config: &Config,
) -> Result<()> {
    for (key, name) in [
        (
            Some(&mut inputs.config.owner_key),
            state.init_env.owner_key.as_str(),
        ),
        (
            Some(&mut inputs.config.gas_wallet),
            state.init_env.gas_wallet.as_str(),
        ),
        (
            inputs.config.prover_credential.as_mut(),
            state
                .init_env
                .prover_credential
                .as_deref()
                .unwrap_or_default(),
        ),
    ] {
        let Some(key) = key else {
            continue;
        };
        if key.mode == "self_generated" {
            continue;
        }
        let spec = config
            .keys
            .get(name)
            .with_context(|| format!("original key '{name}' is unavailable"))?;
        *key = super::init_key_from_config(name, spec, false)?;
    }
    inputs.validate_restored_config()?;
    Ok(())
}

pub async fn run(args: ResumeArgs, env: &Env, config: &Config) -> Result<()> {
    let (target, instance) =
        super::resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;
    let _lock = resume::DeploymentLock::acquire(&env.data_dir, &target, &instance)?;
    let result = tokio::time::timeout(
        Duration::from_secs(args.wait_timeout),
        resume_locked(&target, &instance, env, config),
    )
    .await;
    match result {
        Ok(result) => result,
        Err(_) => bail!("resume stopped waiting after {} seconds; portal timers are unchanged. Run `atakit cloud resume {} --target {}` to check again", args.wait_timeout, instance, target),
    }
}

async fn resume_locked(target: &str, instance: &str, env: &Env, config: &Config) -> Result<()> {
    let mut state = DeployState::load(&env.data_dir, target, instance)?;
    if matches!(
        state.status,
        DeployStatus::Destroying | DeployStatus::Destroyed
    ) {
        bail!("deployment is being destroyed or has been destroyed");
    }
    let provider: Box<dyn CloudProvider> = match state.platform {
        PlatformKind::Aws => Box::new(atakit_cloud::aws::AwsProvider::from_state(&state)?),
        PlatformKind::Azure => Box::new(atakit_cloud::azure::AzureProvider::from_state(&state)?),
        PlatformKind::Gcp => Box::new(atakit_cloud::gcp::GcpProvider::from_state(&state)?),
        PlatformKind::Qemu => bail!("cloud resume supports AWS, Azure, and GCP"),
    };
    if !state.provisioning_complete {
        eprintln!("Resume the saved cloud creation and attachment steps...");
        atakit_cloud::provisioning::resume(
            &env.data_dir,
            target,
            instance,
            provider.as_ref(),
            &ProcessRunner::default(),
        )
        .await?;
        state = DeployState::load(&env.data_dir, target, instance)?;
    }
    if state.initialization.is_none() && state.provisioning.started {
        let ip = provider
            .get_instance_ip(&state, &ProcessRunner::default())
            .await?
            .unwrap_or_default();
        state.set_status(DeployStatus::Deployed { ip }, &env.data_dir)?;
        eprintln!(
            "Cloud provisioning completed. Use atakit cloud init to initialize the workload."
        );
        return Ok(());
    }
    let record = state.initialization.clone().context(
        "no saved initialization request; resume cannot establish whether initialization was sent",
    )?;
    let mut inputs = resume::load_inputs(&env.data_dir, &record)?;
    let verification: SessionVerificationArgs =
        serde_json::from_value(inputs.verification.clone())?;
    let runner = ProcessRunner::default();
    resume::verify_instance_identity(&state, &runner).await?;
    let host = loop {
        if let Some(ip) = provider
            .get_instance_ip(&state, &runner)
            .await?
            .filter(|s| !s.is_empty())
        {
            break ip;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let status_port = state.portal_ports.status;
    let init_port = state.portal_ports.init;
    eprintln!("Verify portal TLS for {target}/{instance}...");
    init::wait_for_portal(&host, status_port, init::PORTAL_READINESS_TIMEOUT_SECONDS).await?;
    let verified = super::session_access::verify_disk_portal_tls(
        &host,
        status_port,
        &verification,
        env,
        &inputs.config.chain,
        &init::cloud_tls_attestation_report_path(&env.data_dir, target, instance),
    )
    .await?;
    let mut last_state = String::new();
    let _disk_progress = super::disk_progress::start(verified.client(), &host, status_port);
    loop {
        let status = init::read_portal_status(verified.client(), &host, status_port)
            .await
            .map_err(anyhow::Error::msg)?;
        let record = state
            .initialization
            .as_ref()
            .context("initialization record is missing")?;
        let action = resume::action(
            record,
            &hex::encode(verified.identity().cert_sha256),
            &status,
        )?;
        let current = status["state"].as_str().unwrap_or_default();
        if current != last_state {
            eprintln!("Portal: {current}");
            last_state = current.into();
        }
        match action {
            ResumeAction::Submit => {
                restore_keys(&mut inputs, &state, config)?;
                let workload = workload_ref(&state)?;
                inputs.config.pcr_policy = super::resolve_init_pcr_policy(
                    inputs.pcr_policy_path.as_deref(), &inputs.config,
                    super::registration_is_off(inputs.config.chain.registration.as_deref()),
                    Some(&verified), &workload,
                ).await?;
                let key_file = state.init_auth_key_file.as_ref().context("original initialization credential is missing")?;
                inputs.config.init_auth = Some(atakit_cloud::init_auth::ClientAuth {
                    key_file: key_file.into(), workload_id: format!("{:#x}", crate::commands::workload::compute_workload_id(&workload)),
                    tls_fingerprint: hex::encode(verified.identity().cert_sha256),
                });
                inputs.config.submission = Some(Submission::for_state(&state, &env.data_dir)?);
                eprintln!("Submit the recorded initialization request...");
                let submitted = submit(&inputs, verified.client(), &host, status_port, init_port).await;
                state = DeployState::load(&env.data_dir, target, instance)?;
                // A lost response can still be reconciled with the recorded ID.
                if let Err(error) = submitted { eprintln!("Initialization response unavailable: {error}"); }
                if state.initialization.as_ref().is_some_and(|r| r.phase == InitializationPhase::Prepared) {
                    bail!("initialization was not sent; correct the reported input or admission error before resuming");
                }
            }
            ResumeAction::Wait => tokio::time::sleep(Duration::from_secs(2)).await,
            ResumeAction::VerifyComplete => {
                complete(&mut state, env, config, verified, &host, status_port, &inputs, &verification).await?;
                eprintln!("Deployment {target}/{instance}: workload and session verified.");
                return Ok(());
            }
            ResumeAction::DiskUnlock => bail!("portal is waiting for a disk passphrase; run `atakit cloud disk unlock {instance} --target {target} --disk <name>`, then resume"),
            ResumeAction::Failed(detail) => {
                state.set_status(DeployStatus::Failed { step: super::WAIT_FOR_PORTAL_RUNNING_STEP.into(), message: detail.clone() }, &env.data_dir)?;
                bail!(detail);
            }
        }
    }
}

async fn submit(
    inputs: &InitializationInputs,
    client: &reqwest::Client,
    host: &str,
    status: u16,
    init_port: u16,
) -> Result<()> {
    let transfer = Duration::from_secs(inputs.transfer_timeout);
    let timeout = Duration::from_secs(inputs.init_timeout);
    if let Some(source) = &inputs.remote_source {
        init::post_portal_init_remote_with_client(
            client,
            host,
            status,
            init_port,
            source,
            inputs.unmeasured_tar.as_ref(),
            &inputs.config,
            transfer,
            timeout,
            &IndicatifReporter,
        )
        .await?;
    } else {
        init::post_portal_init_with_client(
            client,
            host,
            status,
            init_port,
            &inputs.archive_path,
            &inputs.archive_sha256,
            inputs.unmeasured_tar.as_ref(),
            &inputs.config,
            transfer,
            timeout,
            &IndicatifReporter,
        )
        .await?;
    }
    Ok(())
}

fn workload_ref(state: &DeployState) -> Result<automata_tee_workload_measurement::types::AppRef> {
    Ok(automata_tee_workload_measurement::types::AppRef::new(
        state.workload_publisher.parse()?,
        state.workload_name.clone(),
        state.workload_version.clone(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn complete(
    state: &mut DeployState,
    env: &Env,
    config: &Config,
    verified: VerifiedPortalTls,
    host: &str,
    status_port: u16,
    inputs: &InitializationInputs,
    verification: &SessionVerificationArgs,
) -> Result<()> {
    let status = init::read_portal_status(verified.client(), host, status_port)
        .await
        .map_err(anyhow::Error::msg)?;
    let record = state
        .initialization
        .as_ref()
        .context("initialization record is missing")?;
    if resume::action(
        record,
        &hex::encode(verified.identity().cert_sha256),
        &status,
    )? != ResumeAction::VerifyComplete
    {
        bail!("portal no longer confirms this initialization is Running");
    }
    let expected_workload = format!(
        "{:#x}",
        crate::commands::workload::compute_workload_id(&workload_ref(state)?)
    );
    if status["workload_id"].as_str() != Some(expected_workload.as_str()) {
        bail!("Running portal reports a different workload than the saved initialization");
    }
    if status["chain"]["registration"].as_str()
        != Some(
            inputs
                .config
                .chain
                .registration
                .as_deref()
                .unwrap_or("required"),
        )
    {
        bail!("portal registration mode differs from the saved initialization");
    }
    let access = super::session_access::VerifiedPortalAccess {
        target_name: state.target_name.clone(),
        instance_name: state.instance_name.clone(),
        state: state.clone(),
        host: host.into(),
        status_port,
        chain_name: Some(state.init_env.chain.clone()),
        verified_tls: verified,
        registration: inputs.config.chain.registration.clone(),
    };
    let access =
        super::session_access::resolve_verified_session_access(access, verification, config)
            .await?;
    let session = access.verify_current_session().await?;
    if session.binding_mode == atakit_attestation::BindingMode::Chain {
        let expected_registry: alloy_ext::core::primitives::Address =
            inputs.config.chain.session_registry.parse()?;
        if session.binding_registry != expected_registry.0 .0
            || inputs
                .config
                .chain
                .chain_id
                .is_some_and(|expected| expected != session.binding_chain_id)
        {
            bail!("verified session belongs to a different chain or SessionRegistry");
        }
    }
    resume::record_complete(state, &env.data_dir, host)?;
    atakit_cloud::init_auth::retire(state, &env.data_dir).map_err(anyhow::Error::msg)?;
    Ok(())
}
