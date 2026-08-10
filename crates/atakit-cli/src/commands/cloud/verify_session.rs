use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use atakit_attestation_client::TrustedWorkloadSessionPolicy;
use atakit_cloud::cli::VerifySessionArgs;
use atakit_cloud::init;
use atakit_cloud::init::{ChainTrustSource, ExplicitTrustSource};
use atakit_cloud::session::{
    verify_portal_session, PortalSessionVerificationRequest, SessionVerificationMode,
};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::DEFAULT_PORTAL_STATUS_PORT;
use atakit_core::Env;
use atakit_cvm_types::AppRef;
use owo_colors::OwoColorize;

use super::session_access::{connect_attestation_client, decode_hex_32, decode_hex_48};
use super::{resolve_instance, resolve_verifier_tls_measurement_policy};
use crate::config::Config;

/// Parse a canonical `<publisher>/<name>:<version>` reference.
///
/// Chain mode carries typed references rather than strings so an unparseable
/// one cannot reach the registry lookup.
fn parse_ref(value: &str, what: &str) -> Result<AppRef> {
    value
        .parse()
        .with_context(|| format!("invalid {what} reference '{value}'"))
}

struct VerificationSubject {
    host: String,
    status_port: u16,
    base_image_ref: String,
    workload_ref: String,
    report_path: PathBuf,
}

pub async fn run(args: VerifySessionArgs, env: &Env, config: &Config) -> Result<()> {
    let subject = resolve_subject(&args, env)?;
    // `verify-session` no longer needs an `InitChainConfig`: the trust source
    // carries the chain client directly, and nothing here builds an `/init`
    // payload.
    let chain_client = match args.verification.chain.as_deref() {
        Some(chain_name) => {
            let chain = config
                .chains
                .get(chain_name)
                .ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in config"))?;
            let client = connect_attestation_client(chain_name, chain).await?;
            let context = client.context();
            let _ = context;
            Some(client)
        }
        None => None,
    };

    let tls_verification_trust =
        init::load_tls_verification_trust(init::TlsVerificationTrustFiles {
            gcp_ak_root_certs: &args.verification.gcp_ak_root_cert,
            azure_maa_certs: &args.verification.azure_maa_cert,
            aws_nitro_root_certs: &args.verification.aws_nitro_root_cert,
            amd_ark_root_certs: &args.verification.amd_ark_root_cert,
            amd_snp_crls: &args.verification.amd_snp_crl,
            amd_snp_security_policy: args.verification.amd_snp_security_policy.as_deref(),
            aws_document_maximum_age_seconds: args.verification.aws_document_maximum_age_seconds,
            aws_document_allowed_future_clock_difference_seconds: args
                .verification
                .aws_document_allowed_future_clock_difference_seconds,
        })
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

    // One authority per verification, chosen once. Each mode carries only the
    // policies its own authority supplies, so there is no combination left to
    // validate afterwards.
    let mode = match &chain_client {
        Some(client) => {
            let mut conflicting: Vec<&str> = tls_verification_trust
                .sources
                .keys()
                .map(String::as_str)
                .collect();
            // `--measurements` is an operator-supplied base-image policy, which
            // belongs to explicit mode. Chain mode reads that policy from the
            // registry, so accepting both would be the mixed trust the
            // exclusive-source rule forbids.
            if args.verification.measurements.is_some() {
                conflicting.push("--measurements");
            }
            if !conflicting.is_empty() {
                bail!(
                    "--chain resolves every trust input from the registry, so {} cannot also be supplied; drop them, or drop --chain to verify explicitly",
                    conflicting.join(", ")
                );
            }
            if args.verification.trusted_workload_pcr23_sha256.is_some()
                || args.verification.trusted_workload_pcr23_sha384.is_some()
            {
                bail!(
                    "--chain resolves the registered workload policy from the registry, so --trusted-workload-pcr23-sha256 and --trusted-workload-pcr23-sha384 cannot also be supplied"
                );
            }
            SessionVerificationMode::Chain {
                source: ChainTrustSource::from_client(client.clone(), tdx_dcap),
                base_image: parse_ref(&subject.base_image_ref, "base image")?,
                workload: parse_ref(&subject.workload_ref, "workload")?,
            }
        }
        None => {
            let workload_policy = match (
                args.verification.trusted_workload_pcr23_sha256.as_deref(),
                args.verification.trusted_workload_pcr23_sha384.as_deref(),
            ) {
                (Some(sha256), Some(sha384)) => TrustedWorkloadSessionPolicy::from_manifest_pcr23(
                    &subject.workload_ref,
                    decode_hex_32(sha256, "--trusted-workload-pcr23-sha256")?,
                    decode_hex_48(sha384, "--trusted-workload-pcr23-sha384")?,
                )?,
                (None, None) => bail!(
                    "no trusted workload collateral is available; select a verifier chain with --chain or provide both --trusted-workload-pcr23-sha256 and --trusted-workload-pcr23-sha384"
                ),
                _ => bail!(
                    "--trusted-workload-pcr23-sha256 and --trusted-workload-pcr23-sha384 must be supplied together"
                ),
            };
            let measurement_policy = resolve_verifier_tls_measurement_policy(
                args.verification.measurements.as_deref(),
                &subject.base_image_ref,
                &args.verification.measurement_publisher_key,
                &env.data_dir,
                None,
            )
            .await?;
            SessionVerificationMode::Explicit {
                source: ExplicitTrustSource::new(tls_verification_trust, tdx_dcap)
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
                measurement_policy: Box::new(measurement_policy),
                workload_policy,
            }
        }
    };

    eprint!("Verify portal TLS and current session... ");
    let outcome = verify_portal_session(PortalSessionVerificationRequest {
        host: subject.host.clone(),
        status_port: subject.status_port,
        resolved_address: None,
        mode,
        report_path: None,
        required_binding: None,
    })
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let verified = outcome.session;
    eprintln!("{}", "done".green());

    if let Some(parent) = subject.report_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create report directory {}", parent.display()))?;
    }
    // Provenance is reported alongside the verified session so an operator can
    // see which authority supplied each trust input. `flatten` keeps every
    // field the report already carried at the top level.
    #[derive(serde::Serialize)]
    struct SessionVerificationReport<'a> {
        #[serde(flatten)]
        session: &'a atakit_attestation::VerifiedSession,
        trust_provenance: &'a atakit_cloud::init::TrustProvenance,
    }
    let report = SessionVerificationReport {
        session: &verified,
        trust_provenance: outcome.portal_tls.trust_provenance(),
    };
    std::fs::write(&subject.report_path, serde_json::to_vec_pretty(&report)?)
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
        workload_ref: format!(
            "{}/{}:{}",
            state.workload_publisher, state.workload_name, state.workload_version
        ),
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

    #[test]
    fn local_deployment_subject_includes_workload_publisher() {
        use atakit_cloud::{
            GcpResources, NewDeployParams, PersistedInitEnv, PlatformKind, PortalPorts,
        };

        let publisher = "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f";
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("data");
        let env = Env {
            data_dir: data_dir.clone(),
            config_dir: root.path().join("config"),
            cache_dir: root.path().join("cache"),
            image_dir: data_dir.join("images"),
            workload_dir: data_dir.join("workloads"),
        };
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "test-instance".to_string(),
            workload_publisher: publisher.to_string(),
            workload_name: "fedora-oci".to_string(),
            workload_version: "v0.0.16".to_string(),
            target_name: "test-target".to_string(),
            provider_name: "test-provider".to_string(),
            platform: PlatformKind::Gcp,
            image_ref: "automata-linux:v0.2.8-debug".to_string(),
            base_image_ref: Some(format!("{publisher}/automata-linux:v0.2.8-debug")),
            archive_path: "/tmp/fedora-oci-v0.0.16.atawl".to_string(),
            archive_hash: "unused".to_string(),
            init_env: PersistedInitEnv::default(),
            portal_ports: PortalPorts::default(),
            total_steps: 7,
        });
        state.status = DeployStatus::Deployed {
            ip: "192.0.2.10".to_string(),
        };
        state.resources.gcp = Some(GcpResources {
            external_ip: Some("192.0.2.10".to_string()),
            ..Default::default()
        });
        state.save(&env.data_dir).unwrap();

        let subject = load_local_subject("test-instance", Some("test-target"), &env).unwrap();

        assert_eq!(
            subject.workload_ref,
            format!("{publisher}/fedora-oci:v0.0.16")
        );
    }
}
