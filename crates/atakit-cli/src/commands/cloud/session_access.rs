use std::path::Path;

use anyhow::{bail, Context, Result};
use atakit_attestation::{
    BindingMode, SessionAttributeRequirement, SessionPcrPolicy, SessionPcrPolicy384,
    VerifiedSession,
};
use atakit_attestation_client::{
    verify_current_session, AttestationClient, AttestationClientConfig,
    TrustedWorkloadSessionPolicy,
};
use atakit_cloud::cli::SessionVerificationArgs;
use atakit_cloud::init::{self, InitChainConfig, VerifiedPortalTls};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_core::Env;
use atakit_cvm_encoding::pcr_comparison::{encode_static256, encode_static384};
use atakit_workload::{inspect_workload, InspectOptions};

use super::{
    init_chain_from_config, portal_endpoints, registration_is_off, resolve_instance,
    resolve_tls_measurement_policy, synthesize_off_init_chain,
};
use crate::config::{ChainConfig, Config};

pub(crate) async fn connect_attestation_client(
    chain_name: &str,
    chain: &ChainConfig,
) -> Result<AttestationClient> {
    AttestationClient::connect(AttestationClientConfig {
        rpc_url: chain.rpc_url.clone(),
        session_registry: chain.session_registry.clone(),
        expected_chain_id: chain.chain_id,
        expected_base_image_registry: chain.base_image_registry.clone(),
        expected_workload_registry: chain.workload_registry.clone(),
    })
    .await
    .with_context(|| format!("connect attestation client for chain '{chain_name}'"))
}

pub(crate) struct VerifiedPortalAccess {
    pub target_name: String,
    pub instance_name: String,
    pub state: DeployState,
    pub host: String,
    pub status_port: u16,
    pub chain_name: Option<String>,
    pub verified_tls: VerifiedPortalTls,
    registration: Option<String>,
}

pub(crate) struct VerifiedCloudSessionAccess {
    pub target_name: String,
    pub instance_name: String,
    pub state: DeployState,
    pub host: String,
    pub status_port: u16,
    pub chain_name: Option<String>,
    pub required_binding: Option<BindingMode>,
    pub verified_tls: VerifiedPortalTls,
    workload_policy: TrustedWorkloadSessionPolicy,
    /// Present exactly when the registered policy came from a chain. The
    /// session binding is derived from this client and nowhere else, so an
    /// explicit verification cannot acquire one.
    chain_client: Option<AttestationClient>,
}

impl VerifiedCloudSessionAccess {
    pub async fn verify_current_session(&self) -> Result<VerifiedSession> {
        match &self.chain_client {
            Some(client) => {
                client
                    .verify_current_session_with_policy(
                        &self.verified_tls,
                        &self.host,
                        self.status_port,
                        self.workload_policy.clone(),
                        self.required_binding,
                    )
                    .await
            }
            None => {
                verify_current_session(
                    &self.verified_tls,
                    &self.host,
                    self.status_port,
                    self.workload_policy.clone(),
                    self.required_binding,
                )
                .await
            }
        }
        .map_err(|error| anyhow::anyhow!("{error}"))
    }
}

pub(crate) async fn resolve_verified_portal_access(
    instance: &str,
    target_filter: Option<&str>,
    verification: &SessionVerificationArgs,
    env: &Env,
    config: &Config,
) -> Result<VerifiedPortalAccess> {
    let (target_name, instance_name) = resolve_instance(&env.data_dir, instance, target_filter)?;
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

    let chain_name = verification
        .chain
        .as_deref()
        .or((!state.init_env.chain.is_empty()).then_some(state.init_env.chain.as_str()))
        .or(target.chain.as_deref())
        .map(str::to_string);
    let init_chain = match chain_name.as_deref() {
        Some(name) => match config.chains.get(name) {
            Some(chain) => {
                if tls_needs_registry_derivation(
                    verification.measurements.is_some(),
                    chain.base_image_registry.is_some(),
                ) {
                    let prover = chain
                        .prover
                        .as_ref()
                        .and_then(|prover| config.provers.get(prover));
                    init_chain_from_config(name, chain, target.registration.as_deref(), prover)
                        .await?
                } else {
                    verification_chain_without_registry_derivation(
                        chain,
                        target.registration.as_deref(),
                    )
                }
            }
            None => bail!("chain '{name}' not found in [chains]"),
        },
        None if registration_is_off(target.registration.as_deref()) => synthesize_off_init_chain(),
        None => bail!("no chain config is available for verifier trust lookup"),
    };

    let untrusted_portal_base_image_id = if verification.measurements.is_none() {
        Some(
            init::read_untrusted_portal_base_image_id(&host, status_port)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?,
        )
    } else {
        None
    };
    let measurement_policy = resolve_tls_measurement_policy(
        verification.measurements.as_deref(),
        verification.base_image.as_deref(),
        untrusted_portal_base_image_id,
        &verification.measurement_publisher_key,
        &env.data_dir,
        &init_chain,
    )
    .await?;
    let tls_verification_trust = init::load_tls_verification_trust(
        &verification.gcp_ak_root_cert,
        &verification.azure_maa_cert,
        &verification.amd_ark_root_cert,
        &verification.amd_snp_crl,
        verification.amd_snp_security_policy.as_deref(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let automata_read_strategy = init::tdx_dcap_automata_read_strategy(
        &verification.tdx_dcap_automata_read_strategy,
        verification.tdx_dcap_automata_multicall3_address.clone(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let tdx_dcap = init::tdx_dcap_collateral_config_with_read_strategy(
        verification.tdx_dcap_collateral.clone(),
        verification.tdx_dcap_pccs_url.clone(),
        verification.tdx_dcap_automata_collateral_rpc_url.clone(),
        verification.tdx_dcap_automata_pcs_dao.clone(),
        automata_read_strategy,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    let trust_source =
        init::trust_source_for_init_chain(&init_chain, tls_verification_trust, tdx_dcap)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    let verified_tls = init::bootstrap_portal_tls(
        &host,
        status_port,
        Some(measurement_policy),
        None,
        &trust_source,
        None,
        Some(&init::cloud_tls_attestation_report_path(
            &env.data_dir,
            &target_name,
            &instance_name,
        )),
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    Ok(VerifiedPortalAccess {
        target_name,
        instance_name,
        state,
        host,
        status_port,
        chain_name,
        verified_tls,
        registration: target.registration.clone(),
    })
}

pub(crate) async fn resolve_verified_session_access(
    portal: VerifiedPortalAccess,
    verification: &SessionVerificationArgs,
    config: &Config,
) -> Result<VerifiedCloudSessionAccess> {
    let chain_client = match portal.chain_name.as_deref() {
        Some(name) => match config.chains.get(name) {
            Some(chain)
                if should_resolve_registered_workload_policy(
                    portal.registration.as_deref(),
                    chain,
                ) =>
            {
                Some(connect_attestation_client(name, chain).await?)
            }
            Some(_) => None,
            None => bail!("chain '{name}' not found in [chains]"),
        },
        None if registration_is_off(portal.registration.as_deref()) => None,
        None => bail!("no chain config is available for verifier trust lookup"),
    };
    // The deployment records its workload's publisher, so the identifier is
    // recomputable from state rather than being stored opaquely.
    let workload_publisher = portal
        .state
        .workload_publisher
        .parse()
        .context("deployment state has an invalid workload publisher")?;
    let workload_ref = automata_tee_workload_measurement::types::AppRef::new(
        workload_publisher,
        portal.state.workload_name.clone(),
        portal.state.workload_version.clone(),
    );
    let workload_id = crate::commands::workload::compute_workload_id(&workload_ref);
    let workload_policy = resolve_trusted_workload_policy(
        &portal.state,
        verification,
        chain_client.as_ref(),
        workload_id.0,
        portal.verified_tls.identity.base_image_id,
    )
    .await?;
    let required_binding = required_binding_for_registration(portal.registration.as_deref());

    Ok(VerifiedCloudSessionAccess {
        target_name: portal.target_name,
        instance_name: portal.instance_name,
        state: portal.state,
        host: portal.host,
        status_port: portal.status_port,
        chain_name: portal.chain_name,
        required_binding,
        verified_tls: portal.verified_tls,
        workload_policy,
        chain_client,
    })
}

fn verification_chain_without_registry_derivation(
    chain: &ChainConfig,
    registration: Option<&str>,
) -> InitChainConfig {
    InitChainConfig {
        rpc_url: chain.rpc_url.clone(),
        session_registry: chain.session_registry.clone(),
        workload_registry: chain
            .workload_registry
            .clone()
            .unwrap_or_else(|| super::ZERO_ADDR.to_string()),
        base_image_registry: chain
            .base_image_registry
            .clone()
            .unwrap_or_else(|| super::ZERO_ADDR.to_string()),
        registration: registration.map(str::to_string),
        chain_id: chain.chain_id,
        tee_backend: chain.tee_backend.clone(),
        prover: None,
    }
}

fn tls_needs_registry_derivation(
    has_explicit_measurements: bool,
    has_configured_base_image_registry: bool,
) -> bool {
    !has_explicit_measurements && !has_configured_base_image_registry
}

fn should_resolve_registered_workload_policy(
    registration: Option<&str>,
    chain: &ChainConfig,
) -> bool {
    if !registration_is_off(registration) {
        return true;
    }
    !chain.rpc_url.trim().is_empty()
        && chain
            .workload_registry
            .as_deref()
            .is_some_and(|address| address != super::ZERO_ADDR)
}

async fn resolve_trusted_workload_policy(
    state: &DeployState,
    verification: &SessionVerificationArgs,
    chain_client: Option<&AttestationClient>,
    workload_id: [u8; 32],
    selected_base_image_id: Option<[u8; 32]>,
) -> Result<TrustedWorkloadSessionPolicy> {
    let manual_pcr23 = match (
        verification.trusted_workload_pcr23_sha256.as_deref(),
        verification.trusted_workload_pcr23_sha384.as_deref(),
    ) {
        (Some(sha256), Some(sha384)) => Some((sha256, sha384)),
        (None, None) => None,
        _ => bail!(
            "--trusted-workload-pcr23-sha256 and --trusted-workload-pcr23-sha384 must be supplied together"
        ),
    };
    let mut policy = if let Some(client) = chain_client {
        client
            .resolve_workload_policy(
                &format!("{}:{}", state.workload_name, state.workload_version),
                selected_base_image_id.ok_or_else(|| {
                    anyhow::anyhow!("TLS verification did not select a base image ID")
                })?,
            )
            .await?
    } else if manual_pcr23.is_some() {
        TrustedWorkloadSessionPolicy {
            workload_id,
            pcr_specs256: Vec::new(),
            pcr_specs384: Vec::new(),
            attribute_requirements: Vec::new(),
        }
    } else {
        load_local_workload_policy(state, workload_id).await?
    };

    if let Some((sha256, sha384)) = manual_pcr23 {
        policy.pcr_specs256.push(static_pcr23_policy(decode_hex_32(
            sha256,
            "--trusted-workload-pcr23-sha256",
        )?));
        policy
            .pcr_specs384
            .push(static_pcr23_policy384(decode_hex_48(
                sha384,
                "--trusted-workload-pcr23-sha384",
            )?));
    }
    Ok(policy)
}

async fn load_local_workload_policy(
    state: &DeployState,
    workload_id: [u8; 32],
) -> Result<TrustedWorkloadSessionPolicy> {
    let archive_path = Path::new(&state.archive_path);
    if archive_path.extension().and_then(|value| value.to_str()) != Some("atawl") {
        bail!(
            "saved workload archive {} is not a .atawl file; provide both --trusted-workload-pcr23-sha256 and --trusted-workload-pcr23-sha384",
            archive_path.display()
        );
    }
    if state.archive_hash.is_empty() {
        bail!("saved deployment has no trusted workload archive hash");
    }
    let actual_archive_hash = atakit_workload::hash::hash_file(archive_path)
        .with_context(|| format!("hash trusted workload archive {}", archive_path.display()))?;
    if !atakit_workload::hex_equal(&state.archive_hash, &actual_archive_hash) {
        bail!(
            "trusted workload archive hash mismatch: saved {} actual {}",
            state.archive_hash,
            actual_archive_hash
        );
    }
    let inspection = inspect_workload(&InspectOptions {
        publisher: None,
        archive: Some(archive_path.to_path_buf()),
        workload_dir: None,
        engine: None,
        verbose: false,
        measured_data_root: None,
        unmeasured_data_root: None,
    })
    .await
    .with_context(|| {
        format!(
            "inspect trusted workload archive {}",
            archive_path.display()
        )
    })?;
    if inspection.manifest.meta.name != state.workload_name
        || inspection.manifest.meta.version != state.workload_version
    {
        bail!(
            "trusted workload archive identity {}/{} does not match saved workload {}/{}",
            inspection.manifest.meta.name,
            inspection.manifest.meta.version,
            state.workload_name,
            state.workload_version
        );
    }

    Ok(TrustedWorkloadSessionPolicy {
        workload_id,
        pcr_specs256: vec![static_pcr23_policy(decode_hex_32(
            &inspection.pcr23_sha256,
            "trusted workload archive PCR23",
        )?)],
        pcr_specs384: vec![static_pcr23_policy384(decode_hex_48(
            &inspection.pcr23_sha384,
            "trusted workload archive SHA-384 PCR23",
        )?)],
        attribute_requirements: inspection
            .manifest
            .config
            .attributes
            .iter()
            .map(|(name, values)| {
                let (key, allowed_values) =
                    atakit_core::tee_attributes::encode_requirement(name, values)
                        .map_err(anyhow::Error::msg)?;
                Ok(SessionAttributeRequirement {
                    key,
                    allowed_values,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

pub(crate) fn static_pcr23_policy(value: [u8; 32]) -> SessionPcrPolicy {
    SessionPcrPolicy {
        pcr_index: 23,
        comparison: format!("0x{}", hex::encode(encode_static256(value))),
    }
}

pub(crate) fn static_pcr23_policy384(value: [u8; 48]) -> SessionPcrPolicy384 {
    SessionPcrPolicy384 {
        pcr_index: 23,
        comparison: format!("0x{}", hex::encode(encode_static384(value))),
    }
}

pub(crate) fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("decode {label} as hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 32 bytes"))
}

pub(crate) fn decode_hex_48(value: &str, label: &str) -> Result<[u8; 48]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("decode {label} as hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 48 bytes"))
}

fn required_binding_for_registration(registration: Option<&str>) -> Option<BindingMode> {
    match registration {
        Some("off") => Some(BindingMode::Local),
        Some("optional") => None,
        Some("required") | None => Some(BindingMode::Chain),
        Some(_) => Some(BindingMode::Chain),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use atakit_cloud::{NewDeployParams, PersistedInitEnv, PlatformKind, PortalPorts};
    use tempfile::TempDir;

    use super::*;

    fn deployed_state(archive_path: String, archive_hash: String) -> DeployState {
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "instance".into(),
            workload_publisher:
                "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f".into(),
            workload_name: "test".into(),
            workload_version: "v0.0.1".into(),
            target_name: "gcp-tdx".into(),
            provider_name: "gcp".into(),
            platform: PlatformKind::Gcp,
            image_ref: "automata-linux:v1".into(),
            base_image_ref: Some("automata-linux:v1".into()),
            archive_path,
            archive_hash,
            init_env: PersistedInitEnv::default(),
            portal_ports: PortalPorts::default(),
            total_steps: 1,
        });
        state.status = DeployStatus::Deployed {
            ip: "192.0.2.10".into(),
        };
        state
    }

    fn write_test_archive(dir: &Path) -> (String, String) {
        let path = dir.join("test-v0.0.1.atawl");
        let file = std::fs::File::create(&path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let manifest = serde_json::json!({
            "meta": {
                "format": 7,
                "publisher": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "name": "test",
                "version": "v0.0.1"
            },
            "config": {
                "image": "test:v0.0.1",
                "base-image-mode": "blacklist",
                "base-image": [],
                "attributes": {
                    "atakit.attestation.v1.tee.intel-tdx.debug.enabled": [false, true]
                },
                "ports": [],
                "restart": "no",
                "command": null,
                "entrypoint": null,
                "session-ttl": 0,
                "atakit-portal": false,
                "gid-group": "test",
                "measured-data": false,
                "unmeasured-data": false,
                "environment": {},
                "unmeasured-env-files": [],
                "storage": {},
                "dependencies": null,
                "firewall-ports": [],
                "baby-container": null,
                "boot-disk-size": null,
                "cap-add": [],
                "cap-drop": [],
                "logging": {
                    "driver": "k8s-file",
                    "options": {"max-file": "5", "max-size": "50m"},
                    "log-readers": []
                },
                "workload-logs": false
            },
            "disks": {},
            "hashes": {},
            "unmeasured-data": [],
            "unmeasured-env-files": {},
            "images": {}
        })
        .to_string();
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "test/manifest.json", Cursor::new(manifest))
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();
        let hash = atakit_workload::hash::hash_file(&path).unwrap();
        (path.display().to_string(), hash)
    }

    #[test]
    fn registration_policy_maps_to_required_binding() {
        assert_eq!(
            required_binding_for_registration(None),
            Some(BindingMode::Chain)
        );
        assert_eq!(
            required_binding_for_registration(Some("required")),
            Some(BindingMode::Chain)
        );
        assert_eq!(
            required_binding_for_registration(Some("off")),
            Some(BindingMode::Local)
        );
        assert_eq!(required_binding_for_registration(Some("optional")), None);
    }

    #[test]
    fn only_default_chain_tls_needs_base_image_registry_derivation() {
        assert!(!tls_needs_registry_derivation(true, false));
        assert!(!tls_needs_registry_derivation(false, true));
        assert!(tls_needs_registry_derivation(false, false));
    }

    #[test]
    fn registration_off_without_configured_workload_registry_uses_local_policy() {
        let mut chain = super::super::test_chain_config();
        assert!(!should_resolve_registered_workload_policy(
            Some("off"),
            &chain
        ));

        chain.workload_registry = Some(super::super::ZERO_ADDR.to_string());
        assert!(!should_resolve_registered_workload_policy(
            Some("off"),
            &chain
        ));

        chain.workload_registry = Some("0x2222222222222222222222222222222222222222".into());
        assert!(should_resolve_registered_workload_policy(
            Some("off"),
            &chain
        ));

        chain.workload_registry = None;
        assert!(should_resolve_registered_workload_policy(
            Some("required"),
            &chain
        ));
    }

    #[tokio::test]
    async fn registration_off_loads_and_checks_saved_workload_archive() {
        let dir = TempDir::new().unwrap();
        let (archive_path, archive_hash) = write_test_archive(dir.path());
        let state = deployed_state(archive_path, archive_hash);

        let policy = load_local_workload_policy(&state, [0x33; 32])
            .await
            .unwrap();
        assert_eq!(policy.workload_id, [0x33; 32]);
        assert_eq!(policy.pcr_specs256.len(), 1);
        assert_eq!(policy.pcr_specs256[0].pcr_index, 23);
        let comparison = hex::decode(
            policy.pcr_specs256[0]
                .comparison
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            atakit_cvm_encoding::pcr_comparison::decode256(&comparison).unwrap(),
            atakit_cvm_encoding::pcr_comparison::PcrComparison256::Static(_)
        ));
        assert_eq!(policy.attribute_requirements.len(), 1);
        assert_eq!(
            policy.attribute_requirements[0].key,
            atakit_core::tee_attributes::INTEL_TDX_DEBUG_KEY
        );
        assert_eq!(
            policy.attribute_requirements[0].allowed_values,
            [
                atakit_core::tee_attributes::ATTRIBUTE_FALSE,
                atakit_core::tee_attributes::ATTRIBUTE_TRUE
            ]
        );

        let mut mismatched = state;
        mismatched.archive_hash = "0x00".into();
        assert!(load_local_workload_policy(&mismatched, [0x33; 32])
            .await
            .unwrap_err()
            .to_string()
            .contains("archive hash mismatch"));
    }

    #[tokio::test]
    async fn manually_trusted_workload_pcr23_banks_are_available_without_a_local_archive() {
        let state = deployed_state("/missing/workload.atawl".into(), String::new());
        let verification = SessionVerificationArgs {
            trusted_workload_pcr23_sha256: Some(format!("0x{}", hex::encode([0x55; 32]))),
            trusted_workload_pcr23_sha384: Some(format!("0x{}", hex::encode([0x66; 48]))),
            ..Default::default()
        };
        let policy = resolve_trusted_workload_policy(&state, &verification, None, [0x66; 32], None)
            .await
            .unwrap();
        assert_eq!(policy.pcr_specs256, [static_pcr23_policy([0x55; 32])]);
        assert_eq!(policy.pcr_specs384, [static_pcr23_policy384([0x66; 48])]);
    }
}
