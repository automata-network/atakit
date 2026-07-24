use std::path::Path;
use std::time::Duration;

use alloy_ext::core::primitives::{Address, B256};
use alloy_ext::ext::{NetworkProvider, ProviderEx};
use anyhow::{bail, Context, Result};
use atakit_attestation::{
    BindingMode, SessionAttributeRequirement, SessionPcrPolicy, SessionPcrVerifyType,
    TrustedSessionBinding, VerifiedSession,
};
use atakit_cloud::cli::SessionVerificationArgs;
use atakit_cloud::init::{self, InitChainConfig, VerifiedPortalTls};
use atakit_cloud::session::{self, TrustedWorkloadSessionPolicy};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_core::Env;
use atakit_workload::{inspect_workload, InspectOptions};
use automata_tee_workload_measurement::stubs::WorkloadRegistry::WorkloadSpec;
use automata_tee_workload_measurement::workload_registry::WorkloadRegistry;

use super::{
    init_chain_from_config, portal_endpoints, registration_is_off, resolve_instance,
    resolve_tls_measurement_policy, synthesize_off_init_chain,
};
use crate::config::{ChainConfig, Config};

/// Resolve workload policy from sources selected by an independent verifier.
/// Explicit PCR23 collateral wins; otherwise the verifier-selected chain must
/// provide the exact WorkloadSpec.
pub(crate) async fn resolve_verifier_workload_policy(
    workload_ref: &str,
    trusted_workload_pcr23: Option<&str>,
    chain_client: Option<&atakit_attestation_client::AttestationClient>,
    selected_base_image_id: [u8; 32],
) -> Result<TrustedWorkloadSessionPolicy> {
    let parsed = crate::commands::workload::parse_workload_ref(workload_ref)?;
    let crate::commands::workload::WorkloadRef::NameVersion { name, version } = parsed else {
        bail!("--workload-ref requires a canonical name:version reference, not a workload ID");
    };
    let workload_id = crate::commands::workload::compute_workload_id(&name, &version).0;

    if let Some(value) = trusted_workload_pcr23 {
        return Ok(TrustedWorkloadSessionPolicy {
            workload_id,
            pcr_specs: vec![static_pcr23_policy(decode_hex_32(
                value,
                "--trusted-workload-pcr23",
            )?)],
            attribute_requirements: Vec::new(),
        });
    }

    let Some(chain_client) = chain_client else {
        bail!(
            "no trusted workload collateral is available; select a verifier chain with --chain or provide --trusted-workload-pcr23"
        );
    };
    chain_client
        .resolve_workload_policy(workload_ref, selected_base_image_id)
        .await
        .map_err(anyhow::Error::new)
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
    trusted_binding: Option<TrustedSessionBinding>,
}

impl VerifiedCloudSessionAccess {
    pub async fn verify_current_session(&self) -> Result<VerifiedSession> {
        session::verify_current_session(
            &self.verified_tls,
            &self.host,
            self.status_port,
            self.workload_policy.clone(),
            self.required_binding,
            self.trusted_binding,
        )
        .await
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
    let base_image = verification
        .base_image
        .as_deref()
        .or(state.base_image_ref.as_deref())
        .unwrap_or(&state.image_ref);
    let init_chain = match chain_name.as_deref() {
        Some(name) => match config.chains.get(name) {
            Some(chain) => {
                let local_pack_exists = if verification.measurements.is_none() {
                    init::local_measurement_pack_exists(&env.data_dir, base_image)
                        .map_err(|error| anyhow::anyhow!("{error}"))?
                } else {
                    false
                };
                if tls_needs_registry_derivation(
                    !base_image.is_empty(),
                    verification.measurements.is_some(),
                    local_pack_exists,
                    chain.base_image_registry.is_some(),
                    target.registration.as_deref(),
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

    let measurement_policy = resolve_tls_measurement_policy(
        verification.measurements.as_deref(),
        Some(base_image),
        &verification.measurement_publisher_key,
        &env.data_dir,
        &init_chain,
    )
    .await?;
    let trust_anchors = init::load_tls_trust_anchors(
        &verification.gcp_ak_root_cert,
        &verification.azure_maa_key,
        &verification.amd_ark_root_cert,
        &verification.amd_snp_crl,
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

    let verified_tls = init::bootstrap_portal_tls_with_trust_config(
        &host,
        status_port,
        measurement_policy,
        None,
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
    let (init_chain, trusted_binding) = match portal.chain_name.as_deref() {
        Some(name) => match config.chains.get(name) {
            Some(chain) => {
                let prover = chain
                    .prover
                    .as_ref()
                    .and_then(|prover| config.provers.get(prover));
                let init_chain =
                    init_chain_from_config(name, chain, portal.registration.as_deref(), prover)
                        .await?;
                let trusted_binding = resolve_trusted_session_binding(name, chain).await?;
                (init_chain, Some(trusted_binding))
            }
            None => bail!("chain '{name}' not found in [chains]"),
        },
        None if registration_is_off(portal.registration.as_deref()) => {
            (synthesize_off_init_chain(), None)
        }
        None => bail!("no chain config is available for verifier trust lookup"),
    };
    let workload_id = crate::commands::workload::compute_workload_id(
        &portal.state.workload_name,
        &portal.state.workload_version,
    );
    let workload_policy = resolve_trusted_workload_policy(
        &portal.state,
        portal.registration.as_deref(),
        verification,
        &init_chain,
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
        trusted_binding,
    })
}

pub(crate) async fn resolve_trusted_session_binding(
    chain_name: &str,
    chain: &ChainConfig,
) -> Result<TrustedSessionBinding> {
    let registry: Address = chain.session_registry.parse().with_context(|| {
        format!(
            "invalid session_registry address in chain '{chain_name}': {}",
            chain.session_registry
        )
    })?;
    let provider = NetworkProvider::with_http(
        &chain.rpc_url,
        Some(Duration::from_secs(1)),
        Some(Duration::from_secs(37)),
        100,
    )
    .await
    .with_context(|| format!("connect to rpc_url for chain '{chain_name}'"))?;
    let chain_id = provider.chain_id();
    if let Some(configured) = chain.chain_id {
        if configured != chain_id {
            bail!(
                "chain_id in chain '{chain_name}' is {configured}, but its rpc_url reports {chain_id}"
            );
        }
    }
    Ok(TrustedSessionBinding {
        chain_id,
        registry: registry.into_array(),
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
    has_base_image: bool,
    has_explicit_measurements: bool,
    local_pack_exists: bool,
    has_configured_base_image_registry: bool,
    registration: Option<&str>,
) -> bool {
    has_base_image
        && !has_explicit_measurements
        && !local_pack_exists
        && !has_configured_base_image_registry
        && !registration_is_off(registration)
}

async fn resolve_trusted_workload_policy(
    state: &DeployState,
    registration: Option<&str>,
    verification: &SessionVerificationArgs,
    init_chain: &InitChainConfig,
    workload_id: [u8; 32],
    selected_base_image_id: Option<[u8; 32]>,
) -> Result<TrustedWorkloadSessionPolicy> {
    let registry_available =
        init_chain.workload_registry != super::ZERO_ADDR && !init_chain.rpc_url.trim().is_empty();
    let manual_pcr23 = verification.trusted_workload_pcr23.as_deref();
    let mut policy = if !registration_is_off(registration) || registry_available {
        load_registered_workload_policy(
            &state.workload_name,
            &state.workload_version,
            init_chain,
            workload_id,
            selected_base_image_id.ok_or_else(|| {
                anyhow::anyhow!("TLS verification did not select a base image ID")
            })?,
        )
        .await?
    } else if manual_pcr23.is_some() {
        TrustedWorkloadSessionPolicy {
            workload_id,
            pcr_specs: Vec::new(),
            attribute_requirements: Vec::new(),
        }
    } else {
        load_local_workload_policy(state, workload_id).await?
    };

    if let Some(value) = manual_pcr23 {
        policy.pcr_specs.push(static_pcr23_policy(decode_hex_32(
            value,
            "--trusted-workload-pcr23",
        )?));
    }
    Ok(policy)
}

async fn load_registered_workload_policy(
    expected_name: &str,
    expected_version: &str,
    init_chain: &InitChainConfig,
    workload_id: [u8; 32],
    selected_base_image_id: [u8; 32],
) -> Result<TrustedWorkloadSessionPolicy> {
    let registry_address: Address = init_chain.workload_registry.parse().with_context(|| {
        format!(
            "invalid configured WorkloadRegistry address: {}",
            init_chain.workload_registry
        )
    })?;
    let provider = NetworkProvider::with_http(
        &init_chain.rpc_url,
        Some(Duration::from_secs(1)),
        Some(Duration::from_secs(37)),
        100,
    )
    .await
    .context("connect to configured WorkloadRegistry RPC")?;
    let registry = WorkloadRegistry::new(registry_address, provider);
    let spec = registry
        .get_workload_spec(B256::from(workload_id))
        .await
        .with_context(|| {
            format!(
                "resolve trusted WorkloadSpec 0x{} from configured WorkloadRegistry",
                hex::encode(workload_id)
            )
        })?;

    trusted_policy_from_workload_spec(
        expected_name,
        expected_version,
        workload_id,
        selected_base_image_id,
        &spec,
    )
}

fn trusted_policy_from_workload_spec(
    expected_name: &str,
    expected_version: &str,
    workload_id: [u8; 32],
    selected_base_image_id: [u8; 32],
    spec: &WorkloadSpec,
) -> Result<TrustedWorkloadSessionPolicy> {
    if spec.name != expected_name || spec.version != expected_version {
        bail!(
            "trusted WorkloadSpec identity {}/{} does not match expected workload {}/{}",
            spec.name,
            spec.version,
            expected_name,
            expected_version
        );
    }
    ensure_base_image_allowed(
        spec.baseImageMode,
        &spec.baseImageIds,
        B256::from(selected_base_image_id),
    )?;

    let pcr_specs = spec
        .pcrs
        .iter()
        .map(|spec| {
            Ok(SessionPcrPolicy {
                pcr_index: spec.pcrIndex,
                verify_type: match spec.verifyType {
                    0 => SessionPcrVerifyType::Static,
                    1 => SessionPcrVerifyType::DynamicSubset,
                    2 => SessionPcrVerifyType::DynamicSubsequence,
                    value => bail!(
                        "trusted WorkloadSpec has unsupported PCR verifyType {value} for PCR{}",
                        spec.pcrIndex
                    ),
                },
                match_data: spec
                    .matchData
                    .iter()
                    .map(|value| format!("0x{}", hex::encode(value)))
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let attribute_requirements = spec
        .requirements
        .iter()
        .map(|requirement| SessionAttributeRequirement {
            key: requirement.key.0,
            allowed_values: requirement
                .allowedValues
                .iter()
                .map(|value| value.0)
                .collect(),
        })
        .collect();

    Ok(TrustedWorkloadSessionPolicy {
        workload_id,
        pcr_specs,
        attribute_requirements,
    })
}

async fn load_local_workload_policy(
    state: &DeployState,
    workload_id: [u8; 32],
) -> Result<TrustedWorkloadSessionPolicy> {
    let archive_path = Path::new(&state.archive_path);
    if archive_path.extension().and_then(|value| value.to_str()) != Some("atawl") {
        bail!(
            "saved workload archive {} is not a .atawl file; provide --trusted-workload-pcr23",
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
        pcr_specs: vec![static_pcr23_policy(decode_hex_32(
            &inspection.pcr23,
            "trusted workload archive PCR23",
        )?)],
        attribute_requirements: inspection
            .manifest
            .config
            .tee_attributes
            .iter()
            .map(|(name, values)| {
                let attribute = atakit_core::tee_attributes::VerifiedTeeAttribute::from_name(name)
                    .ok_or_else(|| {
                        anyhow::anyhow!("unknown config.tee-attributes name `{name}`")
                    })?;
                if !atakit_core::tee_attributes::validate_allowed_values(values) {
                    bail!("config.tee-attributes `{name}` must be [false] or [false, true]");
                }
                Ok(SessionAttributeRequirement {
                    key: attribute.key(),
                    allowed_values: values
                        .iter()
                        .map(|value| atakit_core::tee_attributes::bool_value(*value))
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn ensure_base_image_allowed(mode: u8, configured: &[B256], selected: B256) -> Result<()> {
    let allowed = match mode {
        0 => true,
        1 => !configured.contains(&selected),
        2 => configured.contains(&selected),
        value => bail!("trusted WorkloadSpec has unsupported baseImageMode {value}"),
    };
    if !allowed {
        bail!(
            "TLS-selected base image 0x{} is not allowed by the trusted WorkloadSpec",
            hex::encode(selected)
        );
    }
    Ok(())
}

pub(crate) fn static_pcr23_policy(value: [u8; 32]) -> SessionPcrPolicy {
    SessionPcrPolicy {
        pcr_index: 23,
        verify_type: SessionPcrVerifyType::Static,
        match_data: vec![format!("0x{}", hex::encode(value))],
    }
}

pub(crate) fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("decode {label} as hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 32 bytes"))
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
    use automata_tee_workload_measurement::stubs::WorkloadRegistry::{
        AttributeRequirement, PcrSpec,
    };
    use tempfile::TempDir;

    use super::*;

    fn deployed_state(archive_path: String, archive_hash: String) -> DeployState {
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "instance".into(),
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
            "meta": {"format": 6, "name": "test", "version": "v0.0.1"},
            "config": {
                "image": "test:v0.0.1",
                "base-image-mode": "blacklist",
                "base-image": [],
                "tee-attributes": {
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
    fn local_tls_measurements_defer_session_registry_derivation() {
        assert!(!tls_needs_registry_derivation(
            true,
            true,
            false,
            false,
            Some("required"),
        ));
        assert!(!tls_needs_registry_derivation(
            true,
            false,
            true,
            false,
            Some("required"),
        ));
        assert!(!tls_needs_registry_derivation(
            true,
            false,
            false,
            true,
            Some("required"),
        ));
        assert!(!tls_needs_registry_derivation(
            true,
            false,
            false,
            false,
            Some("off"),
        ));
        assert!(tls_needs_registry_derivation(
            true,
            false,
            false,
            false,
            Some("required"),
        ));
    }

    #[test]
    fn workload_spec_converts_all_pcrs_requirements_and_base_image_policy() {
        let state = deployed_state(String::new(), String::new());
        let selected_base_image = B256::repeat_byte(0x44);
        let spec = WorkloadSpec {
            name: "test".into(),
            version: "v0.0.1".into(),
            ttl: 0,
            baseImageMode: 2,
            baseImageIds: vec![selected_base_image],
            requirements: vec![AttributeRequirement {
                key: B256::repeat_byte(0xaa),
                allowedValues: vec![B256::repeat_byte(0xbb)],
            }],
            pcrs: vec![
                PcrSpec {
                    pcrIndex: 20,
                    verifyType: 2,
                    matchData: vec![B256::repeat_byte(0x20)],
                },
                PcrSpec {
                    pcrIndex: 23,
                    verifyType: 0,
                    matchData: vec![B256::repeat_byte(0x23)],
                },
            ],
        };

        let policy = trusted_policy_from_workload_spec(
            &state.workload_name,
            &state.workload_version,
            [0x11; 32],
            selected_base_image.0,
            &spec,
        )
        .unwrap();
        assert_eq!(policy.workload_id, [0x11; 32]);
        assert_eq!(policy.pcr_specs.len(), 2);
        assert_eq!(policy.pcr_specs[0].pcr_index, 20);
        assert_eq!(
            policy.pcr_specs[0].verify_type,
            SessionPcrVerifyType::DynamicSubsequence
        );
        assert_eq!(policy.pcr_specs[1].pcr_index, 23);
        assert_eq!(
            policy.pcr_specs[1].verify_type,
            SessionPcrVerifyType::Static
        );
        assert_eq!(policy.attribute_requirements.len(), 1);
        assert_eq!(policy.attribute_requirements[0].key, [0xaa; 32]);
        assert_eq!(
            policy.attribute_requirements[0].allowed_values,
            [[0xbb; 32]]
        );
    }

    #[test]
    fn workload_spec_base_image_modes_are_enforced() {
        let selected = B256::repeat_byte(0x11);
        let other = B256::repeat_byte(0x22);
        ensure_base_image_allowed(0, &[], selected).unwrap();
        ensure_base_image_allowed(1, &[other], selected).unwrap();
        ensure_base_image_allowed(2, &[selected], selected).unwrap();
        assert!(ensure_base_image_allowed(1, &[selected], selected).is_err());
        assert!(ensure_base_image_allowed(2, &[other], selected).is_err());
        assert!(ensure_base_image_allowed(3, &[], selected).is_err());
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
        assert_eq!(policy.pcr_specs.len(), 1);
        assert_eq!(policy.pcr_specs[0].pcr_index, 23);
        assert_eq!(
            policy.pcr_specs[0].verify_type,
            SessionPcrVerifyType::Static
        );
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
    async fn manually_trusted_workload_pcr23_is_available_without_a_local_archive() {
        let state = deployed_state("/missing/workload.atawl".into(), String::new());
        let verification = SessionVerificationArgs {
            trusted_workload_pcr23: Some(format!("0x{}", hex::encode([0x55; 32]))),
            ..Default::default()
        };
        let init_chain = super::super::synthesize_off_init_chain();

        let policy = resolve_trusted_workload_policy(
            &state,
            Some("off"),
            &verification,
            &init_chain,
            [0x66; 32],
            None,
        )
        .await
        .unwrap();
        assert_eq!(policy.pcr_specs, [static_pcr23_policy([0x55; 32])]);
    }
}
