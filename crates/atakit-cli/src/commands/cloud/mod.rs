pub mod deploy;
pub mod destroy;
pub mod image;
pub mod init;
pub mod list;
pub mod provider;
pub mod serial;
pub mod session;
mod session_access;
pub mod ssh;
pub mod status;
pub mod verify_session;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use alloy_ext::core::primitives::Address;
use alloy_ext::ext::NetworkProvider;
use anyhow::{bail, Context, Result};
use atakit_attestation::{
    BaseImage, MeasurementPack, MeasurementPolicy, MeasurementProfile, MeasurementVariant, PcrSpec,
};
use atakit_cloud::aws::AwsProvider;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cloud_images::{CloudImage, CloudImages};
use atakit_cloud::config::CloudProviderConfig;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::init::{InitChainConfig, InitKeyConfig, InitProverConfig, PortalTerminalState};
use atakit_cloud::plan::DeployStep;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::{
    AzureResourceNames, CloudTarget, DeployState, DeployStatus, PersistedInitEnv, PlatformKind,
    ProcessRunner,
};
use atakit_core::Env;
use atakit_image::{import_image_archive, ImageRef, ImageStore, Platform as ImagePlatform};
use atakit_workload::WorkloadStore;
use automata_tee_workload_measurement::base_image_registry::{
    BaseImageHierarchy, BaseImageRegistry,
};
use automata_tee_workload_measurement::stubs::SessionRegistry::SessionRegistryInstance;
use automata_tee_workload_measurement::types::AppRef;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::config::{ChainConfig, Config, KeyMode, KeySpec, ProverSpec};

pub(crate) const WAIT_FOR_PORTAL_RUNNING_STEP: &str = "Wait for portal Running";

pub(crate) fn terminal_initialization_error(
    target_name: &str,
    instance_name: &str,
    error: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::anyhow!(
        "{error}; this deployment cannot resume after portal initialization; run `atakit cloud destroy {instance_name} --target {target_name}`, then run `atakit cloud deploy` again"
    )
}

pub(crate) fn persist_portal_terminal_failure(
    state: &mut DeployState,
    data_dir: &Path,
    target_name: &str,
    instance_name: &str,
    terminal: PortalTerminalState,
) -> Result<anyhow::Error> {
    let detail = match terminal {
        PortalTerminalState::Failed { detail } if detail.is_empty() => {
            "portal reached terminal Failed state".to_string()
        }
        PortalTerminalState::Failed { detail } => {
            format!("portal reached terminal Failed state: {detail}")
        }
        PortalTerminalState::CleanHalt { detail } if detail.is_empty() => {
            "portal reached terminal CleanHalt state".to_string()
        }
        PortalTerminalState::CleanHalt { detail } => {
            format!("portal reached terminal CleanHalt state: {detail}")
        }
        PortalTerminalState::Running => bail!("cannot persist Running as a terminal failure"),
    };
    let error = terminal_initialization_error(target_name, instance_name, detail);
    state.set_status(
        DeployStatus::Failed {
            step: WAIT_FOR_PORTAL_RUNNING_STEP.to_string(),
            message: error.to_string(),
        },
        data_dir,
    )?;
    Ok(error)
}

/// Resolve init env references with precedence: CLI > target config.
pub struct InitEnvResolver<'a> {
    pub cli_chain: Option<&'a str>,
    pub cli_owner_key: Option<&'a str>,
    pub cli_gas_wallet: Option<&'a str>,
    pub target: &'a CloudTarget,
}

impl<'a> InitEnvResolver<'a> {
    pub fn chain_optional(&self) -> Option<String> {
        self.cli_chain
            .map(String::from)
            .or_else(|| self.target.chain.clone())
            .filter(|value| !value.is_empty())
    }

    /// Optional backend-neutral prover credential. Read from the target after
    /// `[cloud.defaults]` has been applied.
    pub fn prover_credential(&self) -> Option<String> {
        self.target.prover_credential.clone()
    }

    /// Resolve persisted init references without panicking on missing fields.
    /// Used when no `/init` will be sent or qemu zero-config deploy is allowed.
    pub fn build_optional(&self) -> PersistedInitEnv {
        PersistedInitEnv {
            chain: self.chain_optional().unwrap_or_default(),
            owner_key: self
                .cli_owner_key
                .map(String::from)
                .or_else(|| self.target.owner_key.clone())
                .unwrap_or_default(),
            gas_wallet: self
                .cli_gas_wallet
                .map(String::from)
                .or_else(|| self.target.gas_wallet.clone())
                .unwrap_or_default(),
            prover_credential: self.prover_credential(),
        }
    }
}

/// Resolve the separately named credential used by a prover. A chain profile
/// takes precedence over the persisted or target value. The gas wallet is not
/// a prover credential.
pub(crate) fn effective_prover_credential(
    config: &Config,
    chain_name: Option<&str>,
    fallback: Option<String>,
    registration_off: bool,
) -> Result<Option<String>> {
    if registration_off {
        return Ok(None);
    }
    let chain = chain_name.and_then(|name| config.chains.get(name));
    let prover = chain
        .and_then(|chain| chain.prover.as_deref())
        .and_then(|name| config.provers.get(name));
    let credential = prover
        .and_then(|prover| prover.credential.clone())
        .or_else(|| fallback.filter(|value| !value.is_empty()));
    let explicit_network_prover = prover.is_some_and(|prover| prover.execution == "network");
    if explicit_network_prover && credential.is_none() {
        bail!(
            "the selected network prover requires a separately named prover_credential; configure it on the prover profile, cloud target, or [cloud.defaults]"
        );
    }
    Ok(credential)
}

#[cfg(test)]
mod prover_credential_tests {
    use super::*;

    fn config() -> Config {
        Config::load_from_str(
            r#"
            [keys.profile]
            type = "es256k"
            mode = "self_generated"

            [keys.target]
            type = "es256k"
            mode = "self_generated"

            [keys.gas]
            type = "es256k"
            mode = "self_generated"

            [provers.sp1]
            backend = "sp1"
            credential = "profile"

            [chains.primary]
            rpc_url = "https://rpc.example"
            session_registry = "0x1"
            prover = "sp1"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn profile_precedes_persisted_target() {
        let config = config();
        assert_eq!(
            effective_prover_credential(&config, Some("primary"), Some("target".into()), false,)
                .unwrap()
                .as_deref(),
            Some("profile")
        );
    }

    #[test]
    fn fallback_and_registration_off_are_deterministic() {
        let config = config();
        assert_eq!(
            effective_prover_credential(&config, Some("unknown"), Some("target".into()), false,)
                .unwrap()
                .as_deref(),
            Some("target")
        );
        assert_eq!(
            effective_prover_credential(&config, Some("primary"), Some("target".into()), true,)
                .unwrap(),
            None
        );
    }

    #[test]
    fn network_prover_requires_a_separate_credential() {
        let config = Config::load_from_str(
            r#"
            [provers.sp1]
            backend = "sp1"
            execution = "network"

            [chains.primary]
            rpc_url = "https://rpc.example"
            session_registry = "0x1"
            prover = "sp1"
            "#,
        )
        .unwrap();
        let error = effective_prover_credential(&config, Some("primary"), None, false).unwrap_err();
        assert!(error
            .to_string()
            .contains("separately named prover_credential"));
    }
}

/// Zero-address placeholder used when the init chain is explicitly off.
/// The portal never submits anything when registration is "off", so the
/// value is only a structural placeholder for the JSON shape.
pub(crate) const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

/// Build an off-chain InitChainConfig: registration "off", placeholder
/// addresses, no RPC. The portal accepts a chain section with no `rpc_url`
/// when `registration = "off"`.
pub(crate) fn synthesize_off_init_chain() -> InitChainConfig {
    InitChainConfig {
        rpc_url: String::new(),
        session_registry: ZERO_ADDR.to_string(),
        workload_registry: ZERO_ADDR.to_string(),
        base_image_registry: ZERO_ADDR.to_string(),
        registration: Some("off".to_string()),
        chain_id: None,
        tee_backend: "auto".to_string(),
        prover: None,
    }
}

pub(crate) fn registration_is_off(registration: Option<&str>) -> bool {
    registration == Some("off")
}

pub(crate) fn synthesize_self_generated_key() -> InitKeyConfig {
    InitKeyConfig {
        mode: "self_generated".to_string(),
        key_type: "es256k".to_string(),
        private_key: None,
    }
}

pub(crate) fn warn_unsafe_skip_tls_attestation() {
    eprintln!(
        "{}",
        "WARNING: --unsafe-skip-tls-attestation disables portal TLS attestation and accepts the self-signed certificate without verification."
            .yellow()
    );
}

pub(crate) async fn resolve_tls_measurement_policy(
    measurements: Option<&std::path::Path>,
    base_image: Option<&str>,
    measurement_publisher_keys: &[String],
    data_dir: &std::path::Path,
    init_chain: &InitChainConfig,
) -> Result<Option<MeasurementPolicy>> {
    if measurements.is_some() {
        return atakit_cloud::init::load_measurement_policy(
            measurements,
            base_image,
            measurement_publisher_keys,
            Some(data_dir),
        )
        .map_err(|e| anyhow::anyhow!("{e}"));
    }

    let Some(base_image_ref) = base_image else {
        return Ok(None);
    };

    if atakit_cloud::init::local_measurement_pack_exists(data_dir, base_image_ref)
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        return atakit_cloud::init::load_measurement_policy(
            None,
            Some(base_image_ref),
            measurement_publisher_keys,
            Some(data_dir),
        )
        .map_err(|e| anyhow::anyhow!("{e}"));
    }

    if chain_measurement_policy_available(init_chain) {
        return Ok(Some(
            load_measurement_policy_from_chain(base_image_ref, init_chain).await?,
        ));
    }

    atakit_cloud::init::load_measurement_policy(
        None,
        Some(base_image_ref),
        measurement_publisher_keys,
        Some(data_dir),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Resolve base-image measurement collateral from sources selected by the
/// verifier. An explicit measurement path wins; otherwise the verifier's
/// selected chain is used. The automatic deployment-local cache is
/// intentionally excluded from this path.
pub(crate) async fn resolve_verifier_tls_measurement_policy(
    measurements: Option<&std::path::Path>,
    base_image: &str,
    measurement_publisher_keys: &[String],
    data_dir: &std::path::Path,
    chain_client: Option<&atakit_attestation_client::AttestationClient>,
) -> Result<MeasurementPolicy> {
    if measurements.is_some() {
        return atakit_cloud::init::load_measurement_policy(
            measurements,
            Some(base_image),
            measurement_publisher_keys,
            Some(data_dir),
        )
        .map_err(|error| anyhow::anyhow!("{error}"))?
        .ok_or_else(|| anyhow::anyhow!("explicit measurement source returned no policy"));
    }

    if let Some(chain_client) = chain_client {
        return chain_client
            .resolve_base_image_measurement_policy(base_image)
            .await
            .map_err(anyhow::Error::new);
    }

    bail!(
        "no trusted base-image measurement collateral is available; select a verifier chain with --chain or provide --measurements"
    )
}

fn chain_measurement_policy_available(init_chain: &InitChainConfig) -> bool {
    init_chain.base_image_registry != ZERO_ADDR && !init_chain.rpc_url.trim().is_empty()
}

async fn load_measurement_policy_from_chain(
    base_image: &str,
    init_chain: &InitChainConfig,
) -> Result<MeasurementPolicy> {
    let app_ref: AppRef = base_image.parse()?;
    let base_image_id = BaseImageRegistry::get_image_id(&app_ref);
    let registry_addr: Address = init_chain.base_image_registry.parse().with_context(|| {
        format!(
            "invalid base_image_registry address for TLS measurement lookup: {}",
            init_chain.base_image_registry
        )
    })?;
    let provider = NetworkProvider::with_http(
        &init_chain.rpc_url,
        Some(Duration::from_secs(1)),
        Some(Duration::from_secs(37)),
        100,
    )
    .await
    .with_context(|| {
        format!(
            "failed to connect to rpc_url for TLS measurement lookup: {}",
            init_chain.rpc_url
        )
    })?;
    let hierarchy = BaseImageRegistry::new(registry_addr, provider)
        .get_hierarchy(base_image_id)
        .await
        .with_context(|| format!("failed to fetch BaseImageRegistry hierarchy for {base_image}"))?;

    chain_hierarchy_to_measurement_policy(&hierarchy, &init_chain.base_image_registry)
}

fn chain_hierarchy_to_measurement_policy(
    hierarchy: &BaseImageHierarchy,
    registry: &str,
) -> Result<MeasurementPolicy> {
    let profiles = hierarchy
        .profiles
        .iter()
        .map(|profile| {
            let (cloud, tee) = infer_cloud_tee_from_profile_name(&profile.profile.name)?;
            let variants = profile
                .variants
                .iter()
                .map(|(variant_id, variant)| MeasurementVariant {
                    name: variant.name.clone(),
                    id: hex0x(variant_id),
                    machine_types: vec![variant.name.clone()],
                    override_pcrs: variant
                        .overridePcrs
                        .iter()
                        .map(chain_pcr_spec_to_measurement)
                        .collect(),
                    attributes: variant
                        .attributes
                        .iter()
                        .map(|attr| {
                            serde_json::json!({
                                "key": hex0x(attr.key),
                                "value": hex0x(attr.value),
                            })
                        })
                        .collect(),
                })
                .collect();
            Ok(MeasurementProfile {
                name: profile.profile.name.clone(),
                id: hex0x(profile.profile_id),
                cloud: cloud.to_string(),
                tee: tee.to_string(),
                invariants: profile
                    .profile
                    .invariants
                    .iter()
                    .map(chain_pcr_spec_to_measurement)
                    .collect(),
                variants,
                attributes: profile
                    .profile
                    .attributes
                    .iter()
                    .map(|attr| {
                        serde_json::json!({
                            "key": hex0x(attr.key),
                            "value": hex0x(attr.value),
                        })
                    })
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(MeasurementPolicy {
        source: format!("chain:{registry}:{}", hex0x(hierarchy.base_image_id)),
        pack: MeasurementPack {
            schema: "atakit.measurement-pack.v1".to_string(),
            revision: 1,
            published_at: chrono::Utc::now().to_rfc3339(),
            base_image: BaseImage {
                name: hierarchy.spec.name.clone(),
                version: hierarchy.spec.version.clone(),
                id: hex0x(hierarchy.base_image_id),
                uri: if hierarchy.spec.uri.is_empty() {
                    None
                } else {
                    Some(hierarchy.spec.uri.clone())
                },
                archive_sha256: None,
            },
            profiles,
        },
    })
}

fn chain_pcr_spec_to_measurement(
    spec: &automata_tee_workload_measurement::stubs::BaseImageRegistry::PcrSpec,
) -> PcrSpec {
    PcrSpec {
        pcr_index: spec.pcrIndex,
        verify_type: match spec.verifyType {
            0 => "static".to_string(),
            1 => "dynamicSubset".to_string(),
            2 => "dynamicSubsequence".to_string(),
            other => format!("unknown-{other}"),
        },
        match_data: spec.matchData.iter().map(hex0x).collect(),
        event_indices: Vec::new(),
        total_events: None,
    }
}

fn infer_cloud_tee_from_profile_name(name: &str) -> Result<(&'static str, &'static str)> {
    let normalized = name.to_ascii_lowercase().replace('_', "-");
    let cloud = if normalized.starts_with("gcp-") || normalized.contains("-gcp-") {
        "gcp"
    } else if normalized.starts_with("azure-") || normalized.contains("-azure-") {
        "azure"
    } else if normalized.starts_with("aws-") || normalized.contains("-aws-") {
        "aws"
    } else {
        bail!(
            "cannot infer cloud from BaseImageRegistry platform profile name {:?}; \
             expected names like gcp-tdx, gcp-sev-snp, azure-tdx, azure-sev-snp, or aws-sev-snp",
            name
        );
    };
    let tee = if normalized.contains("tdx") {
        "tdx"
    } else if normalized.contains("sev-snp") || normalized.contains("snp") {
        "sev-snp"
    } else if normalized.contains("nitro") {
        "nitro"
    } else {
        bail!(
            "cannot infer TEE from BaseImageRegistry platform profile name {:?}; \
             expected names containing tdx, sev-snp, snp, or nitro",
            name
        );
    };
    Ok((cloud, tee))
}

fn hex0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub(crate) fn init_key_from_config(
    key_name: &str,
    spec: &KeySpec,
    require_private_key: bool,
) -> Result<InitKeyConfig> {
    Ok(InitKeyConfig {
        mode: spec.mode.to_string(),
        key_type: spec.key_type.to_string(),
        private_key: if require_private_key || spec.mode == KeyMode::Provisioned {
            Some(spec.resolve(key_name)?)
        } else {
            None
        },
    })
}

#[derive(Debug, Clone)]
struct ChainRegistries {
    workload_registry: String,
    base_image_registry: String,
}

pub(crate) async fn init_chain_from_config(
    chain_name: &str,
    chain: &ChainConfig,
    registration: Option<&str>,
    prover: Option<&ProverSpec>,
) -> Result<InitChainConfig> {
    let registries = if registration_is_off(registration) {
        None
    } else {
        Some(derive_registries_from_session(chain_name, chain).await?)
    };
    build_init_chain_config(chain_name, chain, registration, registries.as_ref(), prover)
}

async fn derive_registries_from_session(
    chain_name: &str,
    chain: &ChainConfig,
) -> Result<ChainRegistries> {
    let session_registry: Address = chain.session_registry.parse().with_context(|| {
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
    .with_context(|| {
        format!(
            "failed to connect to rpc_url for chain '{chain_name}': {}",
            chain.rpc_url
        )
    })?;
    let registry = SessionRegistryInstance::new(session_registry, provider);

    let workload_registry = registry
        .workloadRegistry()
        .call()
        .await
        .with_context(|| {
            format!(
                "failed to derive workload_registry from session_registry in chain '{chain_name}'"
            )
        })?
        .to_string();
    let base_image_registry = registry
        .baseImageRegistry()
        .call()
        .await
        .with_context(|| {
            format!(
                "failed to derive base_image_registry from session_registry in chain '{chain_name}'"
            )
        })?
        .to_string();

    Ok(ChainRegistries {
        workload_registry,
        base_image_registry,
    })
}

fn build_init_chain_config(
    chain_name: &str,
    chain: &ChainConfig,
    registration: Option<&str>,
    registries: Option<&ChainRegistries>,
    prover: Option<&ProverSpec>,
) -> Result<InitChainConfig> {
    let placeholder_ok = registration_is_off(registration);
    let workload_registry = resolve_registry_address(
        chain_name,
        "workload_registry",
        chain.workload_registry.as_deref(),
        registries.map(|r| r.workload_registry.as_str()),
        placeholder_ok,
    )?;
    let base_image_registry = resolve_registry_address(
        chain_name,
        "base_image_registry",
        chain.base_image_registry.as_deref(),
        registries.map(|r| r.base_image_registry.as_str()),
        placeholder_ok,
    )?;

    let prover = prover.map(|prover| InitProverConfig {
        backend: prover.backend.clone(),
        execution: prover.execution.clone(),
        endpoint: prover.endpoint.clone(),
        credential: prover.credential.clone(),
        options: prover
            .options
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    });
    Ok(InitChainConfig {
        rpc_url: chain.rpc_url.clone(),
        session_registry: chain.session_registry.clone(),
        workload_registry,
        base_image_registry,
        registration: registration.map(str::to_string),
        chain_id: chain.chain_id,
        tee_backend: chain.tee_backend.clone(),
        prover,
    })
}

fn resolve_registry_address(
    chain_name: &str,
    field: &str,
    configured: Option<&str>,
    derived: Option<&str>,
    placeholder_ok: bool,
) -> Result<String> {
    match (configured, derived) {
        (Some(configured), Some(derived)) => {
            ensure_same_address(chain_name, field, configured, derived)?;
            Ok(configured.to_string())
        }
        (Some(configured), None) => Ok(configured.to_string()),
        (None, Some(derived)) => Ok(derived.to_string()),
        (None, None) if placeholder_ok => Ok(ZERO_ADDR.to_string()),
        (None, None) => {
            bail!("{field} required in chain '{chain_name}' or derivable from session_registry")
        }
    }
}

fn ensure_same_address(
    chain_name: &str,
    field: &str,
    configured: &str,
    derived: &str,
) -> Result<()> {
    let configured_addr = parse_registry_address(chain_name, field, configured)?;
    let derived_addr = parse_registry_address(chain_name, field, derived)?;
    if configured_addr != derived_addr {
        bail!(
            "{field} in chain '{chain_name}' does not match session_registry: configured {configured}, derived {derived}"
        );
    }
    Ok(())
}

fn parse_registry_address(chain_name: &str, field: &str, value: &str) -> Result<Address> {
    value
        .parse()
        .with_context(|| format!("invalid {field} address in chain '{chain_name}': {value}"))
}

/// Parse instance reference: "target/instance" or just "instance".
pub fn parse_instance_ref(s: &str) -> (Option<&str>, &str) {
    if let Some((target, instance)) = s.split_once('/') {
        (Some(target), instance)
    } else {
        (None, s)
    }
}

/// Resolve an instance reference to (target_name, instance_name) using the state store.
pub fn resolve_instance(
    data_dir: &std::path::Path,
    instance: &str,
    target_filter: Option<&str>,
) -> Result<(String, String)> {
    let (embedded_target, instance_name) = parse_instance_ref(instance);
    let target = target_filter.or(embedded_target);
    atakit_cloud::state::find_instance(data_dir, instance_name, target)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Resolved base image: display name for the plan + optional local file path.
pub(super) struct ResolvedImage {
    /// Human-readable name (image ref or GCE image name).
    pub display_name: String,
    /// Local disk image file path for upload. `None` means the image is
    /// assumed to already exist in GCE.
    pub source_path: Option<String>,
    /// Local secure-boot cert directory from the image store, if available.
    pub certs_dir: Option<String>,
}

/// Resolve the `--image` argument into a display name and optional source path.
///
/// Three cases:
/// 1. Ends with `.atabi` - import into store, then resolve from store.
/// 2. Contains `:` (ImageRef) - look up in ImageStore for the target
///    platform's disk image. If found locally, use as source_path.
///    If not found, treat as existing GCE image name.
/// 3. Otherwise - bare GCE image name, no upload needed.
pub(super) fn resolve_image(
    image_arg: &str,
    platform: &PlatformKind,
    env: &Env,
) -> Result<ResolvedImage> {
    let store = ImageStore::new(&env.image_dir);

    if image_arg.ends_with(".atabi") {
        // Import .atabi archive, then resolve from store.
        let archive_path = PathBuf::from(image_arg);
        if !archive_path.exists() {
            bail!("archive not found: {image_arg}");
        }
        let image_ref = import_image_archive(&archive_path, store.base_dir())
            .with_context(|| format!("failed to import {image_arg}"))?;
        eprintln!("  Imported {} from .atabi archive", image_ref);
        return resolve_store_image(&store, &image_ref, platform);
    }

    if image_arg.contains(':') {
        // Parse as ImageRef (repository:tag).
        let image_ref: ImageRef = image_arg
            .parse()
            .with_context(|| format!("invalid image reference: {image_arg}"))?;
        if store.exists(&image_ref) {
            return resolve_store_image(&store, &image_ref, platform);
        }
        bail!(
            "image {} not found in store (run 'atakit image pull {}' first, \
             or 'atakit image ls --remote' to check available releases)",
            image_ref,
            image_ref,
        );
    }

    // Bare name - existing GCE image.
    Ok(ResolvedImage {
        display_name: image_arg.to_string(),
        source_path: None,
        certs_dir: None,
    })
}

/// Look up a disk image file in the store for the target platform.
fn resolve_store_image(
    store: &ImageStore,
    image_ref: &ImageRef,
    platform: &PlatformKind,
) -> Result<ResolvedImage> {
    let image_platform = match platform {
        PlatformKind::Gcp => ImagePlatform::Gcp,
        PlatformKind::Azure => ImagePlatform::Azure,
        PlatformKind::Aws => ImagePlatform::Aws,
        PlatformKind::Qemu => ImagePlatform::Qemu,
    };

    let disk_path = store.image_path(image_ref, image_platform);
    if !disk_path.exists() {
        let available = store.local_platforms(image_ref);
        let names: Vec<_> = available.iter().map(|p| p.to_string()).collect();
        bail!(
            "no {} disk image for {} in store (available: {})",
            image_platform,
            image_ref,
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            },
        );
    }

    Ok(ResolvedImage {
        display_name: image_ref.to_string(),
        source_path: Some(disk_path.display().to_string()),
        certs_dir: Some(store.certs_dir(image_ref).display().to_string()),
    })
}

/// Resolved workload source: archive path + name/version + declared ports + disks.
pub(crate) struct ResolvedWorkload {
    pub archive_path: PathBuf,
    /// SHA-256 of the same immutable archive bytes used to parse the manifest.
    pub archive_sha256: [u8; 32],
    pub name: String,
    pub version: String,
    pub ports: Vec<String>,
    /// Disk name -> (index, size string e.g. "10GB", declared unlock_method).
    /// The unlock_method list is carried so deploy/init can validate
    /// `--disk-passphrase` against what each disk actually requires.
    pub disks: BTreeMap<String, (u32, String, Vec<String>)>,
    /// Minimum boot/OS disk size (e.g. "50GB"). None = cloud default.
    pub boot_disk_size: Option<String>,
    /// Base image access control mode: "any", "whitelist", or "blacklist".
    pub base_image_mode: String,
    /// Base image references for whitelist/blacklist filtering.
    pub base_image: Vec<String>,
    /// Verified TEE attribute requirements from the measured manifest.
    pub attributes: atakit_core::tee_attributes::AttributeRequirements,
    /// Declared unmeasured-data allowlist paths from the manifest, as
    /// deploy-relative paths (the `unmeasured-data/` prefix stripped). The
    /// operator may supply any subset of this set at `/init`.
    pub unmeasured_data_paths: Vec<String>,
    /// Workload source directory (available in dir mode, None for store-ref/file modes).
    pub workload_dir: Option<PathBuf>,
}

/// Resolve workload from source arg, falling back to dir mode.
pub(crate) fn resolve_workload(
    source: &Option<String>,
    dir: &Option<PathBuf>,
    env: &Env,
    skip_freshness_check: bool,
) -> Result<ResolvedWorkload> {
    if let Some(ref src) = source {
        // Store reference: name:version
        if crate::commands::workload::looks_like_store_ref(src) {
            let (name, version) = src
                .split_once(':')
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .unwrap();
            let store = WorkloadStore::new(&env.workload_dir);
            let blob = store.blob_path(&name, &version)?;
            if !blob.exists() {
                bail!("no archive blob for {name}:{version} in store");
            }
            let (result, archive_sha256) = inspect_workload_archive_snapshot(&blob)
                .context("failed to inspect store archive")?;
            let disks = result
                .manifest
                .disks
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        (v.index, v.size.clone(), v.encryption.unlock_method.clone()),
                    )
                })
                .collect();
            let ports = collect_firewall_ports(&result.manifest);
            let unmeasured_paths = manifest_unmeasured_paths(&result.manifest);
            return Ok(ResolvedWorkload {
                archive_path: blob,
                archive_sha256,
                name,
                version,
                ports,
                disks,
                boot_disk_size: result.manifest.config.boot_disk_size,
                base_image_mode: result.manifest.config.base_image_mode,
                base_image: result.manifest.config.base_image,
                attributes: result.manifest.config.attributes,
                unmeasured_data_paths: unmeasured_paths,
                workload_dir: None,
            });
        }

        // File path: something.atawl
        let path = PathBuf::from(src);
        if !path.exists() {
            bail!("archive not found: {src}");
        }
        let (result, archive_sha256) =
            inspect_workload_archive_snapshot(&path).context("failed to inspect archive")?;
        let disks = result
            .manifest
            .disks
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    (v.index, v.size.clone(), v.encryption.unlock_method.clone()),
                )
            })
            .collect();
        let ports = collect_firewall_ports(&result.manifest);
        let unmeasured_paths = manifest_unmeasured_paths(&result.manifest);
        return Ok(ResolvedWorkload {
            archive_path: path,
            archive_sha256,
            name: result.manifest.meta.name,
            version: result.manifest.meta.version,
            ports,
            disks,
            boot_disk_size: result.manifest.config.boot_disk_size,
            base_image_mode: result.manifest.config.base_image_mode,
            base_image: result.manifest.config.base_image,
            attributes: result.manifest.config.attributes,
            unmeasured_data_paths: unmeasured_paths,
            workload_dir: None,
        });
    }

    // Dir mode: read atakit-workload.toml, find versioned archive.
    let workload_dir = dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    if !workload_dir.join("atakit-workload.toml").exists() {
        bail!(
            "no workload source specified and no atakit-workload.toml found in {}",
            workload_dir.display(),
        );
    }
    let archive_path = crate::commands::workload::find_versioned_archive(&workload_dir)?;

    // Check if any source file is newer than the archive.
    if !skip_freshness_check {
        if let Ok(archive_meta) = std::fs::metadata(&archive_path) {
            if let Ok(archive_mtime) = archive_meta.modified() {
                if let Some(stale_file) = find_newer_source(&workload_dir, &archive_mtime) {
                    bail!(
                        "'{}' is newer than {} - run 'atakit workload build' first, or pass --skip-freshness-check to skip this check",
                        stale_file.display(),
                        archive_path.display(),
                    );
                }
            }
        }
    }

    let (result, archive_sha256) =
        inspect_workload_archive_snapshot(&archive_path).context("failed to inspect archive")?;
    let ports = collect_firewall_ports(&result.manifest);
    let disks = result
        .manifest
        .disks
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                (v.index, v.size.clone(), v.encryption.unlock_method.clone()),
            )
        })
        .collect();
    // The declared unmeasured-data set comes from the manifest (committed to
    // PCR23), not the source TOML, so every deploy mode resolves the same set.
    let unmeasured_paths = manifest_unmeasured_paths(&result.manifest);
    Ok(ResolvedWorkload {
        archive_path,
        archive_sha256,
        name: result.manifest.meta.name,
        version: result.manifest.meta.version,
        ports,
        disks,
        boot_disk_size: result.manifest.config.boot_disk_size,
        base_image_mode: result.manifest.config.base_image_mode,
        base_image: result.manifest.config.base_image,
        attributes: result.manifest.config.attributes,
        unmeasured_data_paths: unmeasured_paths,
        workload_dir: Some(workload_dir),
    })
}

fn inspect_workload_archive_snapshot(
    archive_path: &Path,
) -> Result<(atakit_workload::InspectResult, [u8; 32])> {
    let bytes = std::fs::read(archive_path)
        .with_context(|| format!("failed to read archive {}", archive_path.display()))?;
    let archive_sha256 = Sha256::digest(&bytes).into();
    let inspection = atakit_workload::inspect_workload_archive_bytes(&bytes)?;
    Ok((inspection, archive_sha256))
}

/// The declared unmeasured-data file paths from the manifest, as deploy-relative
/// paths (the `unmeasured-data/` prefix stripped). This is the authoritative set
/// the operator must supply at `/init`; reading it from the manifest (rather than
/// the source TOML) means it works for archive/store deploys, not just dir mode.
fn manifest_unmeasured_paths(m: &atakit_workload::manifest::Manifest) -> Vec<String> {
    m.unmeasured_data
        .iter()
        .map(|p| p.strip_prefix("unmeasured-data/").unwrap_or(p).to_string())
        .collect()
}

/// Walk a workload directory and return the first file newer than `threshold`.
/// Skips `.git`, `target`, and `.atawl` files. Only compares file mtimes,
/// not directory mtimes (directories update on unrelated changes like new files).
fn find_newer_source(
    dir: &std::path::Path,
    threshold: &std::time::SystemTime,
) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == ".git"
            || name_str == "target"
            || name_str == ".claude"
            || name_str == ".codex"
        {
            continue;
        }
        if name_str.ends_with(".atawl") {
            continue;
        }
        let path = entry.path();
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.is_dir() {
                if let Some(found) = find_newer_source(&path, threshold) {
                    return Some(found);
                }
            } else if let Ok(mtime) = meta.modified() {
                if mtime > *threshold {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Collect resolved firewall ports from a manifest as `"port/proto"` strings.
///
/// Uses the manifest's `firewall_ports` which is the authoritative resolved list:
/// auto-derived from container port mappings + firewall allow - deny.
fn collect_firewall_ports(m: &atakit_workload::manifest::Manifest) -> Vec<String> {
    m.config
        .firewall_ports
        .iter()
        .map(|fp| format!("{}/{}", fp.port, fp.protocol))
        .collect()
}

/// Cloud platforms use the deployment's external IP plus the portal ports
/// persisted at deploy time. QEMU forwards those guest ports to dynamic host
/// ports allocated at boot and persisted in state.
pub(crate) fn portal_endpoints(state: &DeployState) -> Result<(String, u16, u16)> {
    if let Some(ref q) = state.resources.qemu {
        let host = if q.external_ip.is_empty() {
            "127.0.0.1".to_string()
        } else {
            q.external_ip.clone()
        };
        if q.host_status_port == 0 || q.host_init_port == 0 {
            bail!("qemu host ports not yet recorded; StartLocalVm must run first");
        }
        return Ok((host, q.host_status_port, q.host_init_port));
    }

    let ip = state
        .resources
        .gcp
        .as_ref()
        .and_then(|g| g.external_ip.clone())
        .or_else(|| {
            state
                .resources
                .azure
                .as_ref()
                .and_then(|a| a.external_ip.clone())
        })
        .or_else(|| {
            state
                .resources
                .aws
                .as_ref()
                .and_then(|a| a.external_ip.clone())
        })
        .ok_or_else(|| anyhow::anyhow!("no external IP available"))?;
    Ok((ip, state.portal_ports.status, state.portal_ports.init))
}

/// Validate that the given image ref is allowed by the workload's base-image policy.
pub(super) fn validate_base_image(
    image_display_name: &str,
    base_image_mode: &str,
    base_image: &[String],
) -> Result<()> {
    if base_image_mode == "any" {
        return Ok(());
    }

    // Every entry must parse as a valid ImageRef (repository:tag).
    for entry in base_image {
        if entry.parse::<ImageRef>().is_err() {
            bail!(
                "invalid base-image entry '{}': must be repository:tag format \
                 (e.g. 'automata-linux:v0.2.6-debug')",
                entry,
            );
        }
    }

    match base_image_mode {
        "whitelist" => {
            // Empty whitelist = nothing allowed.
            if !base_image.iter().any(|b| b == image_display_name) {
                if base_image.is_empty() {
                    bail!(
                        "image '{}' rejected: base-image-mode is 'whitelist' but \
                         base-image list is empty (no images are allowed)",
                        image_display_name,
                    );
                }
                bail!(
                    "image '{}' is not in the workload's base-image whitelist: [{}]",
                    image_display_name,
                    base_image.join(", "),
                );
            }
        }
        "blacklist" => {
            if base_image.iter().any(|b| b == image_display_name) {
                bail!(
                    "image '{}' is blacklisted by the workload",
                    image_display_name,
                );
            }
        }
        other => {
            bail!(
                "invalid base-image-mode '{}': expected 'any', 'whitelist', or 'blacklist'",
                other,
            );
        }
    }
    Ok(())
}

/// Resolve the operator-supplied unmeasured-data into a tar.gz for `/init`,
/// given the manifest's declared allowlist.
///
/// Gated on the **declared path set** (not the per-container mount boolean),
/// because the portal enforces the manifest's `unmeasured-data` array as an
/// allowlist. Missing declared paths are allowed once a root is supplied; the
/// workload must validate every unmeasured file it consumes. When the manifest
/// declares an allowlist but no root is available, this is a hard error because
/// the operator likely forgot `--unmeasured-data-root`.
pub(crate) fn resolve_unmeasured_tar(
    declared_paths: &[String],
    unmeasured_data_root: Option<&PathBuf>,
) -> Result<Option<Vec<u8>>> {
    if declared_paths.is_empty() {
        return Ok(None);
    }
    let Some(dir) = unmeasured_data_root else {
        bail!(
            "workload declares {} unmeasured-data path(s) but no source directory is available; \
             pass --unmeasured-data-root to upload an allowlisted subset",
            declared_paths.len(),
        );
    };
    collect_unmeasured_tar(declared_paths, dir)
}

pub(crate) fn effective_unmeasured_data_root(
    unmeasured_data_root: Option<&PathBuf>,
    unmeasured_data_dir: Option<&PathBuf>,
    workload_dir: Option<&PathBuf>,
) -> Result<Option<PathBuf>> {
    if unmeasured_data_root.is_some() && unmeasured_data_dir.is_some() {
        bail!("use either --unmeasured-data-root or deprecated --unmeasured-data-dir, not both");
    }
    if let Some(root) = unmeasured_data_root.or(unmeasured_data_dir) {
        return Ok(Some(root.clone()));
    }
    Ok(workload_dir.map(|dir| atakit_workload::data::default_unmeasured_data_root(dir)))
}

/// Collect the operator-provided unmeasured-data files into a gzipped tar,
/// by selecting the declared files that are present under the source root.
///
/// `declared` are paths relative to the unmeasured-data root (for example
/// `"secrets/api_key"`) — the manifest's `unmeasured-data` list with the
/// `unmeasured-data/` prefix stripped. `data_dir` is the operator's
/// `--unmeasured-data-root`. Missing declared files are allowed: the manifest
/// commits to the permitted path set, not to file presence or contents.
/// Undeclared files under the root are ignored by the CLI and therefore are
/// not uploaded. The portal still rejects undeclared paths if they appear in
/// the uploaded tar. Returns `None` when nothing declared is present.
pub(crate) fn collect_unmeasured_tar(
    declared: &[String],
    data_dir: &std::path::Path,
) -> Result<Option<Vec<u8>>> {
    if declared.is_empty() {
        return Ok(None);
    }

    let canon_base = data_dir
        .canonicalize()
        .with_context(|| format!("--unmeasured-data-root not found: {}", data_dir.display()))?;

    let mut upload_paths = Vec::new();
    for rel_path in declared {
        let src = canon_base.join(rel_path);
        match std::fs::metadata(&src) {
            Ok(metadata) if metadata.is_file() => upload_paths.push(rel_path.clone()),
            Ok(metadata) if metadata.is_dir() => bail!(
                "unmeasured-data path {} resolves to a directory; manifest paths must be concrete files",
                rel_path,
            ),
            Ok(_) => bail!(
                "unmeasured-data path {} is not a regular file",
                rel_path,
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("read unmeasured-data file {rel_path}"));
            }
        }
    }
    if upload_paths.is_empty() {
        return Ok(None);
    }

    // Build the tar from the declared files that are actually present.
    let buf = Vec::new();
    let encoder = flate2::write::GzEncoder::new(buf, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    for rel_path in upload_paths {
        let src = canon_base.join(&rel_path);
        let metadata = std::fs::metadata(&src)
            .with_context(|| format!("read unmeasured-data file {rel_path}"))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(metadata.len());
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_cksum();
        let file = std::fs::File::open(&src)?;
        tar.append_data(&mut header, &rel_path, file)?;
    }

    let encoder = tar.into_inner()?;
    let bytes = encoder.finish()?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod unmeasured_data_tests {
    use super::*;

    fn write(path: &std::path::Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
    }

    fn tar_entries(bytes: &[u8]) -> Vec<String> {
        let decoder = flate2::read::GzDecoder::new(bytes);
        let mut archive = tar::Archive::new(decoder);
        let mut out = archive
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        out.sort();
        out
    }

    #[test]
    fn resolve_unmeasured_tar_without_root_errors() {
        let declared = vec!["runtime.env".to_string()];
        let err = resolve_unmeasured_tar(&declared, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no source directory is available"), "{msg}");
        assert!(msg.contains("--unmeasured-data-root"), "{msg}");
    }

    #[test]
    fn collect_unmeasured_tar_allows_missing_declared_paths() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path().join("runtime.env").as_path(), b"PORT=8080\n");

        let declared = vec!["runtime.env".to_string(), "missing.env".to_string()];
        let tar = collect_unmeasured_tar(&declared, tmp.path())
            .unwrap()
            .expect("present allowlisted file should produce a tar");

        assert_eq!(tar_entries(&tar), vec!["runtime.env"]);
    }

    #[test]
    fn collect_unmeasured_tar_ignores_undeclared_source_paths() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path().join("runtime.env").as_path(), b"PORT=8080\n");
        write(tmp.path().join("extra.env").as_path(), b"BAD=1\n");

        let declared = vec!["runtime.env".to_string()];
        let tar = collect_unmeasured_tar(&declared, tmp.path())
            .unwrap()
            .expect("present allowlisted file should produce a tar");

        assert_eq!(tar_entries(&tar), vec!["runtime.env"]);
    }
}

/// Build a `CloudImage` record for the given platform.
pub(super) fn build_cloud_image_record(
    provider_config: &CloudProviderConfig,
    image_ref: &str,
    instance_name: &str,
    cc_types: &[atakit_cloud::CcType],
) -> CloudImage {
    match provider_config.platform {
        PlatformKind::Gcp => {
            let names = atakit_cloud::naming::ResourceNames::for_gcp(instance_name, image_ref);
            CloudImage {
                platform: PlatformKind::Gcp,
                cloud_name: names.image,
                bucket: Some(names.bucket),
                gallery_rg: None,
                gallery: None,
                image_version: None,
                cc_types: cc_types.to_vec(),
                uploaded_at: chrono::Utc::now(),
            }
        }
        PlatformKind::Azure => {
            // Only gallery/image fields are used here; storage_account isn't.
            let names =
                AzureResourceNames::for_azure(instance_name, image_ref, &provider_config.region);
            CloudImage {
                platform: PlatformKind::Azure,
                cloud_name: names.image_definition,
                bucket: None,
                gallery_rg: Some(names.gallery_rg),
                gallery: Some(names.gallery),
                image_version: Some(names.image_version),
                cc_types: cc_types.to_vec(),
                uploaded_at: chrono::Utc::now(),
            }
        }
        PlatformKind::Aws => {
            let names = atakit_cloud::naming::ResourceNames::for_aws(instance_name, image_ref);
            CloudImage {
                platform: PlatformKind::Aws,
                cloud_name: names.image,
                bucket: Some(names.bucket),
                gallery_rg: None,
                gallery: None,
                image_version: None,
                cc_types: cc_types.to_vec(),
                uploaded_at: chrono::Utc::now(),
            }
        }
        PlatformKind::Qemu => unreachable!(
            "build_cloud_image_record called for qemu — \
             qemu has no cloud-side image and is filtered out upstream"
        ),
    }
}

/// Result of a cloud image upload attempt.
pub(super) struct UploadResult {
    /// Whether an upload actually happened (false = already existed).
    pub uploaded: bool,
}

/// Ensure a cloud image is uploaded to the given provider. Checks the local
/// `CloudImages` state first to avoid redundant cloud API calls.
///
/// Records the upload in `CloudImages` on success.
/// Returns `uploaded: false` if the image already exists (in local state or cloud).
#[allow(clippy::too_many_arguments)]
pub(super) async fn ensure_cloud_image(
    image_ref: &str,
    provider_name: &str,
    provider_config: &CloudProviderConfig,
    source_path: &str,
    certs_dir: Option<&str>,
    cc_types: &[atakit_cloud::CcType],
    force: bool,
    env: &Env,
    verbose: bool,
) -> Result<UploadResult> {
    let mut cloud_imgs = CloudImages::load(&env.data_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

    let cloud_provider: Box<dyn CloudProvider> = match provider_config.platform {
        PlatformKind::Gcp => {
            let project = provider_config.project.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "provider '{provider_name}' is missing 'project' in \
                     [cloud.providers.{provider_name}]"
                )
            })?;
            Box::new(GcpProvider::new(project, provider_config.region.clone()))
        }
        PlatformKind::Azure => {
            let subscription = provider_config.subscription.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "provider '{provider_name}' is missing 'subscription' in \
                     [cloud.providers.{provider_name}] — set it to the Azure \
                     subscription ID you intend to deploy into (atakit will pass \
                     --subscription to every az call)"
                )
            })?;
            Box::new(AzureProvider::new(
                subscription,
                provider_config.region.clone(),
            ))
        }
        PlatformKind::Aws => Box::new(AwsProvider::new(provider_config.region.clone())),
        PlatformKind::Qemu => unreachable!(
            "ensure_cloud_image called for qemu — qemu has no cloud-side \
             image and is filtered out upstream"
        ),
    };

    let runner = ProcessRunner::new(verbose);

    // Check deps.
    cloud_provider
        .execute_step(&DeployStep::CheckDeps, &runner, verbose)
        .await?;

    // Check existence before uploading so we can report accurately.
    let already_exists = match provider_config.platform {
        PlatformKind::Gcp => {
            let names = atakit_cloud::naming::ResourceNames::for_gcp("upload", image_ref);
            let exists = atakit_cloud::gcp::image::check_image_exists(
                provider_config.project.as_deref().unwrap(),
                &names.image,
                &runner,
            )
            .await
            .map_err(|e| anyhow::anyhow!("failed to check image existence: {e}"))?;
            exists && !force
        }
        PlatformKind::Azure => {
            let subscription = provider_config.subscription.as_deref().unwrap();
            // Image-existence check; storage_account isn't used.
            let names = AzureResourceNames::for_azure("upload", image_ref, &provider_config.region);
            let exists = atakit_cloud::azure::image::check_image_version_exists(
                subscription,
                &names.gallery_rg,
                &names.gallery,
                &names.image_definition,
                &names.image_version,
                &runner,
            )
            .await
            .map_err(|e| anyhow::anyhow!("failed to check image existence: {e}"))?;
            exists && !force
        }
        PlatformKind::Aws => {
            let names = atakit_cloud::naming::ResourceNames::for_aws("upload", image_ref);
            let exists =
                atakit_cloud::aws::image::find_ami(&provider_config.region, &names.image, &runner)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to check image existence: {e}"))?
                    .is_some();
            exists && !force
        }
        PlatformKind::Qemu => unreachable!(
            "ensure_cloud_image existence-check called for qemu — \
             qemu has no cloud-side image and is filtered out upstream"
        ),
    };

    if already_exists {
        // Record in tracking (may be missing if uploaded before tracking existed).
        let record = build_cloud_image_record(provider_config, image_ref, "upload", cc_types);
        cloud_imgs.record(image_ref, provider_name, record);
        cloud_imgs
            .save(&env.data_dir)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        return Ok(UploadResult { uploaded: false });
    }

    // Upload.
    match provider_config.platform {
        PlatformKind::Gcp => {
            let names = atakit_cloud::naming::ResourceNames::for_gcp("upload", image_ref);
            let step = DeployStep::UploadImage {
                bucket: names.bucket.clone(),
                image_name: names.image.clone(),
                source_path: Some(source_path.to_string()),
                certs_dir: certs_dir.map(str::to_string),
                cc_types: cc_types.to_vec(),
                force,
            };
            cloud_provider.execute_step(&step, &runner, verbose).await?;
        }
        PlatformKind::Azure => {
            // Image-upload path. The VHD staging storage account lives in the
            // shared, region-scoped gallery RG (`atakit-images-<region>`), which
            // the UploadImageAzure executor ensures itself (it creates the
            // storage account in `gallery_rg` and ignores the step's
            // `resource_group` field). There is intentionally NO separate staging
            // RG: a previous `CreateResourceGroup { upload-rg }` here was dead
            // (nothing consumed it) and broke multi-region uploads, because the
            // fixed `upload-rg` name cannot exist in two regions at once.
            let names = AzureResourceNames::for_azure("upload", image_ref, &provider_config.region);
            let step = DeployStep::UploadImageAzure {
                resource_group: names.resource_group,
                storage_account: names.storage_account,
                gallery_rg: names.gallery_rg,
                gallery: names.gallery,
                image_definition: names.image_definition,
                image_version: names.image_version,
                source_path: Some(source_path.to_string()),
                certs_dir: certs_dir.map(str::to_string),
                cc_types: cc_types.to_vec(),
                force,
            };
            cloud_provider.execute_step(&step, &runner, verbose).await?;
        }
        PlatformKind::Aws => {
            let names = atakit_cloud::naming::ResourceNames::for_aws("upload", image_ref);
            let step = DeployStep::UploadImageAws {
                bucket: names.bucket,
                image_name: names.image,
                source_path: Some(source_path.to_string()),
                certs_dir: certs_dir.map(str::to_string),
                force,
            };
            cloud_provider.execute_step(&step, &runner, verbose).await?;
        }
        PlatformKind::Qemu => unreachable!(
            "ensure_cloud_image upload step called for qemu — \
             qemu has no cloud-side image and is filtered out upstream"
        ),
    };

    let record = build_cloud_image_record(provider_config, image_ref, "upload", cc_types);
    cloud_imgs.record(image_ref, provider_name, record);
    cloud_imgs
        .save(&env.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(UploadResult { uploaded: true })
}

/// Parse metadata key=value strings into a map.
pub fn parse_metadata(items: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    let mut map = std::collections::BTreeMap::new();
    for item in items {
        let (key, value) = item.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("invalid metadata format: expected KEY=VALUE, got '{item}'")
        })?;
        if key.is_empty() {
            bail!("metadata key cannot be empty in '{item}'");
        }
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}

#[cfg(test)]
fn test_chain_config() -> ChainConfig {
    ChainConfig {
        rpc_url: "https://rpc.test".to_string(),
        session_registry: "0x1111111111111111111111111111111111111111".to_string(),
        workload_registry: None,
        base_image_registry: None,
        chain_id: None,
        tee_backend: "auto".to_string(),
        prover: None,
    }
}

#[cfg(test)]
mod chain_init_tests {
    use super::*;
    use crate::config::KeyType;

    #[test]
    fn qemu_missing_chain_synthesizes_registration_off() {
        let got = synthesize_off_init_chain();
        assert_eq!(got.registration.as_deref(), Some("off"));
        assert!(got.rpc_url.is_empty());
        assert_eq!(got.session_registry, ZERO_ADDR);
        assert_eq!(got.workload_registry, ZERO_ADDR);
        assert_eq!(got.base_image_registry, ZERO_ADDR);
    }

    #[test]
    fn registration_off_does_not_require_derived_registries() {
        let chain = test_chain_config();
        let got = build_init_chain_config("offchain", &chain, Some("off"), None, None).unwrap();
        assert_eq!(got.registration.as_deref(), Some("off"));
        assert_eq!(got.workload_registry, ZERO_ADDR);
        assert_eq!(got.base_image_registry, ZERO_ADDR);
    }

    #[test]
    fn registration_required_uses_derived_registries_when_omitted() {
        let chain = test_chain_config();
        let derived = ChainRegistries {
            workload_registry: "0x2222222222222222222222222222222222222222".to_string(),
            base_image_registry: "0x3333333333333333333333333333333333333333".to_string(),
        };

        let got = build_init_chain_config("hoodi", &chain, Some("required"), Some(&derived), None)
            .unwrap();

        assert_eq!(got.workload_registry, derived.workload_registry);
        assert_eq!(got.base_image_registry, derived.base_image_registry);
    }

    #[test]
    fn registration_required_validates_configured_registries() {
        let mut chain = test_chain_config();
        chain.workload_registry = Some("0x2222222222222222222222222222222222222222".to_string());
        chain.base_image_registry = Some("0x3333333333333333333333333333333333333333".to_string());
        let derived = ChainRegistries {
            workload_registry: "0x2222222222222222222222222222222222222222".to_string(),
            base_image_registry: "0x3333333333333333333333333333333333333333".to_string(),
        };

        let got = build_init_chain_config("hoodi", &chain, Some("required"), Some(&derived), None)
            .unwrap();

        assert_eq!(got.workload_registry, chain.workload_registry.unwrap());
        assert_eq!(got.base_image_registry, chain.base_image_registry.unwrap());
    }

    #[test]
    fn registration_required_rejects_mismatched_configured_registry() {
        let mut chain = test_chain_config();
        chain.workload_registry = Some("0x4444444444444444444444444444444444444444".to_string());
        let derived = ChainRegistries {
            workload_registry: "0x2222222222222222222222222222222222222222".to_string(),
            base_image_registry: "0x3333333333333333333333333333333333333333".to_string(),
        };

        let err = build_init_chain_config("hoodi", &chain, Some("required"), Some(&derived), None)
            .unwrap_err();

        assert!(err.to_string().contains("workload_registry"), "{err}");
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn qemu_forces_registration_off() {
        let chain = test_chain_config();
        let got = build_init_chain_config("local", &chain, Some("off"), None, None).unwrap();
        assert_eq!(got.registration.as_deref(), Some("off"));
        assert_eq!(got.workload_registry, ZERO_ADDR);
        assert_eq!(got.base_image_registry, ZERO_ADDR);
    }

    #[test]
    fn self_generated_key_can_be_sent_without_private_key() {
        let spec = KeySpec {
            key_type: KeyType::Es256k,
            mode: KeyMode::SelfGenerated,
            file: None,
            command: None,
            env: None,
            timeout_secs: None,
        };

        let got = init_key_from_config("gas", &spec, false).unwrap();
        assert_eq!(got.mode, "self_generated");
        assert_eq!(got.key_type, "es256k");
        assert!(got.private_key.is_none());
    }

    #[test]
    fn self_generated_key_cannot_be_forced_to_private_key() {
        let spec = KeySpec {
            key_type: KeyType::Es256k,
            mode: KeyMode::SelfGenerated,
            file: None,
            command: None,
            env: None,
            timeout_secs: None,
        };

        let err = init_key_from_config("owner", &spec, true).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot resolve a self_generated key"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod portal_endpoint_tests {
    use super::*;
    use atakit_cloud::PortalPorts;

    fn base_state(platform: PlatformKind) -> DeployState {
        let now = chrono::Utc::now();
        DeployState {
            format: 1,
            instance_name: "test-instance".to_string(),
            workload_name: "test-workload".to_string(),
            workload_version: "v0.0.1".to_string(),
            target_name: "test-target".to_string(),
            provider_name: "test-provider".to_string(),
            platform,
            created_at: now,
            updated_at: now,
            status: atakit_cloud::DeployStatus::Deployed {
                ip: "127.0.0.1".to_string(),
            },
            image_ref: "test-image:v1".to_string(),
            base_image_ref: Some("test-image:v1".to_string()),
            archive_path: "/tmp/test.atawl".to_string(),
            archive_hash: "abc123".to_string(),
            init_env: PersistedInitEnv::default(),
            portal_ports: PortalPorts::default(),
            resources: atakit_cloud::ResourceSet::default(),
        }
    }

    #[test]
    fn qemu_uses_recorded_host_ports() {
        let mut state = base_state(PlatformKind::Qemu);
        state.resources.qemu = Some(atakit_cloud::QemuResources {
            external_ip: "127.0.0.1".to_string(),
            host_status_port: 41024,
            host_init_port: 41025,
            ..Default::default()
        });

        let got = portal_endpoints(&state).unwrap();

        assert_eq!(got, ("127.0.0.1".to_string(), 41024, 41025));
    }

    #[test]
    fn cloud_platform_uses_external_ip_and_well_known_ports() {
        let mut state = base_state(PlatformKind::Aws);
        state.resources.aws = Some(atakit_cloud::AwsResources {
            region: "us-east-1".to_string(),
            bucket: None,
            snapshot: None,
            ami: None,
            security_group: None,
            instance: None,
            external_ip: Some("203.0.113.10".to_string()),
        });

        let got = portal_endpoints(&state).unwrap();

        assert_eq!(got, ("203.0.113.10".to_string(), 2024, 1024));
    }

    #[test]
    fn cloud_platform_uses_persisted_port_overrides() {
        let mut state = base_state(PlatformKind::Aws);
        state.portal_ports = PortalPorts {
            status: 6024,
            init: 5024,
        };
        state.resources.aws = Some(atakit_cloud::AwsResources {
            region: "us-east-1".to_string(),
            external_ip: Some("203.0.113.10".to_string()),
            ..Default::default()
        });

        let got = portal_endpoints(&state).unwrap();

        assert_eq!(got, ("203.0.113.10".to_string(), 6024, 5024));
    }
}

#[cfg(test)]
mod tls_measurement_policy_tests {
    use super::*;
    use alloy_ext::core::primitives::B256;

    #[test]
    fn infers_cloud_and_tee_from_supported_profile_names() {
        assert_eq!(
            infer_cloud_tee_from_profile_name("gcp-tdx").unwrap(),
            ("gcp", "tdx")
        );
        assert_eq!(
            infer_cloud_tee_from_profile_name("gcp-sev-snp").unwrap(),
            ("gcp", "sev-snp")
        );
        assert_eq!(
            infer_cloud_tee_from_profile_name("azure_snp_westus").unwrap(),
            ("azure", "sev-snp")
        );
        assert_eq!(
            infer_cloud_tee_from_profile_name("aws-nitro").unwrap(),
            ("aws", "nitro")
        );
    }

    #[test]
    fn rejects_unmappable_chain_profile_names() {
        let err = infer_cloud_tee_from_profile_name("production-profile").unwrap_err();
        assert!(err.to_string().contains("cannot infer cloud"), "{err}");

        let err = infer_cloud_tee_from_profile_name("gcp-production").unwrap_err();
        assert!(err.to_string().contains("cannot infer TEE"), "{err}");
    }

    #[test]
    fn converts_chain_pcr_spec_to_measurement_pack_shape() {
        let spec = automata_tee_workload_measurement::stubs::BaseImageRegistry::PcrSpec {
            pcrIndex: 4,
            verifyType: 0,
            matchData: vec![B256::repeat_byte(0xaa)],
        };

        let got = chain_pcr_spec_to_measurement(&spec);

        assert_eq!(got.pcr_index, 4);
        assert_eq!(got.verify_type, "static");
        assert_eq!(got.match_data, vec![format!("0x{}", "aa".repeat(32))]);
        assert!(got.event_indices.is_empty());
        assert_eq!(got.total_events, None);
    }

    #[test]
    fn chain_measurement_policy_is_available_with_registration_off() {
        let mut chain = synthesize_off_init_chain();
        chain.registration = Some("off".to_string());
        chain.rpc_url = "https://rpc.example.com".to_string();
        chain.base_image_registry = "0x1111111111111111111111111111111111111111".to_string();

        assert!(chain_measurement_policy_available(&chain));
    }

    #[tokio::test]
    async fn incomplete_local_pack_does_not_fallback_to_chain() {
        let data_dir = tempfile::tempdir().unwrap();
        let pack_dir = data_dir
            .path()
            .join("baseimage")
            .join("measurements")
            .join(atakit_image::encode_image_ref_path_segment("base"))
            .join(atakit_image::encode_image_ref_path_segment("v1"));
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.json"), b"{}").unwrap();

        let mut chain = synthesize_off_init_chain();
        chain.rpc_url = "https://rpc.example.com".to_string();
        chain.base_image_registry = "0x1111111111111111111111111111111111111111".to_string();

        let error =
            resolve_tls_measurement_policy(None, Some("base:v1"), &[], data_dir.path(), &chain)
                .await
                .unwrap_err();

        assert!(
            error.to_string().contains("measurement-pack.sig"),
            "{error}"
        );
    }
}
