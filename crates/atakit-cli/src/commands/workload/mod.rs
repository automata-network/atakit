pub mod add;
pub mod build;
pub mod create;
pub mod deactivate;
pub mod export;
pub mod import;
pub mod info;
pub mod init;
pub mod ls;
pub mod policy;
pub mod publish;
pub mod pull;
pub mod push;
pub mod rm;
pub mod spec;

use anyhow::Context;
use std::path::{Path, PathBuf};

use alloy_ext::core::primitives::B256;
use atakit_cvm_encoding::pcr_comparison::{decode256, PcrComparison256};
use atakit_workload::store::CachedPcrSpec;
use atakit_workload::CachedChainSpec;
use automata_tee_workload_measurement::types::AppRef;
use sha2::{Digest, Sha256};

/// Look for a single `.atawl` file in the directory.
/// Returns `None` if zero or multiple archives are found.
pub fn find_archive(dir: &Path) -> Option<PathBuf> {
    let mut found = None;
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "atawl") {
            if found.is_some() {
                return None;
            }
            found = Some(path);
        }
    }
    found
}

/// Read `atakit-workload.toml` from `dir` and look for the matching
/// `{name}-{version}.atawl` archive. Returns an error if the config
/// exists but the versioned archive does not.
pub fn find_versioned_archive(dir: &Path) -> anyhow::Result<PathBuf> {
    let config = atakit_workload::config::WorkloadConfig::from_dir(dir)?;
    let name = &config.workload.name;
    let version = &config.workload.version;
    let archive = dir.join(format!("{name}-{version}.atawl"));
    if archive.exists() {
        Ok(archive)
    } else {
        anyhow::bail!(
            "archive not found: {}\nRun `atakit workload build` first.",
            archive.display()
        )
    }
}

/// The specification-defined workload identifier for a publisher-qualified reference.
pub fn compute_workload_id(app_ref: &AppRef) -> B256 {
    B256::from(atakit_cvm_encoding::workload_id(&shared_app_ref(app_ref)))
}

/// The specification-defined base-image identifier for a publisher-qualified reference.
pub fn compute_base_image_id(app_ref: &AppRef) -> B256 {
    B256::from(atakit_cvm_encoding::base_image_id(&shared_app_ref(app_ref)))
}

fn shared_app_ref(app_ref: &AppRef) -> atakit_cvm_types::AppRef {
    atakit_cvm_types::AppRef::new(
        app_ref.publisher.into(),
        app_ref.name.clone(),
        app_ref.version.clone(),
    )
}

pub(crate) fn static_pcr256_value(comparison: &[u8]) -> Option<[u8; 32]> {
    match decode256(comparison).ok()? {
        PcrComparison256::Static(value) => Some(value),
        _ => None,
    }
}

/// Parsed workload reference: either `name:version` or a hex workload ID.
#[derive(Clone)]
pub enum WorkloadRef {
    /// A publisher-qualified reference, from which the identifier is derived.
    Ref(AppRef),
    /// An identifier supplied directly.
    Id(String),
}

impl WorkloadRef {
    /// The workload identifier this reference denotes.
    ///
    /// Both forms yield one, so every caller keys the store the same way and
    /// none of them re-derives the identifier itself.
    pub fn workload_id(&self) -> String {
        match self {
            Self::Ref(app_ref) => format!("{:#x}", compute_workload_id(app_ref)),
            Self::Id(id) => id.clone(),
        }
    }
}

/// Parse a workload reference from command-line input.
///
/// Accepts an identifier (`0x` plus 64 lowercase hexadecimal characters) or a
/// publisher-qualified `<publisher>/<name>:<version>`, where `<publisher>` may
/// be a name from the `[publishers]` configuration section. Alias expansion
/// happens here, before parsing, so an alias can never reach a manifest: the
/// parsed reference holds a fingerprint and has no representation for an
/// unresolved name.
pub fn parse_workload_ref(
    s: &str,
    alias: &atakit_config::AliasConfig,
) -> anyhow::Result<WorkloadRef> {
    if atakit_core::is_canonical_id(s) {
        return Ok(WorkloadRef::Id(s.to_string()));
    }
    let expanded = alias.expand(s)?;
    let app_ref: AppRef = expanded
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid workload reference '{s}': {error}"))?;
    if !atakit_core::is_valid_ref_name(&app_ref.name) {
        anyhow::bail!(
            "invalid workload name in reference: must be alphanumeric and '-', not starting with '-', got '{}'",
            app_ref.name
        );
    }
    if !atakit_core::is_valid_ref_version(&app_ref.version) {
        anyhow::bail!(
            "invalid workload version in reference: must start with 'v' and may contain only alphanumeric, '.', '-', '_' after it, got '{}'",
            app_ref.version
        );
    }
    Ok(WorkloadRef::Ref(app_ref))
}

/// Resolved chain config for workload on-chain commands.
/// Extracted from `[chains.<name>]` with precedence: CLI --chain > [publish] chain.
pub struct ResolvedChain {
    pub rpc_url: String,
    pub session_registry: String,
    /// Default validity window for owner-key-signed operations.
    pub op_expiry_seconds: u64,
}

/// Resolve chain config for on-chain workload commands.
///
/// Precedence: `cli_chain` > `config.publish.chain`. Looks up the name
/// in `config.chains`; the operation window comes from `[owner_operations]`.
pub fn resolve_chain(
    cli_chain: Option<&str>,
    config: &crate::config::Config,
) -> anyhow::Result<ResolvedChain> {
    let chain_name = cli_chain
        .or(config.publish.chain.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!("chain required: use --chain or [publish] chain in config")
        })?;
    let chain = config
        .chains
        .get(chain_name)
        .ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in [chains]"))?;
    Ok(ResolvedChain {
        rpc_url: chain.rpc_url.clone(),
        session_registry: chain.session_registry.clone(),
        op_expiry_seconds: config.owner_operations.op_expiry_seconds,
    })
}

/// Resolve owner key for on-chain workload commands.
///
/// Precedence: `cli_owner_key` > `config.publish.owner_key`. Looks up
/// the name in `config.keys` and resolves the private key.
pub fn resolve_owner_key(
    cli_owner_key: Option<&str>,
    config: &crate::config::Config,
) -> anyhow::Result<String> {
    let key_name = cli_owner_key
        .or(config.publish.owner_key.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!("owner key required: use --owner-key or [publish] owner_key in config")
        })?;
    let key_spec = config
        .keys
        .get(key_name)
        .ok_or_else(|| anyhow::anyhow!("key '{key_name}' not found in [keys]"))?;
    if key_spec.key_type != crate::config::KeyType::Es256k {
        anyhow::bail!(
            "key '{key_name}' has type {}; on-chain workload commands require es256k",
            key_spec.key_type
        );
    }
    Ok(key_spec.resolve(key_name)?)
}

/// Resolve relay key for on-chain workload commands.
///
/// Precedence: `cli_relay_key` > `config.publish.relay_key`. Looks up
/// the name in `config.keys` and resolves the private key.
pub fn resolve_relay_key(
    cli_relay_key: Option<&str>,
    config: &crate::config::Config,
) -> anyhow::Result<String> {
    let key_name = cli_relay_key
        .or(config.publish.relay_key.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!("relay key required: use --relay-key or [publish] relay_key in config")
        })?;
    let key_spec = config
        .keys
        .get(key_name)
        .ok_or_else(|| anyhow::anyhow!("key '{key_name}' not found in [keys]"))?;
    if key_spec.key_type != crate::config::KeyType::Es256k {
        anyhow::bail!(
            "key '{key_name}' has type {}; on-chain workload commands require es256k",
            key_spec.key_type
        );
    }
    Ok(key_spec.resolve(key_name)?)
}

/// On-chain workload data returned by `query_chain_data`.
pub struct ChainData {
    pub status: String,
    pub owner: Option<String>,
    pub revoked: bool,
    pub spec: Option<CachedChainSpec>,
    /// PCR23 decoded from an on-chain STATIC `comparison`.
    pub pcr23: Option<String>,
}

/// Query on-chain workload spec, owner, and revocation status.
///
/// Returns `None` if RPC is not configured. Returns `ChainData` with
/// `status = "not registered"` if the workload is not on-chain.
pub async fn query_chain_data(
    workload_id: B256,
    rpc_url: &str,
    session_registry: &str,
) -> anyhow::Result<ChainData> {
    let session_registry_address: alloy_ext::core::primitives::Address =
        session_registry
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid session registry address"))?;

    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url: rpc_url.to_string(),
        relay_key: None,
        session_registry_address,
    };

    let measurement =
        automata_tee_workload_measurement::WorkloadMeasurement::new(measurement_config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect: {e}"))?;
    let registry = measurement.workload_registry();

    let spec = match registry.get_workload_spec(workload_id).await {
        Ok(s) => s,
        Err(_) => {
            return Ok(ChainData {
                status: "not registered".to_string(),
                owner: None,
                revoked: false,
                spec: None,
                pcr23: None,
            });
        }
    };

    let owner = registry
        .get_workload_owner(workload_id)
        .await
        .ok()
        .map(|fp| format!("0x{}", hex::encode(fp)));

    let revoked = registry
        .is_workload_revoked(workload_id)
        .await
        .unwrap_or(false);

    let pcr23 = spec
        .workloadPcrPolicy
        .pcrSpecs256
        .iter()
        .find(|p| p.pcrIndex == 23)
        .and_then(|p| static_pcr256_value(&p.comparison))
        .map(|value| format!("0x{}", hex::encode(value)));

    let cached = CachedChainSpec {
        session_ttl: spec.sessionTtl,
        base_image_mode: spec.baseImageMode,
        base_image_ids: spec
            .baseImageIds
            .iter()
            .map(|b| format!("0x{}", hex::encode(b)))
            .collect(),
        pcrs: spec
            .workloadPcrPolicy
            .pcrSpecs256
            .iter()
            .map(|p| CachedPcrSpec {
                pcr_index: p.pcrIndex,
                comparison: format!("0x{}", hex::encode(&p.comparison)),
            })
            .collect(),
    };

    let status = if revoked { "revoked" } else { "active" }.to_string();

    Ok(ChainData {
        status,
        owner,
        revoked,
        spec: Some(cached),
        pcr23,
    })
}

/// Update WorkloadMeta in the store with on-chain data.
/// Merges chain data into existing metadata if present, or creates fields on existing.
pub fn apply_chain_data_to_meta(meta: &mut atakit_workload::WorkloadMeta, chain: &ChainData) {
    meta.revoked = chain.revoked;
    if chain.owner.is_some() {
        meta.owner.clone_from(&chain.owner);
    }
    if chain.spec.is_some() {
        meta.on_chain_spec.clone_from(&chain.spec);
    }
    if chain.pcr23.is_some() && meta.pcr23.is_none() {
        meta.pcr23.clone_from(&chain.pcr23);
    }
}

/// Check if a string looks like a `name:version` store reference (not a file path).
pub fn looks_like_store_ref(s: &str) -> bool {
    // Contains a colon and doesn't look like a file path
    s.contains(':') && !s.starts_with('/') && !s.starts_with('.') && !s.ends_with(".atawl")
}

// `hex_equal` now lives in atakit-workload so library code (the
// repository backends) can use it for identity checks. Re-export here
// so existing command handlers keep the same import path.
pub use atakit_workload::hex_equal;

/// Compute the final PCR23 register value from a manifest event hash.
///
/// The CVM agent records `SHA-256(prev_pcr || event_hash)` where the
/// previous PCR value is all zeros for a fresh PCR23 extend. So the
/// final PCR23 value the on-chain registry stores is
/// `SHA-256(zeros_32 || event_hash)`.
///
/// `event_hash_hex` accepts an optional `0x` prefix. Returns `None` if
/// the input isn't valid 32-byte hex.
pub fn compute_final_pcr23(event_hash_hex: &str) -> Option<String> {
    let stripped = event_hash_hex
        .trim()
        .strip_prefix("0x")
        .or_else(|| event_hash_hex.trim().strip_prefix("0X"))
        .unwrap_or(event_hash_hex.trim());
    let event_bytes: [u8; 32] = hex::decode(stripped).ok()?.try_into().ok()?;
    let mut hasher = Sha256::new();
    hasher.update([0u8; 32]);
    hasher.update(event_bytes);
    Some(format!("0x{}", hex::encode(hasher.finalize())))
}

/// The publisher a command is acting as, from its configured identity.
///
/// A file path records a name and version but never who published it, and the
/// identifier is derived from the publisher — so a path form takes its identity
/// from the signing key, defaulting to `[publish] owner_key`. A reference names
/// its publisher and never reaches here.
pub fn configured_publisher(
    signing_key: Option<&str>,
    config: &crate::config::Config,
) -> anyhow::Result<B256> {
    owner_fingerprint(&resolve_owner_key(signing_key, config)?)
}

/// The owner fingerprint of a resolved ES256K key.
///
/// This is the publisher component of every identifier the key can register, so
/// deriving it is how a command that holds a key learns which name space it is
/// writing into. The derivation lives beside the fingerprint definition in the
/// registry crate, so `atakit` and `atakit-imgbuild` cannot drift into giving
/// one key two publishers.
pub fn owner_fingerprint(private_key_hex: &str) -> anyhow::Result<B256> {
    automata_tee_workload_measurement::stubs::es256k_fingerprint(private_key_hex)
        .context("owner key is not a valid ES256K key")
}

#[cfg(test)]
mod tests {
    use super::*;

    // hex_equal tests live in atakit-workload now that the helper is
    // shared. Keep PCR23 tests here because compute_final_pcr23 is
    // workflow-specific glue.

    #[test]
    fn final_pcr23_from_zero_event() {
        // SHA-256(zeros_32 || zeros_32) is deterministic; verify against
        // a known value computed once with a hex tool.
        let zero_event = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let got = compute_final_pcr23(zero_event).unwrap();
        // SHA-256 of 64 zero bytes
        assert_eq!(
            got,
            "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        );
    }

    #[test]
    fn final_pcr23_rejects_bad_hex() {
        assert!(compute_final_pcr23("notahex").is_none());
        assert!(compute_final_pcr23("0xdeadbeef").is_none()); // too short
    }

    /// Cross-check vector against atakit-portal's hand-rolled abi.encode + keccak256.
    /// Pinned against the publisher-qualified derivation. The vectors changed
    /// with the grammar: the previous ones were computed from name and version
    /// alone and no longer describe any identifier the registries produce.
    ///
    /// If this assertion changes, the matching test in atakit-portal must change
    /// too, or the on-chain workload IDs the portal reports will silently
    /// diverge. **atakit-portal has not been updated yet.**
    #[test]
    fn compute_workload_id_known_vector() {
        let publisher = alloy_ext::core::primitives::B256::repeat_byte(0x11);
        let id = compute_workload_id(&AppRef::new(publisher, "test-workload", "v1.0.0"));
        assert_eq!(
            format!("{id:#x}"),
            "0x56454a28816eeb5c79ea820b3ce24e28151f360e642929d8b526640e0f623e35"
        );
    }

    /// Real-world vector: a workload published on-chain. Confirms the synthetic
    /// vector above isn't an artifact of `test-workload`/`v1.0.0` specifically.
    #[test]
    fn compute_workload_id_fedora_oci_v0_0_9() {
        let publisher = alloy_ext::core::primitives::B256::repeat_byte(0x22);
        let id = compute_workload_id(&AppRef::new(publisher, "fedora-oci", "v0.0.9"));
        assert_eq!(
            format!("{id:#x}"),
            "0x9649362cd5dec505d90b11afee0a7d52746555b41997eae2f0a9d603ac2f21bf"
        );
    }

    /// Cross-check vector against atakit-portal's hand-rolled abi.encode + keccak256.
    /// If this assertion changes, the matching test in atakit-portal must change too,
    /// or the on-chain base-image IDs the portal reports will silently diverge.
    #[test]
    fn compute_base_image_id_known_vector() {
        let publisher = alloy_ext::core::primitives::B256::repeat_byte(0x33);
        let id = compute_base_image_id(&AppRef::new(publisher, "test-image", "v1.0.0"));
        assert_eq!(
            format!("{id:#x}"),
            "0x1e088ca5f3c20fc773870ebd578a49a340ce8714d84b4d539f0afee47229a3c8"
        );
    }
}
