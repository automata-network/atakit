pub mod add;
pub mod build;
pub mod create;
pub mod deactivate;
pub mod export;
pub mod import;
pub mod info;
pub mod ls;
pub mod publish;
pub mod pull;
pub mod push;
pub mod rm;
pub mod spec;

use std::path::{Path, PathBuf};

use alloy_ext::core::primitives::{B256, keccak256};
use alloy_ext::core::sol_types::SolValue;
use atakit_workload::store::CachedPcrSpec;
use atakit_workload::{CachedChainSpec, WorkloadStore};
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

/// Compute the on-chain workload ID: `keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))`
/// where `WORKLOAD_DOMAIN = keccak256("CVM_WORKLOAD_V1")`.
pub fn compute_workload_id(name: &str, version: &str) -> B256 {
    let domain = keccak256("CVM_WORKLOAD_V1");
    let encoded = (domain, name.to_string(), version.to_string()).abi_encode_params();
    keccak256(&encoded)
}

/// Compute the on-chain base image ID: `keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))`
/// where `BASEIMAGE_DOMAIN = keccak256("CVM_BASEIMAGE_V1")`.
pub fn compute_base_image_id(name: &str, version: &str) -> B256 {
    let domain = keccak256("CVM_BASEIMAGE_V1");
    let encoded = (domain, name.to_string(), version.to_string()).abi_encode_params();
    keccak256(&encoded)
}

/// Parsed workload reference: either `name:version` or a hex workload ID.
#[derive(Clone)]
pub enum WorkloadRef {
    NameVersion { name: String, version: String },
    Id(String),
}

/// Parse a workload reference string.
///
/// Accepts `name:version` or `0x<64-hex-chars>` (workload ID).
/// Name must be alphanumeric + hyphens, no leading hyphen.
/// Version must start with `v` and contain no path separators.
pub fn parse_workload_ref(s: &str) -> anyhow::Result<WorkloadRef> {
    if s.starts_with("0x") && s.len() == 66 {
        Ok(WorkloadRef::Id(s.to_string()))
    } else if let Some((name, version)) = s.split_once(':') {
        if name.is_empty() || version.is_empty() {
            anyhow::bail!("invalid workload reference: expected 'name:version' or '0x<id>', got '{s}'");
        }
        // Validate name: alphanumeric + hyphens, no leading hyphen
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
            || name.starts_with('-')
        {
            anyhow::bail!(
                "invalid workload name in reference: must be alphanumeric + hyphens, got '{name}'"
            );
        }
        // Validate version: starts with 'v', at least 2 chars, only [A-Za-z0-9._-] after 'v'
        if version.len() < 2 || !version.starts_with('v') {
            anyhow::bail!(
                "invalid workload version in reference: must start with 'v' and be at least 2 characters, got '{version}'"
            );
        }
        if !version[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            anyhow::bail!(
                "invalid workload version in reference: only alphanumeric, '.', '-', '_' allowed after 'v', got '{version}'"
            );
        }
        Ok(WorkloadRef::NameVersion {
            name: name.to_string(),
            version: version.to_string(),
        })
    } else {
        anyhow::bail!("invalid workload reference: expected 'name:version' or '0x<id>', got '{s}'")
    }
}

/// Resolve a WorkloadRef to (name, version), using the store for ID lookups.
pub fn resolve_ref(r: &WorkloadRef, store: &WorkloadStore) -> anyhow::Result<(String, String)> {
    match r {
        WorkloadRef::NameVersion { name, version } => Ok((name.clone(), version.clone())),
        WorkloadRef::Id(id) => {
            let entry = store
                .get_by_id(id)?
                .ok_or_else(|| anyhow::anyhow!("workload ID not found in store: {id}"))?;
            Ok((entry.meta.name, entry.meta.version))
        }
    }
}

/// Resolved chain config for workload on-chain commands.
/// Extracted from `[chains.<name>]` with precedence: CLI --chain > [publish] chain.
pub struct ResolvedChain {
    pub rpc_url: String,
    pub session_registry: String,
}

/// Resolve chain config for on-chain workload commands.
///
/// Precedence: `cli_chain` > `config.publish.chain`. Looks up the name
/// in `config.chains` and returns the rpc_url and session_registry.
pub fn resolve_chain(
    cli_chain: Option<&str>,
    config: &crate::config::Config,
) -> anyhow::Result<ResolvedChain> {
    let chain_name = cli_chain
        .or(config.publish.chain.as_deref())
        .ok_or_else(|| anyhow::anyhow!("chain required: use --chain or [publish] chain in config"))?;
    let chain = config.chains.get(chain_name)
        .ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in [chains]"))?;
    Ok(ResolvedChain {
        rpc_url: chain.rpc_url.clone(),
        session_registry: chain.session_registry.clone(),
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
        .ok_or_else(|| anyhow::anyhow!("owner key required: use --owner-key or [publish] owner_key in config"))?;
    let key_spec = config.keys.get(key_name)
        .ok_or_else(|| anyhow::anyhow!("key '{key_name}' not found in [keys]"))?;
    if key_spec.key_type != crate::config::KeyType::Es256k {
        anyhow::bail!(
            "key '{key_name}' has type {}; on-chain workload commands require es256k",
            key_spec.key_type
        );
    }
    key_spec.resolve(key_name)
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
        .ok_or_else(|| anyhow::anyhow!("relay key required: use --relay-key or [publish] relay_key in config"))?;
    let key_spec = config.keys.get(key_name)
        .ok_or_else(|| anyhow::anyhow!("key '{key_name}' not found in [keys]"))?;
    if key_spec.key_type != crate::config::KeyType::Es256k {
        anyhow::bail!(
            "key '{key_name}' has type {}; on-chain workload commands require es256k",
            key_spec.key_type
        );
    }
    key_spec.resolve(key_name)
}

/// On-chain workload data returned by `query_chain_data`.
pub struct ChainData {
    pub status: String,
    pub owner: Option<String>,
    pub revoked: bool,
    pub spec: Option<CachedChainSpec>,
    /// PCR23 from on-chain matchData (STATIC).
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
        session_registry.parse().map_err(|_| anyhow::anyhow!("invalid session registry address"))?;

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
        .pcrs
        .iter()
        .find(|p| p.pcrIndex == 23)
        .and_then(|p| p.matchData.first())
        .map(|b| format!("0x{}", hex::encode(b)));

    let cached = CachedChainSpec {
        session_ttl: spec.ttl,
        base_image_mode: spec.baseImageMode,
        base_image_ids: spec
            .baseImageIds
            .iter()
            .map(|b| format!("0x{}", hex::encode(b)))
            .collect(),
        pcrs: spec
            .pcrs
            .iter()
            .map(|p| CachedPcrSpec {
                pcr_index: p.pcrIndex,
                verify_type: p.verifyType,
                match_data: p.matchData.iter().map(|b| format!("0x{}", hex::encode(b))).collect(),
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
pub fn apply_chain_data_to_meta(
    meta: &mut atakit_workload::WorkloadMeta,
    chain: &ChainData,
) {
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
    s.contains(':')
        && !s.starts_with('/')
        && !s.starts_with('.')
        && !s.ends_with(".atawl")
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
}
