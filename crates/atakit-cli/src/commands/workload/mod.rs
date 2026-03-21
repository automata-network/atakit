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
use atakit_workload::WorkloadStore;

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

/// Parsed workload reference: either `name:version` or a hex workload ID.
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

/// Check if a string looks like a `name:version` store reference (not a file path).
pub fn looks_like_store_ref(s: &str) -> bool {
    // Contains a colon and doesn't look like a file path
    s.contains(':')
        && !s.starts_with('/')
        && !s.starts_with('.')
        && !s.ends_with(".atawl")
}
