pub mod build;
pub mod create;
pub mod info;
pub mod publish;

use std::path::{Path, PathBuf};

use alloy_ext::core::primitives::{B256, keccak256};
use alloy_ext::core::sol_types::SolValue;

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

/// Compute the on-chain workload ID: `keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))`
/// where `WORKLOAD_DOMAIN = keccak256("CVM_WORKLOAD_V1")`.
pub fn compute_workload_id(name: &str, version: &str) -> B256 {
    let domain = keccak256("CVM_WORKLOAD_V1");
    let encoded = (domain, name.to_string(), version.to_string()).abi_encode_params();
    keccak256(&encoded)
}
