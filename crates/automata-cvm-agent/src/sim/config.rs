//! Configuration types for the simulated CVM agent.
//!
//! Defines service endpoints, workload identity, and optional chain parameters
//! used by [`super::SimCvmAgent`].

use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result};
use automata_tee_workload_measurement::types::AppRef;
use serde::{Deserialize, Serialize};

/// Configuration for a single simulated service endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimServiceConfig {
    /// Service name (from docker-compose).
    pub name: String,
    /// Unix socket path for this service.
    pub socket_path: PathBuf,
}

/// On-chain configuration for the simulated CVM agent.
///
/// Provides shared chain connectivity (`rpc_url`, `session_registry_address`)
/// and per-workload registration entries.  Each workload gets its own
/// independent session key and registration/rotation lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Ethereum RPC URL.
    pub rpc_url: String,
    /// Session registry contract address.
    pub session_registry_address: Address,
    /// Target chain ID (queried from RPC if not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// Anvil listen port (default: 14345).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anvil_port: Option<u16>,
    /// Anvil listen host (default: "0.0.0.0").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anvil_host: Option<String>,
    /// Session expiry offset in seconds (default: 3600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_offset: Option<u64>,
    /// Workloads to register on-chain.  Each entry spawns an independent
    /// registration/rotation loop with its own session key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<WorkloadRegistration>,
}

/// Per-workload registration entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadRegistration {
    /// Workload reference ("name:version").
    pub workload_ref: AppRef,
    /// Temporary workload reference ("name:version-date").
    pub temporary_workload_ref: AppRef,
    /// Base image reference ("name:version").
    pub base_image_ref: AppRef,
    /// Owner private key for this workload (hex, 32 bytes).
    pub owner_private_key: B256,
}

impl ChainConfig {
    /// Returns `true` if registration can proceed (at least one workload).
    pub fn can_register(&self) -> bool {
        !self.workloads.is_empty()
    }
}

/// Top-level configuration for the simulated CVM agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimConfig {
    /// Services to simulate -- each gets its own Unix socket.
    pub services: Vec<SimServiceConfig>,
    /// Workload ID returned in sign-message responses.
    #[serde(default)]
    pub workload_id: B256,
    /// Base image ID returned in sign-message responses.
    #[serde(default)]
    pub base_image_id: B256,
    /// Optional chain configuration for on-chain auto-registration.
    /// If present, the sim agent will auto-register on startup and
    /// rotate the session periodically in the background.
    pub chain: Option<ChainConfig>,
}

impl SimConfig {
    /// Load configuration from a JSON file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let data =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&data).with_context(|| format!("parsing {}", path.display()))
    }

    /// Persist configuration to a JSON file.
    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let data = serde_json::to_string_pretty(self).context("serializing SimConfig")?;
        std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))
    }
}
