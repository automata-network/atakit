use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Cloud platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformKind {
    Gcp,
    Azure,
}

impl std::fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformKind::Gcp => write!(f, "gcp"),
            PlatformKind::Azure => write!(f, "azure"),
        }
    }
}

/// Top-level `[cloud]` configuration section.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CloudConfig {
    /// Default expire offset for CVM agent sessions (seconds).
    pub expire_offset: Option<u64>,
    /// RPC URL (falls back to `[publish]` if not set).
    pub rpc_url: Option<String>,
    /// Session registry contract address.
    pub session_registry: Option<String>,
    /// Path to owner private key file.
    pub owner_key_file: Option<String>,
    /// Path to relay private key file.
    pub relay_key_file: Option<String>,
    /// Named cloud targets.
    #[serde(default)]
    pub targets: BTreeMap<String, CloudTarget>,
}

/// A named cloud deployment target (e.g. `[cloud.targets.prod-gcp]`).
#[derive(Debug, Clone, Deserialize)]
pub struct CloudTarget {
    /// Cloud platform.
    pub platform: PlatformKind,
    /// GCP project ID.
    pub project: Option<String>,
    /// Azure subscription ID (future).
    pub subscription: Option<String>,
    /// Cloud region or zone.
    pub region: String,
    /// VM machine type.
    pub vmtype: String,
    /// Custom instance name prefix.
    pub name: Option<String>,
    /// Extra metadata key-value pairs.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    // Per-target agent env overrides.
    pub rpc_url: Option<String>,
    pub session_registry: Option<String>,
    pub owner_key_file: Option<String>,
    pub relay_key_file: Option<String>,
}
