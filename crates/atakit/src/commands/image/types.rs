//! Shared types for image commands.

use serde::{Deserialize, Serialize};

/// Response from the CVM agent's `/platform-profile` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformProfileResponse {
    /// Cloud provider type (e.g., "gcp", "azure", "aws", "qemu")
    pub cloud_type: String,
    /// TEE type (e.g., "tdx", "snp", "none")
    pub tee_type: String,
    /// Machine type (e.g., "n2d-standard-16", "Standard_D4s_v4")
    pub machine_type: String,
    /// PCR specifications for this platform
    pub pcrs: Vec<PcrSpec>,
}

/// PCR specification from the CVM agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcrSpec {
    /// PCR index (0-23)
    pub pcr_index: u8,
    /// Verification type: 0=Static, 1=DynamicSubset, 2=DynamicSubsequence
    pub verify_type: u8,
    /// Match data (32-byte hashes)
    #[serde(with = "hex_bytes32_vec")]
    pub match_data: Vec<[u8; 32]>,
}

impl PlatformProfileResponse {
    /// Generate a filename for this profile: {cloud_type}-{tee_type}-{machine_type}.json
    pub fn filename(&self) -> String {
        format!("{}-{}-{}.json", self.cloud_type, self.tee_type, self.machine_type)
    }

    /// Generate a platform profile name (cloud_type-tee_type).
    pub fn profile_name(&self) -> String {
        format!("{}-{}", self.cloud_type, self.tee_type)
    }
}

/// Serde helper for Vec<[u8; 32]> as hex strings.
mod hex_bytes32_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(data: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_strings: Vec<String> = data.iter().map(|b| format!("0x{}", hex::encode(b))).collect();
        hex_strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_strings: Vec<String> = Vec::deserialize(deserializer)?;
        hex_strings
            .into_iter()
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            })
            .collect()
    }
}
