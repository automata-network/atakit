use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub environment_id: String,
    pub upstream_rpc_url: String,
    pub anchor_number: u64,
    pub anchor_hash: String,
    pub rpc_url: String,
    pub chain_id: u64,
    pub session_registry: String,
    pub workload_registry: String,
    pub base_image_registry: String,
    pub state: String,
    pub workloads: BTreeMap<String, WorkloadEndpoint>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkloadEndpoint {
    /// Workload version captured when the emulator starts. Older runtimes omit it.
    #[serde(default)]
    pub version: Option<String>,
    pub config_file: PathBuf,
    pub workload_dir: PathBuf,
    pub portal_socket: PathBuf,
    pub owner_fingerprint: Option<String>,
    pub publisher_fingerprint: String,
    pub workload_id: Option<String>,
    pub session_id: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub env: BTreeMap<String, String>,
}
impl EndpointInfo {
    pub fn select(&self, name: Option<&str>) -> Result<(&String, &WorkloadEndpoint)> {
        if let Some(name) = name {
            return self
                .workloads
                .get_key_value(name)
                .ok_or_else(|| anyhow::anyhow!("unknown workload `{name}`"));
        }
        if self.workloads.len() != 1 {
            bail!("--workload is required for a multi-instance environment");
        }
        Ok(self.workloads.iter().next().unwrap())
    }
}
pub fn redact_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "<invalid URL>".into(),
    }
}
pub fn dotenv(env: &BTreeMap<String, String>) -> String {
    env.iter()
        .map(|(k, v)| format!("{k}='{}'\n", v.replace('\'', "'\\''")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_endpoints_without_version_remain_readable() {
        let old = serde_json::json!({
            "config_file":"app.toml", "workload_dir":".", "portal_socket":"portal.sock",
            "owner_fingerprint":null, "publisher_fingerprint":"publisher",
            "workload_id":null, "session_id":null, "state":"ready", "error":null, "env":{}
        });
        let endpoint: WorkloadEndpoint = serde_json::from_value(old).unwrap();
        assert_eq!(endpoint.version, None);
    }
}
