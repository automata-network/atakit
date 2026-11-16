//! Fixed owner-selected runtime settings. CPU choices retain publisher permissions.
use crate::{
    cpu_config::{RuntimeCpuConfig, RuntimeCpuSelection},
    disk_config::RuntimeDiskConfig,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThpMode {
    #[default]
    Never,
    Madvise,
}

/// Operator TOML keeps the existing flat CPU syntax.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeInputs {
    #[serde(flatten)]
    pub cpu: RuntimeCpuConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thp: Option<ThpMode>,
}
impl std::ops::Deref for RuntimeInputs {
    type Target = RuntimeCpuConfig;
    fn deref(&self) -> &Self::Target {
        &self.cpu
    }
}
impl std::ops::DerefMut for RuntimeInputs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cpu
    }
}

/// Complete active choices, stored once in the existing runtime record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub cpu: RuntimeCpuSelection,
    pub disks: RuntimeDiskConfig,
    pub thp: ThpMode,
}

/// Omitted scopes preserve their active and pending choices.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<RuntimeCpuSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disks: Option<RuntimeDiskConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thp: Option<ThpMode>,
}
impl RuntimeUpdate {
    pub fn is_empty(&self) -> bool {
        self.cpu.is_none() && self.disks.is_none() && self.thp.is_none()
    }
}

/// Disk mappings and THP are selected once per VM boot, including retries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootRuntimeConfig {
    pub disks: RuntimeDiskConfig,
    pub thp: ThpMode,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_inputs_keep_omission_and_existing_cpu_fields() {
        let value: RuntimeInputs =
            serde_json::from_str(r#"{"cpuset":"0-3","thp":"madvise"}"#).unwrap();
        assert_eq!(value.cpu.cpuset.as_deref(), Some("0-3"));
        assert_eq!(value.thp, Some(ThpMode::Madvise));
        assert_eq!(
            serde_json::from_str::<RuntimeInputs>("{}").unwrap().thp,
            None
        );
        for invalid in [
            r#"{"thp":"always"}"#,
            r#"{"defrag":"always"}"#,
            r#"{"thp":true}"#,
        ] {
            assert!(serde_json::from_str::<RuntimeInputs>(invalid).is_err());
        }
    }
}
