//! Owner-selected disk setup and scheduling. This never changes the measured disk policy.
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt};

/// Creation-time binding carried in the existing owner-authenticated init config.
/// All included local SSDs back this one manifest disk. The trusted cloud
/// identity selects the provider's device resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSsdConfig {
    pub disk: String,
    pub count: u32,
}

impl LocalSsdConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.disk.is_empty()
            || self.disk.len() > 256
            || ![1, 2, 4, 6, 8, 16, 32].contains(&self.count)
        {
            return Err("invalid Local SSD workload disk or member count".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionWorkqueues {
    #[default]
    Default,
    Bypass,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeDiskOptions {
    pub encryption_workqueues: EncryptionWorkqueues,
}

/// A complete disk scope. Unknown and duplicate disk names are never aliases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RuntimeDiskConfig(pub BTreeMap<String, RuntimeDiskOptions>);

impl<'de> Deserialize<'de> for RuntimeDiskConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = RuntimeDiskConfig;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map of unique workload disk names to queue settings")
            }
            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut disks = BTreeMap::new();
                while let Some((name, options)) = map.next_entry::<String, RuntimeDiskOptions>()? {
                    if name.is_empty() || name.len() > 256 || disks.len() >= 256 {
                        return Err(de::Error::custom(
                            "disk configuration exceeds name/count limits",
                        ));
                    }
                    if disks.insert(name.clone(), options).is_some() {
                        return Err(de::Error::custom(format!("duplicate disk {name:?}")));
                    }
                }
                Ok(RuntimeDiskConfig(disks))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

impl RuntimeDiskConfig {
    /// Validate against verified manifest declarations and fill omitted defaults.
    pub fn resolve<'a>(
        &self,
        declared: impl IntoIterator<Item = (&'a str, bool)>,
    ) -> Result<Self, String> {
        let declared: BTreeMap<_, _> = declared.into_iter().collect();
        for (name, choice) in &self.0 {
            let encrypted = declared
                .get(name.as_str())
                .ok_or_else(|| format!("unknown workload disk {name:?}"))?;
            if choice.encryption_workqueues == EncryptionWorkqueues::Bypass && !encrypted {
                return Err(format!(
                    "disk {name:?} is not encrypted; queue bypass is invalid"
                ));
            }
        }
        Ok(Self(
            declared
                .keys()
                .map(|name| {
                    (
                        (*name).to_owned(),
                        self.0.get(*name).copied().unwrap_or_default(),
                    )
                })
                .collect(),
        ))
    }

    pub fn mode(&self, name: &str) -> EncryptionWorkqueues {
        self.0
            .get(name)
            .copied()
            .unwrap_or_default()
            .encryption_workqueues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_wire_format_and_manifest_scope() {
        for invalid in [
            r#"{"data":{},"data":{}}"#,
            r#"{"data":{"encryption_workqueues":"fast"}}"#,
            r#"{"data":{"device":"/dev/sda"}}"#,
        ] {
            assert!(serde_json::from_str::<RuntimeDiskConfig>(invalid).is_err());
        }
        let choice: RuntimeDiskConfig =
            serde_json::from_str(r#"{"data":{"encryption_workqueues":"bypass"}}"#).unwrap();
        assert!(choice.resolve([("other", true)]).is_err());
        assert!(choice.resolve([("data", false)]).is_err());
        let resolved = choice.resolve([("data", true), ("logs", false)]).unwrap();
        assert_eq!(resolved.mode("data"), EncryptionWorkqueues::Bypass);
        assert_eq!(resolved.mode("logs"), EncryptionWorkqueues::Default);
    }
}
