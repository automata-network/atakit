//! Format-aware output shared by the workload builder and Portal.
//!
//! Optional source settings must have explicit defaults in the compiled JSON.
//! Some fields only exist in specific formats, so their defaults cannot be
//! emitted by a nested type that does not know the manifest format.

use std::collections::{BTreeMap, BTreeSet};

use serde::{ser::SerializeStruct, Serialize, Serializer};
use serde_json::Value;

/// The complete top-level workload manifest. The component-specific nested
/// types keep their own parsing and validation; both writers use this output.
pub struct ManifestSections<'a, M, C, D, I> {
    pub format: u32,
    pub meta: &'a M,
    pub config: &'a C,
    pub disks: &'a D,
    pub hashes: &'a BTreeMap<String, String>,
    pub unmeasured_data: &'a BTreeSet<String>,
    pub unmeasured_env_files: &'a BTreeMap<String, Vec<String>>,
    pub images: &'a I,
}

impl<M: Serialize, C: Serialize, D: Serialize, I: Serialize> Serialize
    for ManifestSections<'_, M, C, D, I>
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut config = serde_json::to_value(self.config).map_err(serde::ser::Error::custom)?;
        let mut disks = serde_json::to_value(self.disks).map_err(serde::ser::Error::custom)?;
        add_format_defaults(self.format, &mut config, &mut disks);

        let mut output = serializer.serialize_struct("Manifest", 7)?;
        output.serialize_field("meta", self.meta)?;
        output.serialize_field("config", &config)?;
        output.serialize_field("disks", &disks)?;
        output.serialize_field("hashes", self.hashes)?;
        output.serialize_field("unmeasured-data", self.unmeasured_data)?;
        output.serialize_field("unmeasured-env-files", self.unmeasured_env_files)?;
        output.serialize_field("images", self.images)?;
        output.end()
    }
}

fn add_format_defaults(format: u32, config: &mut Value, disks: &mut Value) {
    service_defaults(format, config);
    if format >= crate::cpu::CPU_POLICY_FORMAT {
        insert_default(config, "cpu-idle", Value::Null);
        insert_default(config, "cpu-frequency", Value::Null);
    }
    if let Some(dependencies) = config
        .get_mut("dependencies")
        .and_then(Value::as_object_mut)
    {
        for dependency in dependencies.values_mut() {
            service_defaults(format, dependency);
        }
    }
    if let Some(slots) = config
        .pointer_mut("/baby-container/slots")
        .and_then(Value::as_object_mut)
    {
        for slot in slots.values_mut() {
            service_defaults(format, slot);
        }
    }
    if format >= 12 {
        if let Some(disks) = disks.as_object_mut() {
            for disk in disks.values_mut() {
                if let Some(encryption) = disk.get_mut("encryption") {
                    insert_default(encryption, "integrity", Value::Null);
                }
            }
        }
    }
}

fn service_defaults(format: u32, service: &mut Value) {
    if format >= crate::cpu::CPU_POLICY_FORMAT {
        insert_default(service, "cpuset", Value::Null);
        insert_default(service, "cpuset-policy", Value::Null);
    }
    if format >= crate::nofile::NOFILE_FORMAT {
        insert_default(service, "nofile", Value::Null);
    }
    // Format 13 introduced executable. Format 14 replaced it with access lists.
    if format == 13 {
        if let Some(storage) = service.get_mut("storage").and_then(Value::as_object_mut) {
            for mount in storage.values_mut() {
                insert_default(mount, "executable", Value::Bool(false));
            }
        }
    }
}

fn insert_default(object: &mut Value, key: &str, default: Value) {
    if let Some(object) = object.as_object_mut() {
        object.entry(key).or_insert(default);
    }
}
