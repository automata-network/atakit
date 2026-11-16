//! Check the compiled schema, including settings absent from source TOML.
use std::collections::{BTreeMap, BTreeSet};

use atakit_workload::{
    config::WorkloadConfig,
    manifest::{build_manifest, serialize_canonical_json, Manifest},
};
use serde_json::{json, Value};

const SOURCE: &str = r#"
format = 16
[workload]
name = "app"
version = "v1"
image = "app:latest"
base-image-mode = "blacklist"
atakit-portal = true
[workload.storage.data]
disk = "data"
base-path = "/app"
mount-path = "/data"
access = ["read"]
[dependencies.logger]
image = "logger:latest"
[dependencies.logger.storage.data]
disk = "data"
base-path = "/logger"
mount-path = "/data"
access = ["read"]
[baby-container]
enabled = true
max-instances = 1
[baby-container.slots.dev]
parent-service = "app"
[baby-container.slots.dev.storage.data]
disk = "data"
base-path = "/baby"
mount-path = "/data"
access = ["read"]
[disks.data]
size = "10GB"
encryption = { unlock_method = [], bind = [] }
"#;

fn build(config: &WorkloadConfig) -> Manifest {
    atakit_workload::validate::validate_config(
        config,
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
    )
    .unwrap();
    build_manifest(
        config,
        &format!("0x{}", "11".repeat(32)),
        "app:latest",
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .unwrap()
}

fn keys(value: &Value, expected: &[&str]) {
    let actual: BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(actual, expected.iter().copied().collect(), "{value}");
}

#[test]
fn complete_generated_schema_for_every_supported_format() {
    for format in 11..=16 {
        let mut source = SOURCE.replace("format = 16", &format!("format = {format}"));
        if format < 14 {
            source = source.replace("access = [\"read\"]", "read-only = true");
        }
        // A format-12 workload needs an authenticated disk to select format 12.
        // Keep the ordinary disk too, to check its explicit integrity:null.
        if format == 12 {
            source.push_str(
                "\n[disks.authenticated]\nsize = \"10GB\"\nencryption = { unlock_method = [\"tpm\"], bind = [\"baseimage\", \"workload\"], integrity = \"hmac-sha256\" }\n",
            );
        }
        let manifest = build(&WorkloadConfig::load_from_str(&source).unwrap());
        assert_eq!(manifest.meta.format, format);
        let canonical = serialize_canonical_json(&manifest).unwrap();
        let v: Value = serde_json::from_str(&canonical).unwrap();
        assert_eq!(v, serde_json::to_value(&manifest).unwrap());
        let decoded: Manifest = serde_json::from_str(&canonical).unwrap();
        assert_eq!(serialize_canonical_json(&decoded).unwrap(), canonical);

        keys(
            &v,
            &[
                "meta",
                "config",
                "disks",
                "hashes",
                "images",
                "unmeasured-data",
                "unmeasured-env-files",
            ],
        );
        keys(&v["meta"], &["format", "publisher", "name", "version"]);
        let mut config = vec![
            "image",
            "base-image-mode",
            "base-image",
            "attributes",
            "ports",
            "depends_on",
            "restart",
            "command",
            "entrypoint",
            "session-ttl",
            "atakit-portal",
            "gid-group",
            "measured-data",
            "unmeasured-data",
            "environment",
            "unmeasured-env-files",
            "storage",
            "ip_env",
            "dependencies",
            "firewall-ports",
            "baby-container",
            "boot-disk-size",
            "cap-add",
            "cap-drop",
            "logging",
            "workload-logs",
            "readiness",
        ];
        let mut dependency = vec![
            "image",
            "ports",
            "restart",
            "command",
            "entrypoint",
            "atakit-portal",
            "gid-group",
            "environment",
            "unmeasured-env-files",
            "depends_on",
            "measured-data",
            "unmeasured-data",
            "storage",
            "ip_env",
            "cap-add",
            "cap-drop",
            "logging",
            "workload-logs",
            "readiness",
        ];
        let mut slot = vec![
            "allowed_capabilities",
            "parent_service",
            "gid_group",
            "image_selection",
            "max_instances",
            "lifecycle",
            "storage",
            "ip_env",
            "logging",
            "trust_policy",
        ];
        if format == 16 {
            config.extend([
                "cpuset",
                "cpuset-policy",
                "cpu-idle",
                "cpu-frequency",
                "nofile",
            ]);
            dependency.extend(["cpuset", "cpuset-policy", "nofile"]);
            slot.extend(["cpuset", "cpuset-policy", "nofile"]);
            for path in [
                "/config/nofile",
                "/config/dependencies/logger/nofile",
                "/config/baby-container/slots/dev/nofile",
                "/config/cpuset",
                "/config/cpuset-policy",
                "/config/dependencies/logger/cpuset-policy",
                "/config/baby-container/slots/dev/cpuset-policy",
                "/config/cpu-idle",
                "/config/cpu-frequency",
                "/config/dependencies/logger/cpuset",
                "/config/baby-container/slots/dev/cpuset",
            ] {
                assert_eq!(v.pointer(path), Some(&Value::Null), "{path}");
            }
        }
        keys(&v["config"], &config);
        keys(&v["config"]["dependencies"]["logger"], &dependency);
        let baby = &v["config"]["baby-container"];
        keys(baby, &["enabled", "max_instances", "slots"]);
        keys(&baby["slots"]["dev"], &slot);
        keys(
            &baby["slots"]["dev"]["lifecycle"],
            &[
                "rootfs_size_mib",
                "rootfs_disk",
                "rootfs",
                "restart",
                "image_retention",
                "instance_retention",
            ],
        );
        for path in [
            "/config/readiness",
            "/config/dependencies/logger/readiness",
            "/config/baby-container/slots/dev/lifecycle/rootfs_size_mib",
            "/config/baby-container/slots/dev/lifecycle/rootfs_disk",
        ] {
            assert_eq!(v.pointer(path), Some(&Value::Null), "{path}");
        }
        for service in [&v["config"], &v["config"]["dependencies"]["logger"]] {
            keys(&service["logging"], &["driver", "options", "log-readers"]);
        }
        let mut logging = vec!["driver", "options", "log-readers"];
        if format >= 15 {
            logging.push("access");
            assert_eq!(baby["slots"]["dev"]["logging"]["access"], "parent");
        }
        keys(&baby["slots"]["dev"]["logging"], &logging);
        let mut mount = vec!["disk", "base_path", "mount_path"];
        mount.push(if format >= 14 { "access" } else { "read_only" });
        if format == 13 {
            mount.push("executable");
        }
        for path in [
            "/config/storage/data",
            "/config/dependencies/logger/storage/data",
        ] {
            keys(v.pointer(path).unwrap(), &mount);
        }
        mount.extend([
            "retention",
            "scope",
            if format >= 14 {
                "parent_access"
            } else {
                "permissions"
            },
        ]);
        keys(&baby["slots"]["dev"]["storage"]["data"], &mount);
        if format == 13 {
            for path in [
                "/config/storage/data/executable",
                "/config/dependencies/logger/storage/data/executable",
                "/config/baby-container/slots/dev/storage/data/executable",
            ] {
                assert_eq!(v.pointer(path), Some(&json!(false)));
            }
        }
        if format >= 14 {
            assert_eq!(
                baby["slots"]["dev"]["storage"]["data"]["parent_access"],
                json!([])
            );
        }
        keys(&v["disks"]["data"], &["index", "size", "encryption"]);
        let mut encryption = vec!["unlock_method", "bind"];
        if format >= 12 {
            encryption.push("integrity");
            assert_eq!(
                v.pointer("/disks/data/encryption/integrity"),
                Some(&Value::Null)
            );
        }
        keys(&v["disks"]["data"]["encryption"], &encryption);
    }
}

#[test]
fn absent_and_explicit_source_defaults_produce_identical_bytes() {
    let implicit = build(&WorkloadConfig::load_from_str(SOURCE).unwrap());
    let explicit = SOURCE
        .replace("atakit-portal = true", "atakit-portal = true\nrestart = \"no\"\nports = []\ncap-add = []\ncap-drop = []\ndepends_on = []")
        .replace("access = [\"read\"]\n[disks.data]", "access = [\"read\"]\nparent-access = []\n[baby-container.slots.dev.lifecycle]\nrootfs = \"read-only\"\nrestart = \"manual\"\nimage-retention = \"session\"\ninstance-retention = \"ephemeral\"\n[baby-container.slots.dev.logging]\naccess = \"parent\"\n[disks.data]");
    let explicit = build(&WorkloadConfig::load_from_str(&explicit).unwrap());
    assert_eq!(
        serialize_canonical_json(&implicit).unwrap(),
        serialize_canonical_json(&explicit).unwrap()
    );

    let source = SOURCE.replace("[workload.storage.data]", "[workload.cpu-idle]\ndriver = \"intel_idle\"\ndisabled-states = [\"C6\"]\n[workload.cpu-frequency]\ngovernor = \"performance\"\n[workload.storage.data]");
    let implicit = build(&WorkloadConfig::load_from_str(&source).unwrap());
    let explicit = source
        .replace(
            "driver = \"intel_idle\"",
            "driver = \"intel_idle\"\nrequired = true",
        )
        .replace(
            "governor = \"performance\"",
            "governor = \"performance\"\nrequired = true",
        );
    assert_eq!(
        serialize_canonical_json(&implicit).unwrap(),
        serialize_canonical_json(&build(&WorkloadConfig::load_from_str(&explicit).unwrap()))
            .unwrap()
    );
    let value = serde_json::to_value(implicit).unwrap();
    assert_eq!(
        value.pointer("/config/cpu-idle/governor"),
        Some(&Value::Null)
    );
    keys(
        &value["config"]["cpu-idle"],
        &[
            "driver",
            "governor",
            "disabled-states",
            "required",
            "allow-operator",
            "allowed-governors",
            "allowed-disabled-states",
        ],
    );
    keys(
        &value["config"]["cpu-frequency"],
        &[
            "governor",
            "required",
            "allow-operator",
            "allowed-governors",
        ],
    );
    assert!(value["config"]["cpu-idle"]["allow-operator"].is_null());
    assert!(value["config"]["cpu-idle"]["allowed-governors"].is_null());
    assert!(value["config"]["cpu-idle"]["allowed-disabled-states"].is_null());
    assert!(value["config"]["cpu-frequency"]["allow-operator"].is_null());
    assert!(value["config"]["cpu-frequency"]["allowed-governors"].is_null());
    assert_eq!(value["config"]["cpu-idle"]["required"], true);
    assert_eq!(value["config"]["cpu-frequency"]["required"], true);
}

#[test]
fn absent_optional_sections_remain_explicit_without_inventing_services() {
    let mut config = WorkloadConfig::load_from_str(SOURCE).unwrap();
    config.dependencies.clear();
    config.baby_container = None;
    config.workload.storage.clear();
    config.disks.clear();
    let v = serde_json::to_value(build(&config)).unwrap();
    assert_eq!(v.pointer("/config/dependencies"), Some(&Value::Null));
    assert_eq!(
        v["config"]["baby-container"],
        json!({"enabled":false,"max_instances":0,"slots":{}})
    );
    assert_eq!(v["config"]["storage"], json!({}));
    assert_eq!(v["disks"], json!({}));
}
