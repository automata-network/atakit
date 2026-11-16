use atakit_workload::{
    config::WorkloadConfig,
    manifest::{build_manifest, serialize_canonical_json},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
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

[dependencies.helper]
image="helper:latest"
"#;
fn config() -> WorkloadConfig {
    WorkloadConfig::load_from_str(SOURCE).unwrap()
}
fn bytes(c: &WorkloadConfig) -> Result<String, String> {
    atakit_workload::validate::validate_config(c, Path::new(env!("CARGO_MANIFEST_DIR")))
        .map_err(|e| e.to_string())?;
    let m = build_manifest(
        c,
        &format!("0x{}", "11".repeat(32)),
        "app:latest",
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .map_err(|e| e.to_string())?;
    serialize_canonical_json(&m).map_err(|e| e.to_string())
}
fn check(name: &str, f: impl Fn(&mut WorkloadConfig, bool)) {
    let mut a = config();
    let mut b = config();
    f(&mut a, false);
    f(&mut b, true);
    let a = bytes(&a).unwrap_or_else(|e| panic!("{name}: {e}"));
    let b = bytes(&b).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(a, b, "{name}");
    assert_eq!(
        Sha256::digest(a.as_bytes()),
        Sha256::digest(b.as_bytes()),
        "{name}"
    );
}

fn list(b: bool, a: &[&str]) -> Vec<String> {
    let mut v = a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    if b {
        v.reverse();
    }
    v
}
#[test]
fn equivalent_settings_have_identical_bytes_and_hashes() {
    check("cpuset", |c, b| {
        c.workload.cpuset = Some(if b { "0,1,2,3" } else { "0-3" }.into())
    });
    check("idle state order", |c, b| {
        c.workload.cpu_idle = Some(
            serde_json::from_value(
                serde_json::json!({"driver":"intel_idle","disabled-states":list(b,&["C1","C6"])}),
            )
            .unwrap(),
        )
    });
    check("cap-add order", |c, b| {
        c.workload.cap_add = list(b, &["NET_RAW", "NET_ADMIN"])
    });
    check("cap-drop order", |c, b| {
        c.workload.cap_drop = list(b, &["CHOWN", "SETUID"])
    });
    check("cap-add duplicate", |c, b| {
        c.workload.cap_add = if b {
            vec!["NET_ADMIN".into(); 2]
        } else {
            vec!["NET_ADMIN".into()]
        }
    });
    check("base-image order", |c, b| {
        c.workload.base_image = vec![
            format!("0x{}/a:v1", "11".repeat(32)),
            format!("0x{}/b:v1", "11".repeat(32)),
        ];
        if b {
            c.workload.base_image.reverse();
        }
    });
    check("disk binding order", |c, b| {
        let d = c.disks.get_mut("data").unwrap();
        d.encryption.unlock_method = vec!["tpm".into()];
        d.encryption.bind = list(b, &["baseimage", "workload"]);
    });
    check("disk size units", |c, b| {
        c.disks.get_mut("data").unwrap().size = if b { "10240MB" } else { "10GB" }.into()
    });
    check("log size units", |c, b| {
        c.workload
            .logging
            .options
            .insert("max-size".into(), if b { "52428800" } else { "50m" }.into());
    });
    check("log file count zeros", |c, b| {
        c.workload
            .logging
            .options
            .insert("max-file".into(), if b { "05" } else { "5" }.into());
    });
    check("log reader order", |c, b| {
        c.workload.logging.log_readers = list(b, &["logger", "helper"]);
        for d in c.dependencies.values_mut() {
            d.workload_logs = true;
        }
    });
    check("custom attribute order", |c, b| {
        c.workload.attributes.insert(
            "example.environment".into(),
            serde_json::from_value(serde_json::json!(list(b, &["a", "b"]))).unwrap(),
        );
    });
    check("baby capability order", |c, b| {
        c.baby_container
            .as_mut()
            .unwrap()
            .slots
            .get_mut("dev")
            .unwrap()
            .allowed_capabilities = list(b, &["CHOWN", "SETUID"]);
    });
    check("depends_on order", |c, b| {
        c.workload.depends_on = list(b, &["logger", "helper"])
    });
}

#[test]
fn cpusets_normalize_in_every_container_scope() {
    for scope in 0..3 {
        check("cpuset scope", |c, b| {
            let value = Some(if b { "3,1,0,2,2" } else { "0-3" }.into());
            match scope {
                0 => c.workload.cpuset = value,
                1 => c.dependencies.get_mut("logger").unwrap().cpuset = value,
                _ => {
                    c.baby_container
                        .as_mut()
                        .unwrap()
                        .slots
                        .get_mut("dev")
                        .unwrap()
                        .cpuset = value
                }
            }
        });
    }
}
#[test]
fn dependency_and_baby_sets_and_logging_normalize() {
    check("dependency policy", |c, b| {
        let d = c.dependencies.get_mut("logger").unwrap();
        d.cap_add = list(b, &["NET_RAW", "NET_ADMIN"]);
        d.cap_drop = list(b, &["CHOWN", "SETUID"]);
        d.depends_on = list(b, &["app", "helper"]);
        d.logging.log_readers = list(b, &["app", "helper"]);
        d.logging
            .options
            .insert("max-size".into(), if b { "52428800" } else { "50m" }.into());
        d.logging
            .options
            .insert("max-file".into(), if b { "05" } else { "5" }.into());
        c.workload.workload_logs = true;
        c.dependencies.get_mut("helper").unwrap().workload_logs = true;
    });
    check("baby logging", |c, b| {
        let s = c
            .baby_container
            .as_mut()
            .unwrap()
            .slots
            .get_mut("dev")
            .unwrap();
        s.logging.log_readers = list(b, &["logger", "helper"]);
        s.logging
            .options
            .insert("max-size".into(), if b { "52428800" } else { "50m" }.into());
        s.logging
            .options
            .insert("max-file".into(), if b { "05" } else { "5" }.into());
        for d in c.dependencies.values_mut() {
            d.workload_logs = true;
        }
    });
    check("boot disk units", |c, b| {
        c.workload.boot_disk_size = Some(if b { "51200MB" } else { "50GB" }.into())
    });
    check("disk binding duplicates", |c, b| {
        let e = &mut c.disks.get_mut("data").unwrap().encryption;
        e.unlock_method = vec!["tpm".into()];
        e.bind = if b {
            vec!["workload".into(); 2]
        } else {
            vec!["workload".into()]
        };
    });
}
#[test]
fn canonical_units_preserve_exact_sizes_and_meaningful_changes() {
    for (input, expected) in [
        ("10240MB", "10GB"),
        ("10241MB", "10241MB"),
        ("1024GB", "1TB"),
        ("010GB", "10GB"),
    ] {
        let mut c = config();
        c.disks.get_mut("data").unwrap().size = input.into();
        let v: serde_json::Value = serde_json::from_str(&bytes(&c).unwrap()).unwrap();
        assert_eq!(v["disks"]["data"]["size"], expected);
    }
    let mut a = config();
    let mut b = config();
    a.workload.cpuset = Some("0-2".into());
    b.workload.cpuset = Some("0-3".into());
    assert_ne!(bytes(&a).unwrap(), bytes(&b).unwrap());
    a = config();
    b = config();
    a.workload.command = Some(atakit_workload::config::StringOrArray::Array(vec![
        "echo".into(),
        "a".into(),
        "b".into(),
    ]));
    b.workload.command = Some(atakit_workload::config::StringOrArray::Array(vec![
        "echo".into(),
        "b".into(),
        "a".into(),
    ]));
    assert_ne!(bytes(&a).unwrap(), bytes(&b).unwrap());
}
#[test]
fn reading_existing_manifests_does_not_normalize_their_values() {
    let mut value: serde_json::Value = serde_json::from_str(&bytes(&config()).unwrap()).unwrap();
    value["config"]["cpuset"] = serde_json::json!("0-3");
    value["config"]["cap-add"] = serde_json::json!(["NET_RAW", "NET_ADMIN"]);
    value["disks"]["data"]["size"] = serde_json::json!("10240MB");
    let original = serde_json_canonicalizer::to_string(&value).unwrap();
    let parsed: atakit_workload::manifest::Manifest = serde_json::from_str(&original).unwrap();
    assert_eq!(serialize_canonical_json(&parsed).unwrap(), original);
}

#[test]
fn environment_file_precedence_and_entrypoint_order_are_preserved() {
    // Exercise the same build boundary without filesystem validation: only the
    // declared order is relevant here, not env-file contents or archive staging.
    let build = |reverse| {
        let mut c = config();
        c.workload.unmeasured_env_file = Some(atakit_workload::config::StringOrArray::Array(list(
            reverse,
            &["one.env", "two.env"],
        )));
        c.workload.entrypoint = Some(atakit_workload::config::StringOrArray::Array(list(
            reverse,
            &["one", "two"],
        )));
        c.dependencies
            .get_mut("logger")
            .unwrap()
            .unmeasured_env_file = Some(atakit_workload::config::StringOrArray::Array(list(
            reverse,
            &["one.env", "two.env"],
        )));
        build_manifest(
            &c,
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
    };
    for reverse in [false, true] {
        let m = build(reverse);
        let expected = list(
            reverse,
            &["unmeasured-data/one.env", "unmeasured-data/two.env"],
        );
        assert_eq!(m.config.unmeasured_env_files, expected);
        assert_eq!(
            m.config.dependencies.as_ref().unwrap()["logger"].unmeasured_env_files,
            expected
        );
        assert_eq!(
            serde_json::to_value(&m.config.entrypoint).unwrap(),
            serde_json::json!(list(reverse, &["one", "two"]))
        );
    }
    assert_ne!(
        serialize_canonical_json(&build(false)).unwrap(),
        serialize_canonical_json(&build(true)).unwrap()
    );
}

#[test]
fn sets_and_units_normalize_in_older_supported_formats() {
    for format in 11..=15 {
        let source = SOURCE.replace("format = 16", &format!("format = {format}"));
        let source = if format < 14 {
            source.replace("access = [\"read\"]", "read-only = true")
        } else {
            source
        };
        let mut a = WorkloadConfig::load_from_str(&source).unwrap();
        let mut b = WorkloadConfig::load_from_str(&source).unwrap();
        a.workload.cap_add = list(false, &["NET_RAW", "NET_ADMIN"]);
        b.workload.cap_add = list(true, &["NET_RAW", "NET_ADMIN"]);
        b.disks.get_mut("data").unwrap().size = "10240MB".into();
        assert_eq!(
            bytes(&a).unwrap(),
            bytes(&b).unwrap(),
            "source format {format}"
        );
    }
}

#[test]
fn normalization_does_not_hide_invalid_requests() {
    let mut c = config();
    c.workload.cpuset = Some("3-0".into());
    assert!(bytes(&c).is_err());
    c = config();
    c.workload.cpu_idle = Some(
        serde_json::from_value(
            serde_json::json!({"driver":"intel_idle","disabled-states":["C6","C6"]}),
        )
        .unwrap(),
    );
    assert!(bytes(&c).is_err());
    c = config();
    c.workload.cap_add = vec!["net_admin".into()];
    assert!(bytes(&c).is_err());
    c = config();
    c.disks.get_mut("data").unwrap().size = "18446744073709551615TB".into();
    assert!(bytes(&c).is_err());
}
