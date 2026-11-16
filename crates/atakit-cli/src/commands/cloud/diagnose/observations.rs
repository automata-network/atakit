//! Explicit public fields from Portal diagnostics. Raw error messages, probe
//! output, URLs, credentials and arbitrary nested fields never enter exports.
use super::export::{enum_value, fixed_hex, public_reference};
use serde_json::{json, Value};

pub(crate) fn startup(value: &Value) -> Value {
    if !value.is_object() {
        return Value::Null;
    }
    let stage = enum_value(
        &value["stage"],
        &[
            "not_started",
            "identifiers",
            "policy_read",
            "workload_policy_read",
            "base_image_policy_read",
            "workload_signature",
            "base_image_signature",
            "policy_requirements",
            "measurements",
            "pcr_comparison",
            "complete",
        ],
    );
    let status = enum_value(
        &value["status"],
        &["not_run", "running", "passed", "failed", "skipped"],
    );
    let mut output = json!({
        "scope":"portal_local_startup", "status":status, "stage":stage,
        "source":enum_value(&value["source"], &["not_selected","publisher_signed_registry","initialization_policy"]),
        "hardware_verification":enum_value(&value["hardware_verification"], &["not_performed"]),
        "secret_provisioning":"requires_independent_verification",
        "error":if status == Some("failed") { Some(format!("startup_{}_failed",stage.unwrap_or("check"))) } else { None },
        "skip_reason":if status == Some("skipped") { Some("no_initialization_policy") } else { None },
    });
    for key in [
        "workload_id",
        "base_image_id",
        "platform_profile_id",
        "variant_id",
        "workload_publisher",
        "base_image_publisher",
        "workload_policy_digest",
        "base_image_policy_digest",
    ] {
        output[key] = json!(fixed_hex(value[key].as_str(), 32));
    }
    for key in ["workload_signature", "base_image_signature"] {
        output[key] = json!(enum_value(
            &value[key],
            &["not_checked", "passed", "failed"]
        ));
    }
    output["pcr_checks"] = json!(value["pcr_checks"].as_array().map(|checks| checks.iter().take(108).filter_map(|c| {
        let bank = enum_value(&c["bank"], &["sha256","sha384"])?;
        let bytes = if bank == "sha256" {32} else {48};
        let index = c["index"].as_u64().filter(|i| *i <= 23)?;
        let actual = fixed_hex(c["actual"].as_str(),bytes)?;
        Some(json!({"block":enum_value(&c["block"], &["invariant","variant","workload"]),
            "bank":bank,"index":index,"actual":actual,"expected":fixed_hex(c["expected"].as_str(),bytes),
            "status":enum_value(&c["status"], &["passed","failed"]),
            "comparison":enum_value(&c["comparison"], &["static","dynamic_subset","dynamic_subsequence","dynamic_indexed_event_sets","extend_from_zero","invalid"]),
            "rule_digest":fixed_hex(c["rule_digest"].as_str(),32),
            "error":if c["status"] == "failed" {Some("pcr_comparison_failed")} else {None}}))
    }).collect::<Vec<_>>()));
    output
}

pub(crate) fn readiness(value: &Value) -> Value {
    let Some(items) = value.as_object() else {
        return Value::Null;
    };
    json!(items.iter().take(128).filter_map(|(name, v)| {
        let name = public_reference(Some(name))?;
        Some(json!({"service":name,"state":enum_value(&v["state"], &["waiting","not_configured","checking","ready","failed"]),
            "attempts":v["attempts"].as_u64(),"elapsed_ms":v["elapsed_ms"].as_u64(),
            "last_exit_code":v["last_exit_code"].as_i64(),
            "error":if v["state"] == "failed" {Some("readiness_failed")} else {None}}))
    }).collect::<Vec<_>>())
}

fn storage_error(value: &Value) -> Option<&str> {
    enum_value(
        value,
        &[
            "not_mounted_or_locked",
            "filesystem_read_failed",
            "quota_unavailable",
            "mount_table_unavailable",
            "disk_inventory_unavailable",
            "storage_read_failed",
            "collection_pending",
        ],
    )
}

pub(crate) fn storage(value: &Value) -> Value {
    if !value.is_object() {
        return Value::Null;
    }
    let entries = value["entries"].as_array().map(|entries| entries.iter().take(64).filter_map(|v| {
        let kind = enum_value(&v["kind"], &["portal","container_images","workload_disk","baby_root"])?;
        let name = public_reference(v["name"].as_str())?;
        let state = enum_value(&v["state"], &["available","unavailable"])?;
        let available = state == "available";
        let number = |key: &str| if available { v[key].as_u64() } else { None };
        let filesystem = v["filesystem_id"].as_str().filter(|s| {
            s.split_once(':').is_some_and(|(a,b)| a.parse::<u32>().is_ok() && b.parse::<u32>().is_ok())
        });
        let q = &v["quota"];
        let quota = if available && q.is_object() {
            match (q["used_bytes"].as_u64(),q["limit_bytes"].as_u64(),q["used_inodes"].as_u64(),q["limit_inodes"].as_u64()) {
                (Some(used),Some(limit),Some(inodes),Some(inode_limit)) if limit > 0 && inode_limit > 0 =>
                    json!({"used_bytes":used,"limit_bytes":limit,"used_inodes":inodes,"limit_inodes":inode_limit}),
                _ => Value::Null,
            }
        } else { Value::Null };
        Some(json!({"kind":kind,"name":name,"state":state,
            "filesystem_id":if available { filesystem } else { None },
            "capacity_bytes":number("capacity_bytes"),"used_bytes":number("used_bytes"),"available_bytes":number("available_bytes"),
            "low_space":if available { v["low_space"].as_bool() } else { None },
            "quota":quota,"error":storage_error(&v["error"])}))
    }).collect::<Vec<_>>());
    json!({"source":"portal_reported","sampled_at_ms":value["sampled_at_ms"].as_u64(),
        "stale":value["stale"].as_bool(),"refreshing":value["refreshing"].as_bool(),
        "low_space_percent":value["low_space_percent"].as_u64().filter(|n| *n <= 100),
        "truncated":value["truncated"].as_bool(),"error":storage_error(&value["error"]),"entries":entries})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_diagnostics_retain_values_without_raw_errors_or_secrets() {
        let input = json!({"status":"failed","stage":"pcr_comparison","detail":"SECRET https://token@host",
            "workload_signature":"passed","workload_publisher":format!("0x{}","ab".repeat(32)),
            "pcr_checks":[{"block":"workload","bank":"sha256","index":23,"status":"failed",
                "expected":format!("0x{}","11".repeat(32)),"actual":format!("0x{}","22".repeat(32)),"detail":"SECRET"}],
            "private_key":"SECRET"});
        let output = startup(&input);
        assert_eq!(output["error"], "startup_pcr_comparison_failed");
        assert_eq!(
            output["pcr_checks"][0]["actual"],
            input["pcr_checks"][0]["actual"]
        );
        assert!(!output.to_string().contains("SECRET"));
        let ready = readiness(
            &json!({"web":{"state":"failed","attempts":3,"elapsed_ms":1200,"last_exit_code":1,"error":"SECRET","command":"SECRET"}}),
        );
        assert_eq!(ready[0]["attempts"], 3);
        assert_eq!(ready[0]["error"], "readiness_failed");
        assert!(!ready.to_string().contains("SECRET"));
    }
    #[test]
    fn unavailable_and_legacy_storage_cannot_become_zero_usage() {
        assert!(storage(&Value::Null).is_null());
        let output = storage(
            &json!({"entries":[{"kind":"workload_disk","name":"data","state":"unavailable",
            "used_bytes":0,"capacity_bytes":100,"available_bytes":100,"low_space":false,"passphrase":"SECRET"}]}),
        );
        assert!(output["entries"][0]["used_bytes"].is_null());
        assert!(output["entries"][0]["low_space"].is_null());
        assert!(!output.to_string().contains("SECRET"));
    }
}
