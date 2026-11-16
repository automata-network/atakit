use std::time::Duration;

use alloy_ext::{
    core::primitives::{Address, B256},
    ext::NetworkProvider,
    providers::Provider,
};
use anyhow::{bail, Context, Result};
use atakit_attestation::{BindingMode, VerifiedSession};
use atakit_cloud::{
    cli::{DiagnoseArgs, StatusArgs},
    DeployState,
};
use atakit_core::Env;
use automata_tee_workload_measurement::stubs::SessionRegistry::SessionRegistryInstance;
use serde_json::{json, Value};

use super::super::diagnose::{self, display_text, Outcome};
use crate::config::Config;

pub(super) async fn verified(
    args: &StatusArgs,
    state: DeployState,
    env: &Env,
    config: &Config,
) -> Value {
    let report = diagnose::collect(
        DiagnoseArgs {
            report: None,
            workload_log: vec![],
            log_report: None,
            instance: args.instance.clone(),
            target: args.target.clone(),
            check_timeout: args.check_timeout,
            verification: args.verification.clone(),
        },
        state,
        env,
        config,
        false,
    )
    .await;
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            return json!({"failed": true, "portal": {
                "verified": false, "state": null, "error": display_text(&error.to_string())
            }})
        }
    };
    from_report(report, args.check_timeout, config).await
}

async fn from_report(report: diagnose::Report, seconds: u64, config: &Config) -> Value {
    let mut failed = report.failed();
    let checks: Vec<_> = report
        .checks
        .iter()
        .map(|check| {
            json!({
                "name": check.name,
                "outcome": match check.outcome { Outcome::Pass => "PASS", Outcome::Fail => "FAIL",
                    Outcome::Reported => "REPORTED", Outcome::NotChecked => "NOT CHECKED" },
                "detail": display_text(&check.detail),
            })
        })
        .collect();
    let portal = report.status.as_ref().map(|v| portal_summary(v, true)).unwrap_or_else(||
        json!({"state": null, "verified": false, "error": "verified status unavailable; see checks"}));
    let mut session = json!({"verified": false, "expiry": {"outcome": "NOT CHECKED",
        "detail": "no verified current session"}});
    if let Some(verified) = &report.session {
        session["verified"] = json!(true);
        session["id"] = json!(format!("0x{}", hex::encode(verified.session_id)));
        session["binding"] = json!(verified.binding_mode);
        session["expiry"] = if verified.binding_mode == BindingMode::Local {
            json!({"outcome": "NOT APPLICABLE", "detail": "local session has no registry expiry"})
        } else if let Some(name) = report.chain_name.as_deref() {
            match tokio::time::timeout(
                Duration::from_secs(seconds),
                chain_session(name, verified, config),
            )
            .await
            {
                Ok(Ok(value)) => {
                    failed |= value["active"] == false;
                    value
                }
                result => {
                    failed = true;
                    let detail = match result {
                        Ok(Err(error)) => display_text(&error.to_string()),
                        _ => "session registry check timed out".into(),
                    };
                    json!({"outcome": "FAIL", "detail": detail})
                }
            }
        } else {
            json!({"outcome": "NOT CHECKED", "detail": "no configured chain for registry expiry"})
        };
    }
    json!({"ip": report.host, "provider_error": null, "portal": portal,
        "session": session, "checks": checks, "failed": failed})
}

async fn chain_session(name: &str, session: &VerifiedSession, config: &Config) -> Result<Value> {
    let chain = config
        .chains
        .get(name)
        .context("selected chain is not configured")?;
    let address: Address = chain
        .session_registry
        .parse()
        .context("invalid configured session_registry")?;
    if address.as_slice() != session.binding_registry {
        bail!("configured registry differs from verified session binding");
    }
    let provider = NetworkProvider::with_http(
        &chain.rpc_url,
        Some(Duration::from_secs(1)),
        Some(Duration::from_secs(15)),
        1,
    )
    .await?;
    if provider.get_chain_id().await? != session.binding_chain_id {
        bail!("configured RPC chain differs from verified session binding");
    }
    // Pin all three reads to one block so renewal cannot mix expiry and activity.
    let block = provider.get_block_number().await?;
    let registry = SessionRegistryInstance::new(address, provider);
    let id = B256::from(session.session_id);
    let record = registry.getSession(id).block(block.into()).call().await?;
    if record.sessionKeyFingerprint.as_slice() != session.session_key_fingerprint {
        bail!("registry session key differs from the verified session key");
    }
    let active = registry
        .isSessionActive(id)
        .block(block.into())
        .call()
        .await?;
    let expired = registry
        .isSessionExpired(id)
        .block(block.into())
        .call()
        .await?;
    Ok(expiry_summary(
        record.sessionExpiresAt,
        active,
        expired,
        block,
    ))
}

fn expiry_summary(expires_at: u64, active: bool, expired: bool, block: u64) -> Value {
    let expires_at_utc = i64::try_from(expires_at)
        .ok()
        .and_then(|n| chrono::DateTime::from_timestamp(n, 0))
        .map(|time| time.to_rfc3339());
    json!({"outcome": if active { "PASS" } else { "FAIL" }, "active": active,
        "expired": expired, "expires_at": expires_at, "expires_at_utc": expires_at_utc, "block_number": block,
        "detail": if expired { "session expired" } else if !active { "session inactive" }
            else { "session active" }})
}

/// Only public status fields are displayed; never serialize an entire portal response.
pub(super) fn portal_summary(status: &Value, verified: bool) -> Value {
    let disks = status["disks"].as_object().map(|disks| {
        disks
            .iter()
            .map(|(name, disk)| {
                json!({"name": display_text(name), "state": public_string(&disk["state"]),
            "needs_unlock": disk["state"] == "awaiting_passphrase",
            "operation": public_string(&disk["operation"]),
            "elapsed_seconds": disk["elapsed_seconds"].as_u64()})
            })
            .collect::<Vec<_>>()
    });
    let containers = status["containers"]["services"].as_array().map(|services| {
        services
            .iter()
            .map(|s| {
                json!({"name": public_string(&s["name"]), "state": public_string(&s["state"]),
            "exit_code": s["exit_code"].as_i64(), "cpuset": public_string(&s["cpuset"]), "effective_cpuset": public_string(&s["effective_cpuset"])})
            })
            .collect::<Vec<_>>()
    });
    json!({"state": public_string(&status["state"]), "verified": verified, "error": null,
        "disks": disks, "containers": containers,
        "cpu_idle": cpu_idle_summary(&status["cpu_idle"]),
        "runtime": status["runtime"].clone(),
        "cpu_frequency": cpu_frequency_summary(&status["cpu_frequency"]),
        "startup_checks": startup_checks_summary(&status["startup_checks"]),
        "storage": diagnose::observations::storage(&status["storage"]),
        "containers_error": public_string(&status["containers"]["error"]),
        "registration": public_string(&status["chain"]["status"])})
}

// Explicit fields only; observations are not a hardware attestation claim.
fn cpu_idle_summary(value: &Value) -> Value {
    if !value.is_object() {
        return Value::Null;
    }
    let requested = &value["requested"];
    json!({
        "status": public_string(&value["status"]),
        "detail": public_string(&value["detail"]),
        "driver": public_string(&value["driver"]),
        "governor": public_string(&value["governor"]),
        "requested": if requested.is_object() { json!({
            "driver": public_string(&requested["driver"]),
            "governor": public_string(&requested["governor"]),
            "required": requested["required"].as_bool(),
            "disabled-states": requested["disabled-states"].as_array().map(|s| s.iter().filter_map(public_string).collect::<Vec<_>>())
        }) } else { Value::Null },
        "available_governors": value["available_governors"].as_array().map(|s| s.iter().filter_map(public_string).collect::<Vec<_>>()),
        "states": value["states"].as_object().map(|cpus| cpus.iter().filter_map(|(cpu, states)| {
            cpu.parse::<u32>().ok()?;
            Some((cpu.clone(), json!(states.as_array()?.iter().map(|state| json!({"name": public_string(&state["name"]), "disabled": state["disabled"].as_bool()})).collect::<Vec<_>>())))
        }).collect::<serde_json::Map<String, Value>>())
    })
}

fn cpu_frequency_summary(value: &Value) -> Value {
    if !value.is_object() {
        return Value::Null;
    }
    let requested = &value["requested"];
    json!({
        "status": public_string(&value["status"]),
        "detail": public_string(&value["detail"]),
        "requested": if requested.is_object() { json!({
            "governor": public_string(&requested["governor"]),
            "required": requested["required"].as_bool()
        }) } else { Value::Null },
        "policies": value["policies"].as_object().map(|policies| policies.iter().filter_map(|(name, p)| {
            name.strip_prefix("policy")?.parse::<u32>().ok()?;
            Some((name.clone(), json!({
                "driver": public_string(&p["driver"]),
                "governor": public_string(&p["governor"]),
                "available_governors": p["available_governors"].as_array().map(|s| s.iter().filter_map(public_string).collect::<Vec<_>>()),
                "affected_cpus": p["affected_cpus"].as_array().map(|s| s.iter().filter_map(Value::as_u64).collect::<Vec<_>>())
            })))
        }).collect::<serde_json::Map<String, Value>>())
    })
}

// Never turn a Portal-local check into the CLI's independent attestation verdict.
fn startup_checks_summary(value: &Value) -> Value {
    if !value.is_object() {
        return Value::Null;
    }
    let mut output = serde_json::Map::new();
    for field in [
        "status",
        "source",
        "stage",
        "workload_id",
        "base_image_id",
        "platform_profile_id",
        "variant_id",
        "workload_publisher",
        "base_image_publisher",
        "workload_policy_digest",
        "base_image_policy_digest",
        "workload_signature",
        "base_image_signature",
        "detail",
        "hardware_verification",
    ] {
        output.insert(field.into(), json!(public_string(&value[field])));
    }
    output.insert("scope".into(), json!("portal_local_startup"));
    output.insert(
        "secret_provisioning".into(),
        json!("requires_independent_verification"),
    );
    let checks = value["pcr_checks"].as_array().map(|checks| checks.iter().take(108).map(|check| {
        json!({"block": public_string(&check["block"]), "bank": public_string(&check["bank"]),
            "index": check["index"].as_u64(), "status": public_string(&check["status"]),
            "comparison": public_string(&check["comparison"]), "expected": public_string(&check["expected"]),
            "actual": public_string(&check["actual"]), "rule_digest": public_string(&check["rule_digest"]),
            "detail": public_string(&check["detail"])})
    }).collect::<Vec<_>>());
    output.insert("pcr_checks".into(), json!(checks));
    Value::Object(output)
}

fn storage_lines(storage: &Value) -> Vec<String> {
    if !storage.is_object() {
        return vec!["  Storage: NOT REPORTED (older Portal or unavailable status)".into()];
    }
    let gib = |v: &Value| {
        v.as_u64()
            .map(|n| format!("{:.2} GiB", n as f64 / 1073741824.0))
            .unwrap_or_else(|| "unavailable".into())
    };
    let mut lines = vec![format!(
        "  Storage (sample time: {} ms since epoch{}):",
        storage["sampled_at_ms"]
            .as_u64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unavailable".into()),
        if storage["stale"] == true {
            "; STALE"
        } else {
            ""
        }
    )];
    if let Some(error) = storage["error"].as_str() {
        lines.push(format!("    Status: {error}"));
    }
    if storage["truncated"] == true {
        lines.push("    Additional storage entries omitted (report limit reached).".into());
    }
    let mut filesystems = std::collections::BTreeMap::new();
    if let Some(entries) = storage["entries"].as_array() {
        for entry in entries {
            let name = format!(
                "{}: {}",
                entry["kind"].as_str().unwrap_or("storage"),
                entry["name"].as_str().unwrap_or("?")
            );
            if entry["state"] != "available" {
                lines.push(format!(
                    "    {name}: UNAVAILABLE ({})",
                    entry["error"].as_str().unwrap_or("not reported")
                ));
                continue;
            }
            lines.push(format!(
                "    {name}: used {}; available {}; capacity {}{}",
                gib(&entry["used_bytes"]),
                gib(&entry["available_bytes"]),
                gib(&entry["capacity_bytes"]),
                if entry["low_space"] == true {
                    "; LOW SPACE"
                } else {
                    ""
                }
            ));
            if let Some(id) = entry["filesystem_id"].as_str() {
                if let Some(prior) = filesystems.get(id) {
                    lines.push(format!("      Shares filesystem with {prior}."));
                } else {
                    filesystems.insert(id.to_owned(), name);
                }
            }
            if entry["quota"].is_object() {
                let q = &entry["quota"];
                lines.push(format!(
                    "      Quota: {} used / {} allowed; inodes {} / {}",
                    gib(&q["used_bytes"]),
                    gib(&q["limit_bytes"]),
                    q["used_inodes"],
                    q["limit_inodes"]
                ));
            }
            if let Some(error) = entry["error"].as_str() {
                lines.push(format!("      Status: {error}"));
            }
        }
    }
    lines.push("    Capacities are not additive: filesystems may be shared or backed by another listed filesystem.".into());
    lines
}

fn public_string(value: &Value) -> Option<String> {
    value.as_str().map(display_text)
}

fn cpu_idle_lines(idle: &Value) -> Vec<String> {
    if !idle.is_object() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "  CPU idle: {}",
        idle["status"].as_str().unwrap_or("unknown")
    )];
    let requested = &idle["requested"];
    if requested.is_object() {
        let states = requested["disabled-states"]
            .as_array()
            .map(|states| {
                if states.is_empty() {
                    "none".to_string()
                } else {
                    states
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            })
            .unwrap_or_else(|| "unavailable".into());
        lines.push(format!(
            "    Requested: driver {}; governor {}; disabled states {}",
            requested["driver"].as_str().unwrap_or("unavailable"),
            requested["governor"].as_str().unwrap_or("unchanged"),
            states
        ));
    }
    lines.push(format!(
        "    Current: driver {}; governor {}",
        idle["driver"].as_str().unwrap_or("unavailable"),
        idle["governor"].as_str().unwrap_or("unavailable")
    ));
    if let Some(detail) = idle["detail"].as_str() {
        lines.push(format!("    Reason: {detail}"));
    }
    lines
}

pub(super) fn print_details(live: &Value) {
    if let Some(checks) = live["checks"].as_array() {
        for check in checks {
            eprintln!(
                "  {} {}: {}",
                check["outcome"].as_str().unwrap_or("NOT CHECKED"),
                check["name"].as_str().unwrap_or("Check"),
                check["detail"].as_str().unwrap_or("")
            );
        }
    }
    let portal = &live["portal"];
    let runtime = &portal["runtime"];
    if runtime["active"]["cpu"].is_object() {
        println!(
            "  Operator CPU choices: {}",
            runtime["active"]["cpu"]["config"]
        );
        println!(
            "  CPU choice sources: {}",
            runtime["active"]["cpu"]["sources"]
        );
    }
    if let Some(services) = portal["containers"].as_array() {
        for service in services {
            println!(
                "  CPU set {}: requested {}, effective {}",
                service["name"], service["cpuset"], service["effective_cpuset"]
            );
        }
    }
    if runtime["pending"]
        .as_object()
        .is_some_and(|p| !p.is_empty())
    {
        println!(
            "  Pending runtime choices: {} (reboot to apply all groups)",
            runtime["pending"]
        );
    }
    if runtime["active"].is_object() {
        println!("  Runtime disks: {}", runtime["active"]["disks"]);
        println!(
            "  THP: active {}; observed {}",
            runtime["active"]["thp"], runtime["observed"]["thp"]
        );
    }
    for line in cpu_idle_lines(&portal["cpu_idle"]) {
        eprintln!("{line}");
    }
    if portal["cpu_frequency"].is_object() {
        let frequency = &portal["cpu_frequency"];
        eprintln!(
            "  CPU frequency: {}",
            frequency["status"].as_str().unwrap_or("unknown")
        );
        if let Some(policies) = frequency["policies"].as_object() {
            for (name, policy) in policies {
                eprintln!(
                    "    {}: driver {}; governor {}; available {}",
                    name,
                    policy["driver"].as_str().unwrap_or("unavailable"),
                    policy["governor"].as_str().unwrap_or("unavailable"),
                    policy["available_governors"]
                        .as_array()
                        .map(|v| v
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", "))
                        .unwrap_or_default()
                );
            }
        }
        if let Some(detail) = frequency["detail"].as_str() {
            eprintln!("    {detail}");
        }
    }
    for line in storage_lines(&portal["storage"]) {
        eprintln!("{line}");
    }
    if let Some(detail) = portal["startup_checks"].as_object() {
        let field = |key: &str| {
            detail
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("not available")
        };
        eprintln!(
            "  Portal-local startup checks: {} (stage: {}; source: {})",
            field("status"),
            field("stage"),
            field("source")
        );
        eprintln!("    These checks do not authorize secret provisioning; independent verification is required.");
        for (label, key) in [
            ("Workload policy", "workload_id"),
            ("Base image", "base_image_id"),
            ("Profile", "platform_profile_id"),
            ("Variant", "variant_id"),
            ("Workload publisher", "workload_publisher"),
            ("Base-image publisher", "base_image_publisher"),
            ("Workload signature", "workload_signature"),
            ("Base-image signature", "base_image_signature"),
        ] {
            eprintln!("    {label}: {}", field(key));
        }
        if let Some(message) = detail.get("detail").and_then(Value::as_str) {
            eprintln!("    Detail: {message}");
        }
        if let Some(checks) = detail.get("pcr_checks").and_then(Value::as_array) {
            for check in checks.iter().filter(|check| check["status"] == "failed") {
                eprintln!(
                    "    Failed {} {} PCR {} ({}): expected {}; actual {}; {}",
                    check["block"].as_str().unwrap_or("?"),
                    check["bank"].as_str().unwrap_or("?"),
                    check["index"],
                    check["comparison"].as_str().unwrap_or("?"),
                    check["expected"]
                        .as_str()
                        .unwrap_or("dynamic rule; see rule_digest in JSON"),
                    check["actual"].as_str().unwrap_or("unavailable"),
                    check["detail"].as_str().unwrap_or("")
                );
            }
        }
    } else {
        eprintln!(
            "  Portal-local startup checks: NOT REPORTED (older Portal or unavailable status)"
        );
    }
    eprintln!(
        "  Registration: {}",
        portal["registration"].as_str().unwrap_or("NOT CHECKED")
    );
    if let Some(disks) = portal["disks"].as_array() {
        for disk in disks {
            if let Some(operation) = disk["operation"].as_str() {
                eprintln!(
                    "  Disk {}: {} ({}s)",
                    disk["name"].as_str().unwrap_or("?"),
                    operation,
                    disk["elapsed_seconds"].as_u64().unwrap_or(0)
                );
            }
            eprintln!(
                "  Disk {}: {}{}",
                disk["name"].as_str().unwrap_or("?"),
                disk["state"].as_str().unwrap_or("unknown"),
                if disk["needs_unlock"] == true {
                    " (needs unlock)"
                } else {
                    ""
                }
            );
        }
    } else {
        eprintln!("  Disks: NOT CHECKED");
    }
    if let Some(containers) = portal["containers"].as_array() {
        for c in containers {
            eprintln!(
                "  Container {}: {}; exit code: {}",
                c["name"].as_str().unwrap_or("?"),
                c["state"].as_str().unwrap_or("unknown"),
                c["exit_code"]
                    .as_i64()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "not reported".into())
            );
        }
    } else {
        eprintln!(
            "  Containers: NOT CHECKED ({})",
            portal["containers_error"]
                .as_str()
                .unwrap_or("portal did not report container status")
        );
    }
    let expiry = &live["session"]["expiry"];
    eprintln!(
        "  Session expiry: {}; {}{}",
        expiry["outcome"].as_str().unwrap_or("NOT CHECKED"),
        expiry["detail"].as_str().unwrap_or("NOT CHECKED"),
        expiry["expires_at_utc"]
            .as_str()
            .map(|time| format!("; expires at {time}"))
            .or_else(|| expiry["expires_at"]
                .as_u64()
                .map(|n| format!("; Unix timestamp {n}")))
            .unwrap_or_default()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_frequency_status_preserves_requested_and_observed_values() {
        let value = cpu_frequency_summary(&json!({"status":"applied",
            "requested":{"governor":"performance","required":true,"private":"SECRET"},
            "policies":{"policy0":{"driver":"test","governor":"performance",
                "available_governors":["powersave","performance"],"affected_cpus":[0,1],"private":"SECRET"},
                "invalid":{"driver":"SECRET"}},"private":"SECRET"}));
        assert_eq!(value["requested"]["governor"], "performance");
        assert_eq!(value["policies"]["policy0"]["affected_cpus"], json!([0, 1]));
        assert!(!value.to_string().contains("SECRET"));
        assert!(value["policies"].get("invalid").is_none());
        assert!(cpu_frequency_summary(&Value::Null).is_null());
    }

    #[test]
    fn cpu_idle_status_preserves_requested_and_observed_values() {
        let value = cpu_idle_summary(
            &json!({"status":"unsupported", "driver":"none", "governor":"menu",
            "detail":"VM exposes no active CPU idle driver", "requested":{"driver":"auto", "governor":"teo", "required":false,"disabled-states":["C6", "C1E"]},
            "states":{"0":[{"name":"C1","disabled":false}]}, "available_governors":["menu"], "private":"SECRET"}),
        );
        assert_eq!(value["status"], "unsupported");
        assert_eq!(value["requested"]["driver"], "auto");
        assert_eq!(value["requested"]["governor"], "teo");
        assert_eq!(value["requested"]["disabled-states"][0], "C6");
        assert_eq!(value["states"]["0"][0]["disabled"], false);
        assert!(value.get("private").is_none());
        assert!(cpu_idle_summary(&Value::Null).is_null());
        assert_eq!(
            cpu_idle_lines(&value),
            vec![
                "  CPU idle: unsupported",
                "    Requested: driver auto; governor teo; disabled states C6, C1E",
                "    Current: driver none; governor menu",
                "    Reason: VM exposes no active CPU idle driver",
            ]
        );
    }

    #[test]
    fn cpu_idle_text_distinguishes_defaults_and_partial_requests() {
        assert!(cpu_idle_lines(&Value::Null).is_empty());
        let defaults = cpu_idle_lines(
            &json!({"status":"defaults", "driver":"acpi_idle", "governor":"menu", "requested":null}),
        );
        assert_eq!(
            defaults,
            vec![
                "  CPU idle: defaults",
                "    Current: driver acpi_idle; governor menu",
            ]
        );
        let states_only = cpu_idle_lines(
            &json!({"status":"applied", "driver":"intel_idle", "governor":"menu",
            "requested":{"driver":"intel_idle", "governor":null, "disabled-states":["C6"]}}),
        );
        assert!(states_only[1].contains("governor unchanged; disabled states C6"));
        let governor_only = cpu_idle_lines(
            &json!({"status":"applied", "driver":"acpi_idle", "governor":"teo",
            "requested":{"driver":"auto", "governor":"teo", "disabled-states":[]}}),
        );
        assert!(governor_only[1].contains("governor teo; disabled states none"));
    }

    #[test]
    fn storage_display_reports_shared_capacity_quotas_and_unavailable_disks() {
        assert!(storage_lines(&Value::Null)[0].contains("NOT REPORTED"));
        let storage = diagnose::observations::storage(
            &json!({"sampled_at_ms":123,"stale":true,"entries":[
            {"kind":"portal","name":"portal","state":"available","filesystem_id":"8:1","used_bytes":95,"available_bytes":5,"capacity_bytes":100,"low_space":true},
            {"kind":"container_images","name":"container_images","state":"available","filesystem_id":"8:1","used_bytes":95,"available_bytes":5,"capacity_bytes":100,"low_space":true},
            {"kind":"baby_root","name":"root","state":"available","quota":{"used_bytes":10,"limit_bytes":100,"used_inodes":2,"limit_inodes":10}},
            {"kind":"workload_disk","name":"data","state":"unavailable","error":"not_mounted_or_locked"}]}),
        );
        let output = storage_lines(&storage).join("\n");
        for expected in [
            "STALE",
            "LOW SPACE",
            "Shares filesystem with portal: portal",
            "Quota:",
            "inodes 2 / 10",
            "data: UNAVAILABLE",
            "Capacities are not additive",
        ] {
            assert!(output.contains(expected), "{output}");
        }
    }

    #[tokio::test]
    async fn session_expiry_reads_the_verified_id_at_one_block_and_rejects_mismatches() {
        use alloy_ext::core::primitives::keccak256;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (active, expired, key, chain_id) in [
            (true, false, 2u8, 1u64),
            (false, true, 2, 1),
            (false, false, 2, 1),
            (true, false, 3, 1),
            (true, false, 2, 2),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorded = calls.clone();
            let server = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    let parsed: Value = loop {
                        let mut buf = [0; 4096];
                        let n = stream.read(&mut buf).await.unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&buf[..n]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers =
                                String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                            let length: usize = headers
                                .lines()
                                .find_map(|line| {
                                    line.strip_prefix("content-length:")
                                        .map(|n| n.trim().parse().unwrap())
                                })
                                .unwrap();
                            if request.len() >= end + 4 + length {
                                break serde_json::from_slice(&request[end + 4..end + 4 + length])
                                    .unwrap();
                            }
                        }
                    };
                    recorded.lock().unwrap().push(parsed.clone());
                    let result = match parsed["method"].as_str().unwrap() {
                        "eth_chainId" => format!("0x{chain_id:x}"),
                        "eth_blockNumber" => "0x2a".into(),
                        "eth_call" => {
                            let input = parsed["params"][0]["input"]
                                .as_str()
                                .or_else(|| parsed["params"][0]["data"].as_str())
                                .unwrap();
                            assert_eq!(parsed["params"][1], "0x2a");
                            assert_eq!(&input[10..], "01".repeat(32));
                            assert_eq!(parsed["params"][0]["to"], format!("0x{}", "11".repeat(20)));
                            let selector = &input[2..10];
                            if selector == hex::encode(&keccak256(b"getSession(bytes32)")[..4]) {
                                let mut words = vec![0u8; 9 * 32];
                                words[64..96].fill(key);
                                words[8 * 32 + 31] = 100;
                                format!("0x{}", hex::encode(words))
                            } else {
                                let value = if selector
                                    == hex::encode(&keccak256(b"isSessionActive(bytes32)")[..4])
                                {
                                    active
                                } else {
                                    assert_eq!(
                                        selector,
                                        hex::encode(&keccak256(b"isSessionExpired(bytes32)")[..4])
                                    );
                                    expired
                                };
                                format!("0x{:064x}", u8::from(value))
                            }
                        }
                        other => panic!("unexpected RPC {other}"),
                    };
                    let body =
                        json!({"jsonrpc":"2.0", "id":parsed["id"], "result":result}).to_string();
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                }
            });
            let mut config = Config::default();
            config.chains.insert(
                "test".into(),
                crate::config::ChainConfig {
                    rpc_url: format!("http://{address}"),
                    session_registry: format!("0x{}", "11".repeat(20)),
                    workload_registry: None,
                    base_image_registry: None,
                    chain_id: Some(1),
                    tee_backend: "auto".into(),
                    prover: None,
                },
            );
            let session = VerifiedSession {
                session_id: [1; 32],
                session_key_fingerprint: [2; 32],
                session_key_type_id: 3,
                session_public_key: vec![],
                binding_mode: BindingMode::Chain,
                binding_chain_id: 1,
                binding_registry: [0x11; 20],
                attestation_mode: atakit_attestation::SessionAttestationMode::Hardware,
                checks: vec![],
            };
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                chain_session("test", &session, &config),
            )
            .await;
            server.abort();
            let _ = server.await;
            let result = result.expect("registry check timed out");
            if key != 2 || chain_id != 1 {
                assert!(result.is_err());
                assert!(
                    calls
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|c| c["method"] == "eth_call")
                        .count()
                        < 3
                );
            } else {
                let value = result.unwrap();
                assert_eq!(value["active"], active);
                assert_eq!(value["expired"], expired);
                assert_eq!(value["expires_at"], 100);
                assert_eq!(value["block_number"], 42);
                assert_eq!(value["outcome"], if active { "PASS" } else { "FAIL" });
            }
        }
    }

    #[tokio::test]
    async fn failed_refresh_cannot_reuse_previous_verified_status() {
        let mut success = diagnose::Report::default();
        success.status = Some(json!({"state":"Running", "disks":{},
            "containers":{"services":[{"name":"web", "state":"running"}]}}));
        success.session = Some(VerifiedSession {
            session_id: [1; 32],
            session_key_fingerprint: [2; 32],
            session_key_type_id: 3,
            session_public_key: vec![],
            binding_mode: BindingMode::Local,
            binding_chain_id: 0,
            binding_registry: [0; 20],
            attestation_mode: atakit_attestation::SessionAttestationMode::Emulation,
            checks: vec![],
        });
        let first = from_report(success, 1, &Config::default()).await;
        assert_eq!(first["portal"]["verified"], true);
        assert_eq!(first["portal"]["state"], "Running");
        assert_eq!(first["session"]["verified"], true);
        assert_eq!(first["session"]["expiry"]["outcome"], "NOT APPLICABLE");

        let mut failure = diagnose::Report::default();
        failure.checks.push(diagnose::Check {
            name: "Portal TLS".into(),
            outcome: Outcome::Fail,
            detail: "certificate verification failed".into(),
        });
        let second = from_report(failure, 1, &Config::default()).await;
        assert_eq!(second["failed"], true);
        assert_eq!(second["portal"]["verified"], false);
        assert!(second["portal"]["state"].is_null());
        assert!(second["portal"]["containers"].is_null());
        assert_eq!(second["session"]["verified"], false);
        assert!(second["session"]["id"].is_null());
    }

    #[test]
    fn startup_diagnostics_never_replace_independent_verification() {
        let old = portal_summary(&json!({"state":"Running"}), false);
        assert!(old["startup_checks"].is_null());
        let value = portal_summary(
            &json!({"startup_checks": {
                "status":"passed", "scope":"independently_verified", "secret_provisioning":"allowed",
                "private_key":"SECRET", "pcr_checks":[{"bank":"sha256", "index":23,
                    "status":"failed", "expected":"0x01", "actual":"0x02", "secret":"SECRET"}]
            }}),
            false,
        );
        assert_eq!(value["verified"], false);
        assert_eq!(value["startup_checks"]["scope"], "portal_local_startup");
        assert_eq!(
            value["startup_checks"]["secret_provisioning"],
            "requires_independent_verification"
        );
        assert_eq!(value["startup_checks"]["pcr_checks"][0]["expected"], "0x01");
        assert_eq!(value["startup_checks"]["pcr_checks"][0]["actual"], "0x02");
        assert!(!value.to_string().contains("SECRET"));
    }

    #[test]
    fn expiry_uses_registry_results_including_inactive_unexpired_sessions() {
        assert_eq!(expiry_summary(100, true, false, 42)["outcome"], "PASS");
        let expired = expiry_summary(100, false, true, 43);
        assert_eq!(expired["detail"], "session expired");
        assert_eq!(expired["expires_at"], 100);
        assert_eq!(
            expiry_summary(200, false, false, 44)["detail"],
            "session inactive"
        );
    }

    #[test]
    fn status_filters_secrets_and_distinguishes_missing_data_from_empty_data() {
        let value = portal_summary(
            &json!({"state":"Running", "detail":"SECRET",
            "disks":{"data":{"state":"awaiting_passphrase", "passphrase":"SECRET"}},
            "containers":{"services":[{"name":"web", "state":"exited", "exit_code":1,
                "env":"SECRET", "health":"unhealthy"}]}}),
            true,
        );
        assert!(!value.to_string().contains("SECRET"));
        assert_eq!(value["disks"][0]["needs_unlock"], true);
        assert_eq!(value["containers"][0]["exit_code"], 1);
        assert!(portal_summary(&json!({"state":"Running"}), false)["containers"].is_null());
        assert_eq!(
            portal_summary(&json!({"containers":{"services":[]}}), true)["containers"],
            json!([])
        );
    }
}
