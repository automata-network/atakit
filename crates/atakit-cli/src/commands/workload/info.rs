use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::InfoArgs;
use atakit_workload::manifest::{Manifest, ManifestFirewallAllow};
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;
use sha2::Digest;

use super::{find_archive, looks_like_store_ref};
use crate::config::Config;

pub async fn run(args: InfoArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != "auto" => {
            Some(atakit_workload::ContainerEngine::from_str_opt(
                &config.build.container_engine,
            )?)
        }
        None => None,
    };

    let opts = if let Some(ref archive_arg) = args.archive {
        // Check if it looks like a store reference (name:version)
        let archive_str = archive_arg.to_string_lossy();
        if looks_like_store_ref(&archive_str) {
            let store = WorkloadStore::new(&env.workload_dir);
            let (name, version) = archive_str
                .split_once(':')
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .unwrap();
            let blob = store.blob_path(&name, &version)?;
            if !blob.exists() {
                anyhow::bail!("no archive blob for {name}:{version} in store");
            }
            atakit_workload::InspectOptions {
                archive: Some(blob),
                workload_dir: None,
                engine,
                verbose,
            }
        } else {
            atakit_workload::InspectOptions {
                archive: Some(archive_arg.clone()),
                workload_dir: None,
                engine,
                verbose,
            }
        }
    } else {
        // Dir mode: explicit --dir or default to cwd
        let dir = match args.dir {
            Some(d) => std::fs::canonicalize(d)?,
            None => std::env::current_dir()?,
        };
        // Prefer an existing .atawl archive to avoid rebuilding images
        let archive = find_archive(&dir);
        if archive.is_some() {
            atakit_workload::InspectOptions {
                archive,
                workload_dir: None,
                engine,
                verbose,
            }
        } else {
            atakit_workload::InspectOptions {
                archive: None,
                workload_dir: Some(dir),
                engine,
                verbose,
            }
        }
    };

    let result = atakit_workload::inspect_workload(&opts).await?;
    let name = &result.manifest.meta.name;
    let version = &result.manifest.meta.version;

    // Check on-chain status if RPC is configured
    let on_chain_status = refresh_chain_status(name, version, env, config).await;

    print_info(&result.manifest, &result.pcr23, on_chain_status.as_deref());
    Ok(())
}

/// Query on-chain revocation status. Updates the store if status changed.
/// Returns None if RPC is not configured or query fails.
async fn refresh_chain_status(
    name: &str,
    version: &str,
    env: &Env,
    config: &Config,
) -> Option<String> {
    let rpc_url = config.publish.rpc_url.as_deref()?;
    let session_registry_str = config.publish.session_registry.as_deref()?;
    let session_registry_address: alloy_ext::core::primitives::Address =
        session_registry_str.parse().ok()?;

    let workload_id = super::compute_workload_id(name, version);

    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url: rpc_url.to_string(),
        relay_key: None,
        session_registry_address,
    };

    let measurement =
        automata_tee_workload_measurement::WorkloadMeasurement::new(measurement_config)
            .await
            .ok()?;
    let registry = measurement.workload_registry();

    // Check if registered
    let spec = registry.get_workload_spec(workload_id).await.ok();
    if spec.is_none() {
        return Some("not registered".to_string());
    }

    // Check revocation
    let revoked = registry
        .is_workload_revoked(workload_id)
        .await
        .unwrap_or(false);

    // Update store
    let store = WorkloadStore::new(&env.workload_dir);
    if let Ok(Some(entry)) = store.get(name, version) {
        if entry.meta.revoked != revoked {
            let mut meta = entry.meta;
            meta.revoked = revoked;
            let _ = store.save_meta(&meta);
        }
    }

    if revoked {
        Some("revoked".to_string())
    } else {
        Some("active".to_string())
    }
}

fn section_header(name: &str) {
    let prefix = format!("--- {name} ");
    let pad = if prefix.len() < 56 {
        "-".repeat(56 - prefix.len())
    } else {
        String::new()
    };
    println!("{}", format!("{prefix}{pad}").cyan().bold());
}

fn print_info(m: &Manifest, pcr23: &str, chain_status: Option<&str>) {
    // Title
    println!(
        "{}",
        format!("{} {}", m.meta.name, m.meta.version).green().bold()
    );
    println!();

    // --- Image ---
    section_header("Image");
    println!("  {:<18}{}", "Source:", m.config.image);
    println!("  {:<18}{}", "Base Image Mode:", m.config.base_image_mode);
    if !m.config.base_image.is_empty() {
        print_multi("Base Images:", &m.config.base_image);
    }
    println!();

    // --- Runtime ---
    section_header("Runtime");
    println!("  {:<18}{}", "Restart:", m.config.restart);
    println!(
        "  {:<18}{}",
        "CVM Agent:",
        if m.config.cvm_agent { "yes" } else { "no" }
    );
    if !m.config.ports.is_empty() {
        print_multi("Ports:", &m.config.ports);
    }
    if let Some(ref cmd) = m.config.command {
        println!("  {:<18}{}", "Command:", format_string_or_array(cmd));
    }
    if let Some(ref ep) = m.config.entrypoint {
        println!("  {:<18}{}", "Entrypoint:", format_string_or_array(ep));
    }
    if !m.config.environment.is_empty() {
        let max_key = m.config.environment.keys().map(|k| k.len()).max().unwrap_or(0);
        let items: Vec<String> = m
            .config
            .environment
            .iter()
            .map(|(k, v)| format!("{:<width$} = {v}", k, width = max_key))
            .collect();
        print_multi("Environment:", &items);
    }
    println!();

    // --- Data ---
    let has_data = !m.config.measured_data.is_empty()
        || !m.config.unmeasured_data.is_empty()
        || m.config.signing.is_some();
    if has_data {
        section_header("Data");
        if !m.config.measured_data.is_empty() {
            print_multi("Measured:", &m.config.measured_data);
        }
        if !m.config.unmeasured_data.is_empty() {
            print_multi("Unmeasured:", &m.config.unmeasured_data);
        }
        if let Some(ref signing) = m.config.signing {
            if signing.enable {
                println!("  {:<18}enabled", "Signing:");
                if let Some(ref ai) = signing.auth_info {
                    println!("    {:<16}{}", "Auth Info:", ai);
                }
                if let Some(ref p) = signing.policy {
                    println!("    {:<16}{}", "Policy:", p);
                }
            }
        }
        println!();
    }

    // --- Disks ---
    if !m.disks.is_empty() {
        section_header("Disks");
        for (name, disk) in &m.disks {
            let mount = m.config.disks.get(name).map(|s| s.as_str()).unwrap_or("-");
            let mut flags = vec![&disk.size[..]];
            if let Some(ref enc) = disk.encryption {
                if enc.enable {
                    flags.push("encrypted");
                }
            }
            if disk.bind_fs {
                flags.push("bind_fs");
            }
            println!("  {:<18}{}  {}", format!("{name}:"), mount, flags.join("  "));
        }
        println!();
    }

    // --- Firewall ---
    let has_fw = m
        .config
        .firewall
        .as_ref()
        .is_some_and(|fw| !fw.allow.is_empty() || !fw.deny.is_empty());
    if has_fw {
        let fw = m.config.firewall.as_ref().unwrap();
        section_header("Firewall");
        if !fw.allow.is_empty() {
            let items: Vec<String> = fw.allow.iter().map(format_fw_allow).collect();
            print_multi("Allow:", &items);
        }
        if !fw.deny.is_empty() {
            let items: Vec<String> = fw.deny.iter().map(|p| p.to_string()).collect();
            print_multi("Deny:", &items);
        }
        println!();
    }

    // --- Hashes ---
    if !m.hashes.is_empty() {
        section_header("Hashes");
        let max_path = m.hashes.keys().map(|k| k.len()).max().unwrap_or(0);
        for (path, hash) in &m.hashes {
            println!("  {:<width$}  {}", path, hash, width = max_path);
        }
        println!();
    }

    // --- Measurement ---
    section_header("Measurement");
    println!("  {:<18}{}", "SHA256:", pcr23);

    // Compute final PCR register value: SHA-256(zeros_32 || event_hash).
    let event_hex = pcr23.strip_prefix("0x").unwrap_or(pcr23);
    if let Ok(event_bytes) = hex::decode(event_hex) {
        if event_bytes.len() == 32 {
            let mut hasher = sha2::Sha256::new();
            hasher.update([0u8; 32]);
            hasher.update(&event_bytes);
            let final_pcr = format!("0x{:x}", hasher.finalize());
            println!("  {:<18}{}", "PCR23:", final_pcr.green());
        }
    }

    // Compute workload ID: keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))
    // where WORKLOAD_DOMAIN = keccak256("CVM_WORKLOAD_V1")
    let workload_id = super::compute_workload_id(&m.meta.name, &m.meta.version);
    println!("  {:<18}{}", "Workload ID:", format!("0x{}", hex::encode(workload_id)).dimmed());
    match chain_status {
        Some("active") => println!("  {:<18}{}", "On-chain:", "active".green().bold()),
        Some("revoked") => println!("  {:<18}{}", "On-chain:", "revoked".red().bold()),
        Some(s) => println!("  {:<18}{}", "On-chain:", s.dimmed()),
        None => println!("  {:<18}{}", "On-chain:", "-".dimmed()),
    }
}

fn print_multi(label: &str, items: &[String]) {
    for (i, item) in items.iter().enumerate() {
        if i == 0 {
            println!("  {:<18}{}", format!("{label}"), item);
        } else {
            println!("  {:<18}{}", "", item);
        }
    }
}

fn format_string_or_array(s: &atakit_workload::manifest::StringOrArrayOut) -> String {
    use atakit_workload::manifest::StringOrArrayOut;
    match s {
        StringOrArrayOut::Single(s) => s.clone(),
        StringOrArrayOut::Array(v) => format!("[{}]", v.join(", ")),
    }
}

fn format_fw_allow(a: &ManifestFirewallAllow) -> String {
    format!("{}/{}", a.port, a.protocol)
}

