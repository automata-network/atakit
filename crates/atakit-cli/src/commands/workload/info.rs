use anyhow::Result;
use atakit_workload::cli::InfoArgs;
use atakit_workload::manifest::{Manifest, ManifestFirewallAllow};
use owo_colors::OwoColorize;

use super::find_archive;
use crate::config::Config;

pub async fn run(args: InfoArgs, config: &Config, verbose: bool) -> Result<()> {
    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != "auto" => {
            Some(atakit_workload::ContainerEngine::from_str_opt(
                &config.build.container_engine,
            )?)
        }
        None => None,
    };

    let opts = if let Some(archive) = args.archive {
        atakit_workload::InspectOptions {
            archive: Some(archive),
            workload_dir: None,
            engine,
            verbose,
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
    print_info(&result.manifest, &result.pcr23);
    Ok(())
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

fn print_info(m: &Manifest, pcr23: &str) {
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
    println!("  {:<18}{}", "PCR23:", pcr23.green());

    // Compute workload ID: keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))
    // where WORKLOAD_DOMAIN = keccak256("CVM_WORKLOAD_V1")
    let workload_id = super::compute_workload_id(&m.meta.name, &m.meta.version);
    println!("  {:<18}{}", "Workload ID:", format!("0x{}", hex::encode(workload_id)).dimmed());
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

