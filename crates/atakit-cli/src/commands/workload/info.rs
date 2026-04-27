use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::InfoArgs;
use atakit_workload::manifest::{Manifest, ManifestFirewallPort};
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;

use super::{apply_chain_data_to_meta, find_archive, looks_like_store_ref, query_chain_data, ChainData};
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
    let chain_data = refresh_chain(name, version, env, config).await;

    print_info(&result.manifest, &result.sha256, &result.pcr23, chain_data.as_ref());
    Ok(())
}

/// Query on-chain data and update local store. Returns None if chain not configured.
async fn refresh_chain(
    name: &str,
    version: &str,
    env: &Env,
    config: &Config,
) -> Option<ChainData> {
    // Best-effort: resolve publish chain, skip if not configured.
    let chain_name = config.publish.chain.as_deref()?;
    let chain_config = config.chains.get(chain_name)?;
    let rpc_url = &chain_config.rpc_url;
    let session_registry = &chain_config.session_registry;
    let workload_id = super::compute_workload_id(name, version);

    let chain = query_chain_data(workload_id, rpc_url, session_registry)
        .await
        .ok()?;

    // Update store with chain data
    let store = WorkloadStore::new(&env.workload_dir);
    if let Ok(Some(entry)) = store.get(name, version) {
        let mut meta = entry.meta;
        apply_chain_data_to_meta(&mut meta, &chain);
        let _ = store.save_meta(&meta);
    }

    Some(chain)
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

fn print_info(m: &Manifest, sha256: &str, pcr23: &str, chain_info: Option<&ChainData>) {
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
        "Atakit Portal:",
        if m.config.atakit_portal { "yes" } else { "no" }
    );
    println!("  {:<18}{}", "GID Group:", m.config.gid_group);
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
    if m.config.measured_data || m.config.unmeasured_data {
        section_header("Data");
        if m.config.measured_data {
            println!("  {:<20}{}", "Measured:", "enabled (directory mounted)");
        }
        if m.config.unmeasured_data {
            println!("  {:<20}{}", "Unmeasured:", "enabled (directory mounted)");
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
                if !enc.unlock_method.is_empty() {
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

    // --- Dependencies ---
    if let Some(ref deps) = m.config.dependencies {
        if !deps.is_empty() {
            section_header("Dependencies");
            for (name, dep) in deps {
                println!("  {}", format!("[{name}]").bold());
                println!("    {:<16}{}", "Image:", dep.image);
                if !dep.ports.is_empty() {
                    let ports_str = dep.ports.join(", ");
                    println!("    {:<16}{}", "Ports:", ports_str);
                }
                if dep.restart != "no" {
                    println!("    {:<16}{}", "Restart:", dep.restart);
                }
                if !dep.depends_on.is_empty() {
                    println!("    {:<16}{}", "Depends on:", dep.depends_on.join(", "));
                }
                if !dep.disks.is_empty() {
                    for (dk, mount) in &dep.disks {
                        println!("    {:<16}{} -> {}", "Disk:", dk, mount);
                    }
                }
            }
            println!();
        }
    }

    // --- Firewall Ports ---
    if !m.config.firewall_ports.is_empty() {
        section_header("Firewall Ports");
        let items: Vec<String> = m.config.firewall_ports.iter().map(format_fw_port).collect();
        print_multi("Open:", &items);
        println!();
    }

    // --- Images (per-service archive + image-id) ---
    if !m.images.is_empty() {
        section_header("Images");
        let max_svc = m.images.keys().map(|k| k.len()).max().unwrap_or(0);
        for (svc, img) in &m.images {
            println!("  {:<width$}  {}", svc, img.archive, width = max_svc);
            println!("  {:<width$}  {}", "", img.image_id, width = max_svc);
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
    println!("  {:<18}{}", "Manifest SHA256:", sha256);
    println!("  {:<18}{}", "PCR23:", pcr23.green());

    // Show on-chain PCR23 with match/mismatch highlighting.
    if let Some(info) = chain_info {
        if let Some(ref on_chain) = info.pcr23 {
            if on_chain == pcr23 {
                println!("  {:<18}{}", "PCR23 (on-chain):", on_chain.green());
            } else {
                println!("  {:<18}{}", "PCR23 (on-chain):", on_chain.red().bold());
                println!("  {:<18}{}", "", "mismatch with local PCR23".red());
            }
        }
    }

    // Compute workload ID: keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))
    // where WORKLOAD_DOMAIN = keccak256("CVM_WORKLOAD_V1")
    let workload_id = super::compute_workload_id(&m.meta.name, &m.meta.version);
    println!("  {:<18}{}", "Workload ID:", format!("0x{}", hex::encode(workload_id)).dimmed());
    match chain_info {
        Some(info) => match info.status.as_str() {
            "active" => println!("  {:<18}{}", "On-chain:", "active".green().bold()),
            "revoked" => println!("  {:<18}{}", "On-chain:", "revoked".red().bold()),
            s => println!("  {:<18}{}", "On-chain:", s.dimmed()),
        },
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

fn format_fw_port(p: &ManifestFirewallPort) -> String {
    format!("{}/{}", p.port, p.protocol)
}

