use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::InfoArgs;
use atakit_workload::manifest::{Manifest, ManifestFirewallPort};
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;

use super::{
    apply_chain_data_to_meta, find_archive, looks_like_store_ref, query_chain_data, ChainData,
};
use crate::config::Config;

pub async fn run(args: InfoArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != crate::config::ContainerEngine::Auto => Some(
            atakit_workload::ContainerEngine::from_str_opt(config.build.container_engine.as_str())?,
        ),
        None => None,
    };

    // Only a store reference names a publisher, so only that form yields an
    // identifier to query the chain with. Inspecting an archive by path gives a
    // name and version and no way to know whose they are.
    let mut store_workload_id: Option<String> = None;
    let opts = if let Some(ref archive_arg) = args.archive {
        // Check if it looks like a store reference (name:version)
        let archive_str = archive_arg.to_string_lossy();
        if looks_like_store_ref(&archive_str) {
            let store = WorkloadStore::new(&env.workload_dir);
            let workload_id = super::parse_workload_ref(&archive_str, &config.alias)?.workload_id();
            store_workload_id = Some(workload_id.clone());
            let blob = store.blob_path(&workload_id)?;
            if !blob.exists() {
                anyhow::bail!("no archive blob for {archive_str} in store");
            }
            atakit_workload::InspectOptions {
                archive: Some(blob),
                workload_dir: None,
                engine,
                verbose,
                measured_data_root: None,
                unmeasured_data_root: None,
            }
        } else {
            atakit_workload::InspectOptions {
                archive: Some(archive_arg.clone()),
                workload_dir: None,
                engine,
                verbose,
                measured_data_root: None,
                unmeasured_data_root: None,
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
                measured_data_root: None,
                unmeasured_data_root: None,
            }
        } else {
            atakit_workload::InspectOptions {
                archive: None,
                workload_dir: Some(dir),
                engine,
                verbose,
                measured_data_root: args.measured_data_root,
                unmeasured_data_root: args.unmeasured_data_root,
            }
        }
    };

    let result = atakit_workload::inspect_workload(&opts).await?;
    // Check on-chain status if RPC is configured and the input identified a
    // publisher.
    let chain_data = match store_workload_id.as_deref() {
        Some(workload_id) => refresh_chain(workload_id, env, config).await,
        None => None,
    };

    print_info(
        &result.manifest,
        &result.sha256,
        &result.pcr23_sha256,
        store_workload_id.as_deref(),
        chain_data.as_ref(),
    );
    Ok(())
}

/// Query on-chain data and update local store. Returns None if chain not configured.
async fn refresh_chain(workload_id_hex: &str, env: &Env, config: &Config) -> Option<ChainData> {
    // Best-effort: resolve publish chain, skip if not configured.
    let chain_name = config.publish.chain.as_deref()?;
    let chain_config = config.chains.get(chain_name)?;
    let rpc_url = &chain_config.rpc_url;
    let session_registry = &chain_config.session_registry;
    let workload_id: alloy_ext::core::primitives::B256 = workload_id_hex.parse().ok()?;

    let chain = query_chain_data(workload_id, rpc_url, session_registry)
        .await
        .ok()?;

    // Update store with chain data
    let store = WorkloadStore::new(&env.workload_dir);
    if let Ok(Some(entry)) = store.get(workload_id_hex) {
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

fn print_info(
    m: &Manifest,
    sha256: &str,
    pcr23: &str,
    workload_id: Option<&str>,
    chain_info: Option<&ChainData>,
) {
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
    if m.config.attributes.is_empty() {
        println!("  {:<18}none", "Attributes:");
    } else {
        for (index, (name, values)) in m.config.attributes.iter().enumerate() {
            let values = values
                .iter()
                .map(|value| match value {
                    atakit_core::tee_attributes::AttributeValue::Boolean(value) => {
                        value.to_string()
                    }
                    atakit_core::tee_attributes::AttributeValue::String(value) => {
                        format!("{value:?}")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "  {:<18}{} = [{}]",
                if index == 0 { "Attributes:" } else { "" },
                name,
                values
            );
        }
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
        let max_key = m
            .config
            .environment
            .keys()
            .map(|k| k.len())
            .max()
            .unwrap_or(0);
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
    if m.config.measured_data.is_enabled() || m.config.unmeasured_data.is_enabled() {
        section_header("Data");
        if m.config.measured_data.is_enabled() {
            println!("  {:<20}enabled (directory mounted)", "Measured:");
        }
        if m.config.unmeasured_data.is_enabled() {
            println!("  {:<20}enabled (directory mounted)", "Unmeasured:");
        }
        println!();
    }

    // --- Disks ---
    if !m.disks.is_empty() {
        section_header("Disks");
        for (name, disk) in &m.disks {
            let mut flags = vec![&disk.size[..]];
            if !disk.encryption.unlock_method.is_empty() {
                flags.push("encrypted");
            }
            println!("  {:<18}{}", format!("{name}:"), flags.join("  "));
        }
        if !m.config.storage.is_empty() {
            for (label, storage) in &m.config.storage {
                let mode = if storage.read_only { "ro" } else { "rw" };
                println!(
                    "  {:<18}{}:{} -> {} ({mode})",
                    format!("{label}:"),
                    storage.disk,
                    storage.base_path,
                    storage.mount_path
                );
            }
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
                if !dep.storage.is_empty() {
                    for (label, storage) in &dep.storage {
                        let mode = if storage.read_only { "ro" } else { "rw" };
                        println!(
                            "    {:<16}{}: {}:{} -> {} ({mode})",
                            "Storage:", label, storage.disk, storage.base_path, storage.mount_path
                        );
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

    // A manifest cannot know its own identifier: the identifier is derived from
    // the publisher, and nothing in the archive records who that is. It is
    // shown only when the caller named one.
    match workload_id {
        Some(workload_id) => println!("  {:<18}{}", "Workload ID:", workload_id.dimmed()),
        None => println!(
            "  {:<18}{}",
            "Workload ID:",
            "unknown without a publisher".dimmed()
        ),
    }
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
