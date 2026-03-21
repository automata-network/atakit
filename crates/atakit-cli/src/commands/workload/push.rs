use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::PushArgs;
use atakit_workload::{RegistryClient, WorkloadStore};
use owo_colors::OwoColorize;

use super::{compute_workload_id, find_versioned_archive, looks_like_store_ref};
use crate::config::Config;

pub async fn run(args: PushArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);

    // Resolve source archive path
    let archive_path = if let Some(ref source) = args.source {
        if looks_like_store_ref(source) {
            // name:version store reference
            let (name, version) = source
                .split_once(':')
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .unwrap();
            let path = store.blob_path(&name, &version)?;
            if !path.exists() {
                anyhow::bail!(
                    "no archive blob for {name}:{version} in store. Run `atakit workload pull` first."
                );
            }
            path
        } else {
            // File path
            let p = std::path::PathBuf::from(source);
            if !p.exists() {
                anyhow::bail!("archive not found: {}", p.display());
            }
            p
        }
    } else {
        // Auto-detect from --dir or cwd
        let dir = match args.dir {
            Some(d) => std::fs::canonicalize(d)?,
            None => std::env::current_dir()?,
        };
        find_versioned_archive(&dir)?
    };

    // Inspect archive
    let inspect_opts = atakit_workload::InspectOptions {
        archive: Some(archive_path.clone()),
        workload_dir: None,
        engine: None,
        verbose,
    };
    let result = atakit_workload::inspect_workload(&inspect_opts).await?;
    let manifest = &result.manifest;
    let name = &manifest.meta.name;
    let version = &manifest.meta.version;

    let workload_id = compute_workload_id(name, version);
    let workload_id_hex = format!("0x{}", hex::encode(workload_id));

    println!(
        "Workload: {} {}",
        name.green().bold(),
        version,
    );
    println!("PCR23: {}", result.pcr23.dimmed());
    println!("Workload ID: {}", workload_id_hex.dimmed());

    // Resolve registry and stream upload from file
    let registry_url = config.registry.resolve_url(args.registry.as_deref())?;
    let client = RegistryClient::new(&registry_url);

    let file = tokio::fs::File::open(&archive_path)
        .await
        .with_context(|| format!("failed to open {}", archive_path.display()))?;

    println!("Uploading to {}...", registry_url.dimmed());
    let meta = client
        .upload(&workload_id_hex, file)
        .await
        .context("upload failed")?;

    println!();
    println!("{}", "Push complete.".green().bold());
    println!("  {:<18}{}:{}", "Workload:", name, version);
    println!("  {:<18}{}", "Workload ID:", workload_id_hex.dimmed());
    println!("  {:<18}{}", "Archive hash:", meta.archive_hash.dimmed());

    Ok(())
}
