use std::io::Write;

use anyhow::Result;
use atakit_core::{ArchiveCompression, Env};
use atakit_workload::cli::BuildArgs;
use atakit_workload::{WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use crate::config::Config;
use crate::progress::IndicatifReporter;

pub async fn run(args: BuildArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    let workload_dir = match args.dir {
        Some(d) => std::fs::canonicalize(d)?,
        None => std::env::current_dir()?,
    };

    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != "auto" => {
            Some(atakit_workload::ContainerEngine::from_str_opt(
                &config.build.container_engine,
            )?)
        }
        None => None,
    };

    let compression = if args.gz {
        ArchiveCompression::Gz
    } else {
        ArchiveCompression::Zstd
    };

    let opts = atakit_workload::BuildOptions {
        workload_dir,
        output_dir: args.output,
        engine,
        verbose,
        compression,
    };

    let progress = IndicatifReporter;
    let result = atakit_workload::build_workload(&opts, &progress).await?;

    // Inspect the built archive once: we need it to surface the manifest
    // event hash alongside the file hash, and (below) to populate store
    // metadata. Cheap -- just extracts manifest.toml from the archive.
    let inspect_opts = atakit_workload::InspectOptions {
        archive: Some(result.archive_path.clone()),
        workload_dir: None,
        engine: None,
        verbose: false,
    };
    let inspect = atakit_workload::inspect_workload(&inspect_opts).await?;

    println!(
        "{}",
        format!(
            "Done. {} ({} image{}, {} measured file{})",
            result.archive_path.display(),
            result.image_count,
            if result.image_count != 1 { "s" } else { "" },
            result.measured_file_count,
            if result.measured_file_count != 1 { "s" } else { "" },
        )
        .green()
    );
    // Two distinct hashes: the archive file hash is a content-addressable
    // identifier for the .atawl blob; the manifest hash is the PCR23 event
    // hash that appears on-chain and in `workload ls`. Label both clearly
    // so users don't get confused when the values differ.
    //
    // Normalise both to `0x<hex>` at print time so the two rows line up
    // visually. `hash_file` returns `sha256:<hex>` (manifest uses that
    // convention internally for `[hashes]` entries), but mixing it with
    // `inspect.sha256`'s `0x<hex>` in terminal output makes the column
    // edges jagged and confused a user into thinking they were looking
    // at a bug.
    let archive_hex = result
        .archive_hash
        .strip_prefix("sha256:")
        .unwrap_or(&result.archive_hash);
    println!("Archive  SHA-256: {}", format!("0x{archive_hex}").dimmed());
    println!("Manifest SHA-256: {}", inspect.sha256.dimmed());

    // Import into store unless --no-store flag is set
    if !args.no_store {
        let store = WorkloadStore::new(&env.workload_dir);
        let name = &inspect.manifest.meta.name;
        let version = &inspect.manifest.meta.version;

        // Check if an existing entry has a different PCR23 and confirm before overwriting
        let existing_meta = store.load_meta(name, version)?;
        if let Some(ref existing) = existing_meta {
            if let Some(ref old_sha256) = existing.sha256 {
                if *old_sha256 != inspect.sha256 {
                    println!();
                    println!(
                        "{}",
                        format!("Store already has {name}:{version} with a different measurement.").yellow().bold()
                    );
                    println!("  {:<12}{}", "Old SHA256:".dimmed(), old_sha256);
                    println!("  {:<12}{}", "New SHA256:".dimmed(), inspect.sha256);
                    if let Some(ref spec) = existing.on_chain_spec {
                        println!(
                            "  {:<12}{}",
                            "On-chain:".dimmed(),
                            "yes (will be stale after overwrite)".yellow()
                        );
                        let _ = spec; // suppress unused warning
                    }
                    println!();
                    eprint!("Overwrite? [y/N] ");
                    std::io::stderr().flush()?;
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Skipped store import.");
                        return Ok(());
                    }
                }
            }
        }

        let size = store.import_blob(name, version, &result.archive_path)?;

        // Merge into existing meta to preserve chain data from `workload add`
        let workload_id = super::compute_workload_id(name, version);
        let now = chrono::Local::now().to_rfc3339();
        let meta = match existing_meta {
            Some(mut existing) => {
                existing.workload_id = format!("0x{}", hex::encode(workload_id));
                existing.sha256 = Some(inspect.sha256);
                existing.pcr23 = Some(inspect.pcr23);
                existing.archive_size = Some(size);
                existing.added_at = now;
                existing
            }
            None => WorkloadMeta {
                workload_id: format!("0x{}", hex::encode(workload_id)),
                name: name.clone(),
                version: version.clone(),
                sha256: Some(inspect.sha256),
                pcr23: Some(inspect.pcr23),
                owner: None,
                archive_size: Some(size),
                on_chain_spec: None,
                revoked: false,
                repositories: Vec::new(),
                added_at: now,
            },
        };
        store.save_meta(&meta)?;
        println!("{}", "Added to local store.".green());
    }

    Ok(())
}
