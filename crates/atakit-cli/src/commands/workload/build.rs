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
    println!("SHA-256: {}", result.archive_hash.dimmed());

    // Import into store unless --no-store flag is set
    if !args.no_store {
        let store = WorkloadStore::new(&env.workload_dir);

        // Inspect the built archive to get name, version, PCR23
        let inspect_opts = atakit_workload::InspectOptions {
            archive: Some(result.archive_path.clone()),
            workload_dir: None,
            engine: None,
            verbose: false,
        };
        let inspect = atakit_workload::inspect_workload(&inspect_opts).await?;
        let name = &inspect.manifest.meta.name;
        let version = &inspect.manifest.meta.version;

        // Check if an existing entry has a different PCR23 and confirm before overwriting
        let existing_meta = store.load_meta(name, version)?;
        if let Some(ref existing) = existing_meta {
            if let Some(ref old_pcr23) = existing.pcr23 {
                if *old_pcr23 != inspect.pcr23 {
                    println!();
                    println!(
                        "{}",
                        format!("Store already has {name}:{version} with a different measurement.").yellow().bold()
                    );
                    println!("  {:<12}{}", "Old PCR23:".dimmed(), old_pcr23);
                    println!("  {:<12}{}", "New PCR23:".dimmed(), inspect.pcr23);
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
                existing.pcr23 = Some(inspect.pcr23);
                existing.archive_size = Some(size);
                existing.added_at = now;
                existing
            }
            None => WorkloadMeta {
                workload_id: format!("0x{}", hex::encode(workload_id)),
                name: name.clone(),
                version: version.clone(),
                pcr23: Some(inspect.pcr23),
                owner: None,
                archive_size: Some(size),
                on_chain_spec: None,
                revoked: false,
                registries: Vec::new(),
                added_at: now,
            },
        };
        store.save_meta(&meta)?;
        println!("{}", "Added to local store.".green());
    }

    Ok(())
}
