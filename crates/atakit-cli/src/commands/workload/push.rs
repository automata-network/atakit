use std::io::{IsTerminal, Write};

use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::PushArgs;
use atakit_workload::{UploadContext, WorkloadCoords, WorkloadStore};
use owo_colors::OwoColorize;

use super::{compute_workload_id, find_versioned_archive, looks_like_store_ref};
use crate::config::Config;

pub async fn run(args: PushArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);

    // Resolve source archive path.
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
            // File path.
            let p = std::path::PathBuf::from(source);
            if !p.exists() {
                anyhow::bail!("archive not found: {}", p.display());
            }
            p
        }
    } else {
        // Auto-detect from --dir or cwd.
        let dir = match args.dir {
            Some(d) => std::fs::canonicalize(d)?,
            None => std::env::current_dir()?,
        };
        find_versioned_archive(&dir)?
    };

    // Inspect archive.
    let inspect_opts = atakit_workload::InspectOptions {
        archive: Some(archive_path.clone()),
        workload_dir: None,
        engine: None,
        verbose,
    };
    let result = atakit_workload::inspect_workload(&inspect_opts).await?;
    let manifest = &result.manifest;
    let name = manifest.meta.name.clone();
    let version = manifest.meta.version.clone();
    let archive_size = std::fs::metadata(&archive_path)
        .with_context(|| format!("failed to stat {}", archive_path.display()))?
        .len();

    let workload_id = compute_workload_id(&name, &version);
    let workload_id_hex = format!("0x{}", hex::encode(workload_id));

    // Resolve repository.
    let spec = config.workload.resolve(args.repository.as_deref())?;
    let repo = config
        .workload
        .build_repository(spec, config.github_token().map(str::to_string));
    let repo_uri = repo.display_uri();

    if !repo.supports_upload() {
        anyhow::bail!(
            "repository {} does not support push (read-only or missing token)",
            repo_uri
        );
    }

    // Display workload details + target repository so the user can
    // double-check before anything hits the network.
    println!();
    println!(
        "{} {}:{}",
        "Workload:".bold(),
        name.green().bold(),
        version.green().bold(),
    );
    println!("  {:<14}{}", "Archive:", archive_path.display().to_string().dimmed());
    println!("  {:<14}{}", "Size:", format_size(archive_size));
    println!("  {:<14}{}", "SHA256:", result.sha256.dimmed());
    println!("  {:<14}{}", "PCR23:", result.pcr23.dimmed());
    println!("  {:<14}{}", "Workload ID:", workload_id_hex.dimmed());
    println!("  {:<14}{}", "Repository:", repo_uri.cyan());
    println!();

    if !args.yes {
        // Refuse to block on stdin in non-interactive contexts
        // (CI, scripts, piped input). Without this guard `read_line`
        // would hang forever waiting for a confirmation that will
        // never arrive.
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "non-interactive session: pass --yes (or -y) to push without confirmation"
            );
        }
        eprint!("Push? [y/N] ");
        std::io::stderr().flush().ok();
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("failed to read confirmation")?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let coords = WorkloadCoords {
        workload_id: workload_id_hex.clone(),
        name: name.clone(),
        version: version.clone(),
    };
    let ctx = UploadContext {
        coords,
        archive_path: archive_path.as_path(),
        manifest_sha256: result.sha256.clone(),
        pcr23: result.pcr23.clone(),
    };

    println!("Uploading to {}...", repo_uri.dimmed());
    let meta = repo.upload(&ctx).await.context("upload failed")?;

    println!();
    println!("{}", "Push complete.".green().bold());
    println!("  {:<14}{}:{}", "Workload:", name, version);
    println!("  {:<14}{}", "Workload ID:", workload_id_hex.dimmed());
    println!("  {:<14}{}", "Archive hash:", meta.archive_hash.dimmed());
    println!("  {:<14}{}", "Repository:", repo_uri.dimmed());

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
