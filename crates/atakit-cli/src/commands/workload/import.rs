use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::ImportArgs;
use atakit_workload::{WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use super::compute_workload_id;

pub async fn run(args: ImportArgs, env: &Env) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);

    // Inspect archive to get name, version, SHA256
    let opts = atakit_workload::InspectOptions {
        archive: Some(args.archive.clone()),
        workload_dir: None,
        engine: None,
        verbose: false,
    };
    let result = atakit_workload::inspect_workload(&opts)
        .await
        .with_context(|| format!("failed to inspect {}", args.archive.display()))?;

    let name = &result.manifest.meta.name;
    let version = &result.manifest.meta.version;

    // Check if blob already exists (metadata-only entries from `add` should still import)
    if store.has_blob(name, version) && !args.force {
        println!("Workload {name}:{version} already in store (use --force to overwrite).");
        return Ok(());
    }

    // Import blob
    let size = store.import_blob(name, version, &args.archive)?;

    // Build and save metadata (merge into existing to preserve chain data)
    let workload_id = compute_workload_id(name, version);
    let now = chrono::Local::now().to_rfc3339();
    let meta = match store.load_meta(name, version)? {
        Some(mut existing) => {
            existing.workload_id = format!("0x{}", hex::encode(workload_id));
            existing.sha256 = Some(result.sha256.clone());
            existing.pcr23 = Some(result.pcr23.clone());
            existing.archive_size = Some(size);
            existing.added_at = now;
            existing
        }
        None => WorkloadMeta {
            workload_id: format!("0x{}", hex::encode(workload_id)),
            name: name.clone(),
            version: version.clone(),
            sha256: Some(result.sha256.clone()),
            pcr23: Some(result.pcr23.clone()),
            owner: None,
            archive_size: Some(size),
            on_chain_spec: None,
            revoked: false,
            repositories: Vec::new(),
            added_at: now,
        },
    };
    store.save_meta(&meta)?;

    println!("{}", "Imported.".green().bold());
    println!("  {:<18}{}:{}", "Workload:", name, version);
    println!("  {:<18}{}", "Manifest SHA256:", result.sha256.dimmed());

    Ok(())
}
