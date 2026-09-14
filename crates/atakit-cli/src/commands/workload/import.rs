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
        publisher: None,
        archive: Some(args.archive.clone()),
        workload_dir: None,
        engine: None,
        verbose: false,
        measured_data_root: None,
        unmeasured_data_root: None,
    };
    let result = atakit_workload::inspect_workload(&opts)
        .await
        .with_context(|| format!("failed to inspect {}", args.archive.display()))?;

    let app_ref = super::measured_workload_ref(&result.manifest.meta)?;
    let publisher = app_ref.publisher;
    let name = &app_ref.name;
    let version = &app_ref.version;
    let workload_id = compute_workload_id(&app_ref);
    let workload_id_hex = format!("{workload_id:#x}");
    let publisher_hex = format!("{publisher:#x}");

    // Check if blob already exists (metadata-only entries from `add` should still import)
    if store.has_blob(&workload_id_hex) && !args.force {
        println!("Workload {name}:{version} already in store (use --force to overwrite).");
        return Ok(());
    }

    // Import blob
    let size = store.import_blob(&workload_id_hex, &args.archive)?;

    // Build and save metadata (merge into existing to preserve chain data)
    let now = chrono::Local::now().to_rfc3339();
    let existing_meta = match store.load_meta(&workload_id_hex) {
        Ok(meta) => meta,
        Err(atakit_workload::WorkloadError::UnsupportedMeta { .. }) if args.force => None,
        Err(error) => return Err(error.into()),
    };
    let meta = match existing_meta {
        Some(mut existing) => {
            existing.workload_id = workload_id_hex.clone();
            existing.publisher = publisher_hex.clone();
            existing.sha256 = Some(result.sha256.clone());
            existing.pcr23 = Some(result.pcr23_sha256.clone());
            existing.archive_size = Some(size);
            existing.added_at = now;
            existing
        }
        None => WorkloadMeta {
            metadata_format: atakit_workload::store::WORKLOAD_META_FORMAT_VERSION,
            workload_id: workload_id_hex.clone(),
            publisher: publisher_hex.clone(),
            name: name.clone(),
            version: version.clone(),
            sha256: Some(result.sha256.clone()),
            pcr23: Some(result.pcr23_sha256.clone()),
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
