use std::io::Write;

use anyhow::{Context, Result};
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
        None if config.build.container_engine != crate::config::ContainerEngine::Auto => Some(
            atakit_workload::ContainerEngine::from_str_opt(config.build.container_engine.as_str())?,
        ),
        None => None,
    };

    if args.gz {
        eprintln!("Warning: --gz is deprecated for workload builds; writing zstd instead.");
    }

    // The publisher is written into the measured manifest, so it has to be
    // known before the build rather than at store-import time: it is part of
    // what PCR23 covers, and the workload's identifier derives from it. This is
    // why a build requires a key even with --no-store.
    let owner_key = super::resolve_owner_key(args.signing_key.as_deref(), config)?;
    let publisher = super::owner_fingerprint(&owner_key)?;
    let publisher_hex = format!("{publisher:#x}");

    let opts = atakit_workload::BuildOptions {
        workload_dir,
        publisher: publisher_hex.clone(),
        output_dir: args.output,
        engine,
        verbose,
        compression: ArchiveCompression::Zstd,
        measured_data_root: args.measured_data_root,
        unmeasured_data_root: args.unmeasured_data_root,
    };

    let progress = IndicatifReporter;
    let result = atakit_workload::build_workload(&opts, &progress).await?;

    // Inspect the built archive once: we need it to surface the manifest
    // event hash alongside the file hash, and (below) to populate store
    // metadata. Cheap -- just extracts manifest.json from the archive.
    let inspect_opts = atakit_workload::InspectOptions {
        archive: Some(result.archive_path.clone()),
        workload_dir: None,
        publisher: None,
        engine: None,
        verbose: false,
        measured_data_root: None,
        unmeasured_data_root: None,
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
            if result.measured_file_count != 1 {
                "s"
            } else {
                ""
            },
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

        // The publisher resolved above is the one measured into the manifest,
        // so the stored identifier and the archive agree by construction.
        let app_ref = automata_tee_workload_measurement::types::AppRef::new(
            publisher,
            name.clone(),
            version.clone(),
        );
        let workload_id = super::compute_workload_id(&app_ref);
        let workload_id_hex = format!("{workload_id:#x}");

        // Check if an existing entry has a different PCR23 and confirm before overwriting
        let existing_meta = match store.load_meta(&workload_id_hex) {
            Ok(meta) => meta,
            Err(atakit_workload::WorkloadError::UnsupportedMeta { .. }) => {
                println!(
                    "{}",
                    "Replacing unsupported local workload metadata with the current format."
                        .yellow()
                );
                None
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(ref existing) = existing_meta {
            if let Some(ref old_sha256) = existing.sha256 {
                if *old_sha256 != inspect.sha256 {
                    println!();
                    println!(
                        "{}",
                        format!("Store already has {name}:{version} with a different measurement.")
                            .yellow()
                            .bold()
                    );
                    println!("  {:<22}{}", "Old Manifest SHA256:".dimmed(), old_sha256);
                    println!(
                        "  {:<22}{}",
                        "New Manifest SHA256:".dimmed(),
                        inspect.sha256
                    );
                    if let Some(ref spec) = existing.on_chain_spec {
                        println!(
                            "  {:<22}{}",
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

        let size = store.import_blob(&workload_id_hex, &result.archive_path)?;

        // Merge into existing meta to preserve chain data from `workload add`
        let now = chrono::Local::now().to_rfc3339();
        let meta = match existing_meta {
            Some(mut existing) => {
                existing.workload_id = workload_id_hex.clone();
                existing.publisher = publisher_hex.clone();
                existing.sha256 = Some(inspect.sha256.clone());
                existing.pcr23 = Some(inspect.pcr23_sha256.clone());
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
                sha256: Some(inspect.sha256.clone()),
                pcr23: Some(inspect.pcr23_sha256.clone()),
                owner: None,
                archive_size: Some(size),
                on_chain_spec: None,
                revoked: false,
                repositories: Vec::new(),
                added_at: now,
            },
        };
        store.save_meta(&meta)?;

        // A workload's PCR23 was previously bound to its publisher only by
        // on-chain registration, so an offline verifier had nothing to check.
        // The pack is that binding, signed by the same key whose fingerprint is
        // the publisher component of the identifier.
        write_workload_measurement_pack(
            &store,
            &workload_id_hex,
            &publisher_hex,
            name,
            version,
            &inspect,
            archive_hex,
            &owner_key,
        )?;

        println!("{}", "Added to local store.".green());
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct WorkloadPack<'a> {
    schema: &'a str,
    revision: u64,
    published_at: u64,
    subject: PackSubject<'a>,
    measurements: WorkloadMeasurements<'a>,
}

#[derive(serde::Serialize)]
struct PackSubject<'a> {
    publisher: &'a str,
    name: &'a str,
    version: &'a str,
    id: &'a str,
    uri: Option<&'a str>,
    archive_sha256: Option<String>,
}

#[derive(serde::Serialize)]
struct WorkloadMeasurements<'a> {
    pcr23_sha256: &'a str,
    pcr23_sha384: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn write_workload_measurement_pack(
    store: &WorkloadStore,
    workload_id_hex: &str,
    publisher_hex: &str,
    name: &str,
    version: &str,
    inspect: &atakit_workload::InspectResult,
    archive_hex: &str,
    owner_key: &str,
) -> Result<()> {
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::{Signature, SigningKey};

    let pack = WorkloadPack {
        schema: atakit_attestation::WORKLOAD_MEASUREMENT_PACK_SCHEMA,
        revision: 1,
        published_at: chrono::Utc::now().timestamp().max(0) as u64,
        subject: PackSubject {
            publisher: publisher_hex,
            name,
            version,
            id: workload_id_hex,
            uri: None,
            archive_sha256: Some(format!("0x{archive_hex}")),
        },
        measurements: WorkloadMeasurements {
            pcr23_sha256: &inspect.pcr23_sha256,
            pcr23_sha384: &inspect.pcr23_sha384,
        },
    };

    let value = serde_json::to_value(&pack)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)?;

    let raw = owner_key.strip_prefix("0x").unwrap_or(owner_key);
    let bytes = hex::decode(raw).context("owner key is not valid hex")?;
    let signing_key =
        SigningKey::from_slice(&bytes).context("owner key must be a 32-byte es256k key")?;
    let signature: Signature = signing_key.sign(&canonical);

    let json_path = store.measurement_pack_path(workload_id_hex)?;
    let sig_path = store.measurement_pack_sig_path(workload_id_hex)?;
    std::fs::write(&json_path, &canonical)
        .with_context(|| format!("write {}", json_path.display()))?;
    std::fs::write(&sig_path, signature.to_bytes())
        .with_context(|| format!("write {}", sig_path.display()))?;
    println!("Measurement pack: {}", json_path.display());
    Ok(())
}
