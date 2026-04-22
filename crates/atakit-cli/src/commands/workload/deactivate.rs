use std::io::{self, Write};

use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::DeactivateArgs;
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;

use super::{compute_workload_id, looks_like_store_ref, resolve_chain, resolve_owner_key};
use crate::config::Config;

pub async fn run(args: DeactivateArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    // Resolve chain config (rpc_url + session_registry) from [chains].
    let chain = resolve_chain(args.chain.as_deref(), config)?;
    let rpc_url = chain.rpc_url;

    let session_registry_address: alloy_ext::core::primitives::Address =
        chain.session_registry.parse().context("invalid session registry address")?;

    // Resolve owner private key from [keys].
    let private_key_raw = resolve_owner_key(args.owner_key.as_deref(), config)?;
    let private_key_hex = private_key_raw.strip_prefix("0x").unwrap_or(&private_key_raw);
    let signer: alloy_ext::signers::local::PrivateKeySigner = private_key_hex
        .parse()
        .context("invalid private key")?;

    let signer_address = signer.address();
    println!("Signer: {}", format!("{signer_address}").dimmed());

    // Resolve workload identity: name+version or workload ID
    let (name, version, workload_id) = resolve_workload_identity(
        &args, env, config, verbose,
    ).await?;

    let workload_id_hex = format!("0x{}", hex::encode(workload_id));

    println!(
        "Workload: {} {}",
        name.green().bold(),
        version,
    );
    println!("Workload ID: {}", workload_id_hex.dimmed());

    // Use owner key as relay key for transaction submission.
    let relay_key = {
        let bytes: [u8; 32] = hex::decode(private_key_hex)
            .context("invalid owner key hex for relay")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("owner key must be 32 bytes"))?;
        alloy_ext::core::primitives::B256::from(bytes)
    };

    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url,
        relay_key: Some(relay_key),
        session_registry_address,
    };

    println!("Connecting to registry...");
    let measurement = automata_tee_workload_measurement::WorkloadMeasurement::new(
        measurement_config,
    )
    .await
    .context("failed to connect to WorkloadMeasurement")?;

    let registry = measurement.workload_registry();

    // Check if workload is already revoked
    if let Ok(true) = registry.is_workload_revoked(workload_id).await {
        // Update store to reflect revoked state
        let store = WorkloadStore::new(&env.workload_dir);
        if let Ok(Some(entry)) = store.get(&name, &version) {
            if !entry.meta.revoked {
                let mut meta = entry.meta;
                meta.revoked = true;
                let _ = store.save_meta(&meta);
            }
        }
        println!();
        println!(
            "{}",
            "Workload is already deactivated.".yellow().bold()
        );
        println!("  {:<18}{}", "Workload ID:", workload_id_hex);
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        println!();
        print!(
            "Deactivate {} {}? This cannot be undone. [y/N] ",
            name.bold(),
            version,
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("Submitting deactivateWorkload transaction...");
    let tx_hash = registry
        .deactivate_workload(&signer, workload_id, args.expire_offset)
        .await
        .context("deactivateWorkload failed")?;

    println!();
    println!(
        "{}",
        "Workload deactivated successfully.".green().bold()
    );
    println!(
        "  {:<18}0x{}",
        "Tx hash:",
        hex::encode(tx_hash),
    );

    // Mark as revoked in the local store if entry exists
    let store = WorkloadStore::new(&env.workload_dir);
    if let Ok(Some(entry)) = store.get(&name, &version) {
        let mut meta = entry.meta;
        meta.revoked = true;
        let _ = store.save_meta(&meta);
    }

    Ok(())
}

/// Resolve the workload identity from the positional arg.
/// Accepts: name:version, 0x<workload_id>, path to .atawl, or auto-detect from dir.
async fn resolve_workload_identity(
    args: &DeactivateArgs,
    env: &Env,
    config: &Config,
    verbose: bool,
) -> Result<(String, String, alloy_ext::core::primitives::B256)> {
    if let Some(ref archive_arg) = args.archive {
        let s = archive_arg.to_string_lossy();

        // 0x<workload_id> (66 chars)
        if s.starts_with("0x") && s.len() == 66 {
            let id_hex = s.strip_prefix("0x").unwrap();
            let bytes: [u8; 32] = hex::decode(id_hex)
                .context("invalid workload ID hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("workload ID must be 32 bytes"))?;
            let workload_id = alloy_ext::core::primitives::B256::from(bytes);
            // Try store lookup for name+version, fall back to "unknown"
            let store = WorkloadStore::new(&env.workload_dir);
            if let Some(entry) = store.get_by_id(&s)? {
                return Ok((entry.meta.name, entry.meta.version, workload_id));
            }
            // Can't resolve name+version without chain query here,
            // but we need them for display. Use placeholders - the chain
            // will verify the ID.
            return Ok(("(unknown)".to_string(), "".to_string(), workload_id));
        }

        // name:version store ref
        if looks_like_store_ref(&s) {
            let (name, version) = s
                .split_once(':')
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .unwrap();
            let workload_id = compute_workload_id(&name, &version);
            return Ok((name, version, workload_id));
        }

        // File path - inspect archive
        return resolve_from_archive(archive_arg, args, config, verbose).await;
    }

    // No positional arg - auto-detect from dir
    let dir = match args.dir {
        Some(ref d) => std::fs::canonicalize(d)?,
        None => std::env::current_dir()?,
    };
    let archive = super::find_versioned_archive(&dir)?;
    resolve_from_archive(&archive, args, config, verbose).await
}

async fn resolve_from_archive(
    archive: &std::path::Path,
    args: &DeactivateArgs,
    config: &Config,
    verbose: bool,
) -> Result<(String, String, alloy_ext::core::primitives::B256)> {
    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != "auto" => {
            Some(atakit_workload::ContainerEngine::from_str_opt(
                &config.build.container_engine,
            )?)
        }
        None => None,
    };

    let opts = atakit_workload::InspectOptions {
        archive: Some(archive.to_path_buf()),
        workload_dir: None,
        engine,
        verbose,
    };

    let result = atakit_workload::inspect_workload(&opts).await?;
    let name = result.manifest.meta.name.clone();
    let version = result.manifest.meta.version.clone();
    let workload_id = compute_workload_id(&name, &version);
    Ok((name, version, workload_id))
}
