use std::io::{self, Write};

use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::DeactivateArgs;
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;

use super::{
    compute_workload_id, looks_like_store_ref, resolve_chain, resolve_owner_key, WorkloadRef,
};
use crate::config::Config;

pub async fn run(args: DeactivateArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    // Resolve chain config (rpc_url + session_registry) from [chains].
    let chain = resolve_chain(args.chain.as_deref(), config)?;
    let rpc_url = chain.rpc_url;

    let session_registry_address: alloy_ext::core::primitives::Address = chain
        .session_registry
        .parse()
        .context("invalid session registry address")?;

    // Resolve owner private key from [keys].
    let private_key_raw = resolve_owner_key(args.owner_key.as_deref(), config)?;
    let private_key_hex = private_key_raw
        .strip_prefix("0x")
        .unwrap_or(&private_key_raw);
    let signer: alloy_ext::signers::local::PrivateKeySigner =
        private_key_hex.parse().context("invalid private key")?;

    let signer_address = signer.address();
    println!("Signer: {}", format!("{signer_address}").dimmed());

    // Resolve workload identity: name+version or workload ID
    let (name, version, workload_id) =
        resolve_workload_identity(&args, env, config, verbose).await?;

    let workload_id_hex = format!("{workload_id:#x}");

    println!("Workload: {} {}", name.green().bold(), version,);
    println!("Workload ID: {}", workload_id_hex.dimmed());

    // Resolve relay key for transaction submission.
    let relay_key_raw = super::resolve_relay_key(args.relay_key.as_deref(), config)?;
    let relay_key_hex = relay_key_raw.strip_prefix("0x").unwrap_or(&relay_key_raw);
    let relay_key = {
        let bytes: [u8; 32] = hex::decode(relay_key_hex)
            .context("invalid relay key hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("relay key must be 32 bytes"))?;
        alloy_ext::core::primitives::B256::from(bytes)
    };

    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url,
        relay_key: Some(relay_key),
        session_registry_address,
    };

    println!("Connecting to registry...");
    let measurement =
        automata_tee_workload_measurement::WorkloadMeasurement::new(measurement_config)
            .await
            .context("failed to connect to WorkloadMeasurement")?;

    let registry = measurement.workload_registry();

    // Check if workload is already revoked
    if let Ok(true) = registry.is_workload_revoked(workload_id).await {
        // Update store to reflect revoked state
        let store = WorkloadStore::new(&env.workload_dir);
        if let Ok(Some(entry)) = store.get(&workload_id_hex) {
            if !entry.meta.revoked {
                let mut meta = entry.meta;
                meta.revoked = true;
                let _ = store.save_meta(&meta);
            }
        }
        println!();
        println!("{}", "Workload is already deactivated.".yellow().bold());
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
    let op_expiry_seconds = args.op_expiry_seconds.unwrap_or(chain.op_expiry_seconds);
    let tx_hash = registry
        .deactivate_workload(&signer, workload_id, op_expiry_seconds)
        .await
        .context("deactivateWorkload failed")?;

    println!();
    println!("{}", "Workload deactivated successfully.".green().bold());
    println!("  {:<18}0x{}", "Tx hash:", hex::encode(tx_hash),);

    // Mark as revoked in the local store if entry exists
    let store = WorkloadStore::new(&env.workload_dir);
    if let Ok(Some(entry)) = store.get(&workload_id_hex) {
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

        if atakit_core::is_canonical_id(&s) {
            let workload_id: alloy_ext::core::primitives::B256 =
                s.parse().context("invalid workload identifier")?;
            // Try store lookup for name+version, fall back to "unknown"
            let store = WorkloadStore::new(&env.workload_dir);
            if let Some(entry) = store.get(&s)? {
                return Ok((entry.meta.name, entry.meta.version, workload_id));
            }
            // Can't resolve name+version without chain query here,
            // but we need them for display. Use placeholders - the chain
            // will verify the ID.
            return Ok(("(unknown)".to_string(), "".to_string(), workload_id));
        }

        // <publisher>/<name>:<version> store ref
        if looks_like_store_ref(&s) {
            let WorkloadRef::Ref(app_ref) = super::parse_workload_ref(&s, &config.alias)? else {
                unreachable!("an identifier was handled above")
            };
            let workload_id = compute_workload_id(&app_ref);
            return Ok((app_ref.name.clone(), app_ref.version.clone(), workload_id));
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
        None if config.build.container_engine != crate::config::ContainerEngine::Auto => Some(
            atakit_workload::ContainerEngine::from_str_opt(config.build.container_engine.as_str())?,
        ),
        None => None,
    };

    let opts = atakit_workload::InspectOptions {
        archive: Some(archive.to_path_buf()),
        workload_dir: None,
        engine,
        verbose,
        measured_data_root: None,
        unmeasured_data_root: None,
    };

    let result = atakit_workload::inspect_workload(&opts).await?;
    let name = result.manifest.meta.name.clone();
    let version = result.manifest.meta.version.clone();
    // Only the owner can deactivate, so the publisher is the signer's own
    // fingerprint — the same key this command signs the operation with.
    let owner_key = super::resolve_owner_key(args.owner_key.as_deref(), config)?;
    let publisher = super::owner_fingerprint(&owner_key)?;
    let app_ref = automata_tee_workload_measurement::types::AppRef::new(
        publisher,
        name.clone(),
        version.clone(),
    );
    let workload_id = compute_workload_id(&app_ref);
    Ok((name, version, workload_id))
}
