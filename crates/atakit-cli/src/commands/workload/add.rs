use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::AddArgs;
use atakit_workload::store::CachedPcrSpec;
use atakit_workload::{CachedChainSpec, WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use super::{compute_workload_id, parse_workload_ref, resolve_chain, WorkloadRef};
use crate::config::Config;

pub async fn run(args: AddArgs, env: &Env, config: &Config) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);

    // Detect if reference is a file path (.atawl)
    let archive_path = if args.reference.ends_with(".atawl") {
        let p = std::path::PathBuf::from(&args.reference);
        if p.exists() {
            Some(p)
        } else {
            anyhow::bail!("archive not found: {}", p.display());
        }
    } else {
        None
    };

    // If we have an archive, inspect it to get name+version+sha256+pcr23
    let (name, version, archive_sha256, archive_pcr23, archive_size) =
        if let Some(ref path) = archive_path {
            let opts = atakit_workload::InspectOptions {
                archive: Some(path.clone()),
                workload_dir: None,
                engine: None,
                verbose: false,
            };
            let result = atakit_workload::inspect_workload(&opts)
                .await
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            let size = std::fs::metadata(path)?.len();
            (
                result.manifest.meta.name.clone(),
                result.manifest.meta.version.clone(),
                Some(result.sha256),
                Some(result.pcr23),
                Some(size),
            )
        } else {
            // Parse as name:version or 0x<id>
            let wref = parse_workload_ref(&args.reference)?;
            match wref {
                WorkloadRef::NameVersion { name, version } => (name, version, None, None, None),
                WorkloadRef::Id(_) => {
                    // For 0x IDs without an archive, we need on-chain to resolve name+version.
                    // We'll handle this below after the chain query.
                    (String::new(), String::new(), None, None, None)
                }
            }
        };

    // Compute workload ID (or parse from 0x ref)
    let (workload_id, is_id_ref) = if name.is_empty() {
        // 0x<id> reference, no archive
        let id_str = &args.reference;
        let id_hex = id_str.strip_prefix("0x").unwrap_or(id_str);
        let bytes: [u8; 32] = hex::decode(id_hex)
            .context("invalid workload ID hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("workload ID must be 32 bytes"))?;
        (alloy_ext::core::primitives::B256::from(bytes), true)
    } else {
        (compute_workload_id(&name, &version), false)
    };

    let workload_id_hex = format!("0x{}", hex::encode(workload_id));

    // Import archive blob if provided
    if let Some(ref path) = archive_path {
        if store.has_blob(&name, &version) && !args.force {
            // Still continue to merge on-chain data, but skip blob import
            println!("Archive already in store (use --force to overwrite blob).");
        } else {
            store.import_blob(&name, &version, path)?;
        }
    }

    // Resolve chain config (rpc_url + session_registry) from [chains].
    let chain = resolve_chain(args.chain.as_deref(), config)?;
    let rpc_url = chain.rpc_url;

    let session_registry_address: alloy_ext::core::primitives::Address = chain
        .session_registry
        .parse()
        .context("invalid session registry address")?;

    // Query on-chain
    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url,
        relay_key: None,
        session_registry_address,
    };

    println!("Querying on-chain spec...");
    let measurement =
        automata_tee_workload_measurement::WorkloadMeasurement::new(measurement_config)
            .await
            .context("failed to connect to WorkloadMeasurement")?;

    let registry = measurement.workload_registry();
    let spec = registry
        .get_workload_spec(workload_id)
        .await
        .context("workload not found on-chain")?;

    let owner = registry
        .get_workload_owner(workload_id)
        .await
        .ok()
        .map(|fp| format!("0x{}", hex::encode(fp)));

    let revoked = registry
        .is_workload_revoked(workload_id)
        .await
        .unwrap_or(false);

    // Resolve name+version from on-chain if we only had an ID
    let (name, version) = if is_id_ref {
        (spec.name.clone(), spec.version.clone())
    } else {
        (name, version)
    };

    // On-chain STATIC matchData stores the final PCR23 value
    let chain_pcr23 = spec
        .pcrs
        .iter()
        .find(|p| p.pcrIndex == 23)
        .and_then(|p| p.matchData.first())
        .map(|b| format!("0x{}", hex::encode(b)));

    let sha256 = archive_sha256;
    let pcr23 = archive_pcr23.or(chain_pcr23);

    // Build cached chain spec
    let chain_spec = CachedChainSpec {
        session_ttl: spec.ttl,
        base_image_mode: spec.baseImageMode,
        base_image_ids: spec
            .baseImageIds
            .iter()
            .map(|b| format!("0x{}", hex::encode(b)))
            .collect(),
        pcrs: spec
            .pcrs
            .iter()
            .map(|p| CachedPcrSpec {
                pcr_index: p.pcrIndex,
                verify_type: p.verifyType,
                match_data: p
                    .matchData
                    .iter()
                    .map(|b| format!("0x{}", hex::encode(b)))
                    .collect(),
            })
            .collect(),
    };

    // Check if entry exists - merge if so
    let now = chrono::Local::now().to_rfc3339();
    let meta = if let Some(existing) = store.get(&name, &version)? {
        let mut m = existing.meta;
        m.on_chain_spec = Some(chain_spec);
        m.revoked = revoked;
        if owner.is_some() {
            m.owner.clone_from(&owner);
        }
        if sha256.is_some() && m.sha256.is_none() {
            m.sha256.clone_from(&sha256);
        }
        if pcr23.is_some() && m.pcr23.is_none() {
            m.pcr23.clone_from(&pcr23);
        }
        // Update archive_size if we just imported a blob
        if let Some(size) = archive_size {
            m.archive_size = Some(size);
        }
        // Refresh identity and timestamp for consistency with other merge paths
        m.workload_id = workload_id_hex.clone();
        m.name = name.clone();
        m.version = version.clone();
        m.added_at = now.clone();
        m
    } else {
        WorkloadMeta {
            workload_id: workload_id_hex.clone(),
            name: name.clone(),
            version: version.clone(),
            sha256: sha256.clone(),
            pcr23: pcr23.clone(),
            owner: owner.clone(),
            archive_size,
            on_chain_spec: Some(chain_spec),
            revoked,
            repositories: Vec::new(),
            added_at: now,
        }
    };
    store.save_meta(&meta)?;

    println!();
    println!("{}", "Added.".green().bold());
    println!("  {:<18}{}:{}", "Workload:", name, version);
    println!("  {:<18}{}", "Workload ID:", workload_id_hex.dimmed());
    if let Some(ref o) = owner {
        println!("  {:<18}{}", "Owner:", o.dimmed());
    }
    if let Some(ref p) = sha256 {
        println!("  {:<18}{}", "Manifest SHA256:", p.dimmed());
    }
    if archive_path.is_some() {
        println!("  {:<18}imported", "Archive:");
    }

    Ok(())
}
