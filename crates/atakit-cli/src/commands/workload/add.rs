use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::AddArgs;
use atakit_workload::store::CachedPcrSpec;
use atakit_workload::{CachedChainSpec, WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use super::{
    compute_workload_id, parse_workload_ref, resolve_chain, static_pcr256_value, WorkloadRef,
};
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

    // Establish the identifier before anything else: it is what the store is
    // keyed by and what the chain is queried with, and it is derivable only
    // from a publisher-qualified reference.
    let (
        workload_id,
        mut name,
        mut version,
        publisher,
        archive_sha256,
        archive_pcr23,
        archive_size,
    ) = if let Some(ref path) = archive_path {
        let opts = atakit_workload::InspectOptions {
            archive: Some(path.clone()),
            workload_dir: None,
            engine: None,
            verbose: false,
            measured_data_root: None,
            unmeasured_data_root: None,
        };
        let result = atakit_workload::inspect_workload(&opts)
            .await
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        let size = std::fs::metadata(path)?.len();
        let name = result.manifest.meta.name.clone();
        let version = result.manifest.meta.version.clone();
        // A path records no publisher, so the identity comes from the
        // configured signing key.
        let publisher = super::configured_publisher(args.signing_key.as_deref(), config)?;
        let app_ref = automata_tee_workload_measurement::types::AppRef::new(
            publisher,
            name.clone(),
            version.clone(),
        );
        (
            compute_workload_id(&app_ref),
            name,
            version,
            Some(format!("{publisher:#x}")),
            Some(result.sha256),
            Some(result.pcr23_sha256),
            Some(size),
        )
    } else {
        match parse_workload_ref(&args.reference, &config.alias)? {
            WorkloadRef::Ref(app_ref) => (
                compute_workload_id(&app_ref),
                app_ref.name.clone(),
                app_ref.version.clone(),
                Some(format!("{:#x}", app_ref.publisher)),
                None,
                None,
                None,
            ),
            // An identifier alone carries no name, version, or publisher.
            // All three come from the registry record below.
            WorkloadRef::Id(id) => (
                id.parse().context("invalid workload identifier")?,
                String::new(),
                String::new(),
                None,
                None,
                None,
                None,
            ),
        }
    };

    let workload_id_hex = format!("{workload_id:#x}");

    // Import archive blob if provided
    if let Some(ref path) = archive_path {
        if store.has_blob(&workload_id_hex) && !args.force {
            // Still continue to merge on-chain data, but skip blob import
            println!("Archive already in store (use --force to overwrite blob).");
        } else {
            store.import_blob(&workload_id_hex, path)?;
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

    // An identifier-only reference gets its name and version from the record.
    if name.is_empty() {
        name = spec.name.clone();
        version = spec.version.clone();
    }

    // The registry owner is the publisher. For a reference we already derived
    // it; for an identifier this is the only source.
    let publisher = publisher
        .or_else(|| owner.clone())
        .ok_or_else(|| anyhow::anyhow!("workload {workload_id_hex} has no owner on chain"))?;

    // The on-chain STATIC `comparison` commits the final PCR23 value.
    let chain_pcr23 = spec
        .workloadPcrPolicy
        .pcrSpecs256
        .iter()
        .find(|p| p.pcrIndex == 23)
        .and_then(|p| static_pcr256_value(&p.comparison))
        .map(|value| format!("0x{}", hex::encode(value)));

    let sha256 = archive_sha256;
    let pcr23 = archive_pcr23.or(chain_pcr23);

    // Build cached chain spec
    let chain_spec = CachedChainSpec {
        session_ttl: spec.sessionTtl,
        base_image_mode: spec.baseImageMode,
        base_image_ids: spec
            .baseImageIds
            .iter()
            .map(|b| format!("0x{}", hex::encode(b)))
            .collect(),
        pcrs: spec
            .workloadPcrPolicy
            .pcrSpecs256
            .iter()
            .map(|p| CachedPcrSpec {
                pcr_index: p.pcrIndex,
                comparison: format!("0x{}", hex::encode(&p.comparison)),
            })
            .collect(),
    };

    // Check if entry exists - merge if so
    let now = chrono::Local::now().to_rfc3339();
    let existing_entry = match store.get(&workload_id_hex) {
        Ok(entry) => entry,
        Err(atakit_workload::WorkloadError::UnsupportedMeta { .. }) if args.force => None,
        Err(error) => return Err(error.into()),
    };
    let meta = if let Some(existing) = existing_entry {
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
        m.publisher = publisher.clone();
        m.name = name.clone();
        m.version = version.clone();
        m.added_at = now.clone();
        m
    } else {
        WorkloadMeta {
            metadata_format: atakit_workload::store::WORKLOAD_META_FORMAT_VERSION,
            workload_id: workload_id_hex.clone(),
            publisher: publisher.clone(),
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
