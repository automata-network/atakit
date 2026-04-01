use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::PullArgs;
use atakit_workload::{RegistryClient, WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use super::{compute_workload_id, parse_workload_ref, WorkloadRef};
use crate::config::Config;

pub async fn run(args: PullArgs, env: &Env, config: &Config) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);
    let registry_url = config.registry.resolve_url(args.registry.as_deref())?;
    let client = RegistryClient::new(&registry_url);

    // Parse reference and resolve to name+version+workload_id
    let wref = parse_workload_ref(&args.reference)?;
    let (name, version, workload_id_hex) = match &wref {
        WorkloadRef::NameVersion { name, version } => {
            let id = compute_workload_id(name, version);
            (name.clone(), version.clone(), format!("0x{}", hex::encode(id)))
        }
        WorkloadRef::Id(id) => {
            // Query registry for metadata to get name+version
            let meta = client
                .get_meta(id)
                .await
                .context("failed to resolve workload ID from registry")?;
            (meta.name, meta.version, id.clone())
        }
    };

    // Check if blob already in store (metadata-only entries from `add` should still pull)
    if store.has_blob(&name, &version) && !args.force {
        println!(
            "Workload {}:{} already in store (use --force to overwrite).",
            name, version
        );
        return Ok(());
    }

    // Download archive to temp file (streaming, bounded memory)
    println!("Downloading {}:{}...", name.green().bold(), version);
    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;
    let tmp_path = tmp_dir.path().join("download.atawl");
    let archive_size = client
        .download_to_file(&workload_id_hex, &tmp_path)
        .await
        .context("failed to download archive")?;

    // Inspect downloaded archive using the shared library inspector
    let inspect_opts = atakit_workload::InspectOptions {
        archive: Some(tmp_path.clone()),
        workload_dir: None,
        engine: None,
        verbose: false,
    };
    let inspection = atakit_workload::inspect_workload(&inspect_opts)
        .await
        .context("failed to inspect downloaded archive")?;
    let sha256 = &inspection.sha256;
    let pcr23 = &inspection.pcr23;
    let archive_name = &inspection.manifest.meta.name;
    let archive_version = &inspection.manifest.meta.version;

    // Verify the archive's manifest matches the requested identity
    let expected_id = compute_workload_id(archive_name, archive_version);
    let expected_id_hex = format!("0x{}", hex::encode(expected_id));
    if expected_id_hex != workload_id_hex {
        anyhow::bail!(
            "archive identity mismatch: requested {name}:{version} ({}), \
             but archive contains {}:{} ({})",
            &workload_id_hex[..10],
            archive_name,
            archive_version,
            &expected_id_hex[..10],
        );
    }

    // Optionally verify against on-chain spec
    if args.verify {
        println!("Verifying PCR23 against on-chain spec...");
        verify_pcr23(&workload_id_hex, pcr23, config).await?;
    }

    // Import blob from temp file into store
    store.import_blob(&name, &version, &tmp_path)?;

    let now = chrono::Local::now().to_rfc3339();
    let meta = match store.load_meta(&name, &version)? {
        Some(mut existing) => {
            existing.workload_id = workload_id_hex.clone();
            existing.sha256 = Some(sha256.clone());
            existing.pcr23 = Some(pcr23.clone());
            existing.archive_size = Some(archive_size);
            if !existing.registries.contains(&registry_url) {
                existing.registries.push(registry_url.clone());
            }
            existing.added_at = now;
            existing
        }
        None => WorkloadMeta {
            workload_id: workload_id_hex.clone(),
            name: name.clone(),
            version: version.clone(),
            sha256: Some(sha256.clone()),
            pcr23: Some(pcr23.clone()),
            owner: None,
            archive_size: Some(archive_size),
            on_chain_spec: None,
            revoked: false,
            registries: vec![registry_url.clone()],
            added_at: now,
        },
    };
    store.save_meta(&meta)?;

    println!();
    println!("{}", "Pull complete.".green().bold());
    println!("  {:<18}{}:{}", "Workload:", name, version);
    println!("  {:<18}{}", "Size:", format_size(archive_size));
    println!("  {:<18}{}", "SHA256:", sha256.dimmed());

    Ok(())
}

/// Verify the archive's PCR23 (final register value) against on-chain matchData.
///
/// On-chain STATIC matchData for PCR23 contains the final PCR value
/// (SHA-256(zeros_32 || event_hash)), which matches `InspectResult.pcr23`.
async fn verify_pcr23(workload_id_hex: &str, pcr23: &str, config: &Config) -> Result<()> {
    let rpc_url = config
        .publish
        .rpc_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("RPC URL required for --verify"))?;

    let session_registry_str = config
        .publish
        .session_registry
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("session registry required for --verify"))?;

    let session_registry_address: alloy_ext::core::primitives::Address =
        session_registry_str.parse().context("invalid session registry address")?;

    let id_hex = workload_id_hex.strip_prefix("0x").unwrap_or(workload_id_hex);
    let id_bytes: [u8; 32] = hex::decode(id_hex)
        .context("invalid workload ID hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("workload ID must be 32 bytes"))?;
    let workload_id = alloy_ext::core::primitives::B256::from(id_bytes);

    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url: rpc_url.to_string(),
        relay_key: None,
        session_registry_address,
    };

    let measurement = automata_tee_workload_measurement::WorkloadMeasurement::new(measurement_config)
        .await
        .context("failed to connect to WorkloadMeasurement")?;

    let registry = measurement.workload_registry();
    let spec = registry
        .get_workload_spec(workload_id)
        .await
        .context("failed to query on-chain spec")?;

    // Find PCR23 in the spec. matchData[0] is the final PCR register value.
    let on_chain_pcr23 = spec
        .pcrs
        .iter()
        .find(|p| p.pcrIndex == 23)
        .and_then(|p| p.matchData.first())
        .map(|b| format!("0x{}", hex::encode(b)));

    if let Some(ref expected) = on_chain_pcr23 {
        if expected != pcr23 {
            anyhow::bail!(
                "PCR23 mismatch: archive={pcr23}, on-chain={expected}"
            );
        }
        println!("  PCR23 verified: {}", "match".green());
    } else {
        println!("  {}", "No PCR23 found in on-chain spec.".yellow());
    }

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
