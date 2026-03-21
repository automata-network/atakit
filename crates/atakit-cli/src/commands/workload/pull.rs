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

    // Check if already in store
    if store.exists(&name, &version) && !args.force {
        println!(
            "Workload {}:{} already in store (use --force to overwrite).",
            name, version
        );
        return Ok(());
    }

    // Download archive
    println!("Downloading {}:{}...", name.green().bold(), version);
    let (data, _filename) = client
        .download(&workload_id_hex)
        .await
        .context("failed to download archive")?;

    let archive_size = data.len() as u64;

    // Inspect downloaded archive to extract PCR23 and verify identity
    let inspection = inspect_bytes(&data)?;
    let pcr23 = &inspection.pcr23;

    // Verify the archive's manifest matches the requested identity
    let expected_id = compute_workload_id(&inspection.name, &inspection.version);
    let expected_id_hex = format!("0x{}", hex::encode(expected_id));
    if expected_id_hex != workload_id_hex {
        anyhow::bail!(
            "archive identity mismatch: requested {name}:{version} ({}), \
             but archive contains {}:{} ({})",
            &workload_id_hex[..10],
            inspection.name,
            inspection.version,
            &expected_id_hex[..10],
        );
    }

    // Optionally verify against on-chain spec
    if args.verify {
        println!("Verifying PCR23 against on-chain spec...");
        verify_pcr23(&workload_id_hex, pcr23, config).await?;
    }

    // Save blob and metadata (merge into existing meta to preserve chain data)
    store.save_blob(&name, &version, &data)?;

    let now = chrono::Local::now().to_rfc3339();
    let meta = match store.load_meta(&name, &version)? {
        Some(mut existing) => {
            existing.workload_id = workload_id_hex.clone();
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
    println!("  {:<18}{}", "PCR23:", pcr23.dimmed());

    Ok(())
}

struct ArchiveInspection {
    name: String,
    version: String,
    pcr23: String,
}

/// Inspect archive bytes in-memory to extract name, version, and PCR23.
fn inspect_bytes(data: &[u8]) -> Result<ArchiveInspection> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.file_name().is_some_and(|f| f == "manifest.toml") {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;

            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let digest = hasher.finalize();
            let pcr23 = format!("0x{:x}", digest);

            // Parse manifest to extract name and version
            let manifest: toml::Value = toml::from_str(&content)
                .context("failed to parse manifest.toml from archive")?;
            let meta = manifest
                .get("meta")
                .ok_or_else(|| anyhow::anyhow!("manifest.toml missing [meta] section"))?;
            let name = meta
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("manifest.toml missing meta.name"))?
                .to_string();
            let version = meta
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("manifest.toml missing meta.version"))?
                .to_string();

            return Ok(ArchiveInspection {
                name,
                version,
                pcr23,
            });
        }
    }

    anyhow::bail!("manifest.toml not found in downloaded archive")
}

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

    // Find PCR23 in the spec
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
