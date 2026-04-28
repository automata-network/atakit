use std::io::Write;

use anyhow::{Context, Result, bail};
use atakit_core::Env;
use atakit_workload::cli::PublishArgs;
use atakit_workload::{WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use super::{apply_chain_data_to_meta, looks_like_store_ref, query_chain_data, resolve_chain, resolve_owner_key};
use crate::config::Config;

pub async fn run(args: PublishArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
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

    // Inspect workload to get PCR23 and manifest
    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != "auto" => {
            Some(atakit_workload::ContainerEngine::from_str_opt(
                &config.build.container_engine,
            )?)
        }
        None => None,
    };

    let archive = if let Some(ref archive_arg) = args.archive {
        let archive_str = archive_arg.to_string_lossy();
        if looks_like_store_ref(&archive_str) {
            let store = WorkloadStore::new(&env.workload_dir);
            let (name, version) = archive_str
                .split_once(':')
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .unwrap();
            let blob = store.blob_path(&name, &version)?;
            if !blob.exists() {
                bail!("no archive blob for {name}:{version} in store");
            }
            blob
        } else {
            archive_arg.clone()
        }
    } else {
        let dir = match args.dir {
            Some(d) => std::fs::canonicalize(d)?,
            None => std::env::current_dir()?,
        };
        super::find_versioned_archive(&dir)?
    };

    let opts = atakit_workload::InspectOptions {
        archive: Some(archive),
        workload_dir: None,
        engine,
        verbose,
    };

    let result = atakit_workload::inspect_workload(&opts).await?;
    let manifest = &result.manifest;

    // Final PCR23 register value (computed by inspect).
    let pcr23_hex = result.pcr23.strip_prefix("0x").unwrap_or(&result.pcr23);
    let pcr23_bytes: [u8; 32] = hex::decode(pcr23_hex)
        .context("invalid PCR23 hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("PCR23 must be 32 bytes"))?;
    let pcr23_b256 = alloy_ext::core::primitives::B256::from(pcr23_bytes);

    // Derive base image IDs from manifest's base-image list (name:version -> on-chain ID).
    // --base-image-id CLI args override if provided.
    let base_image_ids = if !args.base_image_id.is_empty() {
        let mut ids = Vec::new();
        for id_str in &args.base_image_id {
            let hex_str = id_str.strip_prefix("0x").unwrap_or(id_str);
            let bytes: [u8; 32] = hex::decode(hex_str)
                .context(format!("invalid base image ID hex: {id_str}"))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("base image ID must be 32 bytes: {id_str}"))?;
            ids.push(alloy_ext::core::primitives::B256::from(bytes));
        }
        ids
    } else {
        manifest
            .config
            .base_image
            .iter()
            .map(|entry| {
                let (name, version) = entry.split_once(':').ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid base-image entry '{}': expected name:version format",
                        entry,
                    )
                })?;
                Ok(super::compute_base_image_id(name, version))
            })
            .collect::<Result<Vec<_>>>()?
    };

    // Map base-image-mode string to AccessMode enum value
    // Solidity: ANY=0, BLACKLIST=1, WHITELIST=2
    let base_image_mode = match manifest.config.base_image_mode.as_str() {
        "any" => 0u8,
        "blacklist" => 1u8,
        "whitelist" => 2u8,
        other => bail!("unknown base-image-mode: {other}"),
    };

    // Build WorkloadSpec using the contract's generated types
    use automata_tee_workload_measurement::stubs::WorkloadRegistry::{PcrSpec, WorkloadSpec};

    let spec = WorkloadSpec {
        name: manifest.meta.name.clone(),
        version: manifest.meta.version.clone(),
        ttl: args.session_ttl.unwrap_or(manifest.config.session_ttl),
        baseImageMode: base_image_mode,
        baseImageIds: base_image_ids,
        requirements: vec![],
        pcrs: vec![PcrSpec {
            pcrIndex: 23,
            verifyType: 0, // STATIC
            matchData: vec![pcr23_b256],
        }],
    };

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
        rpc_url: rpc_url.clone(),
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

    // Compute workload ID and display summary before publishing.
    let workload_id = super::compute_workload_id(&manifest.meta.name, &manifest.meta.version);
    let workload_id_hex = format!("0x{}", hex::encode(workload_id));
    let base_image_mode_str = &manifest.config.base_image_mode;

    println!(
        "{} {}",
        manifest.meta.name.green().bold(),
        manifest.meta.version,
    );
    println!();
    println!("  {:<20}{}", "Workload ID:".dimmed(), workload_id_hex);
    println!("  {:<20}{}", "Manifest SHA256:".dimmed(), result.sha256);
    println!("  {:<20}{}", "PCR23:".dimmed(), result.pcr23);
    println!("  {:<20}{} ({})", "Base Image Mode:".dimmed(), base_image_mode_str, base_image_mode);
    if spec.baseImageIds.is_empty() {
        println!("  {:<20}{}", "Base Image IDs:".dimmed(), "none".dimmed());
    } else {
        for (i, id) in spec.baseImageIds.iter().enumerate() {
            let id_hex = format!("0x{}", hex::encode(id));
            // Show source entry alongside hex ID when derived from manifest.
            let source = if args.base_image_id.is_empty() {
                manifest.config.base_image.get(i).map(|s| format!(" ({s})")).unwrap_or_default()
            } else {
                String::new()
            };
            if i == 0 {
                println!("  {:<20}{}{}", "Base Image IDs:".dimmed(), id_hex, source.dimmed());
            } else {
                println!("  {:<20}{}{}", "", id_hex, source.dimmed());
            }
        }
    }
    println!("  {:<20}{}", "TTL:".dimmed(), if spec.ttl == 0 {
        "contract default (30 days)".to_string()
    } else {
        format!("{}s ({} days)", spec.ttl, spec.ttl / 86400)
    });
    println!();

    if let Ok(existing) = registry.get_workload_spec(workload_id).await {
        let is_revoked = registry.is_workload_revoked(workload_id).await.unwrap_or(false);
        println!();
        if is_revoked {
            println!(
                "{}",
                "Workload version was previously deactivated.".yellow().bold()
            );
            println!("  {:<18}{}", "Workload ID:", workload_id_hex);
            println!("  {:<18}{} {}", "Registered as:", existing.name, existing.version);
            println!();
            println!("{}", "A deactivated version cannot be re-registered. Please use a new version tag.".yellow());
            println!("  {}", "Example: update 'version' in workload.toml to a new value (e.g. v0.0.2)".yellow());
        } else {
            println!(
                "{}",
                "Workload already registered.".yellow().bold()
            );
            println!("  {:<18}{}", "Workload ID:", workload_id_hex);
            println!("  {:<18}{} {}", "Registered as:", existing.name, existing.version);
            println!();
            println!("{}", "To publish updated measurements, use a new version tag.".yellow());
            println!("  {}", "Example: update 'version' in workload.toml to a new value (e.g. v0.0.2)".yellow());
        }

        // Always refresh on-chain data into local store
        if let Ok(chain_data) = query_chain_data(workload_id, &rpc_url, &chain.session_registry).await {
            let store = WorkloadStore::new(&env.workload_dir);
            let now = chrono::Local::now().to_rfc3339();
            let meta = match store.load_meta(&manifest.meta.name, &manifest.meta.version)? {
                Some(mut m) => {
                    m.workload_id = workload_id_hex.clone();
                    m.sha256 = Some(result.sha256.clone());
                    m.pcr23 = Some(result.pcr23.clone());
                    apply_chain_data_to_meta(&mut m, &chain_data);
                    m.added_at = now;
                    m
                }
                None => {
                    let mut m = WorkloadMeta {
                        workload_id: workload_id_hex.clone(),
                        name: manifest.meta.name.clone(),
                        version: manifest.meta.version.clone(),
                        sha256: Some(result.sha256.clone()),
                        pcr23: Some(result.pcr23.clone()),
                        owner: None,
                        archive_size: None,
                        on_chain_spec: None,
                        revoked: false,
                        repositories: Vec::new(),
                        added_at: now,
                    };
                    apply_chain_data_to_meta(&mut m, &chain_data);
                    m
                }
            };
            store.save_meta(&meta)?;
            println!("{}", "Local metadata synced with on-chain state.".green());
        }

        return Ok(());
    }

    if !args.yes {
        eprint!("Publish? [y/N] ");
        std::io::stderr().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("Submitting registerWorkload transaction...");
    let expire_offset = args.expire_offset.unwrap_or(chain.expire_offset);
    let result_id = registry
        .register_workload(&signer, spec, expire_offset)
        .await
        .context("registerWorkload failed")?;

    println!();
    println!(
        "{}",
        "Workload published successfully.".green().bold()
    );
    println!(
        "  {:<18}0x{}",
        "Workload ID:",
        hex::encode(result_id),
    );

    // Refresh on-chain data into local store
    if let Ok(chain_data) = query_chain_data(workload_id, &rpc_url, &chain.session_registry).await {
        let store = WorkloadStore::new(&env.workload_dir);
        let now = chrono::Local::now().to_rfc3339();
        let meta = match store.load_meta(&manifest.meta.name, &manifest.meta.version)? {
            Some(mut m) => {
                m.workload_id = workload_id_hex.clone();
                m.sha256 = Some(result.sha256.clone());
                m.pcr23 = Some(result.pcr23.clone());
                apply_chain_data_to_meta(&mut m, &chain_data);
                m.added_at = now;
                m
            }
            None => {
                let mut m = WorkloadMeta {
                    workload_id: workload_id_hex.clone(),
                    name: manifest.meta.name.clone(),
                    version: manifest.meta.version.clone(),
                    sha256: Some(result.sha256.clone()),
                    pcr23: Some(result.pcr23.clone()),
                    owner: None,
                    archive_size: None,
                    on_chain_spec: None,
                    revoked: false,
                    repositories: Vec::new(),
                    added_at: now,
                };
                apply_chain_data_to_meta(&mut m, &chain_data);
                m
            }
        };
        store.save_meta(&meta)?;
        println!("{}", "Local store updated.".green());
    }

    Ok(())
}
