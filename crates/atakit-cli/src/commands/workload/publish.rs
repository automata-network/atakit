use std::io::Write;

use anyhow::{Context, Result, bail};
use atakit_core::Env;
use atakit_workload::cli::PublishArgs;
use atakit_workload::{WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use super::{apply_chain_data_to_meta, looks_like_store_ref, query_chain_data};
use crate::config::Config;

pub async fn run(args: PublishArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    // Resolve RPC URL and session registry from args, config, or env
    let rpc_url = args
        .rpc_url
        .or_else(|| config.publish.rpc_url.clone())
        .ok_or_else(|| anyhow::anyhow!(
            "RPC URL required: use --rpc-url, ATAKIT_RPC_URL, or [publish] rpc_url in config"
        ))?;

    let session_registry_str = args
        .session_registry
        .or_else(|| config.publish.session_registry.clone())
        .ok_or_else(|| anyhow::anyhow!(
            "session registry address required: use --session-registry, ATAKIT_SESSION_REGISTRY, or [publish] session_registry in config"
        ))?;

    let session_registry_address: alloy_ext::core::primitives::Address =
        session_registry_str.parse().context("invalid session registry address")?;

    // Resolve private key: CLI arg > key file from config
    let private_key_raw = match args.owner_key {
        Some(k) => k,
        None => match config.publish.owner_key_file {
            Some(ref path) => crate::config::read_key_file(path)?,
            None => bail!("owner key required: use --owner-key or set publish.owner_key_file in config"),
        },
    };
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

    // Parse base image IDs
    let mut base_image_ids = Vec::new();
    for id_str in &args.base_image_id {
        let hex_str = id_str.strip_prefix("0x").unwrap_or(id_str);
        let bytes: [u8; 32] = hex::decode(hex_str)
            .context(format!("invalid base image ID hex: {id_str}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("base image ID must be 32 bytes: {id_str}"))?;
        base_image_ids.push(alloy_ext::core::primitives::B256::from(bytes));
    }

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
        ttl: args.ttl.unwrap_or(manifest.config.ttl),
        baseImageMode: base_image_mode,
        baseImageIds: base_image_ids,
        requirements: vec![],
        pcrs: vec![PcrSpec {
            pcrIndex: 23,
            verifyType: 0, // STATIC
            matchData: vec![pcr23_b256],
        }],
    };

    // Resolve relay key: CLI arg > key file from config
    let relay_key_raw = match args.relay_key {
        Some(k) => k,
        None => match config.publish.relay_key_file {
            Some(ref path) => crate::config::read_key_file(path)?,
            None => bail!("relay key required: use --relay-key or set publish.relay_key_file in config"),
        },
    };
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
    println!("  {:<20}{}", "SHA256:".dimmed(), result.sha256);
    println!("  {:<20}{}", "PCR23:".dimmed(), result.pcr23);
    println!("  {:<20}{} ({})", "Base Image Mode:".dimmed(), base_image_mode_str, base_image_mode);
    if !args.base_image_id.is_empty() {
        for (i, id) in args.base_image_id.iter().enumerate() {
            if i == 0 {
                println!("  {:<20}{}", "Base Image IDs:".dimmed(), id);
            } else {
                println!("  {:<20}{}", "", id);
            }
        }
    } else {
        println!("  {:<20}{}", "Base Image IDs:".dimmed(), "none".dimmed());
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
        let rpc_url = config.publish.rpc_url.as_deref().unwrap();
        let session_registry = config.publish.session_registry.as_deref().unwrap();
        if let Ok(chain) = query_chain_data(workload_id, rpc_url, session_registry).await {
            let store = WorkloadStore::new(&env.workload_dir);
            let now = chrono::Local::now().to_rfc3339();
            let meta = match store.load_meta(&manifest.meta.name, &manifest.meta.version)? {
                Some(mut m) => {
                    m.workload_id = workload_id_hex.clone();
                    m.sha256 = Some(result.sha256.clone());
                    m.pcr23 = Some(result.pcr23.clone());
                    apply_chain_data_to_meta(&mut m, &chain);
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
                        registries: Vec::new(),
                        added_at: now,
                    };
                    apply_chain_data_to_meta(&mut m, &chain);
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
    let result_id = registry
        .register_workload(&signer, spec, args.expire_offset)
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
    let rpc_url = config.publish.rpc_url.as_deref().unwrap();
    let session_registry = config.publish.session_registry.as_deref().unwrap();
    if let Ok(chain) = query_chain_data(workload_id, rpc_url, session_registry).await {
        let store = WorkloadStore::new(&env.workload_dir);
        let now = chrono::Local::now().to_rfc3339();
        let meta = match store.load_meta(&manifest.meta.name, &manifest.meta.version)? {
            Some(mut m) => {
                m.workload_id = workload_id_hex.clone();
                m.sha256 = Some(result.sha256.clone());
                m.pcr23 = Some(result.pcr23.clone());
                apply_chain_data_to_meta(&mut m, &chain);
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
                    registries: Vec::new(),
                    added_at: now,
                };
                apply_chain_data_to_meta(&mut m, &chain);
                m
            }
        };
        store.save_meta(&meta)?;
        println!("{}", "Local store updated.".green());
    }

    Ok(())
}
