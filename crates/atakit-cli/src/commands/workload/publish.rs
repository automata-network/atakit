use anyhow::{Context, Result, bail};
use atakit_core::Env;
use atakit_workload::cli::PublishArgs;
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;
use sha2::Digest;

use super::looks_like_store_ref;
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

    // Compute final PCR23 register value: SHA-256(zeros_32 || event_hash).
    // The event hash is SHA-256(manifest.toml). The TPM extends from all zeros.
    let pcr23_hex = result.pcr23.strip_prefix("0x").unwrap_or(&result.pcr23);
    let event_hash: [u8; 32] = hex::decode(pcr23_hex)
        .context("invalid PCR23 hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("PCR23 must be 32 bytes"))?;
    let mut extend_hasher = sha2::Sha256::new();
    extend_hasher.update([0u8; 32]); // PCR starts at all zeros
    extend_hasher.update(event_hash);
    let pcr23_final: [u8; 32] = extend_hasher.finalize().into();
    let pcr23_b256 = alloy_ext::core::primitives::B256::from(pcr23_final);

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
        ttl: args.ttl,
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
    let pcr23_final_hex = format!("0x{}", hex::encode(pcr23_final));
    let base_image_mode_str = &manifest.config.base_image_mode;

    println!(
        "{} {}",
        manifest.meta.name.green().bold(),
        manifest.meta.version,
    );
    println!();
    println!("  {:<20}{}", "Workload ID:".dimmed(), workload_id_hex);
    println!("  {:<20}{}", "SHA256:".dimmed(), result.pcr23);
    println!("  {:<20}{}", "PCR23:".dimmed(), pcr23_final_hex);
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
    println!("  {:<20}{}", "TTL:".dimmed(), if args.ttl == 0 { "default (30 days)".to_string() } else { format!("{} days", args.ttl / 86400) });
    println!();

    if let Ok(existing) = registry.get_workload_spec(workload_id).await {
        println!();
        println!(
            "{}",
            "Workload already registered.".yellow().bold()
        );
        println!("  {:<18}{}", "Workload ID:", workload_id_hex);
        println!("  {:<18}{} {}", "Registered as:", existing.name, existing.version);
        return Ok(());
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

    Ok(())
}
