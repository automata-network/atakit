use anyhow::{Context, Result, bail};
use atakit_workload::cli::DeactivateArgs;
use owo_colors::OwoColorize;

use crate::config::Config;

pub async fn run(args: DeactivateArgs, config: &Config, verbose: bool) -> Result<()> {
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

    // Resolve owner private key: CLI arg > key file from config
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

    // Inspect workload to get name+version
    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != "auto" => {
            Some(atakit_workload::ContainerEngine::from_str_opt(
                &config.build.container_engine,
            )?)
        }
        None => None,
    };

    let dir = match args.dir {
        Some(d) => std::fs::canonicalize(d)?,
        None => std::env::current_dir()?,
    };

    let archive = match args.archive {
        Some(a) => a,
        None => super::find_versioned_archive(&dir)?,
    };

    let opts = atakit_workload::InspectOptions {
        archive: Some(archive),
        workload_dir: None,
        engine,
        verbose,
    };

    let result = atakit_workload::inspect_workload(&opts).await?;
    let manifest = &result.manifest;

    println!(
        "Workload: {} {}",
        manifest.meta.name.green().bold(),
        manifest.meta.version,
    );

    let workload_id = super::compute_workload_id(&manifest.meta.name, &manifest.meta.version);
    let workload_id_hex = format!("0x{}", hex::encode(workload_id));
    println!("Workload ID: {}", workload_id_hex.dimmed());

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

    // Check if workload is already revoked
    if let Ok(true) = registry.is_workload_revoked(workload_id).await {
        println!();
        println!(
            "{}",
            "Workload is already deactivated.".yellow().bold()
        );
        println!("  {:<18}{}", "Workload ID:", workload_id_hex);
        return Ok(());
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

    Ok(())
}
