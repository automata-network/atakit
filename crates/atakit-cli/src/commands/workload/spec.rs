use anyhow::{Context, Result};
use atakit_workload::cli::SpecArgs;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::config::Config;

pub async fn run(args: SpecArgs, config: &Config) -> Result<()> {
    // Resolve RPC URL and session registry from args, config, or env
    let rpc_url = args
        .rpc_url
        .or_else(|| config.publish.rpc_url.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "RPC URL required: use --rpc-url, ATAKIT_RPC_URL, or [publish] rpc_url in config"
            )
        })?;

    let session_registry_str = args
        .session_registry
        .or_else(|| config.publish.session_registry.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "session registry address required: use --session-registry, ATAKIT_SESSION_REGISTRY, or [publish] session_registry in config"
            )
        })?;

    let session_registry_address: alloy_ext::core::primitives::Address =
        session_registry_str.parse().context("invalid session registry address")?;

    // Parse workload ID from hex
    let id_hex = args.id.strip_prefix("0x").unwrap_or(&args.id);
    let id_bytes: [u8; 32] = hex::decode(id_hex)
        .context("invalid workload ID hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("workload ID must be 32 bytes"))?;
    let workload_id = alloy_ext::core::primitives::B256::from(id_bytes);

    // Read-only query, no relay key needed
    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url,
        relay_key: None,
        session_registry_address,
    };

    let measurement =
        automata_tee_workload_measurement::WorkloadMeasurement::new(measurement_config)
            .await
            .context("failed to connect to WorkloadMeasurement")?;

    let registry = measurement.workload_registry();

    // Query workload spec
    let spec = match registry.get_workload_spec(workload_id).await {
        Ok(s) => s,
        Err(_) => {
            println!("Workload not found: 0x{}", hex::encode(workload_id));
            return Ok(());
        }
    };

    // Query owner and revocation status
    let owner = registry.get_workload_owner(workload_id).await.ok();
    let revoked = registry
        .is_workload_revoked(workload_id)
        .await
        .unwrap_or(false);

    // Display header
    let status = if revoked {
        "revoked".red().bold().to_string()
    } else {
        "active".green().bold().to_string()
    };
    println!(
        "{} {} [{}]",
        spec.name.green().bold(),
        spec.version,
        status,
    );
    println!();

    // Workload ID and owner
    println!("  {:<20}{}", "Workload ID:", format!("0x{}", hex::encode(workload_id)).dimmed());
    if let Some(owner_fp) = owner {
        println!("  {:<20}{}", "Owner:", format!("0x{}", hex::encode(owner_fp)).dimmed());
    }
    println!("  {:<20}{}", "TTL:", format_ttl(spec.ttl));

    // Base image mode
    let mode_name = match spec.baseImageMode {
        0 => "any",
        1 => "blacklist",
        2 => "whitelist",
        _ => "unknown",
    };
    println!("  {:<20}{} ({})", "Base Image Mode:", mode_name, spec.baseImageMode);
    if spec.baseImageIds.is_empty() {
        println!("  {:<20}{}", "Base Image IDs:", "none".dimmed());
    } else {
        for (i, id) in spec.baseImageIds.iter().enumerate() {
            let label = if i == 0 { "Base Image IDs:" } else { "" };
            println!("  {:<20}{}", label, format!("0x{}", hex::encode(id)).dimmed());
        }
    }
    println!();

    // PCR specs
    println!("  {}", "PCR Specs:".cyan().bold());
    if spec.pcrs.is_empty() {
        println!("    {}", "none".dimmed());
    } else {
        for pcr in &spec.pcrs {
            let verify_type = match pcr.verifyType {
                0 => "STATIC",
                1 => "DYNAMIC_SUBSET",
                2 => "DYNAMIC_SUBSEQUENCE",
                _ => "UNKNOWN",
            };
            println!(
                "    PCR{:<4} {} ({})",
                pcr.pcrIndex,
                verify_type.dimmed(),
                pcr.verifyType,
            );
            // matchData contains events, not the final PCR value.
            // PCR = extend(0x00..00, event1, event2, ...)
            // where extend(pcr, event) = SHA-256(pcr || event)
            let mut pcr_value = [0u8; 32];
            for data in &pcr.matchData {
                let mut hasher = Sha256::new();
                hasher.update(pcr_value);
                hasher.update(data.as_slice());
                pcr_value = hasher.finalize().into();
                println!("      event  {}", format!("0x{}", hex::encode(data)).dimmed());
            }
            println!("      value  {}", format!("0x{}", hex::encode(pcr_value)).green());
        }
    }
    println!();

    // Requirements
    println!("  {}", "Requirements:".cyan().bold());
    if spec.requirements.is_empty() {
        println!("    {}", "none".dimmed());
    } else {
        for req in &spec.requirements {
            println!("    Key: {}", format!("0x{}", hex::encode(req.key)).dimmed());
            for val in &req.allowedValues {
                println!("      {}", format!("0x{}", hex::encode(val)).dimmed());
            }
        }
    }

    Ok(())
}

fn format_ttl(ttl: u64) -> String {
    if ttl == 0 {
        "default (30 days)".to_string()
    } else if ttl.is_multiple_of(86400) {
        format!("{} days ({}s)", ttl / 86400, ttl)
    } else if ttl.is_multiple_of(3600) {
        format!("{} hours ({}s)", ttl / 3600, ttl)
    } else {
        format!("{}s", ttl)
    }
}
