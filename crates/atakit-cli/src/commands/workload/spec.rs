use anyhow::{Context, Result};
use atakit_workload::cli::SpecArgs;
use automata_tee_workload_measurement::pcr_comparison::{
    decode256, decode384, PcrComparison256, PcrComparison384,
};
use owo_colors::OwoColorize;

use super::resolve_chain;
use crate::config::Config;

pub async fn run(args: SpecArgs, config: &Config) -> Result<()> {
    // Resolve chain config (rpc_url + session_registry) from [chains].
    let chain = resolve_chain(args.chain.as_deref(), config)?;
    let rpc_url = chain.rpc_url;

    let session_registry_address: alloy_ext::core::primitives::Address = chain
        .session_registry
        .parse()
        .context("invalid session registry address")?;

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
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("revert") || err_str.contains("execution reverted") {
                println!("Workload not found: 0x{}", hex::encode(workload_id));
            } else {
                println!(
                    "Failed to query workload 0x{}: {e}",
                    hex::encode(workload_id)
                );
            }
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
    println!("{} {} [{}]", spec.name.green().bold(), spec.version, status,);
    println!();

    // Workload ID and owner
    println!(
        "  {:<20}{}",
        "Workload ID:",
        format!("0x{}", hex::encode(workload_id)).dimmed()
    );
    if let Some(owner_fp) = owner {
        println!(
            "  {:<20}{}",
            "Owner:",
            format!("0x{}", hex::encode(owner_fp)).dimmed()
        );
    }
    println!("  {:<20}{}", "TTL:", format_ttl(spec.sessionTtl));

    // Base image mode
    let mode_name = match spec.baseImageMode {
        0 => "any",
        1 => "blacklist",
        2 => "whitelist",
        _ => "unknown",
    };
    println!(
        "  {:<20}{} ({})",
        "Base Image Mode:", mode_name, spec.baseImageMode
    );
    if spec.baseImageIds.is_empty() {
        println!("  {:<20}{}", "Base Image IDs:", "none".dimmed());
    } else {
        for (i, id) in spec.baseImageIds.iter().enumerate() {
            let label = if i == 0 { "Base Image IDs:" } else { "" };
            println!(
                "  {:<20}{}",
                label,
                format!("0x{}", hex::encode(id)).dimmed()
            );
        }
    }
    println!();

    // PCR specs
    println!("  {}", "PCR Specs:".cyan().bold());
    if spec.workloadPcrPolicy.pcrSpecs256.is_empty()
        && spec.workloadPcrPolicy.pcrSpecs384.is_empty()
    {
        println!("    {}", "none".dimmed());
    } else {
        for pcr in &spec.workloadPcrPolicy.pcrSpecs256 {
            print_comparison256(pcr.pcrIndex, &pcr.comparison);
        }
        for pcr in &spec.workloadPcrPolicy.pcrSpecs384 {
            print_comparison384(pcr.pcrIndex, &pcr.comparison);
        }
    }
    println!();

    // Requirements
    println!("  {}", "Requirements:".cyan().bold());
    if spec.requirements.is_empty() {
        println!("    {}", "none".dimmed());
    } else {
        for req in &spec.requirements {
            let key: [u8; 32] = req.key.into();
            if let Some(attribute) =
                atakit_core::tee_attributes::VerifiedTeeAttribute::from_key(&key)
            {
                println!("    {}", attribute.name());
                for value in &req.allowedValues {
                    let raw: [u8; 32] = (*value).into();
                    let display =
                        atakit_core::tee_attributes::readable_reserved_value(attribute, &raw)
                            .unwrap_or_else(|| format!("0x{}", hex::encode(raw)));
                    println!("      {}", display.dimmed());
                }
            } else {
                println!(
                    "    Key: {}",
                    format!("0x{}", hex::encode(req.key)).dimmed()
                );
                for val in &req.allowedValues {
                    println!("      {}", format!("0x{}", hex::encode(val)).dimmed());
                }
            }
        }
    }

    Ok(())
}

fn print_comparison256(pcr_index: u8, comparison: &[u8]) {
    match decode256(comparison) {
        Ok(PcrComparison256::Static(value)) => {
            println!("    PCR{pcr_index:<4} {} (0)", "STATIC".dimmed());
            println!("      value  {}", format!("{value:#x}").green());
        }
        Ok(PcrComparison256::DynamicSubset(values)) => {
            println!("    PCR{pcr_index:<4} {} (1)", "DYNAMIC_SUBSET".dimmed());
            print_values256("landmark", &values);
        }
        Ok(PcrComparison256::DynamicSubsequence(values)) => {
            println!(
                "    PCR{pcr_index:<4} {} (2)",
                "DYNAMIC_SUBSEQUENCE".dimmed()
            );
            print_values256("landmark", &values);
        }
        Ok(PcrComparison256::DynamicIndexedEventSets(rule)) => {
            println!(
                "    PCR{pcr_index:<4} {} (3)",
                "DYNAMIC_INDEXED_EVENT_SETS".dimmed()
            );
            println!("      expected event count: {}", rule.expected_event_count);
            for checked in rule.checked_events {
                println!("      event index {}:", checked.event_index);
                print_values256("allowed", &checked.allowed_values);
            }
        }
        Ok(PcrComparison256::ExtendFromZero(value)) => {
            println!("    PCR{pcr_index:<4} {} (4)", "EXTEND_FROM_ZERO".dimmed());
            println!("      extend value  {}", format!("{value:#x}").green());
        }
        Err(error) => {
            println!("    PCR{pcr_index:<4} {}", "UNKNOWN".dimmed());
            println!("      comparison: 0x{}", hex::encode(comparison));
            println!("      decode error: {error}");
        }
    }
}

fn print_values256(label: &str, values: &[alloy_ext::core::primitives::B256]) {
    for value in values {
        println!("      {label}: {value:#x}");
    }
}

fn print_comparison384(pcr_index: u8, comparison: &[u8]) {
    match decode384(comparison) {
        Ok(PcrComparison384::Static(value)) => {
            println!("    SHA-384 PCR{pcr_index:<4} {} (0)", "STATIC".dimmed());
            println!("      value: 0x{}", hex::encode(value));
        }
        Ok(PcrComparison384::DynamicSubset(values)) => {
            println!(
                "    SHA-384 PCR{pcr_index:<4} {} (1)",
                "DYNAMIC_SUBSET".dimmed()
            );
            print_values384("landmark", &values);
        }
        Ok(PcrComparison384::DynamicSubsequence(values)) => {
            println!(
                "    SHA-384 PCR{pcr_index:<4} {} (2)",
                "DYNAMIC_SUBSEQUENCE".dimmed()
            );
            print_values384("landmark", &values);
        }
        Ok(PcrComparison384::DynamicIndexedEventSets(rule)) => {
            println!(
                "    SHA-384 PCR{pcr_index:<4} {} (3)",
                "DYNAMIC_INDEXED_EVENT_SETS".dimmed()
            );
            println!("      expected event count: {}", rule.expected_event_count);
            for checked in rule.checked_events {
                println!("      event index {}:", checked.event_index);
                print_values384("allowed", &checked.allowed_values);
            }
        }
        Ok(PcrComparison384::ExtendFromZero(value)) => {
            println!(
                "    SHA-384 PCR{pcr_index:<4} {} (4)",
                "EXTEND_FROM_ZERO".dimmed()
            );
            println!("      extend value: 0x{}", hex::encode(value));
        }
        Err(error) => {
            println!("    SHA-384 PCR{pcr_index:<4} {}", "UNKNOWN".dimmed());
            println!("      comparison: 0x{}", hex::encode(comparison));
            println!("      decode error: {error}");
        }
    }
}

fn print_values384(label: &str, values: &[[u8; 48]]) {
    for value in values {
        println!("      {label}: 0x{}", hex::encode(value));
    }
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
