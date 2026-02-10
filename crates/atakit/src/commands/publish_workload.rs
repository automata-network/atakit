//! Publish workload to the WorkloadRegistry contract.

use alloy::primitives::{Address, B256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use automata_tee_workload_measurement::types::AppRef;
use automata_tee_workload_measurement::{WorkloadMeasurement, WorkloadMeasurementConfig};
use clap::Parser;
use tracing::info;

use automata_tee_workload_measurement::stubs::WorkloadRegistry::WorkloadSpec;

use crate::Env;
use crate::types::AtakitConfig;

#[derive(Parser)]
pub struct PublishWorkload {
    /// Workload name (must match a workload in atakit.json)
    workload: String,

    /// Time-to-live in seconds (0 = no expiration)
    #[arg(long, default_value = "0")]
    ttl: u64,

    /// Ethereum RPC URL
    #[arg(long, env = "ATAKIT_RPC_URL")]
    rpc_url: String,

    /// Private key for signing (hex with or without 0x prefix)
    #[arg(long, env = "ATAKIT_PRIVATE_KEY")]
    private_key: B256,

    /// WorkloadRegistry contract address
    #[arg(long, env = "ATAKIT_SESSION_REGISTRY")]
    session_registry: Address,

    /// Signature expiration offset in seconds (default: 3600 = 1 hour)
    #[arg(long, default_value = "3600")]
    expire_offset: u64,

    /// Dry run mode - don't submit transaction
    #[arg(long)]
    dry_run: bool,
}

impl PublishWorkload {
    pub async fn run(self, _env: &Env) -> Result<()> {
        // Load atakit.json to verify workload exists
        let config = AtakitConfig::load()?;

        // Verify workload exists in config
        let workload = config
            .workloads
            .iter()
            .find(|w| w.name == self.workload)
            .with_context(|| {
                format!(
                    "Workload '{}' not found in atakit.json. Available workloads: {}",
                    self.workload,
                    config
                        .workloads
                        .iter()
                        .map(|w| w.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;

        info!(
            workload = %workload.name,
            version = %workload.version,
            image = %workload.image,
            "Publishing workload"
        );

        // Compute base image ID: keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))
        let base_image_ref = AppRef::new(&workload.image.repository, &workload.image.tag);
        let base_image_id = base_image_ref.id("CVM_BASEIMAGE_V1");

        // Build WorkloadSpec
        let spec = WorkloadSpec {
            name: workload.name.clone(),
            version: format!("v{}", workload.version),
            ttl: self.ttl,
            baseImageMode: 2, // AccessMode::WHITELIST
            baseImageIds: vec![base_image_id],
            requirements: vec![],
            pcrs: vec![],
        };

        // Print summary
        println!("Workload: {} v{}", spec.name, spec.version);
        println!("TTL: {} seconds", spec.ttl);
        println!("Base Image Mode: WHITELIST (allowed: {})", workload.image);
        println!("Base Image ID: {}", base_image_id);

        if self.dry_run {
            println!();
            println!("Dry run mode - not submitting transaction");
            return Ok(());
        }
        let wm = WorkloadMeasurement::new(WorkloadMeasurementConfig {
            rpc_url: self.rpc_url.clone(),
            session_registry_address: self.session_registry,
            relay_key: Some(self.private_key),
        })
        .await?;

        let signer =
            PrivateKeySigner::from_bytes(&self.private_key).context("Invalid private key")?;

        // Create registry instance and call register
        let workload_id = wm
            .workload_registry()
            .register_workload(&signer, spec, self.expire_offset)
            .await?;

        println!();
        println!("Workload registered successfully!");
        println!("Workload ID: 0x{}", hex::encode(workload_id));

        Ok(())
    }
}
