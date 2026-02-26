//! Publish base image to the BaseImageRegistry contract.

use std::collections::HashMap;

use alloy::ext::{NetworkProvider, ProviderEx};
use alloy::primitives::{Address, B256, FixedBytes};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use automata_tee_workload_measurement::types::AppRef;
use automata_tee_workload_measurement::{WorkloadMeasurement, WorkloadMeasurementConfig};
use clap::Parser;
use tracing::info;
use automata_linux_release::ImageRef;

use automata_tee_workload_measurement::base_image_registry::BaseImageRegistry;
use automata_tee_workload_measurement::stubs::BaseImageRegistry::{
    Attribute, BaseImageSpec, MeasurementVariant, PcrSpec as ContractPcrSpec, PlatformProfile,
};

use super::types::{PcrSpec, PlatformProfileResponse};
use crate::Env;

#[derive(Parser)]
pub struct Publish {
    /// Base image name (e.g., "automata-linux")
    #[arg(long)]
    image: ImageRef,

    /// Base image URI (e.g., "ipfs://...")
    #[arg(long)]
    uri: String,

    /// Ethereum RPC URL
    #[arg(long, env = "ATAKIT_RPC_URL")]
    rpc_url: String,

    /// Private key for signing (hex with or without 0x prefix)
    #[arg(long, env = "ATAKIT_PRIVATE_KEY")]
    private_key: B256,

    /// SessionRegistry contract address.
    /// If omitted, auto-detected from the registry store.
    #[arg(long, env = "ATAKIT_SESSION_REGISTRY")]
    session_registry: Option<Address>,

    /// BaseImageRegistry contract address
    #[arg(long)]
    base_image_registry: Option<Address>,

    /// Signature expiration offset in seconds (default: 3600 = 1 hour)
    #[arg(long, default_value = "3600")]
    expire_offset: u64,

    /// Dry run mode - don't submit transaction
    #[arg(long)]
    dry_run: bool,
}

impl Publish {
    pub async fn run(self, env: &Env) -> Result<()> {
        // Load all profiles from dev profiles directory
        let profiles_dir = env.image_profiles_dir(&self.image);
        if !profiles_dir.exists() {
            anyhow::bail!(
                "No dev profiles found. Run 'atakit image fetch-dev-profile' first.\n\
                 Expected directory: {}",
                profiles_dir.display()
            );
        }

        let mut profiles = load_profiles(&profiles_dir)?;
        if profiles.is_empty() {
            anyhow::bail!("No profile files found in {}", profiles_dir.display());
        }

        // filter out workload pcr (pcr23)
        for profile in &mut profiles {
            profile.pcrs.retain(|p| p.pcr_index != 23);
        }

        info!(count = profiles.len(), "Loaded platform profiles");

        // Group profiles by (cloud_type, tee_type) -> Vec<PlatformProfileResponse>
        let grouped = group_profiles(profiles);

        // Build contract data structures
        let (platform_profiles, measurement_variants) = build_contract_data(&grouped)?;

        info!(platforms = platform_profiles.len(), "Built contract data");

        // Build base image spec
        let spec = BaseImageSpec {
            name: self.image.repository.clone(),
            version: self.image.tag.clone(),
            uri: self.uri.clone(),
        };

        let app_ref = AppRef::new(&self.image.repository, &self.image.tag);

        // Print summary
        println!("Base Image: {}", self.image);
        println!("URI: {}", self.uri);
        println!("image_id: {}", BaseImageRegistry::get_image_id(&app_ref));
        println!();
        println!("Platform Profiles:");
        for (i, profile) in platform_profiles.iter().enumerate() {
            println!("  {}. {}", i + 1, profile.name);
            for variant in &measurement_variants[i] {
                println!(
                    "     - {} ({} PCRs)",
                    variant.name,
                    variant.overridePcrs.len()
                );
            }
        }

        if self.dry_run {
            println!();
            println!("Dry run mode - not submitting transaction");
            return Ok(());
        }

        let signer = PrivateKeySigner::from_bytes(&self.private_key)?;

        // Resolve SessionRegistry address
        let session_registry = if let Some(addr) = self.session_registry {
            addr
        } else {
            let provider = NetworkProvider::with_http(&self.rpc_url, None, None, 100).await?;
            let chain_id = provider.chain_id();

            let store = env.registry_store();
            store.ensure_data(None).await?;

            let addr = store
                .resolve_contract(None, &chain_id.to_string(), "SessionRegistry")?
                .context(format!("No SessionRegistry found for chain {chain_id}"))?;
            println!(
                "SessionRegistry: {addr} (chain {chain_id})",
            );
            addr
        };

        let wm = WorkloadMeasurement::new(WorkloadMeasurementConfig {
            rpc_url: self.rpc_url.clone(),
            session_registry_address: session_registry,
            relay_key: Some(self.private_key),
        })
        .await?;

        let mut base_image_registry = wm.base_image_registry().clone();
        if let Some(addr) = self.base_image_registry {
            info!(address = %addr, "Using provided BaseImageRegistry address");
            base_image_registry = BaseImageRegistry::new(addr, wm.provider().clone());
        }

        // Create registry instance and call register
        let result = base_image_registry
            .register_base_image(
                &signer,
                spec,
                platform_profiles,
                measurement_variants,
                self.expire_offset,
            )
            .await?;

        println!("Base image registered: {:?}", result);

        Ok(())
    }
}

/// Load all profile JSON files from the directory.
fn load_profiles(dir: &std::path::Path) -> Result<Vec<PlatformProfileResponse>> {
    let mut profiles = Vec::new();

    for entry in std::fs::read_dir(dir).context("Failed to read profiles directory")? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "json") {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;

            let profile: PlatformProfileResponse = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse {}", path.display()))?;

            info!(
                file = %path.display(),
                cloud = %profile.cloud_type,
                tee = %profile.tee_type,
                machine = %profile.machine_type,
                "Loaded profile"
            );

            profiles.push(profile);
        }
    }

    Ok(profiles)
}

/// Group profiles by (cloud_type, tee_type).
fn group_profiles(
    profiles: Vec<PlatformProfileResponse>,
) -> HashMap<String, Vec<PlatformProfileResponse>> {
    let mut grouped: HashMap<String, Vec<PlatformProfileResponse>> = HashMap::new();

    for profile in profiles {
        let key = profile.profile_name();
        grouped.entry(key).or_default().push(profile);
    }

    grouped
}

/// Build contract data structures from grouped profiles.
fn build_contract_data(
    grouped: &HashMap<String, Vec<PlatformProfileResponse>>,
) -> Result<(Vec<PlatformProfile>, Vec<Vec<MeasurementVariant>>)> {
    let mut platform_profiles = Vec::new();
    let mut all_variants = Vec::new();

    for (profile_name, profiles) in grouped {
        // Get cloud and tee from the first profile (all profiles in group have same values)
        let first = profiles.first().expect("group cannot be empty");

        // Build platform profile with cloud/tee attributes, no invariants
        let platform_profile = PlatformProfile {
            name: profile_name.clone(),
            invariants: vec![], // All PCRs go to MeasurementVariant
            attributes: vec![
                Attribute {
                    key: alloy::primitives::keccak256(b"cloud").into(),
                    value: alloy::primitives::keccak256(first.cloud_type.as_bytes()).into(),
                },
                Attribute {
                    key: alloy::primitives::keccak256(b"tee").into(),
                    value: alloy::primitives::keccak256(first.tee_type.as_bytes()).into(),
                },
            ],
        };

        // Build measurement variants with all PCRs
        let mut variants = Vec::new();
        for profile in profiles {
            let variant = MeasurementVariant {
                name: profile.machine_type.clone(),
                overridePcrs: profile.pcrs.iter().map(|p| convert_pcr_spec(p)).collect(),
                attributes: vec![],
            };

            variants.push(variant);
        }

        platform_profiles.push(platform_profile);
        all_variants.push(variants);
    }

    Ok((platform_profiles, all_variants))
}

/// Convert our PcrSpec to the contract's PcrSpec.
fn convert_pcr_spec(spec: &PcrSpec) -> ContractPcrSpec {
    ContractPcrSpec {
        pcrIndex: spec.pcr_index,
        verifyType: spec.verify_type,
        matchData: spec
            .match_data
            .iter()
            .map(|b| FixedBytes::from(*b))
            .collect(),
    }
}
