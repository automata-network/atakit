use alloy::ext::{NetworkProvider, ProviderEx};
use alloy::primitives::Address;
use anyhow::{Context, Result};
use automata_tee_workload_measurement::base_image_registry::{
    BaseImageHierarchy, BaseImageRegistry, ProfileWithVariants,
};
use automata_tee_workload_measurement::session_registry::SessionRegistry;
use automata_tee_workload_measurement::types::AppRef;
use automata_tee_workload_measurement::workload_registry::WorkloadRegistry;
use clap::{Args, Subcommand};

use crate::Env;

/// Query on-chain registry data.
#[derive(Subcommand)]
pub enum Query {
    /// Query base image information
    Image(QueryImage),
    /// Query workload spec
    Workload(QueryWorkload),
}

impl Query {
    pub async fn run(self, env: &Env) -> Result<()> {
        match self {
            Query::Image(cmd) => cmd.run(env).await,
            Query::Workload(cmd) => cmd.run(env).await,
        }
    }
}

/// Query base image info from the BaseImageRegistry contract.
#[derive(Args)]
pub struct QueryImage {
    /// Base image reference (name:version, e.g. "automata-linux:v0.1.0")
    image: String,

    /// RPC endpoint URL
    #[arg(long, env = "ATAKIT_RPC_URL")]
    rpc_url: String,

    /// SessionRegistry contract address.
    /// If omitted, auto-detected from the registry store.
    #[arg(long)]
    session_registry: Option<Address>,
}

impl QueryImage {
    pub async fn run(self, env: &Env) -> Result<()> {
        let image_ref = parse_app_ref(&self.image)?;

        // Resolve SessionRegistry address
        let provider = NetworkProvider::with_http(&self.rpc_url, None, None, 100).await?;
        let chain_id = provider.chain_id();

        let session_registry_addr = match self.session_registry {
            Some(addr) => addr,
            None => {
                let store = env.registry_store();
                store.ensure_data(None).await?;
                store
                    .resolve_contract(None, &chain_id.to_string(), "SessionRegistryMock")?
                    .context(format!(
                        "No SessionRegistry found for chain {chain_id}. Use --session-registry to specify manually."
                    ))?
            }
        };

        let session_registry = SessionRegistry::new(session_registry_addr, provider);
        let base_image_registry = session_registry.base_image_registry().await?;

        let image_id = BaseImageRegistry::get_image_id(&image_ref);

        println!("Image:    {image_ref}");
        println!("Image ID: {image_id}");
        println!();

        let hierarchy = base_image_registry
            .get_hierarchy(image_id)
            .await
            .context("Failed to query base image hierarchy")?;

        print_hierarchy(&hierarchy);

        Ok(())
    }
}

/// Query workload spec from the WorkloadRegistry contract.
#[derive(Args)]
pub struct QueryWorkload {
    /// Workload reference (name:version, e.g. "guardian:v0.1.0")
    workload: String,

    /// RPC endpoint URL
    #[arg(long, env = "ATAKIT_RPC_URL")]
    rpc_url: String,

    /// SessionRegistry contract address.
    /// If omitted, auto-detected from the registry store.
    #[arg(long)]
    session_registry: Option<Address>,
}

impl QueryWorkload {
    pub async fn run(self, env: &Env) -> Result<()> {
        let workload_ref = parse_app_ref(&self.workload)?;

        let provider = NetworkProvider::with_http(&self.rpc_url, None, None, 100).await?;
        let chain_id = provider.chain_id();

        let session_registry_addr = match self.session_registry {
            Some(addr) => addr,
            None => {
                let store = env.registry_store();
                store.ensure_data(None).await?;
                store
                    .resolve_contract(None, &chain_id.to_string(), "SessionRegistryMock")?
                    .context(format!(
                        "No SessionRegistry found for chain {chain_id}. Use --session-registry to specify manually."
                    ))?
            }
        };

        let session_registry = SessionRegistry::new(session_registry_addr, provider);
        let workload_registry = session_registry.workload_registry().await?;

        let workload_id = WorkloadRegistry::get_workload_id(&workload_ref);
        let spec = workload_registry.get_workload_spec(workload_id).await?;

        println!("Workload:    {workload_ref}");
        println!("Workload ID: {workload_id}");
        dbg!(&spec);

        Ok(())
    }
}

fn parse_app_ref(s: &str) -> Result<AppRef> {
    let (name, version) = s
        .split_once(':')
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid image reference '{}'. Expected format: name:version",
                s
            )
        })?;
    Ok(AppRef::new(name, version))
}

fn print_hierarchy(h: &BaseImageHierarchy) {
    println!("=== Base Image Spec ===");
    println!("  Name:    {}", h.spec.name);
    println!("  Version: {}", h.spec.version);
    println!("  URI:     {}", h.spec.uri);

    if h.profiles.is_empty() {
        println!();
        println!("No platform profiles registered.");
        return;
    }

    for profile in &h.profiles {
        println!();
        print_profile(profile);
    }
}

fn print_profile(p: &ProfileWithVariants) {
    println!("=== Platform Profile: {} ===", p.profile.name);
    println!("  Profile ID: {}", p.profile_id);

    if !p.profile.invariants.is_empty() {
        println!("  Invariant PCRs:");
        for pcr in &p.profile.invariants {
            let values: Vec<_> = pcr.matchData.iter().map(|v| format!("{v}")).collect();
            println!("    PCR[{}]: {}", pcr.pcrIndex, values.join(", "));
        }
    }
    if !p.profile.attributes.is_empty() {
        println!("  Attributes:");
        for attr in &p.profile.attributes {
            println!("    {}: {}", attr.key, attr.value);
        }
    }

    if p.variants.is_empty() {
        println!("  (no measurement variants)");
    }
    for (variant_id, variant) in &p.variants {
        println!();
        println!("  --- Variant: {} ---", variant.name);
        println!("      Variant ID: {variant_id}");
        if !variant.overridePcrs.is_empty() {
            println!("      Override PCRs:");
            for pcr in &variant.overridePcrs {
                let values: Vec<_> = pcr.matchData.iter().map(|v| format!("{v}")).collect();
                println!("        PCR[{}]: {}", pcr.pcrIndex, values.join(", "));
            }
        }
        if !variant.attributes.is_empty() {
            println!("      Attributes:");
            for attr in &variant.attributes {
                println!("        {}: {}", attr.key, attr.value);
            }
        }
    }
}
