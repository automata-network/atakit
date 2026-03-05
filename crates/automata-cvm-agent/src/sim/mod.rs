//! Simulated CVM agent for local development and testing.
//!
//! Provides mock `/sign-message` and `/rotate-key` endpoints over Unix
//! sockets, mirroring the real CVM agent API with real secp256k1 cryptography.
//!
//! When [`ChainConfig`] with registration fields is provided, the agent will also perform
//! on-chain session registration and periodic rotation in the background
//! using a [`MockDeviceProvider`](crate::mock::mock_device::MockDeviceProvider).

use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::B256;
use alloy::signers::local::PrivateKeySigner;
use automata_tee_workload_measurement::stubs::WorkloadRegistry::{PcrSpec, WorkloadSpec};

use crate::device::PlatformInfo;
pub use crate::mock;
use crate::mock::builder::MockDataBuilder;
use crate::mock::mock_device::MockDeviceProvider;
use crate::registration::{RegistrationConfig, RegistrationManager};
mod server;
mod state;

pub mod config;
use automata_tee_workload_measurement::base_image_registry::{
    BaseImageHierarchy, BaseImageRegistry,
};
use automata_tee_workload_measurement::{WorkloadMeasurement, WorkloadMeasurementConfig};
pub use config::*;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use state::ServiceState;

/// Simulated CVM agent that serves multiple Unix sockets.
pub struct SimCvmAgent {
    config: SimConfig,
}

impl SimCvmAgent {
    pub fn new(config: SimConfig) -> Self {
        Self { config }
    }

    /// Start all service sockets and block until Ctrl+C.
    pub async fn run(&self) -> Result<()> {
        self.run_with_shutdown(tokio::signal::ctrl_c()).await
    }

    /// Start all service sockets and block until `shutdown` resolves.
    pub async fn run_with_shutdown<F>(&self, shutdown: F) -> Result<()>
    where
        F: std::future::Future<Output = Result<(), std::io::Error>>,
    {
        let cancel = CancellationToken::new();

        let chain = self.config.chain.as_ref();

        // Optionally spawn auto-registration for each workload
        let mut _registration_handles = Vec::new();
        if let Some(chain) = chain {
            // Start embedded Anvil node if fork_url is configured
            let anvil = Self::start_anvil(chain)?;
            if chain.can_register() {
                match Self::spawn_registrations(anvil, chain, cancel.clone()).await {
                    Ok(handles) => _registration_handles = handles,
                    Err(e) => {
                        tracing::error!(error = ?e, "Failed to start auto-registration (continuing without it)");
                    }
                }
            }
        }

        self.serve_sockets(shutdown, cancel).await
    }

    /// Start an embedded Anvil node forking from `fork_url`.
    ///
    /// Returns the `AnvilInstance` (must be kept alive) and a patched
    /// `ChainConfig` with `rpc_url` and `relay_key` populated from Anvil.
    fn start_anvil(chain: &ChainConfig) -> Result<AnvilInstance> {
        let host = chain.anvil_host.as_deref().unwrap_or("0.0.0.0");
        let port = chain.anvil_port.unwrap_or(14345);

        let instance = Anvil::new()
            .fork(&chain.rpc_url)
            .arg("--hardfork")
            .arg("osaka")
            .arg("--host")
            .arg(host)
            .port(port)
            .try_spawn()
            .context("Failed to spawn Anvil (is it installed? try: `curl -L https://foundry.paradigm.xyz | bash && foundryup`)")?;

        // let relay_key = B256::from_slice(&instance.keys()[0].to_bytes());
        let relay_address = instance.addresses()[0];
        let endpoint = instance.endpoint();

        println!("Anvil node started:");
        println!("  Endpoint:      {endpoint}");
        println!("  Fork URL:      {}", chain.rpc_url);
        println!("  Relay address: {relay_address}");

        Ok(instance)
    }

    /// Group services by socket path, spawn a server per socket, and wait for shutdown.
    async fn serve_sockets<F>(&self, shutdown: F, cancel: CancellationToken) -> Result<()>
    where
        F: std::future::Future<Output = Result<(), std::io::Error>>,
    {
        let by_path = self.group_services_by_socket();

        if by_path.is_empty() {
            println!("No services require a sim agent socket.");
            println!("Press Ctrl+C to stop.");
            let _ = shutdown.await;
            cancel.cancel();
            return Ok(());
        }

        println!("Sockets:");
        for (path, names) in &by_path {
            println!("  {} ({})", path.display(), names.join(", "));
        }
        println!();
        println!("Press Ctrl+C to stop.");

        let handles = self.spawn_socket_servers(&by_path).await;

        // Block until shutdown signal
        let _ = shutdown.await;
        println!("\nShutting down...");
        cancel.cancel();

        for h in handles {
            h.abort();
        }
        for path in by_path.keys() {
            let _ = std::fs::remove_file(path);
        }

        Ok(())
    }

    /// Group services by their Unix socket path.
    fn group_services_by_socket(&self) -> BTreeMap<PathBuf, Vec<String>> {
        let mut by_path: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
        for svc in &self.config.services {
            by_path
                .entry(svc.socket_path.clone())
                .or_default()
                .push(svc.name.clone());
        }
        by_path
    }

    /// Spawn a server task per unique socket path.
    async fn spawn_socket_servers(
        &self,
        by_path: &BTreeMap<PathBuf, Vec<String>>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();
        for (path, names) in by_path {
            let label = names.join(", ");
            let path = path.clone();

            let state = Arc::new(ServiceState::new(
                self.config.workload_id,
                self.config.base_image_id,
            ));

            let session_public = state.session_public().await;
            let owner_public = state.owner_public();
            tracing::info!(
                services = %label,
                socket = %path.display(),
                session_fingerprint = %session_public.fingerprint(),
                owner_fingerprint = %owner_public.fingerprint(),
                "Starting sim agent"
            );

            handles.push(tokio::spawn(async move {
                if let Err(e) = server::serve_socket(&path, state).await {
                    tracing::error!(services = %label, error = ?e, "Sim agent failed");
                }
            }));
        }
        handles
    }

    /// Spawn a background registration/rotation loop per workload.
    ///
    /// For each workload:
    /// 1. Fetches the base image hierarchy from on-chain to get PCR specs
    /// 2. Applies platform invariant PCRs + variant override PCRs
    /// 3. Measures the workload package and extends PCR 23
    async fn spawn_registrations(
        anvil: AnvilInstance,
        chain: &ChainConfig,
        cancel: CancellationToken,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>> {
        tracing::info!(
            workloads = chain.workloads.len(),
            "Initialising on-chain auto-registration..."
        );

        let measurement = Arc::new(
            WorkloadMeasurement::new(WorkloadMeasurementConfig {
                rpc_url: anvil.endpoint(),
                session_registry_address: chain.session_registry_address,
                relay_key: Some(B256::from_slice(&anvil.keys()[0].to_bytes())),
            })
            .await?,
        );
        let base_image_registry = measurement.base_image_registry();

        let anvil = Arc::new(anvil);

        let mut handles = Vec::new();
        for entry in &chain.workloads {
            let owner_private_key = entry.owner_private_key;
            let workload_owner = PrivateKeySigner::from_bytes(&owner_private_key)?;

            let mock_data = build_mock_data(base_image_registry, entry).await?;
            let base_image_id = BaseImageRegistry::get_image_id(&entry.base_image_ref);

            // Build WorkloadSpec
            let spec = WorkloadSpec {
                name: entry.temporary_workload_ref.name.clone(),
                version: entry.temporary_workload_ref.version.clone(),
                ttl: 0,
                baseImageMode: 2, // AccessMode::WHITELIST
                baseImageIds: vec![base_image_id],
                requirements: vec![],
                pcrs: vec![PcrSpec {
                    pcrIndex: 23,
                    verifyType: 0,
                    matchData: vec![B256::ZERO],
                }],
            };
            let _workload_id = measurement
                .workload_registry()
                .register_workload(&workload_owner, spec, chain.expire_offset.unwrap_or(3600))
                .await
                .with_context(|| format!("register temporary workload"))?;

            let config = RegistrationConfig {
                workload_ref: entry.temporary_workload_ref.clone(),
                base_image_ref: entry.base_image_ref.clone(),
                owner_private_key,
                session_registry_address: chain.session_registry_address,
                expire_offset: chain.expire_offset.unwrap_or(3600),
            };

            let device = MockDeviceProvider::new(mock_data);
            let mut manager = RegistrationManager::new(device, measurement.clone(), config)?;
            let child_cancel = cancel.child_token();
            let label = entry.temporary_workload_ref.clone();

            handles.push(tokio::spawn({
                let anvil = anvil.clone();
                async move {
                    let _anvil = anvil;
                if let Err(e) = manager.run(child_cancel).await {
                    tracing::error!(workload = %label, error = %e, "Registration loop exited with error");
                }
            }}));

            tracing::info!(
                workload = %entry.temporary_workload_ref,
                "Registration background task spawned"
            );
        }

        Ok(handles)
    }
}

// ---------------------------------------------------------------------------
// Mock data construction helpers
// ---------------------------------------------------------------------------

/// Build a [`MockDataBuilder`] for a single workload registration.
///
/// Fetches the on-chain base image hierarchy to populate platform info and
/// PCR values, then extends PCR 23 with workload measurement events.
async fn build_mock_data(
    registry: &BaseImageRegistry,
    entry: &WorkloadRegistration,
) -> Result<MockDataBuilder> {
    let mut mock_data = MockDataBuilder::new();

    // 1. Fetch base image hierarchy and apply platform PCRs
    let image_id = BaseImageRegistry::get_image_id(&entry.base_image_ref);
    let hierarchy = registry.get_hierarchy(image_id).await.with_context(|| {
        format!(
            "Failed to fetch base image hierarchy for {}",
            entry.base_image_ref
        )
    })?;

    apply_hierarchy(&mut mock_data, &hierarchy, entry)?;

    // 2. Measure workload package and extend PCR 23
    apply_workload_measurement(&mut mock_data, entry)?;

    // 3. set uuid binding
    let uuid = [0_u8; 16];
    mock_data = mock_data.reset_pcr(15).extend_pcr_raw(15, &uuid);

    tracing::info!(
        workload = %entry.temporary_workload_ref,
        pcr23 = %mock_data.pcr_bank.get(23),
        pcr_indices = ?mock_data.pcr_bank.indices(),
        "PCR values configured"
    );

    Ok(mock_data)
}

/// Apply on-chain base image hierarchy (platform info + PCR specs) to the builder.
fn apply_hierarchy(
    mock_data: &mut MockDataBuilder,
    hierarchy: &BaseImageHierarchy,
    entry: &WorkloadRegistration,
) -> Result<()> {
    let first_profile = hierarchy.profiles.first().with_context(|| {
        format!(
            "No platform profiles registered for base image {}",
            entry.base_image_ref
        )
    })?;

    // Parse platform info from profile/variant names
    let (cloud_type, tee_type) = parse_profile_name(&first_profile.profile.name)?;
    let machine_type = first_profile
        .variants
        .first()
        .map(|(_, v)| v.name.clone())
        .unwrap_or_default();

    mock_data.platform_info = PlatformInfo {
        cloud_type: cloud_type.clone(),
        tee_type: tee_type.clone(),
        machine_type: machine_type.clone(),
    };

    tracing::info!(
        workload = %entry.temporary_workload_ref,
        image = %entry.base_image_ref,
        profile = %first_profile.profile.name,
        machine_type = %machine_type,
        "Using on-chain base image profile"
    );

    // Apply invariant PCRs, then variant overrides
    apply_pcr_specs(mock_data, &first_profile.profile.invariants);
    if let Some((_, variant)) = first_profile.variants.first() {
        apply_pcr_specs(mock_data, &variant.overridePcrs);
    }

    Ok(())
}

/// Measure the workload package and extend PCR 23 with the events.
fn apply_workload_measurement(
    mock_data: &mut MockDataBuilder,
    _entry: &WorkloadRegistration,
) -> Result<()> {
    mock_data.pcr_bank.reset(23);
    Ok(())
}

/// Parse a profile name like "gcp-tdx" into (cloud_type, tee_type).
fn parse_profile_name(name: &str) -> Result<(String, String)> {
    let (cloud, tee) = name
        .split_once('-')
        .with_context(|| format!("Invalid profile name '{name}': expected format 'cloud-tee'"))?;
    Ok((cloud.to_string(), tee.to_string()))
}

/// Apply PcrSpec values to a MockDataBuilder.
///
/// For STATIC specs (verifyType = 0), sets the PCR slot to `matchData[0]`.
fn apply_pcr_specs(
    builder: &mut MockDataBuilder,
    specs: &[automata_tee_workload_measurement::stubs::BaseImageRegistry::PcrSpec],
) {
    for spec in specs {
        let idx = spec.pcrIndex as usize;
        // verifyType 0 = STATIC: exact match on matchData[0]
        if spec.verifyType == 0 && !spec.matchData.is_empty() {
            builder.pcr_bank.set_slot(idx, spec.matchData[0]);
        }
    }
}
