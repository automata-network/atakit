//! sim-agent command: Start simulated CVM agents for local development.
//!
//! Reads workload definitions from atakit.json and starts a simulated
//! CVM agent on a Unix socket for each service in the docker-compose.

use alloy::ext::{NetworkProvider, ProviderEx};
use alloy::primitives::{Address, B256};
use anyhow::{Context, Result, bail};
use automata_cvm_agent::sim::{
    ChainConfig, SimConfig, SimCvmAgent, SimServiceConfig, WorkloadRegistration,
};
use automata_tee_workload_measurement::types::AppRef;
use automata_tee_workload_measurement::workload_registry::WorkloadRegistry;
use clap::Args;

use crate::Env;

/// Start simulated CVM agents for local development.
///
/// Reads workload definitions from atakit.json, resolves the docker-compose
/// for selected workloads, and starts a simulated CVM agent on a Unix
/// socket for each service.  Automatically starts an embedded Anvil node
/// that forks from the given RPC URL.
#[derive(Args)]
pub struct SimAgent {
    /// Workload names (from atakit.json workloads[].name).
    /// If omitted, all workloads are started.
    workload: Vec<String>,

    #[arg(long, default_value_t = default_dev_version())]
    dev_version: String,

    /// RPC endpoint URL (used as Anvil fork URL)
    #[arg(long)]
    rpc_url: String,

    /// SessionRegistry contract address.
    /// If omitted, auto-detected from the registry store.
    #[arg(long)]
    session_registry: Option<Address>,

    /// Anvil listen port (default: 14345).
    #[arg(long, default_value_t = 14345)]
    anvil_port: u16,
}

fn default_dev_version() -> String {
    let date = chrono::Utc::now().format("%Y%m%d");
    format!("dev-{date}")
}

impl SimAgent {
    pub async fn run(self, env: &Env) -> Result<()> {
        // Load atakit.json
        let config = env.config()?;
        let config_dir = env.config_dir()?.to_path_buf();

        // Resolve workloads: explicit list or all
        let workloads = if self.workload.is_empty() {
            config.workloads.iter().collect::<Vec<_>>()
        } else {
            self.workload
                .iter()
                .map(|name| {
                    config.workload(Some(name)).with_context(|| {
                        let available: Vec<_> =
                            config.workloads.iter().map(|w| w.name.as_str()).collect();
                        format!(
                            "Workload '{}' not found. Available: {}",
                            name,
                            available.join(", ")
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };

        println!("RPC endpoint: {}", self.rpc_url);
        for wl in &workloads {
            let dev_workload_ref = AppRef::new(&wl.name, &self.dev_version);
            println!(
                "Workload: {} (workload_id: {})",
                dev_workload_ref,
                WorkloadRegistry::get_workload_id(&dev_workload_ref)
            );
        }

        // Collect services from all workloads by extracting .sock bind mounts
        let mut services = Vec::new();

        for workload in &workloads {
            let compose_path = config_dir.join(&workload.docker_compose);
            if !compose_path.exists() {
                bail!(
                    "Docker compose file not found: {}\n(resolved from atakit.json docker_compose: {})",
                    compose_path.display(),
                    workload.docker_compose
                );
            }

            let compose_dir = compose_path
                .parent()
                .context("compose file has no parent directory")?;

            let yaml = std::fs::read_to_string(&compose_path)
                .with_context(|| format!("Failed to read: {}", compose_path.display()))?;

            let compose = workload_compose::from_yaml_str(&yaml)
                .with_context(|| format!("Failed to parse: {}", compose_path.display()))?;

            for (svc_name, svc) in &compose.services {
                for vol in &svc.volumes {
                    if let workload_compose::WorkloadVolumeMount::Bind { host_path, .. } = vol {
                        if host_path.ends_with(".sock") {
                            let socket_path = compose_dir.join(host_path);
                            services.push(SimServiceConfig {
                                name: format!("{}/{}", workload.name, svc_name),
                                socket_path,
                            });
                        }
                    }
                }
            }
        }

        let provider = NetworkProvider::with_http(&self.rpc_url, None, None, 100).await?;
        let chain_id = provider.chain_id();

        // Resolve SessionRegistry address
        let session_registry = if let Some(addr) = self.session_registry {
            println!("SessionRegistry: {addr} (manual)");
            Some(addr)
        } else {
            let store = env.registry_store();
            store.ensure_data(None).await?;

            match store.resolve_contract(None, &chain_id.to_string(), "SessionRegistryMock")? {
                Some(addr) => {
                    println!("SessionRegistry: {addr} (chain {chain_id})");
                    Some(addr)
                }
                None => {
                    println!("No SessionRegistry found for chain {chain_id}");
                    None
                }
            }
        };

        // Build per-workload registration entries (each gets its own random owner key)
        let wl_registrations: Vec<WorkloadRegistration> = workloads
            .iter()
            .map(|wl| {
                let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
                let owner_private_key = B256::from_slice(&sk.to_bytes());
                WorkloadRegistration {
                    workload_ref: AppRef::new(&wl.name, &wl.version),
                    temporary_workload_ref: AppRef::new(&wl.name, self.dev_version.clone()),
                    base_image_ref: AppRef::new(&wl.image.repository, &wl.image.tag),
                    owner_private_key,
                }
            })
            .collect();

        let chain = session_registry.map(|addr| ChainConfig {
            rpc_url: self.rpc_url,
            session_registry_address: addr,
            chain_id: Some(chain_id),
            anvil_port: Some(self.anvil_port),
            anvil_host: None, // use default 0.0.0.0
            expire_offset: None,
            workloads: wl_registrations,
        });

        let sim_config = SimConfig {
            services,
            chain,
            ..Default::default()
        };

        SimCvmAgent::new(sim_config).run().await
    }
}
