pub mod config;
mod init;
mod runner;

use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, anyhow};
use automata_cvm_agent::init_client::DEFAULT_EXPIRE_OFFSET;
use automata_linux_release::{ImageRef, ImageStore};
use clap::Args;
use config::PortDef;
use automata_cvm_agent::init_client::{AdditionalFile, AgentEnv};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::env::Env;
use crate::instances;

/// Deploy a CVM instance to a cloud provider or local QEMU.
///
/// TARGET can be:
///   - A path to a deployment.json file
///   - A deployment name defined in atakit.json
#[derive(Args)]
pub struct Deploy {
    /// Path to deployment.json, or deployment name from atakit.json
    pub target: String,

    /// Platform to deploy to (gcp, azure).
    /// Required when the atakit.json deployment has multiple platforms.
    #[arg(long)]
    pub platform: Option<String>,

    /// Override automata-linux disk image version (e.g., "automata-linux:v0.5.0")
    #[arg(long)]
    pub image: Option<ImageRef>,

    /// Path to workload package (tar.gz) for initialization.
    /// Overrides deployment.json workload_path if provided.
    #[arg(long)]
    pub workload_path: Option<PathBuf>,

    /// Skip confirmation prompts
    #[arg(long)]
    pub quiet: bool,

    /// Use local QEMU instead of cloud provider
    #[arg(long)]
    pub qemu: bool,

    /// Force re-upload disk image even if it already exists.
    /// Deletes the existing image before uploading.
    #[arg(long)]
    pub force_upload_image: bool,

    // ── Agent Environment Configuration ──────────────────────────────
    /// Directory containing additional data files referenced in deployment config.
    /// Defaults to the directory containing the deployment.json file.
    #[arg(long)]
    pub additional_data_dir: Option<PathBuf>,

    /// RPC URL for blockchain connection.
    /// Overrides config value if provided.
    #[arg(long, env = "ATAKIT_RPC_URL")]
    pub rpc_url: Option<String>,

    /// Session registry contract address.
    /// Overrides config value if provided.
    #[arg(long, env = "ATAKIT_SESSION_REGISTRY")]
    pub session_registry: Option<Address>,

    /// Relay private key for session operations (hex encoded).
    /// Overrides config value if provided.
    #[arg(long, env = "ATAKIT_RELAY_PRIVATE_KEY")]
    pub relay_private_key: Option<B256>,

    /// Owner private key for session registration (hex encoded).
    /// Overrides config value if provided.
    #[arg(long, env = "ATAKIT_OWNER_PRIVATE_KEY")]
    pub owner_private_key: B256,

    /// Session expiration offset in seconds (default: 3600).
    /// Overrides config value if provided.
    #[arg(long)]
    pub expire_offset: Option<u64>,
}

impl Deploy {
    pub async fn run(mut self, ctx: &Env) -> Result<()> {
        // Validate: rpc_url, session_registry, and relay_private_key must be provided together or not at all
        let blockchain_opts = [
            self.rpc_url.is_some(),
            self.session_registry.is_some(),
            self.relay_private_key.is_some(),
        ];
        let provided_count = blockchain_opts.iter().filter(|&&b| b).count();
        if provided_count > 0 && provided_count < blockchain_opts.len() {
            anyhow::bail!(
                "--rpc-url, --session-registry, and --relay-private-key must all be provided together or not at all"
            );
        }

        // Derive operator address for VM metadata
        let operator_address = derive_operator_address(self.owner_private_key)?;
        info!(address = %operator_address, "Derived operator address");

        let (mut deploy_config, paths, config_dir) = self.resolve_config(ctx).await?;

        // CLI --qemu overrides the provider to use local QEMU.
        // QEMU mode is always quiet (no confirmation prompts needed for local dev).
        if self.qemu {
            deploy_config.provider = config::ProviderKind::Qemu;
            self.quiet = true;
        }

        let workload_path = self.resolve_workload_path(ctx, &deploy_config, &config_dir)?;
        if !workload_path.exists() {
            anyhow::bail!(
                "Workload package not found: {}\nRun 'atakit build-workload' first, or specify --workload",
                workload_path.display()
            );
        }
        let is_qemu = matches!(deploy_config.provider, config::ProviderKind::Qemu);

        // Build agent environment from config + CLI overrides (optional)
        let mut agent_env = match self.build_agent_env(&deploy_config) {
            Ok(agent_env) => Some(agent_env),
            Err(e) => {
                warn!("Failed to build agent environment: {e}");
                None
            }
        };

        if is_qemu {
            // If agent_env has a localhost RPC URL, expose that port for QEMU
            if let Some(ref mut agent_env) = agent_env {
                if let Some(port) = parse_localhost_port(&agent_env.rpc_url) {
                    deploy_config.ports.push(PortDef::tcp(port));
                    let rpc_rewrite = agent_env
                        .rpc_url
                        .replace("localhost", "10.0.2.2")
                        .replace("127.0.0.1", "10.0.2.2");
                    agent_env.rpc_url = rpc_rewrite;
                }
            }
        }

        // Load additional files
        let additional_files = self
            .load_additional_files(&deploy_config, &config_dir)
            .await?;

        let cancel = CancellationToken::new();

        // For QEMU: start init task before QEMU (runs in parallel).
        // The init task will retry connecting to port 8000 while QEMU boots.
        let init_handle = if is_qemu {
            let token = cancel.clone();
            let path = workload_path.clone();
            let agent_env_clone = agent_env.clone();
            let additional_files_clone = additional_files.clone();
            Some(tokio::spawn(async move {
                println!("monitoring VM for init (this may take a minute)...");
                init::init_workload(
                    "127.0.0.1",
                    &path,
                    agent_env_clone,
                    None, // qemu_platform_response
                    additional_files_clone,
                    Some(self.owner_private_key),
                    token,
                )
                .await
            }))
        } else {
            None
        };

        // Deploy (QEMU blocks here while user interacts)
        let result = runner::deploy(
            &deploy_config,
            &paths,
            operator_address,
            self.force_upload_image,
            ctx,
            self.quiet,
        )
        .await;

        match result {
            Err(e) => {
                // VM creation failed → cancel init task
                cancel.cancel();
                if let Some(h) = init_handle {
                    let _ = h.await;
                }
                return Err(e);
            }
            Ok(instance) => {
                if is_qemu {
                    // QEMU exited → cancel init (VM is gone)
                    cancel.cancel();
                    if let Some(h) = init_handle {
                        // Don't propagate init errors when QEMU exits normally
                        // (user may have quit before init completed)
                        let _ = h.await;
                    }
                } else {
                    // Cloud VM → run init and wait for completion
                    if let Some(ip) = &instance.public_ip {
                        init::init_workload(
                            ip,
                            &workload_path,
                            agent_env,
                            None, // qemu_platform_response
                            additional_files,
                            Some(self.owner_private_key),
                            cancel,
                        )
                        .await?;
                    } else {
                        anyhow::bail!("Cannot initialize workload: no public IP available");
                    }

                    // Save instance record for cloud deployments
                    let platform = match deploy_config.provider {
                        config::ProviderKind::Gcp => "gcp",
                        config::ProviderKind::Azure => "azure",
                        config::ProviderKind::Qemu => "qemu",
                    };
                    let record = instances::create_record(
                        &instance.name,
                        platform,
                        instance.public_ip.clone(),
                        deploy_config.gcp.as_ref().and_then(|g| g.zone.clone()),
                        deploy_config
                            .gcp
                            .as_ref()
                            .and_then(|g| g.project_id.clone()),
                        deploy_config
                            .azure
                            .as_ref()
                            .and_then(|a| a.resource_group.clone()),
                        paths.image_ref.clone(),
                    );
                    let store = ctx.instance_store();
                    match store.save(&record) {
                        Ok(()) => {
                            info!(
                                name = %instance.name,
                                platform = %platform,
                                "Instance record saved"
                            );
                        }
                        Err(e) => {
                            info!(error = %e, "Failed to save instance record");
                        }
                    }
                }

                println!();
                println!("  Instance: {}", instance.name);
                println!(
                    "  Platform: {}",
                    match deploy_config.provider {
                        config::ProviderKind::Gcp => "gcp",
                        config::ProviderKind::Azure => "azure",
                        config::ProviderKind::Qemu => "qemu",
                    }
                );
                if let Some(ip) = &instance.public_ip {
                    println!("  Public IP: {ip}");
                }
                if let Some(v) = &paths.image_ref {
                    println!("  Image: {v}");
                }
            }
        }

        Ok(())
    }

    /// Build AgentEnv from deployment config and CLI overrides.
    /// CLI arguments take precedence over config values.
    /// Returns None if required fields are missing from both CLI and config.
    fn build_agent_env(&self, deploy_config: &config::DeploymentConfig) -> Result<AgentEnv> {
        let config_env = deploy_config.agent_env.as_ref();

        // CLI takes precedence over config for all fields
        let relay_private_key = self
            .relay_private_key
            .or(config_env.map(|c| c.relay_private_key))
            .ok_or_else(|| anyhow!("relay_private_key not provided"))?;

        let rpc_url = self
            .rpc_url
            .clone()
            .or_else(|| config_env.map(|c| c.rpc_url.clone()))
            .ok_or_else(|| anyhow!("rpc_url not provided"))?;

        let session_registry = self
            .session_registry
            .or(config_env.map(|c| c.session_registry))
            .ok_or_else(|| anyhow!("session_registry not provided"))?;

        let owner_private_key = self.owner_private_key;

        // base_image_ref: config.image
        let base_image_ref = deploy_config.image.clone();

        // workload_ref: config.workload
        let workload_ref = deploy_config.workload.clone();

        // expire_offset: CLI > config > default
        let expire_offset = self
            .expire_offset
            .or(config_env.map(|c| c.expire_offset))
            .unwrap_or(DEFAULT_EXPIRE_OFFSET);

        Ok(AgentEnv {
            relay_private_key,
            rpc_url,
            session_registry,
            owner_private_key,
            base_image_ref,
            workload_ref,
            expire_offset,
        })
    }

    /// Load additional files from deployment config's additional_data_files list.
    /// Files are loaded from --additional-data-dir (defaults to config_dir).
    async fn load_additional_files(
        &self,
        deploy_config: &config::DeploymentConfig,
        config_dir: &Path,
    ) -> Result<Vec<AdditionalFile>> {
        info!(
            "Loading additional data files: {:?}",
            deploy_config.additional_data_files
        );
        if deploy_config.additional_data_files.is_empty() {
            return Ok(Vec::new());
        }

        // Use --additional-data-dir if specified, otherwise use config_dir
        let base_dir = self
            .additional_data_dir
            .as_ref()
            .map(|p| p.as_path())
            .unwrap_or(config_dir);

        let mut additional_files = Vec::new();
        for file_path in &deploy_config.additional_data_files {
            let source_path = base_dir.join(file_path);
            if !source_path.exists() {
                anyhow::bail!(
                    "Additional data file not found: {}\n\
                     Searched in: {}\n\
                     Use --additional-data-dir to specify the directory containing these files.",
                    file_path.display(),
                    base_dir.display()
                );
            }

            let data = tokio::fs::read(&source_path).await.with_context(|| {
                format!("Failed to read additional file: {}", source_path.display())
            })?;

            // Destination path: /secrets/{relative_path}
            let dest = format!("/{}", file_path.display());

            info!(source = %source_path.display(), dest = %dest, "Loading additional file");

            additional_files.push(AdditionalFile {
                source: source_path.to_string_lossy().to_string(),
                dest,
                data,
            });
        }

        Ok(additional_files)
    }

    fn resolve_workload_path(
        &self,
        _ctx: &Env,
        deploy_config: &config::DeploymentConfig,
        config_dir: &Path,
    ) -> Result<PathBuf> {
        // Explicit --workload_path takes precedence.
        if let Some(path) = &self.workload_path {
            return Ok(path.clone());
        }

        // Resolve workload path relative to config file directory.
        Ok(config_dir.join(&deploy_config.workload_path))
    }

    async fn resolve_config(
        &self,
        env: &Env,
    ) -> Result<(config::DeploymentConfig, config::ResolvedPaths, PathBuf)> {
        let target = &self.target;
        let store = ImageStore::new(&env.image_dir).with_token_from_env();

        // If the target ends with .json or is an existing file, load and resolve.
        if target.ends_with(".json") || Path::new(target).is_file() {
            let path = Path::new(target);
            if !path.exists() {
                anyhow::bail!("Deployment file not found: {target}");
            }
            info!(file = %path.display(), "Loading deployment config from file");
            let deployment_config = config::load_from_file(path)?;
            let paths = config::resolve_deployment(
                &deployment_config,
                &store,
                &env.image_repo,
                self.image.as_ref(),
            )
            .await?;
            // Config dir is the parent of the deployment.json file.
            let config_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            return Ok((deployment_config, paths, config_dir));
        }

        let atakit_config = env.config()?;
        let project_dir = env.config_dir()?.to_path_buf();

        info!(
            deployment = %target,
            config = %project_dir.display(),
            "Resolving deployment from atakit.json"
        );

        let (deploy_config, resolved_paths) = config::resolve_from_atakit_json(
            &atakit_config,
            &env.image_repo,
            target,
            self.platform.as_deref(),
            self.image.as_ref(),
            &env.image_dir,
            &project_dir,
        )
        .await?;

        // When deploying from atakit.json, workload is in ata_artifacts/{deployment}/
        let config_dir = env
            .project_artifact_dir
            .join(&deploy_config.workload.repository);
        Ok((deploy_config, resolved_paths, config_dir))
    }
}

/// Derive the operator Ethereum address from a private key.
///
/// The address is derived as the last 20 bytes of `keccak256(uncompressed_pubkey[1..])`,
/// matching the standard Ethereum address derivation used by the CVM agent.
fn derive_operator_address(private_key: B256) -> Result<Address> {
    let signer =
        PrivateKeySigner::from_bytes(&private_key).context("Invalid operator private key")?;

    Ok(signer.address())
}

/// Parse port from a localhost URL (e.g., "http://localhost:8545" -> Some(8545)).
/// Returns None if the URL is not localhost/127.0.0.1 or has no port.
fn parse_localhost_port(url: &str) -> Option<u16> {
    let url = url.to_lowercase();
    if !url.contains("localhost") && !url.contains("127.0.0.1") {
        return None;
    }

    // Find port after the last colon (handles http://localhost:8545)
    url.rsplit(':').next().and_then(|s| {
        // Strip trailing path if any (e.g., "8545/api" -> "8545")
        s.split('/').next().and_then(|p| p.parse().ok())
    })
}
