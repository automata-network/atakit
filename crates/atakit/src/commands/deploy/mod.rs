pub mod config;
mod init;
mod runner;

use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use automata_linux_release::ImageStore;
use clap::Args;
use tokio_util::sync::CancellationToken;
use tracing::info;

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

    /// Override automata-linux disk image version (e.g., "v0.5.0")
    #[arg(long)]
    pub image: Option<String>,

    /// Path to workload package (tar.gz) for initialization.
    /// Defaults to ata_artifacts/{target}.tar.gz
    #[arg(long)]
    pub workload: Option<PathBuf>,

    /// Skip confirmation prompts
    #[arg(long)]
    pub quiet: bool,

    /// Use local QEMU instead of cloud provider
    #[arg(long)]
    pub qemu: bool,

    /// Operator private key for signing init requests (hex encoded).
    /// Can also be set via ATAKIT_PRIVATE_KEY environment variable.
    #[arg(long, env = "ATAKIT_PRIVATE_KEY")]
    pub private_key: Option<B256>,
}

impl Deploy {
    pub async fn run(self, ctx: &Env) -> Result<()> {
        // Private key is required for operator authentication
        let private_key = self.private_key.ok_or_else(|| {
            anyhow::anyhow!(
                "Operator private key is required.\n\
                 Provide --private-key or set ATAKIT_PRIVATE_KEY environment variable."
            )
        })?;

        // Derive operator address for VM metadata
        let operator_address = derive_operator_address(private_key)?;
        info!(address = %operator_address, "Derived operator address");

        let (mut deploy_config, paths, config_dir) = self.resolve_config(ctx).await?;

        // CLI --quiet overrides the config value.
        if self.quiet {
            deploy_config.quiet = Some(true);
        }

        // CLI --qemu overrides the provider to use local QEMU.
        // QEMU mode is always quiet (no confirmation prompts needed for local dev).
        if self.qemu {
            deploy_config.provider = config::ProviderKind::Qemu;
            deploy_config.quiet = Some(true);
        }

        let workload_path = self.resolve_workload_path(ctx, &deploy_config, &config_dir)?;
        if !workload_path.exists() {
            anyhow::bail!(
                "Workload package not found: {}\nRun 'atakit build-workload' first, or specify --workload",
                workload_path.display()
            );
        }
        let is_qemu = matches!(deploy_config.provider, config::ProviderKind::Qemu);

        let cancel = CancellationToken::new();

        // For QEMU: start init task before QEMU (runs in parallel).
        // The init task will retry connecting to port 8000 while QEMU boots.
        let init_handle = if is_qemu {
            let token = cancel.clone();
            let path = workload_path.clone();
            Some(tokio::spawn(async move {
                println!("monitoring VM for init (this may take a minute)...");
                init::init_workload("127.0.0.1", &path, Some(private_key), token).await
            }))
        } else {
            None
        };

        // Deploy (QEMU blocks here while user interacts)
        let result = runner::deploy(&deploy_config, &paths, operator_address, ctx).await;

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
                        init::init_workload(ip, &workload_path, Some(private_key), cancel).await?;
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
                        deploy_config.gcp.as_ref().and_then(|g| g.project_id.clone()),
                        deploy_config.azure.as_ref().and_then(|a| a.resource_group.clone()),
                        paths.version.clone(),
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
                println!("  Platform: {}", match deploy_config.provider {
                    config::ProviderKind::Gcp => "gcp",
                    config::ProviderKind::Azure => "azure",
                    config::ProviderKind::Qemu => "qemu",
                });
                if let Some(ip) = &instance.public_ip {
                    println!("  Public IP: {ip}");
                }
                if let Some(v) = &paths.version {
                    println!("  Image: {v}");
                }
            }
        }

        Ok(())
    }

    fn resolve_workload_path(
        &self,
        _ctx: &Env,
        deploy_config: &config::DeploymentConfig,
        config_dir: &Path,
    ) -> Result<PathBuf> {
        // Explicit --workload takes precedence.
        if let Some(path) = &self.workload {
            return Ok(path.clone());
        }

        // Resolve workload path relative to config file directory.
        Ok(config_dir.join(&deploy_config.workload))
    }

    async fn resolve_config(&self, ctx: &Env) -> Result<(config::DeploymentConfig, config::ResolvedPaths, PathBuf)> {
        let target = &self.target;
        let store = ImageStore::new(&ctx.image_dir).with_token_from_env();

        // If the target ends with .json or is an existing file, load and resolve.
        if target.ends_with(".json") || Path::new(target).is_file() {
            let path = Path::new(target);
            if !path.exists() {
                anyhow::bail!("Deployment file not found: {target}");
            }
            info!(file = %path.display(), "Loading deployment config from file");
            let deployment_config = config::load_from_file(path)?;
            let paths = config::resolve_deployment(&deployment_config, &store, self.image.as_deref())
                .await?;
            // Config dir is the parent of the deployment.json file.
            let config_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            return Ok((deployment_config, paths, config_dir));
        }

        let atakit_config = ctx.config()?;
        let project_dir = ctx.config_dir()?.to_path_buf();

        info!(
            deployment = %target,
            config = %project_dir.display(),
            "Resolving deployment from atakit.json"
        );

        let (deploy_config, resolved_paths) = config::resolve_from_atakit_json(
            &atakit_config,
            target,
            self.platform.as_deref(),
            self.image.as_deref(),
            &ctx.image_dir,
            &project_dir,
        )
        .await?;

        // When deploying from atakit.json, workload is in ata_artifacts/{deployment}/
        let config_dir = ctx.project_artifact_dir.join(&deploy_config.name);
        Ok((deploy_config, resolved_paths, config_dir))
    }
}

/// Derive the operator Ethereum address from a private key.
///
/// The address is derived as the last 20 bytes of `keccak256(uncompressed_pubkey[1..])`,
/// matching the standard Ethereum address derivation used by the CVM agent.
fn derive_operator_address(private_key: B256) -> Result<Address> {
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .context("Invalid operator private key")?;

    Ok(signer.address())
}
