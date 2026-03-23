use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use atakit_cloud::cli::DeployArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::init::{self, AgentConfig};
use atakit_cloud::plan::DeployStep;
use atakit_cloud::provider::{CloudProvider, DeployOptions};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::{GcpResources, PlatformKind, ProcessRunner};
use atakit_core::Env;
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::config::{self, Config};
use super::{AgentEnvBuilder, parse_metadata};

/// Resolved workload source: archive path + name/version.
struct ResolvedWorkload {
    archive_path: PathBuf,
    name: String,
    version: String,
}

/// Resolve workload from source arg, falling back to dir mode.
fn resolve_workload(source: &Option<String>, dir: &Option<PathBuf>, env: &Env) -> Result<ResolvedWorkload> {
    if let Some(ref src) = source {
        // Store reference: name:version
        if crate::commands::workload::looks_like_store_ref(src) {
            let (name, version) = src
                .split_once(':')
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .unwrap();
            let store = WorkloadStore::new(&env.workload_dir);
            let blob = store.blob_path(&name, &version)?;
            if !blob.exists() {
                bail!("no archive blob for {name}:{version} in store");
            }
            return Ok(ResolvedWorkload {
                archive_path: blob,
                name,
                version,
            });
        }

        // File path: something.atawl
        let path = PathBuf::from(src);
        if !path.exists() {
            bail!("archive not found: {src}");
        }
        let opts = atakit_workload::InspectOptions {
            archive: Some(path.clone()),
            workload_dir: None,
            engine: None,
            verbose: false,
        };
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(atakit_workload::inspect_workload(&opts))
        }).context("failed to inspect archive")?;
        return Ok(ResolvedWorkload {
            archive_path: path,
            name: result.manifest.meta.name,
            version: result.manifest.meta.version,
        });
    }

    // Dir mode: read atakit-workload.toml, find versioned archive.
    let workload_dir = dir.clone().unwrap_or_else(|| std::env::current_dir().unwrap());
    let archive_path = crate::commands::workload::find_versioned_archive(&workload_dir)?;
    let wl_config = atakit_workload::config::WorkloadConfig::from_dir(&workload_dir)?;
    Ok(ResolvedWorkload {
        archive_path,
        name: wl_config.workload.name,
        version: wl_config.workload.version,
    })
}

pub async fn run(args: DeployArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
	// 1. Resolve workload source (store ref, .atawl file, or dir).
	let resolved = resolve_workload(&args.source, &args.dir, env)?;
	let archive_path = resolved.archive_path;
	let workload_name = resolved.name;
	let workload_version = resolved.version;

	// 2. Resolve target.
	let target_name = args.target.as_deref().ok_or_else(|| {
		anyhow::anyhow!("--target is required (specify a target from [cloud.targets] in config)")
	})?;
	let target = config
		.cloud
		.targets
		.get(target_name)
		.ok_or_else(|| anyhow::anyhow!("target '{target_name}' not found in config"))?
		.clone();

	// 3. Validate platform-specific requirements.
	match target.platform {
		PlatformKind::Gcp => {
			if target.project.is_none() {
				bail!("GCP target '{target_name}' requires 'project' (set in config or ATAKIT_GCP_PROJECT)");
			}
		}
		PlatformKind::Azure => {
			bail!("Azure support is not yet implemented");
		}
	}

	// 4. Instance name.
	let instance_name = args
		.name
		.clone()
		.unwrap_or_else(|| format!("{workload_name}-{target_name}"));

	// 5. Check for existing deployment.
	if atakit_cloud::state::find_instance(&env.data_dir, &instance_name, Some(target_name))
		.is_ok()
	{
		bail!(
			"deployment '{target_name}/{instance_name}' already exists. \
			 Use 'cloud destroy' first, or choose a different --name."
		);
	}

	// 6. Build agent env.
	let agent_env_builder = AgentEnvBuilder {
		cli_rpc_url: args.rpc_url.as_deref(),
		cli_session_registry: args.session_registry.as_deref(),
		cli_owner_key: args.owner_key.as_deref(),
		cli_relay_key: args.relay_key.as_deref(),
		target: &target,
		cloud: &config.cloud,
		publish: &config.publish,
	};
	let agent_env = agent_env_builder.build();

	// 7. Compute archive hash.
	let archive_bytes = std::fs::read(&archive_path)
		.with_context(|| format!("failed to read archive: {}", archive_path.display()))?;
	let archive_hash = format!("{:x}", Sha256::digest(&archive_bytes));

	// 8. Parse metadata.
	let mut metadata = parse_metadata(&args.metadata)?;
	for (k, v) in &target.metadata {
		metadata.entry(k.clone()).or_insert_with(|| v.clone());
	}

	// 9. Resolve image reference.
	let image_ref = args.image.as_deref().ok_or_else(|| {
		anyhow::anyhow!("--image is required (base CVM image reference or path)")
	})?;

	// 10. Create provider.
	let provider: Box<dyn CloudProvider> = match target.platform {
		PlatformKind::Gcp => Box::new(GcpProvider::new(
			target.project.clone().unwrap(),
			target.region.clone(),
		)),
		PlatformKind::Azure => bail!("Azure support is not yet implemented"),
	};

	// 11. Generate plan.
	let deploy_opts = DeployOptions {
		instance_name: instance_name.clone(),
		target_name: target_name.to_string(),
		target: target.clone(),
		image_ref: image_ref.to_string(),
		archive_path: archive_path.display().to_string(),
		archive_hash: archive_hash.clone(),
		workload_name: workload_name.clone(),
		workload_version: workload_version.clone(),
		agent_env: agent_env.clone(),
		metadata: metadata.clone(),
		force_image: args.force_image,
		skip_init: args.skip_init,
	};
	let plan = provider.plan_deploy(&deploy_opts).await?;

	// 12. Display plan.
	eprintln!("{}", "Deploy plan:".dimmed());
	for (i, step) in plan.steps.iter().enumerate() {
		eprintln!("  {}. {step}", i + 1);
	}
	eprintln!();
	eprintln!(
		"  Instance:  {}",
		format!("{target_name}/{instance_name}").bold()
	);
	eprintln!("  Workload:  {workload_name}:{workload_version}");
	eprintln!("  Image:     {image_ref}");
	eprintln!("  Platform:  {}", target.platform);
	eprintln!();

	// 13. Confirm.
	if !args.yes {
		eprint!("Proceed? [y/N] ");
		let mut input = String::new();
		std::io::stdin().read_line(&mut input)?;
		if !input.trim().eq_ignore_ascii_case("y") {
			eprintln!("Aborted.");
			return Ok(());
		}
	}

	// 14. Create initial state.
	let mut state = DeployState::new(atakit_cloud::NewDeployParams {
		instance_name: instance_name.clone(),
		workload_name: workload_name.clone(),
		workload_version: workload_version.clone(),
		target_name: target_name.to_string(),
		platform: target.platform,
		image_ref: image_ref.to_string(),
		archive_path: archive_path.display().to_string(),
		archive_hash,
		agent_env: agent_env.clone(),
	});
	if matches!(target.platform, PlatformKind::Gcp) {
		state.resources.gcp = Some(GcpResources {
			project: target.project.clone().unwrap(),
			zone: target.region.clone(),
			..Default::default()
		});
	}
	state.save(&env.data_dir)?;

	// 15. Execute steps.
	let runner = ProcessRunner;
	let total = plan.steps.len() as u32;

	for (i, step) in plan.steps.iter().enumerate() {
		let step_num = (i + 1) as u32;
		state.advance_step(step_num, &env.data_dir)?;
		eprint!("  [{step_num}/{total}] {step}... ");

		match step {
			DeployStep::WaitForAgent { timeout_secs } => {
				let ip = state
					.resources
					.gcp
					.as_ref()
					.and_then(|g| g.external_ip.as_ref())
					.ok_or_else(|| anyhow::anyhow!("no external IP available for agent wait"))?
					.clone();
				match init::wait_for_agent(&ip, *timeout_secs).await {
					Ok(()) => eprintln!("{}", "done".green()),
					Err(e) => {
						eprintln!("{}", "failed".red());
						if !args.keep_going {
							state.set_status(
								DeployStatus::Failed {
									step: step.to_string(),
									message: e.to_string(),
								},
								&env.data_dir,
							)?;
							return Err(e.into());
						}
						eprintln!("  warning: {e}");
					}
				}
				continue;
			}
			DeployStep::InitializeWorkload { archive_path: ap } => {
				let ip = state
					.resources
					.gcp
					.as_ref()
					.and_then(|g| g.external_ip.as_ref())
					.ok_or_else(|| anyhow::anyhow!("no external IP available for init"))?
					.clone();

				let rpc_url = agent_env
					.rpc_url
					.as_ref()
					.ok_or_else(|| {
						anyhow::anyhow!("rpc_url is required for agent initialization")
					})?
					.clone();
				let session_registry = agent_env
					.session_registry
					.as_ref()
					.ok_or_else(|| {
						anyhow::anyhow!(
							"session_registry is required for agent initialization"
						)
					})?
					.clone();
				let owner_key_file = agent_env.owner_key_file.as_ref().ok_or_else(|| {
					anyhow::anyhow!("owner_key_file is required for agent initialization")
				})?;
				let relay_key_file = agent_env.relay_key_file.as_ref().ok_or_else(|| {
					anyhow::anyhow!("relay_key_file is required for agent initialization")
				})?;
				let owner_key = config::read_key_file(owner_key_file)?;
				let relay_key = config::read_key_file(relay_key_file)?;

				let agent_config = AgentConfig {
					rpc_url,
					session_registry,
					owner_private_key: owner_key,
					relay_private_key: relay_key,
					expire_offset: agent_env.expire_offset.unwrap_or(3600),
				};

				match init::post_init(&ip, ap, None, &agent_config, true).await {
					Ok(()) => eprintln!("{}", "done".green()),
					Err(e) => {
						eprintln!("{}", "failed".red());
						if !args.keep_going {
							state.set_status(
								DeployStatus::Failed {
									step: step.to_string(),
									message: e.to_string(),
								},
								&env.data_dir,
							)?;
							return Err(e.into());
						}
						eprintln!("  warning: {e}");
					}
				}
				continue;
			}
			_ => {}
		}

		// Execute normal provider steps.
		match provider.execute_step(step, &runner, verbose).await {
			Ok(result) => {
				state.apply_resource_updates(&result.resource_updates);
				state.save(&env.data_dir)?;
				eprintln!("{}", "done".green());
			}
			Err(e) => {
				eprintln!("{}", "failed".red());
				if !args.keep_going {
					state.set_status(
						DeployStatus::Failed {
							step: step.to_string(),
							message: e.to_string(),
						},
						&env.data_dir,
					)?;
					return Err(e.into());
				}
				eprintln!("  warning: {e}");
			}
		}
	}

	// 16. Final state.
	let ip = state
		.resources
		.gcp
		.as_ref()
		.and_then(|g| g.external_ip.clone())
		.unwrap_or_default();
	state.set_status(DeployStatus::Deployed { ip: ip.clone() }, &env.data_dir)?;

	eprintln!();
	eprintln!(
		"  {} Deployed {}/{} at {}",
		"*".green(),
		target_name,
		instance_name.bold(),
		if ip.is_empty() { "-" } else { &ip },
	);

	Ok(())
}
