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
use atakit_image::{ImageRef, ImageStore, Platform as ImagePlatform, import_image_archive};
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
    if !workload_dir.join("atakit-workload.toml").exists() {
        bail!(
            "no workload source specified and no atakit-workload.toml found in {}",
            workload_dir.display(),
        );
    }
    let archive_path = crate::commands::workload::find_versioned_archive(&workload_dir)?;
    let wl_config = atakit_workload::config::WorkloadConfig::from_dir(&workload_dir)?;
    Ok(ResolvedWorkload {
        archive_path,
        name: wl_config.workload.name,
        version: wl_config.workload.version,
    })
}

pub async fn run(args: DeployArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
	let image_only = args.image_only;

	// 1. Resolve workload source (unless --image-only).
	let (archive_path, workload_name, workload_version, archive_hash);
	if image_only {
		archive_path = String::new();
		workload_name = String::new();
		workload_version = String::new();
		archive_hash = String::new();
	} else {
		let resolved = resolve_workload(&args.source, &args.dir, env)?;
		workload_name = resolved.name;
		workload_version = resolved.version;
		let ap = resolved.archive_path;
		let bytes = std::fs::read(&ap)
			.with_context(|| format!("failed to read archive: {}", ap.display()))?;
		archive_hash = format!("{:x}", Sha256::digest(&bytes));
		archive_path = ap.display().to_string();
	}

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
	let instance_name = match args.name.clone() {
		Some(name) => name,
		None if image_only => bail!("--name is required with --image-only"),
		None => format!("{workload_name}-{target_name}"),
	};

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

	// 7. Parse metadata.
	let mut metadata = parse_metadata(&args.metadata)?;
	for (k, v) in &target.metadata {
		metadata.entry(k.clone()).or_insert_with(|| v.clone());
	}

	// 8. Resolve image reference.
	let image_arg = args.image.as_deref().ok_or_else(|| {
		anyhow::anyhow!("--image is required (repository:tag, .atabi file, or GCE image name)")
	})?;

	let resolved_image = resolve_image(image_arg, &target.platform, env)?;
	let image_ref = &resolved_image.display_name;

	// 9. Create provider.
	let provider: Box<dyn CloudProvider> = match target.platform {
		PlatformKind::Gcp => Box::new(GcpProvider::new(
			target.project.clone().unwrap(),
			target.region.clone(),
		)),
		PlatformKind::Azure => bail!("Azure support is not yet implemented"),
	};

	// 10. Generate plan.
	let deploy_opts = DeployOptions {
		instance_name: instance_name.clone(),
		target_name: target_name.to_string(),
		target: target.clone(),
		image_ref: image_ref.to_string(),
		source_image_path: resolved_image.source_path.clone(),
		archive_path: archive_path.clone(),
		archive_hash: archive_hash.clone(),
		workload_name: workload_name.clone(),
		workload_version: workload_version.clone(),
		agent_env: agent_env.clone(),
		metadata: metadata.clone(),
		force_image: args.force_image,
		skip_init: image_only || args.skip_init,
	};
	let plan = provider.plan_deploy(&deploy_opts).await?;

	// 11. Display plan and configuration.
	let names = atakit_cloud::naming::ResourceNames::for_gcp(&instance_name, image_ref);
	let ports: Vec<String> = {
		let mut p = vec!["1024".to_string()];
		if let Some(extra) = metadata.get("ports") {
			for port in extra.split(',') {
				let pt = port.trim().to_string();
				if !pt.is_empty() && !p.contains(&pt) {
					p.push(pt);
				}
			}
		}
		p
	};

	eprintln!("{}", "Plan:".dimmed());
	for (i, step) in plan.steps.iter().enumerate() {
		eprintln!("  {}. {step}", i + 1);
	}
	eprintln!();
	eprintln!("{}", "Configuration:".dimmed());
	eprintln!("  {:<15}{}", "Instance:".dimmed(), format!("{target_name}/{instance_name}").bold());
	if let Some(ref project) = target.project {
		eprintln!("  {:<15}{}", "Project:".dimmed(), project);
	}
	eprintln!("  {:<15}{}", "Zone:".dimmed(), target.region);
	eprintln!("  {:<15}{}", "Machine type:".dimmed(), target.vmtype);
	eprintln!("  {:<15}{}", "CC type:".dimmed(), target.cc_type);
	eprintln!("  {:<15}{}", "Image:".dimmed(), image_ref);
	eprintln!("  {:<15}{}", "GCE name:".dimmed(), names.image);
	if resolved_image.source_path.is_some() {
		eprintln!("  {:<15}{}", "Bucket:".dimmed(), names.bucket);
	}
	eprintln!("  {:<15}{} (tcp:{})", "Firewall:".dimmed(), names.firewall, ports.join(","));
	if let Some(ref src) = resolved_image.source_path {
		eprintln!("  {:<15}{}", "Disk image:".dimmed(), src);
	}
	if !image_only {
		eprintln!("  {:<15}{}:{}", "Workload:".dimmed(), workload_name, workload_version);
	} else {
		eprintln!("  {:<15}image-only (no workload)", "Mode:".dimmed());
	}
	if !metadata.is_empty() {
		for (k, v) in &metadata {
			eprintln!("  {:<15}{}={}", "Metadata:".dimmed(), k, v);
		}
	}
	eprintln!();

	// 12. Confirm.
	if !args.yes {
		eprint!("Proceed? [y/N] ");
		let mut input = String::new();
		std::io::stdin().read_line(&mut input)?;
		if !input.trim().eq_ignore_ascii_case("y") {
			eprintln!("Aborted.");
			return Ok(());
		}
	}

	// 13. Create initial state.
	let mut state = DeployState::new(atakit_cloud::NewDeployParams {
		instance_name: instance_name.clone(),
		workload_name: workload_name.clone(),
		workload_version: workload_version.clone(),
		target_name: target_name.to_string(),
		platform: target.platform,
		image_ref: image_ref.to_string(),
		archive_path,
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

		// Upload streams gsutil progress to stderr, so use newline not "...".
		let streams_output = matches!(step, DeployStep::UploadImage { source_path: Some(_), .. });
		if streams_output {
			eprintln!("  [{step_num}/{total}] {step}");
		} else {
			eprint!("  [{step_num}/{total}] {step}... ");
		}

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
				if streams_output {
					eprintln!("  [{step_num}/{total}] {}", "done".green());
				} else {
					eprintln!("{}", "done".green());
				}
				// After instance creation, show VM details.
				if matches!(step, DeployStep::CreateInstance { .. }) {
					if let Some(ref gcp) = state.resources.gcp {
						let ip = gcp.external_ip.as_deref().unwrap_or("-");
						let inst = gcp.instance.as_deref().unwrap_or(&instance_name);
						let project = gcp.project.as_str();
						let zone = gcp.zone.as_str();
						eprintln!();
						eprintln!("  {:<12}{}", "VM:".dimmed(), inst.bold());
						eprintln!("  {:<12}{}", "IP:".dimmed(), ip);
						eprintln!("  {:<12}{}", "Zone:".dimmed(), zone);
						eprintln!("  {:<12}{}", "Project:".dimmed(), project);
						eprintln!();
					}
				}
			}
			Err(e) => {
				if streams_output {
					eprint!("  [{step_num}/{total}] ");
				}
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

	let project = target.project.as_deref().unwrap_or("-");
	let zone = &target.region;

	eprintln!();
	eprintln!("{}", "==> Deployment complete!".green().bold());
	eprintln!();
	eprintln!("    {:<12}{}", "VM:".dimmed(), instance_name.bold());
	eprintln!("    {:<12}{}", "IP:".dimmed(), if ip.is_empty() { "-" } else { &ip });
	eprintln!("    {:<12}{}", "Zone:".dimmed(), zone);
	eprintln!("    {:<12}{}", "Project:".dimmed(), project);
	eprintln!("    {:<12}{}", "Image:".dimmed(), names.image);
	eprintln!("    {:<12}{}", "CC type:".dimmed(), target.cc_type);
	eprintln!();
	eprintln!("    {}:", "Serial console".dimmed());
	eprintln!("      gcloud compute connect-to-serial-port {instance_name} --zone={zone} --project={project}");
	eprintln!();
	eprintln!("    {}:", "SSH".dimmed());
	eprintln!("      gcloud compute ssh {instance_name} --zone={zone} --project={project}");
	eprintln!();
	eprintln!("    {}:", "Cleanup".dimmed());
	eprintln!("      atakit cloud destroy {instance_name}");
	eprintln!();

	Ok(())
}

/// Resolved base image: display name for the plan + optional local file path.
struct ResolvedImage {
    /// Human-readable name (image ref or GCE image name).
    display_name: String,
    /// Local disk image file path for upload. `None` means the image is
    /// assumed to already exist in GCE.
    source_path: Option<String>,
}

/// Resolve the `--image` argument into a display name and optional source path.
///
/// Three cases:
/// 1. Ends with `.atabi` - import into store, then resolve from store.
/// 2. Contains `:` (ImageRef) - look up in ImageStore for the target
///    platform's disk image. If found locally, use as source_path.
///    If not found, treat as existing GCE image name.
/// 3. Otherwise - bare GCE image name, no upload needed.
fn resolve_image(
    image_arg: &str,
    platform: &PlatformKind,
    env: &Env,
) -> Result<ResolvedImage> {
    let store = ImageStore::new(&env.image_dir);

    if image_arg.ends_with(".atabi") {
        // Import .atabi archive, then resolve from store.
        let archive_path = PathBuf::from(image_arg);
        if !archive_path.exists() {
            bail!("archive not found: {image_arg}");
        }
        let image_ref = import_image_archive(&archive_path, store.base_dir())
            .with_context(|| format!("failed to import {image_arg}"))?;
        eprintln!("  Imported {} from .atabi archive", image_ref);
        return resolve_store_image(&store, &image_ref, platform);
    }

    if image_arg.contains(':') {
        // Parse as ImageRef (repository:tag).
        let image_ref: ImageRef = image_arg.parse()
            .with_context(|| format!("invalid image reference: {image_arg}"))?;
        if store.exists(&image_ref) {
            return resolve_store_image(&store, &image_ref, platform);
        }
        bail!(
            "image {} not found in store (run 'atakit image pull {}' first, \
             or 'atakit image ls --remote' to check available releases)",
            image_ref,
            image_ref,
        );
    }

    // Bare name - existing GCE image.
    Ok(ResolvedImage {
        display_name: image_arg.to_string(),
        source_path: None,
    })
}

/// Look up a disk image file in the store for the target platform.
fn resolve_store_image(
    store: &ImageStore,
    image_ref: &ImageRef,
    platform: &PlatformKind,
) -> Result<ResolvedImage> {
    let image_platform = match platform {
        PlatformKind::Gcp => ImagePlatform::Gcp,
        PlatformKind::Azure => ImagePlatform::Azure,
    };

    let disk_path = store.image_path(image_ref, image_platform);
    if !disk_path.exists() {
        let available = store.local_platforms(image_ref);
        let names: Vec<_> = available.iter().map(|p| p.to_string()).collect();
        bail!(
            "no {} disk image for {} in store (available: {})",
            image_platform,
            image_ref,
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            },
        );
    }

    Ok(ResolvedImage {
        display_name: image_ref.to_string(),
        source_path: Some(disk_path.display().to_string()),
    })
}
