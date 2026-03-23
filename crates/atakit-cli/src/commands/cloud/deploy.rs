use anyhow::{Context, Result, bail};
use atakit_cloud::cli::DeployArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::init::{self, AgentConfig};
use atakit_cloud::plan::DeployStep;
use atakit_cloud::provider::{CloudProvider, DeployOptions};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::{GcpResources, PlatformKind, ProcessRunner};
use atakit_core::Env;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::config::{self, Config};
use super::{AgentEnvBuilder, parse_metadata, resolve_image, resolve_workload};

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

				match init::post_init(&ip, ap, None, &agent_config).await {
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

