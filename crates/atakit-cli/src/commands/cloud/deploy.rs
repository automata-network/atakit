use anyhow::{Context, Result, bail};
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::DeployArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::init::{self, AgentConfig};
use atakit_cloud::plan::DeployStep;
use atakit_cloud::provider::{CloudProvider, DeployOptions};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::{AzureResources, AzureResourceNames, GcpResources, PlatformKind, ProcessRunner};
use atakit_core::Env;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::config::{self, Config};
use super::{AgentEnvBuilder, collect_unmeasured_tar, parse_metadata, resolve_image, resolve_workload, validate_base_image};

pub async fn run(args: DeployArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
	let image_only = args.image_only;

	// 1. Resolve workload source (unless --image-only).
	let (archive_path, workload_name, workload_version, archive_hash, workload_ports, workload_disks, boot_disk_size_gb, base_image_mode, base_image_list, unmeasured_tar);
	if image_only {
		archive_path = String::new();
		workload_name = String::new();
		workload_version = String::new();
		archive_hash = String::new();
		workload_ports = Vec::new();
		workload_disks = Vec::new();
		boot_disk_size_gb = None;
		base_image_mode = String::new();
		base_image_list = Vec::new();
		unmeasured_tar = None;
	} else {
		let resolved = resolve_workload(&args.source, &args.dir, env)?;
		workload_name = resolved.name;
		workload_version = resolved.version;
		workload_ports = resolved.ports;
		workload_disks = resolved.disks.iter()
			.map(|(name, (index, size))| {
				let gb = parse_size_gb(size)
					.ok_or_else(|| anyhow::anyhow!("invalid disk size '{size}' for disk '{name}'"))?;
				Ok((name.clone(), *index, gb))
			})
			.collect::<Result<Vec<_>>>()?;
		boot_disk_size_gb = resolved.boot_disk_size.as_deref().and_then(parse_size_gb);
		base_image_mode = resolved.base_image_mode;
		base_image_list = resolved.base_image;
		// Collect unmeasured-data files if a workload directory is available.
		unmeasured_tar = if !resolved.unmeasured_data.is_empty() {
			if let Some(ref wdir) = resolved.workload_dir {
				collect_unmeasured_tar(&resolved.unmeasured_data, wdir)?
			} else {
				eprintln!(
					"  {}: workload declares unmeasured-data but no workload directory available (store-ref/file mode)",
					"warning".yellow(),
				);
				None
			}
		} else {
			None
		};
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
	let provider_config = config
		.cloud
		.providers
		.get(&target.provider)
		.ok_or_else(|| anyhow::anyhow!("provider '{}' not found in [cloud.providers]", target.provider))?;

	// 3. Validate platform-specific requirements.
	atakit_cloud::validate_target(&target, provider_config, target_name)?;
	match provider_config.platform {
		PlatformKind::Gcp => {
			if provider_config.project.is_none() {
				bail!("GCP target '{target_name}' requires 'project' (set in config or ATAKIT_GCP_PROJECT)");
			}
		}
		PlatformKind::Azure => {
			if provider_config.subscription.is_none() {
				bail!("Azure target '{target_name}' requires 'subscription' (set in config)");
			}
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

	// 8. Resolve image reference (--image overrides target.image).
	let image_arg = args
		.image
		.as_deref()
		.or(target.image.as_deref())
		.ok_or_else(|| {
			anyhow::anyhow!(
				"no image specified: pass --image or set `image = \"...\"` \
				 on target '{target_name}' in [cloud.targets]"
			)
		})?;

	let resolved_image = resolve_image(image_arg, &provider_config.platform, env)?;
	let image_ref = &resolved_image.display_name;

	// 8b. Validate image against workload's base-image policy.
	if !image_only {
		validate_base_image(image_ref, &base_image_mode, &base_image_list)?;
	}

	// 8c. Resolve CC types for image registration.
	// Precedence: --cc-types CLI > [cloud.images] lookup (by resolved ref) > inferred cc_type.
	// Lookup uses the resolved display_name (e.g. "dev-baseimage:v0.0.1-debug"),
	// not the raw CLI arg (which might be a .atabi path).
	let resolved_cc = target.resolved_cc_type(provider_config.platform)?;
	let cc_types: Vec<atakit_cloud::CcType> = if !args.cc_types.is_empty() {
		args.cc_types
			.iter()
			.map(|s| s.parse::<atakit_cloud::CcType>())
			.collect::<Result<Vec<_>, _>>()?
	} else if let Some(entry) = config.cloud.images.get(image_ref) {
		entry.cc_types.clone()
	} else {
		vec![resolved_cc]
	};

	// 9. Create provider.
	let provider: Box<dyn CloudProvider> = match provider_config.platform {
		PlatformKind::Gcp => Box::new(GcpProvider::new(
			provider_config.project.clone().unwrap(),
			provider_config.region.clone(),
		)),
		PlatformKind::Azure => Box::new(AzureProvider::new(
			provider_config.subscription.clone().unwrap(),
			provider_config.region.clone(),
		)),
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
		cc_types: cc_types.clone(),
		workload_ports: workload_ports.clone(),
		workload_disks: workload_disks.clone(),
		boot_disk_size_gb,
	};
	let plan = provider.plan_deploy(&deploy_opts).await?;

	// 11. Display plan and configuration.
	let ports: Vec<String> = plan.steps.iter().find_map(|s| {
		if let DeployStep::OpenPorts { ports, .. } = s {
			Some(ports.clone())
		} else {
			None
		}
	}).unwrap_or_default();

	eprintln!("{}", "Plan:".dimmed());
	for (i, step) in plan.steps.iter().enumerate() {
		eprintln!("  {}. {step}", i + 1);
	}
	eprintln!();
	eprintln!("{}", "Configuration:".dimmed());
	eprintln!("  {:<15}{}", "Instance:".dimmed(), format!("{target_name}/{instance_name}").bold());
	match provider_config.platform {
		PlatformKind::Gcp => {
			let names = atakit_cloud::naming::ResourceNames::for_gcp(&instance_name, image_ref);
			if let Some(ref project) = provider_config.project {
				eprintln!("  {:<15}{}", "Project:".dimmed(), project);
			}
			eprintln!("  {:<15}{}", "Zone:".dimmed(), provider_config.region);
			eprintln!("  {:<15}{}", "Machine type:".dimmed(), target.vmtype);
			eprintln!("  {:<15}{}", "CC type:".dimmed(), resolved_cc);
			eprintln!("  {:<15}{}", "Image:".dimmed(), image_ref);
			eprintln!("  {:<15}{}", "GCE name:".dimmed(), names.image);
			if resolved_image.source_path.is_some() {
				eprintln!("  {:<15}{}", "Bucket:".dimmed(), names.bucket);
			}
			eprintln!("  {:<15}{}", "Firewall:".dimmed(), names.firewall);
		}
		PlatformKind::Azure => {
			let names = AzureResourceNames::for_azure(&instance_name, image_ref, &provider_config.region);
			if let Some(ref sub) = provider_config.subscription {
				eprintln!("  {:<15}{}", "Subscription:".dimmed(), sub);
			}
			eprintln!("  {:<15}{}", "Region:".dimmed(), provider_config.region);
			eprintln!("  {:<15}{}", "VM size:".dimmed(), target.vmtype);
			eprintln!("  {:<15}{}", "CC type:".dimmed(), resolved_cc);
			eprintln!("  {:<15}{}", "Image:".dimmed(), image_ref);
			eprintln!("  {:<15}{}", "RG:".dimmed(), names.resource_group);
			eprintln!("  {:<15}{}/{}", "Gallery:".dimmed(), names.gallery_rg, names.gallery);
			eprintln!("  {:<15}{}", "NSG:".dimmed(), names.nsg);
		}
	}
	if let Some(gb) = boot_disk_size_gb {
		eprintln!("  {:<15}{}GB", "Boot disk:".dimmed(), gb);
	}
	let port_lines = atakit_cloud::plan::format_ports_list(&ports);
	for line in &port_lines {
		eprintln!("  {:<15}{}", "", line);
	}
	if !workload_disks.is_empty() {
		let disk_type = match provider_config.platform {
			PlatformKind::Gcp => "pd-balanced",
			PlatformKind::Azure => "Premium_LRS",
		};
		for (i, (name, index, gb)) in workload_disks.iter().enumerate() {
			let label = if i == 0 {
				format!("{:<15}", "Disks:").dimmed().to_string()
			} else {
				format!("{:<15}", "")
			};
			eprintln!("  {label}- {name} ({gb}GB, {disk_type}, LUN {index})");
		}
	}
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
		provider_name: target.provider.clone(),
		platform: provider_config.platform,
		image_ref: image_ref.to_string(),
		archive_path,
		archive_hash,
		agent_env: agent_env.clone(),
		total_steps: plan.steps.len() as u32,
	});
	match provider_config.platform {
		PlatformKind::Gcp => {
			state.resources.gcp = Some(GcpResources {
				project: provider_config.project.clone().unwrap(),
				zone: provider_config.region.clone(),
				..Default::default()
			});
		}
		PlatformKind::Azure => {
			state.resources.azure = Some(AzureResources {
				subscription: provider_config.subscription.clone().unwrap(),
				region: provider_config.region.clone(),
				..Default::default()
			});
		}
	}
	state.save(&env.data_dir)?;

	// 15. Execute steps.
	let runner = ProcessRunner::new(verbose);
	let total = plan.steps.len() as u32;

	for (i, step) in plan.steps.iter().enumerate() {
		let step_num = (i + 1) as u32;
		state.advance_step(step_num, &env.data_dir)?;

		// Upload streams progress to stderr, so use newline not "...".
		let streams_output = matches!(
			step,
			DeployStep::UploadImage { source_path: Some(_), .. }
				| DeployStep::UploadImageAzure { source_path: Some(_), .. }
		);
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
					.or_else(|| state.resources.azure.as_ref().and_then(|a| a.external_ip.as_ref()))
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
					.or_else(|| state.resources.azure.as_ref().and_then(|a| a.external_ip.as_ref()))
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

				match init::post_init(&ip, ap, unmeasured_tar.as_deref(), &agent_config).await {
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
				// After image upload, record in cloud images state.
				if matches!(step, DeployStep::UploadImage { source_path: Some(_), .. }
					| DeployStep::UploadImageAzure { source_path: Some(_), .. })
				{
					match atakit_cloud::cloud_images::CloudImages::load(&env.data_dir) {
						Ok(mut cloud_imgs) => {
							let record = super::build_cloud_image_record(
								provider_config, image_ref, &instance_name, &cc_types,
							);
							cloud_imgs.record(image_ref, &target.provider, record);
							if let Err(e) = cloud_imgs.save(&env.data_dir) {
								tracing::warn!("failed to save cloud images state: {e}");
							}
						}
						Err(e) => {
							tracing::warn!("failed to load cloud images state: {e}");
						}
					}
				}
				// After instance creation, show VM details.
				if matches!(step, DeployStep::CreateInstance { .. } | DeployStep::CreateInstanceAzure { .. }) {
					if let Some(ref gcp) = state.resources.gcp {
						let ip = gcp.external_ip.as_deref().unwrap_or("-");
						let inst = gcp.instance.as_deref().unwrap_or(&instance_name);
						eprintln!();
						eprintln!("  {:<12}{}", "VM:".dimmed(), inst.bold());
						eprintln!("  {:<12}{}", "IP:".dimmed(), ip);
						eprintln!("  {:<12}{}", "Zone:".dimmed(), gcp.zone.as_str());
						eprintln!("  {:<12}{}", "Project:".dimmed(), gcp.project.as_str());
						eprintln!();
					}
					if let Some(ref az) = state.resources.azure {
						let ip = az.external_ip.as_deref().unwrap_or("-");
						let inst = az.instance.as_deref().unwrap_or(&instance_name);
						eprintln!();
						eprintln!("  {:<12}{}", "VM:".dimmed(), inst.bold());
						eprintln!("  {:<12}{}", "IP:".dimmed(), ip);
						eprintln!("  {:<12}{}", "Region:".dimmed(), az.region.as_str());
						eprintln!("  {:<12}{}", "RG:".dimmed(), az.resource_group.as_deref().unwrap_or("-"));
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
		.or_else(|| state.resources.azure.as_ref().and_then(|a| a.external_ip.clone()))
		.unwrap_or_default();
	state.set_status(DeployStatus::Deployed { ip: ip.clone() }, &env.data_dir)?;

	eprintln!();
	eprintln!("{}", "==> Deployment complete!".green().bold());
	eprintln!();
	eprintln!("    {:<12}{}", "VM:".dimmed(), instance_name.bold());
	eprintln!("    {:<12}{}", "IP:".dimmed(), if ip.is_empty() { "-" } else { &ip });

	match provider_config.platform {
		PlatformKind::Gcp => {
			let project = provider_config.project.as_deref().unwrap_or("-");
			let zone = &provider_config.region;
			let names = atakit_cloud::naming::ResourceNames::for_gcp(&instance_name, image_ref);
			eprintln!("    {:<12}{}", "Zone:".dimmed(), zone);
			eprintln!("    {:<12}{}", "Project:".dimmed(), project);
			eprintln!("    {:<12}{}", "Image:".dimmed(), names.image);
			eprintln!("    {:<12}{}", "CC type:".dimmed(), resolved_cc);
			eprintln!();
			eprintln!("    {}:", "Serial console".dimmed());
			eprintln!("      gcloud compute connect-to-serial-port {instance_name} --zone={zone} --project={project}");
			eprintln!();
			eprintln!("    {}:", "SSH".dimmed());
			eprintln!("      gcloud compute ssh {instance_name} --zone={zone} --project={project}");
		}
		PlatformKind::Azure => {
			let names = AzureResourceNames::for_azure(&instance_name, image_ref, &provider_config.region);
			eprintln!("    {:<12}{}", "Region:".dimmed(), provider_config.region);
			eprintln!("    {:<12}{}", "RG:".dimmed(), names.resource_group);
			eprintln!("    {:<12}{}", "CC type:".dimmed(), resolved_cc);
			eprintln!();
			eprintln!("    {}:", "Serial console".dimmed());
			eprintln!("      az serial-console connect --name {instance_name} --resource-group {}", names.resource_group);
			eprintln!();
			eprintln!("    {}:", "SSH".dimmed());
			eprintln!("      az ssh vm --name {instance_name} --resource-group {}", names.resource_group);
		}
	}
	eprintln!();
	eprintln!("    {}:", "Cleanup".dimmed());
	eprintln!("      atakit cloud destroy {instance_name}");
	eprintln!();

	Ok(())
}

/// Parse a human-readable size string (e.g. "10GB", "500MB", "1TB") into whole gigabytes.
/// Returns `None` for invalid formats. Fractional GB from MB conversion rounds up.
fn parse_size_gb(s: &str) -> Option<u64> {
	let s = s.trim();
	let (num_str, suffix) = if let Some(n) = s.strip_suffix("TB") {
		(n, "TB")
	} else if let Some(n) = s.strip_suffix("GB") {
		(n, "GB")
	} else if let Some(n) = s.strip_suffix("MB") {
		(n, "MB")
	} else {
		return None;
	};
	let num: u64 = num_str.trim().parse().ok()?;
	match suffix {
		"TB" => Some(num * 1024),
		"GB" => Some(num),
		"MB" => Some(num.div_ceil(1024)),
		_ => None,
	}
}
