use anyhow::{Context, Result, bail};
use atakit_cloud::aws::AwsProvider;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::DeployArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::init::{self, InitConfig, InitChainConfig, InitKeyConfig};
use atakit_cloud::plan::DeployStep;
use atakit_cloud::provider::{CloudProvider, DeployOptions};
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::{AwsResources, AzureResources, AzureResourceNames, GcpResources, PlatformKind, ProcessRunner};
use atakit_core::Env;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::config::{Config, KeyMode};
use super::{InitEnvResolver, collect_unmeasured_tar, ensure_cloud_image, parse_metadata, resolve_image, resolve_workload, validate_base_image};

/// Multi-target dispatcher. Single target → forward to `run_one`. Multiple
/// targets → fan out into a concurrent deploy (one async future per target,
/// joined via `join_all`).
pub async fn run(mut args: DeployArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
	let targets = std::mem::take(&mut args.target);
	match targets.len() {
		0 => bail!("--target is required (specify a target from [cloud.targets] in config)"),
		1 => {
			args.target = targets;
			run_one(args, env, config, verbose).await
		}
		_ => {
			if args.name.is_some() {
				bail!(
					"--name cannot be combined with multiple --target (instance names \
					 are auto-generated per target in multi-target mode)"
				);
			}
			// No interactive confirmation in multi mode -- N intermixed prompts
			// would be unusable.
			args.yes = true;

			// Phase 1: pre-upload images for unique (provider, image_ref)
			// pairs SERIALLY. The per-deploy `UploadImage` step is
			// check-then-act (check_image_exists -> upload+register), so two
			// concurrent deploys racing the same image both pass the check
			// and both try to register, and the second register fails. Doing
			// the upload once up front lets every per-target deploy's
			// `UploadImage` step short-circuit on existence.
			let mut upload_pairs: std::collections::BTreeMap<
				(String, String),
				(
					atakit_cloud::config::CloudProviderConfig,
					String,
					Option<String>,
					Vec<atakit_cloud::CcType>,
				),
			> = std::collections::BTreeMap::new();
			for target_name in &targets {
				let target = config.cloud.targets.get(target_name).ok_or_else(|| {
					anyhow::anyhow!("target '{target_name}' not found in [cloud.targets]")
				})?;
				let provider_config = config.cloud.providers.get(&target.provider).ok_or_else(|| {
					anyhow::anyhow!(
						"provider '{}' not found in [cloud.providers]",
						target.provider
					)
				})?;
				let image_arg = args
					.image
					.as_deref()
					.or(target.image.as_deref())
					.ok_or_else(|| {
						anyhow::anyhow!(
							"target '{target_name}' has no image (set --image or \
							 `image = \"...\"` on the target)"
						)
					})?;
				let resolved = resolve_image(image_arg, &provider_config.platform, env)?;
				// If the image ref points at an existing cloud image (no local
				// source), no upload is needed -- the cloud image already exists
				// by definition.
				let Some(source_path) = resolved.source_path else {
					continue;
				};
				let resolved_cc = target.resolved_cc_type(provider_config.platform)?;
				let cc_types: Vec<atakit_cloud::CcType> = if !args.cc_types.is_empty() {
					args.cc_types
						.iter()
						.map(|s| s.parse::<atakit_cloud::CcType>())
						.collect::<Result<Vec<_>, _>>()?
				} else if let Some(entry) = config.cloud.images.get(&resolved.display_name) {
					entry.cc_types.clone()
				} else {
					vec![resolved_cc]
				};
				upload_pairs
					.entry((target.provider.clone(), resolved.display_name.clone()))
					.or_insert((
						provider_config.clone(),
						source_path,
						resolved.certs_dir,
						cc_types,
					));
			}

			if !upload_pairs.is_empty() {
				eprintln!(
					"{} {} unique image/provider pair(s) before fan-out...",
					"Pre-uploading".dimmed(),
					upload_pairs.len().to_string().bold(),
				);
				for (
					(provider_name, image_ref),
					(provider_config, source_path, certs_dir, cc_types),
				) in &upload_pairs
				{
					eprintln!(
						"  {} {} -> {}",
						"→".dimmed(),
						image_ref,
						provider_name,
					);
					ensure_cloud_image(
						image_ref,
						provider_name,
						provider_config,
						source_path,
						certs_dir.as_deref(),
						cc_types,
						args.force_image,
						env,
						verbose,
					)
					.await
					.with_context(|| {
						format!("pre-upload of image '{image_ref}' to provider '{provider_name}' failed")
					})?;
				}
				// Subsequent per-target deploys must see the cached image; do
				// not let them attempt a re-upload (they'd just check existence
				// and skip, but force_image would delete + re-upload N times).
			}
			// Phase 2: per-target deploys fan out concurrently. Each one's
			// UploadImage step will check_image_exists -> true -> skip.
			eprintln!();
			eprintln!(
				"{} {} target(s)...",
				"Deploying to".dimmed(),
				targets.len().to_string().bold(),
			);
			// force_image was already honored by the pre-upload phase; clear
			// it for per-target deploys so they don't delete what we just
			// uploaded.
			args.force_image = false;
			let futures = targets.iter().cloned().map(|t| {
				let mut single = args.clone();
				single.target = vec![t.clone()];
				// Image-only requires --name in single-target mode (no
				// workload-name default). Auto-generate per target here so
				// multi-target image-only deploys (the measurement workflow)
				// don't need per-target --name flags.
				if single.image_only && single.name.is_none() {
					single.name = Some(format!("measure-{t}"));
				}
				async move {
					let res = run_one(single, env, config, verbose).await;
					(t, res)
				}
			});
			let results = futures_util::future::join_all(futures).await;
			let n_ok = results.iter().filter(|(_, r)| r.is_ok()).count();
			let n_err = results.len() - n_ok;
			eprintln!();
			eprintln!("{}", "Parallel deploy summary:".bold());
			for (target, r) in &results {
				match r {
					Ok(()) => eprintln!("  {} {}", "✓".green(), target),
					Err(e) => eprintln!("  {} {}: {:#}", "✗".red(), target, e),
				}
			}
			eprintln!();
			eprintln!("  {n_ok} ok / {n_err} failed");
			if n_err > 0 {
				bail!("{n_err} target(s) failed to deploy");
			}
			Ok(())
		}
	}
}

async fn run_one(args: DeployArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
	let image_only = args.image_only;

	// 1. Resolve workload source (unless --image-only).
	// `workload_boot_min` carries the raw workload manifest boot-disk-size string
	// (if any); the effective size is resolved later once the target is known.
	let (archive_path, workload_name, workload_version, archive_hash, workload_ports, workload_disks, workload_boot_min, base_image_mode, base_image_list, unmeasured_tar, unmeasured_data_paths): (_, _, _, _, _, _, Option<String>, _, _, _, Vec<String>);
	if image_only {
		archive_path = String::new();
		workload_name = String::new();
		workload_version = String::new();
		archive_hash = String::new();
		workload_ports = Vec::new();
		workload_disks = Vec::new();
		workload_boot_min = None;
		base_image_mode = String::new();
		base_image_list = Vec::new();
		unmeasured_tar = None;
		unmeasured_data_paths = Vec::<String>::new();
	} else {
		let resolved = resolve_workload(&args.source, &args.dir, env, args.skip_freshness_check)?;
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
		workload_boot_min = resolved.boot_disk_size.clone();
		base_image_mode = resolved.base_image_mode;
		base_image_list = resolved.base_image;
		// Collect unmeasured-data files: --unmeasured-data-dir takes precedence over workload dir.
		unmeasured_tar = if resolved.needs_unmeasured_data {
			let base_dir = args.unmeasured_data_dir.as_ref()
				.or(resolved.workload_dir.as_ref());
			if let Some(dir) = base_dir {
				if resolved.unmeasured_data_paths.is_empty() {
					eprintln!(
						"  {}: workload needs unmeasured-data but no path list available; \
						 provide files in --unmeasured-data-dir",
						"warning".yellow(),
					);
					None
				} else {
					collect_unmeasured_tar(&resolved.unmeasured_data_paths, dir)?
				}
			} else {
				eprintln!(
					"  {}: workload declares unmeasured-data but no source directory available; \
					 use --unmeasured-data-dir to provide one",
					"warning".yellow(),
				);
				None
			}
		} else {
			None
		};
		unmeasured_data_paths = resolved.unmeasured_data_paths;
		let ap = resolved.archive_path;
		let bytes = std::fs::read(&ap)
			.with_context(|| format!("failed to read archive: {}", ap.display()))?;
		archive_hash = format!("{:x}", Sha256::digest(&bytes));
		archive_path = ap.display().to_string();
	}

	// 2. Resolve target. The dispatcher (`run`) guarantees exactly one entry here.
	let target_name = args.target.first().map(|s| s.as_str()).ok_or_else(|| {
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
		PlatformKind::Aws => {
			// AWS targets need only a region, which is always present.
		}
	}

	// 3b. Resolve effective OS boot disk size.
	// Precedence: CLI --boot-disk-size > target.boot_disk_size > workload
	// manifest boot-disk-size > DEFAULT_BOOT_DISK_GB. Errors if the operator's
	// chosen size is below the workload's declared minimum, or below the
	// absolute floor (MIN_BOOT_DISK_GB). Wrapped in Some() to preserve the
	// downstream Option<u64> API.
	let boot_disk_size_gb = Some(resolve_boot_disk_size(
		args.boot_disk_size.as_deref(),
		target.boot_disk_size.as_deref(),
		workload_boot_min.as_deref(),
	)?);

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

	// 6. Build init env (references into [chains] and [keys]).
	let init_env_resolver = InitEnvResolver {
		cli_chain: args.chain.as_deref(),
		cli_owner_key: args.owner_key.as_deref(),
		cli_gas_wallet: args.gas_wallet.as_deref(),
		target: &target,
	};
	let init_env = init_env_resolver.build();

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
		PlatformKind::Gcp => {
			let project = provider_config.project.clone().ok_or_else(|| {
				anyhow::anyhow!(
					"provider '{}' is missing 'project' in [cloud.providers.{}]",
					target.provider,
					target.provider,
				)
			})?;
			Box::new(GcpProvider::new(project, provider_config.region.clone()))
		}
		PlatformKind::Azure => {
			let subscription = provider_config.subscription.clone().ok_or_else(|| {
				anyhow::anyhow!(
					"provider '{}' is missing 'subscription' in [cloud.providers.{}] — \
					 set it to the Azure subscription ID you intend to deploy into \
					 (atakit will pass --subscription to every az call)",
					target.provider,
					target.provider,
				)
			})?;
			Box::new(AzureProvider::new(subscription, provider_config.region.clone()))
		}
		PlatformKind::Aws => {
			Box::new(AwsProvider::new(provider_config.region.clone()))
		}
	};

	// 10. Generate plan.
	let deploy_opts = DeployOptions {
		instance_name: instance_name.clone(),
		target_name: target_name.to_string(),
		target: target.clone(),
		image_ref: image_ref.to_string(),
		source_image_path: resolved_image.source_path.clone(),
		source_image_certs_dir: resolved_image.certs_dir.clone(),
		archive_path: archive_path.clone(),
		archive_hash: archive_hash.clone(),
		workload_name: workload_name.clone(),
		workload_version: workload_version.clone(),
		init_env: init_env.clone(),
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
			// Non-storage fields don't depend on the hash — pass "".
			let names = AzureResourceNames::for_azure(&instance_name, image_ref, &provider_config.region, "");
			// storage_account is randomized per deploy; pull the actual name
			// out of the plan so what we print matches what's created.
			let storage = plan.steps.iter().find_map(|s| match s {
				DeployStep::UploadImageAzure { storage_account, .. } => Some(storage_account.clone()),
				_ => None,
			}).unwrap_or_else(|| names.storage_account.clone());
			if let Some(ref sub) = provider_config.subscription {
				eprintln!("  {:<15}{}", "Subscription:".dimmed(), sub);
			}
			eprintln!("  {:<15}{}", "Region:".dimmed(), provider_config.region);
			eprintln!("  {:<15}{}", "VM size:".dimmed(), target.vmtype);
			eprintln!("  {:<15}{}", "CC type:".dimmed(), resolved_cc);
			eprintln!("  {:<15}{}", "Image:".dimmed(), image_ref);
			eprintln!("  {:<15}{}", "RG:".dimmed(), names.resource_group);
			eprintln!("  {:<15}{}/{}", "Gallery:".dimmed(), names.gallery_rg, names.gallery);
			eprintln!("  {:<15}{}", "Storage:".dimmed(), storage);
			eprintln!("  {:<15}{}", "NSG:".dimmed(), names.nsg);
		}
		PlatformKind::Aws => {
			let names = atakit_cloud::naming::ResourceNames::for_aws(&instance_name, image_ref);
			eprintln!("  {:<15}{}", "Region:".dimmed(), provider_config.region);
			eprintln!("  {:<15}{}", "Instance type:".dimmed(), target.vmtype);
			eprintln!("  {:<15}{}", "CC type:".dimmed(), resolved_cc);
			eprintln!("  {:<15}{}", "Image:".dimmed(), image_ref);
			eprintln!("  {:<15}{}", "AMI name:".dimmed(), names.image);
			if resolved_image.source_path.is_some() {
				eprintln!("  {:<15}{}", "Bucket:".dimmed(), names.bucket);
			}
			eprintln!("  {:<15}{}", "Sec group:".dimmed(), names.firewall);
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
			PlatformKind::Aws => "gp3",
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

	// Chain config: surface BEFORE the operator confirms so the
	// effective registration policy (`required` / `optional` /
	// `off`) is visible — the portal can't change it after /init,
	// so a misconfigured deployment caught here saves a CVM cycle.
	// `init_env.chain` is just a name reference; the lookup /init
	// performs later (around line 450) is the same.
	let chain_for_summary = config.chains.get(&init_env.chain)
		.ok_or_else(|| anyhow::anyhow!(
			"chain '{}' not found in [chains]", init_env.chain
		))?;
	eprintln!("  {:<15}{}", "Chain:".dimmed(), init_env.chain);
	// `registration` default-when-unset matches the portal: "section
	// present, registration field absent → required". Surface that
	// so `off` / `optional` configurations stand out.
	let registration_label = chain_for_summary
		.registration
		.as_deref()
		.unwrap_or("required (default)");
	eprintln!("  {:<15}{}", "Submission:".dimmed(), registration_label);
	eprintln!("  {:<15}{}", "RPC:".dimmed(), chain_for_summary.rpc_url);
	eprintln!("  {:<15}{}", "Registry:".dimmed(), chain_for_summary.session_registry);

	if !metadata.is_empty() {
		for (k, v) in &metadata {
			eprintln!("  {:<15}{}={}", "Metadata:".dimmed(), k, v);
		}
	}
	if unmeasured_tar.is_some() {
		let dir_label = args.unmeasured_data_dir.as_ref()
			.map(|d| d.display().to_string())
			.unwrap_or_else(|| "(workload dir)".to_string());
		eprintln!("  {:<15}{} ({} path{})",
			"Unmeasured:".dimmed(),
			dir_label,
			unmeasured_data_paths.len(),
			if unmeasured_data_paths.len() == 1 { "" } else { "s" },
		);
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
		init_env: init_env.clone(),
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
		PlatformKind::Aws => {
			state.resources.aws = Some(AwsResources {
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
				| DeployStep::UploadImageAws { source_path: Some(_), .. }
		);
		if streams_output {
			eprintln!("  [{step_num}/{total}] {step}");
		} else {
			eprint!("  [{step_num}/{total}] {step}... ");
		}

		match step {
			DeployStep::WaitForPortal { timeout_secs } => {
				let ip = state
					.resources
					.gcp
					.as_ref()
					.and_then(|g| g.external_ip.as_ref())
					.or_else(|| state.resources.azure.as_ref().and_then(|a| a.external_ip.as_ref()))
					.or_else(|| state.resources.aws.as_ref().and_then(|a| a.external_ip.as_ref()))
					.ok_or_else(|| anyhow::anyhow!("no external IP available for agent wait"))?
					.clone();
				match init::wait_for_portal(&ip, 2024, *timeout_secs).await {
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
					.or_else(|| state.resources.aws.as_ref().and_then(|a| a.external_ip.as_ref()))
					.ok_or_else(|| anyhow::anyhow!("no external IP available for init"))?
					.clone();

				// Resolve chain config and key specs from the persisted init_env references.
				let chain_name = &init_env.chain;
				let chain = config.chains.get(chain_name)
					.ok_or_else(|| anyhow::anyhow!("chain '{chain_name}' not found in [chains]"))?;
				let owner_key_name = &init_env.owner_key;
				let owner_key_spec = config.keys.get(owner_key_name)
					.ok_or_else(|| anyhow::anyhow!("key '{owner_key_name}' not found in [keys]"))?;
				let gas_wallet_name = &init_env.gas_wallet;
				let gas_wallet_spec = config.keys.get(gas_wallet_name)
					.ok_or_else(|| anyhow::anyhow!("key '{gas_wallet_name}' not found in [keys]"))?;

				let init_config = InitConfig {
					platform: provider_config.platform.to_string(),
					chain: InitChainConfig {
						rpc_url: chain.rpc_url.clone(),
						session_registry: chain.session_registry.clone(),
						workload_registry: chain.workload_registry.clone()
							.ok_or_else(|| anyhow::anyhow!("workload_registry required in chain '{chain_name}'"))?,
						base_image_registry: chain.base_image_registry.clone()
							.ok_or_else(|| anyhow::anyhow!("base_image_registry required in chain '{chain_name}'"))?,
						expire_offset: chain.expire_offset,
						registration: chain.registration.clone(),
						chain_id: chain.chain_id,
					},
					owner_key: InitKeyConfig {
						mode: owner_key_spec.mode.to_string(),
						key_type: owner_key_spec.key_type.to_string(),
						private_key: Some(owner_key_spec.resolve(owner_key_name)?),
					},
					gas_wallet: InitKeyConfig {
						mode: gas_wallet_spec.mode.to_string(),
						key_type: gas_wallet_spec.key_type.to_string(),
						private_key: if gas_wallet_spec.mode == KeyMode::Provisioned {
							Some(gas_wallet_spec.resolve(gas_wallet_name)?)
						} else {
							None
						},
					},
				};

				match init::post_portal_init(&ip, 1024, ap, unmeasured_tar.as_deref(), &init_config).await {
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
				if matches!(step, DeployStep::CreateInstance { .. } | DeployStep::CreateInstanceAzure { .. } | DeployStep::CreateInstanceAws { .. }) {
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
					if let Some(ref aws) = state.resources.aws {
						let ip = aws.external_ip.as_deref().unwrap_or("-");
						let inst = aws.instance.as_deref().unwrap_or(&instance_name);
						eprintln!();
						eprintln!("  {:<12}{}", "VM:".dimmed(), inst.bold());
						eprintln!("  {:<12}{}", "IP:".dimmed(), ip);
						eprintln!("  {:<12}{}", "Region:".dimmed(), aws.region.as_str());
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
		.or_else(|| state.resources.aws.as_ref().and_then(|a| a.external_ip.clone()))
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
			// Post-deploy instructions: only resource_group is used, so no hash needed.
			let names = AzureResourceNames::for_azure(&instance_name, image_ref, &provider_config.region, "");
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
		PlatformKind::Aws => {
			let region = &provider_config.region;
			let names = atakit_cloud::naming::ResourceNames::for_aws(&instance_name, image_ref);
			let vm_id = state
				.resources
				.aws
				.as_ref()
				.and_then(|a| a.instance.as_deref())
				.unwrap_or("<instance-id>");
			eprintln!("    {:<12}{}", "Region:".dimmed(), region);
			eprintln!("    {:<12}{}", "AMI:".dimmed(), names.image);
			eprintln!("    {:<12}{}", "CC type:".dimmed(), resolved_cc);
			eprintln!();
			eprintln!("    {}:", "Serial console".dimmed());
			eprintln!("      aws ec2 get-console-output --region {region} --instance-id {vm_id} --latest");
			eprintln!();
			eprintln!("    {}:", "SSH".dimmed());
			eprintln!("      aws ec2-instance-connect ssh --region {region} --instance-id {vm_id}");
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

/// Absolute floor for OS boot disk size. The base image is assumed to be
/// ~1 GB; 2 GB leaves room for an ext4 /data partition on the tail.
const MIN_BOOT_DISK_GB: u64 = 2;

/// Default OS boot disk size when nothing is specified by the CLI flag,
/// target config, or workload manifest. Chosen to leave ~3 GB for /data
/// on a ~1 GB base image.
const DEFAULT_BOOT_DISK_GB: u64 = 4;

fn parse_source(source: &str, v: Option<&str>) -> Result<Option<u64>> {
	match v {
		None => Ok(None),
		Some(s) => parse_size_gb(s).map(Some).ok_or_else(|| {
			anyhow::anyhow!("invalid boot disk size {s:?} from {source} (expected e.g. \"100GB\", \"1TB\")")
		}),
	}
}

/// Resolve the effective OS boot disk size from (in precedence order):
/// CLI > target > workload minimum > [`DEFAULT_BOOT_DISK_GB`]. Errors if
/// the operator's chosen size (from CLI or target) is smaller than the
/// workload's declared minimum, or if the resolved size is below
/// [`MIN_BOOT_DISK_GB`].
fn resolve_boot_disk_size(
	cli: Option<&str>,
	target: Option<&str>,
	workload_min: Option<&str>,
) -> Result<u64> {
	let cli_gb = parse_source("--boot-disk-size", cli)?;
	let target_gb = parse_source("target.boot_disk_size", target)?;
	let workload_gb = parse_source("workload boot-disk-size", workload_min)?;

	let effective = cli_gb.or(target_gb).or(workload_gb).unwrap_or(DEFAULT_BOOT_DISK_GB);

	if let Some(m) = workload_gb {
		if effective < m {
			let source = if cli_gb == Some(effective) {
				"--boot-disk-size"
			} else {
				"target.boot_disk_size"
			};
			bail!(
				"{source} is {effective}GB but the workload declares a minimum of {m}GB. \
				 Either raise the boot disk size or lower the workload's boot-disk-size."
			);
		}
	}

	if effective < MIN_BOOT_DISK_GB {
		bail!(
			"boot disk size must be >= {MIN_BOOT_DISK_GB}GB (base image is assumed to be ~1GB \
			 and needs room for /data), got {effective}GB"
		);
	}

	Ok(effective)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn cli_wins_over_target_and_workload() {
		let got = resolve_boot_disk_size(Some("100GB"), Some("50GB"), Some("20GB")).unwrap();
		assert_eq!(got, 100);
	}

	#[test]
	fn target_wins_over_workload() {
		let got = resolve_boot_disk_size(None, Some("50GB"), Some("20GB")).unwrap();
		assert_eq!(got, 50);
	}

	#[test]
	fn workload_is_the_fallback() {
		let got = resolve_boot_disk_size(None, None, Some("20GB")).unwrap();
		assert_eq!(got, 20);
	}

	#[test]
	fn all_unset_yields_default() {
		let got = resolve_boot_disk_size(None, None, None).unwrap();
		assert_eq!(got, DEFAULT_BOOT_DISK_GB);
		assert_eq!(got, 4);
	}

	#[test]
	fn default_satisfies_the_hard_floor() {
		assert!(DEFAULT_BOOT_DISK_GB >= MIN_BOOT_DISK_GB);
	}

	#[test]
	fn workload_min_above_default_wins_over_default() {
		// Default is 4 GB, workload asks for 10 GB → workload wins.
		let got = resolve_boot_disk_size(None, None, Some("10GB")).unwrap();
		assert_eq!(got, 10);
	}

	#[test]
	fn cli_below_workload_minimum_errors() {
		let err = resolve_boot_disk_size(Some("10GB"), None, Some("50GB")).unwrap_err().to_string();
		assert!(err.contains("--boot-disk-size"), "{err}");
		assert!(err.contains("10GB") && err.contains("50GB"), "{err}");
	}

	#[test]
	fn target_below_workload_minimum_errors() {
		let err = resolve_boot_disk_size(None, Some("10GB"), Some("50GB")).unwrap_err().to_string();
		assert!(err.contains("target.boot_disk_size"), "{err}");
		assert!(err.contains("10GB") && err.contains("50GB"), "{err}");
	}

	#[test]
	fn cli_overrides_target_even_when_target_below_workload() {
		// CLI=100, target=10 (< workload min 50), workload=50. CLI wins, target < min
		// does not matter because CLI is the operator's actual choice.
		let got = resolve_boot_disk_size(Some("100GB"), Some("10GB"), Some("50GB")).unwrap();
		assert_eq!(got, 100);
	}

	#[test]
	fn below_hard_floor_errors_from_cli() {
		let err = resolve_boot_disk_size(Some("1GB"), None, None).unwrap_err().to_string();
		assert!(err.contains("2GB"), "{err}");
	}

	#[test]
	fn below_hard_floor_errors_from_workload() {
		let err = resolve_boot_disk_size(None, None, Some("1GB")).unwrap_err().to_string();
		assert!(err.contains("2GB"), "{err}");
	}

	#[test]
	fn image_only_path_still_enforces_floor() {
		// image-only: workload_min is None. 1 GB from CLI still rejected.
		let err = resolve_boot_disk_size(Some("1GB"), None, None).unwrap_err().to_string();
		assert!(err.contains("2GB"), "{err}");
	}

	#[test]
	fn bad_format_names_the_source() {
		let err = resolve_boot_disk_size(Some("garbage"), None, None).unwrap_err().to_string();
		assert!(err.contains("--boot-disk-size"), "{err}");
		let err = resolve_boot_disk_size(None, Some("garbage"), None).unwrap_err().to_string();
		assert!(err.contains("target.boot_disk_size"), "{err}");
		let err = resolve_boot_disk_size(None, None, Some("garbage")).unwrap_err().to_string();
		assert!(err.contains("workload boot-disk-size"), "{err}");
	}

	#[test]
	fn at_hard_floor_is_ok() {
		let got = resolve_boot_disk_size(Some("2GB"), None, None).unwrap();
		assert_eq!(got, 2);
	}

	#[test]
	fn equal_to_workload_minimum_is_ok() {
		let got = resolve_boot_disk_size(Some("50GB"), None, Some("50GB")).unwrap();
		assert_eq!(got, 50);
	}
}
