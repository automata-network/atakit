use anyhow::{Result, bail};
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::UploadImageArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::plan::DeployStep;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::{AzureResourceNames, PlatformKind, ProcessRunner};
use atakit_core::Env;
use owo_colors::OwoColorize;

use crate::config::Config;
use super::resolve_image;

pub async fn run(args: UploadImageArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
	// 1. Resolve target.
	let target = config
		.cloud
		.targets
		.get(&args.target)
		.ok_or_else(|| anyhow::anyhow!("target '{}' not found in config", args.target))?
		.clone();

	match target.platform {
		PlatformKind::Gcp => {
			if target.project.is_none() {
				bail!(
					"GCP target '{}' requires 'project' (set in config or ATAKIT_GCP_PROJECT)",
					args.target,
				);
			}
		}
		PlatformKind::Azure => {
			if target.subscription.is_none() {
				bail!(
					"Azure target '{}' requires 'subscription' (set in config)",
					args.target,
				);
			}
		}
	}

	// 2. Resolve image.
	let resolved = resolve_image(&args.image, &target.platform, env)?;
	let source_path = resolved.source_path.ok_or_else(|| {
		anyhow::anyhow!(
			"'{}' refers to an existing cloud image name, not a local image to upload. \
			 Use repository:tag or a .atabi file path.",
			args.image,
		)
	})?;

	// 3. Create provider.
	let provider: Box<dyn CloudProvider> = match target.platform {
		PlatformKind::Gcp => Box::new(GcpProvider::new(
			target.project.clone().unwrap(),
			target.region.clone(),
		)),
		PlatformKind::Azure => Box::new(AzureProvider::new(
			target.subscription.clone().unwrap(),
			target.region.clone(),
		)),
	};

	// 4. Show plan and confirm.
	eprintln!("{}", "Plan:".dimmed());
	match target.platform {
		PlatformKind::Gcp => {
			let names = atakit_cloud::naming::ResourceNames::for_gcp("upload", &resolved.display_name);
			eprintln!("  1. Check dependencies (gcloud)");
			eprintln!("  2. Upload image to GCE");
			eprintln!();
			eprintln!("{}", "Configuration:".dimmed());
			if let Some(ref project) = target.project {
				eprintln!("  {:<15}{}", "Project:".dimmed(), project);
			}
			eprintln!("  {:<15}{}", "Zone:".dimmed(), target.region);
			eprintln!("  {:<15}{}", "CC type:".dimmed(), target.cc_type);
			eprintln!("  {:<15}{}", "Image:".dimmed(), resolved.display_name);
			eprintln!("  {:<15}{}", "GCE name:".dimmed(), names.image);
			eprintln!("  {:<15}{}", "Bucket:".dimmed(), names.bucket);
			eprintln!("  {:<15}{}", "Disk image:".dimmed(), source_path);
			if args.force {
				eprintln!("  {:<15}yes (will delete existing)", "Force:".dimmed());
			}
		}
		PlatformKind::Azure => {
			let names = AzureResourceNames::for_azure("upload", &resolved.display_name, &target.region);
			eprintln!("  1. Check dependencies (az)");
			eprintln!("  2. Create resource group");
			eprintln!("  3. Upload image to gallery");
			eprintln!();
			eprintln!("{}", "Configuration:".dimmed());
			if let Some(ref sub) = target.subscription {
				eprintln!("  {:<15}{}", "Subscription:".dimmed(), sub);
			}
			eprintln!("  {:<15}{}", "Region:".dimmed(), target.region);
			eprintln!("  {:<15}{}", "CC type:".dimmed(), target.cc_type);
			eprintln!("  {:<15}{}", "Image:".dimmed(), resolved.display_name);
			eprintln!("  {:<15}{}", "Gallery:".dimmed(), format_args!("{}/{}", names.gallery_rg, names.gallery));
			eprintln!("  {:<15}{}", "Definition:".dimmed(), names.image_definition);
			eprintln!("  {:<15}{}", "Disk image:".dimmed(), source_path);
			if args.force {
				eprintln!("  {:<15}yes (will delete existing)", "Force:".dimmed());
			}
		}
	}
	eprintln!();

	if !args.yes {
		eprint!("Proceed? [y/N] ");
		let mut input = String::new();
		std::io::stdin().read_line(&mut input)?;
		if !input.trim().eq_ignore_ascii_case("y") {
			eprintln!("Aborted.");
			return Ok(());
		}
	}

	// 5. Execute steps.
	let runner = ProcessRunner;

	match target.platform {
		PlatformKind::Gcp => {
			let names = atakit_cloud::naming::ResourceNames::for_gcp("upload", &resolved.display_name);

			eprint!("  [1/2] Check dependencies... ");
			provider.execute_step(&DeployStep::CheckDeps, &runner, verbose).await?;
			eprintln!("{}", "done".green());

			eprintln!("  [2/2] Upload image");
			let upload_step = DeployStep::UploadImage {
				bucket: names.bucket.clone(),
				image_name: names.image.clone(),
				source_path: Some(source_path),
				force: args.force,
				cc_type: target.cc_type,
			};
			provider.execute_step(&upload_step, &runner, verbose).await?;
			eprintln!("  [2/2] {}", "done".green());

			eprintln!();
			eprintln!("{}", "==> Image uploaded!".green().bold());
			eprintln!();
			eprintln!("    {:<12}{}", "GCE image:".dimmed(), names.image);
			if let Some(ref project) = target.project {
				eprintln!("    {:<12}{}", "Project:".dimmed(), project);
			}
			eprintln!();
			eprintln!(
				"    Use this image in deploy with: {}",
				format!("--image {}", names.image).bold(),
			);
		}
		PlatformKind::Azure => {
			let names = AzureResourceNames::for_azure("upload", &resolved.display_name, &target.region);

			eprint!("  [1/3] Check dependencies... ");
			provider.execute_step(&DeployStep::CheckDeps, &runner, verbose).await?;
			eprintln!("{}", "done".green());

			eprint!("  [2/3] Create resource group... ");
			provider.execute_step(
				&DeployStep::CreateResourceGroup {
					name: names.resource_group.clone(),
					region: target.region.clone(),
				},
				&runner,
				verbose,
			).await?;
			eprintln!("{}", "done".green());

			eprintln!("  [3/3] Upload image to gallery");
			let upload_step = DeployStep::UploadImageAzure {
				resource_group: names.resource_group.clone(),
				storage_account: names.storage_account.clone(),
				gallery_rg: names.gallery_rg.clone(),
				gallery: names.gallery.clone(),
				image_definition: names.image_definition.clone(),
				image_version: names.image_version.clone(),
				source_path: Some(source_path),
				cc_type: target.cc_type,
				force: args.force,
			};
			provider.execute_step(&upload_step, &runner, verbose).await?;
			eprintln!("  [3/3] {}", "done".green());

			eprintln!();
			eprintln!("{}", "==> Image uploaded!".green().bold());
			eprintln!();
			eprintln!("    {:<12}{}", "Gallery:".dimmed(), format_args!("{}/{}", names.gallery_rg, names.gallery));
			eprintln!("    {:<12}{}", "Definition:".dimmed(), names.image_definition);
			eprintln!("    {:<12}{}", "Version:".dimmed(), names.image_version);
			eprintln!();
			eprintln!(
				"    Use this image in deploy with: {}",
				format!("--image {}", names.image_definition).bold(),
			);
		}
	}
	eprintln!();

	Ok(())
}
