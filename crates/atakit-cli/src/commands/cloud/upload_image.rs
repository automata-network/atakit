use anyhow::{Result, bail};
use atakit_cloud::cli::UploadImageArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::plan::DeployStep;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::PlatformKind;
use atakit_cloud::ProcessRunner;
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
		PlatformKind::Azure => bail!("Azure support is not yet implemented"),
	}

	// 2. Resolve image.
	let resolved = resolve_image(&args.image, &target.platform, env)?;
	let source_path = resolved.source_path.ok_or_else(|| {
		anyhow::anyhow!(
			"'{}' refers to an existing GCE image name, not a local image to upload. \
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
		PlatformKind::Azure => bail!("Azure support is not yet implemented"),
	};

	let names = atakit_cloud::naming::ResourceNames::for_gcp("upload", &resolved.display_name);

	// 4. Show plan and confirm.
	eprintln!("{}", "Plan:".dimmed());
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

	// Step 1: CheckDeps.
	eprint!("  [1/2] Check dependencies... ");
	let check_step = DeployStep::CheckDeps;
	provider.execute_step(&check_step, &runner, verbose).await?;
	eprintln!("{}", "done".green());

	// Step 2: UploadImage.
	eprintln!("  [2/2] Upload image");
	let upload_step = DeployStep::UploadImage {
		bucket: names.bucket.clone(),
		image_name: names.image.clone(),
		source_path: Some(source_path),
		force: args.force,
		cc_type: target.cc_type,
	};
	provider
		.execute_step(&upload_step, &runner, verbose)
		.await?;
	eprintln!("  [2/2] {}", "done".green());

	// 6. Summary.
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
	eprintln!();

	Ok(())
}
