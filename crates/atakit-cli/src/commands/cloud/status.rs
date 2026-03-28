use anyhow::Result;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::StatusArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::ProcessRunner;
use atakit_core::Env;
use owo_colors::OwoColorize;

use crate::config::Config;
use super::resolve_instance;

pub async fn run(args: StatusArgs, env: &Env, _config: &Config) -> Result<()> {
	let (target_name, instance_name) =
		resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;

	let state = DeployState::load(&env.data_dir, &target_name, &instance_name)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	let mut live_ip: Option<String> = None;
	if args.live {
		let provider: Option<Box<dyn CloudProvider>> = match state.platform {
			atakit_cloud::PlatformKind::Gcp => {
				GcpProvider::from_state(&state).ok().map(|p| Box::new(p) as _)
			}
			atakit_cloud::PlatformKind::Azure => {
				AzureProvider::from_state(&state).ok().map(|p| Box::new(p) as _)
			}
		};
		if let Some(provider) = provider {
			let runner = ProcessRunner::default();
			live_ip = provider
				.get_instance_ip(&state, &runner)
				.await
				.ok()
				.flatten();
		}
	}

	// Display status.
	eprintln!(
		"  Instance:  {}",
		format!("{target_name}/{instance_name}").bold()
	);
	eprintln!(
		"  Workload:  {}:{}",
		state.workload_name,
		state.workload_version.dimmed()
	);
	eprintln!("  Platform:  {}", state.platform);
	eprintln!("  Image:     {}", state.image_ref);
	eprintln!(
		"  Created:   {}",
		state.created_at.format("%Y-%m-%d %H:%M:%S UTC")
	);
	eprintln!(
		"  Updated:   {}",
		state.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
	);

	match &state.status {
		DeployStatus::Deploying { step, total } => {
			eprintln!(
				"  Status:    {} deploying ({}/{})",
				"~".yellow(),
				step,
				total
			);
		}
		DeployStatus::Deployed { ip } => {
			let display_ip = live_ip.as_deref().unwrap_or(ip.as_str());
			eprintln!("  Status:    {} deployed", "*".green());
			eprintln!("  IP:        {display_ip}");
		}
		DeployStatus::Failed { step, message } => {
			eprintln!("  Status:    {} failed at: {step}", "x".red());
			eprintln!("  Error:     {message}");
		}
		DeployStatus::Destroying => {
			eprintln!("  Status:    {} destroying", "~".yellow());
		}
		DeployStatus::Destroyed => {
			eprintln!("  Status:    {} destroyed", "o".dimmed());
		}
	}

	// Show resources.
	if let Some(ref gcp) = state.resources.gcp {
		eprintln!();
		eprintln!("  {}", "Resources:".dimmed());
		if let Some(ref i) = gcp.instance {
			eprintln!("    Instance:  {i}");
		}
		if let Some(ref b) = gcp.bucket {
			eprintln!("    Bucket:    {b}");
		}
		if let Some(ref img) = gcp.image {
			eprintln!("    Image:     {img}");
		}
		if let Some(ref fw) = gcp.firewall_rule {
			eprintln!("    Firewall:  {fw}");
		}
		if !gcp.disks.is_empty() {
			eprintln!("    Disks:     {}", gcp.disks.join(", "));
		}
	}
	if let Some(ref az) = state.resources.azure {
		eprintln!();
		eprintln!("  {}", "Resources:".dimmed());
		if let Some(ref i) = az.instance {
			eprintln!("    Instance:  {i}");
		}
		if let Some(ref rg) = az.resource_group {
			eprintln!("    RG:        {rg}");
		}
		if let Some(ref nsg) = az.nsg {
			eprintln!("    NSG:       {nsg}");
		}
		if let Some(ref g) = az.gallery {
			eprintln!("    Gallery:   {g}");
		}
		if let Some(ref def) = az.image_definition {
			eprintln!("    Image def: {def}");
		}
		if let Some(ref sa) = az.storage_account {
			eprintln!("    Storage:   {sa}");
		}
		if !az.disks.is_empty() {
			eprintln!("    Disks:     {}", az.disks.join(", "));
		}
	}

	Ok(())
}
