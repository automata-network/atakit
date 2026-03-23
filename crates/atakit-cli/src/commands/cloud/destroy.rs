use anyhow::{Result, bail};
use atakit_cloud::cli::DestroyArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::ProcessRunner;
use atakit_core::Env;
use owo_colors::OwoColorize;

use crate::config::Config;
use super::resolve_instance;

pub async fn run(args: DestroyArgs, env: &Env, _config: &Config) -> Result<()> {
	let (target_name, instance_name) =
		resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;

	let mut state = DeployState::load(&env.data_dir, &target_name, &instance_name)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	let provider: Box<dyn CloudProvider> = match state.platform {
		atakit_cloud::PlatformKind::Gcp => {
			Box::new(GcpProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?)
		}
		atakit_cloud::PlatformKind::Azure => bail!("Azure support is not yet implemented"),
	};

	let destroy_opts = atakit_cloud::provider::DestroyOptions {
		preserve: args.preserve.clone(),
		delete_image: args.delete_image,
	};

	let plan = provider
		.plan_destroy(&state, &destroy_opts)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	if plan.steps.is_empty() {
		DeployState::delete(&env.data_dir, &target_name, &instance_name)
			.map_err(|e| anyhow::anyhow!("{e}"))?;
		eprintln!("No resources to destroy for {target_name}/{instance_name}.");
		eprintln!(
			"  {} Cleaned up {}/{}",
			"o".dimmed(),
			target_name,
			instance_name.bold(),
		);
		return Ok(());
	}

	// Display plan.
	eprintln!("{}", "Destroy plan:".dimmed());
	for (i, step) in plan.steps.iter().enumerate() {
		eprintln!("  {}. {step}", i + 1);
	}
	eprintln!();

	// Confirm.
	if !args.yes {
		eprint!(
			"Destroy deployment {}? [y/N] ",
			format!("{target_name}/{instance_name}").bold()
		);
		let mut input = String::new();
		std::io::stdin().read_line(&mut input)?;
		if !input.trim().eq_ignore_ascii_case("y") {
			eprintln!("Aborted.");
			return Ok(());
		}
	}

	state
		.set_status(DeployStatus::Destroying, &env.data_dir)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	let runner = ProcessRunner;
	let total = plan.steps.len();

	for (i, step) in plan.steps.iter().enumerate() {
		eprint!("  [{}/{}] {step}... ", i + 1, total);
		match provider.execute_destroy_step(step, &runner, false).await {
			Ok(()) => eprintln!("{}", "done".green()),
			Err(e) => {
				eprintln!("{}", "failed".red());
				eprintln!("  warning: {e}");
			}
		}
	}

	DeployState::delete(&env.data_dir, &target_name, &instance_name)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	eprintln!();
	eprintln!(
		"  {} Destroyed {}/{}",
		"o".dimmed(),
		target_name,
		instance_name.bold(),
	);

	Ok(())
}
