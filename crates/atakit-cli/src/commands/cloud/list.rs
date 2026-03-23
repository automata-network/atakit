use anyhow::Result;
use atakit_cloud::cli::ListArgs;
use atakit_cloud::state::{self, DeployStatus};
use atakit_core::Env;
use owo_colors::OwoColorize;

use crate::config::Config;

pub async fn run(args: ListArgs, env: &Env, _config: &Config) -> Result<()> {
	let all_states =
		state::list_deployments(&env.data_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

	let states: Vec<_> = if let Some(ref target) = args.target {
		all_states
			.into_iter()
			.filter(|s| s.target_name == *target)
			.collect()
	} else {
		all_states
	};

	if states.is_empty() {
		eprintln!("No deployments found.");
		return Ok(());
	}

	// Compute column widths.
	let w_inst = states
		.iter()
		.map(|s| s.instance_name.len())
		.max()
		.unwrap_or(8)
		.max(8);
	let w_target = states
		.iter()
		.map(|s| s.target_name.len())
		.max()
		.unwrap_or(6)
		.max(6);
	let w_workload = states
		.iter()
		.map(|s| s.workload_name.len() + 1 + s.workload_version.len())
		.max()
		.unwrap_or(8)
		.max(8);

	// Header.
	eprintln!(
		"{}",
		format!(
			"{:<w_inst$}  {:<w_target$}  {:<w_workload$}  {:<18}  {}",
			"Instance", "Target", "Workload", "Status", "IP",
		)
		.dimmed()
	);

	for s in &states {
		let workload = format!("{}:{}", s.workload_name, s.workload_version);
		let (status_symbol, status_text) = match &s.status {
			DeployStatus::Deployed { .. } => ("*".green().to_string(), "deployed".to_string()),
			DeployStatus::Deploying { step, total } => {
				("~".yellow().to_string(), format!("deploying {step}/{total}"))
			}
			DeployStatus::Failed { step, .. } => {
				("x".red().to_string(), format!("failed {step}"))
			}
			DeployStatus::Destroying => ("~".yellow().to_string(), "destroying".to_string()),
			DeployStatus::Destroyed => ("o".dimmed().to_string(), "destroyed".to_string()),
		};
		let status_col = format!("{status_symbol} {status_text}");

		let ip = match &s.status {
			DeployStatus::Deployed { ip } if !ip.is_empty() => ip.clone(),
			_ => "-".dimmed().to_string(),
		};

		eprintln!(
			"{:<w_inst$}  {:<w_target$}  {:<w_workload$}  {:<18}  {}",
			s.instance_name.bold(),
			s.target_name,
			workload,
			status_col,
			ip,
		);
	}

	Ok(())
}
