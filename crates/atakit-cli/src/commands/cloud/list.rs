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
		.map(|s| {
			if s.workload_name.is_empty() {
				1
			} else {
				s.workload_name.len() + 1 + s.workload_version.len()
			}
		})
		.max()
		.unwrap_or(8)
		.max(8);
	let w_image = states
		.iter()
		.map(|s| s.image_ref.len())
		.max()
		.unwrap_or(5)
		.max(5);

	// Header.
	eprintln!(
		"{}",
		format!(
			"{:<w_inst$}  {:<w_target$}  {:<w_workload$}  {:<w_image$}  {:<18}  {}",
			"Instance", "Target", "Workload", "Image", "Status", "IP",
		)
		.dimmed()
	);

	for s in &states {
		let workload = if s.workload_name.is_empty() {
			"-".to_string()
		} else {
			format!("{}:{}", s.workload_name, s.workload_version)
		};

		let (status_symbol, status_plain) = match &s.status {
			DeployStatus::Deployed { .. } => ("*", "deployed".to_string()),
			DeployStatus::Deploying { step, total } => ("~", format!("deploying {step}/{total}")),
			DeployStatus::Failed { step, .. } => ("x", format!("failed {step}")),
			DeployStatus::Destroying => ("~", "destroying".to_string()),
			DeployStatus::Destroyed => ("o", "destroyed".to_string()),
		};
		// Pad the plain text first, then colorize, to avoid ANSI escape byte counting.
		let status_padded = format!("{status_symbol} {status_plain}");
		let status_col = format!("{:<18}", status_padded);
		let status_col = match &s.status {
			DeployStatus::Deployed { .. } => {
				let sym = "*".green().to_string();
				format!("{sym} {:<16}", status_plain)
			}
			DeployStatus::Deploying { .. } | DeployStatus::Destroying => {
				let sym = "~".yellow().to_string();
				format!("{sym} {:<16}", status_plain)
			}
			DeployStatus::Failed { .. } => {
				let sym = "x".red().to_string();
				format!("{sym} {:<16}", status_plain)
			}
			DeployStatus::Destroyed => {
				format!("{}", status_col.dimmed())
			}
		};

		let ip = match &s.status {
			DeployStatus::Deployed { ip } if !ip.is_empty() => ip.clone(),
			_ => "-".dimmed().to_string(),
		};

		eprintln!(
			"{:<w_inst$}  {:<w_target$}  {:<w_workload$}  {:<w_image$}  {}  {}",
			s.instance_name.bold(),
			s.target_name,
			workload,
			s.image_ref,
			status_col,
			ip,
		);
	}

	Ok(())
}
