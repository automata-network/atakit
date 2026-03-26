use anyhow::Result;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::SshArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::state::DeployState;
use atakit_core::Env;

use crate::config::Config;
use super::resolve_instance;

pub fn run(args: SshArgs, env: &Env, _config: &Config) -> Result<()> {
	let (target_name, instance_name) =
		resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;

	let state = DeployState::load(&env.data_dir, &target_name, &instance_name)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	let provider: Box<dyn CloudProvider> = match state.platform {
		atakit_cloud::PlatformKind::Gcp => {
			Box::new(GcpProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?)
		}
		atakit_cloud::PlatformKind::Azure => {
			Box::new(AzureProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?)
		}
	};

	let cmd = provider
		.ssh_command(&state)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	if cmd.is_empty() {
		anyhow::bail!("no SSH command available");
	}

	let status = std::process::Command::new(&cmd[0])
		.args(&cmd[1..])
		.status()?;

	std::process::exit(status.code().unwrap_or(1));
}
