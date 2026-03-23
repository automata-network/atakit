use anyhow::Result;
use atakit_cloud::cli::SerialArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::state::DeployState;
use atakit_cloud::ProcessRunner;
use atakit_core::Env;

use crate::config::Config;
use super::resolve_instance;

pub async fn run(args: SerialArgs, env: &Env, _config: &Config) -> Result<()> {
	let (target_name, instance_name) =
		resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;

	let state = DeployState::load(&env.data_dir, &target_name, &instance_name)
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	let provider = match state.platform {
		atakit_cloud::PlatformKind::Gcp => {
			GcpProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?
		}
		atakit_cloud::PlatformKind::Azure => {
			anyhow::bail!("Azure serial console is not yet implemented")
		}
	};

	let runner = ProcessRunner;
	let output = provider
		.get_serial_output(&state, &runner)
		.await
		.map_err(|e| anyhow::anyhow!("{e}"))?;

	print!("{output}");
	Ok(())
}
