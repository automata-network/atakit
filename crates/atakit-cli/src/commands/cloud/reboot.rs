use anyhow::{bail, Result};
use atakit_cloud::aws::{instance, AwsProvider};
use atakit_cloud::cli::RebootArgs;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::state::DeployState;
use atakit_cloud::{PlatformKind, ProcessRunner};
use atakit_core::Env;
use owo_colors::OwoColorize;

use super::resolve_instance;
use crate::config::Config;

pub async fn run(args: RebootArgs, env: &Env, _config: &Config) -> Result<()> {
    let (target_name, instance_name) =
        resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;
    let state = DeployState::load(&env.data_dir, &target_name, &instance_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if state.platform != PlatformKind::Aws {
        bail!(
            "`atakit cloud reboot` currently supports only AWS deployments; {target_name}/{instance_name} uses {}",
            state.platform
        );
    }

    let provider = AwsProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?;
    provider.check_deps().map_err(|e| anyhow::anyhow!("{e}"))?;
    let resources = state.resources.aws.as_ref().ok_or_else(|| {
        anyhow::anyhow!("deployment {target_name}/{instance_name} has no AWS resources")
    })?;
    let instance_id = resources.instance.as_deref().ok_or_else(|| {
        anyhow::anyhow!("deployment {target_name}/{instance_name} has no AWS instance ID")
    })?;

    eprintln!("{}", "Deployment:".dimmed());
    eprintln!("  {:<15}{}", "Instance:".dimmed(), instance_name.bold());
    eprintln!("  {:<15}{}", "Target:".dimmed(), target_name);
    eprintln!("  {:<15}{}", "Region:".dimmed(), resources.region);
    eprintln!("  {:<15}{}", "AWS instance:".dimmed(), instance_id);
    eprintln!();

    if !args.yes {
        eprint!(
            "Reboot {}? [y/N] ",
            format!("{target_name}/{instance_name}").bold()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let runner = ProcessRunner::default();
    instance::reboot_instance(&resources.region, instance_id, &runner)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    eprintln!();
    eprintln!(
        "  {} Reboot request accepted for {}/{}; current AWS instance status checks passed",
        "*".green(),
        target_name,
        instance_name.bold()
    );
    Ok(())
}
