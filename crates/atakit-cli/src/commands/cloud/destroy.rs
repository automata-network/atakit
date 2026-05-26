use anyhow::{bail, Result};
use atakit_cloud::aws::AwsProvider;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::DestroyArgs;
use atakit_cloud::cloud_images::CloudImages;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::plan::DestroyStep;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::ProcessRunner;
use atakit_core::Env;
use owo_colors::OwoColorize;

use super::resolve_instance;
use crate::config::Config;

/// Multi-instance dispatcher. Single instance → forward to `run_one`. Multiple
/// instances → fan out into a concurrent destroy (one async future per
/// instance, joined via `join_all`).
pub async fn run(mut args: DestroyArgs, env: &Env, config: &Config) -> Result<()> {
    let instances = std::mem::take(&mut args.instance);
    match instances.len() {
        0 => bail!("at least one instance is required"),
        1 => {
            args.instance = instances;
            run_one(args, env, config).await
        }
        _ => {
            // No interactive confirmation in multi mode -- N intermixed prompts
            // would be unusable.
            args.yes = true;
            eprintln!(
                "{} {} instance(s)...",
                "Destroying".dimmed(),
                instances.len().to_string().bold(),
            );
            let futures = instances.iter().cloned().map(|i| {
                let mut single = args.clone();
                single.instance = vec![i.clone()];
                async move {
                    let res = run_one(single, env, config).await;
                    (i, res)
                }
            });
            let results = futures_util::future::join_all(futures).await;
            let n_ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            let n_err = results.len() - n_ok;
            eprintln!();
            eprintln!("{}", "Parallel destroy summary:".bold());
            for (instance, r) in &results {
                match r {
                    Ok(()) => eprintln!("  {} {}", "✓".green(), instance),
                    Err(e) => eprintln!("  {} {}: {:#}", "✗".red(), instance, e),
                }
            }
            eprintln!();
            eprintln!("  {n_ok} ok / {n_err} failed");
            if n_err > 0 {
                bail!("{n_err} instance(s) failed to destroy");
            }
            Ok(())
        }
    }
}

async fn run_one(args: DestroyArgs, env: &Env, _config: &Config) -> Result<()> {
    let instance_arg = args
        .instance
        .first()
        .map(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("at least one instance is required"))?;
    let (target_name, instance_name) =
        resolve_instance(&env.data_dir, instance_arg, args.target.as_deref())?;

    let mut state = DeployState::load(&env.data_dir, &target_name, &instance_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let provider: Box<dyn CloudProvider> = match state.platform {
        atakit_cloud::PlatformKind::Gcp => {
            Box::new(GcpProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
        atakit_cloud::PlatformKind::Azure => {
            Box::new(AzureProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
        atakit_cloud::PlatformKind::Aws => {
            Box::new(AwsProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
    };

    // Image preservation: default is to keep the image so future deploys can
    // reuse it. `--clean-image` opts in to deletion, but we still auto-preserve
    // when any sibling deployment references the same image.
    let mut preserve = args.preserve.clone();
    let image_already_preserved = preserve.iter().any(|p| p == "image");
    if !args.clean_image {
        if !image_already_preserved {
            preserve.push("image".to_string());
        }
    } else if !state.image_ref.is_empty() {
        let all = atakit_cloud::state::list_deployments(&env.data_dir)
            .map_err(|e| anyhow::anyhow!("cannot scan deployments for shared image check: {e}"))?;
        let is_self =
            |o: &DeployState| o.target_name == target_name && o.instance_name == instance_name;
        let other_uses_image = all.iter().any(|other| {
            !is_self(other)
                && !matches!(other.status, DeployStatus::Destroyed)
                && other.image_ref == state.image_ref
                && other.provider_name == state.provider_name
        });
        if other_uses_image {
            eprintln!(
                "  {}: image '{}' is used by other deployments, preserving despite --clean-image",
                "note".dimmed(),
                state.image_ref,
            );
            if !image_already_preserved {
                preserve.push("image".to_string());
            }
        }
    }

    let destroy_opts = atakit_cloud::provider::DestroyOptions { preserve };

    let plan = provider
        .plan_destroy(&state, &destroy_opts)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Display deployment details.
    eprintln!("{}", "Deployment:".dimmed());
    eprintln!("  {:<15}{}", "Instance:".dimmed(), instance_name.bold());
    eprintln!("  {:<15}{}", "Target:".dimmed(), target_name);
    eprintln!("  {:<15}{}", "Platform:".dimmed(), state.platform);
    if let Some(ref g) = state.resources.gcp {
        eprintln!("  {:<15}{}", "Project:".dimmed(), g.project);
        eprintln!("  {:<15}{}", "Zone:".dimmed(), g.zone);
        if let Some(ref name) = g.instance {
            eprintln!("  {:<15}{}", "VM:".dimmed(), name);
        }
        if let Some(ref ip) = g.external_ip {
            eprintln!("  {:<15}{}", "IP:".dimmed(), ip);
        }
        if let Some(ref name) = g.image {
            eprintln!("  {:<15}{}", "Image:".dimmed(), name);
        }
        if let Some(ref name) = g.bucket {
            eprintln!("  {:<15}{}", "Bucket:".dimmed(), name);
        }
        if let Some(ref name) = g.firewall_rule {
            eprintln!("  {:<15}{}", "Firewall:".dimmed(), name);
        }
        if !g.disks.is_empty() {
            eprintln!("  {:<15}{}", "Disks:".dimmed(), g.disks.join(", "));
        }
    }
    if let Some(ref az) = state.resources.azure {
        eprintln!("  {:<15}{}", "Subscription:".dimmed(), az.subscription);
        eprintln!("  {:<15}{}", "Region:".dimmed(), az.region);
        if let Some(ref name) = az.instance {
            eprintln!("  {:<15}{}", "VM:".dimmed(), name);
        }
        if let Some(ref ip) = az.external_ip {
            eprintln!("  {:<15}{}", "IP:".dimmed(), ip);
        }
        if let Some(ref name) = az.resource_group {
            eprintln!("  {:<15}{}", "RG:".dimmed(), name);
        }
        if let Some(ref name) = az.nsg {
            eprintln!("  {:<15}{}", "NSG:".dimmed(), name);
        }
        if let Some(ref name) = az.gallery {
            eprintln!("  {:<15}{}", "Gallery:".dimmed(), name);
        }
        if !az.disks.is_empty() {
            eprintln!("  {:<15}{}", "Disks:".dimmed(), az.disks.join(", "));
        }
    }
    if let Some(ref aws) = state.resources.aws {
        eprintln!("  {:<15}{}", "Region:".dimmed(), aws.region);
        if let Some(ref name) = aws.instance {
            eprintln!("  {:<15}{}", "VM:".dimmed(), name);
        }
        if let Some(ref ip) = aws.external_ip {
            eprintln!("  {:<15}{}", "IP:".dimmed(), ip);
        }
        if let Some(ref name) = aws.ami {
            eprintln!("  {:<15}{}", "AMI:".dimmed(), name);
        }
        if let Some(ref name) = aws.bucket {
            eprintln!("  {:<15}{}", "Bucket:".dimmed(), name);
        }
        if let Some(ref name) = aws.security_group {
            eprintln!("  {:<15}{}", "Sec group:".dimmed(), name);
        }
    }
    if !state.workload_name.is_empty() {
        eprintln!(
            "  {:<15}{}:{}",
            "Workload:".dimmed(),
            state.workload_name,
            state.workload_version
        );
    }
    eprintln!();

    if plan.steps.is_empty() {
        DeployState::delete(&env.data_dir, &target_name, &instance_name)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        eprintln!("No resources to destroy. Cleaned up state file.");
        return Ok(());
    }

    // Display plan.
    eprintln!("{}", "Plan:".dimmed());
    for (i, step) in plan.steps.iter().enumerate() {
        eprintln!("  {}. {step}", i + 1);
    }
    eprintln!();

    if !args.preserve.is_empty() {
        eprintln!(
            "  {:<15}{}",
            "Preserving:".dimmed(),
            args.preserve.join(", ")
        );
        eprintln!();
    }

    // Confirm.
    if !args.yes {
        eprint!(
            "Destroy {}? [y/N] ",
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

    let runner = ProcessRunner::default();
    let total = plan.steps.len();

    for (i, step) in plan.steps.iter().enumerate() {
        eprint!("  [{}/{}] {step}... ", i + 1, total);
        match provider.execute_destroy_step(step, &runner, false).await {
            Ok(()) => {
                eprintln!("{}", "done".green());
                // Remove image from CloudImages tracking when the cloud
                // image is actually deleted (not preserved).
                if matches!(
                    step,
                    DestroyStep::DeleteImage { .. }
                        | DestroyStep::DeleteImageVersion { .. }
                        | DestroyStep::DeleteAmi { .. }
                ) && !state.provider_name.is_empty()
                {
                    match CloudImages::load(&env.data_dir) {
                        Ok(mut cloud_imgs) => {
                            cloud_imgs.remove(&state.image_ref, &state.provider_name);
                            if let Err(e) = cloud_imgs.save(&env.data_dir) {
                                tracing::warn!("failed to save cloud images state: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::warn!("failed to load cloud images state: {e}");
                        }
                    }
                }
            }
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
