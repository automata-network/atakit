use anyhow::{bail, Result};
use atakit_cloud::aws::AwsProvider;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::DestroyArgs;
use atakit_cloud::cloud_images::CloudImages;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::plan::DestroyStep;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::qemu::QemuProvider;
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
    run_one_with_runner(args, env, &ProcessRunner::default()).await
}

async fn run_one_with_runner(
    args: DestroyArgs,
    env: &Env,
    runner: &dyn atakit_cloud::CommandRunner,
) -> Result<()> {
    run_one_with_prompt(args, env, runner, &prompt_user).await
}

fn prompt_user(message: &str) -> std::io::Result<bool> {
    use std::io::{IsTerminal, Write};
    // Parallel destroys must never consume each other's answers.
    static PROMPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = PROMPT_LOCK
        .lock()
        .map_err(|_| std::io::Error::other("confirmation lock failed"))?;
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{message}");
    std::io::stderr().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

async fn run_one_with_prompt(
    args: DestroyArgs,
    env: &Env,
    runner: &dyn atakit_cloud::CommandRunner,
    prompt: &dyn Fn(&str) -> std::io::Result<bool>,
) -> Result<()> {
    let instance_arg = args
        .instance
        .first()
        .map(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("at least one instance is required"))?;
    let (target_name, instance_name) =
        resolve_instance(&env.data_dir, instance_arg, args.target.as_deref())?;
    let _deployment_lock =
        atakit_cloud::resume::DeploymentLock::acquire(&env.data_dir, &target_name, &instance_name)?;

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
        atakit_cloud::PlatformKind::Qemu => {
            Box::new(QemuProvider::from_state(&state).map_err(|e| anyhow::anyhow!("{e}"))?)
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

    // Recheck transient errors, but do not forget an attachment lookup that
    // never succeeded. A missing VM on retry cannot recover its disk list.
    state
        .cleanup
        .remaining
        .retain(|key, _| key == "VM attachment inventory");
    state.save(&env.data_dir)?;
    atakit_cloud::provisioning_cleanup::reconcile_records(&env.data_dir, &mut state, runner)
        .await?;

    match atakit_cloud::provisioning_cleanup::record_attachments(&mut state, runner).await {
        Ok(true) => {
            state.cleanup.remaining.remove("VM attachment inventory");
        }
        Ok(false) => {}
        Err(e) => {
            state
                .cleanup
                .remaining
                .insert("VM attachment inventory".into(), e.to_string());
        }
    }
    state.save(&env.data_dir)?;

    let preserve_disks = destroy_opts.preserve.iter().any(|v| v == "disks");
    let disk_review = atakit_cloud::provisioning_cleanup::inspect_unrecorded_disks(
        &mut state,
        preserve_disks,
        runner,
    )
    .await?;
    let mut disk_approval_missing = !disk_review.pending.is_empty();

    let mut plan = provider
        .plan_destroy(&state, &destroy_opts)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Err(error) =
        atakit_cloud::provisioning_cleanup::add_boot_disk_step(&state, &mut plan.steps)
    {
        state
            .cleanup
            .remaining
            .insert("boot disk".into(), error.to_string());
    }
    plan.steps = atakit_cloud::provisioning_cleanup::separate_steps(plan.steps);
    atakit_cloud::provisioning_cleanup::add_confirmed_disk_steps(
        &state,
        &mut plan.steps,
        destroy_opts.preserve.iter().any(|v| v == "disks"),
    );
    plan.steps.retain(|step| {
        !state
            .cleanup
            .completed
            .contains(&atakit_cloud::provisioning_cleanup::step_key(step))
    });

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
    if let Some(ref q) = state.resources.qemu {
        eprintln!("  {:<15}local (qemu)", "Mode:".dimmed());
        eprintln!("  {:<15}{}", "PID:".dimmed(), q.pid);
        if !q.instance_dir.is_empty() {
            eprintln!("  {:<15}{}", "Dir:".dimmed(), q.instance_dir);
        }
        if !q.data_disks.is_empty() {
            eprintln!("  {:<15}{}", "Disks:".dimmed(), q.data_disks.len());
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

    for problem in &disk_review.problems {
        eprintln!("  {problem}; disk retained.");
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

    // Ask before saving any new disk approvals.
    if !args.yes && !prompt(&format!("Destroy {target_name}/{instance_name}? [y/N] "))? {
        eprintln!("Aborted.");
        return Ok(());
    }
    if !disk_review.pending.is_empty() {
        let mut message = format!("\nDeployment: {target_name}/{instance_name}\nThese disks have no saved creation records:\n");
        for (name, disk) in &disk_review.pending {
            let role = if disk.boot { "boot disk" } else { "data disk" };
            message.push_str(&format!("  {name} ({role})\n"));
        }
        message.push_str("Delete these disks permanently? [y/N] ");
        if prompt(&message)? {
            atakit_cloud::provisioning_cleanup::approve_disks(
                &mut state,
                &disk_review.pending,
                runner,
            )
            .await?;
            disk_approval_missing = false;
            atakit_cloud::provisioning_cleanup::add_confirmed_disk_steps(
                &state,
                &mut plan.steps,
                preserve_disks,
            );
            plan.steps.retain(|step| {
                !state
                    .cleanup
                    .completed
                    .contains(&atakit_cloud::provisioning_cleanup::step_key(step))
            });
        } else {
            eprintln!("  Unrecorded disks were not approved and will be retained. Rerun cloud destroy in an interactive terminal to approve them; --yes does not approve these disks.");
        }
    }

    state.cleanup.started = true;
    state
        .set_status(DeployStatus::Destroying, &env.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let total = plan.steps.len();
    let mut failures = Vec::new();

    for (i, step) in plan.steps.iter().enumerate() {
        eprint!("  [{}/{}] {step}... ", i + 1, total);
        let mut vm_deletion_attempted = false;
        let result = async {
            if !atakit_cloud::provisioning_cleanup::before_step(
                &state,
                step,
                destroy_opts.preserve.iter().any(|v| v == "disks"),
                runner,
            )
            .await?
            {
                return Ok(());
            }
            if let DestroyStep::DeleteAmi { name } = step {
                atakit_cloud::provisioning_cleanup::delete_aws_image(
                    &mut state,
                    &env.data_dir,
                    name,
                    runner,
                )
                .await
            } else {
                vm_deletion_attempted = matches!(step, DestroyStep::DeleteInstance { .. });
                provider.execute_destroy_step(step, runner, false).await
            }
        }
        .await;
        match result {
            Ok(()) => {
                eprintln!("{}", "done".green());
                atakit_cloud::provisioning_cleanup::completed(&mut state, step);
                state.save(&env.data_dir)?;
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
                eprintln!("  error: {e}");
                let mut vm_deletion_confirmed = false;
                if matches!(step, DestroyStep::DeleteInstance { .. }) {
                    match atakit_cloud::provisioning_cleanup::stop_verified_vm(&state, runner).await
                    {
                        Ok(power)
                            if vm_deletion_attempted
                                && (power == "absent"
                                    || (state.platform == atakit_cloud::PlatformKind::Aws
                                        && power == "terminated")) =>
                        {
                            // A delete can succeed even when its reply is lost.
                            // Complete the existing step only after its checks
                            // passed and we actually attempted deletion.
                            atakit_cloud::provisioning_cleanup::completed(&mut state, step);
                            vm_deletion_confirmed = true;
                            eprintln!(
                                "  VM deletion confirmed after the request returned an error."
                            );
                        }
                        Ok(power) => {
                            eprintln!("  VM power state: {power}; retained disks and IP addresses may still incur charges.");
                            state.cleanup.vm_power = Some(power);
                        }
                        Err(stop_error) => {
                            eprintln!("  Could not confirm VM shutdown: {stop_error}. Compute charges may continue.");
                            state.cleanup.vm_power = Some(format!("unknown: {stop_error}"));
                        }
                    }
                }
                if !vm_deletion_confirmed {
                    failures.push(format!("{step}: {e}"));
                    state
                        .cleanup
                        .remaining
                        .insert(step.to_string(), e.to_string());
                }
                state.save(&env.data_dir)?;
            }
        }
    }

    if let Err(e) = atakit_cloud::provisioning_cleanup::report_remaining(
        &mut state,
        &destroy_opts.preserve,
        runner,
    )
    .await
    {
        state.cleanup.remaining.insert(
            "resource inventory".into(),
            format!("could not list remaining resources: {e}"),
        );
        failures.push(format!("resource inventory: {e}"));
    }
    let unresolved = atakit_cloud::provisioning_cleanup::has_unresolved(&state);
    if !state.cleanup.remaining.is_empty() {
        eprintln!("\nResources left behind:");
        for (resource, reason) in &state.cleanup.remaining {
            eprintln!("  {resource}: {reason}");
        }
    }
    if destroy_opts.preserve.iter().any(|v| v == "image")
        || state.platform == atakit_cloud::PlatformKind::Azure
    {
        eprintln!(
            "  Shared image resources retained: {} (use atakit image rm to remove them).",
            state.image_ref
        );
        if let Some(a) = &state.resources.aws {
            if let Some(bucket) = &a.bucket {
                eprintln!("  Preserved image bucket: {bucket}");
            }
        }
        if let Some(g) = &state.resources.gcp {
            if let Some(bucket) = &g.bucket {
                eprintln!("  Preserved image bucket: {bucket}");
            }
        }
        if let Some(a) = &state.resources.azure {
            if let Some(group) = &a.gallery_rg {
                eprintln!("  Shared image resource group: {group}");
            }
            if let Some(account) = &a.storage_account {
                eprintln!("  Shared image storage account: {account}");
            }
        }
    }
    state.save(&env.data_dir)?;
    let unplanned_remaining = state.cleanup.remaining.iter().any(|(resource, reason)| {
        !reason.starts_with("preserved") && !resource.starts_with("resource group ")
    });
    if !failures.is_empty() || unresolved || unplanned_remaining {
        let guidance = if disk_approval_missing {
            format!("Unrecorded disks require interactive approval. Run atakit cloud destroy {target_name}/{instance_name} in an interactive terminal and answer the disk deletion prompt. --yes alone does not approve these disks.")
        } else {
            format!("After resolving the reported errors, retry with atakit cloud destroy {target_name}/{instance_name}. A retry cannot supply missing ownership evidence or authorize replacement resources.")
        };
        bail!("cleanup incomplete for {target_name}/{instance_name}; local state retained. {guidance} {}", failures.join("; "));
    }

    atakit_cloud::init_auth::retire(&mut state, &env.data_dir).map_err(anyhow::Error::msg)?;
    if let Some(record) = &state.initialization {
        atakit_cloud::resume::remove_inputs(&env.data_dir, record)?;
    }
    // An empty group or an operator-owned address needs no future Atakit
    // deletion. Do not keep an active deployment that blocks name reuse.
    let needs_tracking = state.cleanup.remaining.iter().any(|(resource, reason)| {
        !resource.starts_with("reserved IP ")
            && !(resource.starts_with("resource group ")
                && reason.starts_with("empty group retained"))
    });
    if !needs_tracking {
        DeployState::delete(&env.data_dir, &target_name, &instance_name)?;
    } else {
        state.set_status(DeployStatus::Destroyed, &env.data_dir)?;
        eprintln!("  Local state retained so the remaining resources stay recorded.");
    }

    eprintln!();
    eprintln!(
        "  {} Cleanup completed for {}/{}",
        "o".dimmed(),
        target_name,
        instance_name.bold(),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    mod deletion;
    mod inventory;
    mod legacy_disks;
    use atakit_cloud::{CloudError, CommandOutput, CommandRunner, NewDeployParams, PlatformKind};
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };

    struct Runner {
        calls: Mutex<Vec<Vec<String>>>,
        fail_first: AtomicBool,
    }
    #[async_trait::async_trait]
    impl CommandRunner for Runner {
        async fn gcp_api(
            &self,
            method: &str,
            _: &str,
            _: Option<&Value>,
        ) -> Result<Value, CloudError> {
            assert_eq!(method, "GET", "destroy must not create anything");
            Err(CloudError::State {
                message: "original operation unavailable".into(),
            })
        }
        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            self.calls.lock().unwrap().push(
                std::iter::once(program)
                    .chain(args.iter().copied())
                    .map(str::to_owned)
                    .collect(),
            );
            if args.starts_with(&["compute", "instances"]) {
                return Err(CloudError::CommandFailed {
                    program: program.into(),
                    args: args.join(" "),
                    stderr: "instance was not found".into(),
                    code: Some(1),
                });
            }
            let one = args.contains(&"one") || args.contains(&"vol-one");
            let deleting = args.contains(&"delete") || args.contains(&"delete-volume");
            if one && deleting && self.fail_first.load(Ordering::SeqCst) {
                return Err(CloudError::CommandFailed {
                    program: program.into(),
                    args: args.join(" "),
                    stderr: "simulated deletion failure".into(),
                    code: Some(1),
                });
            }
            let value = if args.contains(&"describe-volumes") {
                json!({"Volumes":[{"VolumeId":if one {"vol-one"}else{"vol-two"},"VolumeType":"gp3","Size":8,"State":"available","Attachments":[]}]})
            } else if args.starts_with(&["compute", "disks", "describe"]) {
                json!({"id":if one {"1"}else{"2"},"type":"pd-balanced","sizeGb":"8"})
            } else if args.starts_with(&["disk", "show"]) {
                json!({"id":"resource-id","uniqueId":if one {"1"}else{"2"},"sku":{"name":"StandardSSD_LRS"},"diskSizeGb":8})
            } else if args.starts_with(&["resource", "list"]) {
                json!([])
            } else {
                assert!(
                    deleting || args.contains(&"wait"),
                    "unexpected call {program} {args:?}"
                );
                json!({})
            };
            Ok(CommandOutput {
                status: 0,
                stdout: value.to_string(),
                stderr: String::new(),
            })
        }
        async fn run_stream(
            &self,
            _: &str,
            _: &[&str],
            _: bool,
        ) -> Result<CommandOutput, CloudError> {
            panic!("unexpected stream")
        }
    }

    fn fixture(platform: PlatformKind) -> (tempfile::TempDir, Env, DeployState) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env {
            data_dir: dir.path().join("data"),
            config_dir: dir.path().join("config"),
            cache_dir: dir.path().join("cache"),
            image_dir: dir.path().join("images"),
            workload_dir: dir.path().join("workloads"),
        };
        let mut state = DeployState::new(NewDeployParams {
            instance_name: "vm".into(),
            target_name: "target".into(),
            provider_name: "provider".into(),
            platform,
            workload_publisher: "publisher".into(),
            workload_name: "app".into(),
            workload_version: "v1".into(),
            image_ref: "image".into(),
            base_image_ref: None,
            archive_path: String::new(),
            archive_hash: String::new(),
            init_env: Default::default(),
            portal_ports: Default::default(),
            total_steps: 1,
        });
        state.provisioning.started = true;
        match platform {
            PlatformKind::Aws => {
                state.resources.aws = Some(atakit_cloud::AwsResources {
                    region: "region".into(),
                    disks: vec!["vol-one".into(), "vol-two".into()],
                    ..Default::default()
                })
            }
            PlatformKind::Gcp => {
                state.resources.gcp = Some(atakit_cloud::GcpResources {
                    project: "project".into(),
                    zone: "zone".into(),
                    disks: vec!["one".into(), "two".into()],
                    ..Default::default()
                })
            }
            PlatformKind::Azure => {
                state.resources.azure = Some(atakit_cloud::AzureResources {
                    subscription: "sub".into(),
                    region: "region".into(),
                    resource_group: Some("group".into()),
                    disks: vec!["one".into(), "two".into()],
                    ..Default::default()
                })
            }
            _ => unreachable!(),
        }
        for (name, id) in [("one", "1"), ("two", "2")] {
            state.created_disks.insert(
                name.into(),
                atakit_cloud::disk_inventory::CreatedDisk {
                    specification: atakit_cloud::DiskSpec {
                        name: name.into(),
                        device_name: name.into(),
                        index: 0,
                        size_gb: 8,
                        disk_type: "type".into(),
                        performance: None,
                    },
                    observed: atakit_cloud::disk_inventory::ObservedDisk {
                        id: if platform == PlatformKind::Aws {
                            format!("vol-{name}")
                        } else {
                            id.into()
                        },
                        disk_type: "type".into(),
                        size_gb: 8,
                        iops: None,
                        throughput_mibps: None,
                    },
                    creation_verified: true,
                },
            );
        }
        use atakit_cloud::provisioning::{CreateRequest, Creation, CreationOutcome};
        let request = match platform {
            PlatformKind::Aws => CreateRequest::Aws {
                args: vec!["ec2".into(), "create-volume".into()],
            },
            PlatformKind::Gcp => CreateRequest::Gcp {
                project: "project".into(),
                zone: "zone".into(),
                collection: "disks".into(),
                body: json!({"name":"unknown"}),
            },
            PlatformKind::Azure => CreateRequest::AzureVm {
                subscription: "sub".into(),
                group: "group".into(),
                name: "unknown".into(),
                body: json!({}),
            },
            _ => unreachable!(),
        };
        state.provisioning.creations.insert(
            "disk:unknown".into(),
            Creation {
                request,
                token: "request-token".into(),
                sent: true,
                outcome: CreationOutcome::Unknown,
                receipt: None,
                result: None,
            },
        );
        state.save(&env.data_dir).unwrap();
        (dir, env, state)
    }
    fn args() -> DestroyArgs {
        DestroyArgs {
            instance: vec!["target/vm".into()],
            target: None,
            preserve: vec![],
            clean_image: false,
            yes: true,
        }
    }

    #[tokio::test]
    async fn unresolved_boot_reference_keeps_state_while_known_disks_are_cleaned() {
        let (_dir, env, mut state) = fixture(PlatformKind::Gcp);
        state.provisioning.creations.clear();
        state.cloud_instance_id = Some("123".into());
        state.resources.gcp.as_mut().unwrap().instance = Some("vm".into());
        state.created_boot_disk = Some(atakit_cloud::disk_inventory::ObservedDisk {
            id: "456".into(),
            disk_type: "pd-balanced".into(),
            size_gb: 8,
            iops: None,
            throughput_mibps: None,
        });
        state.save(&env.data_dir).unwrap();
        let runner = Runner {
            calls: Mutex::new(vec![]),
            fail_first: AtomicBool::new(false),
        };
        let error = run_one_with_runner(args(), &env, &runner)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cleanup incomplete"));
        let state = DeployState::load(&env.data_dir, "target", "vm").unwrap();
        assert!(state.cleanup.remaining["boot disk"].contains("456"));
        assert_eq!(
            state.cleanup.completed.len(),
            3,
            "VM absence and both data disks should be recorded as complete"
        );
        assert_eq!(state.created_boot_disk.unwrap().id, "456");
        assert!(
            state.cleanup.boot_disk.is_none(),
            "no extra boot record should be saved"
        );
        let calls = runner.calls.lock().unwrap();
        for name in ["one", "two"] {
            assert!(calls
                .iter()
                .any(|call| call.iter().any(|v| v == "delete") && call.iter().any(|v| v == name)));
        }
    }

    #[tokio::test]
    async fn all_providers_continue_cleanup_after_failure_and_checkpoint_successes() {
        for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
            let (_dir, env, _) = fixture(platform);
            let runner = Runner {
                calls: Mutex::new(vec![]),
                fail_first: AtomicBool::new(true),
            };
            assert!(run_one_with_runner(args(), &env, &runner)
                .await
                .unwrap_err()
                .to_string()
                .contains("cleanup incomplete"));
            let state = DeployState::load(&env.data_dir, "target", "vm").unwrap();
            assert!(state.cleanup.started);
            assert!(matches!(state.status, DeployStatus::Destroying));
            assert_eq!(
                state.cleanup.completed.len(),
                1,
                "{platform:?}: {:?}",
                state.cleanup.remaining
            );
            assert!(state
                .cleanup
                .remaining
                .contains_key("creation disk:unknown"));
            assert!(state.cleanup.remaining.keys().any(|k| k.contains("one")));
            runner.fail_first.store(false, Ordering::SeqCst);
            assert!(run_one_with_runner(args(), &env, &runner).await.is_err()); // Unknown create still remains.
            let state = DeployState::load(&env.data_dir, "target", "vm").unwrap();
            assert_eq!(state.cleanup.completed.len(), 2);
            let calls = runner.calls.lock().unwrap();
            let deletes_two = calls
                .iter()
                .filter(|c| {
                    c.iter().any(|s| s == "two" || s == "vol-two")
                        && c.iter().any(|s| s == "delete" || s == "delete-volume")
                })
                .count();
            assert_eq!(deletes_two, 1, "a completed deletion must not be replayed");
            assert!(!calls.iter().any(|c| c
                .iter()
                .any(|s| s == "create" || s == "create-volume" || s == "run-instances")));
        }
    }
    struct VmFailureRunner {
        disks: Runner,
        stopped: AtomicBool,
        power_calls: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl CommandRunner for VmFailureRunner {
        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            if args.contains(&"describe-instances") {
                return Ok(CommandOutput { status: 0, stderr: String::new(), stdout: json!({"Reservations":[{"Instances":[{
                    "InstanceId":"i-owned", "State":{"Name":if self.stopped.load(Ordering::SeqCst){"stopped"}else{"running"}},
                    "RootDeviceName":"/dev/xvda", "BlockDeviceMappings":[]
                }]}]}).to_string() });
            }
            if args.contains(&"terminate-instances") {
                return Err(CloudError::CommandFailed {
                    program: program.into(),
                    args: args.join(" "),
                    stderr: "termination denied".into(),
                    code: Some(1),
                });
            }
            if args.contains(&"stop-instances") || args.contains(&"instance-stopped") {
                self.power_calls.lock().unwrap().push(args.join(" "));
                self.stopped.store(true, Ordering::SeqCst);
                return Ok(CommandOutput {
                    status: 0,
                    stdout: "{}".into(),
                    stderr: String::new(),
                });
            }
            self.disks.run_capture(program, args).await
        }
        async fn run_stream(
            &self,
            _: &str,
            _: &[&str],
            _: bool,
        ) -> Result<CommandOutput, CloudError> {
            panic!("unexpected stream")
        }
    }

    #[tokio::test]
    async fn failed_vm_deletion_stops_vm_then_continues_disk_cleanup_and_reports_failure() {
        let (_dir, env, mut state) = fixture(PlatformKind::Aws);
        state.provisioning.creations.clear();
        state.cloud_instance_id = Some("i-owned".into());
        state.resources.aws.as_mut().unwrap().instance = Some("i-owned".into());
        state.save(&env.data_dir).unwrap();
        let runner = VmFailureRunner {
            disks: Runner {
                calls: Mutex::new(vec![]),
                fail_first: AtomicBool::new(false),
            },
            stopped: AtomicBool::new(false),
            power_calls: Mutex::new(vec![]),
        };
        assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
        let state = DeployState::load(&env.data_dir, "target", "vm").unwrap();
        assert_eq!(state.cleanup.vm_power.as_deref(), Some("stopped"));
        assert_eq!(state.cleanup.completed.len(), 2);
        assert!(state
            .cleanup
            .remaining
            .keys()
            .any(|key| key.contains("i-owned")));
        assert!(matches!(state.status, DeployStatus::Destroying));
        assert_eq!(runner.power_calls.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn an_empty_azure_group_does_not_keep_an_active_deployment() {
        let (_dir, env, mut state) = fixture(PlatformKind::Azure);
        state.provisioning.creations.clear();
        state.created_disks.clear();
        state.resources.azure.as_mut().unwrap().disks.clear();
        state.save(&env.data_dir).unwrap();
        let runner = Runner {
            calls: Mutex::new(vec![]),
            fail_first: AtomicBool::new(false),
        };
        run_one_with_runner(args(), &env, &runner).await.unwrap();
        assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
        assert!(runner.calls.lock().unwrap()[0].starts_with(&[
            "az".into(),
            "resource".into(),
            "list".into()
        ]));
    }
}
