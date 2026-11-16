use super::*;
use std::collections::BTreeMap;

struct LegacyRunner {
    vm_present: AtomicBool,
    disks: Mutex<BTreeMap<String, String>>,
    calls: Mutex<Vec<Vec<String>>>,
    fail_data_delete: AtomicBool,
    replace_data_after_read: AtomicBool,
}

#[async_trait::async_trait]
impl CommandRunner for LegacyRunner {
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        assert_eq!(program, "gcloud");
        self.calls
            .lock()
            .unwrap()
            .push(args.iter().map(|a| a.to_string()).collect());
        let fail = |message: &str| CloudError::CommandFailed {
            program: program.into(),
            args: args.join(" "),
            stderr: message.into(),
            code: Some(1),
        };
        let value = match &args[..3] {
            ["compute", "instances", "describe"] => {
                if !self.vm_present.load(Ordering::SeqCst) {
                    return Err(fail("VM was not found"));
                }
                json!({"id":"original","disks":[
                    {"type":"PERSISTENT","boot":true,"autoDelete":false,"source":"https://www.googleapis.com/compute/v1/projects/project/zones/zone/disks/vm","deviceName":"boot"},
                    {"type":"PERSISTENT","boot":false,"autoDelete":false,"source":"https://www.googleapis.com/compute/v1/projects/project/zones/zone/disks/vm-data","deviceName":"data"}
                ]})
            }
            ["compute", "instances", "delete"] => {
                self.vm_present.store(false, Ordering::SeqCst);
                json!({})
            }
            ["compute", "disks", "describe"] => {
                let name = args[3].rsplit('/').next().unwrap();
                let mut disks = self.disks.lock().unwrap();
                let id = disks
                    .get(name)
                    .ok_or_else(|| fail("disk was not found"))?
                    .clone();
                if name == "vm-data" && self.replace_data_after_read.swap(false, Ordering::SeqCst) {
                    disks.insert(name.into(), "replacement".into());
                }
                json!({"id":id,"users":if self.vm_present.load(Ordering::SeqCst) {
                    vec!["projects/project/zones/zone/instances/vm"]
                } else {vec![]}})
            }
            ["compute", "disks", "delete"] => {
                assert!(!self.vm_present.load(Ordering::SeqCst));
                if args[3] == "vm-data" && self.fail_data_delete.swap(false, Ordering::SeqCst) {
                    return Err(fail("temporary deletion failure"));
                }
                self.disks.lock().unwrap().remove(args[3]);
                json!({})
            }
            ["compute", "firewall-rules", "delete"] => json!({}),
            _ => panic!("unexpected call {args:?}"),
        };
        Ok(CommandOutput {
            status: 0,
            stdout: value.to_string(),
            stderr: String::new(),
        })
    }
    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<CommandOutput, CloudError> {
        panic!("unexpected stream")
    }
}

fn setup(vm_present: bool) -> (tempfile::TempDir, Env, LegacyRunner) {
    let (dir, env, mut state) = fixture(PlatformKind::Gcp);
    state.cloud_instance_id = Some("original".into());
    let g = state.resources.gcp.as_mut().unwrap();
    g.instance = Some("vm".into());
    g.disks = vec!["vm-data".into()];
    g.firewall_rule = Some("vm-ingress".into());
    // Load actual old-shaped JSON, not a new state with populated creation fields.
    let mut old = serde_json::to_value(&state).unwrap();
    for field in [
        "cleanup",
        "provisioning",
        "created_boot_disk",
        "automatic_disk_setup",
        "disk_configuration",
        "created_disks",
    ] {
        old.as_object_mut().unwrap().remove(field);
    }
    let path = env.data_dir.join("cloud/deployments/target/vm.state.json");
    std::fs::write(path, serde_json::to_vec(&old).unwrap()).unwrap();
    if !vm_present {
        let mut state = DeployState::load(&env.data_dir, "target", "vm").unwrap();
        state.cleanup.started = true;
        state.cleanup.retained_disks.insert(
            "vm".into(),
            "boot disk identity was not saved; retained; storage charges may continue".into(),
        );
        state.cleanup.retained_disks.insert(
            "https://www.googleapis.com/compute/v1/projects/project/zones/zone/disks/vm-data"
                .into(),
            "attached disk has no creation record; retained; storage charges may continue".into(),
        );
        for step in [
            DestroyStep::DeleteInstance { name: "vm".into() },
            DestroyStep::DeleteFirewall {
                name: "vm-ingress".into(),
            },
        ] {
            atakit_cloud::provisioning_cleanup::completed(&mut state, &step);
        }
        state.save(&env.data_dir).unwrap();
    }
    (
        dir,
        env,
        LegacyRunner {
            vm_present: AtomicBool::new(vm_present),
            disks: Mutex::new(BTreeMap::from([
                ("vm".into(), "100".into()),
                ("vm-data".into(), "200".into()),
            ])),
            calls: Mutex::new(vec![]),
            fail_data_delete: AtomicBool::new(false),
            replace_data_after_read: AtomicBool::new(false),
        },
    )
}

async fn run_approved(options: DestroyArgs, env: &Env, runner: &LegacyRunner) -> Result<()> {
    run_one_with_prompt(options, env, runner, &|_| Ok(true)).await
}

#[tokio::test]
async fn old_gcp_state_requires_disk_approval_even_with_yes_then_cleans_up() {
    let (_dir, env, runner) = setup(true);
    let error = run_one_with_runner(args(), &env, &runner)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("interactive approval"));
    assert!(error.contains("--yes alone does not approve"));
    assert!(!runner.vm_present.load(Ordering::SeqCst));
    assert_eq!(runner.disks.lock().unwrap().len(), 2);
    let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
    assert!(saved.cleanup.confirmed_disks.is_empty());
    assert!(
        !runner.calls.lock().unwrap().iter().any(|c| c.starts_with(&[
            "compute".into(),
            "disks".into(),
            "delete".into()
        ]))
    );
    run_approved(args(), &env, &runner).await.unwrap();
    assert!(runner.disks.lock().unwrap().is_empty());
    assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
}

#[tokio::test]
async fn reported_partial_cleanup_finishes_after_approval_and_survives_delete_failure() {
    let (_dir, env, runner) = setup(false);
    runner.fail_data_delete.store(true, Ordering::SeqCst);
    let error = run_approved(args(), &env, &runner)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("After resolving the reported errors, retry"));
    let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
    assert_eq!(saved.cleanup.confirmed_disks.len(), 2);
    assert!(saved.created_disks.is_empty());
    assert!(!runner.disks.lock().unwrap().contains_key("vm"));
    run_one_with_runner(args(), &env, &runner).await.unwrap();
    assert!(runner.disks.lock().unwrap().is_empty());
    assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
    let calls = runner.calls.lock().unwrap();
    assert!(!calls.iter().any(|c| c.starts_with(&[
        "compute".into(),
        "instances".into(),
        "delete".into()
    ])));
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with(&[
                "compute".into(),
                "disks".into(),
                "delete".into(),
                "vm".into()
            ]))
            .count(),
        1
    );
}

#[tokio::test]
async fn disk_replaced_after_prompt_is_not_approved_or_deleted() {
    let (_dir, env, runner) = setup(false);
    runner.replace_data_after_read.store(true, Ordering::SeqCst);
    assert!(run_approved(args(), &env, &runner)
        .await
        .unwrap_err()
        .to_string()
        .contains("refusing replacement"));
    let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
    assert!(saved.cleanup.confirmed_disks.is_empty());
    assert_eq!(runner.disks.lock().unwrap().len(), 2);
    assert!(!runner
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.contains(&"delete".into())));
}

#[tokio::test]
async fn disk_replaced_after_failed_deletion_stays_protected_on_retry() {
    let (_dir, env, runner) = setup(false);
    runner.fail_data_delete.store(true, Ordering::SeqCst);
    assert!(run_approved(args(), &env, &runner).await.is_err());
    runner
        .disks
        .lock()
        .unwrap()
        .insert("vm-data".into(), "replacement".into());
    assert!(run_one_with_runner(args(), &env, &runner)
        .await
        .unwrap_err()
        .to_string()
        .contains("refusing replacement"));
    assert_eq!(runner.disks.lock().unwrap()["vm-data"], "replacement");
}

#[tokio::test]
async fn already_absent_legacy_disks_complete_without_deletion_requests() {
    let (_dir, env, runner) = setup(false);
    runner.disks.lock().unwrap().clear();
    run_one_with_runner(args(), &env, &runner).await.unwrap();
    assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
    assert!(!runner
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.contains(&"delete".into())));
}

#[tokio::test]
async fn live_legacy_vm_can_be_cleaned_in_one_approved_run() {
    let (_dir, env, runner) = setup(true);
    run_approved(args(), &env, &runner).await.unwrap();
    assert!(runner.disks.lock().unwrap().is_empty());
    assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
}

#[tokio::test]
async fn confirmed_workload_disk_can_be_preserved_while_boot_disk_is_deleted() {
    let (_dir, env, runner) = setup(false);
    let mut options = args();
    options.preserve = vec!["disks".into()];
    run_approved(options, &env, &runner).await.unwrap();
    {
        let disks = runner.disks.lock().unwrap();
        assert!(!disks.contains_key("vm"));
        assert_eq!(disks["vm-data"], "200");
    }
    let state = DeployState::load(&env.data_dir, "target", "vm").unwrap();
    assert!(matches!(state.status, DeployStatus::Destroyed));
    assert!(state.cleanup.remaining["disk vm-data"].starts_with("preserved"));
    run_approved(args(), &env, &runner).await.unwrap();
    assert!(runner.disks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancelling_normal_prompt_never_saves_approval() {
    let (_dir, env, runner) = setup(true);
    let mut options = args();
    options.yes = false;
    let prompts = std::cell::Cell::new(0);
    run_one_with_prompt(options, &env, &runner, &|message| {
        prompts.set(prompts.get() + 1);
        assert!(message.starts_with("Destroy target/vm?"));
        Ok(false)
    })
    .await
    .unwrap();
    assert_eq!(prompts.get(), 1);
    let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
    assert!(saved.cleanup.confirmed_disks.is_empty());
    assert!(!saved.cleanup.started);
    assert!(runner.vm_present.load(Ordering::SeqCst));
}

#[tokio::test]
async fn declining_disk_prompt_keeps_disks_without_approval() {
    let (_dir, env, runner) = setup(true);
    let prompts = std::cell::Cell::new(0);
    let error = run_one_with_prompt(args(), &env, &runner, &|message| {
        prompts.set(prompts.get() + 1);
        assert!(message.contains("vm (boot disk)"));
        assert!(message.contains("vm-data (data disk)"));
        assert!(message.contains("Delete these disks permanently? [y/N]"));
        Ok(false)
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("interactive approval"));
    assert_eq!(prompts.get(), 1);
    assert_eq!(runner.disks.lock().unwrap().len(), 2);
    let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
    assert!(saved.cleanup.confirmed_disks.is_empty());
}

#[tokio::test]
async fn preserved_data_disk_is_excluded_from_prompt() {
    let (_dir, env, runner) = setup(false);
    let mut options = args();
    options.preserve = vec!["disks".into()];
    run_one_with_prompt(options, &env, &runner, &|message| {
        assert!(message.contains("vm (boot disk)"));
        assert!(!message.contains("vm-data"));
        Ok(true)
    })
    .await
    .unwrap();
    let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
    assert!(!saved.cleanup.confirmed_disks.contains_key("vm-data"));
}
