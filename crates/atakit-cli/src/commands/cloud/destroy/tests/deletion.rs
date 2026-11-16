use super::*;
use std::sync::atomic::AtomicUsize;

struct DeletionRunner {
    disks: Runner,
    calls: Mutex<Vec<Vec<String>>>,
    deleted: AtomicBool,
    stopped: AtomicBool,
    deny_delete: AtomicBool,
    fail_followup: AtomicBool,
    fail_vm_read: AtomicBool,
    show_terminated: bool,
    delete_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl CommandRunner for DeletionRunner {
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        self.calls
            .lock()
            .unwrap()
            .push(args.iter().map(|v| v.to_string()).collect());
        let fail = |message: &str| CloudError::CommandFailed {
            program: program.into(),
            args: args.join(" "),
            stderr: message.into(),
            code: Some(1),
        };
        let absent = || {
            fail(match program {
                "aws" => "InvalidInstanceID.NotFound",
                "gcloud" => "instance was not found",
                _ => "ERROR: (ResourceNotFound) VM absent",
            })
        };
        let reply = |value: Value| {
            Ok(CommandOutput {
                status: 0,
                stdout: value.to_string(),
                stderr: String::new(),
            })
        };
        if args.contains(&"describe-instances")
            || args.starts_with(&["compute", "instances", "describe"])
            || args.starts_with(&["vm", "show"])
        {
            if self.fail_vm_read.load(Ordering::SeqCst)
                || (self.delete_calls.load(Ordering::SeqCst) > 0
                    && self.fail_followup.swap(false, Ordering::SeqCst))
            {
                return Err(fail("VM lookup temporarily unavailable"));
            }
            let deleted = self.deleted.load(Ordering::SeqCst);
            if deleted && !(program == "aws" && self.show_terminated) {
                return Err(absent());
            }
            let stopped = self.stopped.load(Ordering::SeqCst);
            return reply(match program {
                "aws" => json!({"Reservations":[{"Instances":[{
                    "InstanceId":"original",
                    "State":{"Name":if deleted {"terminated"} else if stopped {"stopped"} else {"running"}},
                    "RootDeviceName":"/dev/xvda",
                    "BlockDeviceMappings":if deleted {json!([])} else {json!([{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"vol-one","DeleteOnTermination":false}}])}
                }]}]}),
                "gcloud" => {
                    json!({"id":"original","status":if stopped {"TERMINATED"}else{"RUNNING"},
                    "disks":[{"type":"PERSISTENT","autoDelete":false,"boot":true,"source":"projects/project/zones/zone/disks/one"}]})
                }
                _ => json!({"vmId":"original","storageProfile":{
                    "osDisk":{"name":"one","managedDisk":{"id":"one"},"deleteOption":"Detach"},"dataDisks":[]},
                    "networkProfile":{"networkInterfaces":[]}}),
            });
        }
        if args.contains(&"terminate-instances")
            || args.starts_with(&["compute", "instances", "delete"])
            || args.starts_with(&["vm", "delete"])
        {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            if self.deleted.load(Ordering::SeqCst) {
                return Err(absent());
            }
            if self.deny_delete.load(Ordering::SeqCst) {
                return Err(fail("VM deletion denied"));
            }
            self.deleted.store(true, Ordering::SeqCst);
            return Err(fail("VM deleted but its reply was lost"));
        }
        if args.contains(&"stop-instances")
            || args.starts_with(&["compute", "instances", "stop"])
            || args.starts_with(&["vm", "deallocate"])
        {
            assert!(!self.deleted.load(Ordering::SeqCst));
            self.stopped.store(true, Ordering::SeqCst);
            return reply(json!({}));
        }
        if args.contains(&"get-instance-view") {
            return reply(json!({"statuses":[{"code":"PowerState/deallocated"}]}));
        }
        if args.contains(&"instance-stopped") {
            return reply(json!({}));
        }
        self.disks.run_capture(program, args).await
    }

    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<CommandOutput, CloudError> {
        panic!("unexpected stream")
    }
}

fn setup(
    platform: PlatformKind,
    show_terminated: bool,
) -> (tempfile::TempDir, Env, DeletionRunner) {
    let (dir, env, mut state) = fixture(platform);
    state.provisioning.creations.clear();
    state.cloud_instance_id = Some("original".into());
    state.created_boot_disk = Some(state.created_disks.remove("one").unwrap().observed);
    match platform {
        PlatformKind::Aws => {
            let r = state.resources.aws.as_mut().unwrap();
            r.instance = Some("original".into());
            r.disks = vec!["vol-two".into()];
        }
        PlatformKind::Gcp => {
            let r = state.resources.gcp.as_mut().unwrap();
            r.instance = Some("vm".into());
            r.disks = vec!["two".into()];
        }
        PlatformKind::Azure => {
            let r = state.resources.azure.as_mut().unwrap();
            r.instance = Some("vm".into());
            r.disks = vec!["two".into()];
        }
        _ => unreachable!(),
    }
    state.save(&env.data_dir).unwrap();
    (
        dir,
        env,
        DeletionRunner {
            disks: Runner {
                calls: Mutex::new(vec![]),
                fail_first: AtomicBool::new(false),
            },
            calls: Mutex::new(vec![]),
            deleted: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            deny_delete: AtomicBool::new(false),
            fail_followup: AtomicBool::new(false),
            fail_vm_read: AtomicBool::new(false),
            show_terminated,
            delete_calls: AtomicUsize::new(0),
        },
    )
}

fn vm_step(platform: PlatformKind) -> DestroyStep {
    DestroyStep::DeleteInstance {
        name: if platform == PlatformKind::Aws {
            "original"
        } else {
            "vm"
        }
        .into(),
    }
}

fn vm_completed(state: &DeployState) -> bool {
    state
        .cleanup
        .completed
        .contains(&atakit_cloud::provisioning_cleanup::step_key(&vm_step(
            state.platform,
        )))
}

#[tokio::test]
async fn lost_vm_reply_completes_cleanup_after_confirmed_absence_or_termination() {
    for (platform, terminated) in [
        (PlatformKind::Aws, false),
        (PlatformKind::Aws, true),
        (PlatformKind::Gcp, false),
        (PlatformKind::Azure, false),
    ] {
        let (_dir, env, runner) = setup(platform, terminated);
        run_one_with_runner(args(), &env, &runner).await.unwrap();
        assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
        assert_eq!(runner.delete_calls.load(Ordering::SeqCst), 1);
        assert!(!runner.stopped.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn confirmed_vm_deletion_survives_disk_failure_and_retry_cannot_reopen_inventory() {
    for (platform, terminated) in [
        (PlatformKind::Aws, false),
        (PlatformKind::Aws, true),
        (PlatformKind::Gcp, false),
        (PlatformKind::Azure, false),
    ] {
        let (_dir, env, runner) = setup(platform, terminated);
        runner.disks.fail_first.store(true, Ordering::SeqCst);
        assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
        let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
        assert!(vm_completed(&saved));
        assert_eq!(saved.cleanup.vm_power.as_deref(), Some("deleted"));
        assert!(saved.cleanup.resolved_creations.contains("instance"));
        assert!(!saved
            .cleanup
            .remaining
            .contains_key(&vm_step(platform).to_string()));
        assert_eq!(
            saved.cleanup.completed.len(),
            2,
            "VM and independent data disk completed"
        );

        runner.disks.fail_first.store(false, Ordering::SeqCst);
        runner.fail_vm_read.store(true, Ordering::SeqCst);
        runner.calls.lock().unwrap().clear();
        run_one_with_runner(args(), &env, &runner).await.unwrap();
        assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
        assert_eq!(runner.delete_calls.load(Ordering::SeqCst), 1);
        assert!(!runner.calls.lock().unwrap().iter().any(|call| {
            call.iter().any(|arg| arg == "describe-instances")
                || call.starts_with(&["compute".into(), "instances".into()])
                || call.starts_with(&["vm".into()])
        }));
    }
}

#[tokio::test]
async fn failed_deletion_confirmation_remains_incomplete_and_can_retry() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (_dir, env, runner) = setup(platform, false);
        runner.fail_followup.store(true, Ordering::SeqCst);
        assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
        let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
        assert!(!vm_completed(&saved));
        assert!(saved
            .cleanup
            .vm_power
            .as_deref()
            .unwrap()
            .starts_with("unknown:"));
        run_one_with_runner(args(), &env, &runner).await.unwrap();
        assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
    }
}

#[tokio::test]
async fn stopped_or_deallocated_vm_is_not_completed_as_deleted() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (_dir, env, runner) = setup(platform, false);
        runner.deny_delete.store(true, Ordering::SeqCst);
        runner.disks.fail_first.store(true, Ordering::SeqCst);
        assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
        let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
        assert!(!vm_completed(&saved));
        assert!(!runner.deleted.load(Ordering::SeqCst));
        assert!(runner.stopped.load(Ordering::SeqCst));
        assert!(saved
            .cleanup
            .remaining
            .contains_key(&vm_step(platform).to_string()));
        assert_eq!(
            saved.cleanup.vm_power.as_deref(),
            Some(match platform {
                PlatformKind::Aws => "stopped",
                PlatformKind::Gcp => "TERMINATED (stopped)",
                PlatformKind::Azure => "deallocated",
                _ => unreachable!(),
            })
        );
        runner.deny_delete.store(false, Ordering::SeqCst);
        runner.disks.fail_first.store(false, Ordering::SeqCst);
        run_one_with_runner(args(), &env, &runner).await.unwrap();
        assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
    }
}
