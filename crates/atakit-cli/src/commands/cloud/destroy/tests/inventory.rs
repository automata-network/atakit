use super::*;

struct InventoryRunner {
    disks: Runner,
    fail_inventory: AtomicBool,
    absent: AtomicBool,
    replaced: AtomicBool,
    stopped: AtomicBool,
    extra_present: AtomicBool,
    delete_calls: Mutex<usize>,
}

#[async_trait::async_trait]
impl CommandRunner for InventoryRunner {
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        let vm_read = args.contains(&"describe-instances")
            || args.starts_with(&["compute", "instances", "describe"])
            || args.starts_with(&["vm", "show"]);
        let missing = || CloudError::CommandFailed {
            program: program.into(),
            args: args.join(" "),
            code: Some(1),
            stderr: match program {
                "aws" if vm_read => "InvalidInstanceID.NotFound",
                "aws" => "InvalidVolume.NotFound",
                "gcloud" => "resource was not found",
                _ => "ERROR: (ResourceNotFound) absent",
            }
            .into(),
        };
        let reply = |value: Value| {
            Ok(CommandOutput {
                status: 0,
                stdout: value.to_string(),
                stderr: String::new(),
            })
        };
        if vm_read {
            if self.fail_inventory.swap(false, Ordering::SeqCst) {
                return Err(CloudError::State {
                    message: "attachment inventory unavailable".into(),
                });
            }
            if self.absent.load(Ordering::SeqCst) {
                return Err(missing());
            }
            let id = if self.replaced.load(Ordering::SeqCst) {
                "replacement"
            } else {
                "original"
            };
            let stopped = self.stopped.load(Ordering::SeqCst);
            return reply(match program {
                "aws" => {
                    json!({"Reservations":[{"Instances":[{"InstanceId":id,"State":{"Name":if stopped {"stopped"}else{"running"}},"RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"boot","DeleteOnTermination":false}},{"DeviceName":"/dev/sdf","Ebs":{"VolumeId":"extra","DeleteOnTermination":false}}]}]}]})
                }
                "gcloud" => {
                    json!({"id":id,"status":if stopped {"TERMINATED"}else{"RUNNING"},"disks":[{"type":"PERSISTENT","autoDelete":false,"boot":true,"source":"projects/project/zones/zone/disks/boot"},{"type":"PERSISTENT","autoDelete":false,"boot":false,"source":"projects/project/zones/zone/disks/extra"}]})
                }
                _ => {
                    json!({"vmId":id,"storageProfile":{"osDisk":{"name":"boot","managedDisk":{"id":"boot"},"deleteOption":"Detach"},"dataDisks":[{"name":"extra","lun":0,"managedDisk":{"id":"extra"},"deleteOption":"Detach"}]},"networkProfile":{"networkInterfaces":[]}})
                }
            });
        }
        if args.contains(&"stop-instances")
            || args.contains(&"stop")
            || args.contains(&"deallocate")
        {
            assert!(
                !self.replaced.load(Ordering::SeqCst),
                "never stop a replacement VM"
            );
            self.stopped.store(true, Ordering::SeqCst);
            return reply(json!({}));
        }
        if args.contains(&"instance-stopped") {
            return reply(json!({}));
        }
        if args.contains(&"get-instance-view") {
            return reply(json!({"statuses":[{"code":"PowerState/deallocated"}]}));
        }
        let vm_delete = args.contains(&"terminate-instances")
            || args.starts_with(&["compute", "instances", "delete"])
            || args.starts_with(&["vm", "delete"]);
        if vm_delete {
            *self.delete_calls.lock().unwrap() += 1;
            self.absent.store(true, Ordering::SeqCst);
            return reply(json!({}));
        }
        if args.contains(&"instance-terminated") {
            return reply(json!({}));
        }
        if args
            .iter()
            .any(|arg| *arg == "boot" || arg.ends_with("/extra") || *arg == "extra")
        {
            assert!(
                !args.contains(&"delete") && !args.contains(&"delete-volume"),
                "never delete an unrecorded disk"
            );
            if !self.extra_present.load(Ordering::SeqCst) {
                return Err(missing());
            }
            return reply(json!({})); // Remaining-resource checks need only existence.
        }
        if args.starts_with(&["resource", "list"]) {
            return reply(if self.extra_present.load(Ordering::SeqCst) {
                json!([{"id":"extra","name":"extra","type":"Microsoft.Compute/disks"}])
            } else {
                json!([])
            });
        }
        self.disks.run_capture(program, args).await
    }
    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<CommandOutput, CloudError> {
        panic!("unexpected stream")
    }
}

fn setup(platform: PlatformKind) -> (tempfile::TempDir, Env, InventoryRunner) {
    let (dir, env, mut state) = fixture(platform);
    state.provisioning.creations.clear();
    state.cloud_instance_id = Some("original".into());
    match platform {
        PlatformKind::Aws => {
            state.resources.aws.as_mut().unwrap().instance = Some("original".into())
        }
        PlatformKind::Gcp => state.resources.gcp.as_mut().unwrap().instance = Some("vm".into()),
        PlatformKind::Azure => state.resources.azure.as_mut().unwrap().instance = Some("vm".into()),
        _ => unreachable!(),
    }
    state.save(&env.data_dir).unwrap();
    (
        dir,
        env,
        InventoryRunner {
            disks: Runner {
                calls: Mutex::new(vec![]),
                fail_first: AtomicBool::new(false),
            },
            fail_inventory: AtomicBool::new(true),
            absent: AtomicBool::new(false),
            replaced: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            extra_present: AtomicBool::new(true),
            delete_calls: Mutex::new(0),
        },
    )
}

#[tokio::test]
async fn failed_inventory_stops_vm_cleans_independent_disks_and_retry_reports_attachments() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (_dir, env, runner) = setup(platform);
        assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
        let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
        assert!(saved
            .cleanup
            .remaining
            .contains_key("VM attachment inventory"));
        assert_eq!(*runner.delete_calls.lock().unwrap(), 0);
        assert!(runner.stopped.load(Ordering::SeqCst));
        assert_eq!(
            saved.cleanup.completed.len(),
            2,
            "both independent disks cleaned"
        );

        for _ in 0..2 {
            assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
            let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
            assert!(!saved
                .cleanup
                .remaining
                .contains_key("VM attachment inventory"));
            assert!(saved
                .cleanup
                .remaining
                .keys()
                .any(|key| key.ends_with("extra")));
            assert_eq!(*runner.delete_calls.lock().unwrap(), 1);
        }
        // Simulate an external owner removing the unrecorded disks. A final
        // retry must verify absence, finish, and remove the deployment state.
        runner.extra_present.store(false, Ordering::SeqCst);
        run_one_with_runner(args(), &env, &runner).await.unwrap();
        assert!(DeployState::load(&env.data_dir, "target", "vm").is_err());
        let calls = runner.disks.calls.lock().unwrap();
        for name in if platform == PlatformKind::Aws {
            ["vol-one", "vol-two"]
        } else {
            ["one", "two"]
        } {
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| call.iter().any(|v| v == name)
                        && call.iter().any(|v| v == "delete" || v == "delete-volume"))
                    .count(),
                1
            );
        }
    }
}

#[tokio::test]
async fn vanished_vm_does_not_clear_unresolved_inventory_on_retry() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (_dir, env, runner) = setup(platform);
        assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
        runner.absent.store(true, Ordering::SeqCst);
        runner.extra_present.store(false, Ordering::SeqCst);
        for _ in 0..2 {
            assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
            let saved = DeployState::load(&env.data_dir, "target", "vm").unwrap();
            assert!(saved
                .cleanup
                .remaining
                .contains_key("VM attachment inventory"));
            assert_eq!(*runner.delete_calls.lock().unwrap(), 0);
        }
    }
}

#[tokio::test]
async fn replacement_vm_is_neither_stopped_nor_deleted_after_inventory_failure() {
    for platform in [PlatformKind::Aws, PlatformKind::Gcp, PlatformKind::Azure] {
        let (_dir, env, runner) = setup(platform);
        runner.replaced.store(true, Ordering::SeqCst);
        for _ in 0..2 {
            assert!(run_one_with_runner(args(), &env, &runner).await.is_err());
            assert!(!runner.stopped.load(Ordering::SeqCst));
            assert_eq!(*runner.delete_calls.lock().unwrap(), 0);
        }
    }
}
