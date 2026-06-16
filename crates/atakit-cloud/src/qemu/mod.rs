//! Local QEMU "cloud" provider. Boots a CVM image under qemu-system-x86_64
//! with swtpm + OVMF measured boot for offline workload-init iteration. Not
//! a real TEE — there's no genuine TDX/SEV quote.

pub mod deps;
pub mod disk;
pub mod firmware;
pub mod vm;

use std::path::PathBuf;

use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::plan::{
    DeployPlan, DeployStep, DestroyPlan, DestroyStep, DiskSpec, ResourceUpdates, StepResult,
};
use crate::provider::{CloudProvider, DeployOptions, DestroyOptions};
use crate::state::DeployState;

/// Local QEMU provider.
pub struct QemuProvider {
    /// Parent directory under which per-instance directories live, typically
    /// `<data_dir>/cloud/qemu/`. Created lazily by `start_vm`.
    runtime_dir: PathBuf,
    /// Provider-level UEFI path (from `[cloud.providers.<n>] uefi = "..."`).
    /// `None` is fine — the target may override, or `ATAKIT_QEMU_UEFI` may
    /// be set. Resolution + the missing-firmware error happen in `plan_deploy`.
    provider_uefi: Option<String>,
}

impl QemuProvider {
    pub fn new(runtime_dir: PathBuf, provider_uefi: Option<String>) -> Self {
        Self {
            runtime_dir,
            provider_uefi,
        }
    }

    /// Construct from a `DeployState` for destroy/status/serial paths. No
    /// firmware path needed — destroy doesn't boot anything.
    pub fn from_state(state: &DeployState) -> Result<Self, CloudError> {
        let q = state
            .resources
            .qemu
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "deployment has no QEMU resources".to_string(),
            })?;
        // Recover the parent dir from the recorded instance dir; this is
        // best-effort and only used as a fallback when re-deploying onto an
        // existing state file. Destroy doesn't read it.
        let runtime_dir = PathBuf::from(&q.instance_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/tmp/atakit-qemu"));
        Ok(Self {
            runtime_dir,
            provider_uefi: None,
        })
    }

    fn instance_dir(&self, target: &str, instance: &str) -> PathBuf {
        self.runtime_dir.join(target).join(instance)
    }
}

#[async_trait::async_trait]
impl CloudProvider for QemuProvider {
    fn check_deps(&self) -> Result<(), CloudError> {
        deps::check_local_deps()
    }

    async fn plan_deploy(&self, opts: &DeployOptions) -> Result<DeployPlan, CloudError> {
        // The base disk must be a local file — qemu can't "verify in cloud".
        let base_disk = opts
            .source_image_path
            .clone()
            .ok_or_else(|| CloudError::Config {
                message: format!(
                    "image '{}' has no local qemu_disk.qcow2 in the store; \
                     run `atakit image pull {} qemu` first",
                    opts.image_ref, opts.image_ref
                ),
            })?;

        // Resolve firmware up front so a misconfiguration aborts before any
        // disk is created or the VM is started.
        let ovmf =
            firmware::resolve_uefi(opts.target.uefi.as_deref(), self.provider_uefi.as_deref())?;

        let instance_dir = self.instance_dir(&opts.target_name, &opts.instance_name);
        let boot_overlay = instance_dir.join("boot.qcow2");

        // Build the DiskSpec list for data disks. We reuse DiskSpec verbatim
        // so the step's argv builder can read `device_name` for virtio serial.
        let data_disks: Vec<DiskSpec> = opts
            .workload_disks
            .iter()
            .map(|(disk_name, index, size_gb)| DiskSpec {
                name: format!("{}-{disk_name}", opts.instance_name),
                device_name: disk_name.clone(),
                index: *index,
                size_gb: *size_gb,
                disk_type: "qcow2".to_string(),
            })
            .collect();

        let metadata: Vec<(String, String)> = opts
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let mut steps = vec![
            DeployStep::CheckDeps,
            DeployStep::StartLocalVm {
                instance_dir: instance_dir.display().to_string(),
                base_disk,
                boot_overlay: boot_overlay.display().to_string(),
                boot_disk_size_gb: opts.boot_disk_size_gb,
                ovmf_path: ovmf.display().to_string(),
                data_disks,
                metadata,
                portal_ports: opts.portal_ports,
                workload_ports: opts.workload_ports.clone(),
            },
        ];

        if !opts.skip_init {
            steps.push(DeployStep::WaitForPortal { timeout_secs: 300 });
            steps.push(DeployStep::InitializeWorkload {
                archive_path: opts.archive_path.clone(),
            });
        }

        Ok(DeployPlan { steps })
    }

    async fn execute_step(
        &self,
        step: &DeployStep,
        runner: &dyn CommandRunner,
        _verbose: bool,
    ) -> Result<StepResult, CloudError> {
        let mut updates = ResourceUpdates::default();

        match step {
            DeployStep::CheckDeps => {
                self.check_deps()?;
            }
            DeployStep::StartLocalVm {
                instance_dir,
                base_disk,
                boot_overlay,
                boot_disk_size_gb,
                ovmf_path,
                data_disks,
                metadata,
                portal_ports,
                workload_ports,
            } => {
                let instance_dir = PathBuf::from(instance_dir);
                std::fs::create_dir_all(&instance_dir).map_err(|e| CloudError::IoPath {
                    path: instance_dir.clone(),
                    source: e,
                })?;

                let boot_overlay_path = PathBuf::from(boot_overlay);
                disk::create_boot_overlay(
                    std::path::Path::new(base_disk),
                    &boot_overlay_path,
                    boot_disk_size_gb.unwrap_or(4),
                    runner,
                )
                .await?;

                // Build (spec, path) pairs for the VM step and the data-disk
                // qcow2 list we persist into state.
                let mut data_pairs: Vec<(DiskSpec, PathBuf)> = Vec::new();
                for spec in data_disks {
                    let p = instance_dir.join(format!("data-{}.qcow2", spec.device_name));
                    disk::create_data_disk(&p, spec.size_gb, runner).await?;
                    updates.disks.push(p.display().to_string());
                    data_pairs.push((spec.clone(), p));
                }

                let started = vm::start_vm(vm::StartOptions {
                    instance_dir: &instance_dir,
                    boot_overlay: &boot_overlay_path,
                    ovmf: std::path::Path::new(ovmf_path),
                    data_disks: &data_pairs,
                    metadata,
                    portal_ports: *portal_ports,
                    workload_ports,
                })?;

                updates.qemu_instance_dir = Some(instance_dir.display().to_string());
                updates.qemu_pid = Some(started.pid);
                updates.qemu_base_disk = Some(base_disk.clone());
                updates.qemu_boot_overlay = Some(boot_overlay.clone());
                updates.qemu_host_status_port = Some(started.host_status_port);
                updates.qemu_host_init_port = Some(started.host_init_port);
                updates.qemu_serial_sock = Some(started.serial_sock.display().to_string());
                updates.qemu_workload_port_map = started.workload_port_map;
                updates.external_ip = Some("127.0.0.1".to_string());
                updates.instance = Some(format!("qemu-pid-{}", started.pid));
            }
            DeployStep::WaitForPortal { .. } | DeployStep::InitializeWorkload { .. } => {
                // Handled by the CLI layer (it knows the chain/key config + portal endpoints).
            }
            other => {
                return Err(CloudError::State {
                    message: format!(
                        "non-QEMU step {other:?} executed by QemuProvider; this is a wiring bug"
                    ),
                });
            }
        }

        Ok(StepResult {
            resource_updates: updates,
        })
    }

    fn plan_destroy(
        &self,
        state: &DeployState,
        _opts: &DestroyOptions,
    ) -> Result<DestroyPlan, CloudError> {
        let q = state
            .resources
            .qemu
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no QEMU resources in state".to_string(),
            })?;
        let mut steps = Vec::new();
        if q.pid != 0 {
            steps.push(DestroyStep::StopLocalVm { pid: q.pid });
        }
        if !q.instance_dir.is_empty() {
            steps.push(DestroyStep::RemoveLocalInstanceDir {
                path: q.instance_dir.clone(),
            });
        }
        Ok(DestroyPlan { steps })
    }

    async fn execute_destroy_step(
        &self,
        step: &DestroyStep,
        _runner: &dyn CommandRunner,
        _verbose: bool,
    ) -> Result<(), CloudError> {
        match step {
            DestroyStep::StopLocalVm { pid } => vm::stop_vm(*pid),
            DestroyStep::RemoveLocalInstanceDir { path } => {
                let p = std::path::Path::new(path);
                if p.exists() {
                    std::fs::remove_dir_all(p).map_err(|e| CloudError::IoPath {
                        path: p.to_path_buf(),
                        source: e,
                    })?;
                }
                Ok(())
            }
            other => Err(CloudError::State {
                message: format!(
                    "non-QEMU destroy step {other:?} executed by QemuProvider; \
                     this is a wiring bug"
                ),
            }),
        }
    }

    async fn get_instance_ip(
        &self,
        state: &DeployState,
        _runner: &dyn CommandRunner,
    ) -> Result<Option<String>, CloudError> {
        // QEMU instances are always reachable via loopback. We also surface
        // it explicitly when the state field is set so the value stays
        // consistent with whatever the deploy step recorded.
        let ip = state
            .resources
            .qemu
            .as_ref()
            .map(|q| {
                if q.external_ip.is_empty() {
                    "127.0.0.1".to_string()
                } else {
                    q.external_ip.clone()
                }
            })
            .unwrap_or_else(|| "127.0.0.1".to_string());
        Ok(Some(ip))
    }

    async fn get_serial_output(
        &self,
        state: &DeployState,
        _runner: &dyn CommandRunner,
    ) -> Result<String, CloudError> {
        let q = state
            .resources
            .qemu
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no QEMU resources in state".to_string(),
            })?;
        let log = std::path::Path::new(&q.instance_dir).join("serial.log");
        match std::fs::read_to_string(&log) {
            Ok(s) => Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(CloudError::IoPath {
                path: log,
                source: e,
            }),
        }
    }

    fn ssh_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError> {
        // `cloud ssh` on qemu does NOT run real ssh — there's no sshd in
        // the guest. Instead it socats into the serial chardev's unix
        // socket for an interactive console. `raw,echo=0` puts the local
        // terminal in raw mode so per-keystroke input reaches the VM
        // unchanged; `escape=0x1d` makes Ctrl-] exit socat without
        // killing the VM (Ctrl-C passes through to the guest).
        let q = state
            .resources
            .qemu
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no QEMU resources in state".to_string(),
            })?;
        if q.serial_sock.is_empty() {
            return Err(CloudError::State {
                message: "no serial chardev socket recorded for this instance \
                          (state predates the chardev-socket switch — redeploy)"
                    .to_string(),
            });
        }
        Ok(vec![
            "socat".to_string(),
            "-,raw,echo=0,escape=0x1d".to_string(),
            format!("UNIX-CONNECT:{}", q.serial_sock),
        ])
    }

    fn serial_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError> {
        let q = state
            .resources
            .qemu
            .as_ref()
            .ok_or_else(|| CloudError::State {
                message: "no QEMU resources in state".to_string(),
            })?;
        let log = std::path::Path::new(&q.instance_dir)
            .join("serial.log")
            .display()
            .to_string();
        Ok(vec!["tail".to_string(), "-f".to_string(), log])
    }
}
