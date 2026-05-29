//! QEMU process lifecycle: spawn detached + stop. The rest of the cloud
//! crate uses `CommandRunner`, which waits to completion — that won't do for
//! `qemu-system-x86_64`, which we want to leave running in the background
//! while `deploy` returns.

use std::collections::BTreeMap;
use std::io;
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::error::CloudError;
use crate::plan::DiskSpec;

/// Result of starting a local VM: pid, the host-side port forwards, and the
/// per-disk file paths the caller persists to state.
pub struct StartedVm {
    pub pid: u32,
    pub host_status_port: u16,
    pub host_init_port: u16,
    /// Path to the unix socket that `-serial chardev:ser` is wired to.
    /// `cloud ssh` connects an interactive client (socat) to this socket;
    /// `cloud serial` keeps tailing the chardev's `logfile=` (`serial.log`).
    pub serial_sock: PathBuf,
    /// guest_port → host_port for workload-declared TCP ports (TCP only).
    pub workload_port_map: BTreeMap<u16, u16>,
}

/// Port set allocated up front so qemu's `-netdev hostfwd=...` argv is built
/// from concrete numbers. Ports are bound briefly to `127.0.0.1:0`, the
/// kernel-assigned port is read, and the listener is dropped — qemu binds
/// the freed port a moment later. There is a small race window if something
/// else grabs the port in between; acceptable for a single-operator dev box.
pub struct AllocatedPorts {
    pub status: u16,
    pub init: u16,
}

pub fn allocate_ports() -> io::Result<AllocatedPorts> {
    Ok(AllocatedPorts {
        status: free_loopback_port()?,
        init: free_loopback_port()?,
    })
}

fn free_loopback_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Spawn options for `start_vm`.
pub struct StartOptions<'a> {
    pub instance_dir: &'a Path,
    pub boot_overlay: &'a Path,
    pub ovmf: &'a Path,
    pub data_disks: &'a [(DiskSpec, PathBuf)],
    pub metadata: &'a [(String, String)],
    /// Workload-declared `"port/proto"` entries from the manifest. Only TCP
    /// is honored by qemu's user-mode `hostfwd`; non-tcp entries are dropped
    /// with a warning.
    pub workload_ports: &'a [String],
}

/// Start swtpm (`--terminate`) and qemu detached. Returns the recorded pid
/// and the host-port mapping the CLI will persist + use to drive `/init`.
pub fn start_vm(opts: StartOptions<'_>) -> Result<StartedVm, CloudError> {
    std::fs::create_dir_all(opts.instance_dir).map_err(|e| CloudError::IoPath {
        path: opts.instance_dir.to_path_buf(),
        source: e,
    })?;
    let tpm_dir = opts.instance_dir.join("tpm");
    std::fs::create_dir_all(&tpm_dir).map_err(|e| CloudError::IoPath {
        path: tpm_dir.clone(),
        source: e,
    })?;

    let swtpm_sock = opts.instance_dir.join("swtpm.sock");
    start_swtpm(&tpm_dir, &swtpm_sock)?;

    let ports = allocate_ports().map_err(|e| CloudError::InstanceError {
        message: format!("failed to allocate host ports: {e}"),
    })?;

    let workload_port_map = workload_tcp_port_map(opts.workload_ports);

    let serial_log = opts.instance_dir.join("serial.log");
    let serial_sock = opts.instance_dir.join("serial.sock");
    let qemu_log = opts.instance_dir.join("qemu.log");

    let argv = build_qemu_argv(
        opts.boot_overlay,
        opts.ovmf,
        &swtpm_sock,
        opts.data_disks,
        opts.metadata,
        &ports,
        &workload_port_map,
        &serial_log,
        &serial_sock,
    );

    // `process_group(0)` puts qemu in its own process group so a Ctrl-C on
    // the deploy command (or its parent shell) doesn't take down the VM.
    let qemu_log_w = std::fs::File::create(&qemu_log).map_err(|e| CloudError::IoPath {
        path: qemu_log.clone(),
        source: e,
    })?;
    let child = std::process::Command::new("qemu-system-x86_64")
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(qemu_log_w)
        .process_group(0)
        .spawn()
        .map_err(|e| CloudError::InstanceError {
            message: format!("failed to spawn qemu-system-x86_64: {e}"),
        })?;
    let pid = child.id();
    // Drop the handle without waiting; the kernel keeps qemu running.
    std::mem::forget(child);

    Ok(StartedVm {
        pid,
        host_status_port: ports.status,
        host_init_port: ports.init,
        serial_sock,
        workload_port_map,
    })
}

/// Send SIGTERM to `pid`, then SIGKILL after a grace period. Treats
/// "no such process" as success — the VM may have already exited.
pub fn stop_vm(pid: u32) -> Result<(), CloudError> {
    if pid == 0 {
        return Ok(());
    }
    if !process_alive(pid) {
        return Ok(());
    }
    // SIGTERM via the `kill` tool to avoid pulling in libc/nix for one call.
    let _ = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // Wait up to 5s for graceful exit.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !process_alive(pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Still alive — escalate.
    let _ = std::process::Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

fn process_alive(pid: u32) -> bool {
    // `/proc/<pid>` is the simplest check on Linux without a syscall crate.
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn start_swtpm(tpm_dir: &Path, sock: &Path) -> Result<(), CloudError> {
    // `--terminate` so swtpm exits when qemu disconnects the ctrl channel.
    // `-d` daemonizes — the parent returns once the daemon is ready.
    let tpmstate = format!("dir={}", tpm_dir.display());
    let ctrl = format!("type=unixio,path={}", sock.display());
    let status = std::process::Command::new("swtpm")
        .args([
            "socket",
            "--tpmstate",
            &tpmstate,
            "--ctrl",
            &ctrl,
            "--tpm2",
            "--terminate",
            "-d",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| CloudError::InstanceError {
            message: format!("failed to spawn swtpm: {e}"),
        })?;
    if !status.success() {
        return Err(CloudError::InstanceError {
            message: format!(
                "swtpm exited with status {} (state dir: {})",
                status.code().unwrap_or(-1),
                tpm_dir.display()
            ),
        });
    }
    // Brief wait for the unix socket to appear, since `-d` returns before
    // the listener is necessarily bound on some swtpm versions.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if sock.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(CloudError::InstanceError {
        message: format!("swtpm socket {} did not appear within 3s", sock.display()),
    })
}

/// Build the full `qemu-system-x86_64` argv. Public for unit tests.
#[allow(clippy::too_many_arguments)]
pub fn build_qemu_argv(
    boot_overlay: &Path,
    ovmf: &Path,
    swtpm_sock: &Path,
    data_disks: &[(DiskSpec, PathBuf)],
    metadata: &[(String, String)],
    ports: &AllocatedPorts,
    workload_port_map: &BTreeMap<u16, u16>,
    serial_log: &Path,
    serial_sock: &Path,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-machine".into(),
        "q35".into(),
        "-smp".into(),
        "2".into(),
        "-enable-kvm".into(),
        "-cpu".into(),
        "host".into(),
        "-m".into(),
        "4096".into(),
        "--bios".into(),
        ovmf.display().to_string(),
        "-drive".into(),
        format!("file={},format=qcow2,if=virtio", boot_overlay.display()),
        "-boot".into(),
        "c".into(),
        "-display".into(),
        "none".into(),
    ];

    // Data disks: virtio-blk with `serial=<device_name>` so the in-guest
    // agent discovers them at `/dev/disk/by-id/virtio-<device_name>`, matching
    // the cloud convention.
    for (i, (spec, path)) in data_disks.iter().enumerate() {
        let drive_id = format!("data{i}");
        args.push("-drive".into());
        args.push(format!(
            "if=none,id={drive_id},file={},format=qcow2",
            path.display()
        ));
        args.push("-device".into());
        args.push(format!(
            "virtio-blk-pci,drive={drive_id},serial={}",
            spec.device_name
        ));
    }

    // Networking: forward the portal ports unconditionally (atakit drives
    // them) plus any TCP workload ports (forward guest→same host port for
    // predictable curl). No guest:22 forward — interactive access is via
    // the serial chardev socket, not sshd.
    let mut hostfwd = vec![
        format!("hostfwd=tcp:127.0.0.1:{}-:2024", ports.status),
        format!("hostfwd=tcp:127.0.0.1:{}-:1024", ports.init),
    ];
    for (guest, host) in workload_port_map {
        // Skip the atakit-reserved ports if the workload happens to also
        // declare them — the portal forwards already cover those.
        if *guest == 1024 || *guest == 2024 {
            continue;
        }
        hostfwd.push(format!("hostfwd=tcp:127.0.0.1:{host}-:{guest}"));
    }
    args.push("-netdev".into());
    args.push(format!("user,id=net0,{}", hostfwd.join(",")));
    args.push("-device".into());
    args.push("e1000,netdev=net0".into());

    // vTPM via swtpm.
    args.push("-chardev".into());
    args.push(format!("socket,id=chrtpm,path={}", swtpm_sock.display()));
    args.push("-tpmdev".into());
    args.push("emulator,id=tpm0,chardev=chrtpm".into());
    args.push("-device".into());
    args.push("tpm-tis,tpmdev=tpm0".into());

    // SMBIOS OEM strings carry metadata. Whether the portal reads these
    // under the `qemu` platform is a portal-side concern; passing them is
    // best-effort and a no-op if unused.
    for (k, v) in metadata {
        args.push("-smbios".into());
        args.push(format!("type=11,value={k}={v}"));
    }

    // Serial console: a unix-socket chardev that ALSO logs to a file
    // (`logfile=`). `cloud serial` tails the log; `cloud ssh` socats into
    // the socket for an interactive console. `server=on,wait=off` lets
    // clients connect and disconnect freely without blocking qemu.
    args.push("-chardev".into());
    args.push(format!(
        "socket,id=ser,path={},server=on,wait=off,logfile={},logappend=on",
        serial_sock.display(),
        serial_log.display(),
    ));
    args.push("-serial".into());
    args.push("chardev:ser".into());

    args
}

/// Pick the TCP workload ports out of the manifest's `"port/proto"` list and
/// map each guest port to the same host port (for predictable `curl`). UDP
/// entries are dropped — qemu user-mode hostfwd only supports TCP.
fn workload_tcp_port_map(ports: &[String]) -> BTreeMap<u16, u16> {
    let mut out = BTreeMap::new();
    for entry in ports {
        let (port_s, proto) = entry.split_once('/').unwrap_or((entry, "tcp"));
        if !proto.eq_ignore_ascii_case("tcp") {
            tracing::warn!("ignoring non-tcp workload port {entry} for qemu hostfwd");
            continue;
        }
        if let Ok(p) = port_s.parse::<u16>() {
            out.insert(p, p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports() -> AllocatedPorts {
        AllocatedPorts {
            status: 50001,
            init: 50002,
        }
    }

    #[test]
    fn argv_baseline_no_data_no_metadata() {
        let argv = build_qemu_argv(
            Path::new("/run/boot.qcow2"),
            Path::new("/firm/ovmf.fd"),
            Path::new("/run/swtpm.sock"),
            &[],
            &[],
            &ports(),
            &BTreeMap::new(),
            Path::new("/run/serial.log"),
            Path::new("/run/serial.sock"),
        );
        let joined = argv.join(" ");
        assert!(joined.contains("--bios /firm/ovmf.fd"));
        assert!(joined.contains("file=/run/boot.qcow2,format=qcow2,if=virtio"));
        assert!(joined.contains("-enable-kvm"));
        assert!(joined.contains("type=11,").not(), "no metadata expected");
    }

    trait Not {
        fn not(self) -> bool;
    }
    impl Not for bool {
        fn not(self) -> bool {
            !self
        }
    }

    #[test]
    fn argv_hostfwds_status_and_init_only() {
        let argv = build_qemu_argv(
            Path::new("/b"),
            Path::new("/f"),
            Path::new("/s"),
            &[],
            &[],
            &ports(),
            &BTreeMap::new(),
            Path::new("/l"),
            Path::new("/sock"),
        );
        let joined = argv.join(" ");
        assert!(joined.contains("hostfwd=tcp:127.0.0.1:50001-:2024"));
        assert!(joined.contains("hostfwd=tcp:127.0.0.1:50002-:1024"));
        // No guest:22 forward — interactive shell is the serial socket.
        assert!(!joined.contains("-:22"));
    }

    #[test]
    fn argv_workload_ports_forwarded_same_host() {
        let mut map = BTreeMap::new();
        map.insert(3000_u16, 3000_u16);
        map.insert(8080_u16, 8080_u16);
        let argv = build_qemu_argv(
            Path::new("/b"),
            Path::new("/f"),
            Path::new("/s"),
            &[],
            &[],
            &ports(),
            &map,
            Path::new("/l"),
            Path::new("/sock"),
        );
        let joined = argv.join(" ");
        assert!(joined.contains("hostfwd=tcp:127.0.0.1:3000-:3000"));
        assert!(joined.contains("hostfwd=tcp:127.0.0.1:8080-:8080"));
    }

    #[test]
    fn argv_data_disks_attach_with_serial() {
        let spec = DiskSpec {
            name: "inst-secrets".into(),
            device_name: "secrets".into(),
            index: 1,
            size_gb: 4,
            disk_type: "qcow2".into(),
        };
        let argv = build_qemu_argv(
            Path::new("/b"),
            Path::new("/f"),
            Path::new("/s"),
            &[(spec, PathBuf::from("/run/data-secrets.qcow2"))],
            &[],
            &ports(),
            &BTreeMap::new(),
            Path::new("/l"),
            Path::new("/sock"),
        );
        let joined = argv.join(" ");
        assert!(joined.contains("if=none,id=data0,file=/run/data-secrets.qcow2,format=qcow2"));
        assert!(joined.contains("virtio-blk-pci,drive=data0,serial=secrets"));
    }

    #[test]
    fn argv_smbios_for_each_metadata_kv() {
        let argv = build_qemu_argv(
            Path::new("/b"),
            Path::new("/f"),
            Path::new("/s"),
            &[],
            &[("k1".into(), "v1".into()), ("k2".into(), "v=2".into())],
            &ports(),
            &BTreeMap::new(),
            Path::new("/l"),
            Path::new("/sock"),
        );
        let joined = argv.join(" ");
        assert!(joined.contains("type=11,value=k1=v1"));
        assert!(joined.contains("type=11,value=k2=v=2"));
    }

    #[test]
    fn argv_serial_uses_chardev_socket_with_logfile() {
        let argv = build_qemu_argv(
            Path::new("/b"),
            Path::new("/f"),
            Path::new("/s"),
            &[],
            &[],
            &ports(),
            &BTreeMap::new(),
            Path::new("/run/serial.log"),
            Path::new("/run/serial.sock"),
        );
        let joined = argv.join(" ");
        assert!(joined.contains(
            "socket,id=ser,path=/run/serial.sock,server=on,wait=off,\
             logfile=/run/serial.log,logappend=on"
        ));
        assert!(joined.contains("-serial chardev:ser"));
        // The old `-serial file:...` form must not appear.
        assert!(!joined.contains("-serial file:"));
    }

    #[test]
    fn workload_port_map_drops_udp_and_atakit_ports() {
        let map = workload_tcp_port_map(&[
            "3000/tcp".into(),
            "53/udp".into(),
            "1024/tcp".into(),
            "8080".into(),
        ]);
        // 53/udp dropped; 1024 kept here (filtered at argv-build time so it
        // can still surface in summary / state).
        assert!(map.contains_key(&3000));
        assert!(map.contains_key(&1024));
        assert!(map.contains_key(&8080));
        assert!(!map.contains_key(&53));
    }
}
