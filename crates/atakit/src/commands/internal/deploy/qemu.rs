use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result, bail};
use tracing::info;

use super::CloudPlatform;
use crate::config::{self, Config};
use crate::types::DiskDef;

struct DataDisk {
    name: String,
    size: String,
    /// Resolved data disk path after `ensure_data_disk` runs.
    path: Option<PathBuf>,
}

pub(crate) struct Qemu {
    vm_name: String,
    /// Per-instance working directory: `ata_artifacts/qemu/{vm_name}`.
    instance_dir: PathBuf,
    /// Global disk directory from Config (contains deps/ovmf.fd, gcp_disk.tar.gz).
    disk_dir: PathBuf,
    quiet: bool,
    /// QEMU hostfwd rules derived from compose ports.
    host_forwards: Vec<String>,
    /// Data disks derived from DiskDef entries.
    data_disks: Vec<DataDisk>,
    /// Path to the additional-data FAT image to attach (readonly).
    additional_data_disk_path: Option<PathBuf>,
}

/// Build QEMU `-netdev user` hostfwd rules from compose port mappings.
///
/// Always includes the default agent port (`hostfwd=tcp::8000-:8000`).
/// Compose ports in `HOST:CONTAINER[/proto]` or `IP:HOST:CONTAINER[/proto]`
/// format are appended as `hostfwd=tcp::{HOST}-:{CONTAINER}`.
fn build_host_forwards(compose_ports: &[(String, String)]) -> Vec<String> {
    let mut forwards: Vec<String> = vec!["hostfwd=tcp::8000-:8000".to_string()];

    for (_service, raw) in compose_ports {
        let (port_part, _protocol) = if let Some((p, proto)) = raw.rsplit_once('/') {
            if matches!(proto, "tcp" | "udp" | "sctp") {
                (p, proto)
            } else {
                (raw.as_str(), "tcp")
            }
        } else {
            (raw.as_str(), "tcp")
        };

        let parts: Vec<&str> = port_part.split(':').collect();
        let (host_port, container_port) = match parts.len() {
            1 => continue,
            2 => (parts[0], parts[1]),
            3 => (parts[1], parts[2]),
            _ => continue,
        };

        let fwd = format!("hostfwd=tcp::{}-:{}", host_port, container_port);
        if !forwards.contains(&fwd) {
            forwards.push(fwd);
        }
    }

    forwards
}

impl Qemu {
    pub(crate) fn new(
        deployment_name: &str,
        cfg: &Config,
        quiet: bool,
        compose_ports: &[(String, String)],
        disk_defs: &[&DiskDef],
    ) -> Result<Self> {
        let instance_dir = cfg.artifact_dir.join("qemu").join(deployment_name);
        std::fs::create_dir_all(&instance_dir)
            .with_context(|| format!("Failed to create {}", instance_dir.display()))?;

        let host_forwards = build_host_forwards(compose_ports);
        let data_disks: Vec<DataDisk> = disk_defs
            .iter()
            .map(|d| DataDisk {
                name: d.name.clone(),
                size: d.size.clone(),
                path: None,
            })
            .collect();

        info!(
            platform = "gcp_qemu",
            vm_name = deployment_name,
            instance_dir = %instance_dir.display(),
            forwards = ?host_forwards,
            "QEMU deployment configuration"
        );

        Ok(Self {
            vm_name: deployment_name.to_string(),
            instance_dir,
            disk_dir: cfg.disk_dir.clone(),
            quiet,
            host_forwards,
            data_disks,
            additional_data_disk_path: None,
        })
    }

    /// Start swtpm as a background process. Returns the child handle so
    /// we can kill it after QEMU exits.
    fn start_swtpm(&self) -> Result<Child> {
        let state_dir = std::env::temp_dir().join(format!("swtpm-{}", self.vm_name));
        std::fs::create_dir_all(&state_dir).with_context(|| {
            format!("Failed to create swtpm state dir: {}", state_dir.display())
        })?;

        info!(state_dir = %state_dir.display(), "Starting swtpm");

        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpmstate",
                &format!("dir={}", state_dir.display()),
                "--ctrl",
                "type=unixio,path=/tmp/swtpm-sock",
                "--tpm2",
                "--log",
                "level=1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start swtpm")?;

        // Give swtpm a moment to create the socket.
        std::thread::sleep(std::time::Duration::from_millis(500));
        Ok(child)
    }

    /// Create data disk files for all configured disks that don't already exist.
    fn resolve_data_disks(&mut self) -> Result<()> {
        let instance_dir = self.instance_dir.clone();
        let quiet = self.quiet;
        for disk in &mut self.data_disks {
            let raw_path = instance_dir.join(format!("{}.raw", disk.name));
            if raw_path.exists() {
                info!(disk = %raw_path.display(), "Using existing data disk");
                disk.path = Some(raw_path);
                continue;
            }

            let size = &disk.size;
            // Normalize size for qemu-img: strip trailing "B" (e.g. "100GB" → "100G")
            // and append "G" if purely numeric.
            let size_arg = if size.bytes().all(|b| b.is_ascii_digit()) {
                format!("{}G", size)
            } else {
                size.strip_suffix('B').unwrap_or(size).to_string()
            };
            info!(disk = %raw_path.display(), size = %size_arg, "Creating data disk");

            super::run_cmd(
                "qemu-img",
                &[
                    "create",
                    "-f",
                    "raw",
                    &raw_path.to_string_lossy(),
                    &size_arg,
                ],
                quiet,
            )?;

            disk.path = Some(raw_path);
        }
        Ok(())
    }
}

impl CloudPlatform for Qemu {
    fn name(&self) -> &str {
        "gcp_qemu"
    }

    fn disk_filename(&self) -> &str {
        "gcp_disk.tar.gz"
    }

    fn check_deps(&self, _cfg: &Config) -> Result<()> {
        let required = ["qemu-system-x86_64", "qemu-img", "swtpm"];
        let mut missing: Vec<&str> = Vec::new();

        for dep in &required {
            if !config::command_exists(dep) {
                missing.push(dep);
            }
        }

        let ovmf_path = self.disk_dir.join("deps").join("ovmf.fd");
        if !ovmf_path.exists() {
            bail!(
                "OVMF firmware not found at {}. Place ovmf.fd in the deps/ directory.",
                ovmf_path.display()
            );
        }

        if !missing.is_empty() {
            bail!(
                "Missing required tools: {}. Install them and try again.",
                missing.join(", ")
            );
        }

        Ok(())
    }

    fn prepare_image(&mut self, cfg: &Config) -> Result<()> {
        // Extract disk.raw from gcp_disk.tar.gz into instance_dir.
        let tar_gz_path = cfg.disk_dir.join("gcp_disk.tar.gz");
        if !tar_gz_path.exists() {
            bail!("GCP disk image not found: {}", tar_gz_path.display());
        }

        let dest = self.instance_dir.join("disk.raw");
        info!(src = %tar_gz_path.display(), dest = %dest.display(), "Extracting disk.raw");

        let tar_file = std::fs::File::open(&tar_gz_path)
            .with_context(|| format!("Failed to open {}", tar_gz_path.display()))?;
        let decoder = flate2::read::GzDecoder::new(tar_file);
        let mut archive = tar::Archive::new(decoder);

        let mut found = false;
        for entry in archive.entries().context("Failed to read tar entries")? {
            let mut entry = entry.context("Failed to read tar entry")?;
            let path = entry.path().context("Failed to read entry path")?;
            if path.file_name().map(|f| f == "disk.raw").unwrap_or(false) {
                let mut out = std::fs::File::create(&dest)
                    .with_context(|| format!("Failed to create {}", dest.display()))?;
                std::io::copy(&mut entry, &mut out).context("Failed to extract disk.raw")?;
                found = true;
                break;
            }
        }

        if !found {
            bail!("disk.raw not found inside {}", tar_gz_path.display());
        }

        info!(path = %dest.display(), "disk.raw extracted");
        Ok(())
    }

    fn ensure_data_disk(&mut self) -> Result<()> {
        self.resolve_data_disks()
    }

    fn launch(&self) -> Result<()> {
        // Start swtpm.
        let mut swtpm = self.start_swtpm()?;

        // Build QEMU command.
        let disk_raw = self.instance_dir.join("disk.raw");
        let ovmf_path = self.disk_dir.join("deps").join("ovmf.fd");

        let netdev_arg = {
            let fwds = self.host_forwards.join(",");
            format!("user,id=net0,{}", fwds)
        };

        let mut args: Vec<String> = vec![
            "-smp".into(),
            "2".into(),
            "-machine".into(),
            "accel=tcg".into(),
            "-m".into(),
            "4096".into(),
            "-netdev".into(),
            netdev_arg,
            "-device".into(),
            "e1000,netdev=net0".into(),
            "--bios".into(),
            ovmf_path.to_string_lossy().into_owned(),
            "-drive".into(),
            format!("file={},format=raw,if=virtio", disk_raw.display()),
        ];

        for (i, disk) in self.data_disks.iter().enumerate() {
            if let Some(ref path) = disk.path {
                let id = format!("datadisk{}", i);
                args.push("-drive".into());
                args.push(format!(
                    "file={},format=raw,if=none,id={}",
                    path.display(),
                    id
                ));
                args.push("-device".into());
                args.push(format!("virtio-blk-pci,drive={},serial={}", id, disk.name));
            }
        }

        if let Some(ref ad_path) = self.additional_data_disk_path {
            args.push("-drive".into());
            args.push(format!(
                "file={},format=raw,if=virtio,readonly=on",
                ad_path.display()
            ));
        }

        args.extend([
            "-boot".into(),
            "c".into(),
            "-chardev".into(),
            "socket,id=chrtpm,path=/tmp/swtpm-sock".into(),
            "-tpmdev".into(),
            "emulator,id=tpm0,chardev=chrtpm".into(),
            "-device".into(),
            "tpm-tis,tpmdev=tpm0".into(),
            "-serial".into(),
            "mon:stdio".into(),
            "-nographic".into(),
        ]);

        let full_cmd = format!("qemu-system-x86_64 {}", args.join(" "));
        println!();
        println!("  > {}", full_cmd);

        if !self.quiet {
            use std::io::Write;
            print!("  Proceed? [y/N] ");
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                let _ = swtpm.kill();
                bail!("Aborted: {}", full_cmd);
            }
        }

        info!(vm_name = %self.vm_name, "Launching QEMU (foreground, Ctrl-A X to exit)");

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let status = Command::new("qemu-system-x86_64")
            .args(&arg_refs)
            .status()
            .context("Failed to launch qemu-system-x86_64")?;

        // Clean up swtpm.
        info!("QEMU exited, cleaning up swtpm");
        let _ = swtpm.kill();
        let _ = swtpm.wait();

        if !status.success() {
            bail!("qemu-system-x86_64 exited with status {}", status);
        }

        info!(vm_name = %self.vm_name, "QEMU session complete");
        Ok(())
    }

    fn post_launch(&self) -> Result<()> {
        Ok(())
    }

    fn setup_network(&mut self) -> Result<()> {
        Ok(())
    }
}
