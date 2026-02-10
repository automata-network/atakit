use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::process::{Child, Command};
use tracing::info;

use crate::cmd;
use crate::{
    BlockStorage, CloudProvider, Compute, DiskFormat, ImageManager, InstanceInfo, Metadata,
    PortRule, Protocol,
};

// ── Configuration ─────────────────────────────────────────────────

/// Configuration for creating a [`Qemu`] provider instance.
pub struct QemuConfig {
    pub vm_name: String,
    /// Directory for per-instance files (disk.raw, data disks).
    pub instance_dir: PathBuf,
    /// Path to OVMF firmware file.
    pub ovmf_path: PathBuf,
    /// Path to the source tar.gz containing `disk.raw`.
    pub disk_tar_gz: PathBuf,
    /// Run without confirmation prompts.
    pub quiet: bool,
    /// Port forwarding rules for QEMU user-mode networking.
    pub port_rules: Vec<PortRule>,
}

// ── Provider ──────────────────────────────────────────────────────

pub struct Qemu {
    vm_name: String,
    instance_dir: PathBuf,
    ovmf_path: PathBuf,
    disk_tar_gz: PathBuf,
    quiet: bool,
    /// QEMU hostfwd rules derived from port_rules.
    host_forwards: Vec<String>,
    /// Data disks managed via BlockStorage.
    data_disk_paths: Vec<(String, PathBuf)>,
}

impl Qemu {
    pub fn new(config: QemuConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.instance_dir)
            .with_context(|| format!("Failed to create {}", config.instance_dir.display()))?;

        let host_forwards = build_host_forwards(&config.port_rules);

        Ok(Self {
            vm_name: config.vm_name,
            instance_dir: config.instance_dir,
            ovmf_path: config.ovmf_path,
            disk_tar_gz: config.disk_tar_gz,
            quiet: config.quiet,
            host_forwards,
            data_disk_paths: Vec::new(),
        })
    }

    /// Start swtpm as a background process.
    async fn start_swtpm(&self) -> Result<Child> {
        let state_dir = self.instance_dir.join("swtpm");
        std::fs::create_dir_all(&state_dir).with_context(|| {
            format!("Failed to create swtpm state dir: {}", state_dir.display())
        })?;

        let sock_path = self.swtpm_sock_path();
        info!(state_dir = %state_dir.display(), "Starting swtpm");

        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpmstate",
                &format!("dir={}", state_dir.display()),
                "--ctrl",
                &format!("type=unixio,path={}", sock_path.display()),
                "--tpm2",
                "--log",
                "level=1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start swtpm")?;

        // Give swtpm a moment to create the socket.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        Ok(child)
    }

    /// Path to swtpm socket.
    fn swtpm_sock_path(&self) -> PathBuf {
        self.instance_dir.join("swtpm.sock")
    }
}

// ── CloudProvider ─────────────────────────────────────────────────

#[async_trait]
impl CloudProvider for Qemu {
    fn name(&self) -> &str {
        "qemu"
    }

    fn disk_format(&self) -> DiskFormat {
        DiskFormat::Raw
    }

    async fn check_deps(&self) -> Result<()> {
        let required = ["qemu-system-x86_64", "qemu-img", "swtpm"];
        let mut missing: Vec<&str> = Vec::new();

        for dep in &required {
            if !cmd::command_exists(dep).await {
                missing.push(dep);
            }
        }

        if !self.ovmf_path.exists() {
            bail!(
                "OVMF firmware not found at {}. Place ovmf.fd at the configured path.",
                self.ovmf_path.display()
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
}

// ── ImageManager ──────────────────────────────────────────────────

#[async_trait]
impl ImageManager for Qemu {
    async fn upload_image(
        &mut self,
        _disk_path: &Path,
        _version: Option<&str>,
        _force: bool,
    ) -> Result<()> {
        // Extract disk.raw from the tar.gz into instance_dir.
        // For QEMU, we always extract fresh since it's a local operation.
        let tar_gz_path = &self.disk_tar_gz;
        if !tar_gz_path.exists() {
            bail!("Disk image not found: {}", tar_gz_path.display());
        }

        let dest = self.instance_dir.join("disk.raw");
        info!(src = %tar_gz_path.display(), dest = %dest.display(), "Extracting disk.raw");

        let tar_file = std::fs::File::open(tar_gz_path)
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

    async fn image_exists(&self, _version: Option<&str>) -> bool {
        // QEMU always extracts the image locally, no remote caching.
        false
    }

    async fn delete_image(&mut self) -> Result<()> {
        let disk_raw = self.instance_dir.join("disk.raw");
        if disk_raw.exists() {
            std::fs::remove_file(&disk_raw)
                .with_context(|| format!("Failed to delete {}", disk_raw.display()))?;
        }
        Ok(())
    }
}

// ── Compute ───────────────────────────────────────────────────────

#[async_trait]
impl Compute for Qemu {
    async fn create_instance(&mut self, metadata: &Metadata) -> Result<InstanceInfo> {
        let mut swtpm = self.start_swtpm().await?;

        let disk_raw = self.instance_dir.join("disk.raw");
        let netdev_arg = {
            let fwds = self.host_forwards.join(",");
            format!("user,id=net0,{fwds}")
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
            self.ovmf_path.to_string_lossy().into_owned(),
            "-drive".into(),
            format!("file={},format=raw,if=virtio", disk_raw.display()),
        ];

        // Attach data disks.
        for (i, (name, path)) in self.data_disk_paths.iter().enumerate() {
            let id = format!("datadisk{i}");
            args.push("-drive".into());
            args.push(format!(
                "file={},format=raw,if=none,id={}",
                path.display(),
                id
            ));
            args.push("-device".into());
            args.push(format!("virtio-blk-pci,drive={id},serial={}", name));
        }

        // Pass metadata as SMBIOS type=11 (OEM strings).
        // More universal than fw_cfg (doesn't require CONFIG_FW_CFG_SYSFS).
        // Guest can read via: dmidecode -t 11
        for (key, value) in metadata {
            args.push("-smbios".into());
            args.push(format!("type=11,value={key}={value}"));
        }

        args.extend([
            "-boot".into(),
            "c".into(),
            "-chardev".into(),
            format!("socket,id=chrtpm,path={}", self.swtpm_sock_path().display()),
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
        println!("  > {full_cmd}");

        if !self.quiet {
            use std::io::Write;
            print!("  Proceed? [y/N] ");
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                let _ = swtpm.kill().await;
                bail!("Aborted: {full_cmd}");
            }
        }

        info!(vm_name = %self.vm_name, "Launching QEMU (foreground, Ctrl-A X to exit)");

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        // Launch QEMU with stdin/stdout/stderr inherited for interactive use.
        // Using tokio::process::Command with Stdio::inherit() allows the user
        // to interact via the terminal while other async tasks (like init) run.
        let mut child = Command::new("qemu-system-x86_64")
            .args(&arg_refs)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn qemu-system-x86_64")?;

        // Wait for QEMU to exit. This yields to the tokio runtime,
        // allowing other tasks (like init_workload) to run concurrently.
        let status = child.wait().await.context("Failed to wait for QEMU")?;

        // Clean up swtpm.
        info!("QEMU exited, cleaning up swtpm");
        let _ = swtpm.kill().await;

        if !status.success() {
            bail!("qemu-system-x86_64 exited with status {status}");
        }

        info!(vm_name = %self.vm_name, "QEMU session complete");
        self.instance_info(&self.vm_name.clone()).await
    }

    async fn destroy_instance(&mut self, _name: &str) -> Result<()> {
        // QEMU runs in the foreground; nothing to destroy after it exits.
        Ok(())
    }

    async fn instance_info(&self, name: &str) -> Result<InstanceInfo> {
        Ok(InstanceInfo {
            name: name.to_string(),
            // QEMU user-mode networking doesn't expose a real public IP.
            public_ip: Some("127.0.0.1".to_string()),
        })
    }
}

// ── BlockStorage ──────────────────────────────────────────────────

#[async_trait]
impl BlockStorage for Qemu {
    async fn create_disk(&mut self, name: &str, size: &str) -> Result<()> {
        let raw_path = self.instance_dir.join(format!("{name}.raw"));
        if raw_path.exists() {
            info!(disk = %raw_path.display(), "Using existing data disk");
            if !self.data_disk_paths.iter().any(|(n, _)| n == name) {
                self.data_disk_paths.push((name.to_string(), raw_path));
            }
            return Ok(());
        }

        // Normalize size for qemu-img: strip trailing "B" (e.g. "100GB" -> "100G")
        // and append "G" if purely numeric.
        let size_arg = if size.bytes().all(|b| b.is_ascii_digit()) {
            format!("{size}G")
        } else {
            size.strip_suffix('B').unwrap_or(size).to_string()
        };

        info!(disk = %raw_path.display(), size = %size_arg, "Creating data disk");

        cmd::run_cmd(
            "qemu-img",
            &[
                "create",
                "-f",
                "raw",
                &raw_path.to_string_lossy(),
                &size_arg,
            ],
            self.quiet,
        )
        .await?;

        self.data_disk_paths.push((name.to_string(), raw_path));
        Ok(())
    }

    async fn delete_disk(&mut self, name: &str) -> Result<()> {
        let raw_path = self.instance_dir.join(format!("{name}.raw"));
        if raw_path.exists() {
            std::fs::remove_file(&raw_path)
                .with_context(|| format!("Failed to delete {}", raw_path.display()))?;
        }
        self.data_disk_paths.retain(|(_, p)| p != &raw_path);
        Ok(())
    }

    async fn disk_exists(&self, name: &str) -> Result<bool> {
        let raw_path = self.instance_dir.join(format!("{name}.raw"));
        Ok(raw_path.exists())
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Build QEMU `-netdev user` hostfwd rules from port rules.
///
/// Always includes the default agent port (`hostfwd=tcp::8000-:8000`).
fn build_host_forwards(port_rules: &[PortRule]) -> Vec<String> {
    let mut forwards: Vec<String> = vec!["hostfwd=tcp::8000-:8000".to_string()];

    for rule in port_rules {
        let proto = match rule.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        let fwd = format!("hostfwd={}::{}-:{}", proto, rule.port, rule.port);
        if !forwards.contains(&fwd) {
            forwards.push(fwd);
        }
    }

    forwards
}
