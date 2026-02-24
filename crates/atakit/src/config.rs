use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

#[allow(dead_code)]
#[derive(Debug)]
pub struct Config {
    pub script_dir: PathBuf,
    pub workload_dir: PathBuf,
    pub tools_dir: PathBuf,
    pub artifact_dir: PathBuf,
    pub disk_dir: PathBuf,
    pub is_installed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            script_dir: PathBuf::new(),
            workload_dir: PathBuf::new(),
            tools_dir: PathBuf::new(),
            artifact_dir: PathBuf::new(),
            disk_dir: PathBuf::new(),
            is_installed: false,
        }
    }
}

impl Config {
    /// Detect installation mode and resolve all paths.
    pub fn detect() -> Result<Self> {
        // Check standard installation paths (highest priority)
        let install_paths = [
            "/usr/local/share/atakit",
            "/usr/share/atakit",
            "/opt/homebrew/share/atakit",
        ];

        for base in &install_paths {
            let base = PathBuf::from(base);
            if base.join("scripts").is_dir() {
                let home = std::env::var("HOME").context("HOME not set")?;
                let cvm_home = PathBuf::from(&home).join(".atakit");
                let artifact_dir = cvm_home.join("artifacts");
                let disk_dir = cvm_home.join("disks");
                std::fs::create_dir_all(&artifact_dir)?;
                std::fs::create_dir_all(&disk_dir)?;

                return Ok(Config {
                    script_dir: base.join("scripts"),
                    workload_dir: base.join("workload"),
                    tools_dir: base.join("tools"),
                    artifact_dir,
                    disk_dir,
                    is_installed: true,
                });
            }
        }

        // Development mode: search for scripts/ relative to executable or cwd
        let dev_root = Self::find_dev_root()?;
        let artifact_dir = dev_root.join("_artifacts");
        std::fs::create_dir_all(&artifact_dir)?;

        Ok(Config {
            script_dir: dev_root.join("scripts"),
            workload_dir: dev_root.join("workload"),
            tools_dir: dev_root.join("tools"),
            artifact_dir,
            disk_dir: dev_root,
            is_installed: false,
        })
    }

    fn find_dev_root() -> Result<PathBuf> {
        // Try executable's ancestor directories (handles running from target/debug/)
        if let Ok(exe) = std::env::current_exe() {
            if let Ok(exe) = exe.canonicalize() {
                let mut dir = exe.parent();
                for _ in 0..10 {
                    match dir {
                        Some(d) if d.join("scripts").is_dir() => return Ok(d.to_path_buf()),
                        Some(d) => dir = d.parent(),
                        None => break,
                    }
                }
            }
        }

        // Try current working directory and its ancestors
        if let Ok(cwd) = std::env::current_dir() {
            let mut dir: Option<&Path> = Some(&cwd);
            for _ in 0..10 {
                match dir {
                    Some(d) if d.join("scripts").is_dir() => return Ok(d.to_path_buf()),
                    Some(d) => dir = d.parent(),
                    None => break,
                }
            }
        }

        bail!("Cannot locate atakit installation. Ensure scripts/ directory is present.")
    }

    /// Check that required system dependencies are available.
    pub fn check_dependencies(&self) -> Result<()> {
        let deps = ["curl", "jq", "unzip", "openssl"];
        let mut missing: Vec<&str> = Vec::new();

        for dep in &deps {
            if !command_exists(dep) {
                missing.push(dep);
            }
        }

        // sha256sum (Linux) or shasum (macOS)
        if !command_exists("sha256sum") && !command_exists("shasum") {
            missing.push("coreutils");
        }

        if missing.is_empty() {
            return Ok(());
        }

        warn!(deps = %missing.join(", "), "Missing dependencies");
        info!("Attempting to install missing dependencies");

        if cfg!(target_os = "macos") {
            if command_exists("brew") {
                let status = Command::new("brew")
                    .arg("install")
                    .args(&missing)
                    .status()
                    .context("failed to run brew")?;
                if !status.success() {
                    bail!("Failed to install dependencies via Homebrew");
                }
            } else {
                bail!(
                    "Homebrew not found. Please install dependencies manually:\n  brew install {}",
                    missing.join(" ")
                );
            }
        } else if command_exists("apt-get") {
            let status = Command::new("sudo")
                .args(["apt-get", "update", "-qq"])
                .status()
                .context("failed to run apt-get update")?;
            if !status.success() {
                bail!("apt-get update failed");
            }
            let status = Command::new("sudo")
                .args(["apt-get", "install", "-y"])
                .args(&missing)
                .status()
                .context("failed to run apt-get install")?;
            if !status.success() {
                bail!("Failed to install dependencies via apt-get");
            }
        } else {
            bail!(
                "Could not detect package manager. Please install manually:\n  {}",
                missing.join(" ")
            );
        }

        info!("Dependencies installed successfully");
        Ok(())
    }

    /// Run a script from the scripts directory with a custom workload dir.
    pub fn run_script(&self, name: &str, args: &[&str], workload_dir: &Path) -> Result<()> {
        let script = self.script_dir.join(name);
        let status = Command::new(&script)
            .args(args)
            .env("ARTIFACT_DIR", &self.artifact_dir)
            .env("SCRIPT_DIR", &self.script_dir)
            .env("TOOLS_DIR", &self.tools_dir)
            .env("WORKLOAD_DIR", workload_dir)
            .current_dir(&self.disk_dir)
            .status()
            .with_context(|| format!("failed to execute {}", name))?;
        if !status.success() {
            bail!("{} exited with status {}", name, status);
        }
        Ok(())
    }

    /// Run a script using the default workload directory from config.
    pub fn run_script_default(&self, name: &str, args: &[&str]) -> Result<()> {
        let wl = self.workload_dir.clone();
        self.run_script(name, args, &wl)
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Check if a command is available on PATH.
pub fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run an external command and capture stdout. Returns None on failure or empty output.
pub fn try_capture(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            } else {
                None
            }
        })
}

/// Sanitize a name to lowercase alphanumeric characters only.
pub fn sanitize_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Generate a random lowercase alphanumeric suffix.
pub fn random_suffix(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx: u8 = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Generate a resource name from a VM name with a random suffix.
pub fn generate_name(vm_name: &str, suffix_len: usize) -> String {
    let sanitized = sanitize_name(vm_name);
    let base = if sanitized.is_empty() {
        "cvm".to_string()
    } else {
        sanitized
    };
    format!("{}{}", base, random_suffix(suffix_len))
}