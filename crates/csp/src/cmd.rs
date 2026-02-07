use std::io::{self, Write};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

/// Run a command with optional confirmation prompt.
///
/// Prints the full command, asks the user to confirm (unless `quiet`),
/// then executes. Returns an error on non-zero exit or if the user aborts.
pub async fn run_cmd(program: &str, args: &[&str], quiet: bool) -> Result<()> {
    let full_cmd = format!("{} {}", program, args.join(" "));
    println!();
    println!("  > {full_cmd}");

    if !quiet {
        print!("  Proceed? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            bail!("Aborted: {full_cmd}");
        }
    }

    let status = Command::new(program)
        .args(args)
        .status()
        .await
        .with_context(|| format!("Failed to run {full_cmd}"))?;
    if !status.success() {
        bail!("{full_cmd} failed with status {status}");
    }
    Ok(())
}

/// Run a command silently without prompting. Returns `true` on success.
pub async fn run_cmd_silent(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if a command is available on PATH.
pub async fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run an external command and capture stdout.
///
/// Returns `None` on failure or empty output.
pub async fn try_capture(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;

    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    }
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

/// Generate a resource name from a base name with a random suffix.
pub fn generate_name(base: &str, suffix_len: usize) -> String {
    let sanitized = sanitize_name(base);
    let base = if sanitized.is_empty() {
        "cvm".to_string()
    } else {
        sanitized
    };
    format!("{}{}", base, random_suffix(suffix_len))
}
