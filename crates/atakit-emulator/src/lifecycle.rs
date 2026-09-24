//! Graceful shutdown and scoped cleanup. Lock files keep stable inodes across cleanup.
use crate::runtime::{self, SocketOwnership};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Duration,
};

fn lock_file(dir: &Path, name: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(name))?)
}

/// Call only while holding the runtime lock. Unknown files and data are preserved.
pub(crate) fn cleanup(dir: &Path, purge_data: bool) -> Result<()> {
    let manifest = dir.join("sockets.private.json");
    if manifest.exists() {
        let records: Vec<SocketOwnership> = serde_json::from_slice(&fs::read(&manifest)?)
            .context("invalid socket ownership manifest; refusing unsafe socket cleanup")?;
        for record in records {
            runtime::recover_stale_socket(&record)?;
        }
    }
    let workload_manifest = dir.join("workload-dirs.private.json");
    if workload_manifest.exists() {
        let names: Vec<String> = serde_json::from_slice(&fs::read(&workload_manifest)?)
            .context("invalid workload directory manifest; refusing unsafe cleanup")?;
        for name in &names {
            crate::config::validate_name(name)?;
        }
        for name in names {
            remove(&dir.join(name))?;
        }
    }
    for name in [
        "workload-dirs.private.json",
        "launch.private.json",
        "checkpoint.json",
        "checkpoint.previous.json",
        "endpoints.json",
        "sockets.private.json",
        "emulator.log",
        "anvil.log",
        "compose.yaml",
        "compose",
        "workloads",
        "bridges",
    ] {
        remove(&dir.join(name))?;
    }
    for item in fs::read_dir(dir)? {
        let item = item?;
        let name = item.file_name();
        if [
            "checkpoint.tmp-",
            "launch.private.tmp-",
            "endpoints.tmp-",
            "sockets.private.tmp-",
        ]
        .iter()
        .any(|prefix| name.to_string_lossy().starts_with(prefix))
            && !item.file_type()?.is_dir()
        {
            fs::remove_file(item.path())?;
        }
    }
    if purge_data {
        remove(&dir.join("data"))?;
    }
    Ok(())
}
fn remove(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

pub async fn shutdown(dir: &Path, clean: bool, purge_data: bool) -> Result<Value> {
    if !dir.exists() {
        return Ok(json!({"state":"not_running", "runtime_dir":dir}));
    }
    if ![
        "launch.private.json",
        "checkpoint.json",
        "endpoints.json",
        "startup.lock",
        "runtime.lock",
    ]
    .iter()
    .any(|name| dir.join(name).exists())
    {
        bail!(
            "{} is not a recognized emulator runtime directory; nothing was removed",
            dir.display()
        );
    }
    runtime::private_dir(dir)?;
    let startup = lock_file(dir, "startup.lock")?;
    startup
        .try_lock_exclusive()
        .context("another emulator lifecycle command is in progress; retry after it finishes")?;
    let lock = lock_file(dir, "runtime.lock")?;
    match lock.try_lock_exclusive() {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let op = if clean { "down" } else { "stop" };
            let result = runtime::control(dir, op, None).await;
            // Daemons started by an older binary use `down` for a preserving stop.
            if !clean
                && result
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.to_string().contains("unknown control operation"))
            {
                runtime::control(dir, "down", None).await?;
            } else {
                result.context("could not stop the running emulator; no files were removed")?;
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                match lock.try_lock_exclusive() {
                    Ok(()) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(e) => return Err(e.into()),
                }
                if tokio::time::Instant::now() >= deadline {
                    bail!("emulator did not finish stopping within 30 seconds; no files were removed by this command");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        Err(e) => return Err(e.into()),
    }
    if clean {
        cleanup(dir, purge_data)?;
    }
    Ok(
        json!({"state":if clean {"removed"} else {"stopped"}, "runtime_dir":dir,
        "checkpoint_preserved":dir.join("checkpoint.json").exists(),
        "data_preserved":dir.join("data").exists(),
        "message":if clean {"Runtime state removed; lock files retained for lifecycle coordination."} else {"Runtime state preserved; run emulator up with the same configuration to resume."}}),
    )
}
