use std::path::Path;

use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Create a qcow2 boot overlay backed by `base_disk`, sized to
/// `boot_disk_size_gb`. The base must itself be qcow2 — the image store ships
/// `qemu_disk.qcow2`.
pub async fn create_boot_overlay(
    base_disk: &Path,
    overlay: &Path,
    boot_disk_size_gb: u64,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let size = format!("{boot_disk_size_gb}G");
    let backing = format!("backing_file={},backing_fmt=qcow2", base_disk.display());
    let overlay_str = overlay.display().to_string();
    runner
        .run_capture(
            "qemu-img",
            &[
                "create",
                "-q",
                "-f",
                "qcow2",
                "-o",
                &backing,
                &overlay_str,
                &size,
            ],
        )
        .await
        .map(|_| ())
        .map_err(|e| CloudError::DiskError {
            message: format!("create boot overlay {}: {e}", overlay.display()),
        })
}

/// Create an empty qcow2 data disk at `path`, sized to `size_gb`.
pub async fn create_data_disk(
    path: &Path,
    size_gb: u64,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let size = format!("{size_gb}G");
    let path_str = path.display().to_string();
    runner
        .run_capture(
            "qemu-img",
            &["create", "-q", "-f", "qcow2", &path_str, &size],
        )
        .await
        .map(|_| ())
        .map_err(|e| CloudError::DiskError {
            message: format!("create data disk {}: {e}", path.display()),
        })
}
