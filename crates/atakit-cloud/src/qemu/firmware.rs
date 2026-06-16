use std::path::PathBuf;

use crate::error::CloudError;

const ENV_OVERRIDE: &str = "ATAKIT_QEMU_UEFI";

/// Resolve the qemu UEFI/OVMF firmware path.
///
/// Precedence (highest first):
/// 1. `ATAKIT_QEMU_UEFI` environment variable
/// 2. `[cloud.targets.<name>] uefi = "..."` (per-target override)
/// 3. `[cloud.providers.<name>] uefi = "..."` (provider default — the common case)
///
/// Returns an error if none are set, or if the resolved path does not point
/// at a readable file. The error message names where to drop the OVMF blob.
pub fn resolve_uefi(
    target_uefi: Option<&str>,
    provider_uefi: Option<&str>,
) -> Result<PathBuf, CloudError> {
    let raw = std::env::var(ENV_OVERRIDE)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| target_uefi.map(str::to_string))
        .or_else(|| provider_uefi.map(str::to_string))
        .ok_or_else(|| CloudError::Config {
            message: format!(
                "qemu UEFI firmware not configured. Set one of (in priority order):\n  \
                 - {ENV_OVERRIDE} env var\n  \
                 - `[cloud.targets.<name>] uefi = \"/path/to/ovmf.fd\"`\n  \
                 - `[cloud.providers.<name>] uefi = \"/path/to/ovmf.fd\"`\n\
                 Stock distro OVMF lacks the TPM-measuring build atakit needs; \
                 see the project README for where to download a compatible blob."
            ),
        })?;

    let path = expand_path(&raw);
    if !path.is_file() {
        return Err(CloudError::Config {
            message: format!(
                "qemu UEFI firmware path does not point at a readable file: {} \
                 (source: {ENV_OVERRIDE} / target.uefi / provider.uefi)",
                path.display()
            ),
        });
    }
    Ok(path)
}

/// Expand a leading `~` (and `~/`) to the user's home directory. Anything
/// else is passed through unchanged. We deliberately don't pull in `shellexpand`
/// for a one-character convenience.
fn expand_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if trimmed == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_handles_tilde() {
        std::env::set_var("HOME", "/h");
        assert_eq!(expand_path("~/x"), PathBuf::from("/h/x"));
        assert_eq!(expand_path("~"), PathBuf::from("/h"));
        assert_eq!(expand_path("/abs"), PathBuf::from("/abs"));
        assert_eq!(expand_path("rel/p"), PathBuf::from("rel/p"));
    }
}
