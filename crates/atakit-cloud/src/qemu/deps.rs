use crate::error::CloudError;

/// Tools the qemu provider shells out to.
const REQUIRED: &[(&str, &[&str], &str)] = &[
    (
        "qemu-system-x86_64",
        &["--version"],
        "qemu-system-x86 (apt: qemu-system-x86)",
    ),
    ("qemu-img", &["--version"], "qemu-utils (apt: qemu-utils)"),
    ("swtpm", &["--version"], "swtpm (apt: swtpm)"),
];

/// Verify every required binary is on PATH. Also surfaces a hint about
/// `/dev/kvm`, which `qemu -enable-kvm` will require at runtime.
pub fn check_local_deps() -> Result<(), CloudError> {
    for (bin, args, hint) in REQUIRED {
        match std::process::Command::new(bin)
            .args(*args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CloudError::DependencyMissing {
                    tool: (*bin).to_string(),
                    install_hint: (*hint).to_string(),
                });
            }
            Err(e) => return Err(CloudError::Io(e)),
        }
    }
    if !std::path::Path::new("/dev/kvm").exists() {
        return Err(CloudError::DependencyMissing {
            tool: "/dev/kvm".to_string(),
            install_hint:
                "KVM not available; load `kvm_intel`/`kvm_amd` or run on a host with hardware virt"
                    .to_string(),
        });
    }
    Ok(())
}
