use std::collections::HashSet;
use std::path::Path;

use crate::config::{ImageSource, WorkloadConfig};
use crate::WorkloadError;

/// Validate a parsed config against the spec rules.
///
/// `workload_dir` is the directory containing `atakit-workload.toml`, used to
/// resolve relative paths.
pub fn validate_config(
    config: &WorkloadConfig,
    workload_dir: &Path,
) -> Result<Vec<String>, WorkloadError> {
    let mut warnings = Vec::new();
    let w = &config.workload;

    // ── format version ───────────────────────────────────
    if config.format > crate::FORMAT_VERSION {
        return Err(WorkloadError::Validation(format!(
            "atakit-workload.toml format version {} is newer than supported ({}); upgrade atakit",
            config.format, crate::FORMAT_VERSION
        )));
    }

    // ── name ──────────────────────────────────────────────
    if w.name.is_empty()
        || !w
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        || w.name.starts_with('-')
    {
        return Err(WorkloadError::Validation(format!(
            "name must be alphanumeric + hyphens, got {:?}",
            w.name
        )));
    }

    // ── version ───────────────────────────────────────────
    if !w.version.starts_with('v') {
        return Err(WorkloadError::Validation(format!(
            "version must start with 'v', got {:?}",
            w.version
        )));
    }

    // ── base-image-mode ───────────────────────────────────
    if w.base_image_mode != "whitelist" && w.base_image_mode != "blacklist" {
        return Err(WorkloadError::Validation(format!(
            "base-image-mode must be \"whitelist\" or \"blacklist\", got {:?}",
            w.base_image_mode
        )));
    }

    // ── image source ──────────────────────────────────────
    validate_image_source(&w.image, workload_dir)?;

    // ── measured-data paths ───────────────────────────────
    for p in &w.measured_data {
        if !p.starts_with("./") {
            return Err(WorkloadError::Validation(format!(
                "measured-data path must start with \"./\": {p:?}"
            )));
        }
        let abs = workload_dir.join(p);
        if !abs.exists() {
            return Err(WorkloadError::MeasuredDataMissing(abs));
        }
    }

    // ── unmeasured-data paths (format check only, files need not exist) ──
    for p in &w.unmeasured_data {
        if !p.starts_with("./") {
            return Err(WorkloadError::Validation(format!(
                "unmeasured-data path must start with \"./\": {p:?}"
            )));
        }
    }

    // ── env_file ──────────────────────────────────────────
    if let Some(ref env_files) = w.env_file {
        for ef in env_files.as_vec() {
            let abs = workload_dir.join(&ef);
            if !abs.exists() {
                return Err(WorkloadError::EnvFileMissing(abs));
            }
        }
    }

    // ── signing ───────────────────────────────────────────
    if let Some(ref signing) = config.signing {
        if signing.enable {
            let auth = signing
                .auth_info
                .as_ref()
                .ok_or_else(|| {
                    WorkloadError::Validation(
                        "signing.auth_info is required when signing is enabled".into(),
                    )
                })?;
            let policy = signing
                .policy
                .as_ref()
                .ok_or_else(|| {
                    WorkloadError::Validation(
                        "signing.policy is required when signing is enabled".into(),
                    )
                })?;

            if !auth.starts_with("./") {
                return Err(WorkloadError::Validation(
                    "signing.auth_info must start with \"./\"".into(),
                ));
            }
            if !policy.starts_with("./") {
                return Err(WorkloadError::Validation(
                    "signing.policy must start with \"./\"".into(),
                ));
            }

            let auth_path = workload_dir.join(auth);
            if !auth_path.exists() {
                return Err(WorkloadError::SigningFileMissing(auth_path));
            }
            let policy_path = workload_dir.join(policy);
            if !policy_path.exists() {
                return Err(WorkloadError::SigningFileMissing(policy_path));
            }
        }
    }

    // ── disk references ───────────────────────────────────
    for disk_name in w.disks.keys() {
        if !config.disks.contains_key(disk_name) {
            return Err(WorkloadError::Validation(format!(
                "workload.disks references undefined disk: {disk_name:?}"
            )));
        }
    }

    // ── firewall ──────────────────────────────────────────
    if let Some(ref fw) = config.firewall {
        for rule in &fw.allow {
            if rule.port < 1025 {
                return Err(WorkloadError::Validation(format!(
                    "firewall allow port must be >= 1025, got {}",
                    rule.port
                )));
            }
            if rule.protocol != "tcp" && rule.protocol != "udp" {
                return Err(WorkloadError::Validation(format!(
                    "firewall protocol must be \"tcp\" or \"udp\", got {:?}",
                    rule.protocol
                )));
            }
        }
        for &port in &fw.deny {
            if port < 1025 {
                return Err(WorkloadError::Validation(format!(
                    "firewall deny port must be >= 1025, got {port}"
                )));
            }
        }
    }

    // ── baby-container ────────────────────────────────────
    if let Some(ref bc) = config.baby_container {
        if bc.max_count == 0 {
            return Err(WorkloadError::Validation(
                "baby-container.max_count must be a positive integer".into(),
            ));
        }
    }

    // ── disk size format + encryption ────────────────────
    for (name, disk) in &config.disks {
        if !is_valid_size(&disk.size) {
            return Err(WorkloadError::Validation(format!(
                "disk {name:?} size must be a valid size string (e.g. \"10GB\", \"500MB\"), got {:?}",
                disk.size
            )));
        }
        if let Some(ref enc) = disk.encryption {
            if enc.enable && enc.key_security != "standard" && enc.key_security != "strong" {
                return Err(WorkloadError::Validation(format!(
                    "disk {name:?} encryption.key_security must be \"standard\" or \"strong\""
                )));
            }
        }
    }

    // ── disk single-mount constraint ─────────────────────
    {
        let mut mounted_disks: HashSet<&str> = HashSet::new();
        for disk_name in w.disks.keys() {
            if !mounted_disks.insert(disk_name) {
                return Err(WorkloadError::Validation(format!(
                    "disk {disk_name:?} is mounted more than once"
                )));
            }
        }
        for (dep_name, dep) in &config.dependencies {
            for disk_name in dep.disks.keys() {
                if !mounted_disks.insert(disk_name) {
                    return Err(WorkloadError::Validation(format!(
                        "disk {disk_name:?} is mounted by multiple containers \
                         (also used by dependency {dep_name:?})"
                    )));
                }
            }
        }
    }

    // ── firewall cross-reference with ports ───────────────
    if let Some(ref fw) = config.firewall {
        let auto_ports = collect_auto_derived_ports(config);

        for rule in &fw.allow {
            if rule.protocol == "tcp" && auto_ports.contains(&rule.port) {
                warnings.push(format!(
                    "firewall allow port {} is redundant (already auto-derived from ports)",
                    rule.port
                ));
            }
        }
        for &port in &fw.deny {
            if !auto_ports.contains(&port) {
                warnings.push(format!(
                    "firewall deny port {port} does not match any auto-derived port (no-op)"
                ));
            }
        }
    }

    // ── dependencies (warn, not error) ────────────────────
    if !config.dependencies.is_empty() {
        warnings.push(
            "[dependencies] section found but dependencies are not yet implemented; \
             only the main workload will be built"
                .into(),
        );
    }

    Ok(warnings)
}

fn validate_image_source(source: &ImageSource, workload_dir: &Path) -> Result<(), WorkloadError> {
    match source {
        ImageSource::Registry(s) => {
            if s.is_empty() {
                return Err(WorkloadError::Validation(
                    "image registry string is empty".into(),
                ));
            }
        }
        ImageSource::Build { build, .. } => {
            let ctx = workload_dir.join(build);
            if !ctx.is_dir() {
                return Err(WorkloadError::Validation(format!(
                    "image build context is not a directory: {}",
                    ctx.display()
                )));
            }
        }
        ImageSource::File { file } => {
            if !file.ends_with(".tar") && !file.ends_with(".tar.gz") {
                return Err(WorkloadError::Validation(format!(
                    "image file must end in .tar or .tar.gz: {file:?}"
                )));
            }
            let abs = workload_dir.join(file);
            if !abs.exists() {
                return Err(WorkloadError::ImageFileMissing(abs));
            }
        }
    }
    Ok(())
}

/// Validate a disk size string: digits followed by a unit suffix (MB, GB, TB).
fn is_valid_size(s: &str) -> bool {
    let s = s.trim();
    for suffix in ["TB", "GB", "MB"] {
        if let Some(num) = s.strip_suffix(suffix) {
            return !num.is_empty() && num.chars().all(|c| c.is_ascii_digit());
        }
    }
    false
}

/// Collect all host ports auto-derived from `ports` fields across workload and dependencies.
///
/// Port format: `"host:container"` or `"host:container/udp"`. Auto-derived firewall rules
/// use the host port with TCP.
fn collect_auto_derived_ports(config: &WorkloadConfig) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for spec in &config.workload.ports {
        if let Some(host_port) = parse_host_port(spec) {
            ports.insert(host_port);
        }
    }
    for dep in config.dependencies.values() {
        for spec in &dep.ports {
            if let Some(host_port) = parse_host_port(spec) {
                ports.insert(host_port);
            }
        }
    }
    ports
}

/// Extract the host port number from a port spec like `"3000:3000"` or `"8080:80/udp"`.
fn parse_host_port(spec: &str) -> Option<u16> {
    // Strip optional protocol suffix
    let without_proto = spec.split('/').next()?;
    let host_part = without_proto.split(':').next()?;
    host_part.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_toml() -> &'static str {
        r#"
format = 1

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
"#
    }

    #[test]
    fn valid_minimal_config() {
        let cfg: crate::config::WorkloadConfig = toml::from_str(minimal_toml()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let warnings = validate_config(&cfg, tmp.path()).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn rejects_bad_name() {
        let toml = r#"
format = 1

[workload]
name = "-bad"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_err());
    }

    #[test]
    fn rejects_bad_base_image_mode() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "invalid"
image = "x:latest"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_err());
    }

    #[test]
    fn rejects_missing_measured_data() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
measured-data = ["./does-not-exist"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            validate_config(&cfg, tmp.path()),
            Err(WorkloadError::MeasuredDataMissing(_))
        ));
    }

    #[test]
    fn warns_on_dependencies() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[dependencies.redis]
image = "redis:7"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let warnings = validate_config(&cfg, tmp.path()).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("dependencies"));
    }

    #[test]
    fn rejects_signing_without_dot_slash() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[signing]
enable = true
auth_info = "secrets/auth_info.json"
policy = "./config/policy.json"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("signing.auth_info must start with"));
    }

    #[test]
    fn rejects_invalid_disk_size() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
size = "big"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("size must be a valid size string"));
    }

    #[test]
    fn accepts_valid_disk_sizes() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.a]
size = "10GB"

[disks.b]
size = "500MB"

[disks.c]
size = "1TB"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_ok());
    }

    #[test]
    fn rejects_disk_mounted_by_multiple_containers() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[workload.disks]
shared = "/data"

[dependencies.sidecar]
image = "redis:7"

[dependencies.sidecar.disks]
shared = "/cache"

[disks.shared]
size = "10GB"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("mounted by multiple containers"));
    }

    #[test]
    fn warns_redundant_firewall_allow() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
ports = ["3000:3000"]

[firewall]
allow = [{ port = 3000, protocol = "tcp" }]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let warnings = validate_config(&cfg, tmp.path()).unwrap();
        assert!(warnings.iter().any(|w| w.contains("redundant")));
    }

    #[test]
    fn warns_unmatched_firewall_deny() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
ports = ["3000:3000"]

[firewall]
deny = [9999]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let warnings = validate_config(&cfg, tmp.path()).unwrap();
        assert!(warnings.iter().any(|w| w.contains("no-op")));
    }

    #[test]
    fn no_warning_for_matched_firewall_deny() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
ports = ["3000:3000"]

[firewall]
deny = [3000]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let warnings = validate_config(&cfg, tmp.path()).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn rejects_undefined_disk_ref() {
        let toml = r#"
format = 1

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[workload.disks]
missing-disk = "/data"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_err());
    }
}
