use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path};

use crate::config::{self, ImageSource, WorkloadConfig};
use crate::WorkloadError;

/// Reject paths containing `..` components (lexical check, works on non-existent paths).
fn ensure_no_traversal(path: &str, context: &str) -> Result<(), WorkloadError> {
    let p = Path::new(path);
    for component in p.components() {
        if component == Component::ParentDir {
            return Err(WorkloadError::Validation(format!(
                "{context}: path must not contain \"..\": {path:?}"
            )));
        }
    }
    Ok(())
}

/// Canonicalize both paths and verify `path` is inside `base` (catches symlink escapes).
fn ensure_within(path: &Path, base: &Path, context: &str) -> Result<(), WorkloadError> {
    let canon_path = path.canonicalize().map_err(|_| {
        WorkloadError::Validation(format!(
            "{context}: cannot resolve path: {}",
            path.display()
        ))
    })?;
    let canon_base = base.canonicalize().map_err(|_| {
        WorkloadError::Validation(format!(
            "{context}: cannot resolve base: {}",
            base.display()
        ))
    })?;
    if !canon_path.starts_with(&canon_base) {
        return Err(WorkloadError::Validation(format!(
            "{context}: path escapes workload directory: {}",
            path.display()
        )));
    }
    Ok(())
}

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
    if config.format < 2 {
        return Err(WorkloadError::Validation(format!(
            "atakit-workload.toml format version {} is no longer supported; update to format = 2",
            config.format
        )));
    }
    if config.format > crate::FORMAT_VERSION {
        return Err(WorkloadError::Validation(format!(
            "atakit-workload.toml format version {} is newer than supported ({}); upgrade atakit",
            config.format,
            crate::FORMAT_VERSION
        )));
    }

    // ── gid-group ────────────────────────────────────────
    if let Some(ref gg) = w.gid_group {
        if gg.is_empty() {
            return Err(WorkloadError::Validation(
                "gid-group must not be empty when specified".into(),
            ));
        }
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
    if !w.version.starts_with('v')
        || w.version.len() < 2
        || !w.version[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(WorkloadError::Validation(format!(
            "version must start with 'v' followed by alphanumeric/.-_ chars, got {:?}",
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

    // ── base-image entries (must be name:version, no / in name) ──
    for entry in &w.base_image {
        let Some((name, version)) = entry.split_once(':') else {
            return Err(WorkloadError::Validation(format!(
                "base-image entry must be name:version format, got {:?}",
                entry,
            )));
        };
        if name.is_empty() || version.is_empty() {
            return Err(WorkloadError::Validation(format!(
                "base-image entry has empty name or version: {:?}",
                entry,
            )));
        }
        if name.contains('/') {
            return Err(WorkloadError::Validation(format!(
                "base-image name must not contain '/': {:?}",
                entry,
            )));
        }
    }

    // ── ports ──────────────────────────────────────────────
    for spec in &w.ports {
        validate_container_port(spec, "workload.ports")?;
    }
    for (dep_name, dep) in &config.dependencies {
        for spec in &dep.ports {
            validate_container_port(spec, &format!("dependencies.{dep_name}.ports"))?;
        }
    }

    // ── host port uniqueness and privileged port check ───
    {
        let mut seen_host_ports: HashSet<u16> = HashSet::new();
        for spec in &w.ports {
            if let Ok(parsed) = config::parse_port_spec(spec) {
                if parsed.host < 1024 {
                    return Err(WorkloadError::Validation(format!(
                        "host port {} in workload.ports is a privileged port (must be >= 1024)",
                        parsed.host
                    )));
                }
                if !seen_host_ports.insert(parsed.host) {
                    return Err(WorkloadError::Validation(format!(
                        "duplicate host port {} in workload.ports",
                        parsed.host
                    )));
                }
            }
        }
        for (dep_name, dep) in &config.dependencies {
            for spec in &dep.ports {
                if let Ok(parsed) = config::parse_port_spec(spec) {
                    if parsed.host < 1024 {
                        return Err(WorkloadError::Validation(format!(
                            "host port {} in dependencies.{dep_name}.ports is a privileged port (must be >= 1024)",
                            parsed.host
                        )));
                    }
                    if !seen_host_ports.insert(parsed.host) {
                        return Err(WorkloadError::Validation(format!(
                            "host port {} in dependencies.{dep_name}.ports conflicts with another container",
                            parsed.host
                        )));
                    }
                }
            }
        }
    }

    // ── reserved host ports (CVM agent) ─────────────────
    {
        const RESERVED_PORTS: &[u16] = &[1024, 2024];
        for spec in &w.ports {
            if let Ok(parsed) = config::parse_port_spec(spec) {
                if RESERVED_PORTS.contains(&parsed.host) {
                    return Err(WorkloadError::Validation(format!(
                        "host port {} in workload.ports is reserved for CVM use (ports 1024, 2024)",
                        parsed.host
                    )));
                }
            }
        }
        for (dep_name, dep) in &config.dependencies {
            for spec in &dep.ports {
                if let Ok(parsed) = config::parse_port_spec(spec) {
                    if RESERVED_PORTS.contains(&parsed.host) {
                        return Err(WorkloadError::Validation(format!(
                            "host port {} in dependencies.{dep_name}.ports is reserved for CVM use (ports 1024, 2024)",
                            parsed.host
                        )));
                    }
                }
            }
        }
    }

    // ── image source ──────────────────────────────────────
    validate_image_source(&w.image, workload_dir)?;

    // ── package measured-data paths ─────────────────────────
    for p in config.measured_data_paths() {
        if !p.starts_with("./") {
            return Err(WorkloadError::Validation(format!(
                "package measured-data path must start with \"./\": {p:?}"
            )));
        }
        ensure_no_traversal(p, "package measured-data")?;
        let abs = workload_dir.join(p);
        if !abs.exists() {
            return Err(WorkloadError::MeasuredDataMissing(abs));
        }
        ensure_within(&abs, workload_dir, "package measured-data")?;
    }

    // ── package unmeasured-data paths (format check only, files need not exist) ──
    for p in config.unmeasured_data_paths() {
        if !p.starts_with("./") {
            return Err(WorkloadError::Validation(format!(
                "package unmeasured-data path must start with \"./\": {p:?}"
            )));
        }
        ensure_no_traversal(p, "package unmeasured-data")?;
    }

    // ── package ↔ service opt-in consistency ───────────────
    // A service setting `measured-data = true` / `unmeasured-data = true`
    // commits to bind-mounting that data class, but the portal silently
    // skips the mount when the staged directory is absent. Flag the
    // inconsistent shape at build time so a no-op opt-in doesn't ship.
    {
        let mut measured_offenders: Vec<String> = Vec::new();
        if w.measured_data {
            measured_offenders.push("workload".to_string());
        }
        for (name, dep) in &config.dependencies {
            if dep.measured_data {
                measured_offenders.push(format!("dependencies.{name}"));
            }
        }
        if !measured_offenders.is_empty() && config.measured_data_paths().is_empty() {
            return Err(WorkloadError::Validation(format!(
                "measured-data = true on {} but [package].measured-data is empty or missing",
                measured_offenders.join(", ")
            )));
        }

        let mut unmeasured_offenders: Vec<String> = Vec::new();
        if w.unmeasured_data {
            unmeasured_offenders.push("workload".to_string());
        }
        for (name, dep) in &config.dependencies {
            if dep.unmeasured_data {
                unmeasured_offenders.push(format!("dependencies.{name}"));
            }
        }
        if !unmeasured_offenders.is_empty() && config.unmeasured_data_paths().is_empty() {
            return Err(WorkloadError::Validation(format!(
                "unmeasured-data = true on {} but [package].unmeasured-data is empty or missing",
                unmeasured_offenders.join(", ")
            )));
        }
    }

    // ── env_file ──────────────────────────────────────────
    if let Some(ref env_files) = w.env_file {
        for ef in env_files.as_vec() {
            if !ef.starts_with("./") {
                return Err(WorkloadError::Validation(format!(
                    "env_file path must start with \"./\": {ef:?}"
                )));
            }
            ensure_no_traversal(&ef, "env_file")?;
            let abs = workload_dir.join(&ef);
            if !abs.exists() {
                return Err(WorkloadError::EnvFileMissing(abs));
            }
            ensure_within(&abs, workload_dir, "env_file")?;
        }
    }

    // ── boot-disk-size ─────────────────────────────────────
    if let Some(ref bds) = w.boot_disk_size {
        if !is_valid_size(bds) {
            return Err(WorkloadError::Validation(format!(
                "boot-disk-size must be a valid size string (e.g. \"50GB\", \"1TB\"), got {bds:?}"
            )));
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
        for (label, entries) in [("allow", &fw.allow), ("deny", &fw.deny)] {
            for entry in entries {
                if entry.port < 1025 {
                    return Err(WorkloadError::Validation(format!(
                        "firewall {label} port must be >= 1025, got {}",
                        entry.port
                    )));
                }
                if let Some(ref proto) = entry.protocol {
                    if proto != "tcp" && proto != "udp" {
                        return Err(WorkloadError::Validation(format!(
                            "firewall protocol must be \"tcp\" or \"udp\", got {proto:?}"
                        )));
                    }
                }
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

    // ── disk index + size format + encryption ─────────────
    {
        let resolved = config.resolved_disk_indices();
        let mut seen_indices: HashSet<u32> = HashSet::new();
        for (name, disk) in &config.disks {
            let index = resolved.get(name.as_str()).copied().unwrap_or(10);
            if index < 10 {
                return Err(WorkloadError::Validation(format!(
                    "disk {name:?} index must be >= 10, got {index}"
                )));
            }
            if !seen_indices.insert(index) {
                return Err(WorkloadError::Validation(format!(
                    "disk {name:?} has duplicate index {index}"
                )));
            }
            if !is_valid_size(&disk.size) {
                return Err(WorkloadError::Validation(format!(
                    "disk {name:?} size must be a valid size string (e.g. \"10GB\", \"500MB\"), got {:?}",
                    disk.size
                )));
            }
            if let Some(gb) = parse_size_gb(&disk.size) {
                if gb < 10 {
                    return Err(WorkloadError::Validation(format!(
                        "disk {name:?} size must be at least 10GB, got {:?}",
                        disk.size
                    )));
                }
            }
            let enc = &disk.encryption;
            const SUPPORTED_METHODS: &[&str] = &["tpm", "passphrase"];
            const NOT_YET_IMPLEMENTED_METHODS: &[&str] = &["keyfile", "kms"];
            for method in &enc.unlock_method {
                let m = method.as_str();
                if SUPPORTED_METHODS.contains(&m) {
                    continue;
                }
                if NOT_YET_IMPLEMENTED_METHODS.contains(&m) {
                    return Err(WorkloadError::Validation(format!(
                        "disk {name:?} encryption.unlock_method {method:?} is not implemented yet; \
                         supported methods are {SUPPORTED_METHODS:?}"
                    )));
                }
                return Err(WorkloadError::Validation(format!(
                    "disk {name:?} encryption.unlock_method contains unknown method: {method:?}; \
                     supported methods are {SUPPORTED_METHODS:?}"
                )));
            }
            {
                let mut seen = std::collections::HashSet::new();
                for method in &enc.unlock_method {
                    if !seen.insert(method.as_str()) {
                        return Err(WorkloadError::Validation(format!(
                            "disk {name:?} encryption.unlock_method has duplicate entry {method:?}"
                        )));
                    }
                }
            }
            let valid_bind = ["platform", "baseimage", "workload"];
            for b in &enc.bind {
                if !valid_bind.contains(&b.as_str()) {
                    return Err(WorkloadError::Validation(format!(
                        "disk {name:?} encryption.bind contains unknown binding: {b:?}; \
                         valid bindings are {valid_bind:?}"
                    )));
                }
            }
            // tpm seals the disk key under a TPM2 PCR policy, so it must say
            // which measurements to bind to; an empty bind would seal to no
            // PCRs and give no protection. passphrase unlock ignores bind,
            // so this only applies when tpm is one of the methods.
            if enc.unlock_method.iter().any(|m| m == "tpm") && enc.bind.is_empty() {
                return Err(WorkloadError::Validation(format!(
                    "disk {name:?} uses tpm unlock but encryption.bind is empty; \
                     tpm seals the disk key under a PCR policy and must bind to at \
                     least one of {valid_bind:?} (platform = firmware PCRs 0-7, \
                     baseimage = base image PCR 11, workload = manifest PCR 23)"
                )));
            }
        }
    }

    // ── dependency disk refs ────────────────────────────
    for (dep_name, dep) in &config.dependencies {
        for disk_name in dep.disks.keys() {
            if !config.disks.contains_key(disk_name) {
                return Err(WorkloadError::Validation(format!(
                    "dependencies.{dep_name}.disks references undefined disk: {disk_name:?}"
                )));
            }
        }
    }

    // ── firewall cross-reference with ports ───────────────
    if let Some(ref fw) = config.firewall {
        let auto_ports = collect_auto_derived_ports(config);

        for entry in &fw.allow {
            let redundant = entry_matches_auto(&auto_ports, entry);
            if redundant {
                warnings.push(format!(
                    "firewall allow {} is redundant (already auto-derived from ports)",
                    format_entry(entry)
                ));
            }
        }
        for entry in &fw.deny {
            let matched = entry_matches_auto(&auto_ports, entry);
            if !matched {
                warnings.push(format!(
                    "firewall deny {} does not match any auto-derived port (no-op)",
                    format_entry(entry)
                ));
            }
        }
    }

    // ── dependencies ───────────────────────────────────────
    let dep_names: HashSet<&str> = config.dependencies.keys().map(|s| s.as_str()).collect();
    for (dep_name, dep) in &config.dependencies {
        // Image source validation.
        validate_image_source(&dep.image, workload_dir)?;

        // depends_on must reference other defined dependencies.
        for ref_name in &dep.depends_on {
            if !dep_names.contains(ref_name.as_str()) {
                return Err(WorkloadError::Validation(format!(
                    "dependencies.{dep_name}.depends_on references undefined dependency: {ref_name:?}"
                )));
            }
            if ref_name == dep_name {
                return Err(WorkloadError::Validation(format!(
                    "dependencies.{dep_name}.depends_on cannot reference itself"
                )));
            }
        }

        // env_file validation.
        if let Some(ref env_files) = dep.env_file {
            for ef in env_files.as_vec() {
                if !ef.starts_with("./") {
                    return Err(WorkloadError::Validation(format!(
                        "dependencies.{dep_name}.env_file path must start with \"./\": {ef:?}"
                    )));
                }
                ensure_no_traversal(&ef, &format!("dependencies.{dep_name}.env_file"))?;
                let abs = workload_dir.join(&ef);
                if !abs.exists() {
                    return Err(WorkloadError::EnvFileMissing(abs));
                }
                ensure_within(
                    &abs,
                    workload_dir,
                    &format!("dependencies.{dep_name}.env_file"),
                )?;
            }
        }

        // gid-group validation.
        if let Some(ref gg) = dep.gid_group {
            if gg.is_empty() {
                return Err(WorkloadError::Validation(format!(
                    "dependencies.{dep_name}.gid-group must not be empty when specified"
                )));
            }
        }
    }

    // ── capabilities ─────────────────────────────────────
    // cap-add widens privilege; allowlisted to a small reviewed set.
    // cap-drop narrows privilege; entries must be members of the default cap
    // set (otherwise the drop is a silent no-op that misleads operators).
    // No cap may appear in both lists for the same container.
    validate_caps(&w.cap_add, &w.cap_drop, "workload")?;
    for (dep_name, dep) in &config.dependencies {
        validate_caps(
            &dep.cap_add,
            &dep.cap_drop,
            &format!("dependencies.{dep_name}"),
        )?;
    }

    // ── logging ──────────────────────────────────────────
    // Driver allowlist, options allowlist, ceilings, log-readers name
    // resolution. Cross-service consistency (log-readers ↔ workload-logs)
    // runs once after per-service validation.
    let mut service_names: HashSet<&str> = HashSet::new();
    service_names.insert(w.name.as_str());
    for dep_name in config.dependencies.keys() {
        service_names.insert(dep_name.as_str());
    }
    validate_logging("workload", &w.logging, &service_names)?;
    for (dep_name, dep) in &config.dependencies {
        validate_logging(
            &format!("dependencies.{dep_name}"),
            &dep.logging,
            &service_names,
        )?;
    }
    validate_log_grants(config)?;

    Ok(warnings)
}

/// Allowlist for `cap-add`. Names use the canonical uppercase form without
/// the `CAP_` prefix (matching `--cap-add` argv shape). Each entry widens
/// the workload's attestation surface, so the list is intentionally narrow.
const CAP_ADD_ALLOWLIST: &[&str] = &["NET_ADMIN", "NET_RAW"];

/// The runtime's pinned default cap set. `cap-drop` entries must be members
/// of this list (dropping a cap not in the default set would be a silent
/// no-op). Pinned in the spec at docs/specs/atakit-workload-toml-spec.md so
/// a container engine upgrade does not silently shift the attestation surface.
const DEFAULT_CAPS: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
];

fn validate_caps(
    cap_add: &[String],
    cap_drop: &[String],
    context: &str,
) -> Result<(), WorkloadError> {
    // Check overlap first. The per-list allowlists below are disjoint by
    // construction (no cap is both add-able and drop-able), so a same-name
    // entry in both lists would otherwise surface as a less-clear per-list
    // failure. Reporting the contradiction directly is more useful.
    for cap in cap_add {
        if cap_drop.contains(cap) {
            return Err(WorkloadError::Validation(format!(
                "{context}: capability {cap:?} appears in both cap-add and cap-drop"
            )));
        }
    }
    for cap in cap_add {
        if !CAP_ADD_ALLOWLIST.contains(&cap.as_str()) {
            return Err(WorkloadError::Validation(format!(
                "{context}.cap-add: capability {cap:?} is not in the allowlist {:?}",
                CAP_ADD_ALLOWLIST
            )));
        }
    }
    for cap in cap_drop {
        if !DEFAULT_CAPS.contains(&cap.as_str()) {
            return Err(WorkloadError::Validation(format!(
                "{context}.cap-drop: capability {cap:?} is not in the default cap set {:?}; \
                 dropping a cap that is not in the default set has no effect",
                DEFAULT_CAPS
            )));
        }
    }
    Ok(())
}

// ── logging ──────────────────────────────────────────
//
// See docs/specs/atakit-workload-toml-spec.md → "Container Logging" and
// "Validation Rules / Logging" for the authoritative spec.

/// Log-driver allowlist. Restricted to drivers podman accepts natively in
/// the minimal CVM image. journald is excluded because the image has no
/// systemd. Remote-shipping drivers (fluentd, syslog, gelf, splunk, awslogs)
/// are Docker-only -- podman rejects them at container-create with
/// "Error: running container create option: invalid log driver". Remote
/// log delivery is done by a shipper dependency, not by a log driver.
///
/// MUST stay in sync with atakit-portal-state's mirror constant.
const LOG_DRIVER_ALLOWLIST: &[&str] = &["k8s-file", "none"];

/// Per-driver allowlist of option keys. `path` is portal-injected and never
/// user-settable; setting it from the manifest is a hard error.
fn log_opt_allowlist(driver: &str) -> &'static [&'static str] {
    match driver {
        "k8s-file" => &["max-size", "max-file"],
        _ => &[],
    }
}

/// Upper bound on per-container log file size. With max-file = 20 worst-case
/// disk use is `500m * 20 = 10 GB` per container.
const LOG_MAX_SIZE_CEILING_BYTES: u64 = 500 * 1024 * 1024;

/// Upper bound on number of rotated log files podman keeps per container.
const LOG_MAX_FILE_CEILING: u32 = 20;

/// Parse a size suffix like `"50m"`, `"1g"`, `"1024k"`, or a bare integer
/// (interpreted as bytes). Case-insensitive on the suffix.
fn parse_size_suffix(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size value".to_string());
    }
    let last = s.chars().last().unwrap();
    let (digits, mult) = if last.is_ascii_alphabetic() {
        let mult = match last.to_ascii_lowercase() {
            'k' => 1024u64,
            'm' => 1024 * 1024,
            'g' => 1024 * 1024 * 1024,
            other => {
                return Err(format!(
                    "invalid size suffix {other:?} (expected k, m, or g)"
                ))
            }
        };
        (&s[..s.len() - 1], mult)
    } else {
        (s, 1u64)
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid size number {digits:?}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size overflow for {s:?}"))
}

/// Per-service validation for `[<service>.logging]`. Implements rules 1-9
/// from the spec. Cross-service rules 10-11 are in `validate_log_grants`.
fn validate_logging(
    context: &str,
    logging: &config::LoggingSection,
    valid_service_names: &HashSet<&str>,
) -> Result<(), WorkloadError> {
    // 1. driver in allowlist
    if !LOG_DRIVER_ALLOWLIST.contains(&logging.driver.as_str()) {
        return Err(WorkloadError::Validation(format!(
            "{context}.logging.driver: {:?} is not in the allowlist {:?}",
            logging.driver, LOG_DRIVER_ALLOWLIST
        )));
    }
    // 2. 'path' key rejected (portal-injected)
    if logging.options.contains_key("path") {
        return Err(WorkloadError::Validation(format!(
            "{context}.logging.options: 'path' is portal-injected and not user-settable"
        )));
    }
    // 3. driver == "none" implies empty options
    if logging.driver == "none" && !logging.options.is_empty() {
        return Err(WorkloadError::Validation(format!(
            "{context}.logging: driver = \"none\" must have empty options, got keys {:?}",
            logging.options.keys().collect::<Vec<_>>()
        )));
    }
    // 4. option keys allowlisted per driver
    let allowed = log_opt_allowlist(&logging.driver);
    for key in logging.options.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(WorkloadError::Validation(format!(
                "{context}.logging.options: key {:?} not allowed for driver {:?}; allowed: {:?}",
                key, logging.driver, allowed
            )));
        }
    }
    // 5. max-size parses and is within ceiling
    if let Some(v) = logging.options.get("max-size") {
        let bytes = parse_size_suffix(v).map_err(|e| {
            WorkloadError::Validation(format!("{context}.logging.options.max-size: {e}"))
        })?;
        if bytes > LOG_MAX_SIZE_CEILING_BYTES {
            return Err(WorkloadError::Validation(format!(
                "{context}.logging.options.max-size: {bytes} bytes exceeds ceiling \
                 {LOG_MAX_SIZE_CEILING_BYTES} bytes (500m)"
            )));
        }
    }
    // 6. max-file parses as positive u32 within ceiling
    if let Some(v) = logging.options.get("max-file") {
        let n: u32 = v.parse().map_err(|_| {
            WorkloadError::Validation(format!(
                "{context}.logging.options.max-file: {:?} is not a positive integer",
                v
            ))
        })?;
        if n == 0 {
            return Err(WorkloadError::Validation(format!(
                "{context}.logging.options.max-file: must be positive"
            )));
        }
        if n > LOG_MAX_FILE_CEILING {
            return Err(WorkloadError::Validation(format!(
                "{context}.logging.options.max-file: {n} exceeds ceiling {LOG_MAX_FILE_CEILING}"
            )));
        }
    }
    // 7. driver == "none" implies empty log-readers (nothing to grant)
    if logging.driver == "none" && !logging.log_readers.is_empty() {
        return Err(WorkloadError::Validation(format!(
            "{context}.logging: log-readers is non-empty but driver = \"none\" -- no logs are produced"
        )));
    }
    // 8/9. log-readers: no duplicates, all names resolve
    let mut seen: HashSet<&str> = HashSet::new();
    for reader in &logging.log_readers {
        if !seen.insert(reader.as_str()) {
            return Err(WorkloadError::Validation(format!(
                "{context}.logging.log-readers: duplicate entry {:?}",
                reader
            )));
        }
        if !valid_service_names.contains(reader.as_str()) {
            return Err(WorkloadError::Validation(format!(
                "{context}.logging.log-readers: {:?} is not a service in this workload",
                reader
            )));
        }
    }
    Ok(())
}

/// Cross-service consistency for log-readers / workload-logs. Implements
/// rules 10 (P grants R → R.workload-logs must be true) and 11 (R has
/// workload-logs = true → at least one producer grants R). Both are hard
/// errors; partial states are rejected so log-shipper wiring lands in a
/// single manifest.
fn validate_log_grants(config: &WorkloadConfig) -> Result<(), WorkloadError> {
    // Collect (producer_name, &LoggingSection) for workload + each dependency.
    let mut producers: Vec<(&str, &config::LoggingSection)> = Vec::new();
    producers.push((config.workload.name.as_str(), &config.workload.logging));
    for (name, dep) in &config.dependencies {
        producers.push((name.as_str(), &dep.logging));
    }

    // Build reader -> producers map for rule 11.
    let mut grants_for: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (p_name, p_logging) in &producers {
        for r_name in &p_logging.log_readers {
            grants_for.entry(r_name.as_str()).or_default().push(p_name);
        }
    }

    // workload_logs flag lookup.
    let workload_logs_for = |name: &str| -> bool {
        if name == config.workload.name {
            config.workload.workload_logs
        } else {
            config
                .dependencies
                .get(name)
                .is_some_and(|d| d.workload_logs)
        }
    };

    // Rule 10: P.log-readers includes R → R.workload-logs must be true.
    for (p_name, p_logging) in &producers {
        for r_name in &p_logging.log_readers {
            if !workload_logs_for(r_name) {
                return Err(WorkloadError::Validation(format!(
                    "{p_name}.logging.log-readers grants {:?} access, but {:?} does not \
                     set workload-logs = true",
                    r_name, r_name
                )));
            }
        }
    }

    // Rule 11: R.workload-logs = true → at least one producer grants R.
    for (s_name, _) in &producers {
        if workload_logs_for(s_name) && !grants_for.contains_key(s_name) {
            return Err(WorkloadError::Validation(format!(
                "{s_name} sets workload-logs = true but no producer grants it access in log-readers"
            )));
        }
    }

    Ok(())
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
            ensure_no_traversal(build, "image build context")?;
            let ctx = workload_dir.join(build);
            if !ctx.is_dir() {
                return Err(WorkloadError::Validation(format!(
                    "image build context is not a directory: {}",
                    ctx.display()
                )));
            }
            ensure_within(&ctx, workload_dir, "image build context")?;
        }
        ImageSource::File { file } => {
            if !file.ends_with(".tar") && !file.ends_with(".tar.gz") {
                return Err(WorkloadError::Validation(format!(
                    "image file must end in .tar or .tar.gz: {file:?}"
                )));
            }
            ensure_no_traversal(file, "image file")?;
            let abs = workload_dir.join(file);
            if !abs.exists() {
                return Err(WorkloadError::ImageFileMissing(abs));
            }
            ensure_within(&abs, workload_dir, "image file")?;
        }
    }
    Ok(())
}

/// Validate a container port spec: `"host:container[/proto]"`.
///
/// Uses the shared `parse_port_spec` and enforces that `container` is present.
fn validate_container_port(spec: &str, context: &str) -> Result<(), WorkloadError> {
    let parsed = config::parse_port_spec(spec)
        .map_err(|e| WorkloadError::Validation(format!("{context}: {e} in {spec:?}")))?;
    if parsed.container.is_none() {
        return Err(WorkloadError::Validation(format!(
            "{context}: container port is required, got {spec:?}"
        )));
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

/// Parse a size string to gigabytes. Returns None for invalid formats.
fn parse_size_gb(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_str, suffix) = if let Some(n) = s.strip_suffix("TB") {
        (n, "TB")
    } else if let Some(n) = s.strip_suffix("GB") {
        (n, "GB")
    } else if let Some(n) = s.strip_suffix("MB") {
        (n, "MB")
    } else {
        return None;
    };
    let num: u64 = num_str.trim().parse().ok()?;
    match suffix {
        "TB" => Some(num * 1024),
        "GB" => Some(num),
        "MB" => Some(num.div_ceil(1024)),
        _ => None,
    }
}

/// Collect all auto-derived `(port, protocol)` pairs from `ports` fields.
///
/// No protocol suffix means both tcp and udp.
fn collect_auto_derived_ports(config: &WorkloadConfig) -> HashSet<(u16, &'static str)> {
    let mut ports = HashSet::new();
    let all_specs = config
        .workload
        .ports
        .iter()
        .chain(config.dependencies.values().flat_map(|d| d.ports.iter()));
    for spec in all_specs {
        if let Ok(parsed) = config::parse_port_spec(spec) {
            match parsed.protocol.as_deref() {
                Some("tcp") => {
                    ports.insert((parsed.host, "tcp"));
                }
                Some("udp") => {
                    ports.insert((parsed.host, "udp"));
                }
                _ => {
                    ports.insert((parsed.host, "tcp"));
                    ports.insert((parsed.host, "udp"));
                }
            }
        }
    }
    ports
}

/// Check whether a `FirewallEntry` matches any auto-derived port.
///
/// An entry with no protocol matches if either tcp or udp is auto-derived.
fn entry_matches_auto(auto_ports: &HashSet<(u16, &str)>, entry: &config::FirewallEntry) -> bool {
    match &entry.protocol {
        Some(proto) => auto_ports.contains(&(entry.port, proto.as_str())),
        None => {
            auto_ports.contains(&(entry.port, "tcp")) || auto_ports.contains(&(entry.port, "udp"))
        }
    }
}

/// Format a `FirewallEntry` for display in warnings.
fn format_entry(entry: &config::FirewallEntry) -> String {
    match &entry.protocol {
        Some(proto) => format!("{}/{proto}", entry.port),
        None => entry.port.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_toml() -> &'static str {
        r#"
format = 2

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
format = 2

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
format = 2

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
format = 2

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
format = 2

[package]
measured-data = ["./does-not-exist"]

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
measured-data = true
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            validate_config(&cfg, tmp.path()),
            Err(WorkloadError::MeasuredDataMissing(_))
        ));
    }

    #[test]
    fn accepts_dependencies() {
        let toml = r#"
format = 2

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
        assert!(warnings.is_empty());
    }

    #[test]
    fn rejects_measured_data_optin_without_package() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
measured-data = true
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("measured-data = true") && msg.contains("[package].measured-data"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn rejects_dependency_measured_data_optin_without_package() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[dependencies.sidecar]
image = "redis:7"
measured-data = true
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("dependencies.sidecar") && msg.contains("[package].measured-data"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn rejects_unmeasured_data_optin_without_package() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
unmeasured-data = true
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unmeasured-data = true") && msg.contains("[package].unmeasured-data"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn rejects_duplicate_host_port() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
ports = ["3000:3000"]

[dependencies.sidecar]
image = "redis:7"
ports = ["3000:6379"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("host port 3000"));
    }

    #[test]
    fn rejects_invalid_depends_on() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[dependencies.redis]
image = "redis:7"
depends_on = ["nonexistent"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("undefined dependency"));
    }

    #[test]
    fn rejects_dependency_undefined_disk_ref() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[dependencies.sidecar]
image = "redis:7"

[dependencies.sidecar.disks]
missing-disk = "/data"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("undefined disk"));
    }

    #[test]
    fn rejects_invalid_disk_size() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
index = 10
size = "big"
encryption = { unlock_method = [], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("size must be a valid size string"));
    }

    #[test]
    fn accepts_valid_disk_sizes() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.a]
index = 10
size = "10GB"
encryption = { unlock_method = [], bind = [] }

[disks.b]
index = 11
size = "20GB"
encryption = { unlock_method = [], bind = [] }

[disks.c]
index = 12
size = "1TB"
encryption = { unlock_method = [], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_ok());
    }

    #[test]
    fn rejects_disk_index_below_10() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
index = 5
size = "10GB"
encryption = { unlock_method = [], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("index must be >= 10"));
    }

    #[test]
    fn rejects_duplicate_disk_index() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.a]
index = 10
size = "10GB"
encryption = { unlock_method = [], bind = [] }

[disks.b]
index = 10
size = "5GB"
encryption = { unlock_method = [], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("duplicate index"));
    }

    #[test]
    fn allows_disk_shared_between_containers() {
        let toml = r#"
format = 2

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
index = 10
size = "10GB"
encryption = { unlock_method = [], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_ok());
    }

    #[test]
    fn warns_redundant_firewall_allow() {
        let toml = r#"
format = 2

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
format = 2

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
format = 2

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
format = 2

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

    #[test]
    fn rejects_measured_data_traversal() {
        let toml = r#"
format = 2

[package]
measured-data = ["./../etc/passwd"]

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn rejects_unmeasured_data_traversal() {
        let toml = r#"
format = 2

[package]
unmeasured-data = ["./../secrets"]

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn rejects_image_build_traversal() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = { build = "../other-project" }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn rejects_image_file_traversal() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = { file = "./../stolen.tar" }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn rejects_invalid_port_format() {
        for bad in &["3000", "abc:3000", "3000:xyz", "3000:3000/sctp", "80:80:80"] {
            let toml = format!(
                r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
ports = ["{bad}"]
"#
            );
            let cfg: crate::config::WorkloadConfig = toml::from_str(&toml).unwrap();
            let tmp = tempfile::tempdir().unwrap();
            assert!(
                validate_config(&cfg, tmp.path()).is_err(),
                "expected error for port spec: {bad:?}"
            );
        }
    }

    #[test]
    fn accepts_valid_port_specs() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
ports = ["3000:3000", "8080:80/tcp", "5353:5353/udp"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_ok());
    }

    #[test]
    fn rejects_env_file_traversal() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
env_file = "./../etc/shadow"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn rejects_env_file_without_dot_slash() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
env_file = "prod.env"
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("env_file path must start with"));
    }

    #[test]
    fn accepts_allowlisted_cap_add() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
cap-add = ["NET_ADMIN", "NET_RAW"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_ok());
    }

    #[test]
    fn rejects_cap_add_outside_allowlist() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
cap-add = ["SYS_ADMIN"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("cap-add"));
        assert!(err.to_string().contains("SYS_ADMIN"));
    }

    #[test]
    fn rejects_cap_add_with_cap_prefix() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
cap-add = ["CAP_NET_ADMIN"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_err());
    }

    #[test]
    fn rejects_cap_add_lowercase() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
cap-add = ["net_admin"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_err());
    }

    #[test]
    fn accepts_cap_drop_in_default_set() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
cap-drop = ["NET_BIND_SERVICE", "SETUID", "SETGID"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_ok());
    }

    #[test]
    fn rejects_cap_drop_not_in_default_set() {
        // NET_ADMIN isn't in podman's default cap set; dropping it would be
        // a silent no-op.
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
cap-drop = ["NET_ADMIN"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cap-drop"));
        assert!(msg.contains("NET_ADMIN"));
    }

    #[test]
    fn rejects_overlap_between_cap_add_and_cap_drop() {
        // Same cap in both lists is contradictory.
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
cap-add = ["NET_ADMIN"]
cap-drop = ["NET_BIND_SERVICE"]

[dependencies.sidecar]
image = "redis:7"
cap-add = ["NET_RAW"]
cap-drop = ["NET_RAW"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dependencies.sidecar"));
        assert!(msg.contains("NET_RAW"));
        assert!(msg.contains("both cap-add and cap-drop"));
    }

    #[test]
    fn rejects_reserved_unlock_method_keyfile() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = ["keyfile"], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("keyfile"),
            "expected method name in error: {msg}"
        );
        assert!(
            msg.contains("not implemented yet"),
            "expected 'not implemented yet' wording: {msg}"
        );
    }

    #[test]
    fn rejects_reserved_unlock_method_kms() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = ["kms"], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("kms"));
    }

    #[test]
    fn rejects_duplicate_unlock_method() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = ["tpm", "tpm"], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn accepts_tpm_and_passphrase() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = ["tpm", "passphrase"], bind = ["workload"] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_ok());
    }

    #[test]
    fn rejects_tpm_unlock_with_empty_bind() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = ["tpm"], bind = [] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bind is empty"),
            "expected empty-bind wording: {msg}"
        );
        // The error lists the available bind options.
        assert!(
            msg.contains("platform") && msg.contains("baseimage") && msg.contains("workload"),
            "expected bind options in error: {msg}"
        );
    }

    #[test]
    fn accepts_tpm_unlock_with_bind() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = ["tpm"], bind = ["platform"] }
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        assert!(validate_config(&cfg, tmp.path()).is_ok());
    }

    #[test]
    fn dependency_caps_validated_independently() {
        let toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"

[dependencies.sidecar]
image = "redis:7"
cap-add = ["SYS_PTRACE"]
"#;
        let cfg: crate::config::WorkloadConfig = toml::from_str(toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("dependencies.sidecar.cap-add"));
    }

    // ── logging ──────────────────────────────────────────

    fn logging_toml(workload_extra: &str, deps: &str) -> String {
        format!(
            r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "x:latest"
{workload_extra}

{deps}
"#
        )
    }

    #[test]
    fn injects_default_k8s_file_options() {
        let cfg = crate::config::WorkloadConfig::load_from_str(minimal_toml()).unwrap();
        assert_eq!(cfg.workload.logging.driver, "k8s-file");
        assert_eq!(
            cfg.workload.logging.options.get("max-size"),
            Some(&"50m".to_string())
        );
        assert_eq!(
            cfg.workload.logging.options.get("max-file"),
            Some(&"5".to_string())
        );
        assert!(cfg.workload.logging.log_readers.is_empty());
        assert!(!cfg.workload.workload_logs);
    }

    #[test]
    fn injects_defaults_for_dependency_when_logging_omitted() {
        let toml = logging_toml(
            "",
            r#"
[dependencies.redis]
image = "redis:7"
"#,
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let redis = cfg.dependencies.get("redis").unwrap();
        assert_eq!(redis.logging.driver, "k8s-file");
        assert_eq!(
            redis.logging.options.get("max-size"),
            Some(&"50m".to_string())
        );
        assert!(!redis.workload_logs);
    }

    #[test]
    fn preserves_explicit_options_no_default_injection() {
        let toml = logging_toml(
            r#"
[workload.logging]
driver = "k8s-file"
options = { max-size = "100m", max-file = "10" }
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        assert_eq!(
            cfg.workload.logging.options.get("max-size"),
            Some(&"100m".to_string())
        );
        assert_eq!(
            cfg.workload.logging.options.get("max-file"),
            Some(&"10".to_string())
        );
    }

    #[test]
    fn none_driver_keeps_empty_options() {
        let toml = logging_toml(
            r#"
[workload.logging]
driver = "none"
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        assert_eq!(cfg.workload.logging.driver, "none");
        assert!(cfg.workload.logging.options.is_empty());
    }

    #[test]
    fn rejects_unknown_log_driver() {
        let toml = logging_toml(
            r#"
[workload.logging]
driver = "fluentd"
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("workload.logging.driver"), "got: {msg}");
        assert!(msg.contains("fluentd"), "got: {msg}");
    }

    #[test]
    fn rejects_user_supplied_path() {
        let toml = logging_toml(
            r#"
[workload.logging]
options = { path = "/tmp/log.log" }
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("portal-injected"));
    }

    #[test]
    fn rejects_none_driver_with_nonempty_options() {
        let toml = logging_toml(
            r#"
[workload.logging]
driver = "none"
options = { max-size = "50m" }
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("must have empty options"));
    }

    #[test]
    fn rejects_unallowed_option_key_for_k8s_file() {
        let toml = logging_toml(
            r#"
[workload.logging]
options = { tag = "myapp" }
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tag"), "got: {msg}");
    }

    #[test]
    fn rejects_max_size_above_ceiling() {
        let toml = logging_toml(
            r#"
[workload.logging]
options = { max-size = "501m", max-file = "5" }
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("exceeds ceiling"));
    }

    #[test]
    fn rejects_max_file_above_ceiling() {
        let toml = logging_toml(
            r#"
[workload.logging]
options = { max-size = "50m", max-file = "21" }
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("max-file"));
    }

    #[test]
    fn rejects_max_file_zero() {
        let toml = logging_toml(
            r#"
[workload.logging]
options = { max-size = "50m", max-file = "0" }
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn rejects_none_with_log_readers() {
        let toml = logging_toml(
            r#"
workload-logs = true
[workload.logging]
driver = "none"
log-readers = ["app"]
"#,
            r#"
[dependencies.app]
image = "x:latest"
workload-logs = true
"#,
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("no logs are produced"));
    }

    #[test]
    fn rejects_duplicate_log_readers() {
        let toml = logging_toml(
            r#"
[workload.logging]
log-readers = ["app", "app"]
"#,
            r#"
[dependencies.app]
image = "x:latest"
workload-logs = true
"#,
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_unknown_service_in_log_readers() {
        let toml = logging_toml(
            r#"
[workload.logging]
log-readers = ["nonexistent"]
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("not a service"));
    }

    #[test]
    fn accepts_self_grant() {
        let toml = logging_toml(
            r#"
workload-logs = true
[workload.logging]
log-readers = ["app"]
"#,
            "",
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        validate_config(&cfg, tmp.path()).expect("self-grant should validate");
    }

    #[test]
    fn rejects_grant_without_reader_opt_in() {
        let toml = logging_toml(
            r#"
[workload.logging]
log-readers = ["shipper"]
"#,
            r#"
[dependencies.shipper]
image = "x:latest"
"#,
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("workload-logs = true"), "got: {msg}");
        assert!(msg.contains("\"shipper\""), "got: {msg}");
    }

    #[test]
    fn rejects_opt_in_without_any_grant() {
        let toml = logging_toml(
            "",
            r#"
[dependencies.shipper]
image = "x:latest"
workload-logs = true
"#,
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_config(&cfg, tmp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("shipper"), "got: {msg}");
        assert!(msg.contains("no producer grants"), "got: {msg}");
    }

    #[test]
    fn accepts_matched_grant_and_opt_in() {
        let toml = logging_toml(
            r#"
[workload.logging]
log-readers = ["shipper"]
"#,
            r#"
[dependencies.shipper]
image = "x:latest"
workload-logs = true
"#,
        );
        let cfg = crate::config::WorkloadConfig::load_from_str(&toml).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        validate_config(&cfg, tmp.path()).expect("matched grant+opt-in should validate");
    }
}
