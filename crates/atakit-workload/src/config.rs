use std::collections::BTreeMap;

use serde::de;
use serde::Deserialize;

use crate::WorkloadError;

const CONFIG_FILENAME: &str = "atakit-workload.toml";

/// Top-level structure of `atakit-workload.toml`.
#[derive(Debug, Deserialize)]
pub struct WorkloadConfig {
    pub format: u32,
    #[serde(default)]
    pub package: Option<PackageSection>,
    pub workload: WorkloadSection,
    #[serde(default)]
    pub dependencies: BTreeMap<String, DependencySection>,
    #[serde(default)]
    pub firewall: Option<FirewallSection>,
    #[serde(default, rename = "baby-container")]
    pub baby_container: Option<BabyContainerSection>,
    #[serde(default)]
    pub disks: BTreeMap<String, DiskSection>,
}

/// Package data: file lists for measured-data and unmeasured-data.
#[derive(Debug, Deserialize)]
pub struct PackageSection {
    #[serde(default, rename = "measured-data")]
    pub measured_data: Vec<String>,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: Vec<String>,
}

/// Container logging configuration. Selects the podman log driver, its
/// options, and the manifest-level allowlist of services that may read this
/// service's logs.
///
/// `driver` is restricted to drivers podman accepts natively in the minimal
/// CVM image (no journald). Remote-shipping drivers (fluentd, syslog, ...)
/// are NOT supported by podman natively and are intentionally absent --
/// remote log delivery is implemented as a shipper dependency, not as a log
/// driver. `log-readers` is the manifest-level allowlist that gates the
/// portal-emitted bind-mount; access also requires the reader to be in the
/// same `gid-group` and to opt in with `workload-logs = true`.
#[derive(Debug, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_driver")]
    pub driver: String,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    #[serde(default, rename = "log-readers")]
    pub log_readers: Vec<String>,
}

fn default_log_driver() -> String {
    "k8s-file".to_string()
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            driver: default_log_driver(),
            options: BTreeMap::new(),
            log_readers: Vec::new(),
        }
    }
}

impl LoggingSection {
    /// Inject driver-specific option defaults after deserialization. For
    /// `k8s-file` with empty options, populate {max-size=50m, max-file=5}.
    /// Other drivers (currently only `none`) have no defaults.
    pub(crate) fn inject_defaults(&mut self) {
        if self.driver == "k8s-file" && self.options.is_empty() {
            self.options
                .insert("max-size".to_string(), "50m".to_string());
            self.options.insert("max-file".to_string(), "5".to_string());
        }
    }
}

impl WorkloadConfig {
    /// Read and parse `atakit-workload.toml` from a workload directory.
    pub fn from_dir(workload_dir: &std::path::Path) -> Result<Self, WorkloadError> {
        let path = workload_dir.join(CONFIG_FILENAME);
        let content = std::fs::read_to_string(&path).map_err(|e| WorkloadError::ReadFile {
            path: path.clone(),
            source: e,
        })?;
        check_legacy_fields(&content)?;
        let mut config: Self =
            toml::from_str(&content).map_err(|e| WorkloadError::ParseConfig { path, source: e })?;
        config.inject_defaults();
        Ok(config)
    }

    /// Parse from a TOML string. Runs legacy field checks.
    pub fn load_from_str(content: &str) -> Result<Self, WorkloadError> {
        check_legacy_fields(content)?;
        let mut config: Self = toml::from_str(content).map_err(|e| WorkloadError::ParseConfig {
            path: CONFIG_FILENAME.into(),
            source: e,
        })?;
        config.inject_defaults();
        Ok(config)
    }

    /// Populate defaults that depend on field interactions (currently logging
    /// driver-specific option defaults). Called after toml deserialization.
    fn inject_defaults(&mut self) {
        self.workload.logging.inject_defaults();
        for dep in self.dependencies.values_mut() {
            dep.logging.inject_defaults();
        }
    }

    /// Get package measured-data file paths (empty if no [package] section).
    pub fn measured_data_paths(&self) -> &[String] {
        self.package.as_ref().map_or(&[], |p| &p.measured_data)
    }

    /// Get package unmeasured-data file paths (empty if no [package] section).
    pub fn unmeasured_data_paths(&self) -> &[String] {
        self.package.as_ref().map_or(&[], |p| &p.unmeasured_data)
    }

    /// Resolve disk indices: auto-assign starting from 10 for disks without
    /// an explicit `index`, filling gaps around explicitly assigned indices.
    /// Returns a map of disk name -> resolved index.
    pub fn resolved_disk_indices(&self) -> BTreeMap<String, u32> {
        let mut result = BTreeMap::new();
        // Collect explicitly assigned indices.
        let mut used: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for (name, disk) in &self.disks {
            if let Some(idx) = disk.index {
                result.insert(name.clone(), idx);
                used.insert(idx);
            }
        }
        // Auto-assign for disks without index (BTreeMap iterates alphabetically).
        let mut next = 10u32;
        for name in self.disks.keys() {
            if result.contains_key(name) {
                continue;
            }
            while used.contains(&next) {
                next += 1;
            }
            result.insert(name.clone(), next);
            used.insert(next);
            next += 1;
        }
        result
    }
}

#[derive(Debug, Deserialize)]
pub struct WorkloadSection {
    pub name: String,
    pub version: String,
    #[serde(rename = "base-image-mode")]
    pub base_image_mode: String,
    #[serde(default, rename = "base-image")]
    pub base_image: Vec<String>,
    pub image: ImageSource,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default = "default_restart")]
    pub restart: String,
    #[serde(default)]
    pub command: Option<StringOrArray>,
    #[serde(default)]
    pub entrypoint: Option<StringOrArray>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub env_file: Option<StringOrArray>,
    #[serde(default = "default_session_ttl", rename = "session-ttl")]
    pub session_ttl: u64,
    #[serde(default, rename = "atakit-portal")]
    pub atakit_portal: bool,
    /// GID sharing group. Default: workload name.
    #[serde(default, rename = "gid-group")]
    pub gid_group: Option<String>,
    #[serde(default, rename = "measured-data")]
    pub measured_data: bool,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: bool,
    #[serde(default)]
    pub disks: BTreeMap<String, String>,
    /// Minimum boot/OS disk size (e.g. "50GB"). Cloud default if omitted.
    #[serde(default, rename = "boot-disk-size")]
    pub boot_disk_size: Option<String>,
    /// Linux capabilities to add to the container. Allowlisted to a small set
    /// (currently NET_ADMIN, NET_RAW) so attestation surface stays bounded.
    #[serde(default, rename = "cap-add")]
    pub cap_add: Vec<String>,
    /// Linux capabilities to drop from the default cap set as a hardening
    /// commitment. Entries must be members of the default set.
    #[serde(default, rename = "cap-drop")]
    pub cap_drop: Vec<String>,
    /// Container logging: driver + options + log-readers allowlist.
    #[serde(default)]
    pub logging: LoggingSection,
    /// Opt-in to receive a bind-mount of `/atakit-portal/workload/logs/`,
    /// containing only the producer subdirs that grant access via their
    /// `logging.log-readers` list. The container also needs GID 0 in its
    /// process credentials to actually read the files (k8s-file logs are
    /// 0640 group-owned by the gid-group host GID).
    #[serde(default, rename = "workload-logs")]
    pub workload_logs: bool,
}

/// Default session TTL: 0 means contract default (30 days).
fn default_session_ttl() -> u64 {
    0
}

fn default_restart() -> String {
    "no".to_string()
}

/// How the workload's container image is sourced.
#[derive(Debug)]
pub enum ImageSource {
    /// Pull from a registry: `image = "name:tag"`.
    Registry(String),
    /// Build from source: `image = { build = ".", containerfile = "..." }`.
    Build {
        build: String,
        containerfile: Option<String>,
        args: BTreeMap<String, String>,
    },
    /// Load from a local tar: `image = { file = "./path.tar" }`.
    File { file: String },
}

impl<'de> Deserialize<'de> for ImageSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            String(String),
            Table(RawTable),
        }

        #[derive(Deserialize)]
        struct RawTable {
            build: Option<String>,
            containerfile: Option<String>,
            #[serde(default)]
            args: BTreeMap<String, String>,
            file: Option<String>,
        }

        match Raw::deserialize(deserializer)? {
            Raw::String(s) => Ok(ImageSource::Registry(s)),
            Raw::Table(t) => {
                if let Some(build) = t.build {
                    if t.file.is_some() {
                        return Err(de::Error::custom(
                            "image table cannot have both `build` and `file`",
                        ));
                    }
                    Ok(ImageSource::Build {
                        build,
                        containerfile: t.containerfile,
                        args: t.args,
                    })
                } else if let Some(file) = t.file {
                    Ok(ImageSource::File { file })
                } else {
                    Err(de::Error::custom(
                        "image table must have either `build` or `file`",
                    ))
                }
            }
        }
    }
}

/// A field that can be a single string or an array of strings.
#[derive(Debug, Clone)]
pub enum StringOrArray {
    Single(String),
    Array(Vec<String>),
}

impl StringOrArray {
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            StringOrArray::Single(s) => vec![s.clone()],
            StringOrArray::Array(v) => v.clone(),
        }
    }
}

impl<'de> Deserialize<'de> for StringOrArray {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Single(String),
            Array(Vec<String>),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Single(s) => Ok(StringOrArray::Single(s)),
            Raw::Array(v) => Ok(StringOrArray::Array(v)),
        }
    }
}

/// Dependency container configuration (same container fields as workload).
#[derive(Debug, Deserialize)]
pub struct DependencySection {
    pub image: ImageSource,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default = "default_restart")]
    pub restart: String,
    #[serde(default)]
    pub command: Option<StringOrArray>,
    #[serde(default)]
    pub entrypoint: Option<StringOrArray>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub env_file: Option<StringOrArray>,
    #[serde(default, rename = "atakit-portal")]
    pub atakit_portal: bool,
    /// GID sharing group. Default: workload name.
    #[serde(default, rename = "gid-group")]
    pub gid_group: Option<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default, rename = "measured-data")]
    pub measured_data: bool,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: bool,
    #[serde(default)]
    pub disks: BTreeMap<String, String>,
    #[serde(default, rename = "cap-add")]
    pub cap_add: Vec<String>,
    #[serde(default, rename = "cap-drop")]
    pub cap_drop: Vec<String>,
    #[serde(default)]
    pub logging: LoggingSection,
    #[serde(default, rename = "workload-logs")]
    pub workload_logs: bool,
}

/// Parsed port specification: `host[:container][/protocol]`.
#[derive(Debug, Clone)]
pub struct ParsedPort {
    pub host: u16,
    pub container: Option<u16>,
    /// `None` means both tcp and udp.
    pub protocol: Option<String>,
}

/// Parse a port specification string.
///
/// Format: `host[:container][/protocol]`
/// - `host` is required (u16)
/// - `container` is optional (u16)
/// - `protocol` is optional ("tcp" or "udp"; absent means both)
///
/// Examples: `"3000"`, `"3000/tcp"`, `"3000:3000"`, `"8080:80/tcp"`
pub fn parse_port_spec(s: &str) -> Result<ParsedPort, String> {
    let (ports_part, protocol) = match s.split_once('/') {
        Some((p, proto)) => {
            if proto != "tcp" && proto != "udp" {
                return Err(format!(
                    "protocol must be \"tcp\" or \"udp\", got {proto:?}"
                ));
            }
            (p, Some(proto.to_string()))
        }
        None => (s, None),
    };

    let parts: Vec<&str> = ports_part.split(':').collect();
    match parts.len() {
        1 => {
            let host = parts[0]
                .parse::<u16>()
                .map_err(|_| format!("port must be a valid u16, got {:?}", parts[0]))?;
            Ok(ParsedPort {
                host,
                container: None,
                protocol,
            })
        }
        2 => {
            let host = parts[0]
                .parse::<u16>()
                .map_err(|_| format!("host port must be a valid u16, got {:?}", parts[0]))?;
            let container = parts[1]
                .parse::<u16>()
                .map_err(|_| format!("container port must be a valid u16, got {:?}", parts[1]))?;
            Ok(ParsedPort {
                host,
                container: Some(container),
                protocol,
            })
        }
        _ => Err(format!("invalid port spec: {s:?}")),
    }
}

/// VM firewall overrides.
#[derive(Debug, Deserialize)]
pub struct FirewallSection {
    #[serde(default)]
    pub allow: Vec<FirewallEntry>,
    #[serde(default)]
    pub deny: Vec<FirewallEntry>,
}

/// A firewall entry: port + optional protocol.
///
/// Accepts three TOML forms:
/// - Integer: `3000` (both tcp+udp)
/// - String: `"3000"`, `"3000/tcp"`, `"3000/udp"`
/// - Object: `{ port = 3000, protocol = "tcp" }`
#[derive(Debug)]
pub struct FirewallEntry {
    pub port: u16,
    /// `None` means both tcp and udp.
    pub protocol: Option<String>,
}

impl<'de> serde::Deserialize<'de> for FirewallEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Port(u16),
            Spec(String),
            Full { port: u16, protocol: String },
        }
        match Raw::deserialize(deserializer)? {
            Raw::Port(port) => Ok(FirewallEntry {
                port,
                protocol: None,
            }),
            Raw::Spec(s) => {
                let parsed = parse_port_spec(&s).map_err(de::Error::custom)?;
                if parsed.container.is_some() {
                    return Err(de::Error::custom(
                        "firewall entry must not include a container port",
                    ));
                }
                Ok(FirewallEntry {
                    port: parsed.host,
                    protocol: parsed.protocol,
                })
            }
            Raw::Full { port, protocol } => Ok(FirewallEntry {
                port,
                protocol: Some(protocol),
            }),
        }
    }
}

/// Baby (sidecar) container runtime settings.
#[derive(Debug, Deserialize)]
pub struct BabyContainerSection {
    #[serde(default)]
    pub allow: bool,
    #[serde(default = "default_max_count")]
    pub max_count: u32,
}

fn default_max_count() -> u32 {
    1
}

/// Persistent disk definition.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskSection {
    /// LUN / device index. Must be >= 10 and unique across all disks.
    /// If omitted, auto-assigned starting from 10 in alphabetical disk name order.
    pub index: Option<u32>,
    pub size: String,
    /// Required: a disk declaration must always carry an `encryption` block.
    /// Empty arrays (`unlock_method = []`, `bind = []`) are the explicit
    /// "no encryption" commitment. Omitting the block is a parse error so
    /// that the absence of encryption is always a deliberate choice.
    pub encryption: EncryptionSection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionSection {
    #[serde(default)]
    pub unlock_method: Vec<String>,
    #[serde(default)]
    pub bind: Vec<String>,
}

/// Reject deprecated format-1 fields before serde parsing, with migration hints.
fn check_legacy_fields(content: &str) -> Result<(), WorkloadError> {
    let value: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(_) => return Ok(()), // defer to real parser for syntax errors
    };

    if let Some(fmt) = value.get("format").and_then(|v| v.as_integer()) {
        if fmt == 1 {
            return Err(WorkloadError::Validation(
                "format = 1 is no longer supported. Update to format = 2 \
                 and apply the v2 migration changes (cvm_agent -> atakit-portal, \
                 encryption schema, signing removal)."
                    .into(),
            ));
        }
    }

    if let Some(workload) = value.get("workload").and_then(|v| v.as_table()) {
        if workload.contains_key("cvm_agent") {
            return Err(WorkloadError::Validation(
                "`cvm_agent` is no longer supported in format 2. \
                 Rename to `atakit-portal`."
                    .into(),
            ));
        }
        if workload.contains_key("ttl") {
            return Err(WorkloadError::Validation(
                "`ttl` has been renamed to `session-ttl` in format 2.".into(),
            ));
        }
        if workload.get("measured-data").is_some_and(|v| v.is_array()) {
            return Err(WorkloadError::Validation(
                "`measured-data` on [workload] must be a boolean in format 2. \
                 Move file lists to `[package] measured-data`."
                    .into(),
            ));
        }
        if workload
            .get("unmeasured-data")
            .is_some_and(|v| v.is_array())
        {
            return Err(WorkloadError::Validation(
                "`unmeasured-data` on [workload] must be a boolean in format 2. \
                 Move file lists to `[package] unmeasured-data`."
                    .into(),
            ));
        }
    }

    if let Some(deps) = value.get("dependencies").and_then(|v| v.as_table()) {
        for (name, dep) in deps {
            if let Some(t) = dep.as_table() {
                if t.contains_key("cvm_agent") {
                    return Err(WorkloadError::Validation(format!(
                        "dependencies.{name}: `cvm_agent` is no longer supported. \
                         Rename to `atakit-portal`."
                    )));
                }
                if t.get("measured-data").is_some_and(|v| v.is_array()) {
                    return Err(WorkloadError::Validation(format!(
                        "dependencies.{name}: `measured-data` must be a boolean in format 2. \
                         Move file lists to `[package] measured-data`."
                    )));
                }
                if t.get("unmeasured-data").is_some_and(|v| v.is_array()) {
                    return Err(WorkloadError::Validation(format!(
                        "dependencies.{name}: `unmeasured-data` must be a boolean in format 2. \
                         Move file lists to `[package] unmeasured-data`."
                    )));
                }
            }
        }
    }

    if value.get("signing").is_some() {
        return Err(WorkloadError::Validation(
            "`[signing]` is no longer supported in format 2. \
             Remove the signing section."
                .into(),
        ));
    }

    if let Some(disks) = value.get("disks").and_then(|v| v.as_table()) {
        for (name, disk) in disks {
            if let Some(enc) = disk.get("encryption").and_then(|v| v.as_table()) {
                if enc.contains_key("enable") || enc.contains_key("key_security") {
                    return Err(WorkloadError::Validation(format!(
                        "disk {name:?}: encryption schema has changed in format 2. \
                         Replace {{enable, key_security}} with \
                         {{unlock_method, bind}}."
                    )));
                }
            }
            if let Some(t) = disk.as_table() {
                if t.contains_key("bind_fs") {
                    return Err(WorkloadError::Validation(format!(
                        "disk {name:?}: `bind_fs` is no longer supported. \
                         Manual `--uidmap`/`--gidmap` plus the shared GID scheme \
                         makes bindfs redundant."
                    )));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
format = 2

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.workload.name, "my-app");
        assert_eq!(cfg.workload.version, "v0.0.1");
        assert!(matches!(cfg.workload.image, ImageSource::Registry(ref s) if s == "my-app:latest"));
    }

    #[test]
    fn parse_build_image() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = { build = ".", containerfile = "Containerfile" }
"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        match &cfg.workload.image {
            ImageSource::Build {
                build,
                containerfile,
                ..
            } => {
                assert_eq!(build, ".");
                assert_eq!(containerfile.as_deref(), Some("Containerfile"));
            }
            other => panic!("expected Build, got {other:?}"),
        }
    }

    #[test]
    fn parse_file_image() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = { file = "./images/app.tar" }
"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        assert!(
            matches!(cfg.workload.image, ImageSource::File { ref file } if file == "./images/app.tar")
        );
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
format = 2

[package]
measured-data = ["./config/hello", "./config/cert.pem"]
unmeasured-data = ["./additional-data/signer_key"]

[workload]
name = "secure-signer"
version = "v0.0.1"
base-image-mode = "blacklist"
base-image = ["mola-linux:v0.1.0-debug"]
image = { build = ".", containerfile = "Containerfile" }
ports = ["3000:3000"]
restart = "unless-stopped"
atakit-portal = true
gid-group = "shared"
measured-data = true
unmeasured-data = true

[workload.environment]
RUST_LOG = "info"

[workload.disks]
data = "/data"

[dependencies.redis]
image = "redis:7"

[dependencies.model-server]
image = { file = "./images/model-server.tar" }
ports = ["8080:8080"]
measured-data = true

[firewall]
allow = [{ port = 4000, protocol = "tcp" }]

[baby-container]
allow = true
max_count = 2

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = ["tpm"], bind = ["workload"] }

"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.workload.name, "secure-signer");
        assert_eq!(cfg.workload.ports, vec!["3000:3000"]);
        assert!(cfg.workload.atakit_portal);
        assert_eq!(cfg.workload.gid_group.as_deref(), Some("shared"));
        assert!(cfg.workload.measured_data);
        assert!(cfg.workload.unmeasured_data);
        let pkg = cfg.package.as_ref().unwrap();
        assert_eq!(pkg.measured_data.len(), 2);
        assert_eq!(pkg.unmeasured_data.len(), 1);
        assert!(cfg.dependencies.contains_key("redis"));
        assert!(cfg.dependencies["model-server"].measured_data);
        assert!(!cfg.dependencies["model-server"].unmeasured_data);
        assert!(cfg.firewall.is_some());
        assert!(cfg.baby_container.is_some());
        assert!(cfg.disks.contains_key("data"));
        assert_eq!(cfg.disks["data"].index, Some(10));
        let enc = &cfg.disks["data"].encryption;
        assert_eq!(enc.unlock_method, vec!["tpm"]);
        assert_eq!(enc.bind, vec!["workload"]);
    }

    #[test]
    fn rejects_build_and_file_together() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = { build = ".", file = "./app.tar" }
"#;
        let err = toml::from_str::<WorkloadConfig>(toml).unwrap_err();
        assert!(err.to_string().contains("build") || err.to_string().contains("file"));
    }

    #[test]
    fn string_or_array_single() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
command = "echo hello"
"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        match &cfg.workload.command {
            Some(StringOrArray::Single(s)) => assert_eq!(s, "echo hello"),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn string_or_array_array() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
command = ["echo", "hello"]
"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        match &cfg.workload.command {
            Some(StringOrArray::Array(v)) => assert_eq!(v, &["echo", "hello"]),
            other => panic!("expected Array, got {other:?}"),
        }
    }

    #[test]
    fn rejects_format_1() {
        let toml = r#"
format = 1

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
"#;
        let err = check_legacy_fields(toml).unwrap_err();
        assert!(err.to_string().contains("format = 1"));
    }

    #[test]
    fn rejects_cvm_agent() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
cvm_agent = true
"#;
        let err = check_legacy_fields(toml).unwrap_err();
        assert!(err.to_string().contains("cvm_agent"));
    }

    #[test]
    fn rejects_signing_section() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"

[signing]
enable = true
"#;
        let err = check_legacy_fields(toml).unwrap_err();
        assert!(err.to_string().contains("signing"));
    }

    #[test]
    fn rejects_old_encryption_schema() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"

[disks.data]
index = 10
size = "10GB"
encryption = { enable = true }
"#;
        let err = check_legacy_fields(toml).unwrap_err();
        assert!(err.to_string().contains("encryption schema"));
    }

    #[test]
    fn rejects_disk_bind_fs() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"

[disks.data]
index = 10
size = "10GB"
bind_fs = true
"#;
        let err = check_legacy_fields(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bind_fs"),
            "expected field name in error: {msg}"
        );
        assert!(
            msg.contains("uidmap"),
            "expected migration hint in error: {msg}"
        );
    }

    #[test]
    fn rejects_old_ttl() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
ttl = 3600
"#;
        let err = check_legacy_fields(toml).unwrap_err();
        assert!(err.to_string().contains("session-ttl"));
    }

    #[test]
    fn rejects_array_measured_data_on_workload() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
measured-data = ["./config/hello"]
"#;
        let err = check_legacy_fields(toml).unwrap_err();
        assert!(err.to_string().contains("boolean"));
    }

    #[test]
    fn rejects_array_measured_data_on_dependency() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"

[dependencies.redis]
image = "redis:7"
measured-data = ["./config/hello"]
"#;
        let err = check_legacy_fields(toml).unwrap_err();
        assert!(err.to_string().contains("boolean"));
    }

    #[test]
    fn parses_package_section() {
        let toml = r#"
format = 2

[package]
measured-data = ["./config/hello", "./config/cert.pem"]
unmeasured-data = ["./additional-data/key"]

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
measured-data = true
"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.measured_data_paths(),
            &["./config/hello", "./config/cert.pem"]
        );
        assert_eq!(cfg.unmeasured_data_paths(), &["./additional-data/key"]);
        assert!(cfg.workload.measured_data);
        assert!(!cfg.workload.unmeasured_data);
    }

    #[test]
    fn parses_session_ttl() {
        let toml = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
session-ttl = 3600
"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.workload.session_ttl, 3600);
    }
}
