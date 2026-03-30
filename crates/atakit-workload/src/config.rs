use std::collections::BTreeMap;

use serde::de;
use serde::Deserialize;

use crate::WorkloadError;

const CONFIG_FILENAME: &str = "atakit-workload.toml";

/// Top-level structure of `atakit-workload.toml`.
#[derive(Debug, Deserialize)]
pub struct WorkloadConfig {
    pub format: u32,
    pub workload: WorkloadSection,
    #[serde(default)]
    pub dependencies: BTreeMap<String, DependencySection>,
    #[serde(default)]
    pub firewall: Option<FirewallSection>,
    #[serde(default, rename = "baby-container")]
    pub baby_container: Option<BabyContainerSection>,
    #[serde(default)]
    pub signing: Option<SigningSection>,
    #[serde(default)]
    pub disks: BTreeMap<String, DiskSection>,
}

impl WorkloadConfig {
    /// Read and parse `atakit-workload.toml` from a workload directory.
    pub fn from_dir(workload_dir: &std::path::Path) -> Result<Self, WorkloadError> {
        let path = workload_dir.join(CONFIG_FILENAME);
        let content = std::fs::read_to_string(&path).map_err(|e| WorkloadError::ReadFile {
            path: path.clone(),
            source: e,
        })?;
        toml::from_str(&content).map_err(|e| WorkloadError::ParseConfig { path, source: e })
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
    #[serde(default = "default_ttl")]
    pub ttl: u64,
    #[serde(default)]
    pub cvm_agent: bool,
    #[serde(default, rename = "measured-data")]
    pub measured_data: Vec<String>,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: Vec<String>,
    #[serde(default)]
    pub disks: BTreeMap<String, String>,
    /// Minimum boot/OS disk size (e.g. "50GB"). Cloud default if omitted.
    #[serde(default, rename = "boot-disk-size")]
    pub boot_disk_size: Option<String>,
}

/// Default TTL: 0 means contract default (30 days).
fn default_ttl() -> u64 {
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
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default, rename = "measured-data")]
    pub measured_data: Vec<String>,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: Vec<String>,
    #[serde(default)]
    pub disks: BTreeMap<String, String>,
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

/// Image signing / verification settings.
#[derive(Debug, Deserialize)]
pub struct SigningSection {
    #[serde(default)]
    pub enable: bool,
    pub auth_info: Option<String>,
    pub policy: Option<String>,
}

/// Persistent disk definition.
#[derive(Debug, Deserialize)]
pub struct DiskSection {
    /// LUN / device index. Must be >= 10 and unique across all disks.
    /// If omitted, auto-assigned starting from 10 in alphabetical disk name order.
    pub index: Option<u32>,
    pub size: String,
    #[serde(default)]
    pub bind_fs: bool,
    #[serde(default)]
    pub encryption: Option<EncryptionSection>,
}

#[derive(Debug, Deserialize)]
pub struct EncryptionSection {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_key_security")]
    pub key_security: String,
}

fn default_key_security() -> String {
    "standard".to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
format = 1

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
format = 1

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
format = 1

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = { file = "./images/app.tar" }
"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        assert!(matches!(cfg.workload.image, ImageSource::File { ref file } if file == "./images/app.tar"));
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
format = 1

[workload]
name = "secure-signer"
version = "v0.0.1"
base-image-mode = "blacklist"
base-image = ["mola-linux:v0.1.0-debug"]
image = { build = ".", containerfile = "Containerfile" }
ports = ["3000:3000"]
restart = "unless-stopped"
cvm_agent = true
measured-data = ["./config/hello", "./config/cert.pem"]
unmeasured-data = ["./additional-data/signer_key"]

[workload.environment]
RUST_LOG = "info"

[workload.disks]
data = "/data"

[dependencies.redis]
image = "redis:7"

[firewall]
allow = [{ port = 4000, protocol = "tcp" }]

[baby-container]
allow = true
max_count = 2

[signing]
enable = true
auth_info = "./secrets/auth_info.json"
policy = "./config/cosign_policy.json"

[disks.data]
index = 10
size = "10GB"
bind_fs = true
encryption = { enable = true }

"#;
        let cfg: WorkloadConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.workload.name, "secure-signer");
        assert_eq!(cfg.workload.ports, vec!["3000:3000"]);
        assert!(cfg.workload.cvm_agent);
        assert_eq!(cfg.workload.measured_data.len(), 2);
        assert!(cfg.dependencies.contains_key("redis"));
        assert!(cfg.firewall.is_some());
        assert!(cfg.baby_container.is_some());
        assert!(cfg.signing.is_some());
        assert!(cfg.disks.contains_key("data"));
        assert_eq!(cfg.disks["data"].index, Some(10));
    }

    #[test]
    fn rejects_build_and_file_together() {
        let toml = r#"
format = 1

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
format = 1

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
format = 1

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
}
