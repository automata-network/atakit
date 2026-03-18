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
    #[serde(default)]
    pub deployments: BTreeMap<String, DeploymentSection>,
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
    #[serde(default)]
    pub cvm_agent: bool,
    #[serde(default, rename = "measured-data")]
    pub measured_data: Vec<String>,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: Vec<String>,
    #[serde(default)]
    pub disks: BTreeMap<String, String>,
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

/// VM firewall overrides.
#[derive(Debug, Deserialize)]
pub struct FirewallSection {
    #[serde(default)]
    pub allow: Vec<FirewallAllow>,
    #[serde(default)]
    pub deny: Vec<u16>,
}

#[derive(Debug, Deserialize)]
pub struct FirewallAllow {
    pub port: u16,
    pub protocol: String,
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

/// Deployment target.
#[derive(Debug, Deserialize)]
pub struct DeploymentSection {
    #[serde(default)]
    pub platforms: BTreeMap<String, PlatformSection>,
}

#[derive(Debug, Deserialize)]
pub struct PlatformSection {
    pub vmtype: String,
    pub region: String,
    pub project: String,
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
size = "10GB"
bind_fs = true
encryption = { enable = true }

[deployments.prod.platforms.gcp]
vmtype = "c3-standard-4"
region = "us-central1"
project = "my-project"
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
        assert!(cfg.deployments.contains_key("prod"));
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
