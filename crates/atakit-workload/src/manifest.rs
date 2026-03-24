use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{ImageSource, StringOrArray, WorkloadConfig};
use crate::WorkloadError;

/// Top-level manifest written to `manifest.toml` inside the archive.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub meta: ManifestMeta,
    pub config: ManifestConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub disks: BTreeMap<String, ManifestDisk>,
    pub hashes: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestMeta {
    pub format: u32,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestConfig {
    pub image: String,
    #[serde(rename = "base-image-mode")]
    pub base_image_mode: String,
    #[serde(
        default,
        rename = "base-image",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub base_image: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    #[serde(default = "default_restart", skip_serializing_if = "is_default_restart")]
    pub restart: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<StringOrArrayOut>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<StringOrArrayOut>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ttl: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub cvm_agent: bool,
    #[serde(
        default,
        rename = "measured-data",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub measured_data: Vec<String>,
    #[serde(
        default,
        rename = "unmeasured-data",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub unmeasured_data: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub disks: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<BTreeMap<String, ManifestDependency>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall: Option<ManifestFirewall>,
    #[serde(
        rename = "baby-container",
        skip_serializing_if = "Option::is_none"
    )]
    pub baby_container: Option<ManifestBabyContainer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<ManifestSigning>,
}

fn default_restart() -> String {
    "no".to_string()
}

fn is_default_restart(s: &str) -> bool {
    s == "no"
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn is_false(b: &bool) -> bool {
    !b
}

/// Serialized as either a string or an array of strings.
#[derive(Debug)]
pub enum StringOrArrayOut {
    Single(String),
    Array(Vec<String>),
}

impl Serialize for StringOrArrayOut {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            StringOrArrayOut::Single(s) => serializer.serialize_str(s),
            StringOrArrayOut::Array(v) => v.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for StringOrArrayOut {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Single(String),
            Array(Vec<String>),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Single(s) => Ok(StringOrArrayOut::Single(s)),
            Raw::Array(v) => Ok(StringOrArrayOut::Array(v)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestDependency {
    pub image: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    #[serde(default = "default_restart", skip_serializing_if = "is_default_restart")]
    pub restart: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<StringOrArrayOut>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<StringOrArrayOut>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(
        default,
        rename = "measured-data",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub measured_data: Vec<String>,
    #[serde(
        default,
        rename = "unmeasured-data",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub unmeasured_data: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub disks: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestFirewall {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<ManifestFirewallAllow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestFirewallAllow {
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestBabyContainer {
    pub allow: bool,
    pub max_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestSigning {
    pub enable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestDisk {
    pub size: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub bind_fs: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<ManifestDiskEncryption>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestDiskEncryption {
    pub enable: bool,
    #[serde(default = "default_key_security", skip_serializing_if = "is_default_key_security")]
    pub key_security: String,
}

fn default_key_security() -> String {
    "standard".to_string()
}

fn is_default_key_security(s: &str) -> bool {
    s == "standard"
}

// ── env_file resolution ──────────────────────────────────────

/// Parse a `.env` file, returning key-value pairs.
///
/// Blank lines and lines starting with `#` are skipped.
/// Format: `KEY=VALUE` (no quoting needed for values).
pub fn parse_env_file(
    path: &Path,
    content: &str,
) -> Result<Vec<(String, String)>, WorkloadError> {
    let mut pairs = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(WorkloadError::EnvFileParse {
                path: path.to_path_buf(),
                line: i + 1,
                message: "expected KEY=VALUE".into(),
            });
        };
        pairs.push((key.trim().to_string(), value.trim().to_string()));
    }
    Ok(pairs)
}

/// Resolve environment: merge env_file values first, then explicit environment overrides.
pub fn resolve_environment(
    env_file: &Option<StringOrArray>,
    explicit_env: &BTreeMap<String, String>,
    workload_dir: &Path,
) -> Result<BTreeMap<String, String>, WorkloadError> {
    let mut merged = BTreeMap::new();

    // env_file values first
    if let Some(ref files) = env_file {
        for ef_path in files.as_vec() {
            let abs = workload_dir.join(&ef_path);
            let content =
                std::fs::read_to_string(&abs).map_err(|e| WorkloadError::ReadFile {
                    path: abs.clone(),
                    source: e,
                })?;
            for (k, v) in parse_env_file(&abs, &content)? {
                merged.insert(k, v);
            }
        }
    }

    // explicit environment overrides
    for (k, v) in explicit_env {
        merged.insert(k.clone(), v.clone());
    }

    Ok(merged)
}

/// Strip leading `./` from a path string.
pub fn strip_dot_slash(p: &str) -> &str {
    p.strip_prefix("./").unwrap_or(p)
}

/// Resolve the image reference to a `name:tag` string for the manifest.
pub fn resolve_image_ref(
    source: &ImageSource,
    name: &str,
    version: &str,
) -> String {
    match source {
        ImageSource::Registry(s) => s.clone(),
        ImageSource::Build { .. } | ImageSource::File { .. } => {
            format!("{name}:{version}")
        }
    }
}

fn convert_string_or_array(s: &Option<StringOrArray>) -> Option<StringOrArrayOut> {
    s.as_ref().map(|soa| match soa {
        StringOrArray::Single(s) => StringOrArrayOut::Single(s.clone()),
        StringOrArray::Array(v) => StringOrArrayOut::Array(v.clone()),
    })
}

/// Build a `Manifest` from a parsed config.
///
/// `resolved_image` is the canonical `name:tag` string.
/// `hashes` contains all content hashes computed during staging.
/// `environment` is the already-resolved (env_file merged) environment.
pub fn build_manifest(
    config: &WorkloadConfig,
    resolved_image: &str,
    environment: BTreeMap<String, String>,
    hashes: BTreeMap<String, String>,
) -> Manifest {
    let w = &config.workload;

    // Rewrite measured-data paths: strip "./"
    let measured_data: Vec<String> = w
        .measured_data
        .iter()
        .map(|p| strip_dot_slash(p).to_string())
        .collect();

    // Rewrite unmeasured-data paths: strip "./"
    let unmeasured_data: Vec<String> = w
        .unmeasured_data
        .iter()
        .map(|p| strip_dot_slash(p).to_string())
        .collect();

    // Firewall
    let firewall = config.firewall.as_ref().map(|fw| ManifestFirewall {
        allow: fw
            .allow
            .iter()
            .map(|a| ManifestFirewallAllow {
                port: a.port,
                protocol: a.protocol.clone(),
            })
            .collect(),
        deny: fw.deny.clone(),
    });

    // Baby container
    let baby_container = config
        .baby_container
        .as_ref()
        .map(|bc| ManifestBabyContainer {
            allow: bc.allow,
            max_count: bc.max_count,
        });

    // Signing: rewrite paths to archive-relative
    let signing = config.signing.as_ref().map(|s| ManifestSigning {
        enable: s.enable,
        auth_info: if s.enable {
            Some("signing/auth_info.json".to_string())
        } else {
            None
        },
        policy: if s.enable {
            Some("signing/cosign_policy.json".to_string())
        } else {
            None
        },
    });

    // Dependencies are currently omitted from the manifest until the build
    // pipeline supports staging their images/data and computing hashes.
    let dependencies = None;

    // Disks (top-level)
    let disks: BTreeMap<String, ManifestDisk> = config
        .disks
        .iter()
        .map(|(name, d)| {
            let enc = d.encryption.as_ref().map(|e| ManifestDiskEncryption {
                enable: e.enable,
                key_security: e.key_security.clone(),
            });
            (
                name.clone(),
                ManifestDisk {
                    size: d.size.clone(),
                    bind_fs: d.bind_fs,
                    encryption: enc,
                },
            )
        })
        .collect();

    Manifest {
        meta: ManifestMeta {
            format: crate::FORMAT_VERSION,
            name: w.name.clone(),
            version: w.version.clone(),
        },
        config: ManifestConfig {
            image: resolved_image.to_string(),
            base_image_mode: w.base_image_mode.clone(),
            base_image: w.base_image.clone(),
            ports: w.ports.clone(),
            restart: w.restart.clone(),
            command: convert_string_or_array(&w.command),
            entrypoint: convert_string_or_array(&w.entrypoint),
            ttl: w.ttl,
            cvm_agent: w.cvm_agent,
            measured_data,
            unmeasured_data,
            environment,
            disks: w.disks.clone(),
            dependencies,
            firewall,
            baby_container,
            signing,
        },
        disks,
        hashes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_dot_slash_works() {
        assert_eq!(strip_dot_slash("./config/hello"), "config/hello");
        assert_eq!(strip_dot_slash("config/hello"), "config/hello");
        assert_eq!(strip_dot_slash("./a"), "a");
    }

    #[test]
    fn parse_env_file_basic() {
        let content = "FOO=bar\n# comment\n\nBAZ=qux\n";
        let path = Path::new("test.env");
        let pairs = parse_env_file(path, content).unwrap();
        assert_eq!(pairs, vec![
            ("FOO".into(), "bar".into()),
            ("BAZ".into(), "qux".into()),
        ]);
    }

    #[test]
    fn parse_env_file_error() {
        let content = "INVALID_LINE\n";
        let path = Path::new("test.env");
        let err = parse_env_file(path, content).unwrap_err();
        assert!(matches!(err, WorkloadError::EnvFileParse { line: 1, .. }));
    }

    #[test]
    fn resolve_image_ref_registry() {
        assert_eq!(
            resolve_image_ref(&ImageSource::Registry("alpine:3.18".into()), "x", "v1"),
            "alpine:3.18"
        );
    }

    #[test]
    fn resolve_image_ref_build() {
        let src = ImageSource::Build {
            build: ".".into(),
            containerfile: None,
            args: BTreeMap::new(),
        };
        assert_eq!(resolve_image_ref(&src, "my-app", "v0.0.1"), "my-app:v0.0.1");
    }

    #[test]
    fn env_resolution_order() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join("test.env");
        std::fs::write(&env_path, "A=from_file\nB=from_file\n").unwrap();

        let env_file = Some(StringOrArray::Single("test.env".into()));
        let mut explicit = BTreeMap::new();
        explicit.insert("B".into(), "from_explicit".into());

        let result = resolve_environment(&env_file, &explicit, tmp.path()).unwrap();
        assert_eq!(result["A"], "from_file");
        assert_eq!(result["B"], "from_explicit"); // explicit wins
    }

    #[test]
    fn minimal_manifest_serializes() {
        let toml_str = r#"
format = 1

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
"#;
        let cfg: WorkloadConfig = toml::from_str(toml_str).unwrap();
        let mut hashes = BTreeMap::new();
        hashes.insert("images/my-app.tar".into(), "sha256:abc123".into());

        let manifest = build_manifest(
            &cfg,
            "my-app:latest",
            BTreeMap::new(),
            hashes,
        );

        let output = toml::to_string_pretty(&manifest).unwrap();
        assert!(output.contains("format = 1"));
        assert!(output.contains("name = \"my-app\""));
        assert!(output.contains("version = \"v0.0.1\""));
        assert!(output.contains("image = \"my-app:latest\""));
        assert!(output.contains("images/my-app.tar"));
    }
}
