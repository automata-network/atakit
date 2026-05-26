use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{ImageSource, StringOrArray, WorkloadConfig};
use crate::WorkloadError;

/// Top-level manifest written to `manifest.json` inside the archive.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub meta: ManifestMeta,
    pub config: ManifestConfig,
    #[serde(default)]
    pub disks: BTreeMap<String, ManifestDisk>,
    pub hashes: BTreeMap<String, String>,
    /// Per-service image metadata: archive path + immutable image config
    /// digest ("image ID"). Keyed by service name (workload + each
    /// dependency). Always serialised; defaults to empty when reading
    /// archives that pre-date this field.
    #[serde(default)]
    pub images: BTreeMap<String, ManifestImage>,
}

/// Per-service image metadata.
///
/// `image-id` is `sha256(<image-config-blob>)` -- the same value
/// `podman images --no-trunc` reports as IMAGE ID. It pins the loaded
/// image to its immutable runtime identity so the portal can `podman run`
/// by digest instead of by mutable tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestImage {
    pub archive: String,
    #[serde(rename = "image-id")]
    pub image_id: String,
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
    #[serde(default, rename = "base-image")]
    pub base_image: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default = "default_restart")]
    pub restart: String,
    #[serde(default)]
    pub command: Option<StringOrArrayOut>,
    #[serde(default)]
    pub entrypoint: Option<StringOrArrayOut>,
    #[serde(default, rename = "session-ttl")]
    pub session_ttl: u64,
    #[serde(default, rename = "atakit-portal")]
    pub atakit_portal: bool,
    #[serde(rename = "gid-group")]
    pub gid_group: String,
    #[serde(default, rename = "measured-data")]
    pub measured_data: bool,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: bool,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub disks: BTreeMap<String, String>,
    #[serde(default)]
    pub dependencies: Option<BTreeMap<String, ManifestDependency>>,
    #[serde(default, rename = "firewall-ports")]
    pub firewall_ports: Vec<ManifestFirewallPort>,
    #[serde(default, rename = "baby-container")]
    pub baby_container: Option<ManifestBabyContainer>,
    #[serde(default, rename = "boot-disk-size")]
    pub boot_disk_size: Option<String>,
    #[serde(default, rename = "cap-add")]
    pub cap_add: Vec<String>,
    #[serde(default, rename = "cap-drop")]
    pub cap_drop: Vec<String>,
}

fn default_restart() -> String {
    "no".to_string()
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
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default = "default_restart")]
    pub restart: String,
    #[serde(default)]
    pub command: Option<StringOrArrayOut>,
    #[serde(default)]
    pub entrypoint: Option<StringOrArrayOut>,
    #[serde(default, rename = "atakit-portal")]
    pub atakit_portal: bool,
    #[serde(rename = "gid-group")]
    pub gid_group: String,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
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
}

/// A resolved firewall port to open: port number + protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManifestFirewallPort {
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestBabyContainer {
    pub allow: bool,
    pub max_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestDisk {
    /// LUN / device index for cloud disk attachment.
    pub index: u32,
    pub size: String,
    #[serde(default)]
    pub encryption: Option<ManifestDiskEncryption>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestDiskEncryption {
    pub unlock_method: Vec<String>,
    pub bind: Vec<String>,
}

/// Serialize a Manifest to RFC 8785 canonical JSON.
pub fn serialize_canonical_json(manifest: &Manifest) -> Result<String, WorkloadError> {
    serde_json_canonicalizer::to_string(manifest).map_err(|e| WorkloadError::Json(e.to_string()))
}

// ── env_file resolution ──────────────────────────────────────

/// Parse a `.env` file, returning key-value pairs.
///
/// Blank lines and lines starting with `#` are skipped.
/// Format: `KEY=VALUE` (no quoting needed for values).
pub fn parse_env_file(path: &Path, content: &str) -> Result<Vec<(String, String)>, WorkloadError> {
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
            let content = std::fs::read_to_string(&abs).map_err(|e| WorkloadError::ReadFile {
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
pub fn resolve_image_ref(source: &ImageSource, name: &str, version: &str) -> String {
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
/// `images` contains per-service image metadata (archive path + image ID).
/// `environment` is the already-resolved (env_file merged) environment.
/// `dep_environments` contains resolved environments for each dependency.
pub fn build_manifest(
    config: &WorkloadConfig,
    resolved_image: &str,
    environment: BTreeMap<String, String>,
    dep_environments: BTreeMap<String, BTreeMap<String, String>>,
    hashes: BTreeMap<String, String>,
    images: BTreeMap<String, ManifestImage>,
) -> Manifest {
    let w = &config.workload;

    // Firewall: resolve auto-derived ports + allow - deny into a flat list.
    // Firewall: resolve auto-derived ports + allow - deny into a flat list.
    let firewall_ports = {
        let mut open: HashSet<(u16, String)> = HashSet::new();

        // Auto-derive from ports (workload + dependencies).
        let all_port_specs = w
            .ports
            .iter()
            .chain(config.dependencies.values().flat_map(|d| d.ports.iter()));
        for spec in all_port_specs {
            if let Ok(parsed) = crate::config::parse_port_spec(spec) {
                insert_port_protos(&mut open, parsed.host, &parsed.protocol);
            }
        }

        // Apply firewall overrides.
        if let Some(ref fw) = config.firewall {
            for entry in &fw.allow {
                insert_port_protos(&mut open, entry.port, &entry.protocol);
            }
            for entry in &fw.deny {
                remove_port_protos(&mut open, entry.port, &entry.protocol);
            }
        }

        // Always-allowed portal ports (per spec: 1024 for init, 2024 for
        // status/measurements). TCP only. Injected after user allow/deny
        // so they cannot be denied.
        insert_port_protos(&mut open, 1024, &Some("tcp".to_string()));
        insert_port_protos(&mut open, 2024, &Some("tcp".to_string()));

        // Sort for deterministic output.
        let mut ports: Vec<ManifestFirewallPort> = open
            .into_iter()
            .map(|(port, protocol)| ManifestFirewallPort { port, protocol })
            .collect();
        ports.sort_by(|a, b| {
            a.port
                .cmp(&b.port)
                .then_with(|| a.protocol.cmp(&b.protocol))
        });
        ports
    };

    // Baby container
    let baby_container = config
        .baby_container
        .as_ref()
        .map(|bc| ManifestBabyContainer {
            allow: bc.allow,
            max_count: bc.max_count,
        });

    // Default gid-group: workload name.
    let default_gid_group = w.name.clone();

    // Dependencies: build ManifestDependency for each.
    let dependencies = if config.dependencies.is_empty() {
        None
    } else {
        let version = &w.version;
        let deps: BTreeMap<String, ManifestDependency> = config
            .dependencies
            .iter()
            .map(|(name, dep)| {
                let image = resolve_image_ref(&dep.image, name, version);
                let env = dep_environments.get(name).cloned().unwrap_or_default();
                (
                    name.clone(),
                    ManifestDependency {
                        image,
                        ports: dep.ports.clone(),
                        restart: dep.restart.clone(),
                        command: convert_string_or_array(&dep.command),
                        entrypoint: convert_string_or_array(&dep.entrypoint),
                        atakit_portal: dep.atakit_portal,
                        gid_group: dep
                            .gid_group
                            .clone()
                            .unwrap_or_else(|| default_gid_group.clone()),
                        environment: env,
                        depends_on: dep.depends_on.clone(),
                        measured_data: dep.measured_data,
                        unmeasured_data: dep.unmeasured_data,
                        disks: dep.disks.clone(),
                        cap_add: dep.cap_add.clone(),
                        cap_drop: dep.cap_drop.clone(),
                    },
                )
            })
            .collect();
        Some(deps)
    };

    // Disks (top-level) - resolve auto-assigned indices.
    let resolved_indices = config.resolved_disk_indices();
    let disks: BTreeMap<String, ManifestDisk> = config
        .disks
        .iter()
        .map(|(name, d)| {
            let enc = d.encryption.as_ref().map(|e| ManifestDiskEncryption {
                unlock_method: e.unlock_method.clone(),
                bind: e.bind.clone(),
            });
            let index = resolved_indices.get(name).copied().unwrap_or(10);
            (
                name.clone(),
                ManifestDisk {
                    index,
                    size: d.size.clone(),
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
            session_ttl: w.session_ttl,
            atakit_portal: w.atakit_portal,
            gid_group: w
                .gid_group
                .clone()
                .unwrap_or_else(|| default_gid_group.clone()),
            measured_data: w.measured_data,
            unmeasured_data: w.unmeasured_data,
            environment,
            disks: w.disks.clone(),
            dependencies,
            firewall_ports,
            baby_container,
            boot_disk_size: w.boot_disk_size.clone(),
            cap_add: w.cap_add.clone(),
            cap_drop: w.cap_drop.clone(),
        },
        disks,
        hashes,
        images,
    }
}

/// Insert port with protocol(s) into the open set. `None` means both tcp+udp.
fn insert_port_protos(open: &mut HashSet<(u16, String)>, port: u16, protocol: &Option<String>) {
    match protocol {
        Some(p) => {
            open.insert((port, p.clone()));
        }
        None => {
            open.insert((port, "tcp".to_string()));
            open.insert((port, "udp".to_string()));
        }
    }
}

/// Remove port with protocol(s) from the open set. `None` means both tcp+udp.
fn remove_port_protos(open: &mut HashSet<(u16, String)>, port: u16, protocol: &Option<String>) {
    match protocol {
        Some(p) => {
            open.remove(&(port, p.clone()));
        }
        None => {
            open.remove(&(port, "tcp".to_string()));
            open.remove(&(port, "udp".to_string()));
        }
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
        assert_eq!(
            pairs,
            vec![("FOO".into(), "bar".into()), ("BAZ".into(), "qux".into()),]
        );
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
format = 2

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
"#;
        let cfg: WorkloadConfig = toml::from_str(toml_str).unwrap();
        let mut hashes = BTreeMap::new();
        hashes.insert("images/my-app.tar".into(), "sha256:abc123".into());

        let mut images = BTreeMap::new();
        images.insert(
            "my-app".into(),
            ManifestImage {
                archive: "images/my-app.tar".into(),
                image_id: "sha256:def456".into(),
            },
        );

        let manifest = build_manifest(
            &cfg,
            "my-app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            hashes,
            images,
        );

        let output = serialize_canonical_json(&manifest).unwrap();
        // Canonical JSON: verify key fields are present
        assert!(output.contains("\"format\":2"));
        assert!(output.contains("\"name\":\"my-app\""));
        assert!(output.contains("\"version\":\"v0.0.1\""));
        assert!(output.contains("\"image\":\"my-app:latest\""));
        assert!(output.contains("images/my-app.tar"));
        // gid-group defaults to workload name
        assert!(output.contains("\"gid-group\":\"my-app\""));
        // measured-data and unmeasured-data are booleans
        assert!(output.contains("\"measured-data\":false"));
        assert!(output.contains("\"unmeasured-data\":false"));
        // session-ttl defaults to 0
        assert!(output.contains("\"session-ttl\":0"));
        // images section is present and surfaces image-id
        assert!(output.contains("\"images\":"));
        assert!(output.contains("\"image-id\":\"sha256:def456\""));
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let toml_str = r#"
format = 2

[workload]
name = "test"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "test:latest"
"#;
        let cfg: WorkloadConfig = toml::from_str(toml_str).unwrap();
        let hashes = BTreeMap::new();
        let images = BTreeMap::new();

        let m1 = build_manifest(
            &cfg,
            "test:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            hashes.clone(),
            images.clone(),
        );
        let m2 = build_manifest(
            &cfg,
            "test:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            hashes,
            images,
        );

        let json1 = serialize_canonical_json(&m1).unwrap();
        let json2 = serialize_canonical_json(&m2).unwrap();
        assert_eq!(json1, json2, "canonical JSON must be byte-identical");
    }

    #[test]
    fn canonical_json_with_images_is_deterministic() {
        let toml_str = r#"
format = 2

[workload]
name = "main"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "main:latest"

[dependencies.redis]
image = "redis:7"
"#;
        let cfg: WorkloadConfig = toml::from_str(toml_str).unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("images/main.tar".into(), "sha256:aaa".into());
        hashes.insert("images/redis.tar".into(), "sha256:bbb".into());

        let mut images = BTreeMap::new();
        images.insert(
            "main".into(),
            ManifestImage {
                archive: "images/main.tar".into(),
                image_id: "sha256:1111".into(),
            },
        );
        images.insert(
            "redis".into(),
            ManifestImage {
                archive: "images/redis.tar".into(),
                image_id: "sha256:2222".into(),
            },
        );

        let m1 = build_manifest(
            &cfg,
            "main:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            hashes.clone(),
            images.clone(),
        );
        let m2 = build_manifest(
            &cfg,
            "main:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            hashes,
            images,
        );

        let j1 = serialize_canonical_json(&m1).unwrap();
        let j2 = serialize_canonical_json(&m2).unwrap();
        assert_eq!(j1, j2);
        // Sanity: both image-ids surface in the canonical output.
        assert!(j1.contains("\"image-id\":\"sha256:1111\""));
        assert!(j1.contains("\"image-id\":\"sha256:2222\""));
        // And service-name keying.
        assert!(j1.contains("\"main\":{\"archive\":\"images/main.tar\""));
        assert!(j1.contains("\"redis\":{\"archive\":\"images/redis.tar\""));
    }

    #[test]
    fn cap_fields_always_serialize_when_empty() {
        // Source TOML omits cap-add and cap-drop. Manifest v2 still serialises
        // them as empty arrays so PCR23 binds the absence as a positive
        // commitment rather than as field absence.
        let toml_str = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "app:latest"

[dependencies.sidecar]
image = "redis:7"
"#;
        let cfg: WorkloadConfig = toml::from_str(toml_str).unwrap();
        let manifest = build_manifest(
            &cfg,
            "app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let json = serialize_canonical_json(&manifest).unwrap();

        // Workload-level cap fields present and empty.
        assert!(
            json.contains("\"cap-add\":[]"),
            "expected workload cap-add: [], got: {json}"
        );
        assert!(
            json.contains("\"cap-drop\":[]"),
            "expected workload cap-drop: []"
        );

        // Dependency cap fields present and empty too. Canonical JSON sorts
        // keys, so within the dependency object cap-add comes before cap-drop.
        assert!(
            json.contains("\"sidecar\":{\"atakit-portal\":false,\"cap-add\":[],\"cap-drop\":[]"),
            "expected dependency to surface both cap fields with empty defaults"
        );
    }

    #[test]
    fn cap_fields_propagate_into_manifest() {
        let toml_str = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "app:latest"
cap-add = ["NET_ADMIN"]
cap-drop = ["NET_BIND_SERVICE"]

[dependencies.sidecar]
image = "redis:7"
cap-add = ["NET_RAW"]
cap-drop = ["KILL"]
"#;
        let cfg: WorkloadConfig = toml::from_str(toml_str).unwrap();
        let manifest = build_manifest(
            &cfg,
            "app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        assert_eq!(manifest.config.cap_add, vec!["NET_ADMIN".to_string()]);
        assert_eq!(
            manifest.config.cap_drop,
            vec!["NET_BIND_SERVICE".to_string()]
        );

        let dep = manifest
            .config
            .dependencies
            .as_ref()
            .unwrap()
            .get("sidecar")
            .unwrap();
        assert_eq!(dep.cap_add, vec!["NET_RAW".to_string()]);
        assert_eq!(dep.cap_drop, vec!["KILL".to_string()]);

        let json = serialize_canonical_json(&manifest).unwrap();
        assert!(json.contains("\"cap-add\":[\"NET_ADMIN\"]"));
        assert!(json.contains("\"cap-drop\":[\"NET_BIND_SERVICE\"]"));
        assert!(json.contains("\"cap-add\":[\"NET_RAW\"]"));
        assert!(json.contains("\"cap-drop\":[\"KILL\"]"));
    }

    #[test]
    fn cap_fields_change_canonical_bytes() {
        // Two configs that differ only in cap-add must produce different
        // canonical JSON. This is the property that makes PCR23 bind the
        // capability declaration into attestation.
        let base_toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "app:latest"
"#;
        let with_cap_toml = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "app:latest"
cap-add = ["NET_ADMIN"]
"#;
        let cfg_a: WorkloadConfig = toml::from_str(base_toml).unwrap();
        let cfg_b: WorkloadConfig = toml::from_str(with_cap_toml).unwrap();

        let m_a = build_manifest(
            &cfg_a,
            "app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let m_b = build_manifest(
            &cfg_b,
            "app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        let j_a = serialize_canonical_json(&m_a).unwrap();
        let j_b = serialize_canonical_json(&m_b).unwrap();
        assert_ne!(j_a, j_b, "cap-add must change the canonical JSON bytes");
    }
}
