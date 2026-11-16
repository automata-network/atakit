use atakit_core::storage_access::{self, StorageAccess};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{AttributeRequirements, DataMount, ImageSource, StringOrArray, WorkloadConfig};
use crate::data::{logical_data_path_rel, namespaced_data_path};
use crate::WorkloadError;

/// Top-level manifest written to `manifest.json` inside the archive.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub meta: ManifestMeta,
    pub config: ManifestConfig,
    #[serde(default)]
    pub disks: BTreeMap<String, ManifestDisk>,
    pub hashes: BTreeMap<String, String>,
    /// Declared `unmeasured-data` paths (operator-provided at deploy time).
    ///
    /// Each entry is archive-relative and `unmeasured-data/`-prefixed, mirroring
    /// the `measured-data/` keys in `hashes`. Unlike `hashes`, there is no
    /// content hash: the files are never bundled into the archive -- only the
    /// declared path *set* is committed to the manifest (and thus PCR23). The
    /// portal verifies the operator-supplied tar is a subset of this set at
    /// `/init`; contents stay unverified. A `BTreeSet` because this is a path
    /// *set* with no associated value (unlike `hashes`): it serialises to a
    /// JSON array, sorted + deduped, so canonical JSON is byte-deterministic.
    /// Always serialised (empty `[]` is a positive commitment that the workload
    /// declares no operator-provided files).
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: BTreeSet<String>,
    /// Measured variable-name allowlist for each unmeasured env file.
    ///
    /// Keys are normalized `unmeasured-data/...` paths. Values are sorted,
    /// unique variable names. Runtime values are intentionally absent.
    #[serde(default, rename = "unmeasured-env-files")]
    pub unmeasured_env_files: BTreeMap<String, Vec<String>>,
    /// Per-service image metadata: archive path + immutable image config
    /// digest ("image ID"). Keyed by service name (workload + each
    /// dependency). Always serialised; defaults to empty when reading
    /// archives that pre-date this field.
    #[serde(default)]
    pub images: BTreeMap<String, ManifestImage>,
}

// Use the same format-aware writer as the other component. Nested optional
// CPU/integrity/legacy storage fields need the top-level format to emit defaults.
impl Serialize for Manifest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        atakit_core::workload_manifest::ManifestSections {
            format: self.meta.format,
            meta: &self.meta,
            config: &self.config,
            disks: &self.disks,
            hashes: &self.hashes,
            unmeasured_data: &self.unmeasured_data,
            unmeasured_env_files: &self.unmeasured_env_files,
            images: &self.images,
        }
        .serialize(serializer)
    }
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
    /// Fingerprint of the key that publishes this workload: `0x` followed by 64
    /// lowercase hexadecimal characters.
    ///
    /// The identifier is `keccak256(abi.encode(domain, publisher, name,
    /// version))`, so a workload cannot be identified by name and version
    /// alone. Recording the publisher here places it inside the measured
    /// manifest, which is what lets the portal derive the identifier it reports
    /// rather than be told what to claim.
    pub publisher: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpuset: Option<String>,
    #[serde(
        default,
        rename = "cpuset-policy",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpuset_policy: Option<atakit_core::cpu_config::CpusetRules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nofile: Option<u64>,
    #[serde(default, rename = "cpu-idle", skip_serializing_if = "Option::is_none")]
    pub cpu_idle: Option<atakit_core::cpu_config::CpuIdleRules>,
    #[serde(
        default,
        rename = "cpu-frequency",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpu_frequency: Option<atakit_core::cpu_config::CpuFrequencyRules>,

    #[serde(default)]
    pub readiness: Option<atakit_core::readiness::Readiness>,
    pub image: String,
    #[serde(rename = "base-image-mode")]
    pub base_image_mode: String,
    #[serde(default, rename = "base-image")]
    pub base_image: Vec<String>,
    #[serde(default)]
    pub attributes: AttributeRequirements,
    #[serde(default)]
    pub ports: Vec<String>,
    pub depends_on: Vec<String>,
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
    pub measured_data: ManifestDataMount,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: ManifestDataMount,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default, rename = "unmeasured-env-files")]
    pub unmeasured_env_files: Vec<String>,
    #[serde(default)]
    pub storage: BTreeMap<String, ManifestServiceStorage>,
    #[serde(default)]
    pub ip_env: bool,
    #[serde(default)]
    pub dependencies: Option<BTreeMap<String, ManifestDependency>>,
    #[serde(default, rename = "firewall-ports")]
    pub firewall_ports: Vec<ManifestFirewallPort>,
    #[serde(
        default,
        rename = "baby-container",
        deserialize_with = "deserialize_manifest_baby_container"
    )]
    pub baby_container: ManifestBabyContainer,
    #[serde(default, rename = "boot-disk-size")]
    pub boot_disk_size: Option<String>,
    #[serde(default, rename = "cap-add")]
    pub cap_add: Vec<String>,
    #[serde(default, rename = "cap-drop")]
    pub cap_drop: Vec<String>,
    pub logging: ManifestLogging,
    #[serde(rename = "workload-logs")]
    pub workload_logs: bool,
}

/// Container logging configuration emitted into manifest.json. Common fields
/// are explicit; `access` applies only to baby logging in formats 15+.
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestLogging {
    pub driver: String,
    pub options: BTreeMap<String, String>,
    #[serde(rename = "log-readers")]
    pub log_readers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
}

/// Service data mount declaration in `manifest.json`.
///
/// Old manifest formats used a boolean. Format 5 emits the exact path-list
/// form, but the enum keeps older manifests parseable by local tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManifestDataMount {
    All(bool),
    Paths(Vec<String>),
}

impl Default for ManifestDataMount {
    fn default() -> Self {
        Self::All(false)
    }
}

impl ManifestDataMount {
    pub fn is_enabled(&self) -> bool {
        match self {
            Self::All(enabled) => *enabled,
            Self::Paths(paths) => !paths.is_empty(),
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpuset: Option<String>,
    #[serde(
        default,
        rename = "cpuset-policy",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpuset_policy: Option<atakit_core::cpu_config::CpusetRules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nofile: Option<u64>,

    #[serde(default)]
    pub readiness: Option<atakit_core::readiness::Readiness>,
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
    #[serde(default, rename = "unmeasured-env-files")]
    pub unmeasured_env_files: Vec<String>,
    pub depends_on: Vec<String>,
    #[serde(default, rename = "measured-data")]
    pub measured_data: ManifestDataMount,
    #[serde(default, rename = "unmeasured-data")]
    pub unmeasured_data: ManifestDataMount,
    #[serde(default)]
    pub storage: BTreeMap<String, ManifestServiceStorage>,
    #[serde(default)]
    pub ip_env: bool,
    #[serde(default, rename = "cap-add")]
    pub cap_add: Vec<String>,
    #[serde(default, rename = "cap-drop")]
    pub cap_drop: Vec<String>,
    pub logging: ManifestLogging,
    #[serde(rename = "workload-logs")]
    pub workload_logs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestServiceStorage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Vec<StorageAccess>>,
    pub disk: String,
    pub base_path: String,
    pub mount_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(default, skip_serializing_if = "storage_execution_disabled")]
    pub executable: Option<bool>,
}
impl ManifestServiceStorage {
    pub fn read_only(&self) -> bool {
        storage_access::read_only(&self.access, self.read_only)
    }
    pub fn executable(&self) -> bool {
        storage_access::executable(&self.access, self.executable)
    }
    pub fn validate_access(&self, format: u32) -> Result<(), String> {
        if format < 14 && self.read_only.is_none() {
            return Err("legacy storage requires read_only".into());
        }
        storage_access::validate_mount_access(
            format,
            &self.access,
            self.read_only,
            self.executable,
        )?;
        Ok(())
    }
}

/// A resolved firewall port to open: port number + protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManifestFirewallPort {
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ManifestBabyContainer {
    pub enabled: bool,
    pub max_instances: u32,
    pub slots: BTreeMap<String, ManifestBabyContainerSlot>,
}

fn deserialize_manifest_baby_container<'de, D>(
    deserializer: D,
) -> Result<ManifestBabyContainer, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<ManifestBabyContainer>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestBabyContainerSlot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpuset: Option<String>,
    #[serde(
        default,
        rename = "cpuset-policy",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpuset_policy: Option<atakit_core::cpu_config::CpusetRules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nofile: Option<u64>,

    #[serde(default)]
    pub allowed_capabilities: Vec<String>,
    pub parent_service: String,
    pub gid_group: String,
    pub image_selection: String,
    pub max_instances: u32,
    pub lifecycle: ManifestBabyContainerLifecycle,
    pub storage: BTreeMap<String, ManifestBabyContainerStorage>,
    #[serde(default)]
    pub ip_env: bool,
    pub logging: ManifestLogging,
    pub trust_policy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestBabyContainerLifecycle {
    #[serde(default)]
    pub rootfs_size_mib: Option<u64>,
    #[serde(default)]
    pub rootfs_disk: Option<String>,
    pub image_retention: String,
    pub instance_retention: String,
    pub restart: String,
    pub rootfs: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestBabyContainerStorage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Vec<StorageAccess>>,
    pub disk: String,
    pub base_path: String,
    pub mount_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(default, skip_serializing_if = "storage_execution_disabled")]
    pub executable: Option<bool>,
    pub retention: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_access: Option<Vec<StorageAccess>>,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<ManifestBabyContainerStoragePermissions>,
}
impl ManifestBabyContainerStorage {
    pub fn read_only(&self) -> bool {
        storage_access::read_only(&self.access, self.read_only)
    }
    pub fn executable(&self) -> bool {
        storage_access::executable(&self.access, self.executable)
    }
    pub fn validate_access(&self, format: u32) -> Result<(), String> {
        if format < 14 && self.read_only.is_none() {
            return Err("legacy storage requires read_only".into());
        }
        storage_access::validate_mount_access(
            format,
            &self.access,
            self.read_only,
            self.executable,
        )?;
        if format >= 14 {
            if self.permissions.is_some() {
                return Err(
                    "format 14 storage requires access and parent-access instead of permissions"
                        .into(),
                );
            }
            storage_access::validate_access(self.parent_access.as_deref().unwrap_or(&[]), true)?;
        } else if self.parent_access.is_some() {
            return Err("parent-access requires format 14".into());
        } else if self.permissions.is_none() {
            return Err("legacy baby storage requires permissions".into());
        }
        Ok(())
    }
    pub fn baby_permission(&self) -> &str {
        self.permissions.as_ref().map_or("rw", |p| p.baby.as_str())
    }
    pub fn parent_permission(&self) -> &str {
        self.permissions
            .as_ref()
            .map_or("none", |p| p.parent.as_str())
    }
    pub fn parent_allows(&self, read_only: bool, executable: bool) -> bool {
        if self.access.is_some() {
            storage_access::parent_allows(
                self.parent_access.as_deref().unwrap_or(&[]),
                read_only,
                executable,
            )
        } else {
            self.parent_permission() != "none" && (self.parent_permission() != "ro" || read_only)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestBabyContainerStoragePermissions {
    pub baby: String,
    pub parent: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestDisk {
    /// LUN / device index for cloud disk attachment.
    pub index: u32,
    pub size: String,
    /// Always serialised, even when both lists are empty. An empty
    /// `unlock_method` is itself a positive commitment that the disk
    /// runs without encryption — same "Empty as commitment" rule as
    /// `cap-add`/`cap-drop`.
    pub encryption: ManifestDiskEncryption,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ManifestDiskEncryption {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
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

/// Return whether `name` is a portable shell-style environment name.
pub fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.bytes();
    matches!(chars.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && chars.all(|c| matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Parse the measured variable-name allowlist from a developer-side
/// unmeasured env-file template. Values are deliberately ignored.
pub fn parse_unmeasured_env_file_names(
    path: &Path,
    content: &str,
) -> Result<Vec<String>, WorkloadError> {
    let mut names = BTreeSet::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, _value)) = line.split_once('=') else {
            return Err(WorkloadError::EnvFileParse {
                path: path.to_path_buf(),
                line: i + 1,
                message: "expected KEY=VALUE".into(),
            });
        };
        let key = key.trim();
        if !is_valid_env_name(key) {
            return Err(WorkloadError::EnvFileParse {
                path: path.to_path_buf(),
                line: i + 1,
                message: format!("invalid environment variable name {key:?}"),
            });
        }
        if key.starts_with("ATAKIT_") || key.starts_with("VERIFIERD_") {
            return Err(WorkloadError::EnvFileParse {
                path: path.to_path_buf(),
                line: i + 1,
                message: format!("reserved environment variable name {key:?}"),
            });
        }
        if !names.insert(key.to_string()) {
            return Err(WorkloadError::EnvFileParse {
                path: path.to_path_buf(),
                line: i + 1,
                message: format!("duplicate environment variable name {key:?}"),
            });
        }
    }
    Ok(names.into_iter().collect())
}

/// Read every referenced developer-side unmeasured env-file template and
/// build the top-level measured name allowlists.
pub fn resolve_unmeasured_env_allowlists(
    config: &WorkloadConfig,
    unmeasured_data_root: &Path,
) -> Result<BTreeMap<String, Vec<String>>, WorkloadError> {
    let mut allowlists = BTreeMap::new();
    let service_files = std::iter::once(&config.workload.unmeasured_env_file).chain(
        config
            .dependencies
            .values()
            .map(|dependency| &dependency.unmeasured_env_file),
    );

    for files in service_files.flatten() {
        for logical_path in files.as_vec() {
            let normalized = namespaced_data_path("unmeasured-data", &logical_path);
            if allowlists.contains_key(&normalized) {
                continue;
            }
            let path = unmeasured_data_root.join(logical_data_path_rel(&logical_path));
            let content =
                std::fs::read_to_string(&path).map_err(|source| WorkloadError::ReadFile {
                    path: path.clone(),
                    source,
                })?;
            allowlists.insert(
                normalized,
                parse_unmeasured_env_file_names(&path, &content)?,
            );
        }
    }

    Ok(allowlists)
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

/// Normalize a package-relative path string for manifest storage.
pub fn strip_dot_slash(p: &str) -> &str {
    p.strip_prefix("./").unwrap_or(p).trim_end_matches('/')
}

/// Normalize declared `[package] unmeasured-data` entries into the sorted,
/// deduped, `unmeasured-data/`-prefixed path list recorded in the manifest.
///
/// A trailing slash declares a directory and requires enumeration at build
/// time. Other entries declare files; absent files need no source directory.
pub fn normalize_unmeasured_data(
    paths: &[String],
    root: &Path,
) -> Result<BTreeSet<String>, WorkloadError> {
    let mut out = BTreeSet::new();
    for entry in paths {
        let rel = crate::data::validate_logical_data_path(entry, "package unmeasured-data")?;
        let abs = root.join(&rel);
        if entry.ends_with('/') {
            if !abs.is_dir() {
                return Err(WorkloadError::Validation(format!(
                    "unmeasured-data directory {entry:?} must exist at build time under {} (use --unmeasured-data-root to select its source)", root.display()
                )));
            }
            collect_unmeasured_members(&abs, &rel, &mut out)?;
        } else {
            match std::fs::metadata(&abs) {
                Ok(meta) if meta.is_dir() => {
                    return Err(WorkloadError::Validation(format!(
                    "unmeasured-data {entry:?} is a directory; declare {entry}/ with a trailing '/'"
                )))
                }
                Ok(meta) if !meta.is_file() => {
                    return Err(WorkloadError::Validation(format!(
                        "unmeasured-data {entry:?} is not a regular file"
                    )))
                }
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(WorkloadError::ReadFile {
                        path: abs,
                        source: error,
                    })
                }
                _ => {}
            }
            out.insert(namespaced_data_path("unmeasured-data", entry));
        }
    }
    Ok(out)
}

/// Enumeration errors must not silently remove paths from the measured manifest.
fn collect_unmeasured_members(
    dir: &Path,
    rel: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), WorkloadError> {
    let read_error = |source| WorkloadError::ReadFile {
        path: dir.to_owned(),
        source,
    };
    for entry in std::fs::read_dir(dir).map_err(read_error)? {
        let entry = entry.map_err(read_error)?;
        let name = entry.file_name().into_string().map_err(|_| {
            WorkloadError::Validation(format!(
                "unmeasured-data directory {} contains a non-UTF-8 name",
                dir.display()
            ))
        })?;
        let child = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        crate::data::validate_logical_data_path(
            &format!("/{child}"),
            "unmeasured-data directory member",
        )?;
        let kind = entry.file_type().map_err(read_error)?;
        if kind.is_dir() {
            collect_unmeasured_members(&entry.path(), &child, out)?;
        } else if kind.is_file() {
            out.insert(format!("unmeasured-data/{child}"));
        } else {
            return Err(WorkloadError::Validation(format!(
                "unmeasured-data directory member {} must be a regular file or directory (links are not enumerated)", entry.path().display()
            )));
        }
    }
    Ok(())
}

/// Normalize declared `[package] measured-data` entries into the sorted,
/// deduped, `measured-data/`-prefixed path set staged into the archive.
pub fn normalize_measured_data(paths: &[String], workload_dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in paths {
        let rel = logical_data_path_rel(entry);
        let abs = workload_dir.join(rel);
        if abs.is_dir() {
            collect_member_files_with_prefix(
                &abs,
                &logical_data_path_rel(entry),
                "measured-data",
                &mut out,
            );
        } else {
            out.insert(namespaced_data_path("measured-data", entry));
        }
    }
    out
}

/// Extract the archive-relative measured-data path set from manifest hashes.
pub fn measured_data_from_hashes(hashes: &BTreeMap<String, String>) -> BTreeSet<String> {
    hashes
        .keys()
        .filter(|path| path.starts_with("measured-data/"))
        .cloned()
        .collect()
}

pub(crate) fn data_selector_matches(prefix: &str, path: &str, entry: &str) -> bool {
    let normalized = namespaced_data_path(prefix, path);
    let child = entry
        .strip_prefix(&normalized)
        .is_some_and(|suffix| suffix.starts_with('/'));
    if prefix == "unmeasured-data" {
        if path.ends_with('/') {
            child
        } else {
            entry == normalized
        }
    } else {
        entry == normalized || child
    }
}

fn expand_data_mount(
    mount: &DataMount,
    full_set: &BTreeSet<String>,
    prefix: &str,
) -> ManifestDataMount {
    match mount {
        DataMount::Bool(enabled) => {
            if *enabled {
                ManifestDataMount::Paths(full_set.iter().cloned().collect())
            } else {
                ManifestDataMount::Paths(Vec::new())
            }
        }
        DataMount::Paths(paths) => {
            let mut selected = BTreeSet::new();
            for path in paths {
                for entry in full_set {
                    if data_selector_matches(prefix, path, entry) {
                        selected.insert(entry.clone());
                    }
                }
            }
            ManifestDataMount::Paths(selected.into_iter().collect())
        }
    }
}

/// Normalize per-service runtime env-file declarations to manifest paths.
pub fn normalize_unmeasured_env_files(env_files: &Option<StringOrArray>) -> Vec<String> {
    env_files
        .as_ref()
        .map(|files| {
            files
                .as_vec()
                .into_iter()
                .map(|p| namespaced_data_path("unmeasured-data", &p))
                .collect()
        })
        .unwrap_or_default()
}

fn collect_member_files_with_prefix(
    dir: &Path,
    rel_prefix: &str,
    prefix: &str,
    out: &mut BTreeSet<String>,
) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_rel = if rel_prefix.is_empty() {
            name
        } else {
            format!("{rel_prefix}/{name}")
        };
        if path.is_dir() {
            collect_member_files_with_prefix(&path, &child_rel, prefix, out);
        } else {
            out.insert(format!("{prefix}/{child_rel}"));
        }
    }
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
/// `unmeasured_data` is the normalized, sorted declared unmeasured-data path
/// list (see `normalize_unmeasured_data`).
/// `images` contains per-service image metadata (archive path + image ID).
/// `environment` is the already-resolved (env_file merged) environment.
/// `dep_environments` contains resolved environments for each dependency.
/// `publisher` is the fingerprint of the publishing key; it is measured, so it
/// is validated here rather than trusted.
// Keep each measured manifest section explicit at this deterministic build
// boundary. Grouping them would hide which inputs affect the canonical bytes.
#[allow(clippy::too_many_arguments)]
pub fn build_manifest(
    config: &WorkloadConfig,
    publisher: &str,
    resolved_image: &str,
    environment: BTreeMap<String, String>,
    dep_environments: BTreeMap<String, BTreeMap<String, String>>,
    hashes: BTreeMap<String, String>,
    unmeasured_data: BTreeSet<String>,
    unmeasured_env_files: BTreeMap<String, Vec<String>>,
    images: BTreeMap<String, ManifestImage>,
) -> Result<Manifest, WorkloadError> {
    // A malformed publisher would be measured into PCR23 and would derive an
    // identifier registered to nobody, so it is rejected at the boundary rather
    // than baked into the archive.
    if !atakit_core::is_canonical_id(publisher) {
        return Err(WorkloadError::Validation(format!(
            "publisher must be '0x' followed by 64 lowercase hexadecimal \
             characters, got '{publisher}'"
        )));
    }
    if config.format < crate::BABY_LOG_POLICY_FORMAT_VERSION
        && config.baby_container.as_ref().is_some_and(|baby| {
            baby.slots.values().any(|slot| {
                slot.logging.access.as_deref() == Some("none")
                    || !slot.logging.log_readers.is_empty()
            })
        })
    {
        return Err(WorkloadError::Validation(format!(
            "baby log access restrictions and log-readers require format = {}",
            crate::BABY_LOG_POLICY_FORMAT_VERSION
        )));
    }
    let w = &config.workload;
    atakit_core::nofile::validate_requests(
        config.format,
        w.nofile
            .into_iter()
            .chain(config.dependencies.values().filter_map(|d| d.nofile))
            .chain(
                config
                    .baby_container
                    .iter()
                    .flat_map(|b| b.slots.values())
                    .filter_map(|s| s.nofile),
            ),
    )
    .map_err(WorkloadError::Validation)?;
    atakit_core::cpu_config::validate_rules(
        config.format,
        w.cpu_idle.as_ref(),
        w.cpu_frequency.as_ref(),
        w.cpuset
            .iter()
            .map(String::as_str)
            .chain(
                config
                    .dependencies
                    .values()
                    .filter_map(|d| d.cpuset.as_deref()),
            )
            .chain(
                config
                    .baby_container
                    .iter()
                    .flat_map(|b| b.slots.values())
                    .filter_map(|s| s.cpuset.as_deref()),
            ),
    )
    .map_err(WorkloadError::Validation)?;
    let attributes = crate::validate::normalize_attributes(&w.attributes)?;
    let measured_data = measured_data_from_hashes(&hashes);

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
                        unmeasured_env_files: normalize_unmeasured_env_files(
                            &dep.unmeasured_env_file,
                        ),
                        readiness: dep.readiness.clone(),
                        cpuset: dep.cpuset.clone(),
                        cpuset_policy: dep.cpuset_policy.clone(),
                        nofile: dep.nofile,
                        depends_on: dep.depends_on.clone(),
                        measured_data: expand_data_mount(
                            &dep.measured_data,
                            &measured_data,
                            "measured-data",
                        ),
                        unmeasured_data: expand_data_mount(
                            &dep.unmeasured_data,
                            &unmeasured_data,
                            "unmeasured-data",
                        ),
                        storage: convert_service_storage_compat(&dep.storage, &dep.disks),
                        ip_env: dep.ip_env,
                        cap_add: dep.cap_add.clone(),
                        cap_drop: dep.cap_drop.clone(),
                        logging: convert_logging(&dep.logging),
                        workload_logs: dep.workload_logs,
                    },
                )
            })
            .collect();
        Some(deps)
    };

    let gid_group_for_service = |service_name: &str| -> String {
        if service_name == w.name {
            w.gid_group
                .clone()
                .unwrap_or_else(|| default_gid_group.clone())
        } else {
            config
                .dependencies
                .get(service_name)
                .and_then(|dep| dep.gid_group.clone())
                .unwrap_or_else(|| default_gid_group.clone())
        }
    };

    let baby_container = if let Some(bc) = &config.baby_container {
        if bc.enabled {
            let slots = bc
                .slots
                .iter()
                .map(|(slot_name, slot)| {
                    let storage = slot
                        .storage
                        .iter()
                        .map(|(storage_name, storage)| {
                            (
                                storage_name.clone(),
                                ManifestBabyContainerStorage {
                                    disk: storage.disk.clone(),
                                    base_path: storage.base_path.clone(),
                                    mount_path: storage.mount_path.clone(),
                                    read_only: storage
                                        .access
                                        .is_none()
                                        .then(|| storage.read_only()),
                                    access: storage_access::canonical_access(&storage.access),
                                    parent_access: storage.access.as_ref().map(|_| {
                                        storage_access::canonical_access(&storage.parent_access)
                                            .unwrap_or_default()
                                    }),
                                    executable: storage
                                        .access
                                        .is_none()
                                        .then(|| storage.executable()),
                                    retention: storage.retention.clone(),
                                    scope: storage.scope.clone(),
                                    permissions: storage.access.is_none().then(|| {
                                        ManifestBabyContainerStoragePermissions {
                                            baby: storage.baby_permission().to_string(),
                                            parent: storage.parent_permission().to_string(),
                                        }
                                    }),
                                },
                            )
                        })
                        .collect();
                    (
                        slot_name.clone(),
                        ManifestBabyContainerSlot {
                            allowed_capabilities: slot.allowed_capabilities.clone(),
                            cpuset: slot.cpuset.clone(),
                            cpuset_policy: slot.cpuset_policy.clone(),
                            nofile: slot.nofile,
                            parent_service: slot.parent_service.clone(),
                            gid_group: slot
                                .gid_group
                                .clone()
                                .unwrap_or_else(|| gid_group_for_service(&slot.parent_service)),
                            image_selection: slot.image_selection.clone(),
                            max_instances: slot.max_instances,
                            lifecycle: ManifestBabyContainerLifecycle {
                                rootfs_size_mib: slot.lifecycle.rootfs_size_mib,
                                rootfs_disk: slot.lifecycle.rootfs_disk.clone(),
                                image_retention: slot.lifecycle.image_retention.clone(),
                                instance_retention: slot.lifecycle.instance_retention.clone(),
                                restart: slot.lifecycle.restart.clone(),
                                rootfs: slot.lifecycle.rootfs.replace('-', "_"),
                            },
                            storage,
                            ip_env: slot.ip_env,
                            logging: ManifestLogging {
                                access: (config.format >= crate::BABY_LOG_POLICY_FORMAT_VERSION)
                                    .then(|| {
                                        slot.logging
                                            .access
                                            .clone()
                                            .unwrap_or_else(|| "parent".into())
                                    }),
                                ..convert_logging(&slot.logging)
                            },
                            trust_policy: slot.trust_policy.clone(),
                        },
                    )
                })
                .collect();
            ManifestBabyContainer {
                enabled: true,
                max_instances: bc.max_instances.unwrap_or(1),
                slots,
            }
        } else {
            ManifestBabyContainer {
                enabled: false,
                max_instances: 0,
                slots: BTreeMap::new(),
            }
        }
    } else {
        ManifestBabyContainer {
            enabled: false,
            max_instances: 0,
            slots: BTreeMap::new(),
        }
    };

    // Disks (top-level) - resolve auto-assigned indices.
    let resolved_indices = config.resolved_disk_indices();
    let disks: BTreeMap<String, ManifestDisk> = config
        .disks
        .iter()
        .map(|(name, d)| {
            let enc = ManifestDiskEncryption {
                integrity: d.encryption.integrity.clone(),
                unlock_method: d.encryption.unlock_method.clone(),
                bind: d.encryption.bind.clone(),
            };
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

    let mut manifest = Manifest {
        meta: ManifestMeta {
            format: if config.format >= 16 {
                atakit_core::cpu::CPU_POLICY_FORMAT
            } else if config.format >= 15 {
                crate::BABY_LOG_POLICY_FORMAT_VERSION
            } else if config.format >= 14 {
                crate::ACCESS_STORAGE_FORMAT_VERSION
            } else if config.format >= 13
                || config.workload.storage.values().any(|s| s.executable())
                || config
                    .dependencies
                    .values()
                    .any(|d| d.storage.values().any(|s| s.executable()))
                || config.baby_container.as_ref().is_some_and(|b| {
                    b.enabled
                        && b.slots
                            .values()
                            .any(|slot| slot.storage.values().any(|s| s.executable()))
                })
            {
                crate::EXECUTABLE_STORAGE_FORMAT_VERSION
            } else if config
                .disks
                .values()
                .any(|d| d.encryption.integrity.is_some())
            {
                crate::INTEGRITY_FORMAT_VERSION
            } else {
                crate::FORMAT_VERSION
            },
            publisher: publisher.to_string(),
            name: w.name.clone(),
            version: w.version.clone(),
        },
        config: ManifestConfig {
            image: resolved_image.to_string(),
            base_image_mode: w.base_image_mode.clone(),
            base_image: w.base_image.clone(),
            attributes,
            ports: w.ports.clone(),
            readiness: w.readiness.clone(),
            cpuset: w.cpuset.clone(),
            cpuset_policy: w.cpuset_policy.clone(),
            nofile: w.nofile,
            cpu_idle: w.cpu_idle.clone(),
            cpu_frequency: w.cpu_frequency.clone(),
            depends_on: w.depends_on.clone(),
            restart: w.restart.clone(),
            command: convert_string_or_array(&w.command),
            entrypoint: convert_string_or_array(&w.entrypoint),
            session_ttl: w.session_ttl,
            atakit_portal: w.atakit_portal,
            gid_group: w
                .gid_group
                .clone()
                .unwrap_or_else(|| default_gid_group.clone()),
            measured_data: expand_data_mount(&w.measured_data, &measured_data, "measured-data"),
            unmeasured_data: expand_data_mount(
                &w.unmeasured_data,
                &unmeasured_data,
                "unmeasured-data",
            ),
            environment,
            unmeasured_env_files: normalize_unmeasured_env_files(&w.unmeasured_env_file),
            storage: convert_service_storage_compat(&w.storage, &w.disks),
            ip_env: w.ip_env,
            dependencies,
            firewall_ports,
            baby_container,
            boot_disk_size: w.boot_disk_size.clone(),
            cap_add: w.cap_add.clone(),
            cap_drop: w.cap_drop.clone(),
            logging: convert_logging(&w.logging),
            workload_logs: w.workload_logs,
        },
        disks,
        hashes,
        unmeasured_data,
        unmeasured_env_files,
        images,
    };
    crate::manifest_normalization::normalize(&mut manifest)?;
    Ok(manifest)
}

fn convert_logging(logging: &crate::config::LoggingSection) -> ManifestLogging {
    ManifestLogging {
        driver: logging.driver.clone(),
        options: logging.options.clone(),
        log_readers: logging.log_readers.clone(),
        access: None,
    }
}

fn convert_service_storage(
    storage: &BTreeMap<String, crate::config::ServiceStorageSection>,
) -> BTreeMap<String, ManifestServiceStorage> {
    storage
        .iter()
        .map(|(name, item)| {
            (
                name.clone(),
                ManifestServiceStorage {
                    disk: item.disk.clone(),
                    base_path: item.base_path.clone(),
                    mount_path: item.mount_path.clone(),
                    read_only: item.access.is_none().then(|| item.read_only()),
                    access: storage_access::canonical_access(&item.access),
                    executable: item.access.is_none().then(|| item.executable()),
                },
            )
        })
        .collect()
}

fn convert_legacy_service_disks(
    disks: &BTreeMap<String, String>,
) -> BTreeMap<String, ManifestServiceStorage> {
    disks
        .iter()
        .map(|(disk, mount_path)| {
            (
                disk.clone(),
                ManifestServiceStorage {
                    disk: disk.clone(),
                    base_path: "/".to_string(),
                    mount_path: mount_path.clone(),
                    read_only: Some(false),
                    executable: Some(false),
                    access: None,
                },
            )
        })
        .collect()
}

fn convert_service_storage_compat(
    storage: &BTreeMap<String, crate::config::ServiceStorageSection>,
    legacy_disks: &BTreeMap<String, String>,
) -> BTreeMap<String, ManifestServiceStorage> {
    if storage.is_empty() {
        convert_legacy_service_disks(legacy_disks)
    } else {
        convert_service_storage(storage)
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
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn operator_preset_expands_canonically_with_explicit_overrides() {
        let base = r#"format = 16
[workload]
name = "app"
version = "v1"
image = "app:latest"
base-image-mode = "blacklist"
allow-operator-cpu-tuning = true
atakit-portal = true
[dependencies.logger]
image = "logger:latest"
[baby-container]
enabled = true
[baby-container.slots.tools]
parent-service = "app"
"#;
        let build = |source: &str| {
            let config = WorkloadConfig::load_from_str(source).unwrap();
            let manifest = super::build_manifest(
                &config,
                TEST_PUBLISHER,
                "app:latest",
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .unwrap();
            serialize_canonical_json(&manifest).unwrap()
        };
        let compiled = build(base);
        let json: serde_json::Value = serde_json::from_str(&compiled).unwrap();
        assert!(json["config"].get("allow-operator-cpu-tuning").is_none());
        for pointer in [
            "/config",
            "/config/dependencies/logger",
            "/config/baby-container/slots/tools",
        ] {
            assert_eq!(
                json.pointer(pointer).unwrap()["cpuset-policy"]["allow-operator"],
                true
            );
            assert_eq!(
                json.pointer(pointer).unwrap()["cpuset-policy"]["allowed-cpus"],
                "online"
            );
        }
        assert_eq!(
            json["config"]["cpu-idle"],
            serde_json::json!({
                "driver": "auto", "governor": null, "disabled-states": [],
                "allow-operator": true, "required": false,
                "allowed-governors": ["haltpoll", "menu", "teo"], "allowed-disabled-states": ["*"]
            })
        );
        for driver in ["intel_idle", "acpi_idle"] {
            let explicit_driver = build(&format!(
                "{base}\n[workload.cpu-idle]\ndriver = '{driver}'\n"
            ));
            let value: serde_json::Value = serde_json::from_str(&explicit_driver).unwrap();
            assert_eq!(value["config"]["cpu-idle"]["driver"], driver);
        }
        let disabled = build(
            &(base.to_string() + "\n[dependencies.logger.cpuset-policy]\nallow-operator = false\n"),
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&disabled).unwrap()["config"]["dependencies"]
                ["logger"]["cpuset-policy"]["allow-operator"],
            false
        );
        let explicit = base.replace("allow-operator-cpu-tuning = true", "")
            + r#"
[workload.cpu-idle]
driver = "auto"
allow-operator = true
required = false
allowed-governors = ["teo", "haltpoll", "menu", "teo"]
allowed-disabled-states = ["*"]
[workload.cpu-frequency]
allow-operator = false
required = false
allowed-governors = []
[workload.cpuset-policy]
allow-operator = true
allowed-cpus = "online"
required = false
[dependencies.logger.cpuset-policy]
allow-operator = true
allowed-cpus = "online"
required = false
[baby-container.slots.tools.cpuset-policy]
allow-operator = true
allowed-cpus = "online"
required = false
"#;
        assert_eq!(compiled, build(&explicit));
        let fixed = build(&(base.to_string() + "\n[workload.cpu-idle]\ngovernor = 'menu'\n"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fixed).unwrap()["config"]["cpu-idle"]
                ["required"],
            true
        );
        let no_macro = build(&base.replace("allow-operator-cpu-tuning = true", ""));
        let no_macro: serde_json::Value = serde_json::from_str(&no_macro).unwrap();
        for pointer in [
            "/config",
            "/config/dependencies/logger",
            "/config/baby-container/slots/tools",
        ] {
            assert!(no_macro
                .pointer(pointer)
                .unwrap()
                .get("cpuset-policy")
                .unwrap()
                .is_null());
        }
    }

    #[test]
    fn nofile_defaults_values_and_equivalent_integers_have_canonical_output() {
        let source = r#"
format = 16
[workload]
name = "app"
version = "v1"
image = "app:latest"
base-image-mode = "blacklist"
atakit-portal = true
[dependencies.logger]
image = "logger:latest"
[baby-container]
enabled = true
[baby-container.slots.tools]
parent-service = "app"
"#;
        let build = |source: &str| -> Result<String, WorkloadError> {
            let config = WorkloadConfig::load_from_str(source)?;
            let manifest = super::build_manifest(
                &config,
                TEST_PUBLISHER,
                "app:latest",
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeMap::new(),
                BTreeMap::new(),
            )?;
            serialize_canonical_json(&manifest)
        };
        let absent = build(source).unwrap();
        let json: serde_json::Value = serde_json::from_str(&absent).unwrap();
        for (section, pointer) in [
            ("workload", "/config/nofile"),
            ("dependencies.logger", "/config/dependencies/logger/nofile"),
            (
                "baby-container.slots.tools",
                "/config/baby-container/slots/tools/nofile",
            ),
        ] {
            assert_eq!(json.pointer(pointer), Some(&serde_json::Value::Null));
            let with = |value: &str| {
                source.replace(
                    &format!("[{section}]"),
                    &format!("[{section}]\nnofile = {value}"),
                )
            };
            let explicit = build(&with("262144")).unwrap();
            assert_ne!(absent, explicit);
            assert_eq!(explicit, build(&with("262_144")).unwrap());
            assert_eq!(explicit, build(&with("0x40000")).unwrap());
            let json: serde_json::Value = serde_json::from_str(&explicit).unwrap();
            assert_eq!(json.pointer(pointer), Some(&serde_json::json!(262144)));
            for bad in ["0", "-1", "1.5", "\"unlimited\"", "9223372036854775807"] {
                assert!(build(&with(bad)).is_err(), "{section}: {bad}");
            }
        }
    }

    #[test]
    fn cpu_controls_are_measured_and_require_format_16() {
        let source = r#"
format = 16
[workload]
name = "app"
version = "v1"
image = "app:latest"
base-image-mode = "blacklist"
atakit-portal = true
cpuset = "0-1"
[workload.cpu-idle]
driver = "intel_idle"
governor = "menu"
disabled-states = ["C6"]
[workload.cpu-frequency]
governor = "performance"
[dependencies.logger]
image = "logger:latest"
cpuset = "0"
[baby-container]
enabled = true
[baby-container.slots.dev]
parent-service = "app"
cpuset = "2-3"
"#;
        let build = |source: &str| {
            let config = WorkloadConfig::load_from_str(source).unwrap();
            super::build_manifest(
                &config,
                TEST_PUBLISHER,
                "app:latest",
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeMap::new(),
                BTreeMap::new(),
            )
        };
        let manifest = build(source).unwrap();
        assert_eq!(manifest.meta.format, 16);
        assert!(manifest.config.cpu_idle.as_ref().unwrap().required);
        assert!(manifest.config.cpu_frequency.as_ref().unwrap().required);
        assert_eq!(manifest.config.cpuset.as_deref(), Some("0,1"));
        assert_eq!(
            manifest.config.dependencies.as_ref().unwrap()["logger"]
                .cpuset
                .as_deref(),
            Some("0")
        );
        assert_eq!(
            manifest.config.baby_container.slots["dev"]
                .cpuset
                .as_deref(),
            Some("2,3")
        );
        let original = serialize_canonical_json(&manifest).unwrap();
        for modified in [
            source.replace("0-1", "1"),
            source.replace("C6", "C1"),
            source.replace("2-3", "3"),
            source.replace("menu", "teo"),
            source.replace("performance", "powersave"),
        ] {
            assert_ne!(
                original,
                serialize_canonical_json(&build(&modified).unwrap()).unwrap()
            );
        }
        assert!(build(&source.replace("format = 16", "format = 15"))
            .unwrap_err()
            .to_string()
            .contains("format = 16"));
    }

    #[test]
    fn baby_log_access_is_in_canonical_manifest() {
        let source = r#"
format = 15
[workload]
name = "app"
version = "v1"
image = "app:latest"
base-image-mode = "blacklist"
atakit-portal = true
[baby-container]
enabled = true
[baby-container.slots.dev]
parent-service = "app"
[baby-container.slots.dev.logging]
access = "none"
"#;
        let config = WorkloadConfig::load_from_str(source).unwrap();
        let manifest = build_manifest(
            &config,
            "app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(manifest.meta.format, crate::BABY_LOG_POLICY_FORMAT_VERSION);
        assert_eq!(
            manifest.config.baby_container.slots["dev"]
                .logging
                .access
                .as_deref(),
            Some("none")
        );
        assert!(serde_json::to_string(&manifest)
            .unwrap()
            .contains("\"access\":\"none\""));
        assert!(manifest.config.logging.access.is_none());
    }

    #[test]
    fn format_14_baby_logging_keeps_legacy_manifest_shape() {
        let source = r#"
format = 14
[workload]
name = "app"
version = "v1"
image = "app:latest"
base-image-mode = "blacklist"
atakit-portal = true
[baby-container]
enabled = true
[baby-container.slots.dev]
parent-service = "app"
[baby-container.slots.dev.logging]
access = "parent"
"#;
        let config = WorkloadConfig::load_from_str(source).unwrap();
        let manifest = build_manifest(
            &config,
            "app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(manifest.meta.format, crate::ACCESS_STORAGE_FORMAT_VERSION);
        let value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(
            value["config"]["baby-container"]["slots"]["dev"]["logging"],
            serde_json::json!({"driver":"k8s-file", "options":{}, "log-readers":[]})
        );
    }

    /// Fixed publisher for tests that are not about the publisher itself, so
    /// every manifest they build is identified consistently.
    const TEST_PUBLISHER: &str =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[allow(clippy::too_many_arguments)]
    fn build_manifest(
        config: &WorkloadConfig,
        resolved_image: &str,
        environment: BTreeMap<String, String>,
        dep_environments: BTreeMap<String, BTreeMap<String, String>>,
        hashes: BTreeMap<String, String>,
        unmeasured_data: BTreeSet<String>,
        unmeasured_env_files: BTreeMap<String, Vec<String>>,
        images: BTreeMap<String, ManifestImage>,
    ) -> Manifest {
        super::build_manifest(
            config,
            TEST_PUBLISHER,
            resolved_image,
            environment,
            dep_environments,
            hashes,
            unmeasured_data,
            unmeasured_env_files,
            images,
        )
        .expect("valid test manifest")
    }

    #[test]
    fn executable_storage_is_opt_in_and_measured_for_all_mount_owners() {
        let source = r#"
format = 13
[workload]
name = "app"
version = "v1"
image = "app:latest"
base-image-mode = "blacklist"
[workload.storage.app]
disk = "data"
base-path = "/app"
mount-path = "/app"
[dependencies.helper]
image = "helper:latest"
[dependencies.helper.storage.app]
disk = "data"
base-path = "/app"
mount-path = "/app"
[baby-container]
enabled = true
[baby-container.slots.dev]
parent-service = "app"
[baby-container.slots.dev.storage.app]
disk = "data"
base-path = "/baby"
mount-path = "/app"
"#;
        let build = |cfg: &WorkloadConfig| {
            build_manifest(
                cfg,
                "app:latest",
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeMap::new(),
                BTreeMap::new(),
            )
        };
        let cfg: WorkloadConfig = toml::from_str(source).unwrap();
        let baseline = serde_json::to_value(build(&cfg)).unwrap();
        assert_eq!(baseline["meta"]["format"], 13);
        for path in [
            "/config/storage/app/executable",
            "/config/dependencies/helper/storage/app/executable",
            "/config/baby-container/slots/dev/storage/app/executable",
        ] {
            assert_eq!(baseline.pointer(path), Some(&serde_json::json!(false)));
        }
        for owner in 0..3 {
            let mut cfg: WorkloadConfig = toml::from_str(source).unwrap();
            match owner {
                0 => cfg.workload.storage.get_mut("app").unwrap().executable = Some(true),
                1 => {
                    cfg.dependencies
                        .get_mut("helper")
                        .unwrap()
                        .storage
                        .get_mut("app")
                        .unwrap()
                        .executable = Some(true)
                }
                _ => {
                    cfg.baby_container
                        .as_mut()
                        .unwrap()
                        .slots
                        .get_mut("dev")
                        .unwrap()
                        .storage
                        .get_mut("app")
                        .unwrap()
                        .executable = Some(true)
                }
            }
            let manifest = build(&cfg);
            assert_eq!(
                manifest.meta.format,
                crate::EXECUTABLE_STORAGE_FORMAT_VERSION
            );
            let json = serde_json::to_value(&manifest).unwrap();
            let storage = match owner {
                0 => &json["config"]["storage"]["app"],
                1 => &json["config"]["dependencies"]["helper"]["storage"]["app"],
                _ => &json["config"]["baby-container"]["slots"]["dev"]["storage"]["app"],
            };
            assert_eq!(storage["executable"], true);
            assert_ne!(json, baseline);
            let decoded: Manifest = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), json);
        }
        // Format 14 writes only canonical access lists for every mount owner.
        let source14 = source.replace("format = 13", "format = 14").replace(
            "mount-path = \"/app\"",
            "mount-path = \"/app\"\naccess = [\"execute\", \"read\", \"write\"]",
        );
        let cfg14: WorkloadConfig = toml::from_str(&source14).unwrap();
        let json14 = serde_json::to_value(build(&cfg14)).unwrap();
        assert_eq!(json14["meta"]["format"], 14);
        for path in [
            "/config/storage/app",
            "/config/dependencies/helper/storage/app",
            "/config/baby-container/slots/dev/storage/app",
        ] {
            let mount = json14.pointer(path).unwrap();
            assert_eq!(
                mount["access"],
                serde_json::json!(["read", "write", "execute"])
            );
            for old in ["read_only", "executable", "permissions"] {
                assert!(mount.get(old).is_none());
            }
        }
        let reordered: WorkloadConfig = toml::from_str(&source14.replace(
            "[\"execute\", \"read\", \"write\"]",
            "[\"write\", \"execute\", \"read\"]",
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(build(&reordered)).unwrap(), json14);
        let no_exec: WorkloadConfig =
            toml::from_str(&source14.replace("\"execute\", ", "")).unwrap();
        assert_ne!(serde_json::to_value(build(&no_exec)).unwrap(), json14);
        assert!(toml::from_str::<crate::config::ServiceStorageSection>(
            "disk='d'\nbase-path='/'\nmount-path='/d'\nexecutable='true'"
        )
        .is_err());
    }

    #[test]
    fn strip_dot_slash_works() {
        assert_eq!(strip_dot_slash("./config/hello"), "config/hello");
        assert_eq!(strip_dot_slash("./config/"), "config");
        assert_eq!(strip_dot_slash("config/hello"), "config/hello");
        assert_eq!(strip_dot_slash("config/"), "config");
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
    fn unmeasured_env_file_names_are_sorted_and_values_are_ignored() {
        let path = Path::new("runtime.env");
        let first = parse_unmeasured_env_file_names(path, "ZED=one\nALPHA=two\n").unwrap();
        let second =
            parse_unmeasured_env_file_names(path, "ZED=changed\nALPHA=also-changed\n").unwrap();
        assert_eq!(first, vec!["ALPHA", "ZED"]);
        assert_eq!(first, second);
    }

    #[test]
    fn unmeasured_env_file_names_reject_duplicates_invalid_and_reserved_names() {
        let path = Path::new("runtime.env");
        for content in [
            "TOKEN=one\nTOKEN=two\n",
            "BAD-NAME=value\n",
            "ATAKIT_PUBLIC_IP=value\n",
            "VERIFIERD_PORTAL_ALLOWED_PORTS=[2024]\n",
        ] {
            assert!(parse_unmeasured_env_file_names(path, content).is_err());
        }
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
    fn measured_environment_sources_allow_verifierd_names() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join("verifierd.env");
        std::fs::write(
            &env_path,
            "VERIFIERD_RPC_URL=https://rpc.example\nVERIFIERD_CHAIN_ID=560048\n",
        )
        .unwrap();

        let env_file = Some(StringOrArray::Single("verifierd.env".into()));
        let explicit = BTreeMap::from([
            ("VERIFIERD_TRUST_MODE".into(), "chain".into()),
            ("VERIFIERD_CHAIN_ID".into(), "1".into()),
        ]);

        let result = resolve_environment(&env_file, &explicit, tmp.path()).unwrap();
        assert_eq!(result["VERIFIERD_RPC_URL"], "https://rpc.example");
        assert_eq!(result["VERIFIERD_TRUST_MODE"], "chain");
        assert_eq!(result["VERIFIERD_CHAIN_ID"], "1");
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
            BTreeSet::new(),
            BTreeMap::new(),
            images,
        );

        let output = serialize_canonical_json(&manifest).unwrap();
        // Canonical JSON: verify key fields are present
        assert!(output.contains("\"format\":11"));
        // The publisher is measured: it is part of the canonical bytes PCR23
        // covers, not metadata carried alongside them.
        assert!(output.contains(&format!("\"publisher\":\"{TEST_PUBLISHER}\"")));
        assert!(output.contains("\"attributes\":{}"));
        assert!(output.contains("\"name\":\"my-app\""));
        assert!(output.contains("\"version\":\"v0.0.1\""));
        assert!(output.contains("\"image\":\"my-app:latest\""));
        assert!(output.contains("\"depends_on\":[]"));
        assert!(output.contains("images/my-app.tar"));
        // gid-group defaults to workload name
        assert!(output.contains("\"gid-group\":\"my-app\""));
        // measured-data and unmeasured-data are selective path arrays.
        assert!(output.contains("\"measured-data\":[]"));
        assert!(output.contains("\"unmeasured-data\":[]"));
        // top-level unmeasured-data path list is always emitted (empty here)
        assert!(output.contains("\"unmeasured-data\":[]"));
        // session-ttl defaults to 0
        assert!(output.contains("\"session-ttl\":0"));
        // images section is present and surfaces image-id
        assert!(output.contains("\"images\":"));
        assert!(output.contains("\"image-id\":\"sha256:def456\""));
    }

    #[test]
    fn materializes_optional_readiness_for_workload_and_dependencies() {
        let config = WorkloadConfig::load_from_str(
            r#"
format = 9
[workload]
name="api"
version="v1"
base-image-mode="blacklist"
image="api:latest"
depends_on=["db"]
[workload.readiness]
command=["/app/check"]
interval-seconds=1
attempt-timeout-seconds=2
deadline-seconds=10
[dependencies.db]
image="db:latest"
[dependencies.db.readiness]
command=["/app/db-check","a b","$HOME"]
interval-seconds=2
attempt-timeout-seconds=3
deadline-seconds=20
"#,
        )
        .unwrap();
        let manifest = build_manifest(
            &config,
            "api:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(manifest.config.readiness, config.workload.readiness);
        assert_eq!(
            manifest.config.dependencies.as_ref().unwrap()["db"].readiness,
            config.dependencies["db"].readiness
        );
        let output = serde_json::to_value(manifest).unwrap();
        assert_eq!(output["meta"]["format"], crate::FORMAT_VERSION);
        assert_eq!(
            output["config"]["dependencies"]["db"]["readiness"]["command"],
            serde_json::json!(["/app/db-check", "a b", "$HOME"])
        );
    }

    #[test]
    fn materializes_workload_depends_on() {
        let config = WorkloadConfig::load_from_str(
            r#"
format = 8

[workload]
name = "api"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "api:latest"
depends_on = ["db"]

[dependencies.db]
image = "postgres:17"
"#,
        )
        .unwrap();

        let manifest = build_manifest(
            &config,
            "api:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        assert_eq!(manifest.meta.format, crate::FORMAT_VERSION);
        assert_eq!(manifest.config.depends_on, vec!["db"]);
        assert_eq!(
            manifest.config.dependencies.unwrap()["db"].depends_on,
            Vec::<String>::new()
        );
    }

    #[test]
    fn attributes_are_canonical_and_change_manifest_measurement_bytes() {
        let config = |values: &str| {
            WorkloadConfig::load_from_str(&format!(
                r#"
format = 6

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"

[workload.attributes]
"atakit.attestation.v1.tee.intel-tdx.debug.enabled" = {values}
"#
            ))
            .unwrap()
        };
        let build = |config: &WorkloadConfig| {
            build_manifest(
                config,
                "my-app:latest",
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeMap::new(),
                BTreeMap::new(),
            )
        };

        let false_only = serialize_canonical_json(&build(&config("[false]"))).unwrap();
        let false_or_true = serialize_canonical_json(&build(&config("[false, true]"))).unwrap();

        assert!(false_only.contains(
            "\"attributes\":{\"atakit.attestation.v1.tee.intel-tdx.debug.enabled\":[false]}"
        ));
        assert_ne!(false_only, false_or_true);
        assert_eq!(
            false_only,
            serialize_canonical_json(&build(&config("[false]"))).unwrap()
        );
    }

    fn minimal_config() -> WorkloadConfig {
        WorkloadConfig::load_from_str(
            r#"
format = 8

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
"#,
        )
        .unwrap()
    }

    fn build_with_publisher(publisher: &str) -> Result<Manifest, WorkloadError> {
        super::build_manifest(
            &minimal_config(),
            publisher,
            "my-app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        )
    }

    /// The publisher is part of the workload's identity, so it has to be part of
    /// what PCR23 covers. If it were carried outside the measured bytes, an
    /// operator could run one publisher's workload and attest another's
    /// identity.
    #[test]
    fn publisher_changes_the_measured_bytes() {
        let a = serialize_canonical_json(
            &build_with_publisher(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
        )
        .unwrap();
        let b = serialize_canonical_json(
            &build_with_publisher(
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
        )
        .unwrap();

        assert_ne!(
            a, b,
            "two publishers must not produce the same measured manifest"
        );
    }

    /// A malformed publisher would be measured and would derive an identifier
    /// registered to nobody, so it is refused at the build boundary rather than
    /// written into an archive.
    #[test]
    fn build_manifest_rejects_a_malformed_publisher() {
        for bad in [
            "",
            "automata",
            "0xNOTHEX",
            // Correct length, but uppercase: two spellings of one identifier
            // would compare unequal.
            "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            // Missing the 0x prefix.
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let error = build_with_publisher(bad)
                .expect_err(&format!("expected publisher '{bad}' to be refused"));
            assert!(
                error.to_string().contains("publisher must be"),
                "unexpected error for '{bad}': {error}"
            );
        }
    }

    #[test]
    fn build_manifest_returns_invalid_attribute_error() {
        let config = WorkloadConfig::load_from_str(
            r#"
format = 6

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"

[workload.attributes]
"atakit.attestation.v1.tee.intel-tdx.debug.enabled" = [true]
"#,
        )
        .unwrap();

        let error = super::build_manifest(
            &config,
            TEST_PUBLISHER,
            "my-app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("must be [false] or [false, true]"));
    }

    #[test]
    fn format_2_legacy_service_disks_compile_to_manifest_storage() {
        let toml_str = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "app:latest"

[workload.disks]
data = "/data"

[dependencies.sidecar]
image = "redis:7"

[dependencies.sidecar.disks]
cache = "/cache"

[disks.data]
size = "10GB"
encryption = { unlock_method = [], bind = [] }

[disks.cache]
size = "10GB"
encryption = { unlock_method = [], bind = [] }
"#;
        let cfg: WorkloadConfig = toml::from_str(toml_str).unwrap();
        let manifest = build_manifest(
            &cfg,
            "app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        let workload_storage = &manifest.config.storage["data"];
        assert_eq!(workload_storage.disk, "data");
        assert_eq!(workload_storage.base_path, "/");
        assert_eq!(workload_storage.mount_path, "/data");
        assert!(!workload_storage.read_only());

        let sidecar_storage = &manifest.config.dependencies.unwrap()["sidecar"].storage["cache"];
        assert_eq!(sidecar_storage.disk, "cache");
        assert_eq!(sidecar_storage.base_path, "/");
        assert_eq!(sidecar_storage.mount_path, "/cache");
        assert!(!sidecar_storage.read_only());
    }

    #[test]
    fn unmeasured_env_files_are_normalized_into_manifest() {
        let toml_str = r#"
format = 2

[package]
unmeasured-data = ["/secrets/runtime.env"]

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
unmeasured-env-file = ["/secrets/runtime.env"]
"#;
        let cfg = WorkloadConfig::load_from_str(toml_str).unwrap();
        let manifest = build_manifest(
            &cfg,
            "my-app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::from(["unmeasured-data/secrets/runtime.env".to_string()]),
            BTreeMap::from([(
                "unmeasured-data/secrets/runtime.env".to_string(),
                vec!["API_TOKEN".to_string()],
            )]),
            BTreeMap::new(),
        );
        assert_eq!(
            manifest.config.unmeasured_env_files,
            vec!["unmeasured-data/secrets/runtime.env"]
        );
        assert_eq!(
            manifest.unmeasured_env_files,
            BTreeMap::from([(
                "unmeasured-data/secrets/runtime.env".to_string(),
                vec!["API_TOKEN".to_string()],
            )])
        );
    }

    #[test]
    fn service_data_arrays_expand_against_declared_sets() {
        let toml_str = r#"
format = 4

[package]
measured-data = ["/config/a.txt", "/config/b.txt"]
unmeasured-data = ["/runtime/a.env", "/runtime/b.env"]

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
measured-data = ["/config/a.txt"]
unmeasured-data = ["/runtime/"]

[dependencies.helper]
image = "helper:latest"
measured-data = true
unmeasured-data = false
"#;
        let cfg = WorkloadConfig::load_from_str(toml_str).unwrap();
        let mut hashes = BTreeMap::new();
        hashes.insert("measured-data/config/a.txt".into(), "sha256:aaa".into());
        hashes.insert("measured-data/config/b.txt".into(), "sha256:bbb".into());
        let unmeasured_data = BTreeSet::from([
            "unmeasured-data/runtime/a.env".to_string(),
            "unmeasured-data/runtime/b.env".to_string(),
        ]);

        let manifest = build_manifest(
            &cfg,
            "my-app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            hashes,
            unmeasured_data,
            BTreeMap::new(),
            BTreeMap::new(),
        );

        assert_eq!(
            manifest.config.measured_data,
            ManifestDataMount::Paths(vec!["measured-data/config/a.txt".to_string()])
        );
        assert_eq!(
            manifest.config.unmeasured_data,
            ManifestDataMount::Paths(vec![
                "unmeasured-data/runtime/a.env".to_string(),
                "unmeasured-data/runtime/b.env".to_string(),
            ])
        );
        let helper = manifest
            .config
            .dependencies
            .as_ref()
            .unwrap()
            .get("helper")
            .unwrap();
        assert_eq!(
            helper.measured_data,
            ManifestDataMount::Paths(vec![
                "measured-data/config/a.txt".to_string(),
                "measured-data/config/b.txt".to_string(),
            ])
        );
        assert_eq!(helper.unmeasured_data, ManifestDataMount::Paths(vec![]));
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
            BTreeSet::new(),
            BTreeMap::new(),
            images.clone(),
        );
        let m2 = build_manifest(
            &cfg,
            "test:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            hashes,
            BTreeSet::new(),
            BTreeMap::new(),
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
            BTreeSet::new(),
            BTreeMap::new(),
            images.clone(),
        );
        let m2 = build_manifest(
            &cfg,
            "main:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            hashes,
            BTreeSet::new(),
            BTreeMap::new(),
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
            BTreeSet::new(),
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
            BTreeSet::new(),
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
    fn disk_integrity_is_measured_and_requires_format_12() {
        for integrity in ["", ", integrity = \"hmac-sha256\""] {
            let source = format!(
                r#"
format = 2
[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "app:latest"
[disks.data]
index = 10
size = "10GB"
encryption = {{ unlock_method = ["tpm"], bind = ["baseimage", "workload"]{integrity} }}
"#
            );
            let cfg: WorkloadConfig = toml::from_str(&source).unwrap();
            let manifest = build_manifest(
                &cfg,
                "app:latest",
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeMap::new(),
                BTreeMap::new(),
            );
            assert_eq!(
                manifest.meta.format,
                if integrity.is_empty() { 11 } else { 12 }
            );
            let json = serialize_canonical_json(&manifest).unwrap();
            assert_eq!(json.contains("hmac-sha256"), !integrity.is_empty());
            assert_eq!(json.contains("integrity"), !integrity.is_empty());
        }
    }

    #[test]
    fn disk_encryption_empty_arrays_serialize_to_canonical_shape() {
        // A disk with an explicit empty encryption block must serialise as
        // `{"bind":[],"unlock_method":[]}` — the "no encryption" commitment
        // that contributes to PCR23.
        let toml_str = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "app:latest"

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = [], bind = [] }
"#;
        let cfg: WorkloadConfig = toml::from_str(toml_str).unwrap();
        let manifest = build_manifest(
            &cfg,
            "app:latest",
            BTreeMap::new(), // environment
            BTreeMap::new(), // dep_environments
            BTreeMap::new(), // hashes
            BTreeSet::new(), // unmeasured_data
            BTreeMap::new(), // unmeasured_env_files
            BTreeMap::new(), // images
        );
        let json = serialize_canonical_json(&manifest).unwrap();
        assert!(
            json.contains("\"encryption\":{\"bind\":[],\"unlock_method\":[]}"),
            "expected empty encryption block in canonical JSON, got: {json}"
        );
    }

    #[test]
    fn disk_without_encryption_block_is_rejected_at_parse() {
        // Omitting the `encryption` block on a declared disk must be a
        // parse error. Absence of encryption must always be an explicit
        // `encryption = { unlock_method = [], bind = [] }`.
        let toml_str = r#"
format = 2

[workload]
name = "app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "app:latest"

[disks.data]
index = 10
size = "10GB"
"#;
        let err = toml::from_str::<WorkloadConfig>(toml_str).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("encryption"),
            "expected missing-field error mentioning encryption, got: {msg}"
        );
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
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let m_b = build_manifest(
            &cfg_b,
            "app:latest",
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        let j_a = serialize_canonical_json(&m_a).unwrap();
        let j_b = serialize_canonical_json(&m_b).unwrap();
        assert_ne!(j_a, j_b, "cap-add must change the canonical JSON bytes");
    }

    #[test]
    fn unmeasured_declarations_do_not_infer_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("no-source");
        assert_eq!(
            normalize_unmeasured_data(&["/config/key".into()], &absent).unwrap(),
            BTreeSet::from(["unmeasured-data/config/key".into()])
        );
        assert!(normalize_unmeasured_data(&["/config/".into()], &absent).is_err());
        std::fs::create_dir(tmp.path().join("config")).unwrap();
        let error = normalize_unmeasured_data(&["/config".into()], tmp.path()).unwrap_err();
        assert!(error.to_string().contains("trailing '/'"));
        assert!(normalize_unmeasured_data(&["/config/".into()], tmp.path())
            .unwrap()
            .is_empty());
        std::fs::write(tmp.path().join("file"), "placeholder").unwrap();
        assert!(normalize_unmeasured_data(&["/file/".into()], tmp.path()).is_err());
    }

    #[test]
    fn unmeasured_enumeration_rejects_links_instead_of_following_cycles() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("config")).unwrap();
        std::os::unix::fs::symlink(".", tmp.path().join("config/loop")).unwrap();
        assert!(normalize_unmeasured_data(&["/config/".into()], tmp.path())
            .unwrap_err()
            .to_string()
            .contains("links"));
    }

    #[test]
    fn unmeasured_selectors_distinguish_files_and_directories() {
        assert!(data_selector_matches(
            "unmeasured-data",
            "/config/",
            "unmeasured-data/config/key"
        ));
        assert!(!data_selector_matches(
            "unmeasured-data",
            "/config",
            "unmeasured-data/config/key"
        ));
        assert!(!data_selector_matches(
            "unmeasured-data",
            "/config/",
            "unmeasured-data/config"
        ));
        assert!(data_selector_matches(
            "unmeasured-data",
            "/config/key",
            "unmeasured-data/config/key"
        ));
    }

    #[test]
    fn unmeasured_data_leaf_and_missing_paths() {
        let tmp = tempfile::tempdir().unwrap();
        // A file that exists, plus a path that does not exist at build time.
        std::fs::write(tmp.path().join("present.bin"), "x").unwrap();
        let paths = vec!["/present.bin".to_string(), "/secrets/api_key".to_string()];
        let out: Vec<String> = normalize_unmeasured_data(&paths, tmp.path())
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(
            out,
            vec![
                "unmeasured-data/present.bin".to_string(),
                "unmeasured-data/secrets/api_key".to_string(),
            ]
        );
    }

    #[test]
    fn unmeasured_data_directory_expands_to_member_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("config");
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        std::fs::write(dir.join("b"), "b").unwrap();
        std::fs::write(dir.join("a"), "a").unwrap();
        std::fs::write(dir.join("nested/c"), "c").unwrap();

        // Declaring the directory expands to its sorted member files...
        let from_dir = normalize_unmeasured_data(&["/config/".to_string()], tmp.path()).unwrap();
        assert_eq!(
            from_dir.iter().cloned().collect::<Vec<_>>(),
            vec![
                "unmeasured-data/config/a".to_string(),
                "unmeasured-data/config/b".to_string(),
                "unmeasured-data/config/nested/c".to_string(),
            ]
        );

        // ...and declaring the member files explicitly yields the identical set
        // (the determinism property the boolean refactor lost).
        let from_files = normalize_unmeasured_data(
            &[
                "/config/nested/c".to_string(),
                "/config/a".to_string(),
                "/config/b".to_string(),
            ],
            tmp.path(),
        )
        .unwrap();
        assert_eq!(from_dir, from_files);
    }

    #[test]
    fn measured_data_directory_with_trailing_slash_expands_without_double_slash() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("config");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.conf"), "x").unwrap();

        let from_dir = normalize_measured_data(&["/config/".to_string()], tmp.path());
        assert_eq!(
            from_dir.iter().cloned().collect::<Vec<_>>(),
            vec!["measured-data/config/app.conf".to_string()]
        );
    }

    #[test]
    fn root_data_directories_expand_without_double_slash() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("root.txt"), "x").unwrap();

        let measured = normalize_measured_data(&["/".to_string()], tmp.path());
        assert_eq!(
            measured.iter().cloned().collect::<Vec<_>>(),
            vec!["measured-data/root.txt".to_string()]
        );

        let unmeasured = normalize_unmeasured_data(&["/".to_string()], tmp.path()).unwrap();
        assert_eq!(
            unmeasured.iter().cloned().collect::<Vec<_>>(),
            vec!["unmeasured-data/root.txt".to_string()]
        );
    }
}

fn storage_execution_disabled(value: &Option<bool>) -> bool {
    storage_access::execution_disabled(value)
}
