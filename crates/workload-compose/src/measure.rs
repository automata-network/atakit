//! Workload measurement for PCR23 extension.
//!
//! This module measures a workload folder containing:
//! - `manifest.json` - workload package manifest (required)
//! - `docker-compose.yml` - container definitions
//! - mounted files referenced by the compose file
//!
//! It generates:
//! 1. Isolated docker-compose YAML per service
//! 2. keccak256 hashes of all mounted files
//! 3. Validates no files are unused (except ignored)
//!
//! IMPORTANT: All outputs are deterministic - services are processed in
//! docker-compose file order, and files within directories are sorted.
//!
//! The measure function automatically skips:
//! - manifest.json itself
//! - Docker image tars referenced in manifest.json (docker_images[].image_tar)
//! - Additional data files listed in manifest.json (additional_data_files)
//! - Any files in config.skip_files

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use alloy::primitives::{B256, keccak256};
use anyhow::{Context, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;
use walkdir::WalkDir;

use crate::serialize::service_to_yaml;
use crate::types::{WorkloadCompose, WorkloadService, WorkloadVolumeMount};
use crate::{WorkloadManifest, from_yaml_str, validate_normalized};

/// Configuration for workload measurement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MeasureConfig {
    /// Additional files to skip during measurement (relative paths from workload folder).
    /// Note: manifest.json, image tars, and additional_data_files from manifest are auto-skipped.
    pub skip_files: HashSet<String>,
    /// Image digest per service: service_name -> "sha256:..."
    pub image_digests: IndexMap<String, String>,
}

impl MeasureConfig {
    pub fn cvm() -> Self {
        // Build config - skip_files for image tars and additional_data_files are auto-handled
        // by workload_compose::measure based on manifest.json
        let mut skip_files = HashSet::new();
        // Only need to skip CVM agent config files (not in manifest)
        skip_files.insert("config/cvm_agent/cvm_agent_policy.json".to_string());
        skip_files.insert("config/cvm_agent/sample_image_verify_policy.json".to_string());

        Self {
            skip_files,
            image_digests: IndexMap::new(),
        }
    }
}

/// Result of measuring a workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadMeasurement {
    /// Raw manifest.json content.
    pub manifest: String,
    /// Measurement results for each service.
    pub services: Vec<ServiceMeasurement>,
}

impl WorkloadMeasurement {
    /// Generate measurement events as SHA256 hashes.
    ///
    /// Returns a list of B256 hashes:
    /// 1. First element: SHA256 of the raw manifest.json content
    /// 2. Remaining elements: SHA256 of each service measurement (serialized as JSON)
    pub fn events(&self) -> Vec<B256> {
        let mut events = Vec::with_capacity(1 + self.services.len());

        // SHA256 of manifest
        let manifest_hash = Sha256::digest(self.manifest.as_bytes());
        events.push(B256::from_slice(&manifest_hash));

        // SHA256 of each service measurement (serialized as JSON)
        for service in &self.services {
            let json = serde_json::to_vec(service).expect("ServiceMeasurement serialization");
            let hash = Sha256::digest(&json);
            events.push(B256::from_slice(&hash));
        }

        events
    }

    /// Compute the PCR value by extending from zero with each event.
    ///
    /// PCR extension: new_pcr = SHA256(current_pcr || event)
    /// Starting from PCR = 0x00...00 (32 bytes of zeros)
    pub fn pcr_value(&self) -> B256 {
        let mut pcr = B256::ZERO;

        for event in self.events() {
            // PCR extension: new_pcr = SHA256(pcr || event)
            let mut hasher = Sha256::new();
            hasher.update(pcr.as_slice());
            hasher.update(event.as_slice());
            pcr = B256::from_slice(&hasher.finalize());
        }

        pcr
    }
}

/// Result of measuring a single container/service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceMeasurement {
    /// Service name from docker-compose.
    pub service_name: String,
    /// Isolated docker-compose YAML for this container only.
    pub docker_compose: String,
    /// Image digest from config (e.g., "sha256:abc123...").
    pub image_digest: String,
    /// Files measured: bind mounts + env_files, with keccak256 hashes.
    pub mount_files: Vec<MountedFile>,
    /// Named volumes used by this container.
    pub volumes: Vec<String>,
}

/// A file that is mounted into a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MountedFile {
    /// Path relative to workload folder.
    pub path: String,
    /// keccak256 hash of file content.
    pub hash: B256,
}

/// Errors that can occur during measurement.
#[derive(Debug, Error)]
pub enum MeasureError {
    #[error("Failed to read manifest.json: {0}")]
    ReadManifest(#[source] std::io::Error),

    #[error("Failed to parse manifest.json: {0}")]
    ParseManifest(#[source] anyhow::Error),

    #[error("Failed to read compose file: {0}")]
    ReadCompose(#[source] std::io::Error),

    #[error("Failed to parse compose file: {0}")]
    ParseCompose(#[source] anyhow::Error),

    #[error("Failed to validate compose file: {0}")]
    ValidateCompose(#[source] anyhow::Error),

    #[error("Service '{service}' is missing image digest in config")]
    MissingImageDigest { service: String },

    #[error("Service '{service}' has invalid image digest '{digest}': must start with 'sha256:'")]
    InvalidImageDigest { service: String, digest: String },

    #[error("Failed to read file '{path}': {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to generate isolated compose for service '{service}': {source}")]
    GenerateCompose {
        service: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to walk directory '{path}': {source}")]
    WalkDir {
        path: String,
        #[source]
        source: walkdir::Error,
    },

    #[error("Unused files in workload folder (not referenced by compose or skip_files): {files:?}")]
    UnusedFiles { files: Vec<String> },
}

/// Extract the image digest from a docker save tar file.
///
/// Reads the OCI image index (index.json) directly from the tar without full extraction.
/// For multi-platform images, selects the linux/amd64 manifest.
///
/// The index.json format:
/// ```json
/// {
///   "schemaVersion": 2,
///   "mediaType": "application/vnd.oci.image.index.v1+json",
///   "manifests": [
///     {
///       "mediaType": "application/vnd.oci.image.manifest.v1+json",
///       "digest": "sha256:...",
///       "size": 555,
///       "platform": { "architecture": "amd64", "os": "linux" }
///     }
///   ]
/// }
/// ```
pub fn get_digest_from_docker_tar(tar_path: &Path) -> anyhow::Result<String> {
    let file =
        File::open(tar_path).with_context(|| format!("Failed to open {}", tar_path.display()))?;
    let mut archive = Archive::new(file);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        if path.to_string_lossy() == "index.json" {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;

            let index: OciImageIndex =
                serde_json::from_str(&content).with_context(|| "Failed to parse OCI index.json")?;

            return select_manifest_digest(&index, tar_path);
        }
    }

    bail!("index.json not found in docker tar: {}", tar_path.display())
}

/// Select the appropriate manifest digest from an OCI image index.
/// Prefers linux/amd64 for multi-platform images.
fn select_manifest_digest(index: &OciImageIndex, tar_path: &Path) -> anyhow::Result<String> {
    if index.manifests.is_empty() {
        bail!("OCI index has no manifests: {}", tar_path.display());
    }

    // If only one manifest, use it
    if index.manifests.len() == 1 {
        return Ok(index.manifests[0].digest.clone());
    }

    // For multi-platform images, find linux/amd64
    for manifest in &index.manifests {
        if let Some(platform) = &manifest.platform {
            if platform.os == "linux" && platform.architecture == "amd64" {
                return Ok(manifest.digest.clone());
            }
        }
    }

    // Fallback: check annotations for platform info or use first manifest
    for manifest in &index.manifests {
        if let Some(annotations) = &manifest.annotations {
            // Some images use annotations instead of platform field
            if let Some(ref_name) = annotations.get("org.opencontainers.image.ref.name") {
                if ref_name.contains("amd64") || ref_name.contains("linux") {
                    return Ok(manifest.digest.clone());
                }
            }
        }
    }

    // Last resort: use first manifest
    Ok(index.manifests[0].digest.clone())
}

// ---------------------------------------------------------------------------
// OCI Image Index types for docker tar parsing
// ---------------------------------------------------------------------------

/// OCI Image Index (index.json)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciImageIndex {
    #[allow(dead_code)]
    schema_version: u32,
    manifests: Vec<OciManifestDescriptor>,
}

/// OCI Manifest Descriptor
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciManifestDescriptor {
    digest: String,
    #[allow(dead_code)]
    size: u64,
    #[serde(default)]
    platform: Option<OciPlatform>,
    #[serde(default)]
    annotations: Option<HashMap<String, String>>,
}

/// OCI Platform specification
#[derive(Debug, Deserialize)]
struct OciPlatform {
    architecture: String,
    os: String,
}

/// Measure a workload folder and return measurement results.
///
/// # Arguments
///
/// * `workload_folder` - Path to the folder containing manifest.json, docker-compose.yml and mounted files
/// * `compose_file` - Name of the compose file (e.g., "docker-compose.yml")
/// * `config` - Configuration including skip_files and image_digests
///
/// # Returns
///
/// A `WorkloadMeasurement` containing the manifest and per-service measurements.
/// Services are in the same order as they appear in the docker-compose file.
///
/// # Auto-skipped files
///
/// The following files are automatically skipped (not required in skip_files):
/// - `manifest.json`
/// - Docker image tars from `manifest.docker_images[].image_tar`
/// - Files listed in `manifest.additional_data_files`
pub fn measure(
    workload_folder: &Path,
    compose_file: &str,
    config: &MeasureConfig,
) -> Result<WorkloadMeasurement, MeasureError> {
    // 1. Read and parse manifest.json (required)
    let manifest_path = workload_folder.join("manifest.json");
    let manifest = WorkloadManifest::from_file(&manifest_path).map_err(|e| {
        MeasureError::ParseManifest(anyhow::anyhow!("Failed to load manifest.json: {e:#}"))
    })?;
    let manifest_content =
        std::fs::read_to_string(&manifest_path).map_err(MeasureError::ReadManifest)?;

    // 2. Read and parse the docker-compose file
    let compose_path = workload_folder.join(compose_file);
    let compose_content =
        std::fs::read_to_string(&compose_path).map_err(MeasureError::ReadCompose)?;
    let compose = from_yaml_str(&compose_content).map_err(MeasureError::ParseCompose)?;

    validate_normalized(&compose_content).map_err(MeasureError::ValidateCompose)?;

    // 3. Enumerate all files in the workload folder
    let all_files = enumerate_files(workload_folder)?;

    // 4. Track which files are used
    let mut used_files: HashSet<String> = HashSet::new();

    // The compose file and manifest are used
    used_files.insert(compose_file.to_string());
    used_files.insert("manifest.json".to_string());

    // Auto-skip docker image tars from manifest
    for img in &manifest.docker_images {
        if let Some(tar_name) = &img.image_tar {
            used_files.insert(tar_name.clone());
        }
    }

    // Auto-skip additional data files from manifest
    for file in &manifest.additional_data_files {
        used_files.insert(file.clone());
    }

    // Add user-provided skip_files to used set
    for skip in &config.skip_files {
        used_files.insert(normalize_path(skip));
    }

    // 5. Process each service (IndexMap preserves insertion order from YAML parsing)
    let mut services = Vec::new();

    for (service_name, service) in &compose.services {
        let measurement = measure_service(
            workload_folder,
            service_name,
            service,
            &compose,
            config,
            &mut used_files,
        )?;
        services.push(measurement);
    }

    // 6. Validate all files are used
    let mut unused: Vec<String> = all_files
        .iter()
        .filter(|f| !used_files.contains(*f))
        .cloned()
        .collect();
    // Sort for deterministic error messages
    unused.sort();

    if !unused.is_empty() {
        return Err(MeasureError::UnusedFiles { files: unused });
    }

    Ok(WorkloadMeasurement {
        manifest: manifest_content,
        services,
    })
}

/// Measure a single service.
fn measure_service(
    workload_folder: &Path,
    service_name: &str,
    service: &WorkloadService,
    compose: &WorkloadCompose,
    config: &MeasureConfig,
    used_files: &mut HashSet<String>,
) -> Result<ServiceMeasurement, MeasureError> {
    // Get image digest from config - must start with "sha256:", then strip prefix
    let raw_digest =
        config
            .image_digests
            .get(service_name)
            .ok_or_else(|| MeasureError::MissingImageDigest {
                service: service_name.to_string(),
            })?;
    let image_digest = raw_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| MeasureError::InvalidImageDigest {
            service: service_name.to_string(),
            digest: raw_digest.clone(),
        })?
        .to_string();

    // Collect files to measure and named volumes
    let mut mount_files = Vec::new();
    let mut volumes = Vec::new();

    // Process bind mounts (in order from docker-compose)
    for vol in &service.volumes {
        match vol {
            WorkloadVolumeMount::Bind { host_path, .. } => {
                let normalized = normalize_path(host_path);
                let abs_path = workload_folder.join(&normalized);

                if abs_path.is_file() {
                    // Single file mount
                    let hash = hash_file(&abs_path)?;
                    mount_files.push(MountedFile {
                        path: normalized.clone(),
                        hash,
                    });
                    used_files.insert(normalized);
                } else if abs_path.is_dir() {
                    // Directory mount - walk all files and sort for deterministic order
                    let mut files = walk_directory(&abs_path, workload_folder)?;
                    files.sort(); // Sort by path for deterministic ordering

                    for rel_path in files {
                        let abs_file = workload_folder.join(&rel_path);
                        let hash = hash_file(&abs_file)?;
                        mount_files.push(MountedFile {
                            path: rel_path.clone(),
                            hash,
                        });
                        used_files.insert(rel_path);
                    }
                }
                // If path doesn't exist, we skip it (could be created at runtime)
            }
            WorkloadVolumeMount::Named { name, .. } => {
                volumes.push(name.clone());
            }
        }
    }

    // Process env_file entries (in order from docker-compose)
    for env_path in &service.env_file {
        let normalized = normalize_path(env_path);
        let abs_path = workload_folder.join(&normalized);

        if abs_path.is_file() {
            let hash = hash_file(&abs_path)?;
            mount_files.push(MountedFile {
                path: normalized.clone(),
                hash,
            });
            used_files.insert(normalized);
        }
    }

    // Collect only the named volumes used by this service (preserve order)
    let service_volumes: Vec<String> = volumes
        .iter()
        .filter(|v| compose.volumes.contains(*v))
        .cloned()
        .collect();

    // Generate isolated docker-compose YAML
    let docker_compose = service_to_yaml(service_name, service, &service_volumes).map_err(|e| {
        MeasureError::GenerateCompose {
            service: service_name.to_string(),
            source: e,
        }
    })?;

    Ok(ServiceMeasurement {
        service_name: service_name.to_string(),
        docker_compose,
        image_digest,
        mount_files,
        volumes: service_volumes,
    })
}

/// Enumerate all files in a directory recursively.
fn enumerate_files(dir: &Path) -> Result<HashSet<String>, MeasureError> {
    let mut files = HashSet::new();

    for entry in WalkDir::new(dir).min_depth(1) {
        let entry = entry.map_err(|e| MeasureError::WalkDir {
            path: dir.to_string_lossy().to_string(),
            source: e,
        })?;

        if entry.file_type().is_file() {
            if let Ok(rel_path) = entry.path().strip_prefix(dir) {
                files.insert(rel_path.to_string_lossy().to_string());
            }
        }
    }

    Ok(files)
}

/// Walk a directory and return all file paths relative to workload_folder.
fn walk_directory(dir: &Path, workload_folder: &Path) -> Result<Vec<String>, MeasureError> {
    let mut files = Vec::new();

    for entry in WalkDir::new(dir).min_depth(1) {
        let entry = entry.map_err(|e| MeasureError::WalkDir {
            path: dir.to_string_lossy().to_string(),
            source: e,
        })?;

        if entry.file_type().is_file() {
            if let Ok(rel_to_workload) = entry.path().strip_prefix(workload_folder) {
                files.push(rel_to_workload.to_string_lossy().to_string());
            }
        }
    }

    Ok(files)
}

/// Hash a file's contents with keccak256.
fn hash_file(path: &Path) -> Result<B256, MeasureError> {
    let contents = std::fs::read(path).map_err(|e| MeasureError::ReadFile {
        path: path.to_string_lossy().to_string(),
        source: e,
    })?;
    Ok(keccak256(&contents))
}

/// Normalize a path by removing leading "./" prefix.
fn normalize_path(path: &str) -> String {
    path.strip_prefix("./").unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_workload(
        compose_content: &str,
        files: &[(&str, &str)],
    ) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let workload_path = dir.path().to_path_buf();

        // Write docker-compose.yml
        fs::write(workload_path.join("docker-compose.yml"), compose_content).unwrap();

        // Write a minimal manifest.json
        fs::write(
            workload_path.join("manifest.json"),
            r#"{"name":"test","docker_compose":"docker-compose.yml","docker_images":[]}"#,
        )
        .unwrap();

        // Create additional files
        for (path, content) in files {
            let file_path = workload_path.join(path);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(file_path, content).unwrap();
        }

        (dir, workload_path)
    }

    fn create_test_workload_with_manifest(
        compose_content: &str,
        manifest_content: &str,
        files: &[(&str, &str)],
    ) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let workload_path = dir.path().to_path_buf();

        fs::write(workload_path.join("docker-compose.yml"), compose_content).unwrap();
        fs::write(workload_path.join("manifest.json"), manifest_content).unwrap();

        for (path, content) in files {
            let file_path = workload_path.join(path);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(file_path, content).unwrap();
        }

        (dir, workload_path)
    }

    #[test]
    fn test_measure_basic() {
        let compose = r#"
services:
  app:
    image: myapp:latest
    volumes:
      - ./config.yaml:/app/config.yaml:ro
"#;
        let (_dir, workload_path) = create_test_workload(compose, &[("config.yaml", "key: value")]);

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        let result = measure(&workload_path, "docker-compose.yml", &config).unwrap();

        // Check manifest is included
        assert!(!result.manifest.is_empty());
        assert!(result.manifest.starts_with("{"));

        assert_eq!(result.services.len(), 1);
        let svc = &result.services[0];
        assert_eq!(svc.service_name, "app");
        assert_eq!(svc.image_digest, "sha256:abc123");
        assert_eq!(svc.mount_files.len(), 1);
        assert_eq!(svc.mount_files[0].path, "config.yaml");
    }

    #[test]
    fn test_measure_auto_skip_image_tar() {
        let compose = r#"
services:
  app:
    image: myapp:latest
"#;
        let manifest = r#"{
            "name": "test",
            "docker_compose": "docker-compose.yml",
            "docker_images": [
                {"service": "app", "image_tar": "app-image.tar"}
            ]
        }"#;

        let (_dir, workload_path) = create_test_workload_with_manifest(
            compose,
            manifest,
            &[("app-image.tar", "fake tar content")],
        );

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        // Should succeed - app-image.tar is auto-skipped
        let result = measure(&workload_path, "docker-compose.yml", &config).unwrap();
        assert_eq!(result.services.len(), 1);
    }

    #[test]
    fn test_measure_auto_skip_additional_data() {
        let compose = r#"
services:
  app:
    image: myapp:latest
"#;
        let manifest = r#"{
            "name": "test",
            "docker_compose": "docker-compose.yml",
            "docker_images": [],
            "additional_data_files": ["secrets/key.pem", "data/config.json"]
        }"#;

        let (_dir, workload_path) = create_test_workload_with_manifest(
            compose,
            manifest,
            &[
                ("secrets/key.pem", "secret key"),
                ("data/config.json", "{}"),
            ],
        );

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        // Should succeed - additional_data_files are auto-skipped
        let result = measure(&workload_path, "docker-compose.yml", &config).unwrap();
        assert_eq!(result.services.len(), 1);
    }

    #[test]
    fn test_measure_with_env_file() {
        let compose = r#"
services:
  app:
    image: myapp:latest
    env_file:
      - .env
"#;
        let (_dir, workload_path) = create_test_workload(compose, &[(".env", "FOO=bar")]);

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        let result = measure(&workload_path, "docker-compose.yml", &config).unwrap();

        assert_eq!(result.services.len(), 1);
        let svc = &result.services[0];
        assert_eq!(svc.mount_files.len(), 1);
        assert_eq!(svc.mount_files[0].path, ".env");
    }

    #[test]
    fn test_measure_directory_mount_deterministic_order() {
        let compose = r#"
services:
  app:
    image: myapp:latest
    volumes:
      - ./config:/app/config:ro
"#;
        let (_dir, workload_path) = create_test_workload(
            compose,
            &[
                ("config/c.yaml", "c: 3"),
                ("config/a.yaml", "a: 1"),
                ("config/b.yaml", "b: 2"),
                ("config/sub/d.yaml", "d: 4"),
            ],
        );

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        // Run twice to verify deterministic ordering
        let result1 = measure(&workload_path, "docker-compose.yml", &config).unwrap();
        let result2 = measure(&workload_path, "docker-compose.yml", &config).unwrap();

        let svc1 = &result1.services[0];
        let svc2 = &result2.services[0];

        // Files should be in sorted order
        let paths1: Vec<_> = svc1.mount_files.iter().map(|f| f.path.as_str()).collect();
        let paths2: Vec<_> = svc2.mount_files.iter().map(|f| f.path.as_str()).collect();

        assert_eq!(paths1, paths2);
        assert_eq!(
            paths1,
            vec![
                "config/a.yaml",
                "config/b.yaml",
                "config/c.yaml",
                "config/sub/d.yaml"
            ]
        );
    }

    #[test]
    fn test_measure_service_order_preserved() {
        let compose = r#"
services:
  web:
    image: nginx:latest
  api:
    image: api:latest
  db:
    image: postgres:latest
"#;
        let (_dir, workload_path) = create_test_workload(compose, &[]);

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("web".to_string(), "sha256:web".to_string());
        config
            .image_digests
            .insert("api".to_string(), "sha256:api".to_string());
        config
            .image_digests
            .insert("db".to_string(), "sha256:db".to_string());

        let result = measure(&workload_path, "docker-compose.yml", &config).unwrap();

        assert_eq!(result.services.len(), 3);
        // Services should be in docker-compose order
        assert_eq!(result.services[0].service_name, "web");
        assert_eq!(result.services[1].service_name, "api");
        assert_eq!(result.services[2].service_name, "db");
    }

    #[test]
    fn test_measure_unused_file_error() {
        let compose = r#"
services:
  app:
    image: myapp:latest
"#;
        let (_dir, workload_path) =
            create_test_workload(compose, &[("unused.txt", "should not be here")]);

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        let result = measure(&workload_path, "docker-compose.yml", &config);

        assert!(result.is_err());
        match result {
            Err(MeasureError::UnusedFiles { files }) => {
                assert!(files.contains(&"unused.txt".to_string()));
            }
            _ => panic!("Expected UnusedFiles error"),
        }
    }

    #[test]
    fn test_measure_skip_files() {
        let compose = r#"
services:
  app:
    image: myapp:latest
"#;
        let (_dir, workload_path) =
            create_test_workload(compose, &[("readme.md", "documentation")]);

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());
        config.skip_files.insert("readme.md".to_string());

        let result = measure(&workload_path, "docker-compose.yml", &config).unwrap();
        assert_eq!(result.services.len(), 1);
    }

    #[test]
    fn test_measure_missing_image_digest() {
        let compose = r#"
services:
  app:
    image: myapp:latest
"#;
        let (_dir, workload_path) = create_test_workload(compose, &[]);

        let config = MeasureConfig::default();
        // No image digest provided

        let result = measure(&workload_path, "docker-compose.yml", &config);

        assert!(result.is_err());
        match result {
            Err(MeasureError::MissingImageDigest { service }) => {
                assert_eq!(service, "app");
            }
            _ => panic!("Expected MissingImageDigest error"),
        }
    }

    #[test]
    fn test_measure_missing_manifest() {
        let dir = TempDir::new().unwrap();
        let workload_path = dir.path();

        // Only create docker-compose.yml, no manifest.json
        fs::write(
            workload_path.join("docker-compose.yml"),
            "services:\n  app:\n    image: test\n",
        )
        .unwrap();

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        let result = measure(workload_path, "docker-compose.yml", &config);

        assert!(result.is_err());
        assert!(matches!(result, Err(MeasureError::ReadManifest(_))));
    }

    #[test]
    fn test_measure_with_named_volumes() {
        let compose = r#"
services:
  app:
    image: myapp:latest
    volumes:
      - app-data:/data
volumes:
  app-data:
"#;
        let (_dir, workload_path) = create_test_workload(compose, &[]);

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        let result = measure(&workload_path, "docker-compose.yml", &config).unwrap();

        assert_eq!(result.services.len(), 1);
        let svc = &result.services[0];
        assert_eq!(svc.volumes, vec!["app-data"]);
        assert!(svc.mount_files.is_empty()); // Named volumes don't have files to hash
    }

    #[test]
    fn test_hash_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "hello world").unwrap();

        let hash = hash_file(&file_path).unwrap();

        // keccak256("hello world") = 0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad
        let expected = B256::from_slice(&[
            0x47, 0x17, 0x32, 0x85, 0xa8, 0xd7, 0x34, 0x1e, 0x5e, 0x97, 0x2f, 0xc6, 0x77, 0x28,
            0x63, 0x84, 0xf8, 0x02, 0xf8, 0xef, 0x42, 0xa5, 0xec, 0x5f, 0x03, 0xbb, 0xfa, 0x25,
            0x4c, 0xb0, 0x1f, 0xad,
        ]);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("./config.yaml"), "config.yaml");
        assert_eq!(normalize_path("config.yaml"), "config.yaml");
        assert_eq!(normalize_path("./path/to/file"), "path/to/file");
    }

    #[test]
    fn test_isolated_compose_output() {
        let compose = r#"
services:
  app:
    image: myapp:latest
    restart: always
    volumes:
      - ./config:/app/config:ro
"#;
        let (_dir, workload_path) =
            create_test_workload(compose, &[("config/app.yaml", "key: value")]);

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        let result = measure(&workload_path, "docker-compose.yml", &config).unwrap();
        let svc = &result.services[0];

        // Verify the isolated compose has expected structure
        assert!(svc.docker_compose.contains("services:"));
        assert!(svc.docker_compose.contains("app:"));
        assert!(
            svc.docker_compose
                .contains("docker.io/library/myapp:latest")
        );
        assert!(svc.docker_compose.contains("restart: always"));
        // build and depends_on should be excluded
        assert!(!svc.docker_compose.contains("build:"));
        assert!(!svc.docker_compose.contains("depends_on:"));
    }

    #[test]
    fn test_deterministic_output() {
        let compose = r#"
services:
  app:
    image: myapp:latest
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data:ro
    env_file:
      - .env
"#;
        let (_dir, workload_path) = create_test_workload(
            compose,
            &[
                ("config/b.yaml", "b"),
                ("config/a.yaml", "a"),
                ("data/file.txt", "data"),
                (".env", "VAR=value"),
            ],
        );

        let mut config = MeasureConfig::default();
        config
            .image_digests
            .insert("app".to_string(), "sha256:abc123".to_string());

        // Run multiple times
        let results: Vec<_> = (0..5)
            .map(|_| measure(&workload_path, "docker-compose.yml", &config).unwrap())
            .collect();

        // All runs should produce identical results
        for result in &results[1..] {
            assert_eq!(results[0].manifest, result.manifest);
            assert_eq!(results[0].services.len(), result.services.len());
            for (svc1, svc2) in results[0].services.iter().zip(result.services.iter()) {
                assert_eq!(svc1.service_name, svc2.service_name);
                assert_eq!(svc1.docker_compose, svc2.docker_compose);
                assert_eq!(svc1.image_digest, svc2.image_digest);
                assert_eq!(svc1.volumes, svc2.volumes);
                assert_eq!(svc1.mount_files.len(), svc2.mount_files.len());
                for (f1, f2) in svc1.mount_files.iter().zip(svc2.mount_files.iter()) {
                    assert_eq!(f1.path, f2.path);
                    assert_eq!(f1.hash, f2.hash);
                }
            }
        }
    }
}
