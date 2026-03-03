use std::{fs, path::Path};

use anyhow::Context;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::get_digest_from_docker_tar;
use automata_linux_release::ImageRef;

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkloadManifest {
    pub name: ImageRef,
    pub docker_compose: String,
    pub image: ImageRef,
    pub measured_files: Vec<String>,
    pub additional_data_files: Vec<String>,
    pub docker_images: Vec<DockerImageEntry>,
    pub enable_cvm_agent: Vec<String>,
    pub atakit_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DockerImageEntry {
    pub service: String,
    /// For pre-published images (no build directive).
    pub image_tag: String,
    /// Filename of the saved tar inside the package (for locally built images).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_tar: Option<String>,
}

impl WorkloadManifest {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))
    }

    /// Extract image digests from a workload package directory.
    ///
    /// Reads `manifest.json` and for each docker image entry:
    /// - If `image_tar` is set, extracts the digest from the OCI image index
    /// - If only `image_tag` is set, uses a placeholder `tag:<tag>` value
    ///
    /// # Arguments
    ///
    /// * `workload_dir` - Path to the extracted workload package directory
    ///
    /// # Returns
    ///
    /// A map of service name to image digest (e.g., "sha256:abc123...")
    pub fn extract_image_digests(
        &self,
        workload_dir: &Path,
        platform: &str,
    ) -> anyhow::Result<IndexMap<String, String>> {
        // Build image digests map from docker images
        let mut image_digests = IndexMap::new();
        for img in &self.docker_images {
            let Some(tar_name) = img.image_tar.as_ref() else {
                return Err(anyhow::anyhow!(
                    "Image entry for service '{}' is missing 'image_tar'",
                    img.service
                ));
            };
            let tar_path = workload_dir.join(tar_name);
            let digest = get_digest_from_docker_tar(&tar_path, platform)?;

            info!(service = %img.service, digest = %digest, "Resolved image digest");
            image_digests.insert(img.service.clone(), digest);
        }

        Ok(image_digests)
    }
}
