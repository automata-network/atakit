use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use flate2::Compression;

use crate::WorkloadError;

/// Staging directory layout for a workload archive.
pub struct StagingDir {
    pub root: PathBuf,        // staging/{name}
    pub images_dir: PathBuf,  // staging/{name}/images
    pub measured_dir: PathBuf, // staging/{name}/measured-data
}

impl StagingDir {
    /// Create the staging directory structure inside `temp_dir`.
    pub fn create(temp_dir: &Path, name: &str) -> Result<Self, WorkloadError> {
        let root = temp_dir.join(name);
        let images_dir = root.join("images");
        let measured_dir = root.join("measured-data");

        std::fs::create_dir_all(&images_dir).map_err(|e| WorkloadError::CreateDir {
            path: images_dir.clone(),
            source: e,
        })?;
        // measured-data dir is created on demand when there are files to stage

        Ok(Self {
            root,
            images_dir,
            measured_dir,
        })
    }

    /// Copy measured-data files from source into the staging directory.
    ///
    /// Preserves directory structure relative to `workload_dir`.
    /// Returns the number of files copied.
    pub fn stage_measured_data(
        &self,
        paths: &[String],
        workload_dir: &Path,
    ) -> Result<usize, WorkloadError> {
        let mut count = 0;
        for p in paths {
            let rel = p.strip_prefix("./").unwrap_or(p);
            let src = workload_dir.join(p);
            let dest = self.measured_dir.join(rel);
            count += copy_recursive(&src, &dest)?;
        }
        Ok(count)
    }

    /// Copy signing files into `measured-data/signing/`.
    pub fn stage_signing_files(
        &self,
        auth_info_src: &Path,
        policy_src: &Path,
    ) -> Result<(), WorkloadError> {
        let signing_dir = self.measured_dir.join("signing");
        std::fs::create_dir_all(&signing_dir).map_err(|e| WorkloadError::CreateDir {
            path: signing_dir.clone(),
            source: e,
        })?;

        copy_file(auth_info_src, &signing_dir.join("auth_info.json"))?;
        copy_file(policy_src, &signing_dir.join("cosign_policy.json"))?;
        Ok(())
    }

    /// Copy or link a pre-existing image tar file into `images/`.
    pub fn stage_image_file(
        &self,
        src: &Path,
        tar_name: &str,
    ) -> Result<(), WorkloadError> {
        let dest = self.images_dir.join(tar_name);
        copy_file(src, &dest)
    }

    /// Path where a container engine should save an image tar.
    pub fn image_tar_path(&self, tar_name: &str) -> PathBuf {
        self.images_dir.join(tar_name)
    }

    /// Write manifest.toml to the staging directory.
    pub fn write_manifest(&self, content: &str) -> Result<(), WorkloadError> {
        let path = self.root.join("manifest.toml");
        std::fs::write(&path, content).map_err(|e| WorkloadError::WriteFile {
            path,
            source: e,
        })
    }
}

/// Create a `.atawl` archive (tar.gz) from the staging directory.
///
/// The archive contains a single top-level directory named after the workload.
/// Returns the path to the created archive.
pub fn create_archive(
    staging_root: &Path,
    workload_name: &str,
    output_dir: &Path,
) -> Result<PathBuf, WorkloadError> {
    let archive_path = output_dir.join(format!("{workload_name}.atawl"));
    let file = std::fs::File::create(&archive_path).map_err(|e| WorkloadError::WriteFile {
        path: archive_path.clone(),
        source: e,
    })?;

    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = tar::Builder::new(enc);

    tar.append_dir_all(workload_name, staging_root)
        .map_err(WorkloadError::Io)?;

    tar.into_inner()
        .map_err(WorkloadError::Io)?
        .finish()
        .map_err(WorkloadError::Io)?;

    Ok(archive_path)
}

/// Determine the tar filename for a service's image.
pub fn image_tar_name(service_name: &str) -> String {
    format!("{service_name}.tar")
}

// ── helpers ──────────────────────────────────────────────────

fn copy_file(src: &Path, dest: &Path) -> Result<(), WorkloadError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| WorkloadError::CreateDir {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    std::fs::copy(src, dest).map_err(|e| WorkloadError::CopyFile {
        from: src.to_path_buf(),
        to: dest.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Copy a file or directory recursively. Returns the number of files copied.
fn copy_recursive(src: &Path, dest: &Path) -> Result<usize, WorkloadError> {
    if src.is_file() {
        copy_file(src, dest)?;
        return Ok(1);
    }

    if src.is_dir() {
        std::fs::create_dir_all(dest).map_err(|e| WorkloadError::CreateDir {
            path: dest.to_path_buf(),
            source: e,
        })?;

        let mut count = 0;
        let mut entries: Vec<_> = std::fs::read_dir(src)
            .map_err(WorkloadError::Io)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(WorkloadError::Io)?;
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let child_src = entry.path();
            let child_name = child_src
                .file_name()
                .expect("entry has a filename");
            let child_dest = dest.join(child_name);
            count += copy_recursive(&child_src, &child_dest)?;
        }
        return Ok(count);
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_dir_creates_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = StagingDir::create(tmp.path(), "my-app").unwrap();
        assert!(staging.images_dir.is_dir());
        assert!(staging.root.is_dir());
    }

    #[test]
    fn stage_measured_data_copies_files() {
        let tmp = tempfile::tempdir().unwrap();
        let wl_dir = tmp.path().join("workload");
        std::fs::create_dir_all(wl_dir.join("config")).unwrap();
        std::fs::write(wl_dir.join("config/hello"), "world").unwrap();

        let staging_tmp = tempfile::tempdir().unwrap();
        let staging = StagingDir::create(staging_tmp.path(), "test").unwrap();

        let count = staging
            .stage_measured_data(&["./config/hello".into()], &wl_dir)
            .unwrap();
        assert_eq!(count, 1);
        assert!(staging.measured_dir.join("config/hello").exists());
    }

    #[test]
    fn create_archive_produces_file() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = StagingDir::create(tmp.path(), "test-app").unwrap();
        std::fs::write(staging.root.join("manifest.toml"), "[meta]\n").unwrap();
        std::fs::write(staging.images_dir.join("test-app.tar"), "fake tar").unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let archive = create_archive(&staging.root, "test-app", out_dir.path()).unwrap();
        assert!(archive.exists());
        assert!(archive.to_string_lossy().ends_with(".atawl"));
    }

    #[test]
    fn image_tar_name_format() {
        assert_eq!(image_tar_name("my-app"), "my-app.tar");
        assert_eq!(image_tar_name("redis"), "redis.tar");
    }
}
