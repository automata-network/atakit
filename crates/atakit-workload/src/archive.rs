use std::io;
use std::path::{Path, PathBuf};

use atakit_core::{ArchiveCompression, ProgressHandle};

use crate::WorkloadError;

/// Staging directory layout for a workload archive.
pub struct StagingDir {
    pub root: PathBuf,         // staging/{name}
    pub images_dir: PathBuf,   // staging/{name}/images
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
            // Defense-in-depth: reject any ".." components before joining
            if Path::new(rel)
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err(WorkloadError::Validation(format!(
                    "measured-data path must not contain \"..\": {p:?}"
                )));
            }
            let src = workload_dir.join(p);
            let dest = self.measured_dir.join(rel);
            count += copy_recursive(&src, &dest)?;
        }
        Ok(count)
    }

    /// Copy or link a pre-existing image tar file into `images/`.
    pub fn stage_image_file(&self, src: &Path, tar_name: &str) -> Result<(), WorkloadError> {
        let dest = self.images_dir.join(tar_name);
        copy_file(src, &dest)
    }

    /// Path where a container engine should save an image tar.
    pub fn image_tar_path(&self, tar_name: &str) -> PathBuf {
        self.images_dir.join(tar_name)
    }

    /// Write manifest.json to the staging directory.
    pub fn write_manifest(&self, content: &str) -> Result<(), WorkloadError> {
        let path = self.root.join("manifest.json");
        std::fs::write(&path, content).map_err(|e| WorkloadError::WriteFile { path, source: e })
    }
}

/// Create a `.atawl` archive from the staging directory.
///
/// The archive contains a single top-level directory named after the workload.
/// Returns the path to the created archive.
pub fn create_archive(
    staging_root: &Path,
    workload_name: &str,
    workload_version: &str,
    output_dir: &Path,
    progress: &dyn ProgressHandle,
    compression: ArchiveCompression,
) -> Result<PathBuf, WorkloadError> {
    let archive_path = output_dir.join(format!("{workload_name}-{workload_version}.atawl"));
    let file = std::fs::File::create(&archive_path).map_err(|e| WorkloadError::WriteFile {
        path: archive_path.clone(),
        source: e,
    })?;

    match compression {
        ArchiveCompression::Zstd => {
            let enc = zstd::Encoder::new(file, 0).map_err(WorkloadError::Io)?;
            let counting = ProgressWriter {
                inner: enc,
                progress,
            };
            let mut tar = tar::Builder::new(counting);
            append_dir_deterministic(&mut tar, staging_root, Path::new(workload_name))?;
            tar.into_inner()
                .map_err(WorkloadError::Io)?
                .inner
                .finish()
                .map_err(WorkloadError::Io)?;
        }
        ArchiveCompression::Gz => {
            let enc = flate2::GzBuilder::new()
                .mtime(0)
                .write(file, flate2::Compression::default());
            let counting = ProgressWriter {
                inner: enc,
                progress,
            };
            let mut tar = tar::Builder::new(counting);
            append_dir_deterministic(&mut tar, staging_root, Path::new(workload_name))?;
            tar.into_inner()
                .map_err(WorkloadError::Io)?
                .inner
                .finish()
                .map_err(WorkloadError::Io)?;
        }
    }

    Ok(archive_path)
}

/// Open an archive file with auto-detected decompression (zstd or gzip).
pub(crate) fn open_decoder(
    mut file: std::fs::File,
) -> Result<Box<dyn std::io::Read>, WorkloadError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(WorkloadError::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(WorkloadError::Io)?;

    if magic[..2] == [0x1F, 0x8B] {
        Ok(Box::new(flate2::read::GzDecoder::new(file)))
    } else if magic == [0x28, 0xB5, 0x2F, 0xFD] {
        Ok(Box::new(
            zstd::Decoder::new(file).map_err(WorkloadError::Io)?,
        ))
    } else {
        Err(WorkloadError::Validation(
            "unrecognized archive compression (expected zstd or gzip)".into(),
        ))
    }
}

/// Recursively sum file sizes in a directory. Returns 0 if it doesn't exist.
pub fn dir_size(path: &Path) -> u64 {
    fn walk(path: &Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(path) else {
            return 0;
        };
        let mut total = 0;
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_file() {
                total += meta.len();
            } else if meta.is_dir() {
                total += walk(&entry.path());
            }
        }
        total
    }
    walk(path)
}

/// Writer wrapper that reports bytes written to a progress handle.
struct ProgressWriter<'a, W> {
    inner: W,
    progress: &'a dyn ProgressHandle,
}

impl<W: io::Write> io::Write for ProgressWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.progress.inc(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Recursively append a directory tree to a tar archive with deterministic metadata.
///
/// Sorts entries, sets mtime=0, uid=0, gid=0, and normalises permissions
/// (0o755 for directories, 0o644 for files).
fn append_dir_deterministic<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    src_dir: &Path,
    archive_prefix: &Path,
) -> Result<(), WorkloadError> {
    // Add the directory entry itself
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0o755);
    header.set_cksum();
    let dir_path = format!("{}/", archive_prefix.display());
    tar.append_data(&mut header, &dir_path, std::io::empty())
        .map_err(WorkloadError::Io)?;

    let mut entries: Vec<_> = std::fs::read_dir(src_dir)
        .map_err(WorkloadError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(WorkloadError::Io)?;
    // Sort files before directories (so manifest.json precedes images/),
    // then alphabetically within each group.
    entries.sort_by(|a, b| {
        let a_is_dir = a.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
        let b_is_dir = b.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
        a_is_dir
            .cmp(&b_is_dir)
            .then_with(|| a.file_name().cmp(&b.file_name()))
    });

    for entry in entries {
        let child_src = entry.path();
        let child_name = child_src.file_name().expect("entry has a filename");
        let child_archive = archive_prefix.join(child_name);
        let ft = entry.file_type().map_err(WorkloadError::Io)?;

        if ft.is_dir() {
            append_dir_deterministic(tar, &child_src, &child_archive)?;
        } else if ft.is_file() {
            let metadata = std::fs::metadata(&child_src).map_err(WorkloadError::Io)?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(metadata.len());
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_cksum();
            let file = std::fs::File::open(&child_src).map_err(WorkloadError::Io)?;
            tar.append_data(&mut header, &child_archive, file)
                .map_err(WorkloadError::Io)?;
        }
    }

    Ok(())
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
    let file_type = std::fs::symlink_metadata(src)
        .map_err(WorkloadError::Io)?
        .file_type();

    if file_type.is_symlink() {
        // Reject symlinks to avoid traversing or copying paths outside the workload.
        let err = io::Error::other(format!(
            "symlinks are not allowed in measured data: {}",
            src.display()
        ));
        return Err(WorkloadError::Io(err));
    }

    if file_type.is_file() {
        copy_file(src, dest)?;
        return Ok(1);
    }

    if file_type.is_dir() {
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
            let child_name = child_src.file_name().expect("entry has a filename");
            let child_dest = dest.join(child_name);
            count += copy_recursive(&child_src, &child_dest)?;
        }
        return Ok(count);
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use atakit_core::ProgressReporter;

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
        std::fs::write(staging.root.join("manifest.json"), "{\"meta\":{}}").unwrap();
        std::fs::write(staging.images_dir.join("test-app.tar"), "fake tar").unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let null = atakit_core::NullReporter;
        let handle = null.create("test", 0);
        let archive = create_archive(
            &staging.root,
            "test-app",
            "0.1.0",
            out_dir.path(),
            handle.as_ref(),
            ArchiveCompression::default(),
        )
        .unwrap();
        assert!(archive.exists());
        assert!(archive.to_string_lossy().ends_with("test-app-0.1.0.atawl"));
    }

    #[test]
    fn image_tar_name_format() {
        assert_eq!(image_tar_name("my-app"), "my-app.tar");
        assert_eq!(image_tar_name("redis"), "redis.tar");
    }
}
