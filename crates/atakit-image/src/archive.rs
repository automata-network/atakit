use std::path::{Path, PathBuf};

use atakit_core::{ArchiveCompression, ProgressReporter};
use serde::{Deserialize, Serialize};

use crate::error::{ImageError, Result};
use crate::types::{ImageRef, Platform};

/// Current format version for .atabi archives.
pub const IMAGE_FORMAT_VERSION: u32 = 1;

/// Manifest embedded in an .atabi archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageManifest {
    pub meta: ImageManifestMeta,
}

/// Metadata section of the image manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageManifestMeta {
    pub format: u32,
    pub name: String,
    pub version: String,
    pub platforms: Vec<String>,
}

/// Create an .atabi archive from a tag directory in the image store.
///
/// The archive is a tar.zst (or tar.gz with `--gz`) containing:
/// ```text
/// <repository>/
///   manifest.toml
///   disk_images/
///     gcp_disk.tar.gz
///     ...
///   secure_boot_certs/
///     PK.crt
///     ...
/// ```
///
/// Only platforms that have disk images on disk are included.
/// Metadata is deterministic: mtime=0, uid=0, gid=0.
pub fn create_image_archive(
    tag_dir: &Path,
    image_ref: &ImageRef,
    platforms: &[Platform],
    output_dir: &Path,
    progress: &dyn ProgressReporter,
    compression: ArchiveCompression,
) -> Result<PathBuf> {
    // Compute platform suffix: "all" when every platform is present, otherwise sorted names.
    let mut sorted_names: Vec<String> = platforms.iter().map(|p| p.to_string()).collect();
    sorted_names.sort();
    let suffix = if sorted_names.len() == Platform::ALL.len()
        && Platform::ALL.iter().all(|p| platforms.contains(p))
    {
        "all".to_string()
    } else {
        sorted_names.join("-")
    };
    let archive_name = format!("{}-{}-{}.atabi", image_ref.repository, image_ref.tag, suffix);
    let archive_path = output_dir.join(&archive_name);

    // Compute total source bytes for progress tracking (only matching platform disk images).
    let platform_prefixes: Vec<String> = platforms.iter().map(|p| format!("{}_", p)).collect();
    let total_bytes = filtered_dir_size(&tag_dir.join("disk_images"), &platform_prefixes)
        + dir_size(&tag_dir.join("secure_boot_certs"));
    let handle = progress.create(
        &format!("Packing {}", image_ref),
        total_bytes,
    );

    let file =
        std::fs::File::create(&archive_path).map_err(|e| ImageError::CreateFile {
            path: archive_path.clone(),
            source: e,
        })?;

    // Build manifest.
    let prefix = Path::new(&image_ref.repository);
    let platform_names: Vec<String> = platforms.iter().map(|p| p.to_string()).collect();
    let manifest = ImageManifest {
        meta: ImageManifestMeta {
            format: IMAGE_FORMAT_VERSION,
            name: image_ref.repository.clone(),
            version: image_ref.tag.clone(),
            platforms: platform_names,
        },
    };
    let manifest_toml =
        toml::to_string_pretty(&manifest).expect("manifest serialization cannot fail");

    match compression {
        ArchiveCompression::Zstd => {
            let enc = zstd::Encoder::new(file, 0).map_err(ImageError::Io)?;
            let counting = ProgressWriter::new(enc, handle.as_ref());
            let mut tar = tar::Builder::new(counting);
            write_archive_contents(&mut tar, prefix, &manifest_toml, tag_dir, platforms)?;
            tar.into_inner()
                .map_err(ImageError::Io)?
                .into_inner()
                .finish()
                .map_err(ImageError::Io)?;
        }
        ArchiveCompression::Gz => {
            let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let counting = ProgressWriter::new(enc, handle.as_ref());
            let mut tar = tar::Builder::new(counting);
            write_archive_contents(&mut tar, prefix, &manifest_toml, tag_dir, platforms)?;
            tar.into_inner()
                .map_err(ImageError::Io)?
                .into_inner()
                .finish()
                .map_err(ImageError::Io)?;
        }
    }

    handle.finish();
    Ok(archive_path)
}

/// Import an .atabi archive into the image store.
///
/// Extracts the archive contents into `store_base_dir/<repository>/<tag>/`.
/// Returns the `ImageRef` parsed from the embedded manifest.
pub fn import_image_archive(
    archive_path: &Path,
    store_base_dir: &Path,
) -> Result<ImageRef> {
    let manifest = read_manifest(archive_path)?;

    // Validate manifest-derived path components before using them to build paths.
    validate_path_component(&manifest.meta.name, "manifest name", archive_path)?;
    validate_path_component(&manifest.meta.version, "manifest version", archive_path)?;

    let image_ref = ImageRef {
        repository: manifest.meta.name.clone(),
        tag: manifest.meta.version.clone(),
    };

    // Ensure store_base_dir exists and resolve it to a canonical path once,
    // before building dest_dir. All extraction targets are verified against
    // this canonical root so that pre-existing symlinks inside the store
    // cannot redirect writes outside it.
    std::fs::create_dir_all(store_base_dir).map_err(|e| ImageError::CreateDir {
        path: store_base_dir.to_path_buf(),
        source: e,
    })?;
    let canonical_store = store_base_dir.canonicalize().map_err(|e| ImageError::CreateDir {
        path: store_base_dir.to_path_buf(),
        source: e,
    })?;

    // Build dest_dir component by component from the canonical store,
    // rejecting pre-existing symlinks at each level.
    let dest_dir = create_dir_checked(
        &canonical_store,
        &[&image_ref.repository, &image_ref.tag],
        archive_path,
    )?;

    let file =
        std::fs::File::open(archive_path).map_err(|e| ImageError::ArchiveRead {
            path: archive_path.to_path_buf(),
            source: e,
        })?;
    let decoder = open_decoder(archive_path, file)?;
    let mut archive = tar::Archive::new(decoder);

    // The archive has a top-level directory named after the repository.
    // We need to strip that prefix and extract into dest_dir.
    let strip_prefix = &image_ref.repository;

    for entry in archive.entries().map_err(|e| ImageError::ArchiveRead {
        path: archive_path.to_path_buf(),
        source: e,
    })? {
        let mut entry = entry.map_err(|e| ImageError::ArchiveRead {
            path: archive_path.to_path_buf(),
            source: e,
        })?;

        let entry_path = entry
            .path()
            .map_err(|e| ImageError::ArchiveRead {
                path: archive_path.to_path_buf(),
                source: e,
            })?
            .into_owned();

        // Strip the top-level directory.
        let relative = match entry_path.strip_prefix(strip_prefix) {
            Ok(rel) => rel.to_path_buf(),
            Err(_) => continue, // skip entries outside the expected prefix
        };

        // Skip the root directory entry itself and manifest.toml (already parsed).
        if relative == Path::new("") || relative == Path::new("manifest.toml") {
            // For manifest.toml, we still need to consume it (it's already parsed).
            if relative == Path::new("") {
                continue;
            }
            // Skip manifest file -- we don't store it on disk in the image store.
            continue;
        }

        // Reject entries with path traversal components.
        if !is_safe_relative_path(&relative) {
            return Err(ImageError::ArchiveInvalid {
                path: archive_path.to_path_buf(),
                message: format!(
                    "entry contains path traversal: {}",
                    entry_path.display()
                ),
            });
        }

        // Only allow regular files and directories. Symlinks and hard links
        // can be used to escape the destination directory even when the entry
        // path itself looks safe.
        let entry_type = entry.header().entry_type();
        if !entry_type.is_dir() && !entry_type.is_file() {
            return Err(ImageError::ArchiveInvalid {
                path: archive_path.to_path_buf(),
                message: format!(
                    "unsupported entry type in archive: {}",
                    entry_path.display()
                ),
            });
        }

        let target = dest_dir.join(&relative);

        // Collect path components between dest_dir and target so we can
        // create each one with symlink checking.
        let components: Vec<&str> = relative
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => s.to_str(),
                _ => None,
            })
            .collect();

        if entry_type.is_dir() {
            create_dir_checked(&dest_dir, &components, archive_path)?;
        } else {
            // Create parent directories with symlink checking, then unpack.
            let parent_components = &components[..components.len().saturating_sub(1)];
            if !parent_components.is_empty() {
                create_dir_checked(&dest_dir, parent_components, archive_path)?;
            }

            entry.unpack(&target).map_err(|e| ImageError::WriteFile {
                path: target.clone(),
                source: e,
            })?;

            // Compress VHD files to save disk space.
            if target.extension().is_some_and(|e| e == "vhd") {
                compress_to_zst(&target)?;
            }
        }
    }

    Ok(image_ref)
}

/// Create a directory path from `base` by appending each component one at a
/// time, checking that no existing component is a symlink. Creates missing
/// components as real directories. Returns the final path.
fn create_dir_checked(base: &Path, components: &[&str], archive_path: &Path) -> Result<PathBuf> {
    let mut current = base.to_path_buf();
    for component in components {
        current = current.join(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(ImageError::ArchiveInvalid {
                        path: archive_path.to_path_buf(),
                        message: format!(
                            "symlink in store path: {}",
                            current.display()
                        ),
                    });
                }
                if !meta.is_dir() {
                    return Err(ImageError::ArchiveInvalid {
                        path: archive_path.to_path_buf(),
                        message: format!(
                            "non-directory in store path: {}",
                            current.display()
                        ),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|e| ImageError::CreateDir {
                    path: current.clone(),
                    source: e,
                })?;
            }
            Err(e) => {
                return Err(ImageError::CreateDir {
                    path: current,
                    source: e,
                });
            }
        }
    }
    Ok(current)
}

/// Validate that a value is safe to use as a single path component.
///
/// Rejects empty strings, path separators, parent/current-dir references,
/// and null bytes.
fn validate_path_component(value: &str, field: &str, archive_path: &Path) -> Result<()> {
    if value.is_empty() {
        return Err(ImageError::ArchiveInvalid {
            path: archive_path.to_path_buf(),
            message: format!("{field} is empty"),
        });
    }
    if value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || value == ".."
        || value == "."
    {
        return Err(ImageError::ArchiveInvalid {
            path: archive_path.to_path_buf(),
            message: format!("{field} contains unsafe path characters: {value:?}"),
        });
    }
    Ok(())
}

/// Check that a relative path has no traversal components (`..", root, or prefix).
fn is_safe_relative_path(path: &Path) -> bool {
    use std::path::Component;
    for component in path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

/// Compress a file to `.zst` and remove the original.
fn compress_to_zst(path: &Path) -> Result<()> {
    use std::io::{Read, Write};

    let zst_path = path.with_extension("vhd.zst");
    let mut reader = std::fs::File::open(path).map_err(|e| ImageError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    let out = std::fs::File::create(&zst_path).map_err(|e| ImageError::CreateFile {
        path: zst_path.clone(),
        source: e,
    })?;
    let mut encoder = zstd::Encoder::new(out, 0).map_err(ImageError::Io)?;

    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(ImageError::Io)?;
        if n == 0 {
            break;
        }
        encoder.write_all(&buf[..n]).map_err(ImageError::Io)?;
    }
    encoder.finish().map_err(ImageError::Io)?;

    std::fs::remove_file(path).map_err(|e| ImageError::Remove {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Read and parse the manifest from an .atabi archive without full extraction.
pub fn read_manifest(archive_path: &Path) -> Result<ImageManifest> {
    let file =
        std::fs::File::open(archive_path).map_err(|e| ImageError::ArchiveRead {
            path: archive_path.to_path_buf(),
            source: e,
        })?;
    let decoder = open_decoder(archive_path, file)?;
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries().map_err(|e| ImageError::ArchiveRead {
        path: archive_path.to_path_buf(),
        source: e,
    })? {
        let mut entry = entry.map_err(|e| ImageError::ArchiveRead {
            path: archive_path.to_path_buf(),
            source: e,
        })?;

        let entry_path = entry
            .path()
            .map_err(|e| ImageError::ArchiveRead {
                path: archive_path.to_path_buf(),
                source: e,
            })?
            .into_owned();

        // manifest.toml is the second entry (after the directory).
        if entry_path
            .file_name()
            .map(|n| n == "manifest.toml")
            .unwrap_or(false)
        {
            let mut content = String::new();
            std::io::Read::read_to_string(&mut entry, &mut content).map_err(|e| {
                ImageError::ArchiveRead {
                    path: archive_path.to_path_buf(),
                    source: e,
                }
            })?;

            let manifest: ImageManifest =
                toml::from_str(&content).map_err(|e| ImageError::ParseManifest {
                    path: archive_path.to_path_buf(),
                    reason: e.to_string(),
                })?;

            return Ok(manifest);
        }
    }

    Err(ImageError::ArchiveMissingManifest {
        path: archive_path.to_path_buf(),
    })
}

/// Write the tar archive contents (manifest, disk images, certs).
fn write_archive_contents<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    prefix: &Path,
    manifest_toml: &str,
    tag_dir: &Path,
    platforms: &[Platform],
) -> Result<()> {
    append_dir_entry(tar, prefix)?;
    append_file_bytes(tar, &prefix.join("manifest.toml"), manifest_toml.as_bytes())?;

    // Only include disk images for the specified platforms.
    let disk_images_src = tag_dir.join("disk_images");
    if disk_images_src.is_dir() {
        let disk_prefix = prefix.join("disk_images");
        append_dir_entry(tar, &disk_prefix)?;

        let platform_prefixes: Vec<String> =
            platforms.iter().map(|p| format!("{}_", p)).collect();

        let mut entries: Vec<_> = std::fs::read_dir(&disk_images_src)
            .map_err(|e| ImageError::ReadDir { path: disk_images_src.clone(), source: e })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(ImageError::Io)?;
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        for entry in entries {
            let path = entry.path();
            let fname = path.file_name().expect("entry has a filename");
            let name_str = fname.to_string_lossy();
            if !platform_prefixes.iter().any(|pfx| name_str.starts_with(pfx.as_str())) {
                continue;
            }
            if entry.file_type().map_err(ImageError::Io)?.is_file() {
                append_file(tar, &path, &disk_prefix.join(fname))?;
            }
        }
    }

    let certs_src = tag_dir.join("secure_boot_certs");
    if certs_src.is_dir() {
        let certs_prefix = prefix.join("secure_boot_certs");
        append_dir_entry(tar, &certs_prefix)?;
        append_dir_contents(tar, &certs_src, &certs_prefix)?;
    }
    Ok(())
}

/// Open an archive file with auto-detected decompression (zstd or gzip).
fn open_decoder(
    archive_path: &Path,
    mut file: std::fs::File,
) -> Result<Box<dyn std::io::Read>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| ImageError::ArchiveRead {
        path: archive_path.to_path_buf(),
        source: e,
    })?;
    file.seek(SeekFrom::Start(0)).map_err(|e| ImageError::ArchiveRead {
        path: archive_path.to_path_buf(),
        source: e,
    })?;

    if magic[..2] == [0x1F, 0x8B] {
        Ok(Box::new(flate2::read::GzDecoder::new(file)))
    } else if magic == [0x28, 0xB5, 0x2F, 0xFD] {
        Ok(Box::new(
            zstd::Decoder::new(file).map_err(|e| ImageError::ArchiveRead {
                path: archive_path.to_path_buf(),
                source: e,
            })?,
        ))
    } else {
        Err(ImageError::ParseManifest {
            path: archive_path.to_path_buf(),
            reason: "unrecognized archive compression (expected zstd or gzip)".into(),
        })
    }
}

// ── progress writer ─────────────────────────────────────────

/// Writer wrapper that reports bytes written to a progress handle.
struct ProgressWriter<'a, W> {
    inner: W,
    handle: &'a dyn atakit_core::ProgressHandle,
}

impl<'a, W> ProgressWriter<'a, W> {
    fn new(inner: W, handle: &'a dyn atakit_core::ProgressHandle) -> Self {
        Self { inner, handle }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: std::io::Write> std::io::Write for ProgressWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.handle.inc(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Recursively sum file sizes in a directory. Returns 0 if it doesn't exist.
fn dir_size(path: &Path) -> u64 {
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

/// Sum file sizes in a directory, only counting files whose name starts with one of the prefixes.
fn filtered_dir_size(path: &Path, prefixes: &[String]) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    let mut total = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if prefixes.iter().any(|pfx| name_str.starts_with(pfx.as_str())) {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    total += meta.len();
                }
            }
        }
    }
    total
}

// ── tar helpers ──────────────────────────────────────────────

fn append_dir_entry<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    path: &Path,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0o755);
    header.set_cksum();
    let dir_path = format!("{}/", path.display());
    tar.append_data(&mut header, &dir_path, std::io::empty())
        .map_err(ImageError::Io)?;
    Ok(())
}

fn append_file_bytes<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    path: &Path,
    data: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(data.len() as u64);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, data)
        .map_err(ImageError::Io)?;
    Ok(())
}

/// Append all files in a directory (sorted, non-recursive for files).
fn append_dir_contents<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    src_dir: &Path,
    archive_prefix: &Path,
) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(src_dir)
        .map_err(|e| ImageError::ReadDir {
            path: src_dir.to_path_buf(),
            source: e,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(ImageError::Io)?;

    // Sort: files before directories, then alphabetically.
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
        let ft = entry.file_type().map_err(ImageError::Io)?;

        if ft.is_dir() {
            append_dir_entry(tar, &child_archive)?;
            append_dir_contents(tar, &child_src, &child_archive)?;
        } else if ft.is_file() {
            append_file(tar, &child_src, &child_archive)?;
        }
    }

    Ok(())
}

/// Append a single file from disk to the tar with deterministic metadata.
fn append_file<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &Path,
) -> Result<()> {
    let metadata = std::fs::metadata(src_path).map_err(ImageError::Io)?;
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(metadata.len());
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0o644);
    header.set_cksum();
    let file = std::fs::File::open(src_path).map_err(|e| ImageError::ReadFile {
        path: src_path.to_path_buf(),
        source: e,
    })?;
    tar.append_data(&mut header, archive_path, file)
        .map_err(ImageError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use atakit_core::NullReporter;

    use super::*;

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = ImageManifest {
            meta: ImageManifestMeta {
                format: IMAGE_FORMAT_VERSION,
                name: "automata-linux".to_string(),
                version: "v0.1.6".to_string(),
                platforms: vec!["gcp".to_string(), "aws".to_string()],
            },
        };

        let toml_str = toml::to_string_pretty(&manifest).unwrap();
        let parsed: ImageManifest = toml::from_str(&toml_str).unwrap();
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn archive_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();

        // Set up a fake tag directory.
        let tag_dir = tmp.path().join("tag");
        let disk_dir = tag_dir.join("disk_images");
        let certs_dir = tag_dir.join("secure_boot_certs");
        std::fs::create_dir_all(&disk_dir).unwrap();
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(disk_dir.join("gcp_disk.tar.gz"), b"fake-gcp-image").unwrap();
        std::fs::write(certs_dir.join("PK.crt"), b"fake-pk-cert").unwrap();

        let image_ref: ImageRef = "test-repo:v1.0.0".parse().unwrap();
        let platforms = vec![Platform::Gcp];

        // Create archive.
        let out_dir = tmp.path().join("output");
        std::fs::create_dir_all(&out_dir).unwrap();
        let archive_path =
            create_image_archive(&tag_dir, &image_ref, &platforms, &out_dir, &NullReporter, ArchiveCompression::default()).unwrap();
        assert!(archive_path.exists());
        // Single-platform archive should include the platform name.
        assert_eq!(
            archive_path.file_name().unwrap().to_str().unwrap(),
            "test-repo-v1.0.0-gcp.atabi"
        );

        // Read manifest from archive.
        let manifest = read_manifest(&archive_path).unwrap();
        assert_eq!(manifest.meta.name, "test-repo");
        assert_eq!(manifest.meta.version, "v1.0.0");
        assert_eq!(manifest.meta.platforms, vec!["gcp"]);

        // Import into a fresh store base dir.
        let store_dir = tmp.path().join("store");
        let imported_ref = import_image_archive(&archive_path, &store_dir).unwrap();
        assert_eq!(imported_ref.repository, "test-repo");
        assert_eq!(imported_ref.tag, "v1.0.0");

        // Verify files were extracted.
        let imported_disk = store_dir.join("test-repo/v1.0.0/disk_images/gcp_disk.tar.gz");
        assert!(imported_disk.exists());
        assert_eq!(std::fs::read(&imported_disk).unwrap(), b"fake-gcp-image");

        let imported_cert = store_dir.join("test-repo/v1.0.0/secure_boot_certs/PK.crt");
        assert!(imported_cert.exists());
        assert_eq!(std::fs::read(&imported_cert).unwrap(), b"fake-pk-cert");
    }

    /// A raw tar entry for building test archives that bypass the tar crate's
    /// path validation.
    enum RawEntry<'a> {
        /// Regular file with path and data.
        File(&'a str, &'a [u8]),
        /// Symlink: (link_path, target).
        Symlink(&'a str, &'a str),
        /// Hard link: (link_path, target).
        Hardlink(&'a str, &'a str),
    }

    /// Build a malicious .atabi archive with custom manifest name/version and
    /// extra entries. Uses raw tar bytes to bypass the tar crate's own
    /// validation, allowing us to test our validation layer.
    fn build_malicious_archive(
        dir: &Path,
        name: &str,
        version: &str,
        extra_entries: &[RawEntry],
    ) -> PathBuf {
        use std::io::Write;

        let archive_path = dir.join("malicious.atabi");
        let mut tar_bytes = Vec::new();

        fn write_raw_entry(
            out: &mut Vec<u8>,
            path: &str,
            data: &[u8],
            typeflag: u8,
            link_name: &str,
        ) {
            let mut header = [0u8; 512];
            // Name field: bytes 0..100
            let name_bytes = path.as_bytes();
            let len = name_bytes.len().min(100);
            header[..len].copy_from_slice(&name_bytes[..len]);
            // Mode: bytes 100..108
            if typeflag == b'5' {
                header[100..107].copy_from_slice(b"0000755");
            } else {
                header[100..107].copy_from_slice(b"0000644");
            }
            // Size: bytes 124..136 (symlinks/hardlinks have size 0)
            let size = if typeflag == b'2' || typeflag == b'1' {
                0
            } else {
                data.len()
            };
            let size_str = format!("{:011o}", size);
            header[124..135].copy_from_slice(size_str.as_bytes());
            // Typeflag: byte 156
            header[156] = typeflag;
            // Linkname: bytes 157..257
            if !link_name.is_empty() {
                let link_bytes = link_name.as_bytes();
                let llen = link_bytes.len().min(100);
                header[157..157 + llen].copy_from_slice(&link_bytes[..llen]);
            }
            // Magic: bytes 257..263
            header[257..263].copy_from_slice(b"ustar\0");
            // Version: bytes 263..265
            header[263..265].copy_from_slice(b"00");
            // Checksum: bytes 148..156 (spaces during calculation)
            header[148..156].copy_from_slice(b"        ");
            let cksum: u32 = header.iter().map(|&b| b as u32).sum();
            let cksum_str = format!("{:06o}\0 ", cksum);
            header[148..156].copy_from_slice(cksum_str.as_bytes());

            out.extend_from_slice(&header);
            if size > 0 {
                out.extend_from_slice(data);
                let padding = (512 - (size % 512)) % 512;
                out.extend(std::iter::repeat(0u8).take(padding));
            }
        }

        // Top-level directory.
        write_raw_entry(&mut tar_bytes, &format!("{name}/"), &[], b'5', "");

        // Manifest entry.
        let manifest = format!(
            "[meta]\nformat = 1\nname = {name:?}\nversion = {version:?}\nplatforms = [\"gcp\"]\n"
        );
        write_raw_entry(
            &mut tar_bytes,
            &format!("{name}/manifest.toml"),
            manifest.as_bytes(),
            b'0',
            "",
        );

        for entry in extra_entries {
            match entry {
                RawEntry::File(path, data) => {
                    write_raw_entry(&mut tar_bytes, path, data, b'0', "");
                }
                RawEntry::Symlink(path, target) => {
                    write_raw_entry(&mut tar_bytes, path, &[], b'2', target);
                }
                RawEntry::Hardlink(path, target) => {
                    write_raw_entry(&mut tar_bytes, path, &[], b'1', target);
                }
            }
        }

        // End-of-archive marker (two 512-byte zero blocks).
        tar_bytes.extend(std::iter::repeat(0u8).take(1024));

        let file = std::fs::File::create(&archive_path).unwrap();
        let mut enc = zstd::Encoder::new(file, 0).unwrap();
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap();

        archive_path
    }

    #[test]
    fn import_rejects_traversal_in_manifest_name() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = build_malicious_archive(tmp.path(), "../evil", "v1", &[]);
        let store_dir = tmp.path().join("store");
        let err = import_image_archive(&archive, &store_dir).unwrap_err();
        assert!(
            err.to_string().contains("unsafe path characters"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn import_rejects_slash_in_manifest_name() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = build_malicious_archive(tmp.path(), "foo/bar", "v1", &[]);
        let store_dir = tmp.path().join("store");
        let err = import_image_archive(&archive, &store_dir).unwrap_err();
        assert!(
            err.to_string().contains("unsafe path characters"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn import_rejects_traversal_in_manifest_version() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = build_malicious_archive(tmp.path(), "repo", "../../etc", &[]);
        let store_dir = tmp.path().join("store");
        let err = import_image_archive(&archive, &store_dir).unwrap_err();
        assert!(
            err.to_string().contains("unsafe path characters"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn import_rejects_traversal_in_entry_path() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = build_malicious_archive(
            tmp.path(),
            "repo",
            "v1",
            &[RawEntry::File("repo/../../escaped.txt", b"pwned")],
        );
        let store_dir = tmp.path().join("store");
        let err = import_image_archive(&archive, &store_dir).unwrap_err();
        assert!(
            err.to_string().contains("path traversal"),
            "unexpected error: {err}"
        );
        assert!(!tmp.path().join("escaped.txt").exists());
    }

    #[test]
    fn import_rejects_symlink_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = build_malicious_archive(
            tmp.path(),
            "repo",
            "v1",
            &[RawEntry::Symlink("repo/disk_images", "/tmp")],
        );
        let store_dir = tmp.path().join("store");
        let err = import_image_archive(&archive, &store_dir).unwrap_err();
        assert!(
            err.to_string().contains("unsupported entry type"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn import_rejects_hardlink_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = build_malicious_archive(
            tmp.path(),
            "repo",
            "v1",
            &[RawEntry::Hardlink("repo/evil", "/etc/passwd")],
        );
        let store_dir = tmp.path().join("store");
        let err = import_image_archive(&archive, &store_dir).unwrap_err();
        assert!(
            err.to_string().contains("unsupported entry type"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn import_rejects_preexisting_symlink_in_store() {
        let tmp = tempfile::tempdir().unwrap();
        let escape_target = tmp.path().join("escaped");
        std::fs::create_dir_all(&escape_target).unwrap();

        // Create a clean archive with a file under disk_images/.
        let archive = build_malicious_archive(
            tmp.path(),
            "repo",
            "v1",
            &[RawEntry::File("repo/disk_images/gcp_disk.tar.gz", b"data")],
        );

        // Set up the store with a symlink at repo -> escaped/.
        // When import builds dest_dir = store/repo/v1, the "repo" component
        // follows the symlink, so files would land under escaped/v1/.
        let store_dir = tmp.path().join("store");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::os::unix::fs::symlink(&escape_target, store_dir.join("repo")).unwrap();

        let err = import_image_archive(&archive, &store_dir).unwrap_err();
        assert!(
            err.to_string().contains("symlink in store path"),
            "unexpected error: {err}"
        );
        // Nothing should have been written to the escape target.
        assert!(
            std::fs::read_dir(&escape_target).unwrap().next().is_none(),
            "escape target should remain empty"
        );
    }

    #[test]
    fn import_rejects_empty_manifest_name() {
        let err = validate_path_component("", "manifest name", Path::new("test.atabi")).unwrap_err();
        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn safe_relative_path_checks() {
        assert!(is_safe_relative_path(Path::new("disk_images/gcp_disk.tar.gz")));
        assert!(is_safe_relative_path(Path::new("secure_boot_certs/PK.crt")));
        assert!(!is_safe_relative_path(Path::new("../evil")));
        assert!(!is_safe_relative_path(Path::new("disk_images/../../evil")));
        assert!(!is_safe_relative_path(Path::new("/etc/passwd")));
    }
}
