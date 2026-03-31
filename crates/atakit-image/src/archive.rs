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
    let image_ref = ImageRef {
        repository: manifest.meta.name.clone(),
        tag: manifest.meta.version.clone(),
    };

    let dest_dir = store_base_dir
        .join(&image_ref.repository)
        .join(&image_ref.tag);

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

        let target = dest_dir.join(&relative);

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&target).map_err(|e| ImageError::CreateDir {
                path: target.clone(),
                source: e,
            })?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| ImageError::CreateDir {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
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
}
