use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::info;

/// Create a FAT filesystem image containing all files from `source_dir`.
///
/// Returns `Ok(Some(output_path))` if the image was created, or `Ok(None)` if
/// `source_dir` doesn't exist or is empty.
pub fn create_additional_data_image(
    source_dir: &Path,
    output_path: &Path,
) -> Result<Option<PathBuf>> {
    if !source_dir.is_dir() {
        info!(dir = %source_dir.display(), "Additional-data directory not found, skipping");
        return Ok(None);
    }

    // Collect all files with relative paths and sizes.
    let mut entries: Vec<(PathBuf, u64)> = Vec::new();
    collect_files(source_dir, source_dir, &mut entries)?;

    if entries.is_empty() {
        info!(dir = %source_dir.display(), "Additional-data directory is empty, skipping");
        return Ok(None);
    }

    let total_content: u64 = entries.iter().map(|(_, sz)| *sz).sum();
    // Image size: at least 1MB, content * 2 + 64KB for FAT overhead, rounded
    // up to 1MB boundary (GCP disk size requirement).
    let min_size = (total_content * 2 + 64 * 1024).max(1024 * 1024);
    let image_size = round_up_mb(min_size);

    info!(
        files = entries.len(),
        total_bytes = total_content,
        image_size,
        output = %output_path.display(),
        "Creating additional-data FAT image"
    );

    // Step 1: Create and size the output file.
    {
        let file = std::fs::File::create(output_path)
            .with_context(|| format!("Failed to create {}", output_path.display()))?;
        file.set_len(image_size)
            .context("Failed to set image file size")?;
    }

    // Step 2: Format the volume.
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(output_path)
            .with_context(|| format!("Failed to open {} for formatting", output_path.display()))?;
        let buf = fscommon::BufStream::new(file);
        fatfs::format_volume(
            buf,
            fatfs::FormatVolumeOptions::new().volume_label(*b"ADDITIONAL "),
        )
        .context("Failed to format FAT volume")?;
    }

    // Step 3: Mount and write files.
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(output_path)
            .with_context(|| format!("Failed to open {} for writing", output_path.display()))?;
        let buf = fscommon::BufStream::new(file);
        let fs = fatfs::FileSystem::new(buf, fatfs::FsOptions::new())
            .context("Failed to mount FAT filesystem")?;
        let root = fs.root_dir();

        for (rel_path, _size) in &entries {
            // Ensure parent directories exist.
            if let Some(parent) = rel_path.parent() {
                if parent != Path::new("") {
                    create_dirs(&root, parent)?;
                }
            }

            let fat_path = rel_path.to_string_lossy().replace('\\', "/");
            let mut fat_file = root
                .create_file(&fat_path)
                .with_context(|| format!("Failed to create {} in FAT image", fat_path))?;

            let src_path = source_dir.join(rel_path);
            let content = std::fs::read(&src_path)
                .with_context(|| format!("Failed to read {}", src_path.display()))?;
            fat_file
                .write_all(&content)
                .with_context(|| format!("Failed to write {} to FAT image", fat_path))?;
            fat_file.flush()?;
        }
    }

    info!(path = %output_path.display(), "Additional-data FAT image created");
    Ok(Some(output_path.to_path_buf()))
}

/// Wrap a raw disk image as `disk.raw` inside a tar.gz archive.
///
/// GCP requires images to be uploaded as tar.gz with a `disk.raw` entry.
pub fn package_as_tar_gz(raw_path: &Path, output_path: &Path) -> Result<()> {
    let out_file = std::fs::File::create(output_path)
        .with_context(|| format!("Failed to create {}", output_path.display()))?;
    let encoder =
        flate2::write::GzEncoder::new(out_file, flate2::Compression::default());
    let mut tar_builder = tar::Builder::new(encoder);

    let mut header = tar::Header::new_gnu();
    let metadata = std::fs::metadata(raw_path)
        .with_context(|| format!("Failed to stat {}", raw_path.display()))?;
    header.set_size(metadata.len());
    header.set_mode(0o644);
    header.set_cksum();

    let raw_file = std::fs::File::open(raw_path)
        .with_context(|| format!("Failed to open {}", raw_path.display()))?;
    tar_builder
        .append_data(&mut header, "disk.raw", raw_file)
        .context("Failed to append disk.raw to tar")?;

    tar_builder.finish().context("Failed to finalize tar.gz")?;

    info!(
        src = %raw_path.display(),
        dest = %output_path.display(),
        "Packaged raw image as tar.gz"
    );
    Ok(())
}

/// Recursively collect all files under `base_dir` with their relative paths.
fn collect_files(
    base_dir: &Path,
    current_dir: &Path,
    out: &mut Vec<(PathBuf, u64)>,
) -> Result<()> {
    for entry in std::fs::read_dir(current_dir)
        .with_context(|| format!("Failed to read directory {}", current_dir.display()))?
    {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();

        if ft.is_dir() {
            collect_files(base_dir, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(base_dir)
                .context("Failed to compute relative path")?
                .to_path_buf();
            let size = entry.metadata()?.len();
            out.push((rel, size));
        }
    }
    Ok(())
}

/// Create directories recursively in the FAT filesystem.
fn create_dirs<IO: fatfs::ReadWriteSeek>(
    root: &fatfs::Dir<IO>,
    path: &Path,
) -> Result<()> {
    let mut current = String::new();
    for component in path.components() {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(&component.as_os_str().to_string_lossy());
        // create_dir is idempotent if the dir already exists.
        let _ = root.create_dir(&current);
    }
    Ok(())
}

/// Round `size` up to the next 1MB boundary.
fn round_up_mb(size: u64) -> u64 {
    let mb = 1024 * 1024;
    (size + mb - 1) / mb * mb
}
