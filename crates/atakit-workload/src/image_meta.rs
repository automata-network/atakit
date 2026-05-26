//! Image metadata extraction from container tar archives.
//!
//! Reads the OCI **image config digest** (a.k.a. "image ID") from a
//! docker-archive or oci-archive tar produced by `podman save` / `docker save`.
//!
//! The image ID is `sha256(<image-config-blob-bytes>)`. It is what
//! `podman images --no-trunc` reports as IMAGE ID, and is the canonical
//! immutable identifier for a locally-loaded image. References by tag
//! (e.g. `name:latest`) are mutable; references by image ID are not.
//!
//! Pinning workload manifests to image IDs lets the portal run containers
//! by digest (`podman run sha256:<id>`), closing the gap where a malicious
//! `podman load` could rebind a tag between load and run.

use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::WorkloadError;

/// Read the image config digest ("image ID") from a docker-archive or
/// oci-archive container tar.
///
/// Returns `"sha256:<hex>"`.
///
/// Verifies the digest by hashing the actual config blob inside the tar
/// and comparing against the digest declared in `manifest.json` (or
/// `index.json`). A mismatch indicates a malformed or tampered archive.
pub fn read_image_id(tar_path: &Path) -> Result<String, WorkloadError> {
    let manifest_json = read_top_level_file(tar_path, "manifest.json")?;
    if let Some(content) = manifest_json {
        return read_image_id_docker_archive(tar_path, &content);
    }

    let index_json = read_top_level_file(tar_path, "index.json")?;
    if let Some(content) = index_json {
        return read_image_id_oci_archive(tar_path, &content);
    }

    Err(WorkloadError::Validation(format!(
        "image tar {} contains neither manifest.json nor index.json (not a recognised container archive)",
        tar_path.display()
    )))
}

// ── docker-archive ────────────────────────────────────────────

#[derive(Deserialize)]
struct DockerArchiveEntry {
    #[serde(rename = "Config")]
    config: String,
}

fn read_image_id_docker_archive(
    tar_path: &Path,
    manifest_json: &str,
) -> Result<String, WorkloadError> {
    let entries: Vec<DockerArchiveEntry> = serde_json::from_str(manifest_json).map_err(|e| {
        WorkloadError::Validation(format!(
            "image tar {}: failed to parse manifest.json: {e}",
            tar_path.display()
        ))
    })?;

    if entries.len() != 1 {
        return Err(WorkloadError::Validation(format!(
            "image tar {} contains {} images; exactly one is required",
            tar_path.display(),
            entries.len()
        )));
    }

    let config_path = &entries[0].config;
    let declared_hex = parse_config_filename(config_path).ok_or_else(|| {
        WorkloadError::Validation(format!(
            "image tar {}: unrecognised Config path {config_path:?}",
            tar_path.display()
        ))
    })?;

    let blob = read_file_in_tar(tar_path, config_path)?.ok_or_else(|| {
        WorkloadError::Validation(format!(
            "image tar {}: Config blob {config_path:?} not found in tar",
            tar_path.display()
        ))
    })?;

    let actual_hex = format!("{:x}", Sha256::digest(&blob));
    if !hex_eq_ci(&actual_hex, &declared_hex) {
        return Err(WorkloadError::Validation(format!(
            "image tar {}: Config blob hash {actual_hex} does not match declared {declared_hex}",
            tar_path.display()
        )));
    }

    Ok(format!("sha256:{actual_hex}"))
}

/// Parse the sha256 hex out of a docker-archive `Config` path. Returns the
/// hex string (lowercase) or None if the path doesn't fit either known
/// shape.
///
/// Handles two shapes seen in the wild:
/// - `"blobs/sha256/<hex>"` (newer; podman 4+ and modern docker)
/// - `"<hex>.json"` (older / legacy)
fn parse_config_filename(s: &str) -> Option<String> {
    if let Some(rest) = s.strip_prefix("blobs/sha256/") {
        if is_sha256_hex(rest) {
            return Some(rest.to_ascii_lowercase());
        }
    }
    if let Some(stem) = s.strip_suffix(".json") {
        if is_sha256_hex(stem) {
            return Some(stem.to_ascii_lowercase());
        }
    }
    None
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn hex_eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

// ── oci-archive ───────────────────────────────────────────────

#[derive(Deserialize)]
struct OciIndex {
    manifests: Vec<OciManifestDescriptor>,
}

#[derive(Deserialize)]
struct OciManifestDescriptor {
    digest: String,
}

#[derive(Deserialize)]
struct OciImageManifest {
    config: OciDescriptor,
}

#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
}

fn read_image_id_oci_archive(tar_path: &Path, index_json: &str) -> Result<String, WorkloadError> {
    let index: OciIndex = serde_json::from_str(index_json).map_err(|e| {
        WorkloadError::Validation(format!(
            "image tar {}: failed to parse index.json: {e}",
            tar_path.display()
        ))
    })?;

    if index.manifests.len() != 1 {
        return Err(WorkloadError::Validation(format!(
            "image tar {} index.json declares {} manifests; exactly one is required",
            tar_path.display(),
            index.manifests.len()
        )));
    }

    let manifest_digest = &index.manifests[0].digest;
    let manifest_blob_path = digest_to_blob_path(manifest_digest).ok_or_else(|| {
        WorkloadError::Validation(format!(
            "image tar {}: unrecognised manifest digest {manifest_digest:?}",
            tar_path.display()
        ))
    })?;

    let manifest_bytes = read_file_in_tar(tar_path, &manifest_blob_path)?.ok_or_else(|| {
        WorkloadError::Validation(format!(
            "image tar {}: image manifest blob {manifest_blob_path} not found",
            tar_path.display()
        ))
    })?;

    let image_manifest: OciImageManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| {
            WorkloadError::Validation(format!(
                "image tar {}: failed to parse image manifest: {e}",
                tar_path.display()
            ))
        })?;

    let config_digest = &image_manifest.config.digest;
    let config_hex = config_digest.strip_prefix("sha256:").ok_or_else(|| {
        WorkloadError::Validation(format!(
            "image tar {}: unsupported config digest algorithm {config_digest:?}",
            tar_path.display()
        ))
    })?;
    if !is_sha256_hex(config_hex) {
        return Err(WorkloadError::Validation(format!(
            "image tar {}: malformed config digest {config_digest:?}",
            tar_path.display()
        )));
    }

    let config_blob_path = digest_to_blob_path(config_digest).expect("validated above");
    let config_bytes = read_file_in_tar(tar_path, &config_blob_path)?.ok_or_else(|| {
        WorkloadError::Validation(format!(
            "image tar {}: config blob {config_blob_path} not found",
            tar_path.display()
        ))
    })?;

    let actual_hex = format!("{:x}", Sha256::digest(&config_bytes));
    if !hex_eq_ci(&actual_hex, config_hex) {
        return Err(WorkloadError::Validation(format!(
            "image tar {}: config blob hash {actual_hex} does not match declared {config_hex}",
            tar_path.display()
        )));
    }

    Ok(format!("sha256:{}", actual_hex))
}

fn digest_to_blob_path(digest: &str) -> Option<String> {
    let hex = digest.strip_prefix("sha256:")?;
    if !is_sha256_hex(hex) {
        return None;
    }
    Some(format!("blobs/sha256/{}", hex.to_ascii_lowercase()))
}

// ── tar reading ───────────────────────────────────────────────

/// Read a top-level (root-of-tar) file by name.
fn read_top_level_file(tar_path: &Path, name: &str) -> Result<Option<String>, WorkloadError> {
    let file = std::fs::File::open(tar_path).map_err(|e| WorkloadError::ReadFile {
        path: tar_path.to_path_buf(),
        source: e,
    })?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries().map_err(WorkloadError::Io)? {
        let mut entry = entry.map_err(WorkloadError::Io)?;
        let path = entry.path().map_err(WorkloadError::Io)?;
        let path_str = path.to_string_lossy();
        if path_str == name || path_str == format!("./{name}") {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .map_err(WorkloadError::Io)?;
            return Ok(Some(content));
        }
    }
    Ok(None)
}

/// Read a specific entry from the tar by its archive-relative path.
fn read_file_in_tar(tar_path: &Path, entry_path: &str) -> Result<Option<Vec<u8>>, WorkloadError> {
    let file = std::fs::File::open(tar_path).map_err(|e| WorkloadError::ReadFile {
        path: tar_path.to_path_buf(),
        source: e,
    })?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries().map_err(WorkloadError::Io)? {
        let mut entry = entry.map_err(WorkloadError::Io)?;
        let path = entry.path().map_err(WorkloadError::Io)?;
        let path_str = path.to_string_lossy();
        if path_str == entry_path || path_str == format!("./{entry_path}") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(WorkloadError::Io)?;
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build an in-memory tar containing the listed files at the given paths.
    fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut buf);
            for (name, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, name, *content).unwrap();
            }
            tar.finish().unwrap();
        }
        buf
    }

    fn write_tmp_tar(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    fn config_blob() -> Vec<u8> {
        // Minimal but valid-shaped image config JSON. The parser only cares
        // about bytes-and-hash, so the contents need not match a real image.
        br#"{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":[]}}"#.to_vec()
    }

    fn config_hex(blob: &[u8]) -> String {
        format!("{:x}", Sha256::digest(blob))
    }

    #[test]
    fn parse_config_filename_blobs_path() {
        let h = "a".repeat(64);
        assert_eq!(
            parse_config_filename(&format!("blobs/sha256/{h}")),
            Some(h.clone())
        );
    }

    #[test]
    fn parse_config_filename_legacy_json() {
        let h = "0123456789abcdef".repeat(4); // 64 hex chars
        assert_eq!(parse_config_filename(&format!("{h}.json")), Some(h));
    }

    #[test]
    fn parse_config_filename_rejects_garbage() {
        assert_eq!(parse_config_filename("not-a-hash.json"), None);
        assert_eq!(parse_config_filename("blobs/sha256/short"), None);
        assert_eq!(parse_config_filename("blobs/md5/abc"), None);
        assert_eq!(parse_config_filename(""), None);
    }

    #[test]
    fn docker_archive_blobs_style() {
        let blob = config_blob();
        let hex = config_hex(&blob);
        let manifest =
            format!(r#"[{{"Config":"blobs/sha256/{hex}","RepoTags":["x:latest"],"Layers":[]}}]"#);
        let tar = build_tar(&[
            ("manifest.json", manifest.as_bytes()),
            (&format!("blobs/sha256/{hex}"), &blob),
        ]);
        let f = write_tmp_tar(&tar);
        let id = read_image_id(f.path()).unwrap();
        assert_eq!(id, format!("sha256:{hex}"));
    }

    #[test]
    fn docker_archive_legacy_json_style() {
        let blob = config_blob();
        let hex = config_hex(&blob);
        let manifest =
            format!(r#"[{{"Config":"{hex}.json","RepoTags":["x:latest"],"Layers":[]}}]"#);
        let tar = build_tar(&[
            ("manifest.json", manifest.as_bytes()),
            (&format!("{hex}.json"), &blob),
        ]);
        let f = write_tmp_tar(&tar);
        let id = read_image_id(f.path()).unwrap();
        assert_eq!(id, format!("sha256:{hex}"));
    }

    #[test]
    fn rejects_multi_image_manifest() {
        let blob = config_blob();
        let hex = config_hex(&blob);
        let manifest = format!(
            r#"[
                {{"Config":"blobs/sha256/{hex}","RepoTags":["a:latest"],"Layers":[]}},
                {{"Config":"blobs/sha256/{hex}","RepoTags":["b:latest"],"Layers":[]}}
            ]"#
        );
        let tar = build_tar(&[
            ("manifest.json", manifest.as_bytes()),
            (&format!("blobs/sha256/{hex}"), &blob),
        ]);
        let f = write_tmp_tar(&tar);
        let err = read_image_id(f.path()).unwrap_err();
        assert!(format!("{err}").contains("contains 2 images"));
    }

    #[test]
    fn rejects_corrupt_config_blob() {
        let blob = config_blob();
        let hex = config_hex(&blob);
        let tampered = b"this is not the config you are looking for";
        let manifest =
            format!(r#"[{{"Config":"blobs/sha256/{hex}","RepoTags":["x:latest"],"Layers":[]}}]"#);
        let tar = build_tar(&[
            ("manifest.json", manifest.as_bytes()),
            (&format!("blobs/sha256/{hex}"), tampered),
        ]);
        let f = write_tmp_tar(&tar);
        let err = read_image_id(f.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("does not match declared"), "msg: {msg}");
    }

    #[test]
    fn rejects_missing_config_blob() {
        let hex = "f".repeat(64);
        let manifest =
            format!(r#"[{{"Config":"blobs/sha256/{hex}","RepoTags":["x:latest"],"Layers":[]}}]"#);
        let tar = build_tar(&[("manifest.json", manifest.as_bytes())]);
        let f = write_tmp_tar(&tar);
        let err = read_image_id(f.path()).unwrap_err();
        assert!(format!("{err}").contains("not found in tar"));
    }

    #[test]
    fn oci_archive_basic() {
        let blob = config_blob();
        let cfg_hex = config_hex(&blob);

        // Build a minimal OCI image manifest that references the config blob.
        let img_manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{cfg_hex}","size":{}}},"layers":[]}}"#,
            blob.len()
        );
        let mfst_hex = format!("{:x}", Sha256::digest(img_manifest.as_bytes()));
        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{mfst_hex}","size":{}}}]}}"#,
            img_manifest.len()
        );

        let tar = build_tar(&[
            ("index.json", index.as_bytes()),
            (&format!("blobs/sha256/{mfst_hex}"), img_manifest.as_bytes()),
            (&format!("blobs/sha256/{cfg_hex}"), &blob),
        ]);
        let f = write_tmp_tar(&tar);
        let id = read_image_id(f.path()).unwrap();
        assert_eq!(id, format!("sha256:{cfg_hex}"));
    }

    #[test]
    fn rejects_unrecognised_archive() {
        let tar = build_tar(&[("README", b"not an image archive")]);
        let f = write_tmp_tar(&tar);
        let err = read_image_id(f.path()).unwrap_err();
        assert!(format!("{err}").contains("not a recognised container archive"));
    }
}
