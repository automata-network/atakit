use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::WorkloadError;

/// Compute the SHA-256 hash of a file, returning `"sha256:<hex>"`.
pub fn hash_file(path: &Path) -> Result<String, WorkloadError> {
    let mut file = std::fs::File::open(path).map_err(|e| WorkloadError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| WorkloadError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    let digest = hasher.finalize();
    Ok(format!("sha256:{:x}", digest))
}

/// Hash all files under a directory, returning archive-relative paths → hashes.
///
/// `base_dir` is the staging root (e.g. `staging/my-app/`).
/// `prefix` is the directory within the archive to scan (e.g. `"measured-data"`).
/// Keys are relative to `base_dir` (e.g. `"measured-data/config/hello"`).
pub fn hash_directory(
    base_dir: &Path,
    prefix: &str,
) -> Result<BTreeMap<String, String>, WorkloadError> {
    let dir = base_dir.join(prefix);
    if !dir.exists() {
        return Ok(BTreeMap::new());
    }

    let mut hashes = BTreeMap::new();
    collect_hashes(&dir, base_dir, &mut hashes)?;
    Ok(hashes)
}

fn collect_hashes(
    dir: &Path,
    base_dir: &Path,
    hashes: &mut BTreeMap<String, String>,
) -> Result<(), WorkloadError> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(WorkloadError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(WorkloadError::Io)?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_hashes(&path, base_dir, hashes)?;
        } else {
            let rel_path = path
                .strip_prefix(base_dir)
                .expect("path is under base_dir");
            let rel = rel_path
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<String>>()
                .join("/");
            let hash = hash_file(&path)?;
            hashes.insert(rel, hash);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_known_content() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("test.txt");
        std::fs::write(&file, "hello\n").unwrap();
        let h = hash_file(&file).unwrap();
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn hash_directory_collects_files() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let md = base.join("measured-data").join("config");
        std::fs::create_dir_all(&md).unwrap();
        std::fs::write(md.join("a.txt"), "aaa").unwrap();
        std::fs::write(md.join("b.txt"), "bbb").unwrap();

        let hashes = hash_directory(base, "measured-data").unwrap();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains_key("measured-data/config/a.txt"));
        assert!(hashes.contains_key("measured-data/config/b.txt"));
    }
}
