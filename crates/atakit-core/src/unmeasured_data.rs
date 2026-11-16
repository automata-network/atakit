//! Shared deployment/update collection, validation and staging. Errors never include values.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::fs::{MetadataExt, PermissionsExt},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path},
};
use zeroize::Zeroize;

mod stream;
pub use stream::{extract_archive, prepare_archive, prepare_archive_in, Archive, Tree};
pub const MAX_FILES: usize = 4096;
/// Files plus unique parent directories, excluding the root of the data tree.
pub const MAX_TREE_ENTRIES: usize = MAX_FILES * 16;
pub const MAX_MANIFEST: usize = 1024 * 1024;

pub fn validate_tree_entry_count(count: usize) -> Result<(), String> {
    if count > MAX_TREE_ENTRIES {
        return Err("unmeasured-data exceeds directory entry limit".into());
    }
    Ok(())
}

fn validate_snapshot_limits(files: &Snapshot) -> Result<(), String> {
    if files.0.len() > MAX_FILES {
        return Err("too many unmeasured-data files".into());
    }
    let mut entries = BTreeSet::new();
    for path in files.0.keys() {
        safe_path(path)?;
        let mut entry = path.as_str();
        loop {
            // A previously counted directory already includes all its parents.
            if !entries.insert(entry) {
                break;
            }
            validate_tree_entry_count(entries.len())?;
            let Some((parent, _)) = entry.rsplit_once('/') else {
                break;
            };
            entry = parent;
        }
    }
    Ok(())
}

#[derive(Clone, Default, Deserialize)]
pub struct Policy {
    #[serde(default, rename = "unmeasured-data")]
    pub paths: BTreeSet<String>,
    #[serde(default, rename = "unmeasured-env-files")]
    pub env: BTreeMap<String, Vec<String>>,
}
impl Policy {
    pub fn from_manifest(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_MANIFEST {
            return Err("manifest exceeds size limit".into());
        }
        let policy: Self = serde_json::from_slice(bytes).map_err(|_| "invalid manifest")?;
        for path in &policy.paths {
            relative(path)?;
        }
        for path in policy.env.keys() {
            if !policy.paths.contains(path) {
                return Err("env file is not a declared data path".into());
            }
        }
        Ok(policy)
    }
    pub fn validate(&self, files: &Snapshot) -> Result<(), String> {
        validate_snapshot_limits(files)?;
        for (path, bytes) in &files.0 {
            let declared = format!("unmeasured-data/{path}");
            if !self.paths.contains(&declared) {
                return Err(format!("undeclared uploaded path {path:?}"));
            }
            if let Some(allowed) = self.env.get(&declared) {
                parse_env(bytes, allowed).map_err(|e| format!("env file {path:?}: {e}"))?;
            }
        }
        Ok(())
    }
}

/// Small in-memory fixtures and empty-tree preparation. Production payloads use
/// `Tree`, `prepare_archive_in` and `extract_archive` instead.
#[derive(Default)]
pub struct Snapshot(pub BTreeMap<String, Vec<u8>>);
impl Drop for Snapshot {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

pub fn safe_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|v| v.is_empty() || v == "." || v == "..")
        || Path::new(path)
            .components()
            .any(|v| !matches!(v, Component::Normal(_)))
    {
        return Err("unsafe unmeasured-data path".into());
    }
    Ok(())
}
fn relative(path: &str) -> Result<&str, String> {
    let value = path
        .strip_prefix("unmeasured-data/")
        .ok_or("invalid declared data path")?;
    safe_path(value)?;
    Ok(value)
}

/// Existing env syntax: trim lines, comments, KEY=VALUE, unique declared names.
pub fn parse_env(bytes: &[u8], allowed: &[String]) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "env file is not UTF-8")?;
    let mut values = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected KEY=VALUE", index + 1))?;
        let name = name.trim();
        let valid = !name.is_empty()
            && name.bytes().enumerate().all(|(i, c)| {
                c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
            });
        let reason = if !valid {
            Some("invalid environment variable name")
        } else if name.starts_with("ATAKIT_") || name.starts_with("VERIFIERD_") {
            Some("reserved environment variable name")
        } else if !allowed.iter().any(|v| v == name) {
            Some("variable is not in its measured allowlist")
        } else if values.contains_key(name) {
            Some("duplicate variable")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(format!("line {}: {reason}", index + 1));
        }
        if value.contains('\0') {
            return Err(format!("line {}: invalid environment value", index + 1));
        }
        values.insert(name.into(), value.trim().into());
    }
    Ok(values)
}

// Traverse directory descriptors so a concurrent symlink replacement cannot escape the root.
fn open_beneath(root: &File, path: &str) -> Result<Option<File>, String> {
    safe_path(path)?;
    let mut dir = root.try_clone().map_err(|_| "read source directory")?;
    let parts: Vec<_> = path.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        let name = std::ffi::CString::new(*part).map_err(|_| "invalid path")?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if index + 1 < parts.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(format!("cannot read selected file {path:?}"));
        }
        dir = unsafe { File::from_raw_fd(fd) };
    }
    Ok(Some(dir))
}

pub fn collect(root: &Path, policy: &Policy) -> Result<Snapshot, String> {
    let dir = File::open(root).map_err(|_| "unmeasured-data source directory is unavailable")?;
    if !dir
        .metadata()
        .map_err(|_| "read source directory")?
        .is_dir()
    {
        return Err("unmeasured-data source must be a directory".into());
    }
    let mut result = Snapshot::default();
    for declared in &policy.paths {
        let path = relative(declared)?;
        let Some(file) = open_beneath(&dir, path)? else {
            continue;
        };
        let before = file.metadata().map_err(|_| "read selected file metadata")?;
        if !before.is_file() {
            return Err(format!("selected path {path:?} is not a regular file"));
        }
        let mut bytes = Vec::new();
        (&file)
            .read_to_end(&mut bytes)
            .map_err(|_| "read selected file")?;
        let after = file.metadata().map_err(|_| "read selected file metadata")?;
        if before.len() != bytes.len() as u64
            || before.len() != after.len()
            || (
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            )
        {
            return Err("selected file changed while being read".into());
        }
        result.0.insert(path.into(), bytes);
    }
    policy.validate(&result)?;
    Ok(result)
}

pub fn archive(files: &Snapshot) -> Result<Vec<u8>, String> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    for (path, bytes) in &files.0 {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, bytes.as_slice())
            .map_err(|_| "build data archive")?;
    }
    let bytes = tar
        .into_inner()
        .map_err(|_| "finish data archive")?
        .finish()
        .map_err(|_| "finish compressed archive")?;
    Ok(bytes)
}

pub fn decode_archive(bytes: &[u8], policy: &Policy) -> Result<Snapshot, String> {
    if bytes.is_empty() {
        return Err("invalid data archive size".into());
    }
    let mut decoder = flate2::bufread::GzDecoder::new(bytes);
    let mut decoded = zeroize::Zeroizing::new(Vec::new());
    // Include bounded tar headers/padding; read through gzip's trailer to verify its CRC.
    decoder
        .read_to_end(&mut decoded)
        .map_err(|_| "invalid or incomplete compressed archive")?;
    if !decoder.into_inner().is_empty() {
        return Err("trailing compressed data".into());
    }
    if decoded.len() < 1024 || decoded.len() % 512 != 0 {
        return Err("incomplete tar archive".into());
    }
    let mut tar = tar::Archive::new(decoded.as_slice());
    let mut result = Snapshot::default();
    let mut seen = BTreeSet::new();
    for entry in tar.entries().map_err(|_| "invalid tar archive")? {
        let mut entry = entry.map_err(|_| "invalid tar entry")?;
        let path = entry
            .path()
            .map_err(|_| "invalid tar path")?
            .to_str()
            .ok_or("tar path is not UTF-8")?
            .trim_end_matches('/')
            .to_string();
        safe_path(&path)?;
        if !seen.insert(path.clone()) || seen.len() > MAX_FILES {
            return Err("duplicate path or too many archive entries".into());
        }
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            if entry.size() != 0 {
                return Err("nonempty directory entry".into());
            }
            continue;
        }
        if !kind.is_file() {
            return Err("links and special files are forbidden".into());
        }
        let mut content = Vec::new();
        entry
            .read_to_end(&mut content)
            .map_err(|_| "incomplete tar entry")?;
        if content.len() as u64 != entry.size() {
            return Err("incomplete tar entry".into());
        }
        result.0.insert(path, content);
    }
    // tar stops after the first zero block. Require the second and only zero padding after it.
    let remainder = tar.into_inner();
    if remainder.len() < 512 || remainder.iter().any(|v| *v != 0) {
        return Err("missing tar terminator or trailing archive data".into());
    }
    policy.validate(&result)?;
    Ok(result)
}

pub fn flush_dir(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "flush data directory".into())
}
pub fn remove_tree(path: &Path) -> Result<(), String> {
    if !path.try_exists().map_err(|_| "inspect data directory")? {
        return Ok(());
    }
    fn writable(path: &Path) -> std::io::Result<()> {
        if fs::symlink_metadata(path)?.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            for entry in fs::read_dir(path)? {
                writable(&entry?.path())?;
            }
        }
        Ok(())
    }
    writable(path)
        .and_then(|_| fs::remove_dir_all(path))
        .map_err(|_| "remove data directory".into())
}
pub fn prepare(files: &Snapshot, staging: &Path) -> Result<(), String> {
    validate_snapshot_limits(files)?;
    remove_tree(staging)?;
    fs::create_dir(staging).map_err(|_| "create data staging directory")?;
    fs::set_permissions(staging, fs::Permissions::from_mode(0o700))
        .map_err(|_| "protect staging directory")?;
    for (path, bytes) in &files.0 {
        safe_path(path)?;
        let dest = staging.join(path);
        fs::create_dir_all(dest.parent().unwrap()).map_err(|_| "create data directory")?;
        let mut file = File::create(&dest).map_err(|_| "create data file")?;
        file.write_all(bytes).map_err(|_| "write data file")?;
        file.set_permissions(fs::Permissions::from_mode(0o444))
            .map_err(|_| "protect data file")?;
        file.sync_all().map_err(|_| "flush data file")?;
    }
    fn freeze(path: &Path) -> Result<(), String> {
        for entry in fs::read_dir(path).map_err(|_| "read staging directory")? {
            let entry = entry.map_err(|_| "read staging directory")?;
            if entry.file_type().map_err(|_| "read data type")?.is_dir() {
                freeze(&entry.path())?;
            }
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o555))
            .map_err(|_| "protect data directory")?;
        flush_dir(path)
    }
    freeze(staging)?;
    flush_dir(staging.parent().ok_or("missing staging parent")?)
}

/// The deployment backup/rename sequence, shared by update publication and activation.
/// Caller journals intent first, commits state afterwards, then removes the backup.
pub fn replace_directory(staging: &Path, dest: &Path, backup: &Path) -> Result<(), String> {
    let parent = dest.parent().ok_or("missing data parent")?;
    if dest.try_exists().map_err(|_| "inspect active directory")? {
        if backup
            .try_exists()
            .map_err(|_| "inspect backup directory")?
        {
            return Err("data replacement requires recovery".into());
        }
        fs::rename(dest, backup).map_err(|_| "move previous data aside")?;
        flush_dir(parent)?;
    }
    fs::rename(staging, dest).map_err(|_| "publish prepared data")?;
    flush_dir(parent)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub manifest_hash: String,
    pub boot_id: String,
    pub challenge: String,
    pub archive_length: u64,
    pub archive_sha256: String,
}
pub fn request_digest(tls: &str, operation: &str, authorization: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in [
        b"atakit/unmeasured-data/request/v1".as_slice(),
        tls.as_bytes(),
        operation.as_bytes(),
        authorization,
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            paths: ["unmeasured-data/a.env".into(), "unmeasured-data/key".into()].into(),
            env: [("unmeasured-data/a.env".into(), vec!["TOKEN".into()])].into(),
        }
    }
    #[test]
    fn snapshot_archive_and_staging_count_files_and_unique_parent_directories() {
        // 1,024 independent trees of 63 directories plus one file: exactly 65,536 entries.
        let parents = vec!["d"; 62].join("/");
        let mut files = Snapshot::default();
        for i in 0..1024 {
            files.0.insert(format!("{i}/{parents}/key"), Vec::new());
        }
        let extra = format!("0/{parents}/extra");
        let policy = Policy {
            paths: files
                .0
                .keys()
                .chain(std::iter::once(&extra))
                .map(|path| format!("unmeasured-data/{path}"))
                .collect(),
            env: Default::default(),
        };
        policy.validate(&files).unwrap();
        decode_archive(&archive(&files).unwrap(), &policy).unwrap();
        files.0.insert(extra, Vec::new());
        let expected = "unmeasured-data exceeds directory entry limit";
        assert_eq!(policy.validate(&files).unwrap_err(), expected);
        assert_eq!(
            decode_archive(&archive(&files).unwrap(), &policy)
                .err()
                .unwrap(),
            expected
        );
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("keep"), b"previous").unwrap();
        assert_eq!(prepare(&files, &staging).unwrap_err(), expected);
        assert_eq!(fs::read(staging.join("keep")).unwrap(), b"previous");
    }

    #[test]
    fn shared_parent_directories_are_counted_only_once() {
        let parents = vec!["shared"; 32].join("/");
        let files = Snapshot(
            (0..MAX_FILES)
                .map(|i| (format!("{parents}/{i}"), Vec::new()))
                .collect(),
        );
        let policy = Policy {
            paths: files
                .0
                .keys()
                .map(|path| format!("unmeasured-data/{path}"))
                .collect(),
            env: Default::default(),
        };
        policy.validate(&files).unwrap();
        decode_archive(&archive(&files).unwrap(), &policy).unwrap();
    }

    #[test]
    fn shared_collection_roundtrip_skips_extras_and_preserves_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.env"), b"# comment\nTOKEN= value\n").unwrap();
        fs::write(dir.path().join("extra"), b"not uploaded").unwrap();
        let files = collect(dir.path(), &policy()).unwrap();
        assert_eq!(files.0.len(), 1);
        let decoded = decode_archive(&archive(&files).unwrap(), &policy()).unwrap();
        assert_eq!(decoded.0, files.0);
        let staging = dir.path().join("staging");
        prepare(&decoded, &staging).unwrap();
        assert_eq!(
            fs::read(staging.join("a.env")).unwrap(),
            b"# comment\nTOKEN= value\n"
        );
        assert_eq!(
            fs::metadata(staging.join("a.env"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        remove_tree(&staging).unwrap();
    }
    #[test]
    fn deliberate_empty_archive_is_valid_but_missing_folder_or_body_is_not() {
        let files = Snapshot::default();
        assert!(decode_archive(&archive(&files).unwrap(), &policy())
            .unwrap()
            .0
            .is_empty());
        assert!(decode_archive(&[], &policy()).is_err());
        let root = tempfile::tempdir().unwrap();
        assert!(collect(&root.path().join("missing"), &Policy::default()).is_err());
    }
    #[test]
    fn rejects_truncated_compression_trailer_and_tar_terminator() {
        let files = Snapshot([("key".into(), b"bytes".to_vec())].into());
        let encoded = archive(&files).unwrap();
        for n in [0, encoded.len() / 2, encoded.len() - 1, encoded.len() - 8] {
            assert!(decode_archive(&encoded[..n], &policy()).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(b"trailing");
        assert!(decode_archive(&trailing, &policy()).is_err());
        let mut raw = Vec::new();
        flate2::read::GzDecoder::new(encoded.as_slice())
            .read_to_end(&mut raw)
            .unwrap();
        // Valid gzip containing only a complete tar entry, with no end markers.
        raw.truncate(1024);
        let mut zip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        zip.write_all(&raw).unwrap();
        assert!(decode_archive(&zip.finish().unwrap(), &policy()).is_err());
    }
    #[test]
    fn rejects_undeclared_paths_links_and_duplicate_entries() {
        let files = Snapshot([("extra".into(), vec![1])].into());
        assert!(decode_archive(&archive(&files).unwrap(), &policy()).is_err());
        for kind in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Fifo,
            tar::EntryType::Regular,
        ] {
            let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            ));
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_size(0);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, "key", std::io::empty()).unwrap();
            if kind.is_file() {
                tar.append_data(&mut h, "key", std::io::empty()).unwrap();
            }
            let bytes = tar.into_inner().unwrap().finish().unwrap();
            assert!(decode_archive(&bytes, &policy()).is_err());
        }
    }
    #[test]
    fn rejects_source_links_and_invalid_env_without_echoing_values() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("private"), b"secret").unwrap();
        std::os::unix::fs::symlink("private", root.path().join("key")).unwrap();
        assert!(collect(root.path(), &policy()).is_err());
        fs::remove_file(root.path().join("key")).unwrap();
        for content in [
            "NOT_ALLOWED=secret",
            "TOKEN=secret\nTOKEN=again",
            "secret line",
            "ATAKIT_X=secret",
            "VERIFIERD_X=secret",
        ] {
            fs::write(root.path().join("a.env"), content).unwrap();
            let error = collect(root.path(), &policy()).err().unwrap();
            assert!(!error.contains("secret"));
        }
    }
    #[test]
    fn authorization_binds_operation_instance_and_exact_envelope() {
        let original = request_digest("tls", "update", b"payload");
        assert_ne!(original, request_digest("other", "update", b"payload"));
        assert_ne!(original, request_digest("tls", "discard", b"payload"));
        assert_ne!(original, request_digest("tls", "update", b"altered"));
    }
}
