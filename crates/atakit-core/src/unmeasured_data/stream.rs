//! File-backed production paths. Payload size never determines buffer size.
use super::*;
use std::io::{BufRead, BufReader, Seek};
use std::path::PathBuf;
use std::sync::Arc;

/// Exact private upload bytes. Serialized references keep resume records small.
#[derive(Clone, Serialize)]
pub struct Archive {
    path: PathBuf,
    pub length: u64,
    pub sha256: [u8; 32],
    #[serde(skip)]
    temporary: Option<Arc<tempfile::TempPath>>,
}
impl<'de> Deserialize<'de> for Archive {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input {
            File {
                path: PathBuf,
                length: u64,
                sha256: [u8; 32],
            },
            // Read existing private initialization records without changing them.
            Bytes(Vec<u8>),
        }
        match Input::deserialize(deserializer)? {
            Input::File {
                path,
                length,
                sha256,
            } => Ok(Self {
                path,
                length,
                sha256,
                temporary: None,
            }),
            Input::Bytes(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                Self::from_reader(bytes.as_slice()).map_err(serde::de::Error::custom)
            }
        }
    }
}
impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}
impl Archive {
    pub fn from_reader(mut source: impl Read) -> Result<Self, String> {
        let mut file = tempfile::NamedTempFile::new().map_err(|_| "create private upload file")?;
        std::io::copy(&mut source, &mut file).map_err(|_| "write private upload file")?;
        Self::from_temporary(file)
    }
    fn from_temporary(mut file: tempfile::NamedTempFile) -> Result<Self, String> {
        file.flush().map_err(|_| "flush upload")?;
        file.as_file_mut().rewind().map_err(|_| "rewind upload")?;
        let (length, sha256) = digest(file.as_file_mut())?;
        let path = file.into_temp_path();
        Ok(Self {
            path: path.to_path_buf(),
            length,
            sha256,
            temporary: Some(Arc::new(path)),
        })
    }
    pub fn open(&self) -> Result<File, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
            .map_err(|_| "open private upload file")?;
        if !file
            .metadata()
            .map_err(|_| "read upload metadata")?
            .is_file()
            || digest(&mut file)? != (self.length, self.sha256)
        {
            return Err("prepared unmeasured-data archive changed".into());
        }
        file.rewind().map_err(|_| "rewind upload")?;
        Ok(file)
    }
    /// Copy the prepared bytes beside the existing durable initialization record.
    pub fn save(&self, path: &Path) -> Result<Self, String> {
        let parent = path.parent().ok_or("upload path has no parent")?;
        fs::create_dir_all(parent).map_err(|_| "create private upload directory")?;
        let mut dest =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| "create saved upload")?;
        std::io::copy(&mut self.open()?, &mut dest).map_err(|_| "save prepared upload")?;
        dest.as_file()
            .sync_all()
            .map_err(|_| "flush saved upload")?;
        dest.persist(path).map_err(|_| "publish saved upload")?;
        flush_dir(parent)?;
        Ok(Self {
            path: path.into(),
            length: self.length,
            sha256: self.sha256,
            temporary: None,
        })
    }
    pub fn remove_saved(&self, expected: &Path) -> Result<(), String> {
        if self.temporary.is_none() && self.path == expected {
            match fs::remove_file(expected) {
                Ok(()) => flush_dir(expected.parent().ok_or("upload has no parent")?)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("remove saved upload".into()),
            }
        }
        Ok(())
    }
}
fn digest(source: &mut impl Read) -> Result<(u64, [u8; 32]), String> {
    let mut hash = Sha256::new();
    let mut length = 0u64;
    let mut buffer = zeroize::Zeroizing::new([0u8; 64 * 1024]);
    loop {
        let n = source.read(buffer.as_mut()).map_err(|_| "read upload")?;
        if n == 0 {
            break;
        }
        length = length
            .checked_add(n as u64)
            .ok_or("upload length overflow")?;
        hash.update(&buffer[..n]);
    }
    Ok((length, hash.finalize().into()))
}

/// Metadata only; open source files one at a time through a directory descriptor.
pub struct Tree {
    root: File,
    files: BTreeMap<String, fs::Metadata>,
}
fn same(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) == (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    )
}
impl Tree {
    pub fn collect(root: &Path, policy: &Policy) -> Result<Self, String> {
        let root =
            File::open(root).map_err(|_| "unmeasured-data source directory is unavailable")?;
        if !root
            .metadata()
            .map_err(|_| "read source metadata")?
            .is_dir()
        {
            return Err("unmeasured-data source must be a directory".into());
        }
        let mut files = BTreeMap::new();
        let mut entries = BTreeSet::new();
        for declared in &policy.paths {
            let path = relative(declared)?;
            let Some(mut file) = open_beneath(&root, path)? else {
                continue;
            };
            let before = file.metadata().map_err(|_| "read selected file metadata")?;
            if !before.is_file() {
                return Err("selected path is not a regular file".into());
            }
            if let Some(allowed) = policy.env.get(declared) {
                validate_env(&mut file, allowed)?;
                if !same(
                    &before,
                    &file.metadata().map_err(|_| "read selected file metadata")?,
                ) {
                    return Err("selected file changed while being read".into());
                }
            }
            files.insert(path.to_string(), before);
            if files.len() > MAX_FILES {
                return Err("too many unmeasured-data files".into());
            }
            let mut parent = Some(path);
            while let Some(path) = parent {
                if !entries.insert(path.to_owned()) {
                    break;
                }
                validate_tree_entry_count(entries.len())?;
                parent = path.rsplit_once('/').map(|(p, _)| p);
            }
        }
        Ok(Self { root, files })
    }
    pub fn paths(&self) -> impl Iterator<Item = &String> {
        self.files.keys()
    }
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
    pub fn len(&self) -> usize {
        self.files.len()
    }
    fn visit(
        &self,
        mut visit: impl FnMut(&str, &mut File, u64) -> Result<(), String>,
    ) -> Result<(), String> {
        for (path, before) in &self.files {
            let mut file = open_beneath(&self.root, path)?.ok_or("selected file disappeared")?;
            if !same(
                before,
                &file.metadata().map_err(|_| "read selected file metadata")?,
            ) {
                return Err("selected file changed while being read".into());
            }
            visit(path, &mut file, before.len())?;
            if !same(
                before,
                &file.metadata().map_err(|_| "read selected file metadata")?,
            ) {
                return Err("selected file changed while being read".into());
            }
        }
        Ok(())
    }
    /// Preserve the existing canonical content identity, including sorted paths.
    pub fn feed(&self, mut update: impl FnMut(&[u8])) -> Result<(), String> {
        update(&(self.files.len() as u64).to_be_bytes());
        self.visit(|path, file, length| {
            update(&(path.len() as u64).to_be_bytes());
            update(path.as_bytes());
            update(&length.to_be_bytes());
            let mut remaining = length;
            let mut buffer = zeroize::Zeroizing::new([0u8; 64 * 1024]);
            while remaining != 0 {
                let max = remaining.min(buffer.len() as u64) as usize;
                let n = file
                    .read(&mut buffer[..max])
                    .map_err(|_| "read selected file")?;
                if n == 0 {
                    return Err("selected file changed while being read".into());
                }
                remaining -= n as u64;
                update(&buffer[..n]);
            }
            Ok(())
        })
    }
}
fn validate_env(file: &mut File, allowed: &[String]) -> Result<(), String> {
    // Environment values themselves must be materialized when starting a service.
    // Validate line by line here; ordinary binary data never takes this path.
    let mut names = BTreeSet::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let mut line = zeroize::Zeroizing::new(line.map_err(|_| "env file is not UTF-8")?);
        line.push('\n');
        let values = parse_env(line.as_bytes(), allowed)
            .map_err(|reason| format!("env line {}: {reason}", i + 1))?;
        for (name, mut value) in values {
            value.zeroize();
            if !names.insert(name) {
                return Err("duplicate variable".into());
            }
        }
    }
    Ok(())
}
pub fn prepare_archive(tree: &Tree) -> Result<Archive, String> {
    prepare_archive_in(tree, &std::env::temp_dir())
}
pub fn prepare_archive_in(tree: &Tree, directory: &Path) -> Result<Archive, String> {
    fs::create_dir_all(directory).map_err(|_| "create upload cache directory")?;
    let file =
        tempfile::NamedTempFile::new_in(directory).map_err(|_| "create private upload file")?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    tree.visit(|path, file, length| {
        let mut header = tar::Header::new_gnu();
        header.set_size(length);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, file.take(length))
            .map_err(|_| "archive selected file (check available local disk space)".to_string())
    })?;
    let file = tar
        .into_inner()
        .map_err(|_| "finish data archive")?
        .finish()
        .map_err(|_| "finish compressed archive")?;
    Archive::from_temporary(file)
}

pub fn extract_archive(source: impl Read, staging: &Path, policy: &Policy) -> Result<(), String> {
    remove_tree(staging)?;
    fs::create_dir(staging).map_err(|_| "create data staging directory")?;
    fs::set_permissions(staging, fs::Permissions::from_mode(0o700))
        .map_err(|_| "protect staging directory")?;
    let result = (|| {
        let decoder = flate2::bufread::GzDecoder::new(BufReader::new(source));
        let mut tar = tar::Archive::new(decoder);
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
            if !policy.paths.contains(&format!("unmeasured-data/{path}")) {
                return Err("undeclared uploaded path".into());
            }
            let dest = staging.join(&path);
            fs::create_dir_all(dest.parent().ok_or("missing data parent")?)
                .map_err(|_| "create data directory")?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)
                .map_err(|_| "create data file")?;
            let expected = entry.size();
            let written = std::io::copy(&mut entry, &mut file)
                .map_err(|_| "write data file (check available boot-disk space)")?;
            if written != expected {
                return Err("incomplete tar entry".into());
            }
            file.set_permissions(fs::Permissions::from_mode(0o444))
                .map_err(|_| "protect data file")?;
            file.sync_all().map_err(|_| "flush data file")?;
        }
        // tar consumes the first zero block. Require the second, alignment, and
        // zero-only padding while driving gzip through its checked trailer.
        let mut decoder = tar.into_inner();
        let mut buffer = zeroize::Zeroizing::new([0u8; 64 * 1024]);
        let mut remaining = 0u64;
        loop {
            let n = decoder
                .read(buffer.as_mut())
                .map_err(|_| "invalid or incomplete compressed archive")?;
            if n == 0 {
                break;
            }
            if buffer[..n].iter().any(|v| *v != 0) {
                return Err("trailing archive data".into());
            }
            remaining = remaining
                .checked_add(n as u64)
                .ok_or("archive length overflow")?;
        }
        if remaining < 512 || !remaining.is_multiple_of(512) {
            return Err("missing tar terminator".into());
        }
        if !decoder
            .into_inner()
            .fill_buf()
            .map_err(|_| "read archive trailer")?
            .is_empty()
        {
            return Err("trailing compressed data".into());
        }
        Tree::collect(staging, policy)?;
        freeze(staging)?;
        flush_dir(staging.parent().ok_or("missing staging parent")?)
    })();
    if result.is_err() {
        let _ = remove_tree(staging);
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            paths: ["unmeasured-data/key".into()].into(),
            env: Default::default(),
        }
    }
    #[test]
    fn private_file_archive_roundtrip_and_saved_reference() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("key"), b"exact bytes\0\xff").unwrap();
        fs::write(root.path().join("extra"), b"ignored").unwrap();
        let tree = Tree::collect(root.path(), &policy()).unwrap();
        assert_eq!(tree.paths().collect::<Vec<_>>(), vec!["key"]);
        let archive = prepare_archive(&tree).unwrap();
        let saved = archive.save(&root.path().join("saved.tar.gz")).unwrap();
        let saved: Archive = serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
        drop(archive);
        let staging = root.path().join("staging");
        extract_archive(saved.open().unwrap(), &staging, &policy()).unwrap();
        assert_eq!(fs::read(staging.join("key")).unwrap(), b"exact bytes\0\xff");
        assert!(!staging.join("extra").exists());
        let mut before = Sha256::new();
        tree.feed(|b| before.update(b)).unwrap();
        let mut after = Sha256::new();
        Tree::collect(&staging, &policy())
            .unwrap()
            .feed(|b| after.update(b))
            .unwrap();
        assert_eq!(before.finalize(), after.finalize());
        saved
            .remove_saved(&root.path().join("saved.tar.gz"))
            .unwrap();
        assert!(!root.path().join("saved.tar.gz").exists());
        remove_tree(&staging).unwrap();
    }
    #[test]
    fn streamed_extraction_rejects_corrupt_truncated_and_trailing_data() {
        let root = tempfile::tempdir().unwrap();
        let encoded = archive(&Snapshot([("key".into(), b"bytes".to_vec())].into())).unwrap();
        let staging = root.path().join("staging");
        for n in [0, encoded.len() / 2, encoded.len() - 1, encoded.len() - 8] {
            assert!(extract_archive(&encoded[..n], &staging, &policy()).is_err());
            assert!(!staging.exists());
        }
        let mut corrupt = encoded.clone();
        let at = corrupt.len() - 8;
        corrupt[at] ^= 1;
        assert!(extract_archive(corrupt.as_slice(), &staging, &policy()).is_err());
        for tail in [b"trailing".as_slice(), encoded.as_slice()] {
            let mut trailing = encoded.clone();
            trailing.extend_from_slice(tail);
            assert!(extract_archive(trailing.as_slice(), &staging, &policy()).is_err());
        }
        let mut raw = Vec::new();
        flate2::read::GzDecoder::new(encoded.as_slice())
            .read_to_end(&mut raw)
            .unwrap();
        for length in [1024, raw.len() - 512] {
            let mut zip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            zip.write_all(&raw[..length]).unwrap();
            assert!(
                extract_archive(zip.finish().unwrap().as_slice(), &staging, &policy()).is_err()
            );
        }
    }
    #[test]
    fn streamed_collection_rejects_changed_sources_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("key"), b"old").unwrap();
        let tree = Tree::collect(root.path(), &policy()).unwrap();
        fs::write(root.path().join("key"), b"changed").unwrap();
        assert!(prepare_archive(&tree).is_err());
        fs::remove_file(root.path().join("key")).unwrap();
        std::os::unix::fs::symlink("extra", root.path().join("key")).unwrap();
        assert!(Tree::collect(root.path(), &policy()).is_err());
    }
    #[test]
    fn reads_preexisting_inline_initialization_archive() {
        let encoded = serde_json::to_vec(&b"existing archive".to_vec()).unwrap();
        let archive: Archive = serde_json::from_slice(&encoded).unwrap();
        let mut bytes = Vec::new();
        archive.open().unwrap().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"existing archive");
    }
}
