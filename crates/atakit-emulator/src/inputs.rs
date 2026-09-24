//! Deterministic native inputs, without building or pulling an image.
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};
pub fn measured_files(root: &Path, declared: &[String]) -> Result<Vec<PathBuf>> {
    fn visit(root: &Path, relative: &Path, files: &mut BTreeSet<PathBuf>) -> Result<()> {
        if relative.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            bail!("invalid measured-data path");
        }
        let path = root.join(relative);
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| format!("missing measured data {}", path.display()))?;
        if meta.file_type().is_symlink() {
            bail!("measured-data symlinks are unsupported: {}", path.display());
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(path)? {
                visit(root, &relative.join(entry?.file_name()), files)?;
            }
        } else if meta.is_file() {
            files.insert(relative.into());
        } else {
            bail!("measured-data must be regular files or directories");
        }
        Ok(())
    }
    let mut files = BTreeSet::new();
    for path in declared {
        visit(root, Path::new(path.trim_start_matches('/')), &mut files)?;
    }
    Ok(files.into_iter().collect())
}
pub fn measurement(config_file: &Path, workload_dir: &Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(config_file)?;
    let value: toml::Value = toml::from_str(&text)?;
    let normalized = serde_json_canonicalizer::to_vec(&value)?;
    let config = atakit_workload::config::WorkloadConfig::from_file(config_file)?;
    let root = workload_dir.join("measured-data");
    let mut hash = Sha256::new();
    hash.update(b"ATAKIT_EMULATED_WORKLOAD_V1");
    hash.update((normalized.len() as u64).to_be_bytes());
    hash.update(normalized);
    for file in measured_files(&root, config.measured_data_paths())? {
        let name = file.to_str().context("measured data path is not UTF-8")?;
        let bytes = std::fs::read(root.join(&file))?;
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize().into())
}
