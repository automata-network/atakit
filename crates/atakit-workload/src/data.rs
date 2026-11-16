use std::path::{Component, Path, PathBuf};

use crate::WorkloadError;

pub const DEFAULT_MEASURED_DATA_ROOT: &str = "measured-data";
pub const DEFAULT_UNMEASURED_DATA_ROOT: &str = "unmeasured-data";

#[derive(Debug, Clone)]
pub struct DataRoots {
    pub measured: PathBuf,
    pub unmeasured: PathBuf,
}

impl DataRoots {
    pub fn resolve(
        workload_dir: &Path,
        measured_data_root: Option<&PathBuf>,
        unmeasured_data_root: Option<&PathBuf>,
    ) -> Self {
        Self {
            measured: resolve_root(workload_dir, measured_data_root, DEFAULT_MEASURED_DATA_ROOT),
            unmeasured: resolve_root(
                workload_dir,
                unmeasured_data_root,
                DEFAULT_UNMEASURED_DATA_ROOT,
            ),
        }
    }
}

pub fn default_unmeasured_data_root(workload_dir: &Path) -> PathBuf {
    workload_dir.join(DEFAULT_UNMEASURED_DATA_ROOT)
}

fn resolve_root(workload_dir: &Path, override_root: Option<&PathBuf>, default: &str) -> PathBuf {
    override_root
        .cloned()
        .unwrap_or_else(|| workload_dir.join(default))
}

pub fn validate_logical_data_path(path: &str, context: &str) -> Result<String, WorkloadError> {
    if path.as_bytes().contains(&0) {
        return Err(WorkloadError::Validation(format!(
            "{context}: path must not contain NUL: {path:?}"
        )));
    }
    if path.contains('\\') {
        return Err(WorkloadError::Validation(format!(
            "{context}: path must use '/' separators: {path:?}"
        )));
    }
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(WorkloadError::Validation(format!(
            "{context} path must be a logical absolute path starting with exactly one '/': {path:?}"
        )));
    }
    if path[1..].contains("//") {
        return Err(WorkloadError::Validation(format!(
            "{context}: path must not contain empty components: {path:?}"
        )));
    }
    if path == "/." || path.contains("/./") || path.ends_with("/.") {
        return Err(WorkloadError::Validation(format!(
            "{context}: path must not contain '.': {path:?}"
        )));
    }
    let rel = logical_data_path_rel(path);
    let p = Path::new(&rel);
    for component in p.components() {
        match component {
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(WorkloadError::Validation(format!(
                    "{context}: path must not escape its data root: {path:?}"
                )));
            }
            Component::CurDir => {
                return Err(WorkloadError::Validation(format!(
                    "{context}: path must not contain '.': {path:?}"
                )));
            }
            Component::Normal(_) => {}
        }
    }
    Ok(rel)
}

pub fn logical_data_path_rel(path: &str) -> String {
    path.strip_prefix('/')
        .unwrap_or(path)
        .trim_end_matches('/')
        .to_string()
}

pub fn namespaced_data_path(prefix: &str, path: &str) -> String {
    let rel = logical_data_path_rel(path);
    if rel.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}/{rel}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_logical_absolute_data_paths() {
        assert_eq!(
            validate_logical_data_path("/config/app.conf", "package measured-data").unwrap(),
            "config/app.conf"
        );
        assert_eq!(
            validate_logical_data_path("/", "package measured-data").unwrap(),
            ""
        );
        assert_eq!(
            validate_logical_data_path("/config/", "package measured-data").unwrap(),
            "config"
        );
    }

    #[test]
    fn rejects_non_logical_data_paths() {
        for bad in [
            "config/app.conf",
            "./config/app.conf",
            "//config/app.conf",
            "/config//app.conf",
            "/../config/app.conf",
            "/config/./app.conf",
            "/config\\app.conf",
        ] {
            assert!(
                validate_logical_data_path(bad, "package measured-data").is_err(),
                "should reject {bad:?}"
            );
        }
    }
}
