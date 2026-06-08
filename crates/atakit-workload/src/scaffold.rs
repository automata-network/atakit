use std::path::{Path, PathBuf};

use crate::WorkloadError;

const CONFIG_FILENAME: &str = "atakit-workload.toml";

/// Create a new workload directory with a starter `atakit-workload.toml`.
///
/// Returns the path to the created directory.
pub fn create_workload(base: &Path, name: &str) -> Result<PathBuf, WorkloadError> {
    validate_name(name)?;

    let dir = base.join(name);
    if dir.exists() {
        return Err(WorkloadError::AlreadyExists(dir));
    }

    std::fs::create_dir_all(&dir).map_err(|e| WorkloadError::CreateDir {
        path: dir.clone(),
        source: e,
    })?;

    let config_path = dir.join(CONFIG_FILENAME);
    let content = render_template(name);
    std::fs::write(&config_path, content).map_err(|e| WorkloadError::WriteFile {
        path: config_path,
        source: e,
    })?;

    Ok(dir)
}

fn validate_name(name: &str) -> Result<(), WorkloadError> {
    if name.is_empty()
        || name.starts_with('.')
        || name.starts_with('-')
        || name.contains('/')
        || name.contains('\\')
    {
        return Err(WorkloadError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn render_template(name: &str) -> String {
    include_str!("template.toml").replace("{{name}}", name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_directory_and_config() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = create_workload(tmp.path(), "my-app").unwrap();

        assert!(dir.is_dir());
        assert!(dir.join(CONFIG_FILENAME).is_file());

        let content = std::fs::read_to_string(dir.join(CONFIG_FILENAME)).unwrap();
        assert!(content.contains("format = 2"));
        assert!(content.contains("name = \"my-app\""));
        assert!(content.contains("version = \"v0.0.1\""));
        assert!(content.contains("base-image-mode = \"blacklist\""));
        assert!(content.contains("image = \"my-app:latest\""));
    }

    #[test]
    fn rejects_existing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("exists")).unwrap();

        let err = create_workload(tmp.path(), "exists").unwrap_err();
        assert!(matches!(err, WorkloadError::AlreadyExists(_)));
    }

    #[test]
    fn rejects_invalid_names() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["", ".hidden", "-dash", "a/b", "a\\b"] {
            assert!(
                create_workload(tmp.path(), name).is_err(),
                "should reject: {name:?}"
            );
        }
    }
}
