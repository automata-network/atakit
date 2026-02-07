use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use workload_compose::ComposeSummary;

use crate::types::WorkloadDef;

/// Result of analyzing a docker-compose file.
pub struct ComposeAnalysis {
    /// Path to the docker-compose file (relative to project root).
    pub compose_path: PathBuf,
    /// Files that are included in measurement (bundled into package).
    pub measured_files: Vec<PathBuf>,
    /// Files under additional-data/ that are excluded (operator-provided).
    pub additional_data_files: Vec<PathBuf>,
    /// The compose summary from workload-compose.
    pub summary: ComposeSummary,
}

/// Analyze the docker-compose file referenced by a workload definition.
pub fn analyze(project_dir: &Path, wl_def: &WorkloadDef) -> Result<ComposeAnalysis> {
    let compose_rel = PathBuf::from(&wl_def.docker_compose);
    let compose_abs = project_dir.join(&compose_rel);

    let content = std::fs::read_to_string(&compose_abs)
        .with_context(|| format!("Failed to read {}", compose_abs.display()))?;

    let compose = workload_compose::from_yaml_str(&content)
        .with_context(|| format!("Failed to parse {}", compose_abs.display()))?;

    // The directory containing the docker-compose file is the context base for
    // resolving relative paths within the compose file.
    let compose_dir = compose_abs.parent().unwrap_or(Path::new("."));

    let summary = compose.summarize();

    // Normalize paths from compose-relative to project-relative.
    let mut measured_files: Vec<PathBuf> = summary
        .measured_files()
        .iter()
        .map(|f| normalize_compose_path(compose_dir, &f.path, project_dir))
        .collect();

    let mut additional_data_files: Vec<PathBuf> = summary
        .additional_data_files()
        .iter()
        .map(|f| normalize_compose_path(compose_dir, &f.path, project_dir))
        .collect();

    measured_files.sort();
    measured_files.dedup();
    additional_data_files.sort();
    additional_data_files.dedup();

    Ok(ComposeAnalysis {
        compose_path: compose_rel,
        measured_files,
        additional_data_files,
        summary,
    })
}

/// Resolve a path from the docker-compose file to a project-relative path.
fn normalize_compose_path(compose_dir: &Path, raw: &str, project_dir: &Path) -> PathBuf {
    let abs = if raw.starts_with('/') {
        PathBuf::from(raw)
    } else {
        compose_dir.join(raw)
    };

    // Make relative to project root.
    abs.strip_prefix(project_dir)
        .map(|p| p.to_path_buf())
        .unwrap_or(abs)
}
