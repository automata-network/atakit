mod convert;
pub mod measure;
pub mod serialize;
mod summarize;
pub mod types;

mod manifest;
pub use manifest::*;

pub use measure::{
    MeasureConfig, MeasureError, MountedFile, ServiceMeasurement, WorkloadMeasurement,
    get_digest_from_docker_tar, measure,
};
pub use serialize::{resolve_image_short_name, service_to_yaml, to_yaml, validate_normalized};
pub use summarize::{ComposeAnalysis, analyze};
pub use types::*;

use anyhow::Result;
use compose_spec::Compose;

/// Parse a Docker Compose YAML string into a [`WorkloadCompose`],
/// rejecting unsupported features with collected error messages.
pub fn from_yaml_str(yaml: &str) -> Result<WorkloadCompose> {
    let compose = Compose::options()
        .apply_merge(true)
        .from_yaml_str(yaml)
        .map_err(|e| anyhow::anyhow!("parse compose file failed: {e:#}"))?;
    convert::convert(&compose)
}
