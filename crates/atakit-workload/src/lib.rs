pub mod archive;
pub mod build;
#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
pub mod data;
mod error;
pub mod hash;
pub mod image;
pub mod image_meta;
pub mod inspect;
pub mod manifest;
pub mod repository;
mod scaffold;
pub mod store;
pub mod validate;

pub use build::{build_workload, BuildOptions, BuildResult};
pub use error::WorkloadError;
pub use image::ContainerEngine;
pub use inspect::{
    inspect_workload, inspect_workload_archive_bytes, InspectOptions, InspectResult,
};
pub use repository::{
    hex_equal, GithubWorkloadRepository, HttpWorkloadRepository, RepositoryArchiveMeta,
    RepositoryFilters, UploadContext, WorkloadCoords, WorkloadRepository,
};
pub use scaffold::create_workload;
pub use store::{CachedChainSpec, WorkloadEntry, WorkloadMeta, WorkloadStore};

/// Current format version for `atakit-workload.toml` and `manifest.json`.
///
/// Format 7 added `meta.publisher`. It is the only supported format: a
/// workload's identifier is publisher-qualified, and no earlier manifest
/// records a publisher or allows one to be derived, so an older manifest cannot
/// yield the identifier its workload is registered under.
pub const FORMAT_VERSION: u32 = 7;
