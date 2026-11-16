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
mod manifest_normalization;
pub mod repository;
mod scaffold;
pub mod store;
pub mod validate;

pub use build::{build_workload, BuildOptions, BuildResult};
pub use error::WorkloadError;
pub use image::ContainerEngine;
pub use inspect::{
    inspect_workload, inspect_workload_archive_bytes, inspect_workload_archive_reader,
    InspectOptions, InspectResult,
};
pub use repository::{
    hex_equal, GithubWorkloadRepository, HttpWorkloadRepository, RepositoryArchiveMeta,
    RepositoryFilters, UploadContext, WorkloadCoords, WorkloadRepository,
};
pub use scaffold::create_workload;
pub use store::{CachedChainSpec, WorkloadEntry, WorkloadMeta, WorkloadStore};

/// Highest accepted source TOML format. New workloads use format 16 for v0.3.6.
/// Older source formats remain buildable for older base images.
pub const SOURCE_FORMAT_VERSION: u32 = 16;
/// Baseline compiled format retained when building older source files.
pub const FORMAT_VERSION: u32 = 11;
/// Required for authenticated workload disks; older portals must reject it.
pub const INTEGRITY_FORMAT_VERSION: u32 = 12;
pub const EXECUTABLE_STORAGE_FORMAT_VERSION: u32 = 13;

pub const ACCESS_STORAGE_FORMAT_VERSION: u32 = 14;
/// Required when baby log access or direct log-reader grants change behavior.
pub const BABY_LOG_POLICY_FORMAT_VERSION: u32 = 15;
