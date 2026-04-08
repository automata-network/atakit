pub mod archive;
pub mod build;
#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
mod error;
pub mod hash;
pub mod image;
pub mod inspect;
pub mod manifest;
pub mod repository;
mod scaffold;
pub mod store;
pub mod validate;

pub use build::{build_workload, BuildOptions, BuildResult};
pub use error::WorkloadError;
pub use image::ContainerEngine;
pub use inspect::{inspect_workload, InspectOptions, InspectResult};
pub use repository::{
    hex_equal, GithubWorkloadRepository, HttpWorkloadRepository, RepositoryArchiveMeta,
    RepositoryFilters, UploadContext, WorkloadCoords, WorkloadRepository,
};
pub use scaffold::create_workload;
pub use store::{CachedChainSpec, WorkloadEntry, WorkloadMeta, WorkloadStore};

/// Current format version for `atakit-workload.toml` and `manifest.toml`.
pub const FORMAT_VERSION: u32 = 1;
