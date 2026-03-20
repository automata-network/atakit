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
mod scaffold;
pub mod validate;

pub use build::{build_workload, BuildOptions, BuildResult};
pub use error::WorkloadError;
pub use image::ContainerEngine;
pub use inspect::{inspect_workload, InspectOptions, InspectResult};
pub use scaffold::create_workload;

/// Current format version for `atakit-workload.toml` and `manifest.toml`.
pub const FORMAT_VERSION: u32 = 1;
