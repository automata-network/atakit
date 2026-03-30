pub mod archive;
mod client;
mod download;
mod error;
mod store;
mod types;

#[cfg(feature = "cli")]
mod cli;

pub use archive::{
    ImageManifest, ImageManifestMeta, IMAGE_FORMAT_VERSION,
    create_image_archive, import_image_archive, read_manifest,
};
pub use client::{ReleasesClient, DEFAULT_REPO};
pub use download::{download_asset, DownloadOptions};
pub use error::ImageError;
pub use store::{ImageStore, ReleaseStatus};
pub use types::{Asset, AssetKind, ImageRef, Platform, Release, VersionSelector};

#[cfg(feature = "cli")]
pub use cli::{ImageCommand, LsArgs, PullArgs, RmArgs, ExportArgs, ImportArgs};
