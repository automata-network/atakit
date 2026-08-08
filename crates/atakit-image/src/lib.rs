pub mod archive;
mod client;
mod download;
mod error;
mod store;
mod types;

#[cfg(feature = "cli")]
mod cli;

pub use archive::{
    create_image_archive, import_image_archive, read_manifest, ImageManifest, ImageManifestMeta,
    IMAGE_FORMAT_VERSION,
};
pub use client::ReleasesClient;
pub use download::{download_asset, DownloadOptions};
pub use error::ImageError;
pub use store::{ImageStore, ReleaseStatus};
pub use types::{Asset, AssetKind, ImageRef, Platform, Release, VersionSelector};

#[cfg(feature = "cli")]
pub use cli::{ExportArgs, ImageCommand, ImportArgs, LsArgs, PullArgs, RmArgs};
