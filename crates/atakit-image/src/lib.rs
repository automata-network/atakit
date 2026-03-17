mod client;
mod download;
mod error;
mod store;
mod types;

#[cfg(feature = "cli")]
mod cli;

pub use client::{ReleasesClient, DEFAULT_REPO};
pub use download::{decompress_xz, extract_zip, download_asset, DownloadOptions};
pub use error::ImageError;
pub use store::{ImageStore, ReleaseStatus};
pub use types::{Asset, AssetKind, ImageRef, Platform, Release, VersionSelector};

#[cfg(feature = "cli")]
pub use cli::{ImageCommand, LsArgs, PullArgs, RmArgs};
