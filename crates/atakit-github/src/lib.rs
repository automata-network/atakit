//! Generic client for the GitHub Releases API used by both `atakit-image`
//! (base image distribution) and `atakit-workload` (workload archive
//! distribution).
//!
//! This crate is intentionally narrow: it knows about releases, tags, and
//! assets, but nothing about `.atabi` or `.atawl` archive layouts. Domain
//! specific parsing belongs to the consuming crates.

mod client;
mod download;
mod error;
mod types;
mod upload;

pub use client::ReleasesClient;
pub use download::{download_asset, download_asset_bytes, download_asset_to_path, DownloadOptions};
pub use error::{GithubError, Result};
pub use types::{Asset, CreateReleaseRequest, Release};
pub use upload::{upload_release_asset, upload_release_asset_bytes};
