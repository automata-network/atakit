use std::path::PathBuf;

use atakit_core::ProgressReporter;

use crate::client::ReleasesClient;
use crate::error::Result;
use crate::types::Asset;

pub use atakit_github::DownloadOptions;

/// Download a release asset to the local filesystem.
///
/// Returns the path to the downloaded file.
pub async fn download_asset(
    client: &ReleasesClient,
    asset: &Asset,
    opts: &DownloadOptions,
    progress: &dyn ProgressReporter,
) -> Result<PathBuf> {
    let raw: atakit_github::Asset = asset.into();
    Ok(atakit_github::download_asset(client.inner(), &raw, opts, progress).await?)
}
