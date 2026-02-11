mod download_provenance;
mod generate_livepatch_keys;
mod livepatch;
mod sign_image;
mod sign_livepatch;
mod verify_provenance;

pub use download_provenance::DownloadProvenance;
pub use generate_livepatch_keys::GenerateLivepatchKeys;
pub use livepatch::Livepatch;
pub use sign_image::SignImage;
pub use sign_livepatch::SignLivepatch;
pub use verify_provenance::VerifyProvenance;

use anyhow::Result;
use clap::Subcommand;

use crate::Config;

#[derive(Subcommand)]
pub enum Security {
    /// Download SLSA build provenance from GitHub Release
    DownloadProvenance(DownloadProvenance),
    /// Verify SLSA build provenance for a disk image
    VerifyProvenance(VerifyProvenance),
    /// Sign and verify a container image using Cosign
    SignImage(SignImage),
    /// Generate livepatch keys to use with the CVM
    GenerateLivepatchKeys(GenerateLivepatchKeys),
    /// Sign a livepatch file
    SignLivepatch(SignLivepatch),
    /// Deploy a kernel livepatch to a deployed CVM
    Livepatch(Livepatch),
}

impl Security {
    pub fn run(self, config: &Config) -> Result<()> {
        match self {
            Security::DownloadProvenance(cmd) => cmd.run(config),
            Security::VerifyProvenance(cmd) => cmd.run(config),
            Security::SignImage(cmd) => cmd.run(config),
            Security::GenerateLivepatchKeys(cmd) => cmd.run(config),
            Security::SignLivepatch(cmd) => cmd.run(config),
            Security::Livepatch(cmd) => cmd.run(config),
        }
    }
}
