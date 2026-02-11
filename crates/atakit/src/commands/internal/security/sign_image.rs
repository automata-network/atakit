use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::Config;

#[derive(Args)]
pub struct SignImage {
    /// Source image (e.g., alpine:latest)
    pub source_image: String,
    /// Target image (e.g., docker.io/user/image:signed)
    pub target_image: String,
    /// Cosign private key path
    pub cosign_private: PathBuf,
    /// Cosign public key path
    pub cosign_public: PathBuf,
}

impl SignImage {
    pub fn run(self, cfg: &Config) -> Result<()> {
        let pri = self.cosign_private.to_string_lossy();
        let pub_ = self.cosign_public.to_string_lossy();
        cfg.run_script_default(
            "sign-and-verify.sh",
            &[&self.source_image, &self.target_image, &pri, &pub_],
        )
    }
}
