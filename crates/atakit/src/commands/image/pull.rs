use anyhow::{Result, bail};
use automata_linux_release::{ImageRef, ImageStore, Platform, REPO};
use clap::Args;

use crate::Env;

const ALL_PLATFORMS: [Platform; 3] = [Platform::Gcp, Platform::Aws, Platform::Azure];

/// Pull CVM base images for a specific release.
#[derive(Args)]
pub struct Download {
    /// Release tag to pull (e.g. "automata-linux:v0.5.0").
    /// If omitted, the latest release containing disk images is used.
    pub image: Option<ImageRef>,

    /// Comma-separated list of platforms: gcp,aws,azure.
    /// If omitted, all platforms are pulled.
    pub csps: Option<String>,
}

impl Download {
    pub async fn run(self, ctx: &Env) -> Result<()> {
        let platforms = match &self.csps {
            Some(s) => parse_platforms(s)?,
            None => ALL_PLATFORMS.to_vec(),
        };

        let store = ImageStore::new(&ctx.image_dir).with_token_from_env();

        let image_ref = match self.image {
            Some(i) => i,
            None => {
                println!("No image specified, finding latest image release...");
                let release = store.client().find_latest_image_release(REPO).await?;
                println!("Using {}{}", REPO, release.tag_name);
                ImageRef::new(REPO, &release.tag_name)
            }
        };

        let names: Vec<_> = platforms.iter().map(|p| p.to_string()).collect();
        println!("Pulling {} image(s) for {image_ref}...", names.join(", "));

        let paths = store.download(&image_ref, &platforms).await?;
        for path in &paths {
            println!("  {}", path.display());
        }

        println!("Done.");
        Ok(())
    }
}

fn parse_platforms(s: &str) -> Result<Vec<Platform>> {
    let mut platforms = Vec::new();
    for part in s.split(',') {
        let p = match part.trim() {
            "gcp" => Platform::Gcp,
            "aws" => Platform::Aws,
            "azure" => Platform::Azure,
            other => bail!("unsupported platform '{other}', expected: gcp, aws, azure"),
        };
        if !platforms.contains(&p) {
            platforms.push(p);
        }
    }
    if platforms.is_empty() {
        bail!("no platforms specified");
    }
    Ok(platforms)
}
