use anyhow::Result;
use automata_linux_release::ImageStore;
use clap::Args;

use crate::Env;

/// Remove locally downloaded CVM base images.
#[derive(Args)]
pub struct Delete {
    /// Release tag to remove (e.g. "v0.5.0")
    pub tag: String,
}

impl Delete {
    pub async fn run(self, ctx: &Env) -> Result<()> {
        let store = ImageStore::new(&ctx.image_dir);
        let dir = store.tag_dir(&self.tag);

        if !dir.exists() {
            println!("No local images for {} ({})", self.tag, dir.display());
            return Ok(());
        }

        store.delete(&self.tag).await?;
        println!("Deleted local images for {}", self.tag);

        Ok(())
    }
}
