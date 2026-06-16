use anyhow::Result;
use atakit_core::Env;
use atakit_image::{ImageStore, RmArgs};

pub async fn run(args: RmArgs, env: &Env) -> Result<()> {
    let store = ImageStore::new(&env.image_dir);
    let dir = store.tag_dir(&args.tag);

    if !dir.exists() {
        println!("No local images for {} ({})", args.tag, dir.display());
        return Ok(());
    }

    store.delete(&args.tag).await?;
    println!("Deleted local images for {}", args.tag);

    Ok(())
}
