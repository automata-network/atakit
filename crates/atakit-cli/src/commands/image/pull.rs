use anyhow::{Result, bail};
use atakit_core::Env;
use atakit_image::{DEFAULT_REPO, ImageRef, ImageStore, Platform, PullArgs, ReleasesClient};

use crate::progress::IndicatifReporter;

pub async fn run(args: PullArgs, env: &Env) -> Result<()> {
    let platforms = match &args.csps {
        Some(s) => parse_platforms(s)?,
        None => Platform::ALL.to_vec(),
    };

    let store = ImageStore::new(&env.image_dir);
    let client = ReleasesClient::new().with_token_from_env();
    let progress = IndicatifReporter;

    let image_ref = match args.image {
        Some(i) => i,
        None => {
            println!("No image specified, finding latest image release...");
            let release = client.find_latest_image_release(DEFAULT_REPO).await?;
            println!("Using {}:{}", DEFAULT_REPO, release.tag_name);
            ImageRef::new(DEFAULT_REPO, &release.tag_name)
        }
    };

    let names: Vec<_> = platforms.iter().map(|p| p.to_string()).collect();
    println!("Pulling {} image(s) for {image_ref}...", names.join(", "));

    let paths = store
        .download(&client, &image_ref, &platforms, &progress)
        .await?;
    for path in &paths {
        println!("  {}", path.display());
    }

    println!("Done.");
    Ok(())
}

fn parse_platforms(s: &str) -> Result<Vec<Platform>> {
    let mut platforms = Vec::new();
    for part in s.split(',') {
        let p: Platform = part
            .trim()
            .parse()
            .map_err(|e: atakit_image::ImageError| anyhow::anyhow!("{e}"))?;
        if !platforms.contains(&p) {
            platforms.push(p);
        }
    }
    if platforms.is_empty() {
        bail!("no platforms specified");
    }
    Ok(platforms)
}
