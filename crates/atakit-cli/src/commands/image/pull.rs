use anyhow::{Result, bail};
use atakit_core::Env;
use atakit_image::{ImageRef, ImageStore, Platform, PullArgs, ReleasesClient};

use crate::config::Config;
use crate::progress::IndicatifReporter;

pub async fn run(args: PullArgs, env: &Env, config: &Config) -> Result<()> {
    let repo = &config.image.repository;

    let platforms = match &args.csps {
        Some(s) => parse_platforms(s)?,
        None => match &config.image.platforms {
            Some(names) => parse_platform_list(names)?,
            None => Platform::ALL.to_vec(),
        },
    };

    let store = ImageStore::new(&env.image_dir);
    let client = match config.github_token() {
        Some(token) => ReleasesClient::new().with_token(token),
        None => ReleasesClient::new().with_token_from_env(),
    };
    let progress = IndicatifReporter;

    let image_ref = match args.image {
        Some(i) => i,
        None => {
            println!("No image specified, finding latest image release...");
            let release = client.find_latest_image_release(repo).await?;
            println!("Using {repo}:{}", release.tag_name);
            ImageRef::new(repo, &release.tag_name)
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

fn parse_platform_list(names: &[String]) -> Result<Vec<Platform>> {
    let mut platforms = Vec::new();
    for name in names {
        let p: Platform = name
            .parse()
            .map_err(|e: atakit_image::ImageError| anyhow::anyhow!("{e}"))?;
        if !platforms.contains(&p) {
            platforms.push(p);
        }
    }
    if platforms.is_empty() {
        bail!("no platforms specified in config");
    }
    Ok(platforms)
}
