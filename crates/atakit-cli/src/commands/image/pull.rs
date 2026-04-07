use anyhow::{Result, anyhow, bail};
use atakit_core::Env;
use atakit_image::{ImageRef, ImageStore, Platform, PullArgs, ReleasesClient};

use crate::config::{Config, repo_local_name};
use crate::progress::IndicatifReporter;

pub async fn run(args: PullArgs, env: &Env, config: &Config) -> Result<()> {
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

    // Resolve the GitHub repository to query. When the user specifies an
    // image reference, its repository component (e.g. "dev-baseimage") maps
    // to a configured `owner/repo` entry whose local name matches. Without
    // this mapping, pull would always query the primary repo regardless of
    // which image the user asked for.
    let (github_repo, image_ref) = match args.image {
        Some(image_ref) => {
            let github_repo = config
                .image
                .find_repo_by_local_name(&image_ref.repository)
                .ok_or_else(|| {
                    let configured: Vec<String> = config
                        .image
                        .repos()
                        .iter()
                        .map(|r| format!("  - {r}"))
                        .collect();
                    anyhow!(
                        "no configured repository matches '{}'. Configured repositories:\n{}",
                        image_ref.repository,
                        configured.join("\n"),
                    )
                })?
                .to_string();
            (github_repo, image_ref)
        }
        None => {
            let github_repo = config.image.primary_repo().to_string();
            let local_name = repo_local_name(&github_repo).to_string();
            println!("No image specified, finding latest image release...");
            let release = client.find_latest_image_release(&github_repo).await?;
            println!("Using {local_name}:{}", release.tag_name);
            let image_ref = ImageRef::new(local_name, release.tag_name);
            (github_repo, image_ref)
        }
    };

    let names: Vec<_> = platforms.iter().map(|p| p.to_string()).collect();
    println!("Pulling {} image(s) for {image_ref}...", names.join(", "));

    let paths = store
        .download(&client, &github_repo, &image_ref, &platforms, &progress)
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
