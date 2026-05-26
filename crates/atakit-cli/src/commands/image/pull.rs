use anyhow::{anyhow, bail, Result};
use atakit_core::Env;
use atakit_image::{ImageRef, ImageStore, Platform, PullArgs, ReleasesClient};

use crate::config::{repo_local_name, Config, ImageRepositorySpec};
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
    let progress = IndicatifReporter;

    // Resolve the target entry first: when an image ref is provided,
    // look it up by local name; otherwise use the primary (first
    // declared) configured entry. This lets us read the credential off
    // the spec BEFORE building the network client.
    let (spec, image_ref): (ImageRepositorySpec, Option<ImageRef>) = match args.image {
        Some(image_ref) => {
            let (_, spec) = config
                .image
                .find_by_local_name(&image_ref.repository)?
                .ok_or_else(|| {
                    let configured: Vec<String> = config
                        .image
                        .repositories
                        .iter()
                        .map(|(name, s)| format!("  - {name}: {}", s.repo))
                        .collect();
                    anyhow!(
                        "no configured repository matches '{}'. Configured repositories:\n{}",
                        image_ref.repository,
                        configured.join("\n"),
                    )
                })?;
            (spec.clone(), Some(image_ref))
        }
        None => {
            let (_, spec) = config
                .image
                .primary_entry()
                .ok_or_else(|| anyhow!("no image repositories configured"))?;
            (spec.clone(), None)
        }
    };

    // Resolve the credential for the chosen entry (if any).
    // `command` credentials can block up to `timeout_secs`, so wrap
    // in `block_in_place` to let tokio schedule other work instead
    // of holding the worker thread captive.
    let token = tokio::task::block_in_place(|| -> Result<Option<String>> {
        match spec.credential.as_deref() {
            Some(name) => Ok(Some(config.resolve_credential(name)?)),
            None => Ok(None),
        }
    })?;

    let mut client = ReleasesClient::new();
    if let Some(ref t) = token {
        client = client.with_token(t);
    }

    let github_repo = spec.repo.clone();
    let image_ref = match image_ref {
        Some(r) => r,
        None => {
            let local_name = repo_local_name(&github_repo).to_string();
            println!("No image specified, finding latest image release...");
            let release = client.find_latest_image_release(&github_repo).await?;
            println!("Using {local_name}:{}", release.tag_name);
            ImageRef::new(local_name, release.tag_name)
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
