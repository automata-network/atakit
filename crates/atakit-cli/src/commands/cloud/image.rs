use anyhow::{Result, bail};
use atakit_cloud::cli::{CloudImageGcArgs, CloudImageLsArgs, CloudImageRmArgs, CloudImageUploadArgs};
use atakit_cloud::cloud_images::CloudImages;
use atakit_cloud::PlatformKind;
use atakit_core::Env;
use owo_colors::OwoColorize;

use crate::config::Config;
use super::resolve_image;

pub fn run_ls(args: CloudImageLsArgs, env: &Env) -> Result<()> {
    let cloud_images = CloudImages::load(&env.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let entries = cloud_images.entries();
    if entries.is_empty() {
        eprintln!("No cloud images tracked.");
        return Ok(());
    }

    if args.live {
        eprintln!("Note: --live checking is not yet implemented; showing local state only.");
        eprintln!();
    }

    eprintln!(
        "  {:<30} {:<15} {:<15} {}",
        "IMAGE".dimmed(),
        "PROVIDER".dimmed(),
        "CC TYPES".dimmed(),
        "UPLOADED".dimmed(),
    );

    for (image_ref, provider_name, record) in &entries {
        let cc_display: Vec<String> = record.cc_types.iter().map(|c| c.to_string()).collect();
        let uploaded = record.uploaded_at.format("%Y-%m-%d %H:%M");
        eprintln!(
            "  {:<30} {:<15} {:<15} {}",
            image_ref,
            provider_name,
            cc_display.join(","),
            uploaded,
        );
    }

    Ok(())
}

pub async fn run_upload(
    args: CloudImageUploadArgs,
    env: &Env,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    // 1. Resolve provider.
    let provider_config = config
        .cloud
        .providers
        .get(&args.provider)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider '{}' not found in [cloud.providers]",
                args.provider
            )
        })?;

    match provider_config.platform {
        PlatformKind::Gcp => {
            if provider_config.project.is_none() {
                bail!(
                    "GCP provider '{}' requires 'project'",
                    args.provider,
                );
            }
        }
        PlatformKind::Azure => {
            if provider_config.subscription.is_none() {
                bail!(
                    "Azure provider '{}' requires 'subscription'",
                    args.provider,
                );
            }
        }
    }

    // 2. Resolve image source (before cc_types, so .atabi imports get their resolved ref).
    let resolved = resolve_image(&args.image, &provider_config.platform, env)?;
    let image_ref = &resolved.display_name;
    let source_path = resolved.source_path.ok_or_else(|| {
        anyhow::anyhow!(
            "'{}' refers to an existing cloud image name, not a local image to upload. \
             Use repository:tag or a .atabi file path.",
            args.image,
        )
    })?;

    // 3. Resolve CC types (lookup uses resolved display_name, not raw CLI arg).
    let cc_types: Vec<atakit_cloud::CcType> = if !args.cc_types.is_empty() {
        args.cc_types
            .iter()
            .map(|s| s.parse::<atakit_cloud::CcType>())
            .collect::<Result<Vec<_>, _>>()?
    } else if let Some(entry) = config.cloud.images.get(image_ref) {
        entry.cc_types.clone()
    } else {
        bail!(
            "no CC types specified for '{}'. Use --cc-types or add an entry under [cloud.images].",
            image_ref,
        );
    };

    // 4. Show plan and confirm.
    let cc_display: Vec<String> = cc_types.iter().map(|c| c.to_string()).collect();
    eprintln!("{}", "Configuration:".dimmed());
    eprintln!("  {:<15}{}", "Provider:".dimmed(), args.provider);
    eprintln!("  {:<15}{} {}", "Platform:".dimmed(), provider_config.platform, provider_config.region);
    eprintln!("  {:<15}{}", "CC types:".dimmed(), cc_display.join(", "));
    eprintln!("  {:<15}{}", "Image:".dimmed(), image_ref);
    eprintln!("  {:<15}{}", "Disk image:".dimmed(), source_path);
    if args.force {
        eprintln!("  {:<15}yes (will delete existing)", "Force:".dimmed());
    }
    eprintln!();

    if !args.yes {
        eprint!("Proceed? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    // 5. Upload via shared helper.
    let result = super::ensure_cloud_image(
        image_ref,
        &args.provider,
        provider_config,
        &source_path,
        &cc_types,
        args.force,
        env,
        verbose,
    ).await?;

    if result.uploaded {
        eprintln!();
        eprintln!("{}", "==> Image uploaded!".green().bold());
    } else {
        eprintln!();
        eprintln!("Image already exists, skipped upload.");
    }
    eprintln!();

    Ok(())
}

pub async fn run_rm(_args: CloudImageRmArgs, _env: &Env, _config: &Config) -> Result<()> {
    bail!("cloud image rm is not yet implemented")
}

pub async fn run_gc(_args: CloudImageGcArgs, _env: &Env, _config: &Config) -> Result<()> {
    bail!("cloud image gc is not yet implemented")
}
