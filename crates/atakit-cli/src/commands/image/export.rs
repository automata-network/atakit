use anyhow::{bail, Result};
use atakit_core::{ArchiveCompression, Env};
use atakit_image::{create_image_archive, ExportArgs, ImageStore};
use owo_colors::OwoColorize;

use crate::progress::IndicatifReporter;

pub fn run(args: ExportArgs, env: &Env) -> Result<()> {
    let store = ImageStore::new(&env.image_dir);

    if !store.exists(&args.image) {
        bail!("no local content for {} in image store", args.image,);
    }

    let platforms = store.local_platforms(&args.image);
    let tag_dir = store.tag_dir(&args.image);

    let output_dir = match args.output {
        Some(path) => path,
        None => std::env::current_dir()
            .map_err(|e| anyhow::anyhow!("failed to determine current directory: {e}"))?,
    };

    let compression = if args.gz {
        ArchiveCompression::Gz
    } else {
        ArchiveCompression::Zstd
    };

    let progress = IndicatifReporter;
    let archive_path = create_image_archive(
        &tag_dir,
        &args.image,
        &platforms,
        &output_dir,
        &progress,
        compression,
    )?;

    println!("{}", "Exported.".green().bold());
    println!("  {}", archive_path.display());
    let platform_names: Vec<_> = platforms.iter().map(|p| p.to_string()).collect();
    println!("  Platforms: {}", platform_names.join(", "));
    if store.has_certs(&args.image) {
        println!("  Certs:     included");
    }

    Ok(())
}
