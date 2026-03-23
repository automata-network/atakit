use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_image::{ImportArgs, ImageStore, import_image_archive, read_manifest};
use owo_colors::OwoColorize;

pub fn run(args: ImportArgs, env: &Env) -> Result<()> {
    let store = ImageStore::new(&env.image_dir);

    // Read manifest to check what we're importing.
    let manifest = read_manifest(&args.archive)
        .with_context(|| format!("failed to read {}", args.archive.display()))?;

    let ref_str = format!("{}:{}", manifest.meta.name, manifest.meta.version);

    if store.exists(&atakit_image::ImageRef {
        repository: manifest.meta.name.clone(),
        tag: manifest.meta.version.clone(),
    }) && !args.force
    {
        println!(
            "Image {ref_str} already in store (use --force to overwrite)."
        );
        return Ok(());
    }

    let image_ref = import_image_archive(&args.archive, store.base_dir())
        .with_context(|| format!("failed to import {}", args.archive.display()))?;

    let platforms = store.local_platforms(&image_ref);
    let platform_names: Vec<_> = platforms.iter().map(|p| p.to_string()).collect();

    println!("{}", "Imported.".green().bold());
    println!("  {:<18}{}", "Image:", image_ref);
    println!("  {:<18}{}", "Platforms:", platform_names.join(", "));
    if store.has_certs(&image_ref) {
        println!("  {:<18}yes", "Certs:");
    }

    Ok(())
}
