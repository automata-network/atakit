use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_cvm_types::AppRef;
use atakit_image::{ImageStore, InspectArgs, Platform};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
struct Inspection {
    image: String,
    base_image_ref: String,
    publisher_fingerprint: String,
    base_image_id: String,
    name: String,
    version: String,
    metadata_path: PathBuf,
    local_platforms: Vec<String>,
}

pub fn run(args: InspectArgs, env: &Env) -> Result<()> {
    let store = ImageStore::new(&env.image_dir);
    let metadata_path = store.tag_dir(&args.image).join("baseimage.toml");
    let content = std::fs::read_to_string(&metadata_path).with_context(|| format!(
        "cannot read {}; inspect requires a local image with baseimage.toml metadata (download with `atakit image pull {}`)",
        metadata_path.display(), args.image,
    ))?;
    // Inspect only public identity fields, never dump the complete image config.
    let document: toml::Value = toml::from_str(&content)
        .with_context(|| format!("invalid metadata in {}", metadata_path.display()))?;
    let reference = document
        .get("meta")
        .and_then(|meta| meta.get("base-image-ref"))
        .and_then(toml::Value::as_str)
        .with_context(|| {
            format!(
                "{} does not define meta.base-image-ref",
                metadata_path.display()
            )
        })?;
    let identity: AppRef = reference.parse().with_context(|| {
        format!(
            "{}.meta.base-image-ref must contain a publisher-qualified reference",
            metadata_path.display(),
        )
    })?;
    let inspection = Inspection {
        image: args.image.to_string(),
        base_image_ref: identity.to_string(),
        publisher_fingerprint: format!("0x{}", hex::encode(identity.publisher)),
        base_image_id: format!(
            "0x{}",
            hex::encode(atakit_cvm_encoding::base_image_id(&identity))
        ),
        name: identity.name,
        version: identity.version,
        metadata_path,
        local_platforms: Platform::ALL
            .into_iter()
            .filter(|platform| store.image_path(&args.image, *platform).is_file())
            .map(|platform| platform.to_string())
            .collect(),
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
    } else {
        println!("Image: {}", inspection.image);
        println!("Base image ref: {}", inspection.base_image_ref);
        println!(
            "Publisher fingerprint: {}",
            inspection.publisher_fingerprint
        );
        println!("Base image ID: {}", inspection.base_image_id);
        println!("Metadata: {}", inspection.metadata_path.display());
        println!(
            "Local platforms: {}",
            if inspection.local_platforms.is_empty() {
                "(none)".into()
            } else {
                inspection.local_platforms.join(", ")
            }
        );
    }
    Ok(())
}
