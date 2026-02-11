use std::collections::HashSet;

use anyhow::Result;
use automata_linux_release::{ImageRef, ImageStore, Platform, Release};
use clap::Args;

use crate::Env;

/// List available CVM base image releases from automata-linux.
#[derive(Args)]
pub struct List {
    /// Maximum number of releases to show
    #[arg(long, default_value = "10")]
    pub limit: u32,

    /// Show all releases (not just those with disk images)
    #[arg(long)]
    pub all: bool,

    /// Show a specific release by tag
    #[arg(long)]
    pub tag: Option<ImageRef>,

    #[arg(long, default_value = "automata-linux")]
    pub repo: String,

    /// Show only local images (skip remote query)
    #[arg(long)]
    pub local: bool,
}

impl List {
    pub async fn run(self, ctx: &Env) -> Result<()> {
        let store = ImageStore::new(&ctx.image_dir).with_token_from_env();

        if let Some(tag) = &self.tag {
            let release = store.client().get_release(tag).await?;
            print_release_detail(&self.repo, &release, &store);
            return Ok(());
        }

        // Local-only mode: just list what's on disk.
        if self.local {
            let local_tags = store.list_local()?;
            if local_tags.is_empty() {
                println!("No local images found.");
                return Ok(());
            }
            for tag in &local_tags {
                print_local_tag(&store, tag);
            }
            return Ok(());
        }

        // Get local tags first.
        let local_tags = store.list_local()?;

        // Get remote releases.
        let remote_tags: HashSet<ImageRef>;
        let remote_lines: Vec<String>;

        if self.all {
            let releases = store.client().list_releases(&self.repo, self.limit).await?;
            remote_tags = releases
                .iter()
                .map(|r| ImageRef::new(&self.repo, &r.tag_name))
                .collect();
            remote_lines = releases.iter().map(|r| format!("{}:{r}", self.repo)).collect();
        } else {
            let statuses = store.list(&self.repo, self.limit).await?;
            remote_tags = statuses
                .iter()
                .map(|s| ImageRef::new(&self.repo, &s.release.tag_name))
                .collect();
            remote_lines = statuses.iter().map(|s| format!("{}:{}", self.repo, s)).collect();
        }

        // Find local-only tags (not in remote).
        let local_only: Vec<_> = local_tags
            .iter()
            .filter(|t| !remote_tags.contains(*t))
            .collect();

        if local_only.is_empty() && remote_lines.is_empty() {
            println!("No images found.");
            return Ok(());
        }

        // Print local-only first, then remote.
        for tag in &local_only {
            print_local_tag(&store, tag);
        }
        for line in &remote_lines {
            println!("{line}");
        }

        Ok(())
    }
}

/// Print a local-only tag with its available platforms.
fn print_local_tag(store: &ImageStore, image_ref: &ImageRef) {
    let mut platforms = Vec::new();
    for p in [Platform::Gcp, Platform::Aws, Platform::Azure] {
        if store.image_path(image_ref, p).exists() {
            platforms.push(p.to_string());
        }
    }
    let has_certs = store.certs_dir(image_ref).exists();

    let mut info = platforms.join(", ");
    if has_certs {
        if !info.is_empty() {
            info.push_str(", ");
        }
        info.push_str("+certs");
    }
    if info.is_empty() {
        info = "empty".to_string();
    }
    println!("{image_ref}  [local: {info}]");
}

fn print_release_detail(repo: &str, release: &Release, store: &ImageStore) {
    let image_ref = ImageRef::new(repo, &release.tag_name);
    println!("{}", image_ref);

    if let Some(date) = &release.published_at {
        let short = date.get(..10).unwrap_or(date);
        println!("  published: {short}");
    }

    let platforms = release.available_platforms();
    if platforms.is_empty() {
        println!("  images:    (none)");
    } else {
        for p in &platforms {
            let asset = release.disk_image(*p).unwrap();
            let size_mb = asset.size / (1024 * 1024);
            let local = if store.image_path(&image_ref, *p).exists() {
                " [local]"
            } else {
                ""
            };
            println!("  {p:<8}   {} ({size_mb} MB){local}", asset.name);
        }
    }

    if let Some(certs) = release.secure_boot_certs() {
        let size_kb = certs.size / 1024;
        let local = if store.certs_dir(&image_ref).exists() {
            " [local]"
        } else {
            ""
        };
        println!("  certs:     {} ({size_kb} KB){local}", certs.name);
    }

    if let Some(body) = &release.body {
        let body = body.trim();
        if !body.is_empty() {
            println!();
            println!("{body}");
        }
    }
}
