use std::collections::{BTreeMap, HashSet};
use std::fmt;

use anyhow::Result;
use atakit_core::Env;
use atakit_image::{
    ImageRef, ImageStore, LsArgs, Platform, Release, ReleaseStatus, ReleasesClient,
};
use owo_colors::OwoColorize;

pub async fn run(args: LsArgs, env: &Env) -> Result<()> {
    let store = ImageStore::new(&env.image_dir);
    let client = ReleasesClient::new().with_token_from_env();

    // --tag mode: show detailed view for a single release.
    if let Some(tag) = &args.tag {
        let release = client.get_release(tag).await?;
        print_release_detail(&args.repo, &release, &store);
        return Ok(());
    }

    let mut groups: BTreeMap<String, Vec<ImageRow>> = BTreeMap::new();

    if !args.remote && !args.all {
        // Local-only mode (default): just scan the filesystem.
        let local_tags = store.list_local()?;
        if local_tags.is_empty() {
            println!("No local images found.");
            return Ok(());
        }
        for tag in &local_tags {
            groups
                .entry(tag.repository.clone())
                .or_default()
                .push(row_from_local(tag, &store));
        }
    } else {
        // Fetch remote releases + merge local state (--remote).
        let local_tags = store.list_local()?;
        let remote_tags: HashSet<ImageRef>;

        if args.all {
            let releases = client.list_releases(&args.repo, args.limit).await?;
            remote_tags = releases
                .iter()
                .map(|r| ImageRef::new(&args.repo, &r.tag_name))
                .collect();
            let rows: Vec<_> = releases
                .iter()
                .map(|r| row_from_release(r, &store, &args.repo))
                .collect();
            groups.entry(args.repo.clone()).or_default().extend(rows);
        } else {
            let statuses = store.list(&client, &args.repo, args.limit).await?;
            remote_tags = statuses
                .iter()
                .map(|s| ImageRef::new(&args.repo, &s.release.tag_name))
                .collect();
            let rows: Vec<_> = statuses.iter().map(row_from_status).collect();
            groups.entry(args.repo.clone()).or_default().extend(rows);
        }

        // Append local-only images (not present in remote).
        for tag in &local_tags {
            if !remote_tags.contains(tag) {
                groups
                    .entry(tag.repository.clone())
                    .or_default()
                    .push(row_from_local(tag, &store));
            }
        }
    }

    if groups.values().all(|rows| rows.is_empty()) {
        println!("No images found.");
        return Ok(());
    }

    print_table(&groups);
    Ok(())
}

// ── table types ─────────────────────────────────────────────

enum PlatformStatus {
    Local,
    RemoteOnly,
    Unavailable,
}

impl fmt::Display for PlatformStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "{}", "*".green().bold()),
            Self::RemoteOnly => write!(f, "{}", "o".blue()),
            Self::Unavailable => write!(f, "{}", "-".bright_black()),
        }
    }
}

struct ImageRow {
    version: String,
    date: Option<String>,
    platforms: [PlatformStatus; 3], // GCP, AWS, Azure
    certs: PlatformStatus,
}

impl ImageRow {
    fn has_local(&self) -> bool {
        matches!(self.certs, PlatformStatus::Local)
            || self
                .platforms
                .iter()
                .any(|p| matches!(p, PlatformStatus::Local))
    }
}

// ── row builders ────────────────────────────────────────────

fn row_from_status(status: &ReleaseStatus) -> ImageRow {
    let r = &status.release;
    let remote = r.available_platforms();

    let platforms = Platform::ALL.map(|p| {
        if status.local_platforms.contains(&p) {
            PlatformStatus::Local
        } else if remote.contains(&p) {
            PlatformStatus::RemoteOnly
        } else {
            PlatformStatus::Unavailable
        }
    });

    let certs = if status.local_certs {
        PlatformStatus::Local
    } else if r.secure_boot_certs().is_some() {
        PlatformStatus::RemoteOnly
    } else {
        PlatformStatus::Unavailable
    };

    ImageRow {
        version: r.tag_name.clone(),
        date: r
            .published_at
            .as_ref()
            .map(|d| d.get(..10).unwrap_or(d).to_string()),
        platforms,
        certs,
    }
}

fn row_from_release(release: &Release, store: &ImageStore, repo: &str) -> ImageRow {
    let image_ref = ImageRef::new(repo, &release.tag_name);
    let remote = release.available_platforms();

    let platforms = Platform::ALL.map(|p| {
        if store.image_path(&image_ref, p).exists() {
            PlatformStatus::Local
        } else if remote.contains(&p) {
            PlatformStatus::RemoteOnly
        } else {
            PlatformStatus::Unavailable
        }
    });

    let certs = if store.certs_dir(&image_ref).exists() {
        PlatformStatus::Local
    } else if release.secure_boot_certs().is_some() {
        PlatformStatus::RemoteOnly
    } else {
        PlatformStatus::Unavailable
    };

    ImageRow {
        version: release.tag_name.clone(),
        date: release
            .published_at
            .as_ref()
            .map(|d| d.get(..10).unwrap_or(d).to_string()),
        platforms,
        certs,
    }
}

fn row_from_local(image_ref: &ImageRef, store: &ImageStore) -> ImageRow {
    let platforms = Platform::ALL.map(|p| {
        if store.image_path(image_ref, p).exists() {
            PlatformStatus::Local
        } else {
            PlatformStatus::Unavailable
        }
    });

    let certs = if store.certs_dir(image_ref).exists() {
        PlatformStatus::Local
    } else {
        PlatformStatus::Unavailable
    };

    ImageRow {
        version: image_ref.tag.clone(),
        date: None,
        platforms,
        certs,
    }
}

// ── table renderer ──────────────────────────────────────────

fn print_table(groups: &BTreeMap<String, Vec<ImageRow>>) {
    let mut first = true;
    for (name, rows) in groups {
        if !first {
            println!();
        }
        first = false;

        println!("{}", name.bold());

        let vw = rows
            .iter()
            .map(|r| r.version.len())
            .max()
            .unwrap_or(7)
            .max(7);

        println!(
            "      {:<vw$}     {:10}  GCP  AWS  AZURE  CERTS",
            "VERSION".dimmed(),
            "DATE".dimmed(),
        );

        for row in rows {
            let prefix = if row.has_local() {
                format!("  {}   ", "*".green().bold())
            } else {
                "      ".to_string()
            };
            let date = row.date.as_deref().unwrap_or("-");
            let version = if row.has_local() {
                row.version.green().bold().to_string()
            } else {
                row.version.to_string()
            };
            let [g, a, z] = &row.platforms;
            println!(
                "{prefix}{:<vw$}     {:10}  {}    {}    {}      {}",
                version, date, g, a, z, row.certs,
            );
        }
    }

    if !groups.is_empty() {
        println!();
        println!(
            "{}  {}  {}",
            format_args!("{} = local", "*".green().bold()),
            format_args!("{} = remote only", "o".blue()),
            format_args!("{} = unavailable", "-".bright_black()),
        );
    }
}

fn print_release_detail(repo: &str, release: &Release, store: &ImageStore) {
    let image_ref = ImageRef::new(repo, &release.tag_name);
    println!("{}", image_ref.to_string().bold());

    if let Some(date) = &release.published_at {
        let short = date.get(..10).unwrap_or(date);
        println!("  {} {short}", "published:".dimmed());
    }

    let platforms = release.available_platforms();
    if platforms.is_empty() {
        println!("  {} {}", "images:".dimmed(), "(none)".bright_black());
    } else {
        for p in &platforms {
            let asset = release.disk_image(*p).unwrap();
            let size_mb = asset.size / (1024 * 1024);
            let local = if store.image_path(&image_ref, *p).exists() {
                format!(" {}", "[local]".green())
            } else {
                String::new()
            };
            println!(
                "  {:<8}   {} ({}){local}",
                p.to_string().cyan(),
                asset.name,
                format!("{size_mb} MB").dimmed(),
            );
        }
    }

    if let Some(certs) = release.secure_boot_certs() {
        let size_kb = certs.size / 1024;
        let local = if store.certs_dir(&image_ref).exists() {
            format!(" {}", "[local]".green())
        } else {
            String::new()
        };
        println!(
            "  {:<8}   {} ({}){local}",
            "certs".cyan(),
            certs.name,
            format!("{size_kb} KB").dimmed(),
        );
    }

    if let Some(body) = &release.body {
        let body = body.trim();
        if !body.is_empty() {
            println!();
            println!("{body}");
        }
    }
}
