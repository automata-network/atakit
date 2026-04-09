use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use anyhow::Result;
use atakit_core::Env;
use atakit_image::{
    ImageRef, ImageStore, LsArgs, Platform, Release, ReleaseStatus, ReleasesClient,
};
use owo_colors::OwoColorize;

use crate::config::{Config, ImageRepositorySpec, repo_local_name};

pub async fn run(args: LsArgs, env: &Env, config: &Config) -> Result<()> {
    // Resolve the set of (entry name, spec) pairs to visit. When
    // `--repo` is given we look up the matching configured entry to
    // inherit its credential and list_limit override; if no entry
    // matches we synthesize an anonymous spec so raw `owner/repo`
    // arguments still work.
    let targets: Vec<(String, ImageRepositorySpec)> = if let Some(ref r) = args.repo {
        if let Some((name, spec)) = config
            .image
            .repositories
            .iter()
            .find(|(_, s)| s.repo == *r)
        {
            vec![(name.clone(), spec.clone())]
        } else {
            vec![(
                r.clone(),
                ImageRepositorySpec {
                    repo: r.clone(),
                    credential: None,
                    list_limit: None,
                },
            )]
        }
    } else {
        config
            .image
            .repositories
            .iter()
            .map(|(name, spec)| (name.clone(), spec.clone()))
            .collect()
    };

    // Resolve every referenced credential up front so a slow helper
    // only runs once even when multiple repos share a credential.
    let cred_names: Vec<&str> = targets
        .iter()
        .filter_map(|(_, spec)| spec.credential.as_deref())
        .collect();
    let tokens: HashMap<String, String> = config.resolve_credentials_for(&cred_names)?;

    let build_client = |spec: &ImageRepositorySpec| -> ReleasesClient {
        let mut c = ReleasesClient::new();
        if let Some(ref name) = spec.credential {
            if let Some(token) = tokens.get(name) {
                c = c.with_token(token);
            }
        }
        c
    };

    let store = ImageStore::new(&env.image_dir);

    // --tag mode: show detailed view for a single release.
    if let Some(tag) = &args.tag {
        let (_, spec) = targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("no image repositories configured"))?;
        let client = build_client(spec);
        let release = client.get_release(&spec.repo, &tag.tag).await?;
        let local_name = repo_local_name(&spec.repo);
        print_release_detail(local_name, &release, &store);
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
        // Fetch remote releases + merge local state (--remote / --all).
        let local_tags = store.list_local()?;
        let mut remote_tags: HashSet<ImageRef> = HashSet::new();

        for (_, spec) in &targets {
            let github_repo = spec.repo.as_str();
            let local_name = repo_local_name(github_repo);
            let client = build_client(spec);

            // Precedence: --limit CLI flag > per-repo list_limit >
            // [image] list_limit. The CLI flag is an explicit
            // per-invocation override and wins uniformly across every
            // repo in the fan-out.
            let limit = args
                .limit
                .or(spec.list_limit)
                .unwrap_or(config.image.list_limit);

            if args.all {
                let releases = client.list_releases(github_repo, limit).await?;
                for r in &releases {
                    remote_tags.insert(ImageRef::new(local_name, &r.tag_name));
                }
                let rows: Vec<_> = releases
                    .iter()
                    .map(|r| row_from_release(r, &store, local_name))
                    .collect();
                groups
                    .entry(local_name.to_string())
                    .or_default()
                    .extend(rows);
            } else {
                let statuses = store
                    .list(&client, github_repo, local_name, limit)
                    .await?;
                for s in &statuses {
                    remote_tags.insert(ImageRef::new(local_name, &s.release.tag_name));
                }
                let rows: Vec<_> = statuses.iter().map(row_from_status).collect();
                groups
                    .entry(local_name.to_string())
                    .or_default()
                    .extend(rows);
            }
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

    // Compute version column width across ALL groups for consistent alignment.
    let vw = groups
        .values()
        .flat_map(|rows| rows.iter().map(|r| r.version.len()))
        .max()
        .unwrap_or(7)
        .max(7);

    print_table(&groups, vw);
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
    } else if r.has_archives() {
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
    } else if release.has_archives() {
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

fn print_table(groups: &BTreeMap<String, Vec<ImageRow>>, vw: usize) {
    let mut first = true;
    for (name, rows) in groups {
        if !first {
            println!();
        }
        first = false;

        println!("{}", name.bold());

        // Pad plain strings first, then apply color (ANSI escapes break {:<width$}).
        let vh = format!("{:<vw$}", "VERSION");
        let dh = format!("{:10}", "DATE");
        println!(
            "      {}     {}  GCP  AWS  AZURE  CERTS",
            vh.dimmed(),
            dh.dimmed(),
        );

        for row in rows {
            let prefix = if row.has_local() {
                format!("  {}   ", "*".green().bold())
            } else {
                "      ".to_string()
            };
            let date = row.date.as_deref().unwrap_or("-");
            let version_padded = format!("{:<vw$}", row.version);
            let version = if row.has_local() {
                version_padded.green().bold().to_string()
            } else {
                version_padded
            };
            let [g, a, z] = &row.platforms;
            println!(
                "{prefix}{}     {:10}  {}    {}    {}      {}",
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

    let archives = release.archives();
    if archives.is_empty() {
        println!("  {} {}", "archives:".dimmed(), "(none)".bright_black());
    } else {
        for asset in &archives {
            let size_mb = asset.size / (1024 * 1024);
            let local = if store.exists(&image_ref) {
                format!(" {}", "[local]".green())
            } else {
                String::new()
            };
            println!(
                "  {:<8}   {} ({}){local}",
                "archive".cyan(),
                asset.name,
                format!("{size_mb} MB").dimmed(),
            );
        }
    }

    let local_certs = store.certs_dir(&image_ref).exists();
    if local_certs {
        println!("  {:<8}   {}", "certs".cyan(), "[local]".green());
    }

    if let Some(body) = &release.body {
        let body = body.trim();
        if !body.is_empty() {
            println!();
            println!("{body}");
        }
    }
}
