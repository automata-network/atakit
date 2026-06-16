use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use anyhow::Result;
use atakit_core::Env;
use atakit_image::{
    ImageRef, ImageStore, LsArgs, Platform, Release, ReleaseStatus, ReleasesClient,
};
use owo_colors::OwoColorize;

use crate::config::{repo_local_name, Config, ImageRepositorySpec};

pub async fn run(args: LsArgs, env: &Env, config: &Config) -> Result<()> {
    // Resolve the set of (entry name, spec) pairs to visit. When
    // `--repo` is given we look up the matching configured entry to
    // inherit its credential and list_limit override; if no entry
    // matches we synthesize an anonymous spec so raw `owner/repo`
    // arguments still work.
    let targets: Vec<(String, ImageRepositorySpec)> = if let Some(ref r) = args.repo {
        if let Some((name, spec)) = config.image.repositories.iter().find(|(_, s)| s.repo == *r) {
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

    let store = ImageStore::new(&env.image_dir);

    // Credential resolution is deferred until we actually need to
    // talk to GitHub. Local-only `image ls` (the default, no
    // `--remote` / `--all` / `--tag`) must never touch any
    // credential files / env vars / helpers -- that's the whole
    // point of lazy resolution.

    // --tag mode: single-target, single repo, strict.
    if let Some(tag) = &args.tag {
        // Pick the repository to query for this tag. When `--repo`
        // was passed, `targets` has already been narrowed to that
        // single entry (see the top of the function) so we honour
        // it. When it wasn't, look up the configured entry whose
        // local name matches the tag's `repository` component --
        // running `--tag debug-linux:v0.5` must query the entry
        // that actually points at `*/debug-linux`, not whichever
        // entry happens to be declared first. Mirrors the same
        // lookup `image pull` does for image references.
        let spec = if args.repo.is_some() {
            targets
                .first()
                .map(|(_, s)| s.clone())
                .ok_or_else(|| anyhow::anyhow!("no image repositories configured"))?
        } else {
            let (_, s) = config
                .image
                .find_by_local_name(&tag.repository)?
                .ok_or_else(|| {
                    let configured: Vec<String> = config
                        .image
                        .repositories
                        .iter()
                        .map(|(name, s)| format!("  - {name}: {}", s.repo))
                        .collect();
                    anyhow::anyhow!(
                        "no configured repository matches '{}'. Configured repositories:\n{}",
                        tag.repository,
                        configured.join("\n"),
                    )
                })?;
            s.clone()
        };

        // `command` credentials can block up to `timeout_secs`, so
        // wrap the resolve in `block_in_place`.
        let token = tokio::task::block_in_place(|| -> Result<Option<String>> {
            match spec.credential.as_deref() {
                Some(cred_name) => Ok(Some(config.resolve_credential(cred_name)?)),
                None => Ok(None),
            }
        })?;
        let mut client = ReleasesClient::new();
        if let Some(t) = token {
            client = client.with_token(t);
        }
        let release = client.get_release_by_tag(&spec.repo, &tag.tag).await?;
        let local_name = repo_local_name(&spec.repo);
        print_release_detail(local_name, &release, &store);
        return Ok(());
    }

    let mut groups: BTreeMap<String, Vec<ImageRow>> = BTreeMap::new();

    if !args.remote && !args.all {
        // Local-only mode (default): just scan the filesystem. No
        // network, no credential resolution.
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
        //
        // Resolve every referenced credential up front so a slow
        // helper only runs once even when multiple repos share a
        // credential. Strictness keys off fan-out CARDINALITY, not
        // whether the user passed --repo:
        // * Exactly one target: strict. A credential failure is
        //   fatal because there's no fallback -- skipping would
        //   downgrade the actionable "your token is bad" signal
        //   into a misleading "no images found". Applies equally
        //   whether the single target came from --repo or from
        //   a one-entry config.
        // * Multi-target fan-out: best-effort. One broken credential
        //   must not abort listing for repositories that don't need
        //   it. Repos whose credential fails are skipped with a
        //   per-repo warning.
        let single_target = targets.len() == 1;
        let cred_names: Vec<&str> = targets
            .iter()
            .filter_map(|(_, spec)| spec.credential.as_deref())
            .collect();
        // Credential resolution can spawn a `command`-type helper
        // with up to `timeout_secs` of blocking wait. Wrap in
        // `block_in_place` so the tokio worker thread can yield to
        // other tasks instead of being held captive -- matches the
        // other two fan-out call sites in workload/ls and
        // workload/pull.
        let (tokens, cred_errs): (HashMap<String, String>, HashMap<String, String>) =
            tokio::task::block_in_place(|| -> Result<_> {
                Ok(if single_target {
                    (config.resolve_credentials_for(&cred_names)?, HashMap::new())
                } else {
                    config.resolve_credentials_best_effort(&cred_names)
                })
            })?;
        for (cred_name, msg) in &cred_errs {
            eprintln!(
                "{} credential '{}' failed: {}",
                "warning:".yellow(),
                cred_name.dimmed(),
                msg,
            );
        }

        let build_client = |spec: &ImageRepositorySpec| -> ReleasesClient {
            let mut c = ReleasesClient::new();
            if let Some(ref name) = spec.credential {
                if let Some(token) = tokens.get(name) {
                    c = c.with_token(token);
                }
            }
            c
        };

        let local_tags = store.list_local()?;
        let mut remote_tags: HashSet<ImageRef> = HashSet::new();

        for (name, spec) in &targets {
            // Skip targets whose credential failed to resolve (only
            // relevant in multi-target mode; single-target mode
            // already errored strictly above).
            if let Some(ref cred_name) = spec.credential {
                if cred_errs.contains_key(cred_name) {
                    eprintln!(
                        "{} skipping {} (credential '{}' failed)",
                        "warning:".yellow(),
                        name.dimmed(),
                        cred_name.dimmed(),
                    );
                    continue;
                }
            }

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

            // API errors are handled differently based on cardinality,
            // matching the credential-failure rule earlier in this
            // function and the `workload ls` fan-out behavior:
            // * Single target: fatal. There's no fallback repository,
            //   so returning "No images found" on a 500 / rate-limit
            //   would hide the real cause.
            // * Multi-target fan-out: warn to stderr and continue so
            //   one broken or slow repository doesn't kill the
            //   listing for every other configured repo.
            if args.all {
                match client.list_releases(github_repo, limit).await {
                    Ok(releases) => {
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
                    }
                    Err(e) => {
                        if single_target {
                            return Err(e.into());
                        }
                        eprintln!(
                            "{} {} ({}): {}",
                            "warning:".yellow(),
                            name.dimmed(),
                            github_repo.dimmed(),
                            e,
                        );
                    }
                }
            } else {
                match store.list(&client, github_repo, local_name, limit).await {
                    Ok(statuses) => {
                        for s in &statuses {
                            remote_tags.insert(ImageRef::new(local_name, &s.release.tag_name));
                        }
                        let rows: Vec<_> = statuses.iter().map(row_from_status).collect();
                        groups
                            .entry(local_name.to_string())
                            .or_default()
                            .extend(rows);
                    }
                    Err(e) => {
                        if single_target {
                            return Err(e.into());
                        }
                        eprintln!(
                            "{} {} ({}): {}",
                            "warning:".yellow(),
                            name.dimmed(),
                            github_repo.dimmed(),
                            e,
                        );
                    }
                }
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
    platforms: [PlatformStatus; 4], // GCP, AWS, Azure, QEMU
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
            "      {}     {}  GCP  AWS  AZURE  QEMU  CERTS",
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
            let [g, a, z, q] = &row.platforms;
            println!(
                "{prefix}{}     {:10}  {}    {}    {}      {}     {}",
                version, date, g, a, z, q, row.certs,
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
