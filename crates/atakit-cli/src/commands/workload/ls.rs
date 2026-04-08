use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::LsArgs;
use atakit_workload::{RepositoryArchiveMeta, RepositoryFilters, WorkloadStore};
use futures_util::future::join_all;
use owo_colors::OwoColorize;

use super::{compute_final_pcr23, compute_workload_id, hex_equal, query_chain_data};
use crate::config::Config;

/// Merged display entry combining local and remote data. When a workload
/// appears in more than one repository, the `sources` vector records every
/// repository name that advertises it.
struct DisplayEntry {
    name: String,
    version: String,
    status: Status,
    revoked: bool,
    sha256: Option<String>,
    owner: Option<String>,
    archive_size: Option<u64>,
    sources: Vec<String>,
    /// True when at least two sources advertised the same (name, version)
    /// but with different `sha256` values. Rendered in red.
    divergent: bool,
}

enum Status {
    /// Has blob and on-chain metadata.
    LocalTracked,
    /// Has blob only, no on-chain metadata.
    Local,
    /// Has metadata only, no blob.
    Tracked,
    /// Only on remote repository.
    Remote,
}

impl Status {
    fn symbol(&self) -> &'static str {
        match self {
            Status::LocalTracked => "\u{25c9}", // ◉
            Status::Local => "\u{25d4}",        // ◔
            Status::Tracked => "\u{25cc}",      // ◌
            Status::Remote => "\u{25ca}",       // ◊
        }
    }
}

pub async fn run(args: LsArgs, env: &Env, config: &Config) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);
    let show_local = !args.remote;
    let show_remote = args.remote || args.all;

    let mut entries: Vec<DisplayEntry> = Vec::new();

    // Collect local entries.
    if show_local {
        let local = store.list()?;
        for e in local {
            entries.push(DisplayEntry {
                name: e.meta.name.clone(),
                version: e.meta.version.clone(),
                status: match (e.has_blob, e.meta.on_chain_spec.is_some()) {
                    (true, true) => Status::LocalTracked,
                    (true, false) => Status::Local,
                    (false, _) => Status::Tracked,
                },
                revoked: e.meta.revoked,
                sha256: e.meta.sha256.clone(),
                owner: e.meta.owner.clone(),
                archive_size: e.meta.archive_size,
                sources: Vec::new(),
                divergent: false,
            });
        }
    }

    // Collect remote entries from every configured repository (or the
    // single one selected via --repository).
    if show_remote {
        match config.workload.all_repositories(args.repository.as_deref()) {
            Ok(specs) => {
                let token = config.github_token().map(str::to_string);
                let filters = RepositoryFilters {
                    owner: args.owner.clone(),
                    name: None,
                    name_prefix: None,
                    limit: args.limit,
                    offset: None,
                };

                for (repo_name, spec) in specs {
                    let repo = config.workload.build_repository(spec, token.clone());
                    let uri = repo.display_uri();
                    match repo.list(&filters).await {
                        Ok(remote_entries) => {
                            for rm in remote_entries {
                                // Client-side substring filter.
                                if let Some(ref name_filter) = args.name {
                                    if !rm.name.contains(name_filter.as_str()) {
                                        continue;
                                    }
                                }
                                merge_remote(&mut entries, &rm, &repo_name);
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "{} {} ({}): {}",
                                "warning:".yellow(),
                                repo_name.dimmed(),
                                uri.dimmed(),
                                e,
                            );
                        }
                    }
                }
            }
            Err(e) => {
                if args.remote {
                    return Err(e);
                }
                // --all mode: warn but continue with local-only.
                eprintln!("warning: {e}");
            }
        }
    }

    // Apply name filter for local entries (remote already filtered above).
    if let Some(ref filter) = args.name {
        if show_local {
            entries.retain(|e| e.name.contains(filter.as_str()));
        }
    }

    // Cross-check advertised repository sha256 values against the on-chain
    // WorkloadRegistry spec. This is best-effort: if RPC isn't configured
    // or a workload isn't registered we silently skip. A mismatch marks
    // the entry as divergent (rendered in red) and emits a stderr warning.
    if show_remote {
        verify_entries_against_chain(&mut entries, config).await;
    }

    if entries.is_empty() {
        if args.remote || args.all {
            println!("No workloads found.");
        } else {
            println!("No local workloads found.");
        }
        return Ok(());
    }

    // Sort by name, then version.
    entries.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

    print_table(&entries, args.wide);
    Ok(())
}

/// Best-effort cross-check of every entry's repository-advertised sha256
/// against the on-chain WorkloadRegistry's PCR23 entry.
///
/// For each `DisplayEntry` that has a sha256:
///
/// 1. Compute the expected final PCR23 from that sha256 (event hash):
///    `SHA-256(zeros_32 || event_hash)`.
/// 2. Query the on-chain workload spec for `(name, version)` in parallel.
/// 3. If the spec exists and contains a PCR23 matchData entry, compare
///    the computed value to the on-chain value.
/// 4. On mismatch: mark the entry as `divergent` (rendered red) and emit
///    a stderr warning.
///
/// All failure modes (no RPC config, RPC error, workload not registered,
/// no PCR23 in spec) are silent skips. The function never errors.
async fn verify_entries_against_chain(entries: &mut [DisplayEntry], config: &Config) {
    let Some(rpc_url) = config.publish.rpc_url.as_deref() else {
        return;
    };
    let Some(session_registry) = config.publish.session_registry.as_deref() else {
        return;
    };

    // Pick out entries that we can usefully check: must have an event
    // hash to compare against.
    let targets: Vec<(usize, alloy_ext::core::primitives::B256, String)> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            let sha256 = e.sha256.as_ref()?;
            let id = compute_workload_id(&e.name, &e.version);
            Some((i, id, sha256.clone()))
        })
        .collect();
    if targets.is_empty() {
        return;
    }

    // Query on-chain spec for every target in parallel. `query_chain_data`
    // already returns Ok(ChainData{status: "not registered", ...}) for
    // workloads that aren't on-chain, so a None below only happens on
    // unrecoverable RPC errors.
    let queries = targets.iter().map(|(_, id, _)| {
        let rpc = rpc_url.to_string();
        let sreg = session_registry.to_string();
        let id = *id;
        async move { query_chain_data(id, &rpc, &sreg).await.ok() }
    });
    let results = join_all(queries).await;

    for ((idx, _, sha256), chain) in targets.iter().zip(results) {
        let Some(chain) = chain else { continue };
        let Some(on_chain_pcr23) = chain.pcr23 else {
            continue;
        };
        let Some(expected) = compute_final_pcr23(sha256) else {
            continue;
        };
        if !hex_equal(&expected, &on_chain_pcr23) {
            entries[*idx].divergent = true;
            eprintln!(
                "{} on-chain PCR23 mismatch for {}:{}\n  on-chain:   {}\n  computed:   {}\n  (from repository sha256 {})",
                "warning:".yellow(),
                entries[*idx].name,
                entries[*idx].version,
                on_chain_pcr23,
                expected,
                shorten(sha256),
            );
        }
    }
}

/// Merge a remote listing into the accumulated display entries.
///
/// * If an entry with matching (name, version) already exists, append
///   `repo_name` to its `sources` list.
/// * Otherwise push a new remote-status entry with `repo_name` as its
///   first source.
///
/// Emits a stderr warning if sha256 values diverge across repositories
/// for the same workload: identical workload IDs should have identical
/// content.
fn merge_remote(
    entries: &mut Vec<DisplayEntry>,
    rm: &RepositoryArchiveMeta,
    repo_name: &str,
) {
    // Canonical workload_id is deterministic from (name, version).
    // Every honest repository must report this exact value. If a
    // repository advertises a different one, flag the entry as
    // divergent so the user notices -- this could indicate a bug in
    // the repository backend, a stale sidecar, or an adversarial
    // response trying to smuggle a different workload under a known
    // name/version.
    let canonical_id = compute_workload_id(&rm.name, &rm.version);
    let canonical_id_hex = format!("0x{}", hex::encode(canonical_id));
    let workload_id_matches_canonical =
        rm.workload_id.is_empty() || hex_equal(&rm.workload_id, &canonical_id_hex);
    if !workload_id_matches_canonical {
        eprintln!(
            "{} repository {} reported workload_id {} for {}:{}, but canonical is {}",
            "warning:".yellow(),
            repo_name,
            shorten(&rm.workload_id),
            rm.name,
            rm.version,
            shorten(&canonical_id_hex),
        );
    }

    if let Some(existing) = entries
        .iter_mut()
        .find(|e| e.name == rm.name && e.version == rm.version)
    {
        if !existing.sources.iter().any(|s| s == repo_name) {
            existing.sources.push(repo_name.to_string());
        }
        if !workload_id_matches_canonical {
            existing.divergent = true;
        }

        // Divergent sha256 is a red flag. Keep the first one but warn,
        // and mark the entry so the table row is rendered in red. Use
        // hex_equal so harmless prefix differences (`0x` vs `sha256:`,
        // upper vs lowercase) don't get flagged as divergence.
        if !rm.sha256.is_empty() {
            match &existing.sha256 {
                Some(prev) if !prev.is_empty() && !hex_equal(prev, &rm.sha256) => {
                    existing.divergent = true;
                    eprintln!(
                        "{} divergent sha256 for {}:{}: {} vs {} (source: {})",
                        "warning:".yellow(),
                        existing.name,
                        existing.version,
                        shorten(prev),
                        shorten(&rm.sha256),
                        repo_name,
                    );
                }
                None => existing.sha256 = Some(rm.sha256.clone()),
                _ => {}
            }
        }
        if existing.owner.is_none() && !rm.owner.is_empty() {
            existing.owner = Some(rm.owner.clone());
        }
        if existing.archive_size.is_none() && rm.archive_size > 0 {
            existing.archive_size = Some(rm.archive_size);
        }
        return;
    }

    entries.push(DisplayEntry {
        name: rm.name.clone(),
        version: rm.version.clone(),
        status: Status::Remote,
        revoked: false,
        sha256: if rm.sha256.is_empty() {
            None
        } else {
            Some(rm.sha256.clone())
        },
        owner: if rm.owner.is_empty() {
            None
        } else {
            Some(rm.owner.clone())
        },
        archive_size: Some(rm.archive_size),
        sources: vec![repo_name.to_string()],
        divergent: !workload_id_matches_canonical,
    });
}

fn shorten(h: &str) -> String {
    if h.len() <= 12 {
        h.to_string()
    } else {
        format!("{}..", &h[..12])
    }
}

fn term_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .or_else(|| std::env::var("COLUMNS").ok()?.parse().ok())
        .unwrap_or(80)
}

/// Truncate a hex string to fit in `width` chars.
/// Min: "0xab..cdef" (10 chars = "0x" + 2 bytes prefix + ".." + 2 bytes suffix).
fn truncate_hex(h: &str, width: usize) -> String {
    if h.len() <= width {
        return h.to_string();
    }
    let width = width.max(10); // floor at "0xab..cdef"
    let inner = width - 2; // subtract ".."
    let prefix = inner.div_ceil(2);
    let suffix = inner / 2;
    format!("{}..{}", &h[..prefix], &h[h.len() - suffix..])
}

/// Join a list of source names for the REPOSITORIES column. If the full
/// list doesn't fit, show the first one plus `+N more`.
fn format_sources(sources: &[String], width: usize) -> String {
    if sources.is_empty() {
        return "-".to_string();
    }
    let full = sources.join(", ");
    if full.len() <= width {
        return full;
    }
    if sources.len() == 1 {
        // Single name too long: raw truncate.
        let w = width.max(4);
        return format!("{}..", &sources[0][..w.saturating_sub(2).min(sources[0].len())]);
    }
    // Show first + "+N more".
    let first = &sources[0];
    let rest_count = sources.len() - 1;
    let suffix = format!(" +{rest_count} more");
    if first.len() + suffix.len() <= width {
        return format!("{first}{suffix}");
    }
    // First name is still too wide; show ellipsis of first.
    let avail = width.saturating_sub(suffix.len() + 2).max(1);
    format!(
        "{}..{suffix}",
        &first[..avail.min(first.len())]
    )
}

fn print_table(entries: &[DisplayEntry], wide: bool) {
    let has_owner = entries.iter().any(|e| e.owner.is_some());
    let has_sources = entries.iter().any(|e| !e.sources.is_empty());
    let tw = term_width();

    // Fixed column widths.
    let w_name = entries.iter().map(|e| e.name.len()).max().unwrap_or(4).max(4);
    let w_ver = entries
        .iter()
        .map(|e| e.version.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let w_size = 6;
    let gap = 2; // spaces between columns
    let sym = 3; // " X " in data rows, "   " in header

    // Compute remaining space for variable columns (hex columns + optional sources).
    let fixed = w_name + gap + w_ver + sym + w_size;
    let remaining = tw.saturating_sub(fixed);

    // Compute the natural max width of the sources column.
    let max_source_width = entries
        .iter()
        .map(|e| e.sources.join(", ").len())
        .max()
        .unwrap_or(0);

    // Column budget: owner (optional) + sha256 + sources (optional).
    //
    // In `--wide` mode the sources column gets its full natural width and
    // the row may extend past the terminal -- the user explicitly opted in.
    // In normal mode sources gets ~1/3 of the remaining width, with the
    // rest split between owner and sha256, and long source lists are
    // truncated by `format_sources`.
    let (w_owner, w_sha256, w_sources) = if has_owner && has_sources {
        if wide {
            let avail = remaining.saturating_sub(gap * 3);
            let half = avail / 2;
            (half.max(10), (avail - half).max(10), max_source_width)
        } else {
            let avail = remaining.saturating_sub(gap * 3);
            let w_src = (avail / 3).max(12);
            let hex_avail = avail.saturating_sub(w_src);
            let half = hex_avail / 2;
            (half.max(10), (hex_avail - half).max(10), w_src)
        }
    } else if has_owner {
        let avail = remaining.saturating_sub(gap * 2);
        let half = avail / 2;
        (half.max(10), (avail - half).max(10), 0)
    } else if has_sources {
        if wide {
            let avail = remaining.saturating_sub(gap * 2);
            (0, avail.saturating_sub(max_source_width).max(10), max_source_width)
        } else {
            let avail = remaining.saturating_sub(gap * 2);
            let w_src = (avail / 3).max(12);
            (0, avail.saturating_sub(w_src).max(10), w_src)
        }
    } else {
        (0, remaining.saturating_sub(gap).max(10), 0)
    };

    // Header.
    print!(
        "{:<w_name$}  {:<w_ver$}   {:<w_size$}",
        "NAME", "VERSION", "SIZE"
    );
    if has_owner {
        print!("  {:<w_owner$}", "OWNER");
    }
    print!("  {:<w_sha256$}", "SHA256");
    if has_sources {
        print!("  {:<w_sources$}", "REPOSITORIES");
    }
    println!();

    let mut last_name = String::new();
    for e in entries {
        let name_col = if e.name == last_name {
            String::new()
        } else {
            last_name.clone_from(&e.name);
            e.name.clone()
        };

        let symbol = if e.revoked { "\u{2717}" } else { e.status.symbol() }; // ✗ for revoked

        let ver_padded = format!("{:<w_ver$}", e.version);

        let size_plain = match e.archive_size {
            Some(s) => format_size(s),
            None => "-".to_string(),
        };
        // Pad plain text, then dim the whole padded string.
        let size_padded = format!("{:<w_size$}", size_plain);
        let size_col = size_padded.dimmed();

        let sha256_plain = match &e.sha256 {
            Some(h) => truncate_hex(h, w_sha256),
            None => "-".to_string(),
        };
        let sha256_padded = format!("{:<w_sha256$}", sha256_plain);

        // Divergent entries (same (name, version) but different sha256
        // across repositories) are rendered in red so they stand out from
        // the normal dimmed rows. Revoked entries already have a distinct
        // `✗` symbol; divergent uses color instead since the two states
        // are orthogonal.
        let name_padded = format!("{:<w_name$}", name_col);
        let name_styled = if e.divergent {
            format!("{}", name_padded.red().bold())
        } else {
            name_padded
        };
        let sha256_styled = if e.divergent {
            format!("{}", sha256_padded.red())
        } else {
            format!("{}", sha256_padded.dimmed())
        };

        let mut row = format!("{name_styled}  {ver_padded} {symbol} {size_col}");

        if has_owner {
            let owner_plain = match &e.owner {
                Some(o) => truncate_hex(o, w_owner),
                None => "-".to_string(),
            };
            let owner_padded = format!("{:<w_owner$}", owner_plain);
            row.push_str(&format!("  {}", owner_padded.dimmed()));
        }
        row.push_str(&format!("  {sha256_styled}"));

        if has_sources {
            let src = format_sources(&e.sources, w_sources);
            let src_padded = format!("{:<w_sources$}", src);
            let src_styled = if e.divergent {
                format!("{}", src_padded.red())
            } else {
                format!("{}", src_padded.cyan())
            };
            row.push_str(&format!("  {src_styled}"));
        }

        println!("{row}");
    }

    // Legend.
    let legend_parts = [
        "\u{25c9} local+tracked",
        "\u{25d4} local",
        "\u{25cc} tracked",
        "\u{25ca} remote",
        "\u{2717} revoked",
        "red = divergent sha256 across repositories",
    ];
    println!();
    println!("{}", legend_parts.join("  ").dimmed());
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
