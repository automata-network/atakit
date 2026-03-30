use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::LsArgs;
use atakit_workload::registry::{RegistryFilters, RegistryMeta};
use atakit_workload::{RegistryClient, WorkloadStore};
use owo_colors::OwoColorize;

use crate::config::Config;

/// Merged display entry combining local and remote data.
struct DisplayEntry {
    name: String,
    version: String,
    status: Status,
    revoked: bool,
    sha256: Option<String>,
    owner: Option<String>,
    archive_size: Option<u64>,
}

enum Status {
    /// Has blob and on-chain metadata.
    LocalTracked,
    /// Has blob only, no on-chain metadata.
    Local,
    /// Has metadata only, no blob.
    Tracked,
    /// Only on remote registry.
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

    // Collect local entries
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
            });
        }
    }

    // Collect remote entries
    if show_remote {
        match config.registry.resolve_url(args.registry.as_deref()) {
            Ok(url) => {
                let client = RegistryClient::new(&url);
                let filters = RegistryFilters {
                    owner: args.owner.clone(),
                    name: None,
                    name_prefix: None,
                    limit: args.limit,
                    offset: None,
                };
                match client.list(&filters).await {
                    Ok(resp) => {
                        for rm in resp.workloads {
                            // Client-side substring filter (registry has no substring query)
                            if let Some(ref name_filter) = args.name {
                                if !rm.name.contains(name_filter.as_str()) {
                                    continue;
                                }
                            }
                            // Skip if we already have this entry from local
                            if entries.iter().any(|e| {
                                e.name == rm.name && e.version == rm.version
                            }) {
                                continue;
                            }
                            entries.push(from_registry_meta(&rm));
                        }
                    }
                    Err(e) => {
                        eprintln!("warning: failed to list remote workloads: {e}");
                    }
                }
            }
            Err(e) => {
                if args.remote {
                    return Err(e);
                }
                // --all mode: warn but continue with local-only
                eprintln!("warning: {e}");
            }
        }
    }

    // Apply name filter for local entries (remote already filtered by API)
    if let Some(ref filter) = args.name {
        if show_local {
            entries.retain(|e| e.name.contains(filter.as_str()));
        }
    }

    if entries.is_empty() {
        if args.remote || args.all {
            println!("No workloads found.");
        } else {
            println!("No local workloads found.");
        }
        return Ok(());
    }

    // Sort by name, then version
    entries.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

    print_table(&entries);
    Ok(())
}

fn from_registry_meta(rm: &RegistryMeta) -> DisplayEntry {
    DisplayEntry {
        name: rm.name.clone(),
        version: rm.version.clone(),
        status: Status::Remote,
        revoked: false,
        sha256: Some(rm.sha256.clone()),
        owner: Some(rm.owner.clone()),
        archive_size: Some(rm.archive_size),
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

fn print_table(entries: &[DisplayEntry]) {
    let has_owner = entries.iter().any(|e| e.owner.is_some());
    let tw = term_width();

    // Fixed column widths
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

    // Compute remaining space for hex columns.
    // Fixed cols: NAME(gap)VERSION(sym)SIZE
    let fixed = w_name + gap + w_ver + sym + w_size;
    let remaining = tw.saturating_sub(fixed);

    let (w_owner, w_sha256) = if has_owner {
        // Two hex columns, two gaps: remaining = gap + owner + gap + sha256
        let avail = remaining.saturating_sub(gap * 2);
        let half = avail / 2;
        (half.max(10), (avail - half).max(10))
    } else {
        // One hex column, one gap: remaining = gap + sha256
        (0, remaining.saturating_sub(gap).max(10))
    };

    // Header -- "   " matches " X " symbol column in data rows
    if has_owner {
        println!(
            "{:<w_name$}  {:<w_ver$}   {:<w_size$}  {:<w_owner$}  SHA256",
            "NAME", "VERSION", "SIZE", "OWNER"
        );
    } else {
        println!(
            "{:<w_name$}  {:<w_ver$}   {:<w_size$}  SHA256",
            "NAME", "VERSION", "SIZE"
        );
    }

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
        // Pad plain text, then dim the whole padded string
        let size_padded = format!("{:<w_size$}", size_plain);
        let size_col = size_padded.dimmed();

        let sha256_plain = match &e.sha256 {
            Some(h) => truncate_hex(h, w_sha256),
            None => "-".to_string(),
        };

        if has_owner {
            let owner_plain = match &e.owner {
                Some(o) => truncate_hex(o, w_owner),
                None => "-".to_string(),
            };
            let owner_padded = format!("{:<w_owner$}", owner_plain);
            println!(
                "{:<w_name$}  {ver_padded} {symbol} {}  {}  {}",
                name_col,
                size_col,
                owner_padded.dimmed(),
                sha256_plain.dimmed(),
            );
        } else {
            println!(
                "{:<w_name$}  {ver_padded} {symbol} {}  {}",
                name_col,
                size_col,
                sha256_plain.dimmed(),
            );
        }
    }

    // Legend
    let legend_parts = [
        "\u{25c9} local+tracked",
        "\u{25d4} local",
        "\u{25cc} tracked",
        "\u{25ca} remote",
        "\u{2717} revoked",
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
