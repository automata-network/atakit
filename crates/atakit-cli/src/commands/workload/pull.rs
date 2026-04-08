use std::io::{IsTerminal, Write};

use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::PullArgs;
use atakit_workload::{
    RepositoryArchiveMeta, WorkloadCoords, WorkloadMeta, WorkloadRepository, WorkloadStore,
};
use owo_colors::OwoColorize;

use super::{compute_workload_id, hex_equal, parse_workload_ref, WorkloadRef};
use crate::config::Config;
use crate::progress::IndicatifReporter;

/// One repository that advertises the requested workload.
struct Candidate {
    name: String,
    repo: WorkloadRepository,
    coords: WorkloadCoords,
    meta: RepositoryArchiveMeta,
}

pub async fn run(args: PullArgs, env: &Env, config: &Config) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);

    // Build every repository we need to consider. If --repository was
    // passed, we only consider that one (and go directly to download if
    // the workload is present). Otherwise we fan out across every
    // configured repository.
    let specs = config.workload.all_repositories(args.repository.as_deref())?;
    let token = config.github_token().map(str::to_string);

    // Parse the user's reference. We need it up front so we know whether
    // to do name-based lookups (cheap) or id-based scans (more expensive
    // for github backends).
    let wref = parse_workload_ref(&args.reference)?;

    // Probe every repository for the workload. A `None` return means
    // "workload isn't in this repo" -- a clean negative, silent. An
    // `Err` means the repository itself is broken (network fault, auth
    // failure, 5xx) -- warn to stderr and continue so other repositories
    // can still serve the pull.
    let mut candidates: Vec<Candidate> = Vec::new();
    for (name, spec) in specs {
        let repo = config.workload.build_repository(spec, token.clone());
        let display = repo.display_uri();

        let probe: Result<Option<(WorkloadCoords, RepositoryArchiveMeta)>, _> = match &wref {
            WorkloadRef::NameVersion {
                name: wname,
                version: wversion,
            } => {
                let id = compute_workload_id(wname, wversion);
                let coords = WorkloadCoords {
                    workload_id: format!("0x{}", hex::encode(id)),
                    name: wname.clone(),
                    version: wversion.clone(),
                };
                repo.get_meta(&coords)
                    .await
                    .map(|opt| opt.map(|meta| (coords, meta)))
            }
            WorkloadRef::Id(id) => repo.resolve(id).await,
        };

        match probe {
            Ok(Some((coords, meta))) => candidates.push(Candidate {
                name,
                repo,
                coords,
                meta,
            }),
            Ok(None) => {
                // Not in this repo -- expected during multi-repo discovery.
            }
            Err(e) => {
                eprintln!(
                    "{} {}: {}",
                    "warning:".yellow(),
                    display.dimmed(),
                    e.to_string().dimmed(),
                );
            }
        }
    }

    let chosen = match candidates.len() {
        0 => {
            anyhow::bail!(
                "workload {} was not found in any configured repository",
                args.reference
            );
        }
        1 => candidates.remove(0),
        _ => select_candidate(&args.reference, candidates)?,
    };

    let Candidate {
        name: repo_name,
        repo,
        coords,
        meta: probe_meta,
    } = chosen;
    let repo_uri = repo.display_uri();

    // Check if blob already in store (metadata-only entries from `add`
    // should still pull).
    if store.has_blob(&coords.name, &coords.version) && !args.force {
        println!(
            "Workload {}:{} already in store (use --force to overwrite).",
            coords.name, coords.version
        );
        return Ok(());
    }

    // Download archive to temp file (streaming, bounded memory).
    println!(
        "Downloading {}:{} from {} ({})...",
        coords.name.green().bold(),
        coords.version,
        repo_name.cyan(),
        repo_uri.dimmed(),
    );
    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;
    let tmp_path = tmp_dir.path().join("download.atawl");
    let reporter = IndicatifReporter;
    let archive_size = repo
        .download_to_file(&coords, &tmp_path, &reporter)
        .await
        .context("failed to download archive")?;

    // Inspect downloaded archive using the shared library inspector.
    let inspect_opts = atakit_workload::InspectOptions {
        archive: Some(tmp_path.clone()),
        workload_dir: None,
        engine: None,
        verbose: false,
    };
    let inspection = atakit_workload::inspect_workload(&inspect_opts)
        .await
        .context("failed to inspect downloaded archive")?;
    let sha256 = &inspection.sha256;
    let pcr23 = &inspection.pcr23;
    let archive_name = &inspection.manifest.meta.name;
    let archive_version = &inspection.manifest.meta.version;

    // Verify the archive's manifest matches the requested identity.
    let expected_id = compute_workload_id(archive_name, archive_version);
    let expected_id_hex = format!("0x{}", hex::encode(expected_id));
    if expected_id_hex != coords.workload_id {
        anyhow::bail!(
            "archive identity mismatch: requested {}:{} ({}), \
             but archive contains {}:{} ({})",
            coords.name,
            coords.version,
            &coords.workload_id[..10],
            archive_name,
            archive_version,
            &expected_id_hex[..10],
        );
    }

    // Integrity check against the repository's own advertised metadata.
    // Catches a tampered or corrupted archive served by an honest-looking
    // repository. For the stronger on-chain check pass --verify.
    if !probe_meta.sha256.is_empty() && !hex_equal(&probe_meta.sha256, sha256) {
        anyhow::bail!(
            "manifest sha256 mismatch between repository metadata and downloaded archive\n\
             \n  repository ({}): {}\n  downloaded archive: {}",
            repo_name,
            probe_meta.sha256,
            sha256,
        );
    }
    if !probe_meta.archive_hash.is_empty() {
        let actual_archive_hash = atakit_workload::hash::hash_file(&tmp_path)
            .context("failed to hash downloaded archive")?;
        if !hex_equal(&probe_meta.archive_hash, &actual_archive_hash) {
            anyhow::bail!(
                "archive sha256 mismatch between repository metadata and downloaded archive\n\
                 \n  repository ({}): {}\n  downloaded archive: {}",
                repo_name,
                probe_meta.archive_hash,
                actual_archive_hash,
            );
        }
        println!("  {}", "Archive integrity verified against repository metadata.".dimmed());
    } else if !probe_meta.sha256.is_empty() {
        println!("  {}", "Manifest sha256 verified against repository metadata.".dimmed());
    }

    // Verify against the on-chain spec. This is always best-effort: if
    // RPC is configured and the workload is registered on-chain, the
    // PCR23 must match -- a mismatch is a hard error. If RPC is not
    // configured or the workload isn't registered yet, the check is
    // silently skipped. Pass `--verify` to require all of these to
    // exist and match (strict mode).
    verify_pcr23(&coords.workload_id, pcr23, config, args.verify).await?;

    // Import blob from temp file into store.
    store.import_blob(&coords.name, &coords.version, &tmp_path)?;

    let now = chrono::Local::now().to_rfc3339();
    let meta = match store.load_meta(&coords.name, &coords.version)? {
        Some(mut existing) => {
            existing.workload_id = coords.workload_id.clone();
            existing.sha256 = Some(sha256.clone());
            existing.pcr23 = Some(pcr23.clone());
            existing.archive_size = Some(archive_size);
            if !existing.repositories.contains(&repo_uri) {
                existing.repositories.push(repo_uri.clone());
            }
            existing.added_at = now;
            existing
        }
        None => WorkloadMeta {
            workload_id: coords.workload_id.clone(),
            name: coords.name.clone(),
            version: coords.version.clone(),
            sha256: Some(sha256.clone()),
            pcr23: Some(pcr23.clone()),
            owner: None,
            archive_size: Some(archive_size),
            on_chain_spec: None,
            revoked: false,
            repositories: vec![repo_uri.clone()],
            added_at: now,
        },
    };
    store.save_meta(&meta)?;

    println!();
    println!("{}", "Pull complete.".green().bold());
    println!("  {:<18}{}:{}", "Workload:", coords.name, coords.version);
    println!("  {:<18}{}", "Size:", format_size(archive_size));
    println!("  {:<18}{}", "SHA256:", sha256.dimmed());

    Ok(())
}

/// Interactive selector for resolving ties when multiple repositories
/// advertise the same workload. Refuses in non-interactive sessions.
fn select_candidate(reference: &str, candidates: Vec<Candidate>) -> Result<Candidate> {
    if !std::io::stdin().is_terminal() {
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        anyhow::bail!(
            "workload {reference} is available in {} repositories ({}); \
             pass --repository to choose one",
            candidates.len(),
            names.join(", "),
        );
    }

    eprintln!(
        "{} {} is available in {} repositories:",
        "note:".cyan(),
        reference,
        candidates.len(),
    );
    for (i, c) in candidates.iter().enumerate() {
        let sha = c
            .meta
            .sha256
            .get(..10)
            .map(|s| format!(" (sha256 {}..)", s))
            .unwrap_or_default();
        eprintln!(
            "  [{idx}] {name}  {uri}{sha}",
            idx = i + 1,
            name = c.name.cyan().bold(),
            uri = c.repo.display_uri().dimmed(),
        );
    }
    eprint!("Select [1-{}] (or enter to cancel): ", candidates.len());
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("failed to read selection")?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("cancelled");
    }
    let pick: usize = trimmed
        .parse()
        .with_context(|| format!("invalid selection '{trimmed}'"))?;
    if pick == 0 || pick > candidates.len() {
        anyhow::bail!("selection {pick} out of range");
    }
    // Note: candidates is a Vec, so .into_iter().nth(pick - 1) consumes it.
    Ok(candidates.into_iter().nth(pick - 1).unwrap())
}

/// Verify the archive's PCR23 (final register value) against on-chain matchData.
///
/// On-chain STATIC matchData for PCR23 contains the final PCR value
/// (SHA-256(zeros_32 || event_hash)), which matches `InspectResult.pcr23`.
///
/// # Modes
///
/// * `strict = false` (default from `workload pull`): best-effort. Missing
///   `[publish] rpc_url` / `[publish] session_registry`, a workload that
///   isn't registered on-chain, or an on-chain spec with no PCR23 entry
///   are all silently skipped. A PCR23 **mismatch** is ALWAYS an error.
/// * `strict = true` (from `workload pull --verify`): require RPC config,
///   require the workload to be registered, require a PCR23 entry, and
///   require a match. Any gap bails.
async fn verify_pcr23(
    workload_id_hex: &str,
    pcr23: &str,
    config: &Config,
    strict: bool,
) -> Result<()> {
    let Some(rpc_url) = config.publish.rpc_url.as_deref() else {
        if strict {
            anyhow::bail!("RPC URL required for --verify");
        }
        return Ok(());
    };
    let Some(session_registry_str) = config.publish.session_registry.as_deref() else {
        if strict {
            anyhow::bail!("session registry required for --verify");
        }
        return Ok(());
    };

    let session_registry_address: alloy_ext::core::primitives::Address =
        session_registry_str.parse().context("invalid session registry address")?;

    let id_hex = workload_id_hex.strip_prefix("0x").unwrap_or(workload_id_hex);
    let id_bytes: [u8; 32] = hex::decode(id_hex)
        .context("invalid workload ID hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("workload ID must be 32 bytes"))?;
    let workload_id = alloy_ext::core::primitives::B256::from(id_bytes);

    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url: rpc_url.to_string(),
        relay_key: None,
        session_registry_address,
    };

    let measurement =
        match automata_tee_workload_measurement::WorkloadMeasurement::new(measurement_config).await
        {
            Ok(m) => m,
            Err(e) => {
                if strict {
                    return Err(anyhow::anyhow!("failed to connect to WorkloadMeasurement: {e}"));
                }
                eprintln!(
                    "{} on-chain verification skipped: {e}",
                    "warning:".yellow()
                );
                return Ok(());
            }
        };

    let registry = measurement.workload_registry();
    let spec = match registry.get_workload_spec(workload_id).await {
        Ok(s) => s,
        Err(_) => {
            if strict {
                anyhow::bail!("workload not registered on-chain (id {workload_id_hex})");
            }
            // Not-registered is a perfectly valid state during iteration
            // (user may be pulling a workload before publishing it on a
            // mirror). Silent skip.
            return Ok(());
        }
    };

    // Find PCR23 in the spec. matchData[0] is the final PCR register value.
    let on_chain_pcr23 = spec
        .pcrs
        .iter()
        .find(|p| p.pcrIndex == 23)
        .and_then(|p| p.matchData.first())
        .map(|b| format!("0x{}", hex::encode(b)));

    match on_chain_pcr23 {
        Some(ref expected) => {
            if !hex_equal(expected, pcr23) {
                anyhow::bail!(
                    "PCR23 mismatch between downloaded archive and on-chain spec\n\
                     \n  archive:  {pcr23}\n  on-chain: {expected}"
                );
            }
            println!("  {}", "On-chain PCR23 verified.".green());
        }
        None => {
            if strict {
                anyhow::bail!("on-chain spec for {workload_id_hex} has no PCR23 entry");
            }
            eprintln!(
                "{} on-chain spec has no PCR23 entry; integrity check skipped",
                "warning:".yellow()
            );
        }
    }

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
