use std::io::{IsTerminal, Write};

use anyhow::{Context, Result};
use atakit_core::Env;
use atakit_workload::cli::PullArgs;
use atakit_workload::{
    RepositoryArchiveMeta, WorkloadCoords, WorkloadError, WorkloadMeta, WorkloadRepository,
    WorkloadStore,
};
use futures_util::future::join_all;
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
    let pinned = args.repository.is_some();
    // Strictness keys off fan-out CARDINALITY, not whether
    // --repository was passed. With exactly one target, failures
    // (credential or probe) are fatal because there's no fallback --
    // downgrading them to warnings leaves the user staring at a
    // misleading "not found in any configured repository" message
    // when the real problem was a stale token or a network hiccup.
    // A one-entry config behaves the same as --repository=<that
    // entry> without the user having to spell it out.
    let single_target = specs.len() == 1;

    // Resolve every distinct credential up front so a slow helper is
    // invoked at most once even in multi-repo discovery mode.
    //
    // * Single target: strict. Credential failure -> hard error with
    //   the real cause, not a downgraded skip.
    // * Multi-target discovery: best-effort. One broken credential
    //   must not abort discovery for unrelated repositories that
    //   could still serve the pull. Repos whose credential fails
    //   are skipped with a per-repo warning.
    let cred_names: Vec<&str> = specs
        .iter()
        .filter_map(|(_, spec)| match spec {
            crate::config::WorkloadRepositorySpec::Github {
                credential: Some(name),
                ..
            } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    // Credential resolution can spawn a `command`-type helper with
    // up to `timeout_secs` of blocking wait. Wrap in
    // `block_in_place` so the tokio worker thread can yield to
    // other tasks instead of being held captive.
    let (tokens, cred_errs): (
        std::collections::HashMap<String, String>,
        std::collections::HashMap<String, String>,
    ) = tokio::task::block_in_place(|| -> Result<_> {
        Ok(if single_target {
            (
                config.resolve_credentials_for(&cred_names)?,
                std::collections::HashMap::new(),
            )
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

    // Parse the user's reference. We need it up front so we know whether
    // to do name-based lookups (cheap) or id-based scans (more expensive
    // for github backends).
    let wref = parse_workload_ref(&args.reference)?;

    // Filter out repos whose credential resolution failed (discovery
    // mode only -- pinned/single-target mode would have already
    // errored via `resolve_credentials_for?` above) and build a
    // ready-to-probe list of (display-name, WorkloadRepository)
    // pairs. Each surviving entry will be probed in parallel.
    let ready_repos: Vec<(String, WorkloadRepository)> = specs
        .into_iter()
        .filter_map(|(name, spec)| {
            if let crate::config::WorkloadRepositorySpec::Github {
                credential: Some(cred_name),
                ..
            } = &spec
            {
                if cred_errs.contains_key(cred_name) {
                    eprintln!(
                        "{} skipping {} (credential '{}' failed)",
                        "warning:".yellow(),
                        name.dimmed(),
                        cred_name.dimmed(),
                    );
                    return None;
                }
            }
            let resolved_token = match &spec {
                crate::config::WorkloadRepositorySpec::Github {
                    credential: Some(cred_name),
                    ..
                } => tokens.get(cred_name).cloned(),
                _ => None,
            };
            let repo = config.workload.build_repository(spec, resolved_token);
            Some((name, repo))
        })
        .collect();

    // Probe every ready repository for the workload IN PARALLEL.
    // `get_meta` for name:version and `resolve` for 0xhex are both
    // read-only network calls, so running them concurrently is a
    // pure latency win -- the docs already promised this behavior
    // and `workload ls --remote` has the same shape. Each future
    // owns its `(name, repo)` pair and the workload ref and
    // returns everything the post-join loop needs to build a
    // `Candidate` or emit a warning.
    //
    // A `Hit` probe result means the workload was found and
    // carries coords + metadata. A `Miss` means the workload
    // isn't in this repo -- expected during multi-repo discovery,
    // silent. An `IdMismatch` means the repository returned a
    // workload whose id doesn't match what we asked for (defense
    // in depth against a backend that redirects / mis-routes) --
    // we warn and treat it as a miss. An `Err` means the
    // repository itself is broken (network fault, auth failure,
    // 5xx) -- single-target: fatal with the real cause;
    // multi-target: warn and continue.
    enum ProbeResult {
        Hit(WorkloadCoords, RepositoryArchiveMeta),
        Miss,
        IdMismatch {
            returned: String,
            expected: String,
        },
        Error(WorkloadError),
    }

    let probe_futures = ready_repos.into_iter().map(|(name, repo)| {
        let wref = wref.clone();
        async move {
            let display = repo.display_uri();
            let result = match wref {
                WorkloadRef::NameVersion {
                    name: wname,
                    version: wversion,
                } => {
                    let id = compute_workload_id(&wname, &wversion);
                    let coords = WorkloadCoords {
                        workload_id: format!("0x{}", hex::encode(id)),
                        name: wname,
                        version: wversion,
                    };
                    match repo.get_meta(&coords).await {
                        Ok(Some(meta)) => ProbeResult::Hit(coords, meta),
                        Ok(None) => ProbeResult::Miss,
                        Err(e) => ProbeResult::Error(e),
                    }
                }
                WorkloadRef::Id(id) => match repo.resolve(&id).await {
                    Ok(Some((coords, meta))) => {
                        if hex_equal(&coords.workload_id, &id) {
                            ProbeResult::Hit(coords, meta)
                        } else {
                            ProbeResult::IdMismatch {
                                returned: coords.workload_id,
                                expected: id,
                            }
                        }
                    }
                    Ok(None) => ProbeResult::Miss,
                    Err(e) => ProbeResult::Error(e),
                },
            };
            (name, repo, display, result)
        }
    });
    let probe_results = join_all(probe_futures).await;

    let mut candidates: Vec<Candidate> = Vec::new();
    for (name, repo, display, result) in probe_results {
        match result {
            ProbeResult::Hit(coords, meta) => candidates.push(Candidate {
                name,
                repo,
                coords,
                meta,
            }),
            ProbeResult::Miss => {
                // Not in this repo -- expected during multi-repo discovery.
            }
            ProbeResult::IdMismatch { returned, expected } => {
                eprintln!(
                    "{} {}: returned metadata for {} instead of requested {}; ignoring",
                    "warning:".yellow(),
                    display.dimmed(),
                    returned.dimmed(),
                    expected.dimmed(),
                );
            }
            ProbeResult::Error(e) => {
                if single_target {
                    // Exactly one target in play (either user pinned
                    // it with --repository or the config has a
                    // single entry). A probe failure is the real
                    // reason the pull can't proceed; don't swallow
                    // it as a warning and pretend "not found in any
                    // configured repository" later.
                    return Err(anyhow::Error::from(e)).with_context(|| {
                        format!("repository {display} probe failed")
                    });
                }
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
            if pinned {
                anyhow::bail!(
                    "workload {} was not found in repository {}",
                    args.reference,
                    args.repository.as_deref().unwrap_or("?"),
                );
            }
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
    // Use hex_equal so harmless prefix / case differences between what
    // the repository stored and what we compute locally don't trigger
    // a false mismatch.
    let expected_id = compute_workload_id(archive_name, archive_version);
    let expected_id_hex = format!("0x{}", hex::encode(expected_id));
    if !hex_equal(&expected_id_hex, &coords.workload_id) {
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
    //
    // Checks (2) and (3) can be silently skipped when the repository
    // didn't supply the corresponding field (hand-curated github
    // repos without sidecar `.meta.json`). In that case we warn to
    // stderr explicitly instead of pretending "integrity verified"
    // when two of four checks were quietly dropped -- matches the
    // verbosity of check (4)'s skip path in `verify_pcr23`. Track
    // whether each check actually ran so the summary line below
    // only claims what we really verified.
    let sha256_checked = if probe_meta.sha256.is_empty() {
        eprintln!(
            "{} repository {} did not advertise a manifest sha256; \
             integrity check (2) skipped",
            "warning:".yellow(),
            repo_name.dimmed(),
        );
        false
    } else if !hex_equal(&probe_meta.sha256, sha256) {
        anyhow::bail!(
            "manifest sha256 mismatch between repository metadata and downloaded archive\n\
             \n  repository ({}): {}\n  downloaded archive: {}",
            repo_name,
            probe_meta.sha256,
            sha256,
        );
    } else {
        true
    };

    let archive_checked = if probe_meta.archive_hash.is_empty() {
        eprintln!(
            "{} repository {} did not advertise an archive hash; \
             integrity check (3) skipped",
            "warning:".yellow(),
            repo_name.dimmed(),
        );
        false
    } else {
        // `hash_file` uses synchronous std::fs I/O. For large `.atawl`
        // archives (hundreds of MB) that blocks a Tokio worker thread
        // for the duration of the hash, starving other async work.
        // Move it onto the blocking pool.
        let hash_path = tmp_path.clone();
        let actual_archive_hash = tokio::task::spawn_blocking(move || {
            atakit_workload::hash::hash_file(&hash_path)
        })
        .await
        .context("archive hashing task panicked")?
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
        true
    };

    if archive_checked {
        println!(
            "  {}",
            "Archive integrity verified against repository metadata.".dimmed()
        );
    } else if sha256_checked {
        println!(
            "  {}",
            "Manifest sha256 verified against repository metadata.".dimmed()
        );
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
    println!("  {:<18}{}", "Manifest SHA256:", sha256.dimmed());

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
///   `[publish] rpc_url` / `[publish] session_registry` is a silent skip
///   (the user hasn't opted in to chain verification). The remaining
///   conditions -- unreachable RPC, workload not yet registered on-chain,
///   on-chain spec without a PCR23 entry -- do not fail the pull, but
///   the first two emit a `warning:` on stderr so transient or
///   configuration issues are visible. A PCR23 **mismatch** is ALWAYS a
///   hard error regardless of mode.
/// * `strict = true` (from `workload pull --verify`): require RPC config,
///   require the workload to be registered, require a PCR23 entry, and
///   require a match. Any gap bails.
async fn verify_pcr23(
    workload_id_hex: &str,
    pcr23: &str,
    config: &Config,
    strict: bool,
) -> Result<()> {
    let Some(chain_name) = config.publish.chain.as_deref() else {
        if strict {
            anyhow::bail!("chain config required for --verify: set [publish] chain in config");
        }
        return Ok(());
    };
    let Some(chain_config) = config.chains.get(chain_name) else {
        if strict {
            anyhow::bail!("chain '{chain_name}' not found in [chains]");
        }
        return Ok(());
    };
    let rpc_url = chain_config.rpc_url.as_str();
    let session_registry_str = chain_config.session_registry.as_str();

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
        Err(e) => {
            // Distinguish "workload not yet registered" (a valid state
            // during an early pull) from transient RPC / contract
            // errors (user should know). We don't have typed errors
            // from the automata-tee-workload-measurement binding, so
            // use a best-effort string match on the error message.
            // Anything that doesn't look like "revert / not found /
            // not registered" is treated as unexpected.
            let msg = e.to_string();
            let m = msg.to_ascii_lowercase();
            let looks_not_registered = m.contains("revert")
                || m.contains("not found")
                || m.contains("not registered")
                || m.contains("empty return data");

            if strict {
                if looks_not_registered {
                    anyhow::bail!("workload not registered on-chain (id {workload_id_hex})");
                }
                anyhow::bail!(
                    "failed to query on-chain spec for {workload_id_hex}: {e}"
                );
            }

            if !looks_not_registered {
                // Transient or unexpected failure: make it visible so
                // users don't mistake a broken RPC for a missing spec.
                eprintln!(
                    "{} on-chain spec query for {} failed: {}",
                    "warning:".yellow(),
                    workload_id_hex,
                    e,
                );
            }
            // Either way we skip the check and let the pull continue.
            // Not-registered is an expected state during a mirror pull
            // before publish; unexpected errors shouldn't block pulls
            // either, they just need to be visible.
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
