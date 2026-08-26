use std::io::Write;

use anyhow::{bail, Context, Result};
use atakit_core::Env;
use atakit_workload::cli::PublishArgs;
use atakit_workload::{WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use super::{
    apply_chain_data_to_meta, looks_like_store_ref, query_chain_data, resolve_chain,
    resolve_owner_key,
};
use crate::config::Config;

pub async fn run(args: PublishArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    // Resolve chain config (rpc_url + session_registry) from [chains].
    let chain = resolve_chain(args.chain.as_deref(), config)?;
    let rpc_url = chain.rpc_url;

    let session_registry_address: alloy_ext::core::primitives::Address = chain
        .session_registry
        .parse()
        .context("invalid session registry address")?;

    // Resolve owner private key from [keys].
    let private_key_raw = resolve_owner_key(args.owner_key.as_deref(), config)?;
    let private_key_hex = private_key_raw
        .strip_prefix("0x")
        .unwrap_or(&private_key_raw);
    let signer: alloy_ext::signers::local::PrivateKeySigner =
        private_key_hex.parse().context("invalid private key")?;

    let signer_address = signer.address();
    println!("Signer: {}", format!("{signer_address}").dimmed());

    // Inspect workload to get PCR23 and manifest
    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != crate::config::ContainerEngine::Auto => Some(
            atakit_workload::ContainerEngine::from_str_opt(config.build.container_engine.as_str())?,
        ),
        None => None,
    };

    let archive = if let Some(ref archive_arg) = args.archive {
        let archive_str = archive_arg.to_string_lossy();
        if looks_like_store_ref(&archive_str) {
            let store = WorkloadStore::new(&env.workload_dir);
            let workload_id = super::parse_workload_ref(&archive_str, &config.alias)?.workload_id();
            let blob = store.blob_path(&workload_id)?;
            if !blob.exists() {
                bail!("no archive blob for {archive_str} in store");
            }
            blob
        } else {
            archive_arg.clone()
        }
    } else {
        let dir = match args.dir {
            Some(d) => std::fs::canonicalize(d)?,
            None => std::env::current_dir()?,
        };
        super::find_versioned_archive(&dir)?
    };

    let opts = atakit_workload::InspectOptions {
        publisher: None,
        archive: Some(archive),
        workload_dir: None,
        engine,
        verbose,
        measured_data_root: None,
        unmeasured_data_root: None,
    };

    let result = atakit_workload::inspect_workload(&opts).await?;
    let manifest = &result.manifest;
    let publisher = super::owner_fingerprint(&private_key_raw)?;
    let resolved =
        super::policy::resolve(&result, publisher, args.session_ttl, &args.base_image_id)?;
    let spec = resolved.chain;
    let base_image_mode = spec.baseImageMode;

    // Resolve relay key for transaction submission.
    let relay_key_raw = super::resolve_relay_key(args.relay_key.as_deref(), config)?;
    let relay_key_hex = relay_key_raw.strip_prefix("0x").unwrap_or(&relay_key_raw);
    let relay_key = {
        let bytes: [u8; 32] = hex::decode(relay_key_hex)
            .context("invalid relay key hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("relay key must be 32 bytes"))?;
        alloy_ext::core::primitives::B256::from(bytes)
    };

    let measurement_config = automata_tee_workload_measurement::WorkloadMeasurementConfig {
        rpc_url: rpc_url.clone(),
        relay_key: Some(relay_key),
        session_registry_address,
    };

    println!("Connecting to registry...");
    let measurement =
        automata_tee_workload_measurement::WorkloadMeasurement::new(measurement_config)
            .await
            .context("failed to connect to WorkloadMeasurement")?;

    let registry = measurement.workload_registry();

    // The workload is published as whoever signs the registration, so the
    // owner key's fingerprint is its publisher and therefore part of its
    // identifier.
    let publisher_hex = format!("{publisher:#x}");
    let workload_app_ref = automata_tee_workload_measurement::types::AppRef::new(
        publisher,
        manifest.meta.name.clone(),
        manifest.meta.version.clone(),
    );
    let workload_id = super::compute_workload_id(&workload_app_ref);
    let workload_id_hex = format!("{workload_id:#x}");
    let base_image_mode_str = &manifest.config.base_image_mode;

    println!(
        "{} {}",
        manifest.meta.name.green().bold(),
        manifest.meta.version,
    );
    println!();
    println!("  {:<20}{}", "Workload ID:".dimmed(), workload_id_hex);
    println!("  {:<20}{}", "Manifest SHA256:".dimmed(), result.sha256);
    println!("  {:<20}{}", "PCR23:".dimmed(), result.pcr23_sha256);
    println!(
        "  {:<20}{} ({})",
        "Base Image Mode:".dimmed(),
        base_image_mode_str,
        base_image_mode
    );
    if spec.baseImageIds.is_empty() {
        println!("  {:<20}{}", "Base Image IDs:".dimmed(), "none".dimmed());
    } else {
        for (i, id) in spec.baseImageIds.iter().enumerate() {
            let id_hex = format!("0x{}", hex::encode(id));
            // Show source entry alongside hex ID when derived from manifest.
            let source = if args.base_image_id.is_empty() {
                manifest
                    .config
                    .base_image
                    .get(i)
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default()
            } else {
                String::new()
            };
            if i == 0 {
                println!(
                    "  {:<20}{}{}",
                    "Base Image IDs:".dimmed(),
                    id_hex,
                    source.dimmed()
                );
            } else {
                println!("  {:<20}{}{}", "", id_hex, source.dimmed());
            }
        }
    }
    println!(
        "  {:<20}{}",
        "TTL:".dimmed(),
        if spec.sessionTtl == 0 {
            "contract default (30 days)".to_string()
        } else {
            format!("{}s ({} days)", spec.sessionTtl, spec.sessionTtl / 86400)
        }
    );
    if spec.requirements.is_empty() {
        println!("  {:<20}{}", "Attributes:".dimmed(), "none".dimmed());
    } else {
        for (index, requirement) in spec.requirements.iter().enumerate() {
            let key: [u8; 32] = requirement.key.into();
            let attribute = atakit_core::tee_attributes::VerifiedTeeAttribute::from_key(&key);
            let name = attribute
                .map(|attribute| attribute.name())
                .or_else(|| {
                    manifest
                        .config
                        .attributes
                        .keys()
                        .find(|name| atakit_core::tee_attributes::attribute_key(name) == key)
                        .map(String::as_str)
                })
                .unwrap_or("unknown");
            let values = if attribute.is_none() {
                manifest
                    .config
                    .attributes
                    .get(name)
                    .into_iter()
                    .flatten()
                    .map(|value| match value {
                        atakit_core::tee_attributes::AttributeValue::String(value) => {
                            format!("{value:?}")
                        }
                        atakit_core::tee_attributes::AttributeValue::Boolean(value) => {
                            value.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                requirement
                    .allowedValues
                    .iter()
                    .map(|value| {
                        let value: [u8; 32] = (*value).into();
                        attribute
                            .and_then(|attribute| {
                                atakit_core::tee_attributes::readable_reserved_value(
                                    attribute, &value,
                                )
                            })
                            .unwrap_or_else(|| format!("0x{}", hex::encode(value)))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!(
                "  {:<20}{} = [{}]",
                if index == 0 { "Attributes:" } else { "" },
                name,
                values
            );
        }
    }
    println!();

    if let Ok(existing) = registry.get_workload_spec(workload_id).await {
        let is_revoked = registry
            .is_workload_revoked(workload_id)
            .await
            .unwrap_or(false);
        println!();
        if is_revoked {
            println!(
                "{}",
                "Workload version was previously deactivated."
                    .yellow()
                    .bold()
            );
            println!("  {:<18}{}", "Workload ID:", workload_id_hex);
            println!(
                "  {:<18}{} {}",
                "Registered as:", existing.name, existing.version
            );
            println!();
            println!(
                "{}",
                "A deactivated version cannot be re-registered. Please use a new version tag."
                    .yellow()
            );
            println!(
                "  {}",
                "Example: update 'version' in workload.toml to a new value (e.g. v0.0.2)".yellow()
            );
        } else {
            println!("{}", "Workload already registered.".yellow().bold());
            println!("  {:<18}{}", "Workload ID:", workload_id_hex);
            println!(
                "  {:<18}{} {}",
                "Registered as:", existing.name, existing.version
            );
            println!();
            println!(
                "{}",
                "To publish updated measurements, use a new version tag.".yellow()
            );
            println!(
                "  {}",
                "Example: update 'version' in workload.toml to a new value (e.g. v0.0.2)".yellow()
            );
        }

        // Always refresh on-chain data into local store
        if let Ok(chain_data) =
            query_chain_data(workload_id, &rpc_url, &chain.session_registry).await
        {
            let store = WorkloadStore::new(&env.workload_dir);
            let now = chrono::Local::now().to_rfc3339();
            let existing_meta = match store.load_meta(&workload_id_hex) {
                Ok(meta) => meta,
                Err(atakit_workload::WorkloadError::UnsupportedMeta { .. }) => None,
                Err(error) => return Err(error.into()),
            };
            let meta = match existing_meta {
                Some(mut m) => {
                    m.workload_id = workload_id_hex.clone();
                    m.publisher = publisher_hex.clone();
                    m.publisher = publisher_hex.clone();
                    m.sha256 = Some(result.sha256.clone());
                    m.pcr23 = Some(result.pcr23_sha256.clone());
                    apply_chain_data_to_meta(&mut m, &chain_data);
                    m.added_at = now;
                    m
                }
                None => {
                    let mut m = WorkloadMeta {
                        metadata_format: atakit_workload::store::WORKLOAD_META_FORMAT_VERSION,
                        workload_id: workload_id_hex.clone(),
                        publisher: publisher_hex.clone(),
                        name: manifest.meta.name.clone(),
                        version: manifest.meta.version.clone(),
                        sha256: Some(result.sha256.clone()),
                        pcr23: Some(result.pcr23_sha256.clone()),
                        owner: None,
                        archive_size: None,
                        on_chain_spec: None,
                        revoked: false,
                        repositories: Vec::new(),
                        added_at: now,
                    };
                    apply_chain_data_to_meta(&mut m, &chain_data);
                    m
                }
            };
            store.save_meta(&meta)?;
            println!("{}", "Local metadata synced with on-chain state.".green());
        }

        return Ok(());
    }

    if !args.yes {
        eprint!("Publish? [y/N] ");
        std::io::stderr().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("Submitting registerWorkload transaction...");
    let op_expiry_seconds = args.op_expiry_seconds.unwrap_or(chain.op_expiry_seconds);
    let result_id = registry
        .register_workload(&signer, spec, op_expiry_seconds)
        .await
        .context("registerWorkload failed")?;

    println!();
    println!("{}", "Workload published successfully.".green().bold());
    println!("  {:<18}0x{}", "Workload ID:", hex::encode(result_id),);

    // Refresh on-chain data into local store
    if let Ok(chain_data) = query_chain_data(workload_id, &rpc_url, &chain.session_registry).await {
        let store = WorkloadStore::new(&env.workload_dir);
        let now = chrono::Local::now().to_rfc3339();
        let existing_meta = match store.load_meta(&workload_id_hex) {
            Ok(meta) => meta,
            Err(atakit_workload::WorkloadError::UnsupportedMeta { .. }) => None,
            Err(error) => return Err(error.into()),
        };
        let meta = match existing_meta {
            Some(mut m) => {
                m.workload_id = workload_id_hex.clone();
                m.publisher = publisher_hex.clone();
                m.sha256 = Some(result.sha256.clone());
                m.pcr23 = Some(result.pcr23_sha256.clone());
                apply_chain_data_to_meta(&mut m, &chain_data);
                m.added_at = now;
                m
            }
            None => {
                let mut m = WorkloadMeta {
                    metadata_format: atakit_workload::store::WORKLOAD_META_FORMAT_VERSION,
                    workload_id: workload_id_hex.clone(),
                    publisher: publisher_hex.clone(),
                    name: manifest.meta.name.clone(),
                    version: manifest.meta.version.clone(),
                    sha256: Some(result.sha256.clone()),
                    pcr23: Some(result.pcr23_sha256.clone()),
                    owner: None,
                    archive_size: None,
                    on_chain_spec: None,
                    revoked: false,
                    repositories: Vec::new(),
                    added_at: now,
                };
                apply_chain_data_to_meta(&mut m, &chain_data);
                m
            }
        };
        store.save_meta(&meta)?;
        println!("{}", "Local store updated.".green());
    }

    Ok(())
}
