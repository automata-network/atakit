use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::BuildArgs;
use atakit_workload::{WorkloadMeta, WorkloadStore};
use owo_colors::OwoColorize;

use crate::config::Config;
use crate::progress::IndicatifReporter;

pub async fn run(args: BuildArgs, env: &Env, config: &Config, verbose: bool) -> Result<()> {
    let workload_dir = match args.dir {
        Some(d) => std::fs::canonicalize(d)?,
        None => std::env::current_dir()?,
    };

    let engine = match args.engine {
        Some(ref e) => Some(atakit_workload::ContainerEngine::from_str_opt(e)?),
        None if config.build.container_engine != "auto" => {
            Some(atakit_workload::ContainerEngine::from_str_opt(
                &config.build.container_engine,
            )?)
        }
        None => None,
    };

    let opts = atakit_workload::BuildOptions {
        workload_dir,
        output_dir: args.output,
        engine,
        verbose,
    };

    let progress = IndicatifReporter;
    let result = atakit_workload::build_workload(&opts, &progress).await?;

    println!(
        "{}",
        format!(
            "Done. {} ({} image{}, {} measured file{})",
            result.archive_path.display(),
            result.image_count,
            if result.image_count != 1 { "s" } else { "" },
            result.measured_file_count,
            if result.measured_file_count != 1 { "s" } else { "" },
        )
        .green()
    );
    println!("SHA-256: {}", result.archive_hash.dimmed());

    // Import into store if --store flag is set
    if args.store {
        let store = WorkloadStore::new(&env.workload_dir);

        // Inspect the built archive to get name, version, PCR23
        let inspect_opts = atakit_workload::InspectOptions {
            archive: Some(result.archive_path.clone()),
            workload_dir: None,
            engine: None,
            verbose: false,
        };
        let inspect = atakit_workload::inspect_workload(&inspect_opts).await?;
        let name = &inspect.manifest.meta.name;
        let version = &inspect.manifest.meta.version;

        let size = store.import_blob(name, version, &result.archive_path)?;

        let workload_id = super::compute_workload_id(name, version);
        let now = chrono::Local::now().to_rfc3339();
        let meta = WorkloadMeta {
            workload_id: format!("0x{}", hex::encode(workload_id)),
            name: name.clone(),
            version: version.clone(),
            pcr23: Some(inspect.pcr23),
            owner: None,
            archive_size: Some(size),
            on_chain_spec: None,
            revoked: false,
            registries: Vec::new(),
            added_at: now,
        };
        store.save_meta(&meta)?;
        println!("{}", "Added to local store.".green());
    }

    Ok(())
}
