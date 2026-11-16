use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::RmArgs;
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;

use super::parse_workload_ref;
use crate::config::Config;

pub fn run(args: RmArgs, env: &Env, config: &Config) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);

    let workload_id = parse_workload_ref(&args.reference, &config.alias)?.workload_id();
    let entry = store
        .get(&workload_id)?
        .ok_or_else(|| anyhow::anyhow!("workload not found in store: {workload_id}"))?;
    let (name, version) = (entry.meta.name.clone(), entry.meta.version.clone());

    if args.blob_only {
        store.remove_blob(&workload_id)?;
        println!(
            "Removed archive blob for {}:{}.",
            name.green().bold(),
            version
        );
    } else {
        store.remove(&workload_id)?;
        println!("Removed {}:{}.", name.green().bold(), version);
    }

    Ok(())
}
