use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::RmArgs;
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;

use super::parse_workload_ref;

pub fn run(args: RmArgs, env: &Env) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);

    let wref = parse_workload_ref(&args.reference)?;
    let (name, version) = super::resolve_ref(&wref, &store)?;

    if !store.exists(&name, &version) {
        anyhow::bail!("workload not found in store: {name}:{version}");
    }

    if args.blob_only {
        store.remove_blob(&name, &version)?;
        println!(
            "Removed archive blob for {}:{}.",
            name.green().bold(),
            version
        );
    } else {
        store.remove(&name, &version)?;
        println!("Removed {}:{}.", name.green().bold(), version);
    }

    Ok(())
}
