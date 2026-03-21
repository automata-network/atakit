use anyhow::Result;
use atakit_core::Env;
use atakit_workload::cli::ExportArgs;
use atakit_workload::WorkloadStore;
use owo_colors::OwoColorize;

use super::parse_workload_ref;

pub fn run(args: ExportArgs, env: &Env) -> Result<()> {
    let store = WorkloadStore::new(&env.workload_dir);

    let wref = parse_workload_ref(&args.reference)?;
    let (name, version) = super::resolve_ref(&wref, &store)?;

    if !store.has_blob(&name, &version) {
        anyhow::bail!("no archive blob for {name}:{version} in store");
    }

    let src = store.blob_path(&name, &version)?;
    let output_dir = match args.output {
        Some(path) => path,
        None => std::env::current_dir()
            .map_err(|e| anyhow::anyhow!("failed to determine current directory: {e}"))?,
    };
    let dest = output_dir.join(format!("{name}-{version}.atawl"));

    std::fs::copy(&src, &dest)?;

    println!("{}", "Exported.".green().bold());
    println!("  {}", dest.display());

    Ok(())
}
