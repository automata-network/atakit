use anyhow::Result;
use atakit_workload::cli::BuildArgs;
use owo_colors::OwoColorize;

use crate::config::Config;
use crate::progress::IndicatifReporter;

pub async fn run(args: BuildArgs, config: &Config, verbose: bool) -> Result<()> {
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

    Ok(())
}
