mod commands;
mod config;
mod progress;

use anyhow::Result;
use atakit_core::Env;
use config::Config;
use atakit_image::ImageCommand;
use atakit_workload::cli::WorkloadCommand;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// atakit -- All-in-one tool for creation, provisioning, and management of CVMs.
#[derive(Parser)]
#[command(name = "atakit", version, about)]
struct Cli {
    /// Show verbose output (e.g. container build logs)
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage CVM base images
    #[command(subcommand)]
    Image(ImageCommand),
    /// Manage workloads
    #[command(subcommand)]
    Workload(WorkloadCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let env = Env::from_env();
    for (path, err) in env.ensure_dirs() {
        eprintln!("warning: failed to create directory '{}': {err}", path.display());
    }
    config::ensure_template(&env.config_dir);
    let cli = Cli::parse();
    let config = Config::load(&env.config_dir)?;
    if let Some(legacy) = env.check_legacy_dir() {
        // Sanity check: refuse to suggest rm on suspiciously short paths.
        let safe = |p: &std::path::Path| p.components().count() >= 3;
        let q = |p: &std::path::Path| shell_escape::escape(p.display().to_string().into());
        if legacy.new_dir_exists {
            eprintln!(
                "warning: legacy image store at {} is no longer used",
                legacy.legacy_dir.display(),
            );
            eprintln!(
                "  atakit now uses {}.",
                legacy.new_dir.display(),
            );
            if safe(&legacy.legacy_dir) {
                eprintln!("  You can remove the old directory:");
                eprintln!(
                    "    rm -r {} && rmdir {} 2>/dev/null",
                    q(&legacy.legacy_dir),
                    q(&legacy.legacy_parent),
                );
            }
        } else {
            eprintln!(
                "warning: legacy image store detected at {}",
                legacy.legacy_dir.display(),
            );
            if safe(&legacy.legacy_dir) && safe(&legacy.new_dir) {
                eprintln!("  atakit now uses XDG paths. To migrate, run:");
                eprintln!(
                    "    mkdir -p {} && mv {} {} && rmdir {} 2>/dev/null",
                    q(legacy.new_dir.parent().unwrap_or(&legacy.new_dir)),
                    q(&legacy.legacy_dir),
                    q(&legacy.new_dir),
                    q(&legacy.legacy_parent),
                );
            } else {
                eprintln!("  atakit now uses XDG paths. Please migrate manually.");
            }
        }
    }

    match cli.command {
        Command::Image(cmd) => match cmd {
            ImageCommand::Ls(args) => commands::image::ls::run(args, &env, &config).await,
            ImageCommand::Pull(args) => commands::image::pull::run(args, &env, &config).await,
            ImageCommand::Rm(args) => commands::image::rm::run(args, &env).await,
        },
        Command::Workload(cmd) => match cmd {
            WorkloadCommand::Create(args) => commands::workload::create::run(args),
            WorkloadCommand::Build(args) => {
                commands::workload::build::run(args, &config, cli.verbose).await
            }
            WorkloadCommand::Info(args) => {
                commands::workload::info::run(args, &config, cli.verbose).await
            }
            WorkloadCommand::Publish(args) => {
                commands::workload::publish::run(args, &config, cli.verbose).await
            }
            WorkloadCommand::Deactivate(args) => {
                commands::workload::deactivate::run(args, &config, cli.verbose).await
            }
            WorkloadCommand::Spec(args) => {
                commands::workload::spec::run(args, &config).await
            }
        },
    }
}
