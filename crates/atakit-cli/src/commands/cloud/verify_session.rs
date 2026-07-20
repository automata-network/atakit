use std::path::PathBuf;

use anyhow::{Context, Result};
use atakit_cloud::cli::VerifySessionArgs;
use atakit_core::Env;
use owo_colors::OwoColorize;

use super::session_access::resolve_verified_session_access;
use crate::config::Config;

pub async fn run(args: VerifySessionArgs, env: &Env, config: &Config) -> Result<()> {
    eprint!("Verify portal TLS... ");
    let access = resolve_verified_session_access(
        &args.instance,
        args.target.as_deref(),
        &args.verification,
        env,
        config,
    )
    .await?;
    eprintln!("{}", "done".green());

    eprint!("Verify current session... ");
    let verified = access.verify_current_session().await?;
    eprintln!("{}", "done".green());

    let report_path =
        session_report_path(&env.data_dir, &access.target_name, &access.instance_name);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create report directory {}", parent.display()))?;
    }
    std::fs::write(&report_path, serde_json::to_vec_pretty(&verified)?)
        .with_context(|| format!("write session report {}", report_path.display()))?;

    println!();
    println!("{}", "==> Session verified off-chain".green().bold());
    println!("    Session:  0x{}", hex::encode(verified.session_id));
    println!("    Binding:  {:?}", verified.binding_mode);
    println!("    Checks:   {}", verified.checks.len());
    println!("    Report:   {}", report_path.display());
    Ok(())
}

pub(crate) fn session_report_path(
    data_dir: &std::path::Path,
    target_name: &str,
    instance_name: &str,
) -> PathBuf {
    data_dir
        .join("cloud")
        .join("deployments")
        .join(target_name)
        .join(format!("{instance_name}.session-verification-report.json"))
}
