use anyhow::Result;
use atakit_workload::cli::NewArgs;
use owo_colors::OwoColorize;

pub fn run_new(args: NewArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let dir = atakit_workload::create_workload(&cwd, &args.name)?;

    println!(
        "Created workload {} at {}",
        args.name.green(),
        dir.display()
    );
    Ok(())
}
