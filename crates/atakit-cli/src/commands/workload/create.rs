use anyhow::Result;
use atakit_workload::cli::CreateArgs;
use owo_colors::OwoColorize;

pub fn run(args: CreateArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let dir = atakit_workload::create_workload(&cwd, &args.name)?;

    println!(
        "Created workload {} at {}",
        args.name.green(),
        dir.display()
    );
    Ok(())
}
