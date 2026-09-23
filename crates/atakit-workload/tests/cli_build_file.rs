#![cfg(feature = "cli")]

use atakit_workload::cli::BuildArgs;
use clap::Parser;

#[derive(Parser)]
struct Command {
    #[command(flatten)]
    build: BuildArgs,
}

#[test]
fn selects_a_config_without_changing_the_workload_root() {
    let result = Command::try_parse_from([
        "build",
        "-d",
        ".",
        "--file",
        "workloads/validator/atakit-workload.toml",
    ]);
    let command = result.unwrap_or_else(|error| panic!("--file should select a config: {error}"));
    assert_eq!(command.build.dir.unwrap(), std::path::PathBuf::from("."));
    assert_eq!(
        command.build.file.unwrap(),
        std::path::PathBuf::from("workloads/validator/atakit-workload.toml")
    );
}
