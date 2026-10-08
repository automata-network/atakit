use std::{path::PathBuf, str::FromStr};

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "atakit-emulator")]
pub struct EmulatorCli {
    #[command(subcommand)]
    pub command: EmulatorCommand,
}

#[derive(Debug, Subcommand)]
pub enum EmulatorCommand {
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        runtime_dir: PathBuf,
    },
    Up(UpArgs),
    Status(RuntimeArgs),
    Env(WorkloadArgs),
    Exec(ExecArgs),
    Logs(WorkloadArgs),
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Refresh(RuntimeArgs),
    /// Stop and save chain/session state for a later restart.
    Stop(RuntimeArgs),
    /// Stop and remove runtime state, preserving application data by default.
    Down(DownArgs),
    /// Run the selected engine's Compose provider; regenerate the Compose file before up.
    #[command(disable_help_flag = true)]
    WorkloadCompose(WorkloadComposeArgs),
}

#[derive(Debug, Clone, Args)]
pub struct UpArgs {
    /// Use a configured cloud target to select platform and machine measurements.
    #[arg(long)]
    pub target: Option<String>,
    /// Emulator config (defaults to ./atakit-emulator.toml when present).
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub runtime_dir: Option<PathBuf>,
    #[arg(long)]
    pub chain: Option<String>,
    #[arg(long)]
    pub fork_url: Option<String>,
    #[arg(long)]
    pub fork_block: Option<u64>,
    #[arg(long)]
    pub anvil_port: Option<u16>,
    /// Anvil hardfork (default: osaka); overrides the emulator configuration.
    #[arg(long)]
    pub hardfork: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub foreground: Option<bool>,
    #[arg(long = "workload")]
    pub workloads: Vec<WorkloadInput>,
    #[arg(long = "output-socket")]
    pub output_sockets: Vec<NamedValue>,
    #[arg(long = "owner-key")]
    pub owner_keys: Vec<NamedValue>,
    /// Select a registered profile by name; use NAME=PROFILE for multiple workloads.
    #[arg(long = "platform-profile")]
    pub platform_profiles: Vec<NamedValue>,
    /// Select a registered measurement variant by name; use NAME=VARIANT for multiple workloads.
    #[arg(long = "measurement-variant")]
    pub measurement_variants: Vec<NamedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadInput {
    pub name: Option<String>,
    pub path: PathBuf,
}

impl FromStr for WorkloadInput {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, path) = split_named(value);
        if path.is_empty() {
            return Err("workload path cannot be empty".into());
        }
        Ok(Self {
            name,
            path: path.into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedValue {
    pub name: Option<String>,
    pub value: String,
}

impl FromStr for NamedValue {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, value) = split_named(value);
        if value.is_empty() {
            return Err("value cannot be empty".into());
        }
        Ok(Self {
            name,
            value: value.into(),
        })
    }
}

fn split_named(value: &str) -> (Option<String>, &str) {
    match value.split_once('=') {
        Some((name, rest)) if !name.is_empty() => (Some(name.to_owned()), rest),
        _ => (None, value),
    }
}

#[derive(Debug, Clone, Args)]
pub struct RuntimeArgs {
    #[arg(long)]
    pub runtime_dir: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct WorkloadArgs {
    #[arg(long)]
    pub runtime_dir: Option<PathBuf>,
    #[arg(long)]
    pub workload: Option<String>,
    #[arg(long)]
    pub format: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct ExecArgs {
    #[command(flatten)]
    pub target: WorkloadArgs,
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SessionCommand {
    Rotate(WorkloadArgs),
    Revoke(WorkloadArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PortalTransport {
    Bridge,
    Native,
}

#[derive(Debug, Clone, Args)]
pub struct ComposeArgs {
    /// Target container platform, e.g. linux/amd64 (defaults to the engine's platform).
    #[arg(long)]
    pub platform: Option<String>,
    /// Connect through a bridge or directly bind-mount the host Unix socket.
    #[arg(long, value_enum, default_value = "native")]
    pub portal_transport: PortalTransport,
    #[arg(long)]
    pub runtime_dir: Option<PathBuf>,
    #[arg(long = "workload")]
    pub workloads: Vec<String>,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct WorkloadComposeArgs {
    #[command(flatten)]
    pub compose: ComposeArgs,
    /// Show Atakit options and the selected engine's Compose help.
    #[arg(short = 'h', long)]
    pub help: bool,
    /// Compose subcommand and arguments, e.g. up --build or logs -f.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<std::ffi::OsString>,
}

#[derive(Debug, Clone, Args)]
pub struct DownArgs {
    #[arg(long)]
    pub runtime_dir: Option<PathBuf>,
    /// Also permanently remove the runtime's local application data directory.
    #[arg(long)]
    pub purge_data: bool,
    #[arg(long)]
    pub json: bool,
}
