use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::types::ImageRef;

/// Image subcommand.
#[derive(Subcommand)]
pub enum ImageCommand {
    /// List available CVM base image releases
    #[command(name = "ls")]
    Ls(LsArgs),
    /// Pull a CVM base image from a release
    #[command(name = "pull")]
    Pull(PullArgs),
    /// Remove locally downloaded CVM base images
    #[command(name = "rm")]
    Rm(RmArgs),
    /// Export an image from the store as a portable .atabi archive
    #[command(name = "export")]
    Export(ExportArgs),
    /// Import a .atabi archive into the image store
    #[command(name = "import")]
    Import(ImportArgs),
}

/// Arguments for `image ls`.
#[derive(Args)]
pub struct LsArgs {
    /// Maximum number of releases to show
    #[arg(long)]
    pub limit: Option<u32>,

    /// Show all releases (not just those with disk images)
    #[arg(long)]
    pub all: bool,

    /// Show a specific release by tag
    #[arg(long)]
    pub tag: Option<ImageRef>,

    /// GitHub repository (owner/repo)
    #[arg(long)]
    pub repo: Option<String>,

    /// Query remote releases (GitHub API)
    #[arg(long)]
    pub remote: bool,
}

/// Arguments for `image pull`.
#[derive(Args)]
pub struct PullArgs {
    /// Release tag to pull (e.g. "automata-linux:v0.5.0").
    /// If omitted, the latest release containing disk images is used.
    pub image: Option<ImageRef>,

    /// Comma-separated list of platforms: gcp,aws,azure.
    /// If omitted, all platforms are pulled.
    pub csps: Option<String>,
}

/// Arguments for `image rm`.
#[derive(Args)]
pub struct RmArgs {
    /// Release tag to remove (e.g. "automata-linux:v0.5.0")
    pub tag: ImageRef,
}

/// Arguments for `image export`.
#[derive(Args)]
pub struct ExportArgs {
    /// Image reference to export (e.g. "automata-linux:v0.1.6")
    pub image: ImageRef,

    /// Output directory (default: current directory)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Use gzip compression instead of zstd
    #[arg(long)]
    pub gz: bool,
}

/// Arguments for `image import`.
#[derive(Args)]
pub struct ImportArgs {
    /// Path to .atabi archive file
    pub archive: PathBuf,

    /// Overwrite existing files in the store
    #[arg(long)]
    pub force: bool,
}
