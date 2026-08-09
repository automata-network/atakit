//! Produce and inspect `.atatp` trust packs.
//!
//! The format had no command-line surface, so a pack could only be built by a
//! Rust caller and never tried by hand. That also left the three provisional
//! archive limits unmeasured, because measuring them needs a real pack.
//!
//! Entries are named by their payload path rather than inferred from file
//! extensions. The path decides which namespace rule and which parser applies,
//! so guessing it from a filename would put the producer's guess where the
//! specification puts an explicit choice.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use atakit_attestation_client::{
    read_trust_pack_file, ArchiveLimits, TrustPackBuilder, TrustPackKind, TrustPackReadOptions,
};
use clap::{Args, Subcommand};
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature, SigningKey};
use owo_colors::OwoColorize;

use crate::config::Config;

#[derive(Subcommand)]
pub enum TrustPackCommand {
    /// Build a signed `.atatp` trust pack
    Build(BuildArgs),
    /// Verify a `.atatp` trust pack and print what it contains
    Inspect(InspectArgs),
}

#[derive(Args)]
pub struct BuildArgs {
    /// Payload namespace: collateral-trust or workload-trust
    #[arg(long)]
    pub kind: String,
    /// Human label identifying the publisher. Never used in a trust decision.
    #[arg(long)]
    pub issuer: String,
    /// Monotonic per issuer and kind. Informational only; no reader enforces it.
    #[arg(long, default_value_t = 1)]
    pub revision: u64,
    /// Validity start, Unix seconds.
    #[arg(long)]
    pub not_before: u64,
    /// Intended validity end, Unix seconds. Lowered to the earliest expiry
    /// among the contents, so the emitted value may be earlier than this.
    #[arg(long)]
    pub not_after: u64,
    /// A payload entry, as `<payload path>=<file>`. Repeatable.
    ///
    /// For example
    /// `--entry payload/roots/gcp-ak-root.pem=/tmp/gcp-ak-root.pem`.
    #[arg(long = "entry", value_name = "PATH=FILE")]
    pub entries: Vec<String>,
    /// Name of an es256k key in `[keys]` to sign with.
    #[arg(long)]
    pub signing_key: Option<String>,
    /// Where to write the archive.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct InspectArgs {
    /// The `.atatp` archive to read.
    pub archive: PathBuf,
    /// Payload namespace the archive must occupy. A pack cannot select which
    /// configured key verifies it, so the caller states the kind.
    #[arg(long)]
    pub kind: String,
    /// Uncompressed SEC1 secp256k1 public key of the publisher for that kind,
    /// as hex. This is the verifier's configuration; it never comes from the
    /// pack.
    #[arg(long)]
    pub publisher_key: String,
    /// Verification time, Unix seconds. Defaults to now.
    #[arg(long)]
    pub at: Option<u64>,
    /// Require this exact `trust-pack.json` digest. Pinning is the only
    /// rollback control the format has.
    #[arg(long)]
    pub pin: Option<String>,
}

pub fn build(args: BuildArgs, config: &Config) -> Result<()> {
    let kind = parse_kind(&args.kind)?;
    let mut builder = TrustPackBuilder::new(
        kind,
        args.issuer.clone(),
        args.revision,
        args.not_before,
        args.not_after,
    );

    if args.entries.is_empty() {
        bail!("a trust pack needs at least one --entry");
    }
    for entry in &args.entries {
        let (path, file) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("--entry must be '<payload path>=<file>', got {entry:?}")
        })?;
        let bytes = std::fs::read(file).with_context(|| format!("read {file}"))?;
        builder
            .insert(path, bytes)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }

    let key = super::workload::resolve_owner_key(args.signing_key.as_deref(), config)?;
    let raw = key.strip_prefix("0x").unwrap_or(&key);
    let bytes = hex::decode(raw).context("signing key is not valid hex")?;
    let signing_key =
        SigningKey::from_slice(&bytes).context("signing key must be a 32-byte es256k key")?;

    let archive = builder
        .build(|message| {
            let signature: Signature = signing_key.sign(message);
            Ok::<_, std::convert::Infallible>(signature.to_bytes().to_vec())
        })
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    if let Some(parent) = args.out.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(&args.out, &archive).with_context(|| format!("write {}", args.out.display()))?;

    // The derived window and the digest are what an operator needs next: the
    // first because it may be earlier than requested, the second because it is
    // what `--pin` takes.
    let index = builder
        .index_bytes()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let digest = sha2::Sha256::digest(&index);
    println!("{} {}", "Wrote".green(), args.out.display());
    println!("{:<14}{}", "Kind:", kind.as_str());
    println!("{:<14}{} bytes", "Archive:", archive.len());
    println!("{:<14}0x{}", "Digest:", hex::encode(digest));
    Ok(())
}

pub fn inspect(args: InspectArgs) -> Result<()> {
    let kind = parse_kind(&args.kind)?;
    let raw = args
        .publisher_key
        .strip_prefix("0x")
        .unwrap_or(&args.publisher_key);
    let publisher_key = hex::decode(raw).context("--publisher-key is not valid hex")?;
    let now = match args.at {
        Some(at) => at,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0),
    };

    let mut options = TrustPackReadOptions::new(kind, publisher_key, now);
    if let Some(pin) = args.pin.as_deref() {
        let raw = pin.strip_prefix("0x").unwrap_or(pin);
        let decoded = hex::decode(raw).context("--pin is not valid hex")?;
        let digest: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("--pin must be 32 bytes"))?;
        options = options.pinned(digest);
    }

    let pack = read_trust_pack_file(&args.archive, &options)
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    println!("{}", "Verified".green());
    println!("{:<14}{}", "Kind:", pack.kind.as_str());
    println!("{:<14}{}", "Issuer:", pack.index.issuer);
    println!("{:<14}{}", "Revision:", pack.index.revision);
    println!(
        "{:<14}{} to {}",
        "Valid:", pack.index.not_before, pack.index.not_after
    );
    println!("{:<14}{}", "Digest:", pack.digest_hex());
    println!("{:<14}", "Payload:");
    for (path, bytes) in &pack.payload {
        println!("  {:<48}{} bytes", path, bytes.len());
    }

    // The three provisional limits are measured against real packs, so report
    // what this one uses rather than leaving an operator to compute it.
    let limits = ArchiveLimits::default();
    let total: u64 = pack.payload.values().map(|bytes| bytes.len() as u64).sum();
    let largest = pack
        .payload
        .values()
        .map(|bytes| bytes.len() as u64)
        .max()
        .unwrap_or(0);
    println!(
        "{:<14}{} of {} entries, {} of {} bytes, largest entry {} of {}",
        "Against limits:",
        pack.payload.len(),
        limits.max_entries,
        total,
        limits.max_total_bytes,
        largest,
        limits.max_entry_bytes
    );
    Ok(())
}

fn parse_kind(value: &str) -> Result<TrustPackKind> {
    TrustPackKind::parse(value).map_err(|error| anyhow::anyhow!("{error}"))
}

use sha2::Digest as _;
