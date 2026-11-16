//! `atakit keys` — inspect the keys declared in `[keys]`.
//!
//! Listing and inspection are separate commands on purpose. A `command` key
//! source runs an external helper, which may prompt, touch a hardware token, or
//! reach a remote vault; listing what is declared must never do that. `ls`
//! therefore reads only configuration, and `show` resolves exactly one named key
//! because the operator asked for it.
//!
//! Private key material is never rendered. Everything these commands print —
//! fingerprint, public key, type, mode, source — is public by construction.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use owo_colors::OwoColorize;

use crate::config::{Config, KeyMode, KeySpec, KeyType};

#[derive(Subcommand)]
pub enum KeysCommand {
    /// Create a dedicated initialization key; print only its public bootstrap JSON
    CreateInit,
    /// List the keys declared in `[keys]`
    Ls(LsArgs),
    /// Show one key's type, fingerprint, and public key
    Show(ShowArgs),
}

pub fn create_init(env: &atakit_core::Env) -> Result<()> {
    let (path, bootstrap) =
        atakit_cloud::init_auth::create(&env.data_dir).map_err(anyhow::Error::msg)?;
    eprintln!("Private initialization credential: {}", path.display());
    println!("{}", serde_json::to_string(&bootstrap)?);
    Ok(())
}

#[derive(Args)]
pub struct LsArgs {}

#[derive(Args)]
pub struct ShowArgs {
    /// Name of a key declared in `[keys]`
    pub name: String,
}

/// Where a key's material comes from, described without reading it.
#[derive(Debug, PartialEq, Eq)]
pub enum KeySource {
    File(String),
    Command(Vec<String>),
    Env(String),
    /// `mode = "self_generated"`: the portal generates this key at init time, so
    /// no material exists on this machine.
    PortalGenerated,
}

impl KeySource {
    fn of(spec: &KeySpec) -> Self {
        if let Some(path) = &spec.file {
            return Self::File(path.clone());
        }
        if let Some(argv) = &spec.command {
            return Self::Command(argv.clone());
        }
        if let Some(var) = &spec.env {
            return Self::Env(var.clone());
        }
        Self::PortalGenerated
    }

    fn render(&self) -> String {
        match self {
            Self::File(path) => format!("file {path}"),
            Self::Command(argv) => format!("command {}", argv.join(" ")),
            Self::Env(var) => format!("env {var}"),
            Self::PortalGenerated => "portal-generated".to_string(),
        }
    }
}

/// The public identity of a resolved key.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyIdentity {
    /// `LibKey.computeKeyFingerprint` over the public key: the publisher
    /// component of every identifier this key can register.
    pub fingerprint: String,
    /// Uncompressed SEC1 public key, `0x04 || x || y`.
    pub public_key: String,
}

/// Whether a declared key has a public identity derivable on this machine.
///
/// `Unavailable` carries the reason rather than being silently absent: a wrong
/// or missing fingerprint would name the wrong publisher, which is the one
/// mistake this command exists to prevent.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyIdentityStatus {
    Derived(KeyIdentity),
    Unavailable(String),
}

/// Derive the public identity of a declared key.
///
/// A `self_generated` key has no local material, and only `es256k` has a
/// derivation path here; both come back as `Unavailable` with the reason. An
/// error means the key was declared as resolvable and resolution failed, which
/// is a real fault worth surfacing.
pub fn identity_of(name: &str, spec: &KeySpec) -> Result<KeyIdentityStatus> {
    if spec.mode == KeyMode::SelfGenerated {
        return Ok(KeyIdentityStatus::Unavailable(
            "no local material; the portal generates this key at init".to_string(),
        ));
    }
    if spec.key_type != KeyType::Es256k {
        return Ok(KeyIdentityStatus::Unavailable(format!(
            "fingerprint derivation is implemented for es256k only, not {}",
            spec.key_type
        )));
    }

    let private_key = spec
        .resolve(name)
        .with_context(|| format!("resolve key '{name}'"))?;
    let identity = public_identity(&private_key)
        .with_context(|| format!("derive the public identity of key '{name}'"))?;
    Ok(KeyIdentityStatus::Derived(identity))
}

/// Derive fingerprint and public key from ES256K private key material.
///
/// The private key is borrowed and never returned or rendered; only the public
/// half leaves this function.
fn public_identity(private_key_hex: &str) -> Result<KeyIdentity> {
    use alloy_ext::signers::local::PrivateKeySigner;
    use automata_tee_workload_measurement::stubs::PublicIdentity;

    let raw = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);
    let signer: PrivateKeySigner = raw.parse().context("key is not a valid es256k key")?;
    let identity = PublicIdentity::secp256k1(&signer);

    Ok(KeyIdentity {
        fingerprint: identity.fingerprint().to_string(),
        public_key: format!("0x{}", hex::encode(&identity.key)),
    })
}

pub fn ls(_args: LsArgs, config: &Config) -> Result<()> {
    if config.keys.is_empty() {
        println!("No keys declared. Add a [keys.<name>] entry to config.toml.");
        return Ok(());
    }

    let name_width = config
        .keys
        .keys()
        .map(String::len)
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "{:<name_width$}  {:<9}  {:<14}  {}",
        "NAME".bold(),
        "TYPE".bold(),
        "MODE".bold(),
        "SOURCE".bold(),
    );
    for (name, spec) in &config.keys {
        println!(
            "{:<name_width$}  {:<9}  {:<14}  {}",
            name.green(),
            spec.key_type.to_string(),
            spec.mode.to_string(),
            KeySource::of(spec).render().dimmed(),
        );
    }
    Ok(())
}

pub fn show(args: ShowArgs, config: &Config) -> Result<()> {
    let spec = config.keys.get(&args.name).ok_or_else(|| {
        let known: Vec<&str> = config.keys.keys().map(String::as_str).collect();
        let known = if known.is_empty() {
            "[keys] is empty".to_string()
        } else {
            format!("known keys: {}", known.join(", "))
        };
        anyhow::anyhow!("key '{}' not found in [keys]; {known}", args.name)
    })?;

    println!("{:<13}{}", "Name:", args.name.green().bold());
    println!("{:<13}{}", "Type:", spec.key_type);
    println!("{:<13}{}", "Mode:", spec.mode);
    println!("{:<13}{}", "Source:", KeySource::of(spec).render());

    match identity_of(&args.name, spec)? {
        KeyIdentityStatus::Derived(identity) => {
            println!("{:<13}{}", "Fingerprint:", identity.fingerprint.yellow());
            println!("{:<13}{}", "Public key:", identity.public_key.dimmed());
        }
        KeyIdentityStatus::Unavailable(reason) => {
            println!(
                "{:<13}{}",
                "Fingerprint:",
                format!("unavailable — {reason}").dimmed()
            );
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
//                              tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Anvil development account 0. A published test key, never a secret.
    const TEST_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn spec(key_type: KeyType, mode: KeyMode) -> KeySpec {
        KeySpec {
            key_type,
            mode,
            file: None,
            command: None,
            env: None,
            timeout_secs: None,
        }
    }

    #[test]
    fn source_reports_each_declared_form() {
        let mut file_spec = spec(KeyType::Es256k, KeyMode::Provisioned);
        file_spec.file = Some("~/.config/atakit/owner_key".to_string());
        assert_eq!(
            KeySource::of(&file_spec).render(),
            "file ~/.config/atakit/owner_key"
        );

        let mut command_spec = spec(KeyType::Es256k, KeyMode::Provisioned);
        command_spec.command = Some(vec!["pass".to_string(), "show".to_string()]);
        assert_eq!(KeySource::of(&command_spec).render(), "command pass show");

        let mut env_spec = spec(KeyType::Es256k, KeyMode::Provisioned);
        env_spec.env = Some("GH_CI_TOKEN".to_string());
        assert_eq!(KeySource::of(&env_spec).render(), "env GH_CI_TOKEN");

        assert_eq!(
            KeySource::of(&spec(KeyType::Es256k, KeyMode::SelfGenerated)).render(),
            "portal-generated"
        );
    }

    /// Known-answer vector: the fingerprint is what `LibKey.computeKeyFingerprint`
    /// produces on chain, so it must not drift with a refactor here.
    #[test]
    fn public_identity_matches_the_on_chain_fingerprint() {
        let identity = public_identity(TEST_KEY).unwrap();

        assert_eq!(identity.public_key.len(), 2 + 130, "uncompressed SEC1");
        assert!(identity.public_key.starts_with("0x04"));
        assert!(atakit_core::is_canonical_id(&identity.fingerprint));

        // Recomputed independently through the same shared type the registries use.
        use alloy_ext::signers::local::PrivateKeySigner;
        use automata_tee_workload_measurement::stubs::PublicIdentity;
        let signer: PrivateKeySigner = TEST_KEY.strip_prefix("0x").unwrap().parse().unwrap();
        let expected = PublicIdentity::secp256k1(&signer).fingerprint().to_string();
        assert_eq!(identity.fingerprint, expected);
    }

    /// The whole point of this command is to expose public material. If a
    /// refactor ever leaks the private half into the rendered identity, this
    /// fails.
    #[test]
    fn rendered_identity_never_contains_private_material() {
        let identity = public_identity(TEST_KEY).unwrap();
        let bare = TEST_KEY.strip_prefix("0x").unwrap();

        assert!(!identity.fingerprint.contains(bare));
        assert!(!identity.public_key.contains(bare));
    }

    fn unavailable_reason(status: KeyIdentityStatus) -> String {
        match status {
            KeyIdentityStatus::Unavailable(reason) => reason,
            KeyIdentityStatus::Derived(identity) => {
                panic!("expected no derivable identity, got {identity:?}")
            }
        }
    }

    #[test]
    fn self_generated_key_reports_no_local_material() {
        let status = identity_of("gas", &spec(KeyType::Es256k, KeyMode::SelfGenerated)).unwrap();
        let reason = unavailable_reason(status);
        assert!(reason.contains("no local material"), "{reason}");
    }

    /// A non-es256k key is reported as underivable rather than silently given
    /// some other key's fingerprint.
    #[test]
    fn non_es256k_key_reports_the_unsupported_type() {
        let mut es256 = spec(KeyType::Es256, KeyMode::Provisioned);
        es256.file = Some("/nonexistent".to_string());

        let reason = unavailable_reason(identity_of("web", &es256).unwrap());
        assert!(reason.contains("es256k only"), "{reason}");
        assert!(reason.contains("es256"), "{reason}");
    }
}
