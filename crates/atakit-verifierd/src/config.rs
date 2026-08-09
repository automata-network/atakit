//! `VERIFIED_*` configuration, parsed as one mutually exclusive type.
//!
//! Two rules shape everything here.
//!
//! **The mode is a sum, not a set of optional fields.** Variables belonging to
//! a mode that was not selected are a configuration error, not values that are
//! ignored. An operator who shipped a trust pack believes it is in use, and a
//! daemon that silently ignored it would be verifying under an authority the
//! operator did not choose.
//!
//! **A role is bound to a key at configuration time.** `kind` selects which
//! configured key must have signed a pack, so a `workload-trust` publisher
//! cannot sign a `collateral-trust` pack and inherit trust-root authority. No
//! pack supplies the key that verifies its own signature.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use atakit_attestation_client::{
    read_trust_pack_file, TrustPack, TrustPackKind, TrustPackReadOptions,
};

/// Where the portal mounts unmeasured data, and therefore where packs are
/// found. Packs are unmeasured deliberately: they are signed and pinnable in
/// their own right, and measuring them would force a workload rebuild on every
/// collateral refresh.
pub const UNMEASURED_DATA_DIR: &str = "/atakit-portal/unmeasured-data";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

/// The complete daemon configuration.
#[derive(Debug)]
pub struct VerifierdConfig {
    pub listen: String,
    pub mode: TrustModeConfig,
    /// The only addresses this daemon will ever connect to.
    ///
    /// A caller names a key here; it never supplies a host or port. Because
    /// `[dependencies.<name>.environment]` is measured manifest environment,
    /// this complete set lands in PCR23 and is readable by a third party
    /// verifying the workload.
    pub peers: BTreeMap<String, String>,
}

/// One authority, with only the inputs that authority supplies.
#[derive(Debug)]
pub enum TrustModeConfig {
    Chain {
        rpc_url: String,
        session_registry: String,
        chain_id: Option<u64>,
    },
    TrustPack {
        collateral_packs: Vec<TrustPack>,
        workload_packs: Vec<TrustPack>,
        pccs_url: Option<String>,
    },
    Explicit {
        /// Left opaque here. Explicit mode's inputs are the same files
        /// `atakit cloud verify-session` takes, and are loaded by the same
        /// code rather than re-parsed differently for the daemon.
        measurements: Option<PathBuf>,
        pccs_url: Option<String>,
    },
}

impl TrustModeConfig {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Chain { .. } => "chain",
            Self::TrustPack { .. } => "trust-pack",
            Self::Explicit { .. } => "explicit",
        }
    }
}

/// Variables that belong to exactly one mode.
///
/// Listed rather than inferred, so adding a variable forces a decision about
/// which authority owns it instead of defaulting to "accepted everywhere".
const CHAIN_ONLY: &[&str] = &[
    "VERIFIED_RPC_URL",
    "VERIFIED_CHAIN_ID",
    "VERIFIED_SESSION_REGISTRY",
];
const TRUST_PACK_ONLY: &[&str] = &[
    "VERIFIED_COLLATERAL_PUBLISHER_PUBKEY",
    "VERIFIED_WORKLOAD_PUBLISHER_PUBKEY",
    "VERIFIED_COLLATERAL_TRUST_PACK_SHA256",
    "VERIFIED_WORKLOAD_TRUST_PACK_SHA256",
];
const EXPLICIT_ONLY: &[&str] = &["VERIFIED_MEASUREMENTS"];

/// Read configuration from an environment.
///
/// Takes the variables as a map rather than reading the process environment, so
/// the rules below are testable without a subprocess.
pub fn load(
    env: &BTreeMap<String, String>,
    unmeasured_dir: &Path,
    now_unix: u64,
) -> Result<VerifierdConfig, ConfigError> {
    let mode_name = env
        .get("VERIFIED_TRUST_MODE")
        .map(String::as_str)
        .ok_or_else(|| {
            invalid(
            "VERIFIED_TRUST_MODE is required and has no default; a daemon that guessed would pick \
             a trust authority on the operator's behalf",
        )
        })?;

    let packs = discover_packs(unmeasured_dir)?;
    let mode = match mode_name {
        "chain" => {
            reject_foreign(env, mode_name, TRUST_PACK_ONLY)?;
            reject_foreign(env, mode_name, EXPLICIT_ONLY)?;
            // A pack on disk under chain mode is a configuration error, not an
            // ignored file: the operator who shipped it believes it is in use.
            if let Some(path) = packs.first() {
                return Err(invalid(format!(
                    "VERIFIED_TRUST_MODE is chain, but {} is present; remove it, or select \
                     trust-pack mode",
                    path.display()
                )));
            }
            TrustModeConfig::Chain {
                rpc_url: required(env, "VERIFIED_RPC_URL")?,
                session_registry: required(env, "VERIFIED_SESSION_REGISTRY")?,
                chain_id: match env.get("VERIFIED_CHAIN_ID") {
                    Some(value) => Some(value.parse().map_err(|_| {
                        invalid(format!("VERIFIED_CHAIN_ID is not a number: {value:?}"))
                    })?),
                    None => None,
                },
            }
        }
        "trust-pack" => {
            reject_foreign(env, mode_name, CHAIN_ONLY)?;
            reject_foreign(env, mode_name, EXPLICIT_ONLY)?;
            load_trust_pack_mode(env, &packs, now_unix)?
        }
        "explicit" => {
            reject_foreign(env, mode_name, CHAIN_ONLY)?;
            reject_foreign(env, mode_name, TRUST_PACK_ONLY)?;
            if let Some(path) = packs.first() {
                return Err(invalid(format!(
                    "VERIFIED_TRUST_MODE is explicit, but {} is present; remove it, or select \
                     trust-pack mode",
                    path.display()
                )));
            }
            TrustModeConfig::Explicit {
                measurements: env.get("VERIFIED_MEASUREMENTS").map(PathBuf::from),
                pccs_url: env.get("VERIFIED_PCCS_URL").cloned(),
            }
        }
        other => {
            return Err(invalid(format!(
                "VERIFIED_TRUST_MODE is {other:?}; expected chain, trust-pack, or explicit"
            )))
        }
    };

    Ok(VerifierdConfig {
        listen: env
            .get("VERIFIED_LISTEN")
            .cloned()
            .unwrap_or_else(|| "0.0.0.0:9100".to_string()),
        mode,
        peers: peers(env)?,
    })
}

/// `VERIFIED_PEER_<NAME>` becomes the lowercase peer name a caller may ask for.
fn peers(env: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>, ConfigError> {
    let mut peers = BTreeMap::new();
    for (key, value) in env {
        let Some(name) = key.strip_prefix("VERIFIED_PEER_") else {
            continue;
        };
        if name.is_empty() {
            return Err(invalid("VERIFIED_PEER_ needs a peer name after the prefix"));
        }
        if !value.contains(':') {
            return Err(invalid(format!(
                "{key} must be '<host>:<port>', got {value:?}"
            )));
        }
        peers.insert(name.to_ascii_lowercase(), value.clone());
    }
    Ok(peers)
}

fn load_trust_pack_mode(
    env: &BTreeMap<String, String>,
    packs: &[PathBuf],
    now_unix: u64,
) -> Result<TrustModeConfig, ConfigError> {
    if packs.is_empty() {
        return Err(invalid(format!(
            "VERIFIED_TRUST_MODE is trust-pack, but no *.atatp was found in {UNMEASURED_DATA_DIR}"
        )));
    }
    let collateral_key = publisher_key(env, "VERIFIED_COLLATERAL_PUBLISHER_PUBKEY")?;
    let workload_key = publisher_key(env, "VERIFIED_WORKLOAD_PUBLISHER_PUBKEY")?;
    let collateral_pin = pin(env, "VERIFIED_COLLATERAL_TRUST_PACK_SHA256")?;
    let workload_pin = pin(env, "VERIFIED_WORKLOAD_TRUST_PACK_SHA256")?;

    // A pack's own `kind` selects which configured key must have signed it. A
    // pack cannot choose the key that verifies it, so each is tried against
    // exactly one role rather than against a list.
    let mut collateral_packs = Vec::new();
    let mut workload_packs = Vec::new();
    for path in packs {
        let kind = peek_kind(path)?;
        let (key, pinned) = match kind {
            TrustPackKind::CollateralTrust => (&collateral_key, collateral_pin),
            TrustPackKind::WorkloadTrust => (&workload_key, workload_pin),
        };
        let mut options = TrustPackReadOptions::new(kind, key.clone(), now_unix);
        if let Some(digest) = pinned {
            options = options.pinned(digest);
        }
        let pack = read_trust_pack_file(path, &options)
            .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
        match kind {
            TrustPackKind::CollateralTrust => collateral_packs.push(pack),
            TrustPackKind::WorkloadTrust => workload_packs.push(pack),
        }
    }

    Ok(TrustModeConfig::TrustPack {
        collateral_packs,
        workload_packs,
        pccs_url: env.get("VERIFIED_PCCS_URL").cloned(),
    })
}

/// Read a pack's declared `kind` without trusting it.
///
/// This only decides which configured key the pack is then verified against.
/// A pack that lies about its kind is checked against the wrong role's key and
/// fails the signature check, so the claim cannot buy anything.
fn peek_kind(path: &Path) -> Result<TrustPackKind, ConfigError> {
    let bytes = std::fs::read(path)
        .map_err(|error| invalid(format!("read {}: {error}", path.display())))?;
    let tar = zstd::stream::decode_all(bytes.as_slice())
        .map_err(|error| invalid(format!("{} is not a zstd stream: {error}", path.display())))?;
    let mut archive = tar::Archive::new(tar.as_slice());
    let entries = archive
        .entries()
        .map_err(|error| invalid(format!("{} is not a tar archive: {error}", path.display())))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| invalid(format!("{}: {error}", path.display())))?;
        if entry.path_bytes().as_ref() != b"trust-pack.json" {
            continue;
        }
        let mut text = String::new();
        std::io::Read::read_to_string(&mut entry, &mut text)
            .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
        let kind = value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid(format!("{}: trust-pack.json has no kind", path.display())))?;
        return TrustPackKind::parse(kind)
            .map_err(|error| invalid(format!("{}: {error}", path.display())));
    }
    Err(invalid(format!(
        "{} has no trust-pack.json",
        path.display()
    )))
}

fn discover_packs(dir: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(invalid(format!("read {}: {error}", dir.display()))),
    };
    let mut packs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| invalid(format!("read {}: {error}", dir.display())))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("atatp") {
            packs.push(path);
        }
    }
    packs.sort();
    Ok(packs)
}

fn required(env: &BTreeMap<String, String>, key: &str) -> Result<String, ConfigError> {
    env.get(key)
        .cloned()
        .ok_or_else(|| invalid(format!("{key} is required in this mode")))
}

fn publisher_key(env: &BTreeMap<String, String>, key: &str) -> Result<Vec<u8>, ConfigError> {
    let value = required(env, key)?;
    let raw = value.strip_prefix("0x").unwrap_or(&value);
    let bytes =
        hex::decode(raw).map_err(|error| invalid(format!("{key} is not hexadecimal: {error}")))?;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(invalid(format!(
            "{key} must be a 65-byte uncompressed SEC1 secp256k1 point beginning 0x04, got {} \
             bytes",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn pin(env: &BTreeMap<String, String>, key: &str) -> Result<Option<[u8; 32]>, ConfigError> {
    let Some(value) = env.get(key) else {
        return Ok(None);
    };
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(raw).map_err(|error| invalid(format!("{key} is not hexadecimal: {error}")))?;
    let digest: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid(format!("{key} must be 32 bytes")))?;
    Ok(Some(digest))
}

fn reject_foreign(
    env: &BTreeMap<String, String>,
    mode: &str,
    foreign: &[&str],
) -> Result<(), ConfigError> {
    let present: Vec<&str> = foreign
        .iter()
        .copied()
        .filter(|key| env.contains_key(*key))
        .collect();
    if present.is_empty() {
        return Ok(());
    }
    Err(invalid(format!(
        "VERIFIED_TRUST_MODE is {mode}, so {} belongs to a mode that was not selected; a variable \
         for an unselected authority is a configuration error, not a value to ignore",
        present.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn empty_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    /// No default, because a default would choose a trust authority for the
    /// operator.
    #[test]
    fn a_missing_mode_refuses_to_start() {
        let dir = empty_dir();
        let error = load(&env(&[]), dir.path(), 1_786_000_000)
            .expect_err("a daemon without a mode must refuse to start");
        assert!(error.to_string().contains("VERIFIED_TRUST_MODE"), "{error}");
    }

    #[test]
    fn an_unknown_mode_is_refused() {
        let dir = empty_dir();
        let error = load(
            &env(&[("VERIFIED_TRUST_MODE", "whatever")]),
            dir.path(),
            1_786_000_000,
        )
        .expect_err("an unknown mode must be refused");
        assert!(error.to_string().contains("expected chain"), "{error}");
    }

    /// A variable belonging to another mode is an error, not an ignored value.
    /// Each direction is checked, because ignoring one silently would leave an
    /// operator believing an input was in use.
    #[test]
    fn variables_from_an_unselected_mode_are_refused() {
        let dir = empty_dir();
        /// Selected mode, the foreign variable to add, and what the failure
        /// must name.
        struct Case {
            mode: &'static str,
            extra: &'static [(&'static str, &'static str)],
            expected: &'static str,
        }
        let cases = &[
            Case {
                mode: "chain",
                extra: &[
                    ("VERIFIED_RPC_URL", "https://rpc.example"),
                    ("VERIFIED_SESSION_REGISTRY", "0x11"),
                    ("VERIFIED_COLLATERAL_PUBLISHER_PUBKEY", "0x04ab"),
                ],
                expected: "VERIFIED_COLLATERAL_PUBLISHER_PUBKEY",
            },
            Case {
                mode: "chain",
                extra: &[
                    ("VERIFIED_RPC_URL", "https://rpc.example"),
                    ("VERIFIED_SESSION_REGISTRY", "0x11"),
                    ("VERIFIED_MEASUREMENTS", "/tmp/m.json"),
                ],
                expected: "VERIFIED_MEASUREMENTS",
            },
            Case {
                mode: "explicit",
                extra: &[("VERIFIED_RPC_URL", "https://rpc.example")],
                expected: "VERIFIED_RPC_URL",
            },
            Case {
                mode: "trust-pack",
                extra: &[("VERIFIED_SESSION_REGISTRY", "0x11")],
                expected: "VERIFIED_SESSION_REGISTRY",
            },
        ];
        for Case {
            mode,
            extra,
            expected,
        } in cases
        {
            let mut pairs = vec![("VERIFIED_TRUST_MODE", *mode)];
            pairs.extend_from_slice(extra);
            let Err(error) = load(&env(&pairs), dir.path(), 1_786_000_000) else {
                panic!("{mode} must refuse {expected}");
            };
            let message = error.to_string();
            assert!(
                message.contains(expected),
                "{mode}: the failure must name {expected}; got {message}"
            );
            assert!(
                message.contains("not a value to ignore"),
                "{mode}: the failure must say why; got {message}"
            );
        }
    }

    /// A pack on disk under an authority that does not read packs is an error.
    /// The operator who shipped it believes it is in use.
    #[test]
    fn a_pack_under_a_non_pack_mode_is_refused() {
        let dir = empty_dir();
        std::fs::write(dir.path().join("collateral.atatp"), b"not really a pack").unwrap();
        for mode in ["chain", "explicit"] {
            let mut pairs = vec![("VERIFIED_TRUST_MODE", mode)];
            if mode == "chain" {
                pairs.push(("VERIFIED_RPC_URL", "https://rpc.example"));
                pairs.push(("VERIFIED_SESSION_REGISTRY", "0x11"));
            }
            let error = load(&env(&pairs), dir.path(), 1_786_000_000)
                .expect_err("a pack present under a non-pack mode must be refused");
            assert!(error.to_string().contains("collateral.atatp"), "{error}");
        }
    }

    #[test]
    fn trust_pack_mode_needs_a_pack() {
        let dir = empty_dir();
        let error = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "trust-pack"),
                ("VERIFIED_COLLATERAL_PUBLISHER_PUBKEY", "0x04ab"),
                ("VERIFIED_WORKLOAD_PUBLISHER_PUBKEY", "0x04cd"),
            ]),
            dir.path(),
            1_786_000_000,
        )
        .expect_err("trust-pack mode with no pack must be refused");
        assert!(error.to_string().contains("no *.atatp"), "{error}");
    }

    /// The peer allowlist is the complete set of addresses this daemon will
    /// ever connect to. A caller names a key here and never supplies a host.
    #[test]
    fn peers_are_named_and_must_carry_a_port() {
        let dir = empty_dir();
        let config = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "explicit"),
                ("VERIFIED_PEER_BETA", "203.0.113.10:2024"),
            ]),
            dir.path(),
            1_786_000_000,
        )
        .expect("explicit mode needs nothing else");
        assert_eq!(
            config.peers.get("beta").map(String::as_str),
            Some("203.0.113.10:2024")
        );
        assert_eq!(config.mode.name(), "explicit");

        let error = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "explicit"),
                ("VERIFIED_PEER_BETA", "203.0.113.10"),
            ]),
            dir.path(),
            1_786_000_000,
        )
        .expect_err("a peer without a port must be refused");
        assert!(error.to_string().contains("<host>:<port>"), "{error}");
    }

    #[test]
    fn a_publisher_key_must_be_an_uncompressed_sec1_point() {
        let dir = empty_dir();
        std::fs::write(dir.path().join("c.atatp"), b"x").unwrap();
        let error = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "trust-pack"),
                ("VERIFIED_COLLATERAL_PUBLISHER_PUBKEY", "0x04ab"),
                ("VERIFIED_WORKLOAD_PUBLISHER_PUBKEY", "0x04cd"),
            ]),
            dir.path(),
            1_786_000_000,
        )
        .expect_err("a short key must be refused");
        assert!(error.to_string().contains("65-byte"), "{error}");
    }
}
