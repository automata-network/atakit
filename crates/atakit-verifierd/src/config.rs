//! Strict `VERIFIED_*` configuration for `atakit-verifierd`.
//!
//! A configuration selects exactly one trust authority. Unknown names in the
//! `VERIFIED_*` namespace are rejected, because ignoring a misspelled optional
//! pin or expected chain ID would silently weaken verification.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use atakit_attestation::MeasurementPolicy;
use atakit_attestation_client::{
    load_measurement_policy, load_tls_verification_trust, read_trust_pack_file,
    tdx_dcap_collateral_config, AttestationClientConfig, ExplicitTrustSource,
    IntelTdxDcapCollateralConfig, IntelTdxDcapCollateralSource, PackTrustSource,
    TlsVerificationTrustFiles, TrustPack, TrustPackError, TrustPackKind, TrustPackReadOptions,
};
use atakit_cvm_types::AppRef;
use ipnet::IpNet;
use serde::Serialize;

use crate::destination::PortalDestinationPolicy;

/// Where the portal mounts unmeasured data, and therefore where packs are
/// found. Pack bytes are signed and optionally pinned; their publisher keys
/// and pins belong in measured environment configuration.
pub const UNMEASURED_DATA_DIR: &str = "/atakit-portal/unmeasured-data";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

/// Public information about one verified pack, used by `GET /v1/config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadedPack {
    pub kind: String,
    pub issuer: String,
    pub revision: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub digest: String,
}

/// The complete daemon configuration.
#[derive(Debug)]
pub struct VerifierdConfig {
    pub listen: SocketAddr,
    pub mode: TrustModeConfig,
    pub portal_destination_policy: PortalDestinationPolicy,
}

/// One authority, carrying only inputs supplied by that authority.
#[derive(Debug)]
pub enum TrustModeConfig {
    Chain {
        client: AttestationClientConfig,
        tdx_dcap_collateral: IntelTdxDcapCollateralConfig,
    },
    TrustPack {
        source: PackTrustSource,
        packs: Vec<LoadedPack>,
    },
    Explicit {
        source: Box<ExplicitTrustSource>,
        measurement_policy: Box<MeasurementPolicy>,
        base_image: AppRef,
        workload_pcr23_sha256: [u8; 32],
        workload_pcr23_sha384: [u8; 48],
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

const GLOBAL: &[&str] = &[
    "VERIFIED_TRUST_MODE",
    "VERIFIED_LISTEN",
    "VERIFIED_PCCS_URL",
    "VERIFIED_PORTAL_ALLOWED_PORTS",
    "VERIFIED_PORTAL_ALLOWED_CIDRS",
];
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
const EXPLICIT_ONLY: &[&str] = &[
    "VERIFIED_MEASUREMENTS",
    "VERIFIED_MEASUREMENT_PUBLISHER_PUBKEYS",
    "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA256",
    "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA384",
    "VERIFIED_GCP_AK_ROOT_CERTS",
    "VERIFIED_AZURE_MAA_CERTS",
    "VERIFIED_AWS_NITRO_ROOT_CERTS",
    "VERIFIED_AMD_ARK_ROOT_CERTS",
    "VERIFIED_AMD_SNP_CRLS",
    "VERIFIED_AMD_SNP_SECURITY_POLICY",
    "VERIFIED_TDX_DCAP_COLLATERAL",
    "VERIFIED_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS",
    "VERIFIED_AWS_DOCUMENT_ALLOWED_FUTURE_CLOCK_DIFFERENCE_SECONDS",
];

/// Parse and fully validate configuration. Trust packs and explicit trust
/// files are consumed here, so malformed or ambiguous inputs stop startup.
pub fn load(
    env: &BTreeMap<String, String>,
    unmeasured_dir: &Path,
    now_unix: u64,
) -> Result<VerifierdConfig, ConfigError> {
    reject_unknown_verified_names(env)?;
    let mode_name = required(env, "VERIFIED_TRUST_MODE")?;
    let packs = discover_packs(unmeasured_dir)?;
    let pccs_url = optional_nonempty(env, "VERIFIED_PCCS_URL")?;
    if let Some(url) = &pccs_url {
        validate_http_url("VERIFIED_PCCS_URL", url)?;
    }

    let mode = match mode_name.as_str() {
        "chain" => {
            reject_foreign(env, &mode_name, TRUST_PACK_ONLY)?;
            reject_foreign(env, &mode_name, EXPLICIT_ONLY)?;
            reject_packs(&mode_name, &packs)?;
            let rpc_url = required(env, "VERIFIED_RPC_URL")?;
            validate_http_url("VERIFIED_RPC_URL", &rpc_url)?;
            let session_registry = required(env, "VERIFIED_SESSION_REGISTRY")?;
            let chain_id = optional_u64(env, "VERIFIED_CHAIN_ID")?;
            let tdx_dcap_collateral =
                tdx_dcap_collateral_config(None, pccs_url.clone(), None, None)
                    .map_err(|error| invalid(error.to_string()))?;
            TrustModeConfig::Chain {
                client: AttestationClientConfig {
                    rpc_url,
                    session_registry,
                    expected_chain_id: chain_id,
                    expected_base_image_registry: None,
                    expected_workload_registry: None,
                },
                tdx_dcap_collateral,
            }
        }
        "trust-pack" => {
            reject_foreign(env, &mode_name, CHAIN_ONLY)?;
            reject_foreign(env, &mode_name, EXPLICIT_ONLY)?;
            load_trust_pack_mode(env, &packs, now_unix, pccs_url.clone())?
        }
        "explicit" => {
            reject_foreign(env, &mode_name, CHAIN_ONLY)?;
            reject_foreign(env, &mode_name, TRUST_PACK_ONLY)?;
            reject_packs(&mode_name, &packs)?;
            load_explicit_mode(env, pccs_url.clone())?
        }
        other => {
            return Err(invalid(format!(
                "VERIFIED_TRUST_MODE is {other:?}; expected chain, trust-pack, or explicit"
            )))
        }
    };

    let listen = env
        .get("VERIFIED_LISTEN")
        .map(String::as_str)
        .unwrap_or("0.0.0.0:9100")
        .parse::<SocketAddr>()
        .map_err(|error| {
            invalid(format!(
                "VERIFIED_LISTEN must be an IP address and port: {error}"
            ))
        })?;

    Ok(VerifierdConfig {
        listen,
        mode,
        portal_destination_policy: portal_destination_policy(env)?,
    })
}

fn load_trust_pack_mode(
    env: &BTreeMap<String, String>,
    packs: &[PathBuf],
    now_unix: u64,
    pccs_url: Option<String>,
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

    let mut collateral_packs = Vec::new();
    let mut workload_packs = Vec::new();
    for path in packs {
        let pack = read_role_pack(
            path,
            now_unix,
            &collateral_key,
            &workload_key,
            collateral_pin,
            workload_pin,
        )?;
        match pack.kind {
            TrustPackKind::CollateralTrust => collateral_packs.push(pack),
            TrustPackKind::WorkloadTrust => workload_packs.push(pack),
        }
    }
    if collateral_packs.is_empty() {
        return Err(invalid(
            "VERIFIED_COLLATERAL_PUBLISHER_PUBKEY has no matching collateral-trust pack",
        ));
    }
    if workload_packs.len() != 1 {
        return Err(invalid(format!(
            "trust-pack mode requires exactly one workload-trust pack, found {}",
            workload_packs.len()
        )));
    }

    let summaries = collateral_packs
        .iter()
        .chain(&workload_packs)
        .map(pack_summary)
        .collect();
    let tdx_dcap_collateral = tdx_dcap_collateral_config(None, pccs_url, None, None)
        .map_err(|error| invalid(error.to_string()))?;
    let source = PackTrustSource::new(collateral_packs, workload_packs, tdx_dcap_collateral)
        .map_err(|error| invalid(error.to_string()))?;
    Ok(TrustModeConfig::TrustPack {
        source,
        packs: summaries,
    })
}

/// Determine the declared role through the bounded reader, then verify under
/// exactly the configured key and optional pin for that role. No unbounded
/// pre-parse occurs before signature verification.
fn read_role_pack(
    path: &Path,
    now_unix: u64,
    collateral_key: &[u8],
    workload_key: &[u8],
    collateral_pin: Option<[u8; 32]>,
    workload_pin: Option<[u8; 32]>,
) -> Result<TrustPack, ConfigError> {
    let collateral_options = TrustPackReadOptions::new(
        TrustPackKind::CollateralTrust,
        collateral_key.to_vec(),
        now_unix,
    );
    match read_trust_pack_file(path, &collateral_options) {
        Ok(pack) => {
            if let Some(pin) = collateral_pin {
                read_trust_pack_file(path, &collateral_options.pinned(pin))
                    .map_err(|error| pack_error(path, error))
            } else {
                Ok(pack)
            }
        }
        Err(TrustPackError::KindMismatch { found, .. })
            if found == TrustPackKind::WorkloadTrust.as_str() =>
        {
            let mut options = TrustPackReadOptions::new(
                TrustPackKind::WorkloadTrust,
                workload_key.to_vec(),
                now_unix,
            );
            if let Some(pin) = workload_pin {
                options = options.pinned(pin);
            }
            read_trust_pack_file(path, &options).map_err(|error| pack_error(path, error))
        }
        Err(error) => Err(pack_error(path, error)),
    }
}

fn pack_error(path: &Path, error: TrustPackError) -> ConfigError {
    invalid(format!("{}: {error}", path.display()))
}

fn pack_summary(pack: &TrustPack) -> LoadedPack {
    LoadedPack {
        kind: pack.kind.as_str().to_string(),
        issuer: pack.index.issuer.clone(),
        revision: pack.index.revision,
        not_before: pack.index.not_before,
        not_after: pack.index.not_after,
        digest: pack.digest_hex(),
    }
}

fn load_explicit_mode(
    env: &BTreeMap<String, String>,
    pccs_url: Option<String>,
) -> Result<TrustModeConfig, ConfigError> {
    let measurements = PathBuf::from(required(env, "VERIFIED_MEASUREMENTS")?);
    let measurement_publisher_keys =
        required_string_list(env, "VERIFIED_MEASUREMENT_PUBLISHER_PUBKEYS")?;
    let measurement_policy =
        load_measurement_policy(Some(&measurements), None, &measurement_publisher_keys, None)
            .map_err(|error| invalid(error.to_string()))?
            .ok_or_else(|| invalid("VERIFIED_MEASUREMENTS did not produce a measurement policy"))?;
    let base_image = format!(
        "{}/{}:{}",
        measurement_policy.pack.subject.publisher,
        measurement_policy.pack.subject.name,
        measurement_policy.pack.subject.version
    )
    .parse::<AppRef>()
    .map_err(|error| {
        invalid(format!(
            "VERIFIED_MEASUREMENTS has an invalid subject: {error}"
        ))
    })?;

    let gcp_roots = path_list(env, "VERIFIED_GCP_AK_ROOT_CERTS")?;
    let azure_maa = path_list(env, "VERIFIED_AZURE_MAA_CERTS")?;
    let aws_nitro_roots = path_list(env, "VERIFIED_AWS_NITRO_ROOT_CERTS")?;
    let amd_ark = path_list(env, "VERIFIED_AMD_ARK_ROOT_CERTS")?;
    let amd_crls = path_list(env, "VERIFIED_AMD_SNP_CRLS")?;
    let amd_policy = optional_path(env, "VERIFIED_AMD_SNP_SECURITY_POLICY")?;
    let aws_document_maximum_age_seconds =
        optional_u64(env, "VERIFIED_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS")?;
    let aws_document_allowed_future_clock_difference_seconds = optional_u64(
        env,
        "VERIFIED_AWS_DOCUMENT_ALLOWED_FUTURE_CLOCK_DIFFERENCE_SECONDS",
    )?;
    match (
        aws_document_maximum_age_seconds,
        aws_document_allowed_future_clock_difference_seconds,
    ) {
        (Some(0), Some(_)) => {
            return Err(invalid(
                "VERIFIED_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS must be greater than zero",
            ));
        }
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(invalid(
                "VERIFIED_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS and \
                 VERIFIED_AWS_DOCUMENT_ALLOWED_FUTURE_CLOCK_DIFFERENCE_SECONDS must be supplied together",
            ));
        }
    }
    let trust = load_tls_verification_trust(TlsVerificationTrustFiles {
        gcp_ak_root_certs: &gcp_roots,
        azure_maa_certs: &azure_maa,
        aws_nitro_root_certs: &aws_nitro_roots,
        amd_ark_root_certs: &amd_ark,
        amd_snp_crls: &amd_crls,
        amd_snp_security_policy: amd_policy.as_deref(),
        aws_document_maximum_age_seconds,
        aws_document_allowed_future_clock_difference_seconds,
    })
    .map_err(|error| invalid(error.to_string()))?;

    let collateral_file = optional_path(env, "VERIFIED_TDX_DCAP_COLLATERAL")?;
    let tdx_dcap_collateral = match (collateral_file, pccs_url) {
        (Some(path), None) => IntelTdxDcapCollateralConfig {
            source: IntelTdxDcapCollateralSource::File(path),
        },
        (None, Some(url)) => IntelTdxDcapCollateralConfig {
            source: IntelTdxDcapCollateralSource::HttpPccs { url },
        },
        (None, None) => tdx_dcap_collateral_config(None, None, None, None)
            .map_err(|error| invalid(error.to_string()))?,
        (Some(_), Some(_)) => {
            return Err(invalid(
                "choose only one of VERIFIED_TDX_DCAP_COLLATERAL and VERIFIED_PCCS_URL",
            ));
        }
    };
    let source = ExplicitTrustSource::new(trust, tdx_dcap_collateral)
        .map_err(|error| invalid(error.to_string()))?;

    Ok(TrustModeConfig::Explicit {
        source: Box::new(source),
        measurement_policy: Box::new(measurement_policy),
        base_image,
        workload_pcr23_sha256: fixed_hex::<32>(env, "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA256")?,
        workload_pcr23_sha384: fixed_hex::<48>(env, "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA384")?,
    })
}

fn reject_unknown_verified_names(env: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    for key in env.keys().filter(|key| key.starts_with("VERIFIED_")) {
        if GLOBAL.contains(&key.as_str())
            || CHAIN_ONLY.contains(&key.as_str())
            || TRUST_PACK_ONLY.contains(&key.as_str())
            || EXPLICIT_ONLY.contains(&key.as_str())
        {
            continue;
        }
        return Err(invalid(format!(
            "unknown {key}; every VERIFIED_* variable must be recognized so a misspelled security input cannot be ignored"
        )));
    }
    Ok(())
}

fn portal_destination_policy(
    env: &BTreeMap<String, String>,
) -> Result<PortalDestinationPolicy, ConfigError> {
    let allowed_ports = match env.get("VERIFIED_PORTAL_ALLOWED_PORTS") {
        Some(raw) => {
            let ports: Vec<u16> = serde_json::from_str(raw).map_err(|error| {
                invalid(format!(
                    "VERIFIED_PORTAL_ALLOWED_PORTS must be a JSON array of ports: {error}"
                ))
            })?;
            ports.into_iter().collect::<BTreeSet<_>>()
        }
        None => BTreeSet::from([2024]),
    };
    let allowed_cidrs = env
        .get("VERIFIED_PORTAL_ALLOWED_CIDRS")
        .map(|_| required_string_list(env, "VERIFIED_PORTAL_ALLOWED_CIDRS"))
        .transpose()?
        .map(|values| {
            values
                .into_iter()
                .map(|value| {
                    value.parse::<IpNet>().map_err(|error| {
                        invalid(format!(
                            "VERIFIED_PORTAL_ALLOWED_CIDRS contains invalid CIDR {value:?}: {error}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    PortalDestinationPolicy::new(allowed_ports, allowed_cidrs)
        .map_err(|error| invalid(error.to_string()))
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
        let file_type = entry.file_type().map_err(|error| {
            invalid(format!(
                "read file type for {}: {error}",
                entry.path().display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("atatp") {
            if !file_type.is_file() {
                return Err(invalid(format!(
                    "{} has an .atatp extension but is not a regular file",
                    path.display()
                )));
            }
            packs.push(path);
        }
    }
    packs.sort();
    Ok(packs)
}

fn reject_packs(mode: &str, packs: &[PathBuf]) -> Result<(), ConfigError> {
    if let Some(path) = packs.first() {
        return Err(invalid(format!(
            "VERIFIED_TRUST_MODE is {mode}, but {} is present; remove it, or select trust-pack mode",
            path.display()
        )));
    }
    Ok(())
}

fn required(env: &BTreeMap<String, String>, key: &str) -> Result<String, ConfigError> {
    let value = env
        .get(key)
        .ok_or_else(|| invalid(format!("{key} is required in this mode")))?;
    if value.trim().is_empty() {
        return Err(invalid(format!("{key} must not be empty")));
    }
    Ok(value.clone())
}

fn optional_nonempty(
    env: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<String>, ConfigError> {
    env.get(key).map(|_| required(env, key)).transpose()
}

fn optional_path(
    env: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<PathBuf>, ConfigError> {
    optional_nonempty(env, key).map(|value| value.map(PathBuf::from))
}

fn optional_u64(env: &BTreeMap<String, String>, key: &str) -> Result<Option<u64>, ConfigError> {
    optional_nonempty(env, key)?
        .map(|value| {
            value
                .parse()
                .map_err(|_| invalid(format!("{key} is not an unsigned integer: {value:?}")))
        })
        .transpose()
}

fn required_string_list(
    env: &BTreeMap<String, String>,
    key: &str,
) -> Result<Vec<String>, ConfigError> {
    let raw = required(env, key)?;
    let values: Vec<String> = serde_json::from_str(&raw)
        .map_err(|error| invalid(format!("{key} must be a JSON array of strings: {error}")))?;
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(invalid(format!(
            "{key} must contain at least one nonempty string"
        )));
    }
    Ok(values)
}

fn path_list(env: &BTreeMap<String, String>, key: &str) -> Result<Vec<PathBuf>, ConfigError> {
    match env.get(key) {
        Some(_) => required_string_list(env, key)
            .map(|values| values.into_iter().map(PathBuf::from).collect()),
        None => Ok(Vec::new()),
    }
}

fn publisher_key(env: &BTreeMap<String, String>, key: &str) -> Result<Vec<u8>, ConfigError> {
    let value = required(env, key)?;
    let bytes = canonical_hex(key, &value)?;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(invalid(format!(
            "{key} must be a 65-byte uncompressed SEC1 secp256k1 point beginning 0x04, got {} bytes",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn pin(env: &BTreeMap<String, String>, key: &str) -> Result<Option<[u8; 32]>, ConfigError> {
    let Some(value) = env.get(key) else {
        return Ok(None);
    };
    let bytes = canonical_hex(key, value)?;
    let digest = bytes
        .try_into()
        .map_err(|_| invalid(format!("{key} must be 32 bytes")))?;
    Ok(Some(digest))
}

fn fixed_hex<const N: usize>(
    env: &BTreeMap<String, String>,
    key: &str,
) -> Result<[u8; N], ConfigError> {
    canonical_hex(key, &required(env, key)?)?
        .try_into()
        .map_err(|_| invalid(format!("{key} must be {N} bytes")))
}

fn canonical_hex(key: &str, value: &str) -> Result<Vec<u8>, ConfigError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("{key} must start with 0x")))?;
    if raw.is_empty()
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{key} must use lowercase hexadecimal after 0x"
        )));
    }
    hex::decode(raw).map_err(|error| invalid(format!("{key} is not hexadecimal: {error}")))
}

fn validate_http_url(key: &str, value: &str) -> Result<(), ConfigError> {
    let uri: axum::http::Uri = value
        .parse()
        .map_err(|error| invalid(format!("{key} is not a valid URL: {error}")))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        return Err(invalid(format!(
            "{key} must be an http or https URL with a host"
        )));
    }
    Ok(())
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
        "VERIFIED_TRUST_MODE is {mode}, so {} belongs to a mode that was not selected; a variable for an unselected authority is a configuration error, not a value to ignore",
        present.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use atakit_attestation_client::TrustPackBuilder;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::{Signature, SigningKey};

    const NOW: u64 = 1_786_000_000;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn empty_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn publisher(seed: u8) -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[seed; 32].into()).expect("signing key");
        let public_key = key.verifying_key().to_encoded_point(false);
        (key, format!("0x{}", hex::encode(public_key.as_bytes())))
    }

    fn write_pack(dir: &Path, name: &str, kind: TrustPackKind, key: &SigningKey, issuer: &str) {
        let mut builder = TrustPackBuilder::new(kind, issuer, 1, NOW - 100, NOW + 100);
        match kind {
            TrustPackKind::CollateralTrust => builder
                .insert(
                    "payload/aws-document-limits.json",
                    br#"{"maximum_age_seconds":300,"allowed_future_clock_difference_seconds":60}"#
                        .to_vec(),
                )
                .expect("AWS document limits"),
            TrustPackKind::WorkloadTrust => builder
                .insert("payload/workload-spec.json", b"{}".to_vec())
                .expect("workload spec"),
        }
        let archive = builder
            .build(|message| {
                let signature: Signature = key.sign(message);
                Ok::<_, std::convert::Infallible>(signature.to_bytes().to_vec())
            })
            .expect("trust pack");
        std::fs::write(dir.join(name), archive).expect("write trust pack");
    }

    fn trust_pack_env(collateral_key: &str, workload_key: &str) -> BTreeMap<String, String> {
        env(&[
            ("VERIFIED_TRUST_MODE", "trust-pack"),
            ("VERIFIED_COLLATERAL_PUBLISHER_PUBKEY", collateral_key),
            ("VERIFIED_WORKLOAD_PUBLISHER_PUBKEY", workload_key),
        ])
    }

    fn write_measurement_pack(dir: &Path) -> (String, String) {
        let publisher = format!("0x{}", "aa".repeat(32));
        let reference = format!("{publisher}/automata-linux:v1");
        let app_ref: AppRef = reference.parse().expect("base-image reference");
        let id = atakit_cvm_encoding::base_image_id(&app_ref);
        let json = format!(
            r#"{{"measurements":{{"profiles":[]}},"published_at":1786000000,"revision":1,"schema":"atakit.base_image_measurement_pack.v4","subject":{{"id":"0x{}","name":"automata-linux","publisher":"{publisher}","version":"v1"}}}}"#,
            hex::encode(id)
        );
        let key = SigningKey::from_bytes(&[0x21; 32].into()).expect("measurement signing key");
        let signature: Signature = key.sign(json.as_bytes());
        let json_path = dir.join("measurement-pack.json");
        std::fs::write(&json_path, json).expect("measurement pack");
        std::fs::write(dir.join("measurement-pack.sig"), signature.to_bytes())
            .expect("measurement signature");
        let public_key = hex::encode(key.verifying_key().to_encoded_point(false).as_bytes());
        (json_path.display().to_string(), public_key)
    }

    #[test]
    fn missing_and_unknown_modes_are_refused() {
        let dir = empty_dir();
        assert!(load(&env(&[]), dir.path(), 1_786_000_000)
            .unwrap_err()
            .to_string()
            .contains("VERIFIED_TRUST_MODE"));
        assert!(load(
            &env(&[("VERIFIED_TRUST_MODE", "whatever")]),
            dir.path(),
            1_786_000_000,
        )
        .unwrap_err()
        .to_string()
        .contains("expected chain"));
    }

    #[test]
    fn an_unknown_verified_name_is_never_ignored() {
        let dir = empty_dir();
        for typo in [
            "VERIFIED_CHAIN_IDD",
            "VERIFIED_WORKLOAD_TRUST_PACK_SHA25",
            "VERIFIED_PCSS_URL",
        ] {
            let error = load(
                &env(&[("VERIFIED_TRUST_MODE", "explicit"), (typo, "value")]),
                dir.path(),
                1_786_000_000,
            )
            .expect_err("a misspelled VERIFIED_* variable must stop startup");
            assert!(error.to_string().contains(typo), "{error}");
        }
    }

    #[test]
    fn variables_from_an_unselected_mode_are_refused() {
        let dir = empty_dir();
        let cases = [
            ("chain", "VERIFIED_COLLATERAL_PUBLISHER_PUBKEY"),
            ("chain", "VERIFIED_MEASUREMENTS"),
            ("explicit", "VERIFIED_RPC_URL"),
            ("trust-pack", "VERIFIED_SESSION_REGISTRY"),
        ];
        for (mode, foreign) in cases {
            let mut values = vec![("VERIFIED_TRUST_MODE", mode), (foreign, "value")];
            if mode == "chain" {
                values.extend([
                    ("VERIFIED_RPC_URL", "https://rpc.example"),
                    (
                        "VERIFIED_SESSION_REGISTRY",
                        "0x1111111111111111111111111111111111111111",
                    ),
                ]);
            }
            let error = load(&env(&values), dir.path(), 1_786_000_000)
                .expect_err("a foreign authority variable must stop startup");
            assert!(error.to_string().contains(foreign), "{error}");
        }
    }

    #[test]
    fn a_pack_under_a_non_pack_mode_is_refused() {
        let dir = empty_dir();
        std::fs::write(dir.path().join("collateral.atatp"), b"not a pack").unwrap();
        let error = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "chain"),
                ("VERIFIED_RPC_URL", "https://rpc.example"),
                (
                    "VERIFIED_SESSION_REGISTRY",
                    "0x1111111111111111111111111111111111111111",
                ),
            ]),
            dir.path(),
            1_786_000_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("collateral.atatp"), "{error}");
    }

    #[test]
    fn peer_variables_are_rejected_instead_of_silently_ignored() {
        let dir = empty_dir();
        let error = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "chain"),
                ("VERIFIED_RPC_URL", "https://rpc.example"),
                (
                    "VERIFIED_SESSION_REGISTRY",
                    "0x1111111111111111111111111111111111111111",
                ),
                ("VERIFIED_PEER_BETA", "203.0.113.10:2024"),
            ]),
            dir.path(),
            NOW,
        )
        .expect_err("the removed peer allowlist must not be accepted");
        assert!(error.to_string().contains("unknown VERIFIED_PEER_BETA"));
    }

    #[test]
    fn destination_policy_defaults_to_port_2024_without_a_cidr_limit() {
        let policy = portal_destination_policy(&env(&[])).unwrap();
        assert_eq!(policy.allowed_ports(), &BTreeSet::from([2024]));
        assert_eq!(policy.allowed_cidrs(), None);
    }

    #[test]
    fn destination_policy_parses_optional_ports_and_cidrs_strictly() {
        let policy = portal_destination_policy(&env(&[
            ("VERIFIED_PORTAL_ALLOWED_PORTS", "[2024,12024]"),
            (
                "VERIFIED_PORTAL_ALLOWED_CIDRS",
                r#"["10.0.0.0/8","2001:db8::/32"]"#,
            ),
        ]))
        .unwrap();
        assert_eq!(policy.allowed_ports(), &BTreeSet::from([2024, 12024]));
        assert_eq!(
            policy
                .allowed_cidrs()
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.0/8", "2001:db8::/32"]
        );

        for (key, value) in [
            ("VERIFIED_PORTAL_ALLOWED_PORTS", "[]"),
            ("VERIFIED_PORTAL_ALLOWED_PORTS", "[0]"),
            ("VERIFIED_PORTAL_ALLOWED_PORTS", "[\"2024\"]"),
            ("VERIFIED_PORTAL_ALLOWED_CIDRS", "[]"),
            ("VERIFIED_PORTAL_ALLOWED_CIDRS", "[\"bad\"]"),
        ] {
            assert!(
                portal_destination_policy(&env(&[(key, value)])).is_err(),
                "{key}={value}"
            );
        }
    }

    #[test]
    fn empty_known_values_are_refused() {
        let dir = empty_dir();
        let error = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "chain"),
                ("VERIFIED_RPC_URL", ""),
                (
                    "VERIFIED_SESSION_REGISTRY",
                    "0x1111111111111111111111111111111111111111",
                ),
            ]),
            dir.path(),
            1_786_000_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must not be empty"), "{error}");
    }

    #[test]
    fn chain_mode_keeps_the_configured_off_chain_pccs() {
        let dir = empty_dir();
        let loaded = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "chain"),
                ("VERIFIED_RPC_URL", "https://rpc.example"),
                (
                    "VERIFIED_SESSION_REGISTRY",
                    "0x1111111111111111111111111111111111111111",
                ),
                ("VERIFIED_PCCS_URL", "https://pccs.example/v4"),
            ]),
            dir.path(),
            NOW,
        )
        .expect("chain configuration");
        let TrustModeConfig::Chain {
            tdx_dcap_collateral,
            ..
        } = loaded.mode
        else {
            panic!("expected chain mode");
        };
        assert!(matches!(
            tdx_dcap_collateral.source,
            IntelTdxDcapCollateralSource::HttpPccs { ref url }
                if url == "https://pccs.example/v4"
        ));
    }

    #[test]
    fn explicit_mode_constructs_its_complete_authority_at_startup() {
        let dir = empty_dir();
        let (measurement_path, measurement_public_key) = write_measurement_pack(dir.path());
        let loaded = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "explicit"),
                ("VERIFIED_MEASUREMENTS", &measurement_path),
                (
                    "VERIFIED_MEASUREMENT_PUBLISHER_PUBKEYS",
                    &format!(r#"["{measurement_public_key}"]"#),
                ),
                (
                    "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA256",
                    &format!("0x{}", "11".repeat(32)),
                ),
                (
                    "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA384",
                    &format!("0x{}", "22".repeat(48)),
                ),
            ]),
            dir.path(),
            NOW,
        )
        .expect("explicit configuration");
        let TrustModeConfig::Explicit { base_image, .. } = loaded.mode else {
            panic!("expected explicit mode");
        };
        assert_eq!(base_image.name, "automata-linux");
        assert_eq!(base_image.version, "v1");
    }

    #[test]
    fn explicit_mode_names_both_conflicting_tdx_collateral_variables() {
        let dir = empty_dir();
        let (measurement_path, measurement_public_key) = write_measurement_pack(dir.path());
        let collateral = dir.path().join("tdx-collateral.json");
        std::fs::write(&collateral, b"{}").expect("collateral placeholder");
        let error = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "explicit"),
                ("VERIFIED_MEASUREMENTS", &measurement_path),
                (
                    "VERIFIED_MEASUREMENT_PUBLISHER_PUBKEYS",
                    &format!(r#"["{measurement_public_key}"]"#),
                ),
                (
                    "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA256",
                    &format!("0x{}", "11".repeat(32)),
                ),
                (
                    "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA384",
                    &format!("0x{}", "22".repeat(48)),
                ),
                (
                    "VERIFIED_TDX_DCAP_COLLATERAL",
                    &collateral.display().to_string(),
                ),
                ("VERIFIED_PCCS_URL", "https://pccs.example/v4"),
            ]),
            dir.path(),
            NOW,
        )
        .expect_err("two Intel TDX collateral sources must be refused");
        let message = error.to_string();
        assert!(message.contains("VERIFIED_TDX_DCAP_COLLATERAL"));
        assert!(message.contains("VERIFIED_PCCS_URL"));
    }

    #[test]
    fn explicit_mode_consumes_aws_root_and_document_limits() {
        let dir = empty_dir();
        let (measurement_path, measurement_public_key) = write_measurement_pack(dir.path());
        let aws_root = dir.path().join("aws-root.der");
        let amd_ark = dir.path().join("amd-ark.der");
        let amd_policy = dir.path().join("amd-policy.json");
        std::fs::write(&aws_root, [0x30, 0x82, 0x01]).expect("AWS root");
        std::fs::write(&amd_ark, [0x30, 0x82, 0x02]).expect("AMD ARK");
        std::fs::write(
            &amd_policy,
            br#"{
                "schema": "atakit.amd-sev-snp-security-policy",
                "version": 1,
                "policies": [{
                    "cpuid": "0x191101",
                    "minimumTcb": "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
                    "platformInfoPolicy": "0x0000000000000000000000000000000000000000000000000000000000000020",
                    "requiredLaunchMitigationVector": "0x0000000000000000",
                    "requiredCurrentMitigationVector": "0x0000000000000000"
                }]
            }"#,
        )
        .expect("AMD policy");

        let loaded = load(
            &env(&[
                ("VERIFIED_TRUST_MODE", "explicit"),
                ("VERIFIED_MEASUREMENTS", &measurement_path),
                (
                    "VERIFIED_MEASUREMENT_PUBLISHER_PUBKEYS",
                    &format!(r#"["{measurement_public_key}"]"#),
                ),
                (
                    "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA256",
                    &format!("0x{}", "11".repeat(32)),
                ),
                (
                    "VERIFIED_TRUSTED_WORKLOAD_PCR23_SHA384",
                    &format!("0x{}", "22".repeat(48)),
                ),
                (
                    "VERIFIED_AWS_NITRO_ROOT_CERTS",
                    &format!(r#"["{}"]"#, aws_root.display()),
                ),
                (
                    "VERIFIED_AMD_ARK_ROOT_CERTS",
                    &format!(r#"["{}"]"#, amd_ark.display()),
                ),
                (
                    "VERIFIED_AMD_SNP_SECURITY_POLICY",
                    &amd_policy.display().to_string(),
                ),
                ("VERIFIED_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS", "300"),
                (
                    "VERIFIED_AWS_DOCUMENT_ALLOWED_FUTURE_CLOCK_DIFFERENCE_SECONDS",
                    "60",
                ),
            ]),
            dir.path(),
            NOW,
        )
        .expect("explicit AWS configuration");

        let TrustModeConfig::Explicit { source, .. } = loaded.mode else {
            panic!("expected explicit mode");
        };
        assert_eq!(source.supported_platforms(), ["aws-sev-snp"]);
    }

    #[test]
    fn a_valid_collateral_and_workload_pack_pair_constructs_the_live_source() {
        let dir = empty_dir();
        let (collateral_signing_key, collateral_public_key) = publisher(0x31);
        let (workload_signing_key, workload_public_key) = publisher(0x32);
        write_pack(
            dir.path(),
            "collateral.atatp",
            TrustPackKind::CollateralTrust,
            &collateral_signing_key,
            "collateral-publisher",
        );
        write_pack(
            dir.path(),
            "workload.atatp",
            TrustPackKind::WorkloadTrust,
            &workload_signing_key,
            "workload-publisher",
        );

        let loaded = load(
            &trust_pack_env(&collateral_public_key, &workload_public_key),
            dir.path(),
            NOW,
        )
        .expect("valid trust-pack configuration");
        let TrustModeConfig::TrustPack { source, packs } = loaded.mode else {
            panic!("expected trust-pack mode");
        };
        assert_eq!(packs.len(), 2);
        assert!(source.supported_platforms().is_empty());
    }

    #[test]
    fn trust_pack_roles_are_bound_to_distinct_configured_keys() {
        let dir = empty_dir();
        let (collateral_signing_key, collateral_public_key) = publisher(0x41);
        let (workload_signing_key, workload_public_key) = publisher(0x42);
        write_pack(
            dir.path(),
            "collateral.atatp",
            TrustPackKind::CollateralTrust,
            &collateral_signing_key,
            "collateral-publisher",
        );
        write_pack(
            dir.path(),
            "workload.atatp",
            TrustPackKind::WorkloadTrust,
            &workload_signing_key,
            "workload-publisher",
        );

        let error = load(
            &trust_pack_env(&workload_public_key, &collateral_public_key),
            dir.path(),
            NOW,
        )
        .expect_err("a pack signed by the other role must fail");
        assert!(error.to_string().contains("signature"), "{error}");
    }

    #[test]
    fn trust_pack_mode_requires_both_roles() {
        let (collateral_signing_key, collateral_public_key) = publisher(0x51);
        let (workload_signing_key, workload_public_key) = publisher(0x52);

        let collateral_only = empty_dir();
        write_pack(
            collateral_only.path(),
            "collateral.atatp",
            TrustPackKind::CollateralTrust,
            &collateral_signing_key,
            "collateral-publisher",
        );
        let error = load(
            &trust_pack_env(&collateral_public_key, &workload_public_key),
            collateral_only.path(),
            NOW,
        )
        .expect_err("a workload pack is required");
        assert!(
            error.to_string().contains("exactly one workload-trust"),
            "{error}"
        );

        let workload_only = empty_dir();
        write_pack(
            workload_only.path(),
            "workload.atatp",
            TrustPackKind::WorkloadTrust,
            &workload_signing_key,
            "workload-publisher",
        );
        let error = load(
            &trust_pack_env(&collateral_public_key, &workload_public_key),
            workload_only.path(),
            NOW,
        )
        .expect_err("a collateral pack is required");
        assert!(
            error.to_string().contains("no matching collateral"),
            "{error}"
        );
    }

    #[test]
    fn trust_pack_digest_pins_are_checked_at_startup() {
        let dir = empty_dir();
        let (collateral_signing_key, collateral_public_key) = publisher(0x61);
        let (workload_signing_key, workload_public_key) = publisher(0x62);
        write_pack(
            dir.path(),
            "collateral.atatp",
            TrustPackKind::CollateralTrust,
            &collateral_signing_key,
            "collateral-publisher",
        );
        write_pack(
            dir.path(),
            "workload.atatp",
            TrustPackKind::WorkloadTrust,
            &workload_signing_key,
            "workload-publisher",
        );

        let first = load(
            &trust_pack_env(&collateral_public_key, &workload_public_key),
            dir.path(),
            NOW,
        )
        .expect("unpinned packs");
        let TrustModeConfig::TrustPack { packs, .. } = first.mode else {
            panic!("expected trust-pack mode");
        };
        let collateral_digest = packs
            .iter()
            .find(|pack| pack.kind == TrustPackKind::CollateralTrust.as_str())
            .expect("collateral summary")
            .digest
            .clone();
        let workload_digest = packs
            .iter()
            .find(|pack| pack.kind == TrustPackKind::WorkloadTrust.as_str())
            .expect("workload summary")
            .digest
            .clone();

        let mut pinned = trust_pack_env(&collateral_public_key, &workload_public_key);
        pinned.insert(
            "VERIFIED_COLLATERAL_TRUST_PACK_SHA256".to_string(),
            collateral_digest,
        );
        pinned.insert(
            "VERIFIED_WORKLOAD_TRUST_PACK_SHA256".to_string(),
            workload_digest,
        );
        load(&pinned, dir.path(), NOW).expect("matching pins");

        pinned.insert(
            "VERIFIED_WORKLOAD_TRUST_PACK_SHA256".to_string(),
            format!("0x{}", "00".repeat(32)),
        );
        let error = load(&pinned, dir.path(), NOW).expect_err("a mismatched pin must fail");
        assert!(error.to_string().contains("digest"), "{error}");
    }

    #[test]
    fn duplicate_collateral_claims_fail_during_configuration_load() {
        let dir = empty_dir();
        let (collateral_signing_key, collateral_public_key) = publisher(0x71);
        let (workload_signing_key, workload_public_key) = publisher(0x72);
        for name in ["collateral-a.atatp", "collateral-b.atatp"] {
            write_pack(
                dir.path(),
                name,
                TrustPackKind::CollateralTrust,
                &collateral_signing_key,
                "collateral-publisher",
            );
        }
        write_pack(
            dir.path(),
            "workload.atatp",
            TrustPackKind::WorkloadTrust,
            &workload_signing_key,
            "workload-publisher",
        );

        let error = load(
            &trust_pack_env(&collateral_public_key, &workload_public_key),
            dir.path(),
            NOW,
        )
        .expect_err("duplicate trust claims must fail before serving");
        assert!(error.to_string().contains("duplicate claims"), "{error}");
    }
}
