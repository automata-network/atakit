//! Verifier-supplied trust inputs read from files, and the PEM/DER decoding
//! every certificate flag shares.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use atakit_attestation::{
    parse_amd_snp_security_policy_file_json, AzureMaaTrustCertificate, TrustAnchors,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::PortalVerificationError;

/// Verifier-side source for Azure MAA signing keys.
///
/// The portal includes the Azure MAA JWT in `/tls-attestation`, but the
/// verifier still needs a trust anchor for the JWT signing key. For the CLI
/// default path this is derived from the configured SessionRegistry, matching
/// the on-chain registration verifier's MAA key registry rather than requiring
/// operators to pass `--azure-maa-key` manually.
#[derive(Debug, Clone, Default)]
pub struct AzureMaaTrustConfig {
    pub source: AzureMaaTrustSource,
}

#[derive(Debug, Clone, Default)]
pub enum AzureMaaTrustSource {
    /// Do not resolve Azure MAA signing keys automatically.
    #[default]
    None,
    /// Resolve MaaKeyRegistry through SessionRegistry -> AkCollateralVerifier.
    OnchainRegistry {
        rpc_url: String,
        session_registry: String,
    },
}

/// Build verifier-side Automata on-chain trust config from the chain
/// coordinates the verifier selected. This is independent of portal
/// registration policy: registration controls session submission, while the
/// verifier may still read collateral and trust roots from the chain as a data
/// source.
///
/// This takes the two coordinates rather than a configuration struct because
/// the `/init` payload types stay with `atakit-cloud`; that crate keeps an
/// adapter over its own `InitChainConfig`.
pub fn azure_maa_trust_config_from_chain(
    rpc_url: &str,
    session_registry: &str,
) -> AzureMaaTrustConfig {
    if rpc_url.trim().is_empty() || is_zero_eth_address(session_registry) {
        return AzureMaaTrustConfig::default();
    }
    AzureMaaTrustConfig {
        source: AzureMaaTrustSource::OnchainRegistry {
            rpc_url: rpc_url.to_string(),
            session_registry: session_registry.to_string(),
        },
    }
}

/// Whether a chain is actually selected, rather than a placeholder left in a
/// configuration that has registration turned off.
pub fn chain_coordinates_configured(rpc_url: &str, session_registry: &str) -> bool {
    !rpc_url.trim().is_empty() && !is_zero_eth_address(session_registry)
}

fn is_zero_eth_address(value: &str) -> bool {
    let raw = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    raw.len() == 40 && raw.bytes().all(|byte| byte == b'0')
}

pub(crate) fn parse_measurement_publisher_keys(
    values: &[String],
) -> Result<Vec<Vec<u8>>, PortalVerificationError> {
    parse_hex_blobs(values, "--measurement-publisher-key")
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TlsVerificationTrustFiles<'a> {
    pub gcp_ak_root_certs: &'a [PathBuf],
    pub azure_maa_certs: &'a [PathBuf],
    pub aws_nitro_root_certs: &'a [PathBuf],
    pub amd_ark_root_certs: &'a [PathBuf],
    pub amd_snp_crls: &'a [PathBuf],
    pub amd_snp_security_policy: Option<&'a Path>,
    pub aws_document_maximum_age_seconds: Option<u64>,
    pub aws_document_allowed_future_clock_difference_seconds: Option<u64>,
}

pub fn load_tls_verification_trust(
    files: TlsVerificationTrustFiles<'_>,
) -> Result<TlsVerificationTrust, PortalVerificationError> {
    let TlsVerificationTrustFiles {
        gcp_ak_root_certs,
        azure_maa_certs,
        aws_nitro_root_certs,
        amd_ark_root_certs,
        amd_snp_crls,
        amd_snp_security_policy,
        aws_document_maximum_age_seconds,
        aws_document_allowed_future_clock_difference_seconds,
    } = files;
    let amd_snp_security_policies = match amd_snp_security_policy {
        Some(path) => {
            let document =
                std::fs::read(path).map_err(|source| PortalVerificationError::IoPath {
                    path: path.to_path_buf(),
                    source,
                })?;
            parse_amd_snp_security_policy_file_json(&document).map_err(|error| {
                PortalVerificationError::Config {
                    message: format!("{}: {error}", path.display()),
                }
            })?
        }
        None => Vec::new(),
    };
    let mut sources = BTreeMap::new();
    record_sources(&mut sources, "--gcp-ak-root-cert", gcp_ak_root_certs);
    record_sources(&mut sources, "--azure-maa-cert", azure_maa_certs);
    record_sources(&mut sources, "--aws-nitro-root-cert", aws_nitro_root_certs);
    record_sources(&mut sources, "--amd-ark-root-cert", amd_ark_root_certs);
    record_sources(&mut sources, "--amd-snp-crl", amd_snp_crls);
    if let Some(path) = amd_snp_security_policy {
        record_sources(
            &mut sources,
            "--amd-snp-security-policy",
            std::slice::from_ref(&path.to_path_buf()),
        );
    }
    let (aws_document_maximum_age_seconds, aws_document_allowed_future_clock_difference_seconds) =
        match (
            aws_document_maximum_age_seconds,
            aws_document_allowed_future_clock_difference_seconds,
        ) {
            (Some(maximum_age), Some(allowed_future)) if maximum_age > 0 => {
                (Some(maximum_age), Some(allowed_future))
            }
            (Some(0), Some(_)) => {
                return Err(PortalVerificationError::Config {
                    message: "--aws-document-maximum-age-seconds must be greater than zero"
                        .to_string(),
                });
            }
            (None, None) => (None, None),
            _ => {
                return Err(PortalVerificationError::Config {
                    message: "--aws-document-maximum-age-seconds and \
                              --aws-document-allowed-future-clock-difference-seconds must be \
                              supplied together"
                        .to_string(),
                });
            }
        };
    Ok(TlsVerificationTrust {
        trust_anchors: TrustAnchors {
            gcp_roots: read_der_files(gcp_ak_root_certs, "--gcp-ak-root-cert")?,
            azure_maa_keys: parse_azure_maa_certificates(azure_maa_certs)?,
            aws_nitro_roots: read_der_files(aws_nitro_root_certs, "--aws-nitro-root-cert")?,
            aws_document_maximum_age_seconds,
            aws_document_allowed_future_clock_difference_seconds,
            amd_ark_roots: read_der_files(amd_ark_root_certs, "--amd-ark-root-cert")?,
            amd_snp_security_policies,
            ..TrustAnchors::default()
        },
        amd_snp_crls: read_der_files(amd_snp_crls, "--amd-snp-crl")?,
        sources,
    })
}

/// Verifier-approved roots and verifier-resolved AMD SEV-SNP revocation data.
#[derive(Debug, Clone, Default)]
pub struct TlsVerificationTrust {
    pub trust_anchors: TrustAnchors,
    pub amd_snp_crls: Vec<Vec<u8>>,
    /// Which files fed which flag, keyed by flag name. Retained so explicit
    /// mode can report per-input provenance rather than leaving each caller to
    /// reconstruct it from its own configuration.
    pub sources: BTreeMap<String, Vec<String>>,
}

fn record_sources(sources: &mut BTreeMap<String, Vec<String>>, flag: &str, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    sources.insert(
        flag.to_string(),
        paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
    );
}

/// Read a certificate or revocation list from a file, accepting PEM or DER.
///
/// PEM is detected by its header rather than by file extension, so a `.crt`
/// holding PEM and a `.pem` holding DER both work. A PEM file carrying more
/// than one block contributes every block, which is what a certificate bundle
/// is for.
fn read_der_files(paths: &[PathBuf], flag: &str) -> Result<Vec<Vec<u8>>, PortalVerificationError> {
    let mut out = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path).map_err(|source| PortalVerificationError::IoPath {
            path: path.to_path_buf(),
            source,
        })?;
        if bytes.is_empty() {
            return Err(PortalVerificationError::Config {
                message: format!("{flag} {} is empty", path.display()),
            });
        }
        if bytes.starts_with(b"-----BEGIN") {
            let mut ders = parse_pem_certificates(&bytes).map_err(|error| {
                PortalVerificationError::Config {
                    message: format!("{flag} {}: {error}", path.display()),
                }
            })?;
            out.append(&mut ders);
        } else {
            out.push(bytes);
        }
    }
    Ok(out)
}

/// Read `--azure-maa-cert` files: X.509 certificates in PEM or DER.
///
/// The public key comes from the certificate's `SubjectPublicKeyInfo` and the
/// expiry from its validity period. A bare public key is rejected rather than
/// defaulting to never-expires: that default is what previously made every
/// manually trusted Azure MAA key immortal.
///
/// This takes a path rather than hex because Azure MAA signing certificates
/// embed the attestation policy and run to tens of kilobytes — one observed
/// certificate is 30531 bytes, which is 61062 hex characters. That does not
/// belong on a command line.
fn parse_azure_maa_certificates(
    paths: &[PathBuf],
) -> Result<Vec<AzureMaaTrustCertificate>, PortalVerificationError> {
    use x509_cert::der::Decode;

    read_der_files(paths, "--azure-maa-cert")?
        .into_iter()
        .map(|der| {
            let certificate =
                x509_cert::Certificate::from_der(&der).map_err(|e| PortalVerificationError::Config {
                    message: format!(
                        "--azure-maa-cert must be an X.509 certificate in PEM or DER, not a bare public key: {e}"
                    ),
                })?;
            let public_key = certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| PortalVerificationError::Config {
                    message: "--azure-maa-cert SubjectPublicKeyInfo is not byte-aligned"
                        .to_string(),
                })?
                .to_vec();
            let not_after = certificate
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs();
            Ok(AzureMaaTrustCertificate {
                public_key,
                not_after,
            })
        })
        .collect()
}

fn parse_hex_blobs(values: &[String], flag: &str) -> Result<Vec<Vec<u8>>, PortalVerificationError> {
    values
        .iter()
        .map(|value| {
            let raw = value.strip_prefix("0x").unwrap_or(value);
            hex::decode(raw).map_err(|e| PortalVerificationError::Config {
                message: format!("invalid {flag} hex: {e}"),
            })
        })
        .collect()
}

/// Decode every `CERTIFICATE` block in a PEM document.
///
/// The messages describe only what is wrong with the input; the caller supplies
/// what the input was. Both certificate-file loading and the AMD Key
/// Distribution Service chain fetch use this, so a message naming either one is
/// wrong for the other — as it previously was, reporting a malformed
/// `--gcp-ak-root-cert` as an AMD certificate chain.
pub(crate) fn parse_pem_certificates(input: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(input).map_err(|error| format!("not UTF-8 PEM: {error}"))?;
    let mut remaining = text;
    let mut certs = Vec::new();
    while let Some(begin) = remaining.find(BEGIN) {
        let body = &remaining[begin + BEGIN.len()..];
        let end = body
            .find(END)
            .ok_or_else(|| "unterminated PEM block".to_string())?;
        let encoded = body[..end].lines().map(str::trim).collect::<String>();
        let der = STANDARD
            .decode(encoded)
            .map_err(|error| format!("decode PEM block: {error}"))?;
        certs.push(der);
        remaining = &body[end + END.len()..];
    }
    if certs.is_empty() {
        return Err("no PEM certificates".to_string());
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tls_verification_trust_keeps_amd_crls_separate_from_trust_anchors() {
        let directory = tempfile::tempdir().unwrap();
        let ark = directory.path().join("ark.der");
        let crl = directory.path().join("snp.crl");
        std::fs::write(&ark, [0xaa, 0xbb]).unwrap();
        std::fs::write(&crl, [0xcc, 0xdd]).unwrap();

        let trust = load_tls_verification_trust(TlsVerificationTrustFiles {
            amd_ark_root_certs: &[ark],
            amd_snp_crls: &[crl],
            ..TlsVerificationTrustFiles::default()
        })
        .expect("TLS verification trust");

        assert_eq!(trust.trust_anchors.amd_ark_roots, vec![vec![0xaa, 0xbb]]);
        assert_eq!(trust.amd_snp_crls, vec![vec![0xcc, 0xdd]]);
    }

    /// A PEM file contributes every block it holds, so a bundle works. DER is
    /// taken verbatim. Detection is by header, not file extension.
    #[test]
    fn certificate_files_accept_pem_bundles_and_raw_der() {
        let directory = tempfile::tempdir().unwrap();

        let der = directory.path().join("root.pem");
        std::fs::write(&der, [0x30, 0x82, 0x01]).unwrap();
        assert_eq!(
            read_der_files(&[der], "--gcp-ak-root-cert").unwrap(),
            vec![vec![0x30, 0x82, 0x01]],
            "a .pem holding DER must still be read as DER"
        );

        let bundle = directory.path().join("bundle.crt");
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(b"first"),
            STANDARD.encode(b"second")
        );
        std::fs::write(&bundle, pem).unwrap();
        assert_eq!(
            read_der_files(&[bundle], "--amd-ark-root-cert").unwrap(),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn certificate_files_reject_missing_and_empty_files() {
        let directory = tempfile::tempdir().unwrap();

        let absent = directory.path().join("absent.der");
        assert!(read_der_files(&[absent], "--gcp-ak-root-cert").is_err());

        let empty = directory.path().join("empty.der");
        std::fs::write(&empty, b"").unwrap();
        let error = read_der_files(&[empty], "--gcp-ak-root-cert")
            .expect_err("an empty certificate file must be rejected");
        assert!(
            error.to_string().contains("--gcp-ak-root-cert"),
            "the failure must name the flag; got {error}"
        );
    }

    #[test]
    fn tls_verification_trust_loads_explicit_amd_snp_security_policy() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("amd-snp-security-policy.json");
        std::fs::write(
            &policy_path,
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
        .unwrap();

        let trust = load_tls_verification_trust(TlsVerificationTrustFiles {
            amd_snp_security_policy: Some(&policy_path),
            ..TlsVerificationTrustFiles::default()
        })
        .expect("explicit AMD SEV-SNP security policy");

        assert_eq!(trust.trust_anchors.amd_snp_security_policies.len(), 1);
        assert_eq!(
            trust.trust_anchors.amd_snp_security_policies[0].cpuid,
            0x191101
        );
    }

    #[test]
    fn tls_verification_trust_loads_aws_root_and_freshness_limits_together() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("aws-nitro-root.der");
        std::fs::write(&root, [0x30, 0x82, 0x01]).unwrap();

        let trust = load_tls_verification_trust(TlsVerificationTrustFiles {
            aws_nitro_root_certs: &[root],
            aws_document_maximum_age_seconds: Some(300),
            aws_document_allowed_future_clock_difference_seconds: Some(60),
            ..TlsVerificationTrustFiles::default()
        })
        .expect("AWS trust inputs");

        assert_eq!(
            trust.trust_anchors.aws_nitro_roots,
            vec![vec![0x30, 0x82, 0x01]]
        );
        assert_eq!(
            trust.trust_anchors.aws_document_maximum_age_seconds,
            Some(300)
        );
        assert_eq!(
            trust
                .trust_anchors
                .aws_document_allowed_future_clock_difference_seconds,
            Some(60)
        );
    }

    #[test]
    fn tls_verification_trust_rejects_one_aws_freshness_limit() {
        let error = load_tls_verification_trust(TlsVerificationTrustFiles {
            aws_document_maximum_age_seconds: Some(300),
            ..TlsVerificationTrustFiles::default()
        })
        .expect_err("both AWS document limits are required together");

        assert!(error.to_string().contains(
            "--aws-document-maximum-age-seconds and \
             --aws-document-allowed-future-clock-difference-seconds"
        ));
    }

    #[test]
    fn parses_amd_kds_pem_chain() {
        let pem = b"-----BEGIN CERTIFICATE-----\nYXNr\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nYXJr\n-----END CERTIFICATE-----\n";

        assert_eq!(
            parse_pem_certificates(pem).unwrap(),
            vec![b"ask".to_vec(), b"ark".to_vec()]
        );
    }

    /// A malformed certificate file must be reported as what the operator
    /// actually supplied. The shared PEM decoder previously called every input
    /// an AMD certificate chain, so a bad `--gcp-ak-root-cert` named the wrong
    /// vendor.
    #[test]
    fn pem_failures_name_the_flag_that_supplied_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let unterminated = directory.path().join("root.pem");
        std::fs::write(&unterminated, b"-----BEGIN CERTIFICATE-----\nYXNr\n").unwrap();

        let error = read_der_files(&[unterminated], "--gcp-ak-root-cert")
            .expect_err("an unterminated PEM block must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("--gcp-ak-root-cert"),
            "the failure must name the flag; got {message}"
        );
        assert!(
            message.contains("unterminated PEM block"),
            "the failure must say what is wrong; got {message}"
        );
        assert!(
            !message.contains("AMD"),
            "a GCP root certificate must not be reported as an AMD chain; got {message}"
        );
    }
}

#[cfg(test)]
mod synthetic_azure_maa_certificate {
    use super::*;

    #[test]
    fn extracts_public_key_and_expiry_from_a_generated_certificate() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["attestation.example.invalid".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("certificate.der");
        std::fs::write(&path, cert.der()).unwrap();
        let certificates = parse_azure_maa_certificates(&[path]).unwrap();
        assert_eq!(certificates.len(), 1);
        assert!(!certificates[0].public_key.is_empty());
        assert_eq!(certificates[0].not_after, 1_893_456_000);
    }
}
