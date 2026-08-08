//! Verifier-supplied trust inputs read from files, and the PEM/DER decoding
//! every certificate flag shares.

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

fn is_zero_eth_address(value: &str) -> bool {
    let raw = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    raw.len() == 40 && raw.bytes().all(|byte| byte == b'0')
}

pub(crate) fn parse_measurement_publisher_keys(
    values: &[String],
) -> Result<Vec<Vec<u8>>, PortalVerificationError> {
    parse_hex_blobs(values, "--measurement-publisher-key")
}

pub fn load_tls_verification_trust(
    gcp_ak_root_certs: &[PathBuf],
    azure_maa_certs: &[PathBuf],
    amd_ark_root_certs: &[PathBuf],
    amd_snp_crls: &[PathBuf],
    amd_snp_security_policy: Option<&Path>,
) -> Result<TlsVerificationTrust, PortalVerificationError> {
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
    Ok(TlsVerificationTrust {
        trust_anchors: TrustAnchors {
            gcp_roots: read_der_files(gcp_ak_root_certs, "--gcp-ak-root-cert")?,
            azure_maa_keys: parse_azure_maa_certificates(azure_maa_certs)?,
            amd_ark_roots: read_der_files(amd_ark_root_certs, "--amd-ark-root-cert")?,
            amd_snp_security_policies,
            ..TrustAnchors::default()
        },
        amd_snp_crls: read_der_files(amd_snp_crls, "--amd-snp-crl")?,
    })
}

/// Verifier-approved roots and verifier-resolved AMD SEV-SNP revocation data.
#[derive(Debug, Clone, Default)]
pub struct TlsVerificationTrust {
    pub trust_anchors: TrustAnchors,
    pub amd_snp_crls: Vec<Vec<u8>>,
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

        let trust = load_tls_verification_trust(&[], &[], &[ark], &[crl], None)
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

        let trust = load_tls_verification_trust(&[], &[], &[], &[], Some(&policy_path))
            .expect("explicit AMD SEV-SNP security policy");

        assert_eq!(trust.trust_anchors.amd_snp_security_policies.len(), 1);
        assert_eq!(
            trust.trust_anchors.amd_snp_security_policies[0].cpuid,
            0x191101
        );
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
mod real_azure_maa_certificate {
    use super::*;

    /// The certificate fetched from `https://sharedeus.eus.attest.azure.net/certs`
    /// on 2026-08-08, whose public key was confirmed to verify a live MAA JWT
    /// from the Azure Intel TDX target. 30531 bytes — the size is the point:
    /// as hex on a command line it would be 61062 characters, which is why
    /// these flags take a path.
    const LIVE_MAA_CERTIFICATE: &[u8] = include_bytes!("../testdata/azure-maa-sharedeus.der");

    #[test]
    fn extracts_public_key_and_expiry_from_a_real_maa_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("maa.der");
        std::fs::write(&path, LIVE_MAA_CERTIFICATE).unwrap();

        let certificates =
            parse_azure_maa_certificates(&[path]).expect("real Azure MAA certificate");

        assert_eq!(certificates.len(), 1);
        let certificate = &certificates[0];
        assert!(!certificate.public_key.is_empty());
        // notAfter is 2027-08-07T01:33:34Z; the value that replaces u64::MAX.
        assert_eq!(certificate.not_after, 1_817_602_414);
        assert_ne!(certificate.not_after, u64::MAX);
    }
}

/// End-to-end Azure Intel TDX verification against captured live evidence.
///
/// The evidence in `testdata/` was taken from a real Azure Intel TDX CVM
/// (`Standard_DC2es_v6`, `automata-linux:v0.2.8-debug`) on 2026-08-08, together
/// with the Intel DCAP collateral for that exact quote and the Azure MAA
/// signing certificate that signed its attestation token.
///
/// This replaces a live target for regression purposes. The step 1b acceptance
/// baseline required the *same instance and session* to still exist, so it died
/// the moment that instance was destroyed. Captured evidence does not expire,
/// because `verify_tls_attestation_at` takes a caller-selected verification
/// time and every certificate, collateral, and token check uses that one value.
#[cfg(test)]
mod azure_tdx_captured_evidence {
    use super::*;
    use atakit_attestation::{
        verify_tls_attestation_at, CheckResult, IntelTdxDcapCollateral, TlsAttestationResponse,
        TrustAnchors, VerificationFailure, VerificationInputs,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const ATTESTATION: &str = include_str!("../testdata/azure-tdx-tls-attestation.json");
    const DCAP_COLLATERAL: &str = include_str!("../testdata/azure-tdx-dcap-collateral.json");
    const MAA_CERTIFICATE: &[u8] = include_bytes!("../testdata/azure-maa-sharedeus.der");

    /// Inside the captured MAA token's window, 1786125506 to 1786154306.
    const VERIFICATION_TIME: u64 = 1_786_130_000;

    fn inputs() -> VerificationInputs {
        let raw: serde_json::Value = serde_json::from_str(ATTESTATION).unwrap();
        let quote = B64
            .decode(raw["teeEvidence"]["report"].as_str().unwrap())
            .unwrap();
        let nonce: [u8; 32] = B64
            .decode(raw["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .expect("32-byte nonce");
        let live_peer_cert_der = B64.decode(raw["tlsCertDer"].as_str().unwrap()).unwrap();
        let response: TlsAttestationResponse = serde_json::from_str(ATTESTATION).unwrap();

        let directory = tempfile::tempdir().unwrap();
        let maa_path = directory.path().join("maa.der");
        std::fs::write(&maa_path, MAA_CERTIFICATE).unwrap();
        let azure_maa_keys = parse_azure_maa_certificates(&[maa_path]).unwrap();

        VerificationInputs {
            nonce,
            live_peer_cert_der,
            response,
            intel_tdx_dcap_collateral: Some(
                IntelTdxDcapCollateral::from_file_json(DCAP_COLLATERAL, &quote).unwrap(),
            ),
            amd_snp_collateral: None,
            measurement_policy: None,
            trust_anchors: TrustAnchors {
                azure_maa_keys,
                ..TrustAnchors::default()
            },
        }
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn failed_checks(failure: &VerificationFailure) -> Vec<&str> {
        failure
            .report
            .checks
            .iter()
            .filter(|check| matches!(check.result, CheckResult::Fail))
            .map(|check| check.name.as_str())
            .collect()
    }

    /// Every cryptographic check passes against the captured evidence. The
    /// whole chain is exercised: the TPM quote over the nonce and the live TLS
    /// certificate, the Azure MAA token under the fetched signing certificate,
    /// and the Intel TDX vendor report against real DCAP collateral.
    ///
    /// `measurement-policy` is the sole expected failure. The fixture supplies
    /// no measurement policy, because verifying the signed pack for
    /// `automata-linux:v0.2.8-debug` needs the publisher key that signed it,
    /// which is an operator secret and not committed here. In chain mode the
    /// registry supplies that policy instead.
    ///
    /// Asserting the whole check vector rather than a boolean pins more than
    /// success would: if the relocation of this code changes any check's
    /// outcome, drops one, or reorders the evidence path, this fails.
    #[test]
    fn every_cryptographic_check_passes_against_captured_evidence() {
        let failure = verify_tls_attestation_at(inputs(), at(VERIFICATION_TIME))
            .expect_err("no measurement policy is supplied, so verification cannot succeed");

        let failed: Vec<&str> = failure
            .report
            .checks
            .iter()
            .filter(|check| matches!(check.result, CheckResult::Fail))
            .map(|check| check.name.as_str())
            .collect();

        assert_eq!(
            failed,
            vec!["measurement-policy"],
            "only the deliberately absent measurement policy may fail"
        );

        // The checks that carry the actual security of the attestation.
        for required in [
            "nonce",
            "tls-cert-der",
            "tpm-quote",
            "tpm-signature",
            "live-cert-hash",
            "qualifying-data",
            "tpm-quote-challenge",
            "tpm-quote-pcr-digest",
            "azure-maa-jwt",
            "tpm-quote-signature",
            "tee-evidence",
            "azure-tee-ak-binding",
            "azure-tee-var-data-binding",
            "azure-tee-vendor-report",
            "ak-binding",
        ] {
            let check = failure
                .report
                .checks
                .iter()
                .find(|check| check.name == required)
                .unwrap_or_else(|| panic!("check {required} is missing from the report"));
            assert!(
                matches!(check.result, CheckResult::Pass),
                "{required} must pass against captured live evidence, got {:?}",
                check.result
            );
        }
    }

    /// The nonce binds the attestation to one request. Changing it must fail:
    /// the TPM signed the qualifying data derived from it, so a replayed
    /// response cannot be presented against a different challenge.
    #[test]
    fn rejects_a_different_nonce() {
        let mut inputs = inputs();
        inputs.nonce[0] ^= 0xff;
        let failure = verify_tls_attestation_at(inputs, at(VERIFICATION_TIME)).unwrap_err();
        assert!(
            failed_checks(&failure).contains(&"nonce"),
            "a different nonce must fail the nonce check, not merely fail overall: {:?}",
            failed_checks(&failure)
        );
    }

    /// The quote binds the live TLS certificate. Substituting it must fail,
    /// which is what stops evidence from one host vouching for another.
    #[test]
    fn rejects_a_substituted_tls_certificate() {
        let mut inputs = inputs();
        inputs.live_peer_cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let failure = verify_tls_attestation_at(inputs, at(VERIFICATION_TIME)).unwrap_err();
        assert!(
            failed_checks(&failure).contains(&"live-cert-hash"),
            "a substituted certificate must fail the live certificate binding: {:?}",
            failed_checks(&failure)
        );
    }

    /// Verification is time-checked. After the MAA token expires the same
    /// evidence must stop verifying, which is why the fixture pins a time
    /// rather than using the wall clock.
    #[test]
    fn rejects_evidence_after_the_maa_token_expires() {
        // One second past the captured token's exp.
        let failure = verify_tls_attestation_at(inputs(), at(1_786_154_307)).unwrap_err();
        assert!(
            failed_checks(&failure).contains(&"azure-maa-jwt"),
            "an expired MAA token must fail the MAA check: {:?}",
            failed_checks(&failure)
        );
    }

    /// Without the Azure MAA signing certificate there is no trust anchor for
    /// the attestation token, so verification must fail closed.
    #[test]
    fn rejects_missing_azure_maa_trust_anchor() {
        let mut inputs = inputs();
        inputs.trust_anchors.azure_maa_keys.clear();
        let failure = verify_tls_attestation_at(inputs, at(VERIFICATION_TIME)).unwrap_err();
        assert!(
            failed_checks(&failure).contains(&"azure-maa-jwt"),
            "no MAA trust anchor must fail the MAA check: {:?}",
            failed_checks(&failure)
        );
    }
}
