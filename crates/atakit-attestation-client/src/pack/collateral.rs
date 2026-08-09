//! Converting a `collateral-trust` pack into trust anchors.
//!
//! The conversion produces the same typed values a chain-resolved verifier
//! would produce and weakens no check. What it must not do is decide anything
//! a check depends on: entries are placed into [`TrustAnchors`] exactly as the
//! explicit path places operator-supplied files, and the existing requirement
//! matrix decides which of them a presented platform actually needs.

use std::collections::BTreeMap;

use atakit_attestation::{
    parse_amd_snp_security_policy_file_json, AmdSnpSecurityPolicy, AzureMaaTrustCertificate,
    TrustAnchors,
};

use crate::pack::read::TrustPack;
use crate::pack::{TrustPackError, TrustPackKind};

/// Trust inputs one or more `collateral-trust` packs supply.
#[derive(Debug, Clone, Default)]
pub struct CollateralTrustInputs {
    pub trust_anchors: TrustAnchors,
    pub amd_snp_crls: Vec<Vec<u8>>,
    /// Intel TDX DCAP collateral documents, keyed by payload path.
    ///
    /// Kept as bytes rather than parsed here because parsing one requires the
    /// quote it is selected for: `IntelTdxDcapCollateral::from_file_json`
    /// checks the document's selector against the quote's own
    /// `(fmspc, pceId, pckCa)`. Selection is per verification, so parsing is
    /// too.
    pub tdx_dcap_documents: BTreeMap<String, Vec<u8>>,
    /// Which pack supplied the inputs, for provenance reporting.
    pub issuers: Vec<PackProvenance>,
}

/// Identity of one pack that contributed inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackProvenance {
    /// Human label from `trust-pack.json`. Never used in a trust decision.
    pub issuer: String,
    /// SHA-256 of `trust-pack.json` bytes — what a digest pin names.
    pub digest: String,
}

/// Convert several packs into one set of inputs.
///
/// Duplicate claims across packs are fatal: two packs supplying the same CPUID
/// policy, or the same root, means refusing to start. Silently choosing one
/// would make the winner invisible, and an operator who believed they pinned a
/// value could not tell which one was used.
pub(crate) fn collateral_trust_inputs_from_all(
    packs: &[TrustPack],
) -> Result<CollateralTrustInputs, TrustPackError> {
    let mut inputs = CollateralTrustInputs::default();
    for pack in packs {
        merge_collateral_pack(&mut inputs, pack)?;
    }
    Ok(inputs)
}

fn merge_collateral_pack(
    inputs: &mut CollateralTrustInputs,
    pack: &TrustPack,
) -> Result<(), TrustPackError> {
    if pack.kind != TrustPackKind::CollateralTrust {
        return Err(TrustPackError::KindMismatch {
            expected: TrustPackKind::CollateralTrust.as_str(),
            found: pack.kind.as_str().to_string(),
        });
    }

    for (path, bytes) in &pack.payload {
        match path.as_str() {
            "payload/roots/gcp-ak-root.pem" => {
                push_unique(
                    &mut inputs.trust_anchors.gcp_roots,
                    read_certificate(path, bytes)?,
                    path,
                    "GCP vTPM attestation key root",
                )?;
            }
            "payload/roots/aws-nitro-root.pem" => {
                push_unique(
                    &mut inputs.trust_anchors.aws_nitro_roots,
                    read_certificate(path, bytes)?,
                    path,
                    "AWS Nitro root",
                )?;
            }
            "payload/aws-document-limits.json" => {
                let limits = parse_aws_document_limits(path, bytes)?;
                if inputs
                    .trust_anchors
                    .aws_document_maximum_age_seconds
                    .is_some()
                {
                    return Err(duplicate(path, "AWS attestation document limits"));
                }
                inputs.trust_anchors.aws_document_maximum_age_seconds =
                    Some(limits.maximum_age_seconds);
                inputs
                    .trust_anchors
                    .aws_document_allowed_future_clock_difference_seconds =
                    Some(limits.allowed_future_clock_difference_seconds);
            }
            _ if path.starts_with("payload/roots/amd-ark-") => {
                push_unique(
                    &mut inputs.trust_anchors.amd_ark_roots,
                    read_certificate(path, bytes)?,
                    path,
                    "AMD ARK root",
                )?;
            }
            _ if path.starts_with("payload/azure-maa/") => {
                let certificate = parse_azure_maa_certificate(path, bytes)?;
                if inputs
                    .trust_anchors
                    .azure_maa_keys
                    .iter()
                    .any(|existing| existing.public_key == certificate.public_key)
                {
                    return Err(duplicate(path, "Azure MAA signing certificate"));
                }
                inputs.trust_anchors.azure_maa_keys.push(certificate);
            }
            _ if path.starts_with("payload/amd-snp-security-policy/") => {
                for policy in parse_amd_snp_policies(path, bytes)? {
                    if inputs
                        .trust_anchors
                        .amd_snp_security_policies
                        .iter()
                        .any(|existing| existing.cpuid == policy.cpuid)
                    {
                        return Err(duplicate(
                            path,
                            &format!(
                                "AMD SEV-SNP security policy for CPUID {:#010x}",
                                policy.cpuid
                            ),
                        ));
                    }
                    inputs.trust_anchors.amd_snp_security_policies.push(policy);
                }
            }
            _ if path.starts_with("payload/amd-snp-crl/") => {
                push_unique(
                    &mut inputs.amd_snp_crls,
                    bytes.clone(),
                    path,
                    "AMD SEV-SNP certificate revocation list",
                )?;
            }
            _ if path.starts_with("payload/tdx-dcap/") => {
                if inputs
                    .tdx_dcap_documents
                    .insert(path.clone(), bytes.clone())
                    .is_some()
                {
                    return Err(duplicate(path, "Intel TDX DCAP collateral"));
                }
            }
            // Unreachable: the namespace check refused anything else before
            // this ran. Kept as a rejection rather than a silent skip so a
            // future namespace entry cannot be added without converting it.
            other => {
                return Err(TrustPackError::OutsideNamespace {
                    path: other.to_string(),
                    kind: TrustPackKind::CollateralTrust.as_str(),
                })
            }
        }
    }

    inputs.issuers.push(PackProvenance {
        issuer: pack.index.issuer.clone(),
        digest: pack.digest_hex(),
    });
    Ok(())
}

fn push_unique(
    target: &mut Vec<Vec<u8>>,
    value: Vec<u8>,
    path: &str,
    what: &str,
) -> Result<(), TrustPackError> {
    if target.contains(&value) {
        return Err(duplicate(path, what));
    }
    target.push(value);
    Ok(())
}

fn duplicate(path: &str, what: &str) -> TrustPackError {
    TrustPackError::Payload {
        path: path.to_string(),
        message: format!(
            "a second {what} claims the same input; duplicate claims are fatal, because silently \
             choosing one would make the winner invisible"
        ),
    }
}

/// One PEM certificate, converted to DER.
///
/// A bundle is refused: with several certificates in one entry, which one the
/// path names would be undefined, and `hashes` covers the file rather than any
/// certificate inside it.
fn read_certificate(path: &str, bytes: &[u8]) -> Result<Vec<u8>, TrustPackError> {
    let mut certificates =
        crate::trust::files::parse_pem_certificates(bytes).map_err(|message| {
            TrustPackError::Payload {
                path: path.to_string(),
                message,
            }
        })?;
    if certificates.len() != 1 {
        return Err(TrustPackError::Payload {
            path: path.to_string(),
            message: format!(
                "expected exactly one PEM certificate, found {}",
                certificates.len()
            ),
        });
    }
    Ok(certificates.remove(0))
}

/// The MAA signing certificate, not a bare public key.
///
/// The public key comes from `SubjectPublicKeyInfo` and the expiry from the
/// validity period. A bare key would produce a never-expiring trust key, which
/// is the defect the certificate form exists to prevent.
fn parse_azure_maa_certificate(
    path: &str,
    bytes: &[u8],
) -> Result<AzureMaaTrustCertificate, TrustPackError> {
    use x509_cert::der::Decode;

    let der = read_certificate(path, bytes)?;
    let certificate =
        x509_cert::Certificate::from_der(&der).map_err(|error| TrustPackError::Payload {
            path: path.to_string(),
            message: format!(
                "must be an X.509 MAA signing certificate, not a bare public key: {error}"
            ),
        })?;
    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| TrustPackError::Payload {
            path: path.to_string(),
            message: "SubjectPublicKeyInfo is not byte-aligned".to_string(),
        })?
        .to_vec();
    Ok(AzureMaaTrustCertificate {
        public_key,
        not_after: certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    })
}

fn parse_amd_snp_policies(
    path: &str,
    bytes: &[u8],
) -> Result<Vec<AmdSnpSecurityPolicy>, TrustPackError> {
    parse_amd_snp_security_policy_file_json(bytes).map_err(|error| TrustPackError::Payload {
        path: path.to_string(),
        message: error.to_string(),
    })
}

/// The `(fmspc, pceId, pckCa)` a packed Intel TDX DCAP collateral document
/// declares.
///
/// Strict, and called at construction rather than per verification. An earlier
/// version answered the weaker question "does this document claim this
/// identity?" and returned `false` when the selector was unreadable — which is
/// indistinguishable from a genuine miss, and a miss is permitted to fetch from
/// a configured off-chain source. A corrupt entry therefore became a silent
/// fetch. Parsing up front makes it a configuration error instead, and leaves
/// verification-time selection as a lookup that cannot be ambiguous.
pub(crate) fn parse_collateral_selector(
    document: &[u8],
) -> Result<atakit_attestation::IntelTdxQuoteCollateralIdentity, String> {
    let value: serde_json::Value =
        serde_json::from_slice(document).map_err(|error| format!("not JSON: {error}"))?;
    let selector = value
        .get("selector")
        .ok_or_else(|| "no selector object".to_string())?;
    let field = |name: &str| -> Result<&str, String> {
        selector
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("selector.{name} is missing or not a string"))
    };

    let fmspc = decode_selector_bytes::<6>("selector.fmspc", field("fmspc")?)?;
    let pce_id = decode_selector_bytes::<2>("selector.pceId", field("pceId")?)?;
    let pck_ca = match field("pckCa")? {
        "platform" => atakit_attestation::IntelTdxPckCa::Platform,
        "processor" => atakit_attestation::IntelTdxPckCa::Processor,
        other => {
            return Err(format!(
                "selector.pckCa is {other:?}, not platform or processor"
            ))
        }
    };

    Ok(atakit_attestation::IntelTdxQuoteCollateralIdentity {
        fmspc,
        pce_id,
        pck_ca,
    })
}

/// Lowercase hexadecimal of an exact length.
///
/// Case-strict because the selector is compared against a value derived from
/// the quote; accepting either case would let one identity be spelled two ways
/// and defeat the duplicate-entry check that runs beside it.
fn decode_selector_bytes<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{field} must be {} lowercase hexadecimal characters, got {value:?}",
            N * 2
        ));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(value, &mut out).map_err(|error| format!("{field}: {error}"))?;
    Ok(out)
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsDocumentLimits {
    maximum_age_seconds: u64,
    allowed_future_clock_difference_seconds: u64,
}

fn parse_aws_document_limits(
    path: &str,
    bytes: &[u8],
) -> Result<AwsDocumentLimits, TrustPackError> {
    let limits: AwsDocumentLimits =
        serde_json::from_slice(bytes).map_err(|error| TrustPackError::Payload {
            path: path.to_string(),
            message: error.to_string(),
        })?;
    if limits.maximum_age_seconds == 0 {
        return Err(TrustPackError::Payload {
            path: path.to_string(),
            message: "maximum_age_seconds is 0, which would reject every attestation document"
                .to_string(),
        });
    }
    Ok(limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::fixture::{
        amd_snp_policy_document, certificate_pem, collateral_builder, crl_der, round_trip,
        tdx_dcap_document, tdx_dcap_document_with_fmspc, unchecked_archive, Publisher,
    };
    use crate::pack::write::TrustPackBuilder;
    use crate::trust::request::CollateralRequest;
    use crate::trust::requirements::{required_trust_inputs_for_request, RequiredTrustInput};

    fn pack(builder: &TrustPackBuilder, publisher: &Publisher) -> TrustPack {
        round_trip(builder, TrustPackKind::CollateralTrust, publisher).expect("round trip")
    }

    /// Every entry class lands in the field the chain path would have filled,
    /// so the conversion produces the same typed values rather than a parallel
    /// shape.
    #[test]
    fn every_entry_class_converts_into_its_trust_anchor_field() {
        let publisher = Publisher::new(0x11);
        let mut builder = collateral_builder("example-publisher");
        builder
            .insert(
                "payload/roots/aws-nitro-root.pem",
                certificate_pem("aws-nitro"),
            )
            .unwrap();
        builder
            .insert(
                "payload/roots/amd-ark-milan.pem",
                certificate_pem("amd-ark-milan"),
            )
            .unwrap();
        builder
            .insert("payload/azure-maa/sharedeus.pem", certificate_pem("maa"))
            .unwrap();
        builder
            .insert(
                "payload/amd-snp-security-policy/milan.json",
                amd_snp_policy_document("0x191101"),
            )
            .unwrap();
        builder
            .insert("payload/amd-snp-crl/milan.der", crl_der())
            .unwrap();
        builder
            .insert("payload/tdx-dcap/00806f050000.json", tdx_dcap_document())
            .unwrap();

        let inputs =
            collateral_trust_inputs_from_all(&[pack(&builder, &publisher)]).expect("conversion");

        assert_eq!(inputs.trust_anchors.gcp_roots.len(), 1);
        assert_eq!(inputs.trust_anchors.aws_nitro_roots.len(), 1);
        assert_eq!(inputs.trust_anchors.amd_ark_roots.len(), 1);
        assert_eq!(inputs.trust_anchors.azure_maa_keys.len(), 1);
        assert_eq!(inputs.trust_anchors.amd_snp_security_policies.len(), 1);
        assert_eq!(
            inputs.trust_anchors.amd_snp_security_policies[0].cpuid,
            0x191101
        );
        assert_eq!(
            inputs.trust_anchors.aws_document_maximum_age_seconds,
            Some(300)
        );
        assert_eq!(
            inputs
                .trust_anchors
                .aws_document_allowed_future_clock_difference_seconds,
            Some(60)
        );
        assert_eq!(inputs.amd_snp_crls.len(), 1);
        assert_eq!(inputs.tdx_dcap_documents.len(), 1);
        assert_eq!(inputs.issuers.len(), 1);
        assert_eq!(inputs.issuers[0].issuer, "example-publisher");
    }

    /// An Azure MAA entry carries its own expiry, so a packed key expires the
    /// way a chain-resolved one does rather than never.
    #[test]
    fn an_azure_maa_entry_carries_its_certificate_expiry() {
        let publisher = Publisher::new(0x11);
        let mut builder = collateral_builder("example-publisher");
        builder
            .insert("payload/azure-maa/sharedeus.pem", certificate_pem("maa"))
            .unwrap();

        let inputs = collateral_trust_inputs_from_all(&[pack(&builder, &publisher)]).unwrap();
        let certificate = &inputs.trust_anchors.azure_maa_keys[0];
        assert!(!certificate.public_key.is_empty());
        assert_ne!(
            certificate.not_after,
            u64::MAX,
            "a packed MAA key must not be immortal"
        );
    }

    /// Two files claiming one CPUID is fatal. Choosing one silently would make
    /// the winner invisible, which is the whole reason duplicates are refused.
    #[test]
    fn a_cpuid_claimed_twice_is_fatal() {
        let publisher = Publisher::new(0x11);
        let mut builder = collateral_builder("example-publisher");
        builder
            .insert(
                "payload/amd-snp-security-policy/first.json",
                amd_snp_policy_document("0x191101"),
            )
            .unwrap();
        builder
            .insert(
                "payload/amd-snp-security-policy/second.json",
                amd_snp_policy_document("0x191101"),
            )
            .unwrap();

        let error = collateral_trust_inputs_from_all(&[pack(&builder, &publisher)])
            .expect_err("a CPUID claimed twice must be refused");
        assert!(
            error.to_string().contains("duplicate claims are fatal"),
            "got {error}"
        );

        // A different CPUID in the second file is not a duplicate.
        let mut distinct = collateral_builder("example-publisher");
        distinct
            .insert(
                "payload/amd-snp-security-policy/first.json",
                amd_snp_policy_document("0x191101"),
            )
            .unwrap();
        distinct
            .insert(
                "payload/amd-snp-security-policy/second.json",
                amd_snp_policy_document("0x190f10"),
            )
            .unwrap();
        let inputs = collateral_trust_inputs_from_all(&[pack(&distinct, &publisher)])
            .expect("distinct CPUIDs are not duplicates");
        assert_eq!(inputs.trust_anchors.amd_snp_security_policies.len(), 2);
    }

    /// Duplicate claims across packs are fatal for the same reason they are
    /// within one.
    #[test]
    fn the_same_root_supplied_by_two_packs_is_fatal() {
        let publisher = Publisher::new(0x11);
        let root = certificate_pem("shared-root");

        let mut first = TrustPackBuilder::new(
            TrustPackKind::CollateralTrust,
            "first",
            1,
            crate::pack::fixture::NOT_BEFORE,
            crate::pack::fixture::NOT_AFTER,
        );
        first
            .insert("payload/roots/gcp-ak-root.pem", root.clone())
            .unwrap();
        let mut second = TrustPackBuilder::new(
            TrustPackKind::CollateralTrust,
            "second",
            1,
            crate::pack::fixture::NOT_BEFORE,
            crate::pack::fixture::NOT_AFTER,
        );
        second
            .insert("payload/roots/gcp-ak-root.pem", root)
            .unwrap();

        let packs = vec![pack(&first, &publisher), pack(&second, &publisher)];
        let error = collateral_trust_inputs_from_all(&packs)
            .expect_err("two packs supplying one root must be refused");
        assert!(
            error.to_string().contains("duplicate claims are fatal"),
            "got {error}"
        );
    }

    /// A bare public key where a certificate belongs is refused rather than
    /// accepted with no expiry — by the producer, which cannot derive an
    /// expiry from it, and independently by the reader, which must not depend
    /// on the producer having checked.
    #[test]
    fn an_azure_maa_entry_that_is_not_a_certificate_is_refused() {
        let publisher = Publisher::new(0x11);
        let not_a_certificate =
            b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n".to_vec();

        let mut builder = collateral_builder("example-publisher");
        builder
            .insert("payload/azure-maa/bare.pem", not_a_certificate.clone())
            .unwrap();
        let error = builder
            .build(|bytes| Ok::<_, std::convert::Infallible>(publisher.sign(bytes)))
            .expect_err("the producer cannot derive an expiry from a bare key");
        assert!(error.to_string().contains("X.509"), "got {error}");

        // The same entry inside an archive a conforming producer would never
        // have emitted.
        let archive = unchecked_archive(
            TrustPackKind::CollateralTrust,
            &publisher,
            &[("payload/azure-maa/bare.pem", not_a_certificate)],
        );
        let read = crate::pack::read::read_trust_pack(
            &archive,
            &crate::pack::fixture::options(TrustPackKind::CollateralTrust, &publisher),
        )
        .expect("the archive is structurally valid");
        let error = collateral_trust_inputs_from_all(&[read])
            .expect_err("a non-certificate MAA entry must be refused on read");
        assert!(error.to_string().contains("X.509"), "got {error}");
    }

    #[test]
    fn aws_document_limits_that_would_reject_everything_are_refused() {
        let publisher = Publisher::new(0x11);
        let mut builder = TrustPackBuilder::new(
            TrustPackKind::CollateralTrust,
            "example-publisher",
            1,
            crate::pack::fixture::NOT_BEFORE,
            crate::pack::fixture::NOT_AFTER,
        );
        builder
            .insert(
                "payload/aws-document-limits.json",
                br#"{"maximum_age_seconds":0,"allowed_future_clock_difference_seconds":60}"#
                    .to_vec(),
            )
            .unwrap();

        let error = collateral_trust_inputs_from_all(&[pack(&builder, &publisher)])
            .expect_err("a zero maximum age must be refused");
        assert!(
            error.to_string().contains("maximum_age_seconds"),
            "got {error}"
        );
    }

    /// Every packed Intel TDX selector is parsed and indexed when the source
    /// is constructed, so a malformed one is a configuration error rather than
    /// a per-quote surprise.
    ///
    /// This replaced a test that called a helper and asserted on its boolean.
    /// That proved the helper matched, not that a verification could reach the
    /// entry or that a corrupt entry stopped a fetch — and a corrupt entry
    /// silently becoming a fetch was the actual defect.
    #[test]
    fn packed_collateral_selectors_are_validated_when_the_source_is_built() {
        use crate::collateral::intel_tdx::IntelTdxDcapCollateralConfig;
        use crate::trust::source::PackTrustSource;
        use atakit_attestation::{IntelTdxPckCa, IntelTdxQuoteCollateralIdentity};

        let publisher = Publisher::new(0x11);
        let build = |entries: Vec<(&str, Vec<u8>)>| {
            let mut builder = collateral_builder("example-publisher");
            for (path, bytes) in entries {
                builder.insert(path, bytes).expect("entry");
            }
            PackTrustSource::new(
                vec![pack(&builder, &publisher)],
                Vec::new(),
                IntelTdxDcapCollateralConfig::default(),
            )
        };

        // The fixture's selector parses to exactly the identity it names.
        let identity = parse_collateral_selector(&tdx_dcap_document())
            .expect("the fixture selector must parse");
        assert_eq!(
            identity,
            IntelTdxQuoteCollateralIdentity {
                fmspc: [0x00, 0x80, 0x6f, 0x05, 0x00, 0x00],
                pce_id: [0x00, 0x00],
                pck_ca: IntelTdxPckCa::Platform,
            }
        );

        assert!(build(vec![("payload/tdx-dcap/a.json", tdx_dcap_document())]).is_ok());

        // A selector that cannot be read stops construction. Previously it was
        // treated as "claims no identity", which a caller could not tell from a
        // genuine miss, and a miss is allowed to fetch.
        for (label, document) in [
            ("no selector", {
                // Built from the valid document so it still carries the payload
                // the writer derives an expiry from; otherwise it would be
                // refused before the selector is ever looked at.
                let mut value: serde_json::Value =
                    serde_json::from_slice(&tdx_dcap_document()).unwrap();
                value.as_object_mut().unwrap().remove("selector");
                serde_json::to_vec(&value).unwrap()
            }),
            (
                "an uppercase fmspc",
                tdx_dcap_document_with_fmspc("00806F050000"),
            ),
            ("a short fmspc", tdx_dcap_document_with_fmspc("00806f05")),
        ] {
            let error = build(vec![("payload/tdx-dcap/bad.json", document)])
                .expect_err(&format!("{label} must stop construction"));
            assert!(
                error.to_string().contains("payload/tdx-dcap/bad.json"),
                "{label}: the failure must name the entry; got {error}"
            );
        }

        // Two entries claiming one identity is fatal, for the reason every
        // other duplicate claim is.
        let error = build(vec![
            ("payload/tdx-dcap/a.json", tdx_dcap_document()),
            ("payload/tdx-dcap/b.json", tdx_dcap_document()),
        ])
        .expect_err("two entries claiming one identity must be refused");
        assert!(
            error.to_string().contains("duplicate claims are fatal"),
            "got {error}"
        );
    }

    /// The converted anchors satisfy the same requirement matrix chain and
    /// explicit modes are measured against, which is what "the same typed
    /// values" has to mean in practice.
    #[test]
    fn converted_anchors_satisfy_the_shared_requirement_matrix() {
        let publisher = Publisher::new(0x11);
        let mut builder = collateral_builder("example-publisher");
        builder
            .insert(
                "payload/roots/aws-nitro-root.pem",
                certificate_pem("aws-nitro"),
            )
            .unwrap();
        builder
            .insert(
                "payload/roots/amd-ark-milan.pem",
                certificate_pem("amd-ark-milan"),
            )
            .unwrap();
        builder
            .insert(
                "payload/amd-snp-security-policy/milan.json",
                amd_snp_policy_document("0x191101"),
            )
            .unwrap();

        let inputs = collateral_trust_inputs_from_all(&[pack(&builder, &publisher)]).unwrap();
        let request = CollateralRequest {
            cloud: "aws".to_string(),
            tee: "sev-snp".to_string(),
            machine_type: "m6a.large".to_string(),
            azure_maa_jwt: None,
            gcp_ak_root: None,
            aws_nitro_root: Some(vec![0x03; 16]),
            amd_snp_cpuid: Some(0x191101),
            amd_ark: Some(vec![0x02; 16]),
        };

        for input in required_trust_inputs_for_request(&request) {
            assert!(
                input.is_satisfied_by(&inputs.trust_anchors, &request),
                "{} must be satisfied by the converted anchors",
                input.name()
            );
        }
        // The matrix asked for something, so the loop above is not vacuous.
        assert!(required_trust_inputs_for_request(&request)
            .contains(&RequiredTrustInput::AmdSnpSecurityPolicy));
    }
}
