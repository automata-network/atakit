//! Which trust inputs a platform requires, as a declarative matrix.

use atakit_attestation::TrustAnchors;

use crate::trust::request::CollateralRequest;

/// A trust input a verification requires for a given platform.
///
/// Which inputs are required is decided by `platform.cloud` and `platform.tee`
/// and is therefore knowable only after the TLS attestation response arrives.
/// Naming them lets a verifier report exactly which input it could not satisfy
/// instead of failing with a generic message, and lets the requirement set be
/// tested without a live target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequiredTrustInput {
    /// GCP vTPM attestation-key root certificate, or its approved hash.
    GcpAkRoot,
    /// Azure MAA signing certificate.
    AzureMaaSigningCertificate,
    /// AMD ARK root certificate, or its approved hash.
    AmdArkRoot,
    /// AMD SEV-SNP security policy for the exact CPUID in the signed report.
    AmdSnpSecurityPolicy,
    /// AWS NitroTPM root certificate, or its approved hash.
    AwsNitroRoot,
    /// AWS attestation-document freshness limits.
    AwsDocumentLimits,
}

impl RequiredTrustInput {
    /// The flag or configuration key that supplies this input explicitly.
    /// Used to name the missing input in a failure.
    pub fn explicit_source(self) -> &'static str {
        match self {
            Self::GcpAkRoot => "--gcp-ak-root-cert",
            Self::AzureMaaSigningCertificate => "--azure-maa-cert",
            Self::AmdArkRoot => "--amd-ark-root-cert",
            Self::AmdSnpSecurityPolicy => "--amd-snp-security-policy",
            Self::AwsNitroRoot => "--aws-nitro-root-cert",
            Self::AwsDocumentLimits => "--aws-document-limits",
        }
    }

    /// Stable name used in failures and in reported provenance.
    pub fn name(self) -> &'static str {
        match self {
            Self::GcpAkRoot => "gcp-ak-root",
            Self::AzureMaaSigningCertificate => "azure-maa-signing-certificate",
            Self::AmdArkRoot => "amd-ark-root",
            Self::AmdSnpSecurityPolicy => "amd-snp-security-policy",
            Self::AwsNitroRoot => "aws-nitro-root",
            Self::AwsDocumentLimits => "aws-document-limits",
        }
    }

    /// Whether the supplied anchors satisfy this input for this exact request.
    ///
    /// This is stricter than the platform-pair form: the AMD SEV-SNP policy
    /// must match the exact family-model-stepping value in the signed report,
    /// which the platform pair cannot see.
    pub fn is_satisfied_by(self, anchors: &TrustAnchors, request: &CollateralRequest) -> bool {
        match self {
            Self::GcpAkRoot => !anchors.gcp_roots.is_empty() || !anchors.gcp_root_hashes.is_empty(),
            Self::AzureMaaSigningCertificate => !anchors.azure_maa_keys.is_empty(),
            Self::AmdArkRoot => {
                !anchors.amd_ark_roots.is_empty() || !anchors.amd_ark_root_hashes.is_empty()
            }
            Self::AmdSnpSecurityPolicy => match request.amd_snp_cpuid {
                Some(cpuid) => anchors
                    .amd_snp_security_policies
                    .iter()
                    .any(|policy| policy.cpuid == cpuid),
                None => !anchors.amd_snp_security_policies.is_empty(),
            },
            Self::AwsNitroRoot => {
                !anchors.aws_nitro_roots.is_empty() || !anchors.aws_nitro_root_hashes.is_empty()
            }
            Self::AwsDocumentLimits => {
                anchors.aws_document_maximum_age_seconds.is_some()
                    && anchors
                        .aws_document_allowed_future_clock_difference_seconds
                        .is_some()
            }
        }
    }
}

/// The trust inputs one specific request requires.
///
/// This is the precise form. It closes both gaps the platform-pair matrix
/// documents: an Azure response is only required to carry a MAA signing
/// certificate when its `akBinding` actually is an Azure MAA token, and the
/// AMD SEV-SNP policy is matched against the exact CPUID in the signed report
/// rather than accepting any policy at all.
pub fn required_trust_inputs_for_request(request: &CollateralRequest) -> Vec<RequiredTrustInput> {
    let mut required = required_trust_inputs(&request.cloud, &request.tee);
    if request.azure_maa_jwt.is_none() {
        required.retain(|input| *input != RequiredTrustInput::AzureMaaSigningCertificate);
    }
    required
}

/// The trust inputs a `(cloud, tee)` pair requires.
///
/// The coarse form, keyed on the platform pair alone. It can be asserted per
/// platform without a live portal, a chain, or a network, which is what makes
/// explicit-mode verification testable.
///
/// # Two requirements this cannot express
///
/// `(cloud, tee)` is not enough to reproduce resolution exactly. Both gaps err
/// toward **over**-requiring, so a caller may be told an input is missing that
/// resolution would not have asked for. Neither can under-require, so neither
/// can cause an input to be silently skipped.
///
/// - **Azure MAA** additionally depends on `akBinding.kind` being
///   `azure-maa-jwt`. An Azure response carrying a different binding kind needs
///   no MAA signing certificate, but is listed here as needing one.
/// - **AMD SEV-SNP security policy** is matched against the exact CPUID in the
///   signed report. That value exists only after decoding the report, so this
///   can say a policy is needed but not which.
///
/// [`required_trust_inputs_for_request`] closes both gaps and is what
/// resolution actually uses.
///
/// An unrecognised pair yields an empty set rather than an error: the caller
/// decides whether an unknown platform is fatal, and every current caller
/// already rejects unsupported platforms earlier.
pub fn required_trust_inputs(cloud: &str, tee: &str) -> Vec<RequiredTrustInput> {
    let is_gcp = cloud.eq_ignore_ascii_case("gcp");
    let is_azure = cloud.eq_ignore_ascii_case("azure");
    let is_aws = cloud.eq_ignore_ascii_case("aws");
    let is_snp = tee.eq_ignore_ascii_case("sev-snp");
    let is_tdx = tee.eq_ignore_ascii_case("tdx");

    if !(is_gcp || is_azure || is_aws) || !(is_snp || is_tdx) {
        return Vec::new();
    }

    let mut required = Vec::new();
    if is_gcp {
        required.push(RequiredTrustInput::GcpAkRoot);
    }
    if is_azure {
        required.push(RequiredTrustInput::AzureMaaSigningCertificate);
    }
    if is_aws {
        required.push(RequiredTrustInput::AwsNitroRoot);
        required.push(RequiredTrustInput::AwsDocumentLimits);
    }
    if is_snp {
        required.push(RequiredTrustInput::AmdArkRoot);
        required.push(RequiredTrustInput::AmdSnpSecurityPolicy);
    }
    required
}

/// Which of `required_trust_inputs` the supplied anchors do not satisfy.
///
/// Intel TDX DCAP collateral is deliberately absent: it is vendor-signed and
/// self-authenticating, resolved per request from a configured source rather
/// than supplied as a trust anchor.
pub fn unsatisfied_trust_inputs(
    cloud: &str,
    tee: &str,
    anchors: &TrustAnchors,
) -> Vec<RequiredTrustInput> {
    required_trust_inputs(cloud, tee)
        .into_iter()
        .filter(|input| match input {
            RequiredTrustInput::GcpAkRoot => {
                anchors.gcp_roots.is_empty() && anchors.gcp_root_hashes.is_empty()
            }
            RequiredTrustInput::AzureMaaSigningCertificate => anchors.azure_maa_keys.is_empty(),
            RequiredTrustInput::AmdArkRoot => {
                anchors.amd_ark_roots.is_empty() && anchors.amd_ark_root_hashes.is_empty()
            }
            RequiredTrustInput::AmdSnpSecurityPolicy => {
                anchors.amd_snp_security_policies.is_empty()
            }
            RequiredTrustInput::AwsNitroRoot => {
                anchors.aws_nitro_roots.is_empty() && anchors.aws_nitro_root_hashes.is_empty()
            }
            RequiredTrustInput::AwsDocumentLimits => {
                anchors.aws_document_maximum_age_seconds.is_none()
                    || anchors
                        .aws_document_allowed_future_clock_difference_seconds
                        .is_none()
            }
        })
        .collect()
}

/// Deterministic per-platform trust-input fixtures.
///
/// These pin the requirement set for every supported `(cloud, tee)` pair
/// without a live portal, a chain, or any network access. They exist to gate
/// the relocation of the verification half of `atakit-cloud`: the captured
/// `atakit cloud verify-session` baseline was taken with `--chain`, so it
/// proves chain-mode behaviour is preserved and says nothing about
/// explicit-mode behaviour, which relocates in the same change.
#[cfg(test)]
mod explicit_trust_fixtures {
    use super::*;
    use atakit_attestation::{AmdSnpSecurityPolicy, AzureMaaTrustCertificate};

    /// Every `(cloud, tee)` pair the resolution matrix distinguishes.
    const SUPPORTED_PLATFORMS: &[(&str, &str)] = &[
        ("gcp", "tdx"),
        ("gcp", "sev-snp"),
        ("azure", "tdx"),
        ("azure", "sev-snp"),
        ("aws", "sev-snp"),
    ];

    fn maa_certificate() -> AzureMaaTrustCertificate {
        AzureMaaTrustCertificate {
            public_key: vec![0xaa; 32],
            not_after: u64::MAX,
        }
    }

    fn snp_security_policy(cpuid: u32) -> AmdSnpSecurityPolicy {
        AmdSnpSecurityPolicy {
            cpuid,
            minimum_tcb: [0u8; 32],
            platform_info_policy: [0u8; 32],
            required_launch_mitigation_vector: 0,
            required_current_mitigation_vector: 0,
        }
    }

    /// Anchors satisfying exactly the requirement set for one platform, and
    /// nothing more. Building from the matrix rather than by hand keeps the
    /// fixture honest: it cannot drift from what the code requires.
    fn complete_anchors(cloud: &str, tee: &str) -> TrustAnchors {
        let mut anchors = TrustAnchors::default();
        for input in required_trust_inputs(cloud, tee) {
            match input {
                RequiredTrustInput::GcpAkRoot => anchors.gcp_roots.push(vec![0x01; 16]),
                RequiredTrustInput::AzureMaaSigningCertificate => {
                    anchors.azure_maa_keys.push(maa_certificate())
                }
                RequiredTrustInput::AmdArkRoot => anchors.amd_ark_roots.push(vec![0x02; 16]),
                RequiredTrustInput::AmdSnpSecurityPolicy => anchors
                    .amd_snp_security_policies
                    .push(snp_security_policy(1)),
                RequiredTrustInput::AwsNitroRoot => anchors.aws_nitro_roots.push(vec![0x03; 16]),
                RequiredTrustInput::AwsDocumentLimits => {
                    anchors.aws_document_maximum_age_seconds = Some(300);
                    anchors.aws_document_allowed_future_clock_difference_seconds = Some(60);
                }
            }
        }
        anchors
    }

    /// The requirement set per platform, pinned exactly. A change to the
    /// matrix must update this table deliberately rather than silently.
    #[test]
    fn requirement_set_is_pinned_for_every_supported_platform() {
        use RequiredTrustInput::*;

        let expected: &[(&str, &str, &[RequiredTrustInput])] = &[
            ("gcp", "tdx", &[GcpAkRoot]),
            (
                "gcp",
                "sev-snp",
                &[GcpAkRoot, AmdArkRoot, AmdSnpSecurityPolicy],
            ),
            ("azure", "tdx", &[AzureMaaSigningCertificate]),
            (
                "azure",
                "sev-snp",
                &[AzureMaaSigningCertificate, AmdArkRoot, AmdSnpSecurityPolicy],
            ),
            (
                "aws",
                "sev-snp",
                &[
                    AwsNitroRoot,
                    AwsDocumentLimits,
                    AmdArkRoot,
                    AmdSnpSecurityPolicy,
                ],
            ),
        ];

        for (cloud, tee, want) in expected {
            assert_eq!(
                required_trust_inputs(cloud, tee),
                want.to_vec(),
                "requirement set changed for {cloud}/{tee}"
            );
        }
        assert_eq!(
            expected.len(),
            SUPPORTED_PLATFORMS.len(),
            "a supported platform is missing from the pinned table"
        );
    }

    /// Explicit mode resolves every required input from the supplied anchors.
    /// Nothing is left for a chain to fill.
    #[test]
    fn complete_explicit_anchors_satisfy_every_platform() {
        for (cloud, tee) in SUPPORTED_PLATFORMS {
            let anchors = complete_anchors(cloud, tee);
            assert!(
                unsatisfied_trust_inputs(cloud, tee, &anchors).is_empty(),
                "{cloud}/{tee}: complete explicit anchors left an input unsatisfied"
            );
        }
    }

    /// Withholding any single required input fails closed and names exactly
    /// that input. A generic "no trusted collateral available" is a failure of
    /// this test: the operator must be told which artifact to supply.
    #[test]
    fn withholding_any_required_input_names_exactly_that_input() {
        for (cloud, tee) in SUPPORTED_PLATFORMS {
            for withheld in required_trust_inputs(cloud, tee) {
                let mut anchors = complete_anchors(cloud, tee);
                match withheld {
                    RequiredTrustInput::GcpAkRoot => {
                        anchors.gcp_roots.clear();
                        anchors.gcp_root_hashes.clear();
                    }
                    RequiredTrustInput::AzureMaaSigningCertificate => {
                        anchors.azure_maa_keys.clear()
                    }
                    RequiredTrustInput::AmdArkRoot => {
                        anchors.amd_ark_roots.clear();
                        anchors.amd_ark_root_hashes.clear();
                    }
                    RequiredTrustInput::AmdSnpSecurityPolicy => {
                        anchors.amd_snp_security_policies.clear()
                    }
                    RequiredTrustInput::AwsNitroRoot => {
                        anchors.aws_nitro_roots.clear();
                        anchors.aws_nitro_root_hashes.clear();
                    }
                    RequiredTrustInput::AwsDocumentLimits => {
                        anchors.aws_document_maximum_age_seconds = None;
                        anchors.aws_document_allowed_future_clock_difference_seconds = None;
                    }
                }

                assert_eq!(
                    unsatisfied_trust_inputs(cloud, tee, &anchors),
                    vec![withheld],
                    "{cloud}/{tee}: withholding {withheld:?} must name exactly that input"
                );
            }
        }
    }

    /// A hash-only anchor satisfies the requirement. The chain path stores
    /// approved hashes rather than certificates, and an explicit verifier that
    /// pinned a hash must not be told the input is missing.
    #[test]
    fn approved_hashes_satisfy_root_requirements() {
        let mut anchors = TrustAnchors::default();
        anchors.gcp_root_hashes.push([0x11; 32]);
        assert!(unsatisfied_trust_inputs("gcp", "tdx", &anchors).is_empty());

        let mut anchors = TrustAnchors::default();
        anchors.aws_nitro_root_hashes.push([0x22; 32]);
        anchors.amd_ark_root_hashes.push([0x33; 32]);
        anchors
            .amd_snp_security_policies
            .push(snp_security_policy(1));
        anchors.aws_document_maximum_age_seconds = Some(300);
        anchors.aws_document_allowed_future_clock_difference_seconds = Some(60);
        assert!(unsatisfied_trust_inputs("aws", "sev-snp", &anchors).is_empty());
    }

    /// Both AWS freshness limits are one input. Supplying only one leaves it
    /// unsatisfied, because a half-configured freshness window silently
    /// widens what a verifier accepts.
    #[test]
    fn partial_aws_document_limits_do_not_satisfy_the_input() {
        let mut anchors = complete_anchors("aws", "sev-snp");
        anchors.aws_document_allowed_future_clock_difference_seconds = None;
        assert_eq!(
            unsatisfied_trust_inputs("aws", "sev-snp", &anchors),
            vec![RequiredTrustInput::AwsDocumentLimits]
        );
    }

    /// An unrecognised platform requires nothing here; rejecting it is the
    /// caller's job and happens earlier. Pinned so that adding a platform to
    /// the matrix without adding it to the fixtures is visible.
    #[test]
    fn unsupported_platforms_require_nothing() {
        for (cloud, tee) in [("qemu", "tdx"), ("gcp", "sgx"), ("", "")] {
            assert!(required_trust_inputs(cloud, tee).is_empty());
        }
    }

    /// The platform-pair matrix is deliberately coarser than the request form:
    /// it requires a MAA certificate for every Azure response, because it
    /// cannot see the binding kind. Over-requiring, never under-requiring.
    /// `required_trust_inputs_for_request` is the precise form and is what
    /// resolution uses; this pins the difference so the coarse form is not
    /// mistaken for it.
    #[test]
    fn azure_requirement_is_coarser_than_the_request_form() {
        assert!(required_trust_inputs("azure", "tdx")
            .contains(&RequiredTrustInput::AzureMaaSigningCertificate));
    }

    /// The coarse form cannot decode the signed report, so any AMD SEV-SNP
    /// policy satisfies it. Resolution matches the exact CPUID through
    /// `RequiredTrustInput::is_satisfied_by`, which
    /// `a_policy_for_another_cpuid_does_not_satisfy_the_requirement` covers.
    #[test]
    fn the_coarse_snp_policy_requirement_ignores_cpuid() {
        let mut anchors = complete_anchors("aws", "sev-snp");
        anchors.amd_snp_security_policies = vec![snp_security_policy(0xdead_beef)];
        assert!(
            unsatisfied_trust_inputs("aws", "sev-snp", &anchors).is_empty(),
            "a wrong-CPUID policy satisfies the coarse matrix; the request \
             form is what rejects it"
        );
    }
}
