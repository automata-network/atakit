//! Portal TLS attestation collection: fetch `/tls-attestation`, resolve the
//! trust inputs the presented platform requires, verify, and return a client
//! pinned to the attested certificate.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use atakit_attestation::{
    verify_tls_attestation, verify_tls_attestation_with_workload_attributes, CheckResult,
    EvidenceSummary, MeasurementPolicy, TlsAttestationResponse, VerificationCheck,
    VerificationInputs, VerificationReport, VerifiedTlsIdentity,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::collateral::amd_snp::resolve_amd_snp_collateral;
use crate::collateral::intel_tdx::{
    resolve_tdx_dcap_collateral, tdx_collateral_quote, IntelTdxDcapCollateralConfig,
    IntelTdxDcapCollateralSource,
};
use crate::error::PortalVerificationError;
use crate::http::read_response_bytes_limited;
use crate::portal::session::{
    PortalSessionVerificationContext, TlsManualOverride, VerifiedPortalTls,
};
use crate::trust::builder::TrustAnchorsBuilder;
use crate::trust::measurement::write_tls_attestation_report;
use crate::trust::request::CollateralRequest;
use crate::trust::source::TrustSource;

const MAX_TLS_ATTESTATION_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PORTAL_ERROR_RESPONSE_BYTES: usize = 64 * 1024;

/// Fetch and verify the portal's TLS attestation, resolving every trust input
/// from one selected source, then return a client pinned to the attested
/// self-signed certificate.
// Keep the request inputs explicit at this protocol boundary.
#[allow(clippy::too_many_arguments)]
/// Resolve Intel TDX DCAP collateral for the selected trust source.
///
/// In trust-pack mode the configured packs are consulted first, and only a
/// genuine miss reaches the configured off-chain source. Vendor collateral is
/// self-authenticating, so fetching what a pack does not contain is an
/// availability choice rather than a trust one — but an entry that is present
/// and unusable fails the verification, because fetching past a broken pinned
/// entry would make pinning advisory.
///
/// Every other mode resolves exactly as before.
async fn resolve_tdx_dcap_for_source(
    response: &TlsAttestationResponse,
    trust_source: &TrustSource,
    config: &IntelTdxDcapCollateralConfig,
) -> Result<Option<atakit_attestation::IntelTdxDcapCollateral>, String> {
    if let TrustSource::Packs(packs) = trust_source {
        if let Some(quote) = tdx_collateral_quote(response)? {
            match packs.select_tdx_dcap_collateral(&quote) {
                Ok(Some(collateral)) => return Ok(Some(collateral)),
                Err(error) => return Err(error.to_string()),
                Ok(None) => {
                    if matches!(config.source, IntelTdxDcapCollateralSource::None) {
                        return Err(format!(
                            "the configured trust packs carry no Intel TDX DCAP collateral for \
                             this quote{}, and no off-chain source is configured to fetch it \
                             from",
                            if packs.carries_tdx_dcap_collateral() {
                                " — they carry collateral for other hardware, so this peer's \
                                 platform is not covered"
                            } else {
                                ""
                            }
                        ));
                    }
                }
            }
        }
    }
    resolve_tdx_dcap_collateral(response, config).await
}

pub async fn bootstrap_portal_tls(
    host: &str,
    status_port: u16,
    measurement_policy: Option<MeasurementPolicy>,
    workload_attributes: Option<atakit_core::tee_attributes::AttributeRequirements>,
    trust_source: &TrustSource,
    trust_tls_cert_sha256: Option<&str>,
    report_path: Option<&Path>,
) -> Result<VerifiedPortalTls, PortalVerificationError> {
    let amd_snp_crls = match trust_source {
        TrustSource::Explicit(source) => source.amd_snp_crls().to_vec(),
        TrustSource::Packs(source) => source.amd_snp_crls().to_vec(),
        TrustSource::Chain(_) => Vec::new(),
    };
    let tdx_dcap_collateral = trust_source.tdx_dcap_collateral().clone();
    let nonce = random_nonce()?;
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
    let url = format!("https://{host}:{status_port}/tls-attestation?nonce={nonce_b64}");
    let bootstrap = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| PortalVerificationError::Http {
            message: e.to_string(),
        })?;

    let resp = bootstrap.get(&url).send().await.map_err(|e| {
        PortalVerificationError::PortalTlsAttestationFailed {
            message: format!("request failed: {e}"),
        }
    })?;
    let live_peer_cert_der = peer_cert_der(&resp)?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = read_response_bytes_limited(
            resp,
            MAX_PORTAL_ERROR_RESPONSE_BYTES,
            "portal TLS attestation error response",
        )
        .await
        .map(|body| String::from_utf8_lossy(&body).into_owned())
        .unwrap_or_else(|error| format!("<could not read response body: {error}>"));
        let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
        let live_hash = format!("0x{}", hex::encode(live_sha));
        let report = endpoint_failure_report(status.as_u16(), &body, &live_hash);
        let written_report_path = if let Some(path) = report_path {
            write_tls_attestation_report(&report, path)?;
            Some(path.to_path_buf())
        } else {
            None
        };
        if trust_tls_cert_sha256 == Some(live_hash.as_str()) {
            let client = pinned_client(&live_peer_cert_der, Duration::from_secs(300))?;
            return Ok(VerifiedPortalTls {
                client,
                identity: VerifiedTlsIdentity {
                    cert_der: live_peer_cert_der,
                    cert_sha256: live_sha,
                    base_image_id: None,
                    platform_profile_id: None,
                    variant_id: None,
                },
                trust_provenance: Default::default(),
                manual_override: Some(TlsManualOverride {
                    live_cert_sha256: live_hash,
                    report,
                    report_path: written_report_path,
                }),
                session_verification: None,
            });
        }
        let report_location = written_report_path
            .as_ref()
            .map(|path| format!("\nfailure report: {}", path.display()))
            .unwrap_or_default();
        return Err(PortalVerificationError::PortalTlsAttestationFailed {
            message: format!(
                "portal returned {status}: {body}{report_location}\nmanual override after inspection: --trust-tls-cert-sha256 {live_hash}"
            ),
        });
    }

    let response_body = read_response_bytes_limited(
        resp,
        MAX_TLS_ATTESTATION_RESPONSE_BYTES,
        "portal TLS attestation response",
    )
    .await
    .map_err(|message| PortalVerificationError::PortalTlsAttestationFailed { message })?;
    let response =
        serde_json::from_slice::<TlsAttestationResponse>(&response_body).map_err(|e| {
            PortalVerificationError::PortalTlsAttestationFailed {
                message: format!("invalid response JSON: {e}"),
            }
        })?;
    let intel_tdx_dcap_collateral =
        match resolve_tdx_dcap_for_source(&response, trust_source, &tdx_dcap_collateral).await {
            Ok(collateral) => collateral,
            Err(detail) => {
                let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
                let live_hash = format!("0x{}", hex::encode(live_sha));
                let report = tls_preverification_failure_report(
                    &response,
                    &live_hash,
                    "tdx-dcap-collateral",
                    detail,
                );
                return handle_tls_attestation_failure(
                    report,
                    live_peer_cert_der,
                    trust_tls_cert_sha256,
                    report_path,
                );
            }
        };

    let amd_snp_collateral = match resolve_amd_snp_collateral(&response, amd_snp_crls).await {
        Ok(collateral) => collateral,
        Err(detail) => {
            let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
            let live_hash = format!("0x{}", hex::encode(live_sha));
            let report = tls_preverification_failure_report(
                &response,
                &live_hash,
                "amd-snp-collateral",
                detail,
            );
            return handle_tls_attestation_failure(
                report,
                live_peer_cert_der,
                trust_tls_cert_sha256,
                report_path,
            );
        }
    };

    let request = match CollateralRequest::from_response(&response, amd_snp_collateral.as_ref()) {
        Ok(request) => request,
        Err(detail) => {
            let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
            let live_hash = format!("0x{}", hex::encode(live_sha));
            let report = tls_preverification_failure_report(
                &response,
                &live_hash,
                "collateral-request",
                detail,
            );
            return handle_tls_attestation_failure(
                report,
                live_peer_cert_der,
                trust_tls_cert_sha256,
                report_path,
            );
        }
    };

    // One source resolves everything. A required input the source cannot
    // supply fails closed naming the input; it never falls through.
    let builder = TrustAnchorsBuilder::new(trust_source.clone());
    let (trust_anchors, trust_provenance) = match builder.resolve(&request).await {
        Ok(resolved) => resolved,
        Err(error) => {
            let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
            let live_hash = format!("0x{}", hex::encode(live_sha));
            let report = tls_preverification_failure_report(
                &response,
                &live_hash,
                "trust-anchors",
                error.to_string(),
            );
            return handle_tls_attestation_failure(
                report,
                live_peer_cert_der,
                trust_tls_cert_sha256,
                report_path,
            );
        }
    };
    let manual_azure_maa_keys = trust_anchors.azure_maa_keys.clone();

    // Only chain mode has a chain client to bind a session to. Trust-pack and
    // explicit modes have none by construction, which is what stops a session
    // binding being taken from one authority while policy comes from another.
    let session_chain_client = match trust_source {
        TrustSource::Chain(source) => Some(source.client().clone()),
        TrustSource::Explicit(_) | TrustSource::Packs(_) => None,
    };
    let session_verification =
        measurement_policy
            .clone()
            .map(|measurement_policy| PortalSessionVerificationContext {
                platform: response.platform.clone(),
                measurement_policy,
                trust_anchors: trust_anchors.clone(),
                chain_client: session_chain_client.clone(),
                manual_azure_maa_keys: manual_azure_maa_keys.clone(),
                amd_snp_collateral: amd_snp_collateral.clone(),
                intel_tdx_dcap_collateral: intel_tdx_dcap_collateral.clone(),
            });
    let verification_inputs = VerificationInputs {
        nonce,
        live_peer_cert_der: live_peer_cert_der.clone(),
        response,
        intel_tdx_dcap_collateral,
        amd_snp_collateral,
        measurement_policy,
        trust_anchors,
    };
    let verification = match workload_attributes.as_ref() {
        Some(attributes) => {
            verify_tls_attestation_with_workload_attributes(verification_inputs, attributes)
        }
        None => verify_tls_attestation(verification_inputs),
    };
    match verification {
        Ok(identity) => {
            let client = pinned_client(&identity.cert_der, Duration::from_secs(300))?;
            Ok(VerifiedPortalTls {
                client,
                identity,
                manual_override: None,
                session_verification,
                trust_provenance,
            })
        }
        Err(failure) => handle_tls_attestation_failure(
            *failure.report,
            live_peer_cert_der,
            trust_tls_cert_sha256,
            report_path,
        ),
    }
}

fn tls_preverification_failure_report(
    response: &TlsAttestationResponse,
    live_hash: &str,
    check_name: &str,
    detail: String,
) -> VerificationReport {
    VerificationReport {
        checks: vec![VerificationCheck {
            name: check_name.to_string(),
            result: CheckResult::Fail,
            detail: Some(detail),
        }],
        evidence: EvidenceSummary {
            tls_cert_der: Some(response.tls_cert_der.clone()),
            live_tls_cert_sha256: Some(live_hash.to_string()),
            response_tls_cert_sha256: Some(response.tls_cert_sha256.clone()),
            nonce: Some(response.nonce.clone()),
            qualifying_data: Some(response.qualifying_data.clone()),
            cloud: Some(response.platform.cloud.clone()),
            tee: Some(response.platform.tee.clone()),
            machine_type: Some(response.platform.machine_type.clone()),
            tpm_ak_public: Some(response.tpm.ak_public.clone()),
            tpm_quote: Some(response.tpm.quote.clone()),
            tpm_signature: Some(response.tpm.signature.clone()),
            pcrs: response.tpm.pcrs.clone(),
            event_log_hashes: response.tpm.event_log_hashes.clone(),
            tee_evidence_kind: response
                .tee_evidence
                .as_ref()
                .map(|evidence| evidence.kind.clone()),
            tee_evidence_report: response
                .tee_evidence
                .as_ref()
                .map(|evidence| evidence.report.clone()),
            tee_evidence_auxiliary: response
                .tee_evidence
                .as_ref()
                .and_then(|evidence| evidence.auxiliary.clone()),
            ak_binding_kind: response
                .ak_binding
                .as_ref()
                .map(|binding| binding.kind.clone()),
            ak_binding_data: response
                .ak_binding
                .as_ref()
                .map(|binding| binding.data.clone()),
            collateral: response.collateral.clone(),
            ..EvidenceSummary::default()
        },
    }
}

fn handle_tls_attestation_failure(
    report: VerificationReport,
    live_peer_cert_der: Vec<u8>,
    trust_tls_cert_sha256: Option<&str>,
    report_path: Option<&Path>,
) -> Result<VerifiedPortalTls, PortalVerificationError> {
    let written_report_path = if let Some(path) = report_path {
        write_tls_attestation_report(&report, path)?;
        Some(path.to_path_buf())
    } else {
        None
    };
    let live_sha: [u8; 32] = Sha256::digest(&live_peer_cert_der).into();
    let live_hash = format!("0x{}", hex::encode(live_sha));
    if trust_tls_cert_sha256 == Some(live_hash.as_str()) {
        let client = pinned_client(&live_peer_cert_der, Duration::from_secs(300))?;
        return Ok(VerifiedPortalTls {
            client,
            identity: VerifiedTlsIdentity {
                cert_der: live_peer_cert_der,
                cert_sha256: live_sha,
                base_image_id: None,
                platform_profile_id: None,
                variant_id: None,
            },
            trust_provenance: Default::default(),
            manual_override: Some(TlsManualOverride {
                live_cert_sha256: live_hash,
                report,
                report_path: written_report_path,
            }),
            session_verification: None,
        });
    }
    let report_json = serde_json::to_string_pretty(&report)
        .unwrap_or_else(|_| "<failed to render report>".to_string());
    let report_location = written_report_path
        .as_ref()
        .map(|path| format!("\nfailure report: {}", path.display()))
        .unwrap_or_default();
    Err(PortalVerificationError::PortalTlsAttestationFailed {
        message: format!(
            "{report_json}{report_location}\nmanual override after inspection: --trust-tls-cert-sha256 {live_hash}"
        ),
    })
}

fn peer_cert_der(resp: &reqwest::Response) -> Result<Vec<u8>, PortalVerificationError> {
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .map(|der| der.to_vec())
        .ok_or_else(|| PortalVerificationError::PortalTlsAttestationFailed {
            message: "bootstrap connection did not expose a peer certificate".to_string(),
        })
}

fn endpoint_failure_report(status: u16, body: &str, live_hash: &str) -> VerificationReport {
    VerificationReport {
        checks: vec![atakit_attestation::VerificationCheck {
            name: "tls-attestation-endpoint".to_string(),
            result: atakit_attestation::CheckResult::Fail,
            detail: Some(format!("portal returned HTTP {status}: {body}")),
        }],
        evidence: atakit_attestation::EvidenceSummary {
            live_tls_cert_sha256: Some(live_hash.to_string()),
            ..atakit_attestation::EvidenceSummary::default()
        },
    }
}

pub fn tls_manual_override_message(verified: &VerifiedPortalTls) -> Option<String> {
    let override_info = verified.manual_override.as_ref()?;
    let report_json = serde_json::to_string_pretty(&override_info.report)
        .unwrap_or_else(|_| "<failed to render report>".to_string());
    Some(format!(
        "TLS attestation failed, but manual override accepted for live certificate {}.{}\n{}",
        override_info.live_cert_sha256,
        override_info
            .report_path
            .as_ref()
            .map(|path| format!("\nFailure report: {}", path.display()))
            .unwrap_or_default(),
        report_json
    ))
}

fn pinned_client(
    cert_der: &[u8],
    timeout: Duration,
) -> Result<reqwest::Client, PortalVerificationError> {
    let cert = reqwest::Certificate::from_der(cert_der).map_err(|e| {
        PortalVerificationError::PortalTlsAttestationFailed {
            message: format!("invalid attested TLS certificate: {e}"),
        }
    })?;
    reqwest::Client::builder()
        .add_root_certificate(cert)
        // Portal certs are issued for `atakit-portal`, while clients usually
        // connect by cloud IP. Cert validity is pinned by the attestation hash;
        // only hostname verification is relaxed here.
        .danger_accept_invalid_hostnames(true)
        .timeout(timeout)
        .build()
        .map_err(|e| PortalVerificationError::Http {
            message: e.to_string(),
        })
}

fn random_nonce() -> Result<[u8; 32], PortalVerificationError> {
    let mut nonce = [0u8; 32];
    let mut file =
        std::fs::File::open("/dev/urandom").map_err(|e| PortalVerificationError::IoPath {
            path: "/dev/urandom".into(),
            source: e,
        })?;
    file.read_exact(&mut nonce)
        .map_err(|e| PortalVerificationError::IoPath {
            path: "/dev/urandom".into(),
            source: e,
        })?;
    Ok(nonce)
}
