//! Intel TDX DCAP collateral: `File`, `HttpPccs`, or `AutomataOnchainPccs`
//! resolved into an `IntelTdxDcapCollateral` for the presented quote.

mod pccs;

use std::path::PathBuf;
use std::time::Duration;

use atakit_attestation::{IntelTdxDcapCollateral, TlsAttestationResponse};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::PortalVerificationError;
use pccs::{
    fetch_automata_collateral, fetch_http_collateral, parse_dcap_collateral_json,
    AutomataPccsOverrides,
};

const DEFAULT_TDX_DCAP_AUTOMATA_CHAIN: &str = "hoodi";
const DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL: &str = "https://ethereum-hoodi-rpc.publicnode.com";

/// Verifier-side source for Intel TDX DCAP collateral.
#[derive(Debug, Clone, Default)]
pub struct IntelTdxDcapCollateralConfig {
    pub source: IntelTdxDcapCollateralSource,
}

#[derive(Debug, Clone, Default)]
pub enum IntelTdxDcapCollateralSource {
    /// Do not resolve collateral before verification. Intel TDX verification
    /// then fails closed. This is retained for internal callers; the CLI
    /// defaults to Automata on-chain PCCS.
    #[default]
    None,
    /// Load an `atakit.intel-tdx-dcap-collateral` version 1 JSON document
    /// from disk.
    File(PathBuf),
    /// Fetch Intel TDX DCAP collateral from a direct HTTP PCCS/PCS endpoint.
    HttpPccs { url: String },
    /// Read collateral through Automata's on-chain PCCS contracts.
    ///
    /// This is intentionally modeled separately from HTTP PCCS: the access
    /// path is chain RPC plus contract calls, not the PCS/PCCS HTTP API.
    AutomataOnchainPccs {
        chain: Option<String>,
        rpc_url: Option<String>,
        pcs_dao: Option<String>,
        pck_dao: Option<String>,
        fmspc_tcb_dao: Option<String>,
        enclave_identity_dao: Option<String>,
        read_strategy: TdxDcapAutomataReadStrategy,
    },
}

/// Selects how Automata on-chain PCCS contract reads are grouped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TdxDcapAutomataReadStrategy {
    /// Send independent `eth_call` requests concurrently.
    #[default]
    DirectConcurrent,
    /// Send the group through Multicall3.
    ///
    /// `None` uses Alloy's standard Multicall3 address. A failed batch falls
    /// back to direct concurrent calls in `pccs-reader-rs`.
    Multicall3 { address: Option<String> },
}

/// Build a verifier-side TDX DCAP collateral config from CLI-style options.
pub fn tdx_dcap_collateral_config(
    collateral_file: Option<PathBuf>,
    pccs_url: Option<String>,
    automata_collateral_rpc_url: Option<String>,
    automata_pcs_dao: Option<String>,
) -> Result<IntelTdxDcapCollateralConfig, PortalVerificationError> {
    tdx_dcap_collateral_config_with_read_strategy(
        collateral_file,
        pccs_url,
        automata_collateral_rpc_url,
        automata_pcs_dao,
        TdxDcapAutomataReadStrategy::DirectConcurrent,
    )
}

/// Build a verifier-side TDX DCAP collateral config with an explicit Automata
/// on-chain read strategy.
pub fn tdx_dcap_collateral_config_with_read_strategy(
    collateral_file: Option<PathBuf>,
    pccs_url: Option<String>,
    automata_collateral_rpc_url: Option<String>,
    automata_pcs_dao: Option<String>,
    automata_read_strategy: TdxDcapAutomataReadStrategy,
) -> Result<IntelTdxDcapCollateralConfig, PortalVerificationError> {
    let non_default_automata_strategy =
        automata_read_strategy != TdxDcapAutomataReadStrategy::DirectConcurrent;
    let selected = usize::from(collateral_file.is_some())
        + usize::from(pccs_url.is_some())
        + usize::from(
            automata_collateral_rpc_url.is_some()
                || automata_pcs_dao.is_some()
                || non_default_automata_strategy,
        );
    if selected > 1 {
        return Err(PortalVerificationError::Config {
            message: "choose only one TDX DCAP collateral source: --tdx-dcap-collateral, --tdx-dcap-pccs-url, or --tdx-dcap-automata-*".to_string(),
        });
    }
    let source = if let Some(path) = collateral_file {
        IntelTdxDcapCollateralSource::File(path)
    } else if let Some(url) = pccs_url {
        IntelTdxDcapCollateralSource::HttpPccs { url }
    } else if automata_collateral_rpc_url.is_some() || automata_pcs_dao.is_some() {
        IntelTdxDcapCollateralSource::AutomataOnchainPccs {
            chain: Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN.to_string()),
            rpc_url: automata_collateral_rpc_url,
            pcs_dao: automata_pcs_dao,
            pck_dao: None,
            fmspc_tcb_dao: None,
            enclave_identity_dao: None,
            read_strategy: automata_read_strategy,
        }
    } else {
        IntelTdxDcapCollateralSource::AutomataOnchainPccs {
            chain: Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN.to_string()),
            rpc_url: Some(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL.to_string()),
            pcs_dao: None,
            pck_dao: None,
            fmspc_tcb_dao: None,
            enclave_identity_dao: None,
            read_strategy: automata_read_strategy,
        }
    };
    Ok(IntelTdxDcapCollateralConfig { source })
}

/// Parse the CLI values for the Automata on-chain read strategy.
pub fn tdx_dcap_automata_read_strategy(
    strategy: &str,
    multicall3_address: Option<String>,
) -> Result<TdxDcapAutomataReadStrategy, PortalVerificationError> {
    match strategy {
        "direct-concurrent" if multicall3_address.is_none() => {
            Ok(TdxDcapAutomataReadStrategy::DirectConcurrent)
        }
        "direct-concurrent" => Err(PortalVerificationError::Config {
            message:
                "--tdx-dcap-automata-multicall3-address requires --tdx-dcap-automata-read-strategy multicall3"
                    .to_string(),
        }),
        "multicall3" => Ok(TdxDcapAutomataReadStrategy::Multicall3 {
            address: multicall3_address,
        }),
        value => Err(PortalVerificationError::Config {
            message: format!(
                "invalid --tdx-dcap-automata-read-strategy {value}; expected direct-concurrent or multicall3"
            ),
        }),
    }
}

/// The quote Intel TDX DCAP collateral is selected for, or `None` when the
/// response is not Intel TDX.
///
/// Shared so packed collateral is selected for exactly the quote the
/// configured-source path would have used. Two ways of deciding which bytes the
/// quote is would be two ways of selecting the wrong collateral.
pub(crate) fn tdx_collateral_quote(
    response: &TlsAttestationResponse,
) -> Result<Option<Vec<u8>>, String> {
    if !is_tdx(response) {
        return Ok(None);
    }
    let evidence = response
        .tee_evidence
        .as_ref()
        .ok_or_else(|| "TDX response is missing teeEvidence".to_string())?;
    URL_SAFE_NO_PAD
        .decode(&evidence.report)
        .map(Some)
        .map_err(|e| format!("decode teeEvidence.report for DCAP collateral lookup: {e}"))
}

pub(crate) async fn resolve_tdx_dcap_collateral_for_quote(
    quote: &[u8],
    config: &IntelTdxDcapCollateralConfig,
) -> Result<IntelTdxDcapCollateral, String> {
    let collateral = match &config.source {
        IntelTdxDcapCollateralSource::None => {
            return Err("no Intel TDX DCAP collateral source is configured".to_string())
        }
        IntelTdxDcapCollateralSource::File(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("read TDX DCAP collateral file {}: {e}", path.display()))?;
            parse_dcap_collateral_json(&raw, quote).map_err(|error| {
                format!("parse TDX DCAP collateral file {}: {error}", path.display())
            })?
        }
        IntelTdxDcapCollateralSource::HttpPccs { url } => {
            fetch_http_collateral(url, quote)
                .await
                .map_err(|e| format!("fetch TDX DCAP collateral from {url}: {e}"))?
        }
        IntelTdxDcapCollateralSource::AutomataOnchainPccs {
            chain,
            rpc_url,
            pcs_dao,
            pck_dao,
            fmspc_tcb_dao,
            enclave_identity_dao,
            read_strategy,
        } => {
            let chain = chain.as_deref().unwrap_or(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN);
            let rpc_url = rpc_url
                .as_deref()
                .unwrap_or(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL);
            tokio::time::timeout(
                Duration::from_secs(180),
                fetch_automata_collateral(
                    rpc_url,
                    chain,
                    AutomataPccsOverrides {
                        pcs_dao: pcs_dao.as_deref(),
                        pck_dao: pck_dao.as_deref(),
                        fmspc_tcb_dao: fmspc_tcb_dao.as_deref(),
                        enclave_identity_dao: enclave_identity_dao.as_deref(),
                    },
                    read_strategy,
                    quote,
                ),
            )
            .await
            .map_err(|_| {
                format!(
                    "fetch TDX DCAP collateral from Automata {chain}: timed out after 180 seconds"
                )
            })?
            .map_err(|e| format!("fetch TDX DCAP collateral from Automata {chain}: {e}"))?
        }
    };
    Ok(collateral)
}

fn is_tdx(response: &TlsAttestationResponse) -> bool {
    response.platform.tee.eq_ignore_ascii_case("tdx")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automata_pccs_default_config_defers_versioned_daos_to_tcb_eval() {
        let cfg = tdx_dcap_collateral_config(None, None, None, None).expect("collateral config");
        match cfg.source {
            IntelTdxDcapCollateralSource::AutomataOnchainPccs {
                chain,
                rpc_url,
                pcs_dao,
                pck_dao,
                fmspc_tcb_dao,
                enclave_identity_dao,
                read_strategy,
            } => {
                assert_eq!(chain.as_deref(), Some(DEFAULT_TDX_DCAP_AUTOMATA_CHAIN));
                assert_eq!(rpc_url.as_deref(), Some(DEFAULT_TDX_DCAP_AUTOMATA_RPC_URL));
                assert!(pcs_dao.is_none());
                assert!(pck_dao.is_none());
                assert!(fmspc_tcb_dao.is_none());
                assert!(enclave_identity_dao.is_none());
                assert_eq!(read_strategy, TdxDcapAutomataReadStrategy::DirectConcurrent);
            }
            other => panic!("expected Automata on-chain PCCS, got {other:?}"),
        }
    }

    #[test]
    fn automata_pccs_multicall3_strategy_preserves_an_address_override() {
        let strategy = tdx_dcap_automata_read_strategy(
            "multicall3",
            Some("0x1111111111111111111111111111111111111111".to_string()),
        )
        .expect("read strategy");
        assert_eq!(
            strategy,
            TdxDcapAutomataReadStrategy::Multicall3 {
                address: Some("0x1111111111111111111111111111111111111111".to_string())
            }
        );
    }

    #[test]
    fn automata_pccs_rejects_multicall3_address_with_direct_reads() {
        let error = tdx_dcap_automata_read_strategy(
            "direct-concurrent",
            Some("0x1111111111111111111111111111111111111111".to_string()),
        )
        .expect_err("address requires multicall3");
        assert!(error.to_string().contains("requires"));
    }
}
