use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use atakit_attestation::TdxDcapCollateral;
use automata_dcap_network_registry::Network;
use dcap_rs::types::quote::Quote;
use futures_util::StreamExt;
use pccs_reader_rs::tcb_pem::generate_tcb_issuer_chain_pem;
use pccs_reader_rs::{Collaterals, PccsReadStrategy, PccsReader};
use serde_json::value::RawValue;
use x509_cert::der::Encode;

use crate::init::TdxDcapAutomataReadStrategy;

const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";
const INTEL_ROOT_CA_CRL_URL: &str =
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";
const MAX_DCAP_COLLATERAL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TDX_QUOTE_BYTES: usize = 16 * 1024;

pub(crate) struct AutomataPccsOverrides<'a> {
    pub(crate) pcs_dao: Option<&'a str>,
    pub(crate) pck_dao: Option<&'a str>,
    pub(crate) fmspc_tcb_dao: Option<&'a str>,
    pub(crate) enclave_identity_dao: Option<&'a str>,
}

pub(crate) async fn fetch_automata_collateral(
    rpc_url: &str,
    chain: &str,
    overrides: AutomataPccsOverrides<'_>,
    read_strategy: &TdxDcapAutomataReadStrategy,
    quote: &[u8],
) -> Result<TdxDcapCollateral, String> {
    let rpc_url = rpc_url
        .parse()
        .map_err(|error| format!("parse Automata PCCS RPC URL {rpc_url}: {error}"))?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let mut network = Network::from_provider(&provider, None)
        .await
        .map_err(|error| format!("resolve Automata PCCS network: {error:#}"))?
        .clone();

    let short_key = network
        .key
        .split_once('_')
        .map_or(network.key.as_str(), |(_, suffix)| suffix);
    if chain != network.key && chain != short_key {
        return Err(format!(
            "configured Automata PCCS chain {chain} does not match RPC chain {} ({})",
            network.key, network.chain_id
        ));
    }

    if let Some(address) = overrides.pcs_dao {
        network.contracts.pccs.pcs_dao = parse_address(address, "PCS DAO")?;
    }
    if let Some(address) = overrides.pck_dao {
        network.contracts.pccs.pck_dao = parse_address(address, "PCK DAO")?;
    }

    let tcb_eval_num =
        if overrides.fmspc_tcb_dao.is_some() || overrides.enclave_identity_dao.is_some() {
            let evaluation = network
                .resolve_tcb_evaluation_data_number(&provider, None, 1)
                .await
                .map_err(|error| {
                    format!("resolve standard TDX TCB evaluation data number: {error:#}")
                })?;
            if let Some(address) = overrides.fmspc_tcb_dao {
                network
                    .contracts
                    .pccs
                    .fmspc_tcb_dao
                    .versioned
                    .insert(evaluation, parse_address(address, "FMSPC TCB DAO")?);
            }
            if let Some(address) = overrides.enclave_identity_dao {
                network
                    .contracts
                    .pccs
                    .enclave_id_dao
                    .versioned
                    .insert(evaluation, parse_address(address, "enclave identity DAO")?);
            }
            Some(evaluation)
        } else {
            None
        };

    let read_strategy = match read_strategy {
        TdxDcapAutomataReadStrategy::DirectConcurrent => PccsReadStrategy::DirectConcurrent,
        TdxDcapAutomataReadStrategy::Multicall3 { address: None } => PccsReadStrategy::multicall3(),
        TdxDcapAutomataReadStrategy::Multicall3 {
            address: Some(address),
        } => PccsReadStrategy::Multicall3 {
            address: parse_address(address, "Multicall3")?,
        },
    };
    let reader = PccsReader::from_network(&provider, &network).with_read_strategy(read_strategy);
    let collaterals = reader
        .find_missing_collaterals_from_quote(quote, false, tcb_eval_num)
        .await
        .map_err(|error| format!("read Automata PCCS collateral: {error}"))?;

    collateral_from_automata_reads(quote, collaterals)
}

pub(crate) async fn fetch_http_collateral(
    base_url: &str,
    quote: &[u8],
) -> Result<TdxDcapCollateral, String> {
    let material = quote_material(quote)?;
    let base_url = normalized_pcs_base_url(base_url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|error| format!("build HTTP PCCS client: {error}"))?;

    let pck_crl_url = format!(
        "{base_url}/sgx/certification/v4/pckcrl?ca={}&encoding=der",
        material.pck_ca
    );
    let pck_crl_response = checked_get(&client, &pck_crl_url).await?;
    let pck_crl_issuer_chain = decoded_header(&pck_crl_response, "SGX-PCK-CRL-Issuer-Chain")?;
    let pck_crl = read_limited_body(pck_crl_response, &pck_crl_url).await?;

    let tcb_info_url = format!(
        "{base_url}/tdx/certification/v4/tcb?fmspc={}",
        material.fmspc
    );
    let tcb_info_response = checked_get(&client, &tcb_info_url).await?;
    let tcb_info_issuer_chain = decoded_header_any(
        &tcb_info_response,
        &["SGX-TCB-Info-Issuer-Chain", "TCB-Info-Issuer-Chain"],
    )?;
    let raw_tcb_info = read_limited_text(tcb_info_response, &tcb_info_url).await?;
    let (tcb_info, tcb_info_signature) = split_signed_document(&raw_tcb_info, "tcbInfo")?;

    let qe_identity_url = format!("{base_url}/tdx/certification/v4/qe/identity?update=standard");
    let qe_identity_response = checked_get(&client, &qe_identity_url).await?;
    let qe_identity_issuer_chain =
        decoded_header(&qe_identity_response, "SGX-Enclave-Identity-Issuer-Chain")?;
    let raw_qe_identity = read_limited_text(qe_identity_response, &qe_identity_url).await?;
    let (qe_identity, qe_identity_signature) =
        split_signed_document(&raw_qe_identity, "enclaveIdentity")?;

    let root_ca_crl = fetch_root_ca_crl(&client, &base_url).await?;

    Ok(TdxDcapCollateral {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: Some(material.pck_certificate_chain),
    })
}

fn collateral_from_automata_reads(
    quote: &[u8],
    collaterals: Collaterals,
) -> Result<TdxDcapCollateral, String> {
    let material = quote_material(quote)?;
    let issuer_chain =
        generate_tcb_issuer_chain_pem(&collaterals.tcb_signing_ca, &collaterals.root_ca)
            .map_err(|error| format!("encode Automata TCB issuer chain: {error:#}"))?;
    let (tcb_info, tcb_info_signature) = split_signed_document(&collaterals.tcb_info, "tcbInfo")?;
    let (qe_identity, qe_identity_signature) =
        split_signed_document(&collaterals.qe_identity, "enclaveIdentity")?;

    Ok(TdxDcapCollateral {
        pck_crl_issuer_chain: material.pck_crl_issuer_chain,
        root_ca_crl: collaterals.root_ca_crl,
        pck_crl: collaterals.pck_crl,
        tcb_info_issuer_chain: issuer_chain.clone(),
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain: issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: Some(material.pck_certificate_chain),
    })
}

#[derive(Debug)]
struct QuoteMaterial {
    fmspc: String,
    pck_ca: &'static str,
    pck_crl_issuer_chain: String,
    pck_certificate_chain: String,
}

fn quote_material(raw_quote: &[u8]) -> Result<QuoteMaterial, String> {
    if raw_quote.len() > MAX_TDX_QUOTE_BYTES {
        return Err(format!("TDX quote exceeds {MAX_TDX_QUOTE_BYTES} bytes"));
    }
    let mut quote_bytes = raw_quote;
    let quote =
        Quote::read(&mut quote_bytes).map_err(|error| format!("parse TDX quote: {error:#}"))?;
    if quote.header.tee_type != dcap_rs::types::quote::TDX_TEE_TYPE
        || !matches!(quote.header.version.get(), 4 | 5)
    {
        return Err(format!(
            "expected a TDX quote with version 4 or 5, got tee_type 0x{:x} and version {}",
            quote.header.tee_type,
            quote.header.version.get()
        ));
    }
    if quote_bytes.iter().any(|byte| *byte != 0) {
        return Err(format!(
            "TDX quote has {} non-zero trailing bytes",
            quote_bytes.len()
        ));
    }
    let pck_data = quote
        .signature
        .get_pck_cert_chain()
        .map_err(|error| format!("extract PCK certificate chain from quote: {error:#}"))?;
    if pck_data.pck_cert_chain.len() < 2 {
        return Err(
            "PCK certificate chain in quote must contain the leaf and its issuer".to_string(),
        );
    }

    let pck_ca = {
        let issuer = pck_data.pck_cert_chain[0]
            .tbs_certificate
            .issuer
            .to_string();
        if issuer.contains(pccs_reader_rs::constants::INTEL_PCK_PLATFORM_CA_CN) {
            "platform"
        } else if issuer.contains(pccs_reader_rs::constants::INTEL_PCK_PROCESSOR_CA_CN) {
            "processor"
        } else {
            return Err(format!("unrecognized PCK certificate issuer: {issuer}"));
        }
    };
    let certificate_der = pck_data
        .pck_cert_chain
        .iter()
        .map(|certificate| {
            certificate
                .to_der()
                .map_err(|error| format!("encode PCK certificate as DER: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(QuoteMaterial {
        fmspc: hex::encode_upper(pck_data.pck_extension.fmspc),
        pck_ca,
        pck_crl_issuer_chain: pem_chain_from_der(&certificate_der[1..])?,
        pck_certificate_chain: pem_chain_from_der(&certificate_der)?,
    })
}

async fn checked_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response, String> {
    client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("request {url}: {error}"))?
        .error_for_status()
        .map_err(|error| format!("request {url}: {error}"))
}

async fn read_limited_text(response: reqwest::Response, url: &str) -> Result<String, String> {
    let body = read_limited_body(response, url).await?;
    String::from_utf8(body).map_err(|error| format!("read {url} as UTF-8: {error}"))
}

async fn read_limited_body(response: reqwest::Response, url: &str) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DCAP_COLLATERAL_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "response from {url} exceeds {MAX_DCAP_COLLATERAL_RESPONSE_BYTES} bytes"
        ));
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("read {url}: {error}"))?;
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| format!("response size from {url} overflows usize"))?;
        if new_len > MAX_DCAP_COLLATERAL_RESPONSE_BYTES {
            return Err(format!(
                "response from {url} exceeds {MAX_DCAP_COLLATERAL_RESPONSE_BYTES} bytes"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn decoded_header(response: &reqwest::Response, name: &str) -> Result<String, String> {
    decoded_header_any(response, &[name])
}

fn decoded_header_any(response: &reqwest::Response, names: &[&str]) -> Result<String, String> {
    let (name, value) = names
        .iter()
        .find_map(|name| response.headers().get(*name).map(|value| (*name, value)))
        .ok_or_else(|| format!("PCCS response is missing header {}", names.join(" or ")))?;
    let value = value
        .to_str()
        .map_err(|error| format!("PCCS header {name} is not valid text: {error}"))?;
    urlencoding::decode(value)
        .map(|value| value.into_owned())
        .map_err(|error| format!("decode PCCS header {name}: {error}"))
}

async fn fetch_root_ca_crl(client: &reqwest::Client, base_url: &str) -> Result<Vec<u8>, String> {
    if !base_url.starts_with(INTEL_PCS_URL) {
        let root_ca_crl_url = format!("{base_url}/sgx/certification/v4/rootcacrl");
        if let Ok(response) = checked_get(client, &root_ca_crl_url).await {
            let body = read_limited_text(response, &root_ca_crl_url).await?;
            return hex::decode(body.trim())
                .map_err(|error| format!("decode root CA CRL from {root_ca_crl_url}: {error}"));
        }
    }

    let response = checked_get(client, INTEL_ROOT_CA_CRL_URL).await?;
    read_limited_body(response, INTEL_ROOT_CA_CRL_URL).await
}

fn split_signed_document(
    document: &str,
    body_field: &'static str,
) -> Result<(String, Vec<u8>), String> {
    let value: std::collections::BTreeMap<String, &RawValue> = serde_json::from_str(document)
        .map_err(|error| format!("{body_field} response is not valid JSON: {error}"))?;
    let body = value
        .get(body_field)
        .ok_or_else(|| format!("{body_field} response is missing {body_field}"))?;
    let signature = value
        .get("signature")
        .ok_or_else(|| format!("{body_field} response is missing signature"))?;
    let signature: String = serde_json::from_str(signature.get())
        .map_err(|error| format!("{body_field} signature is not a JSON string: {error}"))?;
    let signature = signature.strip_prefix("0x").unwrap_or(&signature);
    let signature = hex::decode(signature)
        .map_err(|error| format!("{body_field} signature is not valid hex: {error}"))?;
    Ok((body.get().to_string(), signature))
}

fn normalized_pcs_base_url(url: &str) -> String {
    url.trim_end_matches('/')
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4")
        .to_string()
}

fn parse_address(address: &str, label: &str) -> Result<Address, String> {
    Address::from_str(address).map_err(|error| format!("parse {label} address {address}: {error}"))
}

fn pem_chain_from_der(certificates: &[Vec<u8>]) -> Result<String, String> {
    if certificates.is_empty() {
        return Err("cannot build a PEM chain from no certificates".to_string());
    }
    Ok(certificates
        .iter()
        .map(|certificate| {
            pem::encode(&pem::Pem::new(
                "CERTIFICATE".to_string(),
                certificate.clone(),
            ))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_pccs_and_pcs_base_urls() {
        assert_eq!(
            normalized_pcs_base_url("https://pccs.example/tdx/certification/v4/"),
            "https://pccs.example"
        );
        assert_eq!(
            normalized_pcs_base_url("https://api.trustedservices.intel.com"),
            INTEL_PCS_URL
        );
    }

    #[test]
    fn splits_signed_intel_document() {
        let (body, signature) = split_signed_document(
            r#"{"tcbInfo":{"version":3,"id":"TDX"},"signature":"0x0102"}"#,
            "tcbInfo",
        )
        .expect("split signed document");
        assert_eq!(body, r#"{"version":3,"id":"TDX"}"#);
        assert_eq!(signature, vec![1, 2]);
    }

    #[test]
    fn extracts_material_from_the_upstream_tdx_quote_sample() {
        let quote = hex::decode(include_str!("../testdata/automata-dcap/quotev4.hex").trim())
            .expect("decode quote");
        let material = quote_material(&quote).expect("extract quote material");
        assert_eq!(material.fmspc.len(), 12);
        assert!(matches!(material.pck_ca, "processor" | "platform"));
        assert!(material
            .pck_crl_issuer_chain
            .contains("-----BEGIN CERTIFICATE-----"));
        assert!(material
            .pck_certificate_chain
            .contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn rejects_non_tdx_quotes_and_nonzero_trailing_bytes() {
        let sgx_quote = hex::decode(include_str!("../testdata/automata-dcap/quotev3.hex").trim())
            .expect("decode SGX quote");
        assert!(quote_material(&sgx_quote)
            .expect_err("SGX quote must not be accepted as TDX")
            .contains("expected a TDX quote"));

        let mut padded_tdx_quote =
            hex::decode(include_str!("../testdata/automata-dcap/quotev4.hex").trim())
                .expect("decode TDX quote");
        *padded_tdx_quote.last_mut().expect("sample quote") = 1;
        assert!(quote_material(&padded_tdx_quote)
            .expect_err("non-zero trailing bytes must be rejected")
            .contains("non-zero trailing bytes"));
    }

    #[tokio::test]
    #[ignore = "requires a live Hoodi RPC endpoint"]
    async fn live_automata_collateral_verifies_the_tdx_sample() {
        let quote = hex::decode(include_str!("../testdata/automata-dcap/quotev4.hex").trim())
            .expect("decode TDX quote");
        let collateral = fetch_automata_collateral(
            "https://ethereum-hoodi-rpc.publicnode.com",
            "hoodi",
            AutomataPccsOverrides {
                pcs_dao: None,
                pck_dao: None,
                fmspc_tcb_dao: None,
                enclave_identity_dao: None,
            },
            &TdxDcapAutomataReadStrategy::DirectConcurrent,
            &quote,
        )
        .await
        .expect("fetch Automata collateral");
        let collateral = collateral
            .to_automata_collateral()
            .expect("convert Automata collateral");
        let mut quote_bytes = quote.as_slice();
        let quote = Quote::read(&mut quote_bytes).expect("parse quote");
        dcap_rs::verify_dcap_quote_with_policy(
            std::time::SystemTime::now(),
            collateral,
            quote,
            &dcap_rs::DcapVerificationPolicy::production().with_tdx_tcb_revocation_policy(
                dcap_rs::TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch,
            ),
        )
        .expect("verify quote with fetched collateral");
    }
}
