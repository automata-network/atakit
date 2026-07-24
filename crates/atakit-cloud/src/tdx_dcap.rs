use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use atakit_attestation::TdxDcapCollateral;
use automata_dcap_network_registry::Network;
use dcap_rs::types::quote::Quote;
use pccs_reader_rs::tcb_pem::generate_tcb_issuer_chain_pem;
use pccs_reader_rs::{Collaterals, PccsReadStrategy, PccsReader};
use x509_cert::der::Encode;
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::init::TdxDcapAutomataReadStrategy;

const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";

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
    let pck_crl = pck_crl_response
        .bytes()
        .await
        .map_err(|error| format!("read {pck_crl_url}: {error}"))?
        .to_vec();

    let tcb_info_url = format!(
        "{base_url}/tdx/certification/v4/tcb?fmspc={}",
        material.fmspc
    );
    let tcb_info_response = checked_get(&client, &tcb_info_url).await?;
    let tcb_info_issuer_chain = decoded_header_any(
        &tcb_info_response,
        &["SGX-TCB-Info-Issuer-Chain", "TCB-Info-Issuer-Chain"],
    )?;
    let raw_tcb_info = tcb_info_response
        .text()
        .await
        .map_err(|error| format!("read {tcb_info_url}: {error}"))?;
    let (tcb_info, tcb_info_signature) = split_signed_document(&raw_tcb_info, "tcbInfo")?;

    let qe_identity_url = format!("{base_url}/tdx/certification/v4/qe/identity?update=standard");
    let qe_identity_response = checked_get(&client, &qe_identity_url).await?;
    let qe_identity_issuer_chain =
        decoded_header(&qe_identity_response, "SGX-Enclave-Identity-Issuer-Chain")?;
    let raw_qe_identity = qe_identity_response
        .text()
        .await
        .map_err(|error| format!("read {qe_identity_url}: {error}"))?;
    let (qe_identity, qe_identity_signature) =
        split_signed_document(&raw_qe_identity, "enclaveIdentity")?;

    let root_ca_crl = fetch_root_ca_crl(&client, &base_url, &qe_identity_issuer_chain).await?;

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

struct QuoteMaterial {
    fmspc: String,
    pck_ca: &'static str,
    pck_crl_issuer_chain: String,
    pck_certificate_chain: String,
}

fn quote_material(raw_quote: &[u8]) -> Result<QuoteMaterial, String> {
    let mut quote_bytes = raw_quote;
    let quote =
        Quote::read(&mut quote_bytes).map_err(|error| format!("parse TDX quote: {error:#}"))?;
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

async fn fetch_root_ca_crl(
    client: &reqwest::Client,
    base_url: &str,
    qe_identity_issuer_chain: &str,
) -> Result<Vec<u8>, String> {
    if !base_url.starts_with(INTEL_PCS_URL) {
        let root_ca_crl_url = format!("{base_url}/sgx/certification/v4/rootcacrl");
        if let Ok(response) = checked_get(client, &root_ca_crl_url).await {
            let body = response
                .text()
                .await
                .map_err(|error| format!("read {root_ca_crl_url}: {error}"))?;
            return hex::decode(body.trim())
                .map_err(|error| format!("decode root CA CRL from {root_ca_crl_url}: {error}"));
        }
    }

    let certificates = pem::parse_many(qe_identity_issuer_chain)
        .map_err(|error| format!("parse QE identity issuer chain: {error}"))?;
    let root = certificates
        .last()
        .ok_or_else(|| "QE identity issuer chain is empty".to_string())?;
    let crl_url = crl_distribution_point(root.contents())?
        .ok_or_else(|| "Intel root certificate has no CRL distribution point".to_string())?;
    checked_get(client, &crl_url)
        .await?
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|error| format!("read root CA CRL from {crl_url}: {error}"))
}

fn crl_distribution_point(certificate_der: &[u8]) -> Result<Option<String>, String> {
    let (_, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|error| format!("parse Intel root certificate: {error}"))?;
    for extension in certificate.extensions() {
        let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() else {
            continue;
        };
        for point in &points.points {
            let Some(DistributionPointName::FullName(names)) = &point.distribution_point else {
                continue;
            };
            for name in names {
                if let GeneralName::URI(uri) = name {
                    return Ok(Some((*uri).to_string()));
                }
            }
        }
    }
    Ok(None)
}

fn split_signed_document(
    document: &str,
    body_field: &'static str,
) -> Result<(String, Vec<u8>), String> {
    let value: serde_json::Value = serde_json::from_str(document)
        .map_err(|error| format!("{body_field} response is not valid JSON: {error}"))?;
    let body = value
        .get(body_field)
        .ok_or_else(|| format!("{body_field} response is missing {body_field}"))?;
    let signature = value
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{body_field} response is missing signature"))?;
    let signature = signature.strip_prefix("0x").unwrap_or(signature);
    let signature = hex::decode(signature)
        .map_err(|error| format!("{body_field} signature is not valid hex: {error}"))?;
    let body =
        serde_json::to_string(body).map_err(|error| format!("serialize {body_field}: {error}"))?;
    Ok((body, signature))
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
            r#"{"tcbInfo":{"version":3},"signature":"0x0102"}"#,
            "tcbInfo",
        )
        .expect("split signed document");
        assert_eq!(body, r#"{"version":3}"#);
        assert_eq!(signature, vec![1, 2]);
    }

    #[test]
    fn extracts_material_from_the_upstream_tdx_quote_sample() {
        let quote =
            hex::decode(include_str!("../../../vendor/automata-dcap/samples/quotev4.hex").trim())
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
}
