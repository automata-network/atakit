use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use atakit_attestation::{
    intel_tdx_quote_collateral_identity, IntelTdxCollateralSelection, IntelTdxDcapCollateral,
};
use automata_dcap_network_registry::Network;
use futures_util::StreamExt;
use pccs_reader_rs::tcb_pem::generate_tcb_issuer_chain_pem;
use pccs_reader_rs::{Collaterals, PccsReadStrategy, PccsReader};

use super::TdxDcapAutomataReadStrategy;

const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";
const INTEL_ROOT_CA_CRL_URL: &str =
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";
const MAX_DCAP_COLLATERAL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

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
) -> Result<IntelTdxDcapCollateral, String> {
    quote_material(quote)?;
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

    let selection = tcb_eval_num.map_or(
        IntelTdxCollateralSelection::Standard,
        IntelTdxCollateralSelection::EvaluationDataNumber,
    );
    collateral_from_automata_reads(collaterals, quote, selection)
}

pub(crate) async fn fetch_http_collateral(
    base_url: &str,
    quote: &[u8],
) -> Result<IntelTdxDcapCollateral, String> {
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

    let qe_identity_url = format!("{base_url}/tdx/certification/v4/qe/identity?update=standard");
    let qe_identity_response = checked_get(&client, &qe_identity_url).await?;
    let qe_identity_issuer_chain =
        decoded_header(&qe_identity_response, "SGX-Enclave-Identity-Issuer-Chain")?;
    let raw_qe_identity = read_limited_text(qe_identity_response, &qe_identity_url).await?;
    if !issuer_chains_match(&tcb_info_issuer_chain, &qe_identity_issuer_chain) {
        return Err(
            "TCB info and QE identity issuer chains differ; Automata dcap-rs requires one shared issuer chain"
                .to_string(),
        );
    }

    let root_ca_crl = fetch_root_ca_crl(&client, &base_url).await?;

    IntelTdxDcapCollateral::from_source_material(
        quote,
        IntelTdxCollateralSelection::Standard,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        raw_tcb_info,
        raw_qe_identity,
    )
    .map_err(|error| error.to_string())
}

fn collateral_from_automata_reads(
    collaterals: Collaterals,
    quote: &[u8],
    selection: IntelTdxCollateralSelection,
) -> Result<IntelTdxDcapCollateral, String> {
    let issuer_chain =
        generate_tcb_issuer_chain_pem(&collaterals.tcb_signing_ca, &collaterals.root_ca)
            .map_err(|error| format!("encode Automata TCB issuer chain: {error:#}"))?;

    IntelTdxDcapCollateral::from_source_material(
        quote,
        selection,
        collaterals.root_ca_crl,
        collaterals.pck_crl,
        issuer_chain,
        collaterals.tcb_info,
        collaterals.qe_identity,
    )
    .map_err(|error| error.to_string())
}

#[derive(Debug)]
struct QuoteMaterial {
    fmspc: String,
    pck_ca: &'static str,
}

fn quote_material(raw_quote: &[u8]) -> Result<QuoteMaterial, String> {
    let identity =
        intel_tdx_quote_collateral_identity(raw_quote).map_err(|error| error.to_string())?;
    Ok(QuoteMaterial {
        fmspc: hex::encode_upper(identity.fmspc),
        pck_ca: identity.pck_ca.pcs_query_value(),
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

pub(crate) fn parse_dcap_collateral_json(
    document: &str,
    quote: &[u8],
) -> Result<IntelTdxDcapCollateral, String> {
    IntelTdxDcapCollateral::from_file_json(document, quote).map_err(|error| error.to_string())
}

fn issuer_chains_match(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }

    let Ok(left_certificates) = pem::parse_many(left) else {
        return false;
    };
    let Ok(right_certificates) = pem::parse_many(right) else {
        return false;
    };

    !left_certificates.is_empty()
        && left_certificates.len() == right_certificates.len()
        && left_certificates
            .iter()
            .zip(&right_certificates)
            .all(|(left, right)| left.contents() == right.contents())
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

#[cfg(test)]
mod tests {
    use super::*;
    use atakit_attestation::{IntelTdxDcapCollateralError, IntelTdxPckCa};
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams,
        DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, SerialNumber,
    };

    fn synthetic_collateral_for_quote_with_selection(
        quote: &[u8],
        selection: IntelTdxCollateralSelection,
    ) -> Result<IntelTdxDcapCollateral, IntelTdxDcapCollateralError> {
        let identity =
            intel_tdx_quote_collateral_identity(quote).expect("extract quote collateral identity");
        let pck_ca_common_name = match identity.pck_ca {
            IntelTdxPckCa::Processor => "Intel SGX PCK Processor CA",
            IntelTdxPckCa::Platform => "Intel SGX PCK Platform CA",
        };

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, pck_ca_common_name);
        let mut certificate_params =
            CertificateParams::new(Vec::<String>::new()).expect("certificate parameters");
        certificate_params.distinguished_name = distinguished_name;
        certificate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        certificate_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let key_pair = KeyPair::generate().expect("generate certificate key");
        let certificate = certificate_params
            .self_signed(&key_pair)
            .expect("generate issuer certificate");
        let crl = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2027, 1, 1),
            crl_number: SerialNumber::from(1),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&certificate, &key_pair)
        .expect("generate certificate revocation list");

        let evaluation_data_number = 7;
        let tcb_info = serde_json::json!({
            "tcbInfo": {
                "id": "TDX",
                "version": 3,
                "issueDate": "2026-01-01T00:00:00Z",
                "nextUpdate": "2027-01-01T00:00:00Z",
                "fmspc": hex::encode_upper(identity.fmspc),
                "pceId": hex::encode_upper(identity.pce_id),
                "tcbType": 0,
                "tcbEvaluationDataNumber": evaluation_data_number,
                "tcbLevels": []
            },
            "signature": ""
        })
        .to_string();
        let qe_identity = serde_json::json!({
            "enclaveIdentity": {
                "id": "TD_QE",
                "version": 2,
                "issueDate": "2026-01-01T00:00:00Z",
                "nextUpdate": "2027-01-01T00:00:00Z",
                "tcbEvaluationDataNumber": evaluation_data_number,
                "miscselect": "00000000",
                "miscselectMask": "FFFFFFFF",
                "attributes": "00000000000000000000000000000000",
                "attributesMask": "00000000000000000000000000000000",
                "mrsigner": "0000000000000000000000000000000000000000000000000000000000000000",
                "isvprodid": 0,
                "tcbLevels": []
            },
            "signature": ""
        })
        .to_string();

        IntelTdxDcapCollateral::from_source_material(
            quote,
            selection,
            crl.der().to_vec(),
            crl.der().to_vec(),
            certificate.pem(),
            tcb_info,
            qe_identity,
        )
    }

    fn synthetic_collateral_for_quote(quote: &[u8]) -> IntelTdxDcapCollateral {
        synthetic_collateral_for_quote_with_selection(quote, IntelTdxCollateralSelection::Standard)
            .expect("parse synthetic collateral")
    }

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
    fn rejects_the_former_quote_collateral_v3_json_shape() {
        let legacy = serde_json::json!({
            "pck_crl_issuer_chain": "pck",
            "root_ca_crl": [1, 2],
            "pck_crl": [3, 4],
            "tcb_info_issuer_chain": "issuer",
            "tcb_info": "{}",
            "tcb_info_signature": [5, 6],
            "qe_identity_issuer_chain": "issuer",
            "qe_identity": "{}",
            "qe_identity_signature": [7, 8]
        });

        let error = parse_dcap_collateral_json(&legacy.to_string(), &[])
            .expect_err("the former QuoteCollateralV3 JSON shape must not parse");
        assert!(error.contains("invalid Intel TDX collateral file"));
    }

    #[test]
    fn extracts_material_from_the_upstream_tdx_quote_sample() {
        let quote = hex::decode(include_str!("../../../testdata/automata-dcap/quotev4.hex").trim())
            .expect("decode quote");
        let material = quote_material(&quote).expect("extract quote material");
        assert_eq!(material.fmspc.len(), 12);
        assert!(matches!(material.pck_ca, "processor" | "platform"));
    }

    #[test]
    fn version_one_file_round_trip_preserves_collateral_and_exact_selector() {
        let quote = hex::decode(include_str!("../../../testdata/automata-dcap/quotev4.hex").trim())
            .expect("decode TDX quote");
        let collateral = synthetic_collateral_for_quote(&quote);
        let clone = collateral.clone();
        assert!(std::ptr::eq(collateral.parsed(), clone.parsed()));

        let document = collateral
            .to_file_json()
            .expect("encode version 1 collateral file");
        let decoded =
            parse_dcap_collateral_json(&document, &quote).expect("parse version 1 collateral file");

        assert_eq!(decoded.key().identity, collateral.key().identity);
        assert_eq!(
            decoded.key().selection,
            IntelTdxCollateralSelection::EvaluationDataNumber(7)
        );
        assert_eq!(decoded.tcb_evaluation_data_number(), 7);
        assert_eq!(decoded.qe_identity_evaluation_data_number(), 7);
        assert_eq!(
            decoded
                .to_file_json()
                .expect("encode decoded version 1 collateral file"),
            document
        );
    }

    #[test]
    fn exact_evaluation_number_must_match_signed_tcb_info() {
        let quote = hex::decode(include_str!("../../../testdata/automata-dcap/quotev4.hex").trim())
            .expect("decode TDX quote");
        let collateral = synthetic_collateral_for_quote_with_selection(
            &quote,
            IntelTdxCollateralSelection::EvaluationDataNumber(7),
        )
        .expect("matching exact evaluation data number");
        assert_eq!(
            collateral.key().selection,
            IntelTdxCollateralSelection::EvaluationDataNumber(7)
        );

        let error = synthetic_collateral_for_quote_with_selection(
            &quote,
            IntelTdxCollateralSelection::EvaluationDataNumber(999),
        )
        .expect_err("mislabeled exact evaluation data number must fail");
        assert!(
            error.to_string().contains(
                "requested TCB evaluation data number 999, but signed TCB Info contains 7"
            ),
            "{error}"
        );
    }

    #[test]
    fn rejects_non_tdx_quotes_and_nonzero_trailing_bytes() {
        let sgx_quote =
            hex::decode(include_str!("../../../testdata/automata-dcap/quotev3.hex").trim())
                .expect("decode SGX quote");
        assert!(quote_material(&sgx_quote)
            .expect_err("SGX quote must not be accepted as TDX")
            .contains("expected a TDX quote"));

        let mut padded_tdx_quote =
            hex::decode(include_str!("../../../testdata/automata-dcap/quotev4.hex").trim())
                .expect("decode TDX quote");
        padded_tdx_quote.push(1);
        assert!(quote_material(&padded_tdx_quote)
            .expect_err("non-zero trailing bytes must be rejected")
            .contains("non-zero trailing bytes"));
    }

    #[tokio::test]
    #[ignore = "requires a live Hoodi RPC endpoint"]
    async fn live_automata_collateral_verifies_the_tdx_sample() {
        let quote = hex::decode(include_str!("../../../testdata/automata-dcap/quotev4.hex").trim())
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
        let mut quote_bytes = quote.as_slice();
        let quote = dcap_rs::types::quote::Quote::read(&mut quote_bytes).expect("parse quote");
        dcap_rs::verify_dcap_quote_with_policy_ref(
            std::time::SystemTime::now(),
            collateral.parsed(),
            quote,
            &dcap_rs::DcapVerificationPolicy::production().with_tdx_tcb_revocation_policy(
                dcap_rs::TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch,
            ),
        )
        .expect("verify quote with fetched collateral");
    }
}

#[cfg(test)]
mod capture_fixture_collateral {
    use super::*;

    /// One-shot capture helper. Ignored by default because it reaches Intel's
    /// Provisioning Certification Service over the network; the committed
    /// artifact it produces is what the offline fixture actually uses.
    ///
    ///     cargo test -p atakit-attestation-client capture_azure_tdx_collateral -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn capture_azure_tdx_collateral() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine as _;

        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/testdata/azure-tdx-tls-attestation.json"
        ))
        .expect("captured attestation response");
        let response: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let quote = B64
            .decode(response["teeEvidence"]["report"].as_str().unwrap())
            .expect("decode TDX quote");

        let collateral = fetch_http_collateral("https://api.trustedservices.intel.com", &quote)
            .await
            .expect("fetch Intel TDX DCAP collateral");

        collateral
            .ensure_quote_matches(&quote)
            .expect("collateral must match the captured quote");

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/testdata/azure-tdx-dcap-collateral.json"
        );
        std::fs::write(path, collateral.to_file_json().unwrap()).unwrap();
        println!("wrote {path}");
        println!(
            "tcb_evaluation_data_number = {}",
            collateral.tcb_evaluation_data_number()
        );
    }
}
