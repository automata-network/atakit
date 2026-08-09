use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use dcap_rs::types::collateral::Collateral;
use dcap_rs::types::quote::{Quote, TDX_TEE_TYPE};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x509_cert::der::Encode;

const INTEL_TDX_COLLATERAL_SCHEMA: &str = "atakit.intel-tdx-dcap-collateral";
const INTEL_TDX_COLLATERAL_VERSION: u8 = 1;
const INTEL_PCK_PLATFORM_CA_CN: &str = "Intel SGX PCK Platform CA";
const INTEL_PCK_PROCESSOR_CA_CN: &str = "Intel SGX PCK Processor CA";
const MAX_TDX_QUOTE_BYTES: usize = 16 * 1024;
const MAX_COLLATERAL_FILE_BYTES: usize = 16 * 1024 * 1024;
/// Largest single Intel TDX DCAP collateral component this crate will parse.
///
/// Public because `.atatp` pins its single-entry archive limit to this value:
/// a component a trust pack reader accepted but this parser rejected would be
/// a wasted parse, so the two must agree. The `.atatp` reader asserts the
/// equality in a test rather than restating the number.
pub const MAX_COLLATERAL_COMPONENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ISSUER_CHAIN_CERTIFICATES: usize = 8;

#[derive(Debug, Error)]
pub enum IntelTdxDcapCollateralError {
    #[error("invalid Intel TDX quote: {0}")]
    Quote(String),
    #[error("invalid Intel TDX DCAP source material: {0}")]
    SourceMaterial(String),
    #[error("invalid Intel TDX collateral file: {0}")]
    File(String),
    #[error(
        "unsupported Intel TDX collateral file schema {schema:?} version {version}; expected {expected_schema:?} version {expected_version}"
    )]
    UnsupportedFileFormat {
        schema: String,
        version: u8,
        expected_schema: &'static str,
        expected_version: u8,
    },
    #[error("Intel TDX collateral does not match the quote: {0}")]
    QuoteMismatch(String),
    #[error("could not encode Intel TDX collateral file: {0}")]
    Encode(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IntelTdxPckCa {
    Processor,
    Platform,
}

impl IntelTdxPckCa {
    pub fn pcs_query_value(self) -> &'static str {
        match self {
            Self::Processor => "processor",
            Self::Platform => "platform",
        }
    }

    fn expected_issuer_common_name(self) -> &'static str {
        match self {
            Self::Processor => INTEL_PCK_PROCESSOR_CA_CN,
            Self::Platform => INTEL_PCK_PLATFORM_CA_CN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntelTdxCollateralSelection {
    Standard,
    Early,
    EvaluationDataNumber(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntelTdxQuoteCollateralIdentity {
    pub fmspc: [u8; 6],
    pub pce_id: [u8; 2],
    pub pck_ca: IntelTdxPckCa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntelTdxCollateralKey {
    pub identity: IntelTdxQuoteCollateralIdentity,
    pub selection: IntelTdxCollateralSelection,
}

/// Parsed Intel TDX DCAP collateral owned by one verifier operation.
///
/// The portal does not supply this value. The verifier resolves it from its
/// configured source and may reuse the immutable parsed value only for quotes
/// whose [`IntelTdxQuoteCollateralIdentity`] matches `key.identity`.
#[derive(Debug, Clone)]
pub struct IntelTdxDcapCollateral {
    key: IntelTdxCollateralKey,
    tcb_evaluation_data_number: u32,
    qe_identity_evaluation_data_number: u32,
    collateral: Arc<Collateral>,
}

impl IntelTdxDcapCollateral {
    #[allow(clippy::too_many_arguments)]
    pub fn from_source_material(
        quote: &[u8],
        selection: IntelTdxCollateralSelection,
        root_ca_crl_der: Vec<u8>,
        pck_crl_der: Vec<u8>,
        tcb_info_and_qe_identity_issuer_chain_pem: String,
        tcb_info_json: String,
        qe_identity_json: String,
    ) -> Result<Self, IntelTdxDcapCollateralError> {
        for (name, length) in [
            ("root CA certificate revocation list", root_ca_crl_der.len()),
            ("PCK certificate revocation list", pck_crl_der.len()),
            (
                "TCB Info and QE Identity issuer chain",
                tcb_info_and_qe_identity_issuer_chain_pem.len(),
            ),
            ("signed TCB Info JSON", tcb_info_json.len()),
            ("signed QE Identity JSON", qe_identity_json.len()),
        ] {
            if length > MAX_COLLATERAL_COMPONENT_BYTES {
                return Err(IntelTdxDcapCollateralError::SourceMaterial(format!(
                    "{name} exceeds {MAX_COLLATERAL_COMPONENT_BYTES} bytes"
                )));
            }
        }
        let identity = intel_tdx_quote_collateral_identity(quote)?;
        let collateral = Collateral::new(
            &root_ca_crl_der,
            &pck_crl_der,
            tcb_info_and_qe_identity_issuer_chain_pem.as_bytes(),
            &tcb_info_json,
            &qe_identity_json,
        )
        .map_err(|error| {
            IntelTdxDcapCollateralError::SourceMaterial(format!(
                "parse certificates, revocation lists, TCB Info, and QE Identity: {error:#}"
            ))
        })?;
        let parsed = Self::from_parsed(
            IntelTdxCollateralKey {
                identity,
                selection,
            },
            collateral,
        )?;
        if let IntelTdxCollateralSelection::EvaluationDataNumber(requested) = selection {
            if parsed.tcb_evaluation_data_number != requested {
                return Err(IntelTdxDcapCollateralError::SourceMaterial(format!(
                    "requested TCB evaluation data number {requested}, but signed TCB Info contains {}",
                    parsed.tcb_evaluation_data_number
                )));
            }
        }
        Ok(parsed)
    }

    pub fn from_file_json(
        document: &str,
        quote: &[u8],
    ) -> Result<Self, IntelTdxDcapCollateralError> {
        if document.len() > MAX_COLLATERAL_FILE_BYTES {
            return Err(IntelTdxDcapCollateralError::File(format!(
                "document exceeds {MAX_COLLATERAL_FILE_BYTES} bytes"
            )));
        }
        let file: IntelTdxCollateralFileV1 = serde_json::from_str(document)
            .map_err(|error| IntelTdxDcapCollateralError::File(error.to_string()))?;
        if file.schema != INTEL_TDX_COLLATERAL_SCHEMA
            || file.version != INTEL_TDX_COLLATERAL_VERSION
        {
            return Err(IntelTdxDcapCollateralError::UnsupportedFileFormat {
                schema: file.schema,
                version: file.version,
                expected_schema: INTEL_TDX_COLLATERAL_SCHEMA,
                expected_version: INTEL_TDX_COLLATERAL_VERSION,
            });
        }

        let declared_identity = IntelTdxQuoteCollateralIdentity {
            fmspc: decode_selector_hex::<6>("selector.fmspc", &file.selector.fmspc)?,
            pce_id: decode_selector_hex::<2>("selector.pceId", &file.selector.pce_id)?,
            pck_ca: file.selector.pck_ca,
        };
        let quote_identity = intel_tdx_quote_collateral_identity(quote)?;
        if declared_identity != quote_identity {
            return Err(IntelTdxDcapCollateralError::QuoteMismatch(format!(
                "file selector {} does not match quote selector {}",
                display_identity(declared_identity),
                display_identity(quote_identity)
            )));
        }

        let root_ca_crl_der =
            decode_component("payload.rootCaCrlDer", &file.payload.root_ca_crl_der)?;
        let pck_crl_der = decode_component("payload.pckCrlDer", &file.payload.pck_crl_der)?;
        if file.payload.issuer_chain_der.is_empty()
            || file.payload.issuer_chain_der.len() > MAX_ISSUER_CHAIN_CERTIFICATES
        {
            return Err(IntelTdxDcapCollateralError::File(format!(
                "payload.issuerChainDer must contain 1 through {MAX_ISSUER_CHAIN_CERTIFICATES} certificates"
            )));
        }
        let issuer_chain = file
            .payload
            .issuer_chain_der
            .iter()
            .enumerate()
            .map(|(index, encoded)| {
                decode_component(&format!("payload.issuerChainDer[{index}]"), encoded)
                    .map(|der| pem::Pem::new("CERTIFICATE", der))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tcb_info_json = decode_utf8_component(
            "payload.tcbInfoSignedJson",
            &file.payload.tcb_info_signed_json,
        )?;
        let qe_identity_json = decode_utf8_component(
            "payload.qeIdentitySignedJson",
            &file.payload.qe_identity_signed_json,
        )?;

        let collateral = Collateral::new(
            &root_ca_crl_der,
            &pck_crl_der,
            pem::encode_many(&issuer_chain).as_bytes(),
            &tcb_info_json,
            &qe_identity_json,
        )
        .map_err(|error| {
            IntelTdxDcapCollateralError::File(format!("parse collateral payload: {error:#}"))
        })?;
        let parsed = Self::from_parsed(
            IntelTdxCollateralKey {
                identity: declared_identity,
                selection: IntelTdxCollateralSelection::EvaluationDataNumber(
                    file.selector.tcb_evaluation_data_number,
                ),
            },
            collateral,
        )?;
        if parsed.tcb_evaluation_data_number != file.selector.tcb_evaluation_data_number {
            return Err(IntelTdxDcapCollateralError::File(format!(
                "selector.tcbEvaluationDataNumber is {}, but signed TCB Info contains {}",
                file.selector.tcb_evaluation_data_number, parsed.tcb_evaluation_data_number
            )));
        }
        if parsed.qe_identity_evaluation_data_number
            != file.selector.qe_identity_evaluation_data_number
        {
            return Err(IntelTdxDcapCollateralError::File(format!(
                "selector.qeIdentityEvaluationDataNumber is {}, but signed QE Identity contains {}",
                file.selector.qe_identity_evaluation_data_number,
                parsed.qe_identity_evaluation_data_number
            )));
        }
        Ok(parsed)
    }

    /// Encode this parsed collateral as an atakit version 1 JSON document.
    ///
    /// A file selects the exact evaluation data number contained in the signed
    /// TCB Info and QE Identity responses. It does not preserve whether the
    /// original resolver requested the standard or early source selection.
    pub fn to_file_json(&self) -> Result<String, IntelTdxDcapCollateralError> {
        let root_ca_crl_der = self
            .collateral
            .root_ca_crl
            .to_der()
            .map_err(|error| IntelTdxDcapCollateralError::Encode(error.to_string()))?;
        let pck_crl_der = self
            .collateral
            .pck_crl
            .to_der()
            .map_err(|error| IntelTdxDcapCollateralError::Encode(error.to_string()))?;
        let issuer_chain_der = self
            .collateral
            .tcb_info_and_qe_identity_issuer_chain
            .iter()
            .map(|certificate| {
                certificate
                    .to_der()
                    .map(|der| URL_SAFE_NO_PAD.encode(der))
                    .map_err(|error| IntelTdxDcapCollateralError::Encode(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tcb_info_signed_json =
            serde_json::to_vec(&self.collateral.tcb_info).map_err(|error| {
                IntelTdxDcapCollateralError::Encode(format!("serialize signed TCB Info: {error}"))
            })?;
        let qe_identity_signed_json =
            serde_json::to_vec(&self.collateral.qe_identity).map_err(|error| {
                IntelTdxDcapCollateralError::Encode(format!(
                    "serialize signed QE Identity: {error}"
                ))
            })?;

        for (name, length) in [
            ("payload.rootCaCrlDer", root_ca_crl_der.len()),
            ("payload.pckCrlDer", pck_crl_der.len()),
            ("payload.tcbInfoSignedJson", tcb_info_signed_json.len()),
            (
                "payload.qeIdentitySignedJson",
                qe_identity_signed_json.len(),
            ),
        ] {
            if length > MAX_COLLATERAL_COMPONENT_BYTES {
                return Err(IntelTdxDcapCollateralError::Encode(format!(
                    "{name} exceeds {MAX_COLLATERAL_COMPONENT_BYTES} bytes"
                )));
            }
        }

        let file = IntelTdxCollateralFileV1 {
            schema: INTEL_TDX_COLLATERAL_SCHEMA.to_string(),
            version: INTEL_TDX_COLLATERAL_VERSION,
            selector: IntelTdxCollateralFileSelectorV1 {
                fmspc: hex::encode(self.key.identity.fmspc),
                pce_id: hex::encode(self.key.identity.pce_id),
                pck_ca: self.key.identity.pck_ca,
                tcb_evaluation_data_number: self.tcb_evaluation_data_number,
                qe_identity_evaluation_data_number: self.qe_identity_evaluation_data_number,
            },
            payload: IntelTdxCollateralFilePayloadV1 {
                root_ca_crl_der: URL_SAFE_NO_PAD.encode(root_ca_crl_der),
                pck_crl_der: URL_SAFE_NO_PAD.encode(pck_crl_der),
                issuer_chain_der,
                tcb_info_signed_json: URL_SAFE_NO_PAD.encode(tcb_info_signed_json),
                qe_identity_signed_json: URL_SAFE_NO_PAD.encode(qe_identity_signed_json),
            },
        };
        let document = serde_json::to_string_pretty(&file).map_err(|error| {
            IntelTdxDcapCollateralError::Encode(format!("serialize version 1 document: {error}"))
        })?;
        if document.len() > MAX_COLLATERAL_FILE_BYTES {
            return Err(IntelTdxDcapCollateralError::Encode(format!(
                "document exceeds {MAX_COLLATERAL_FILE_BYTES} bytes"
            )));
        }
        Ok(document)
    }

    fn from_parsed(
        key: IntelTdxCollateralKey,
        collateral: Collateral,
    ) -> Result<Self, IntelTdxDcapCollateralError> {
        if collateral.tcb_info_and_qe_identity_issuer_chain.is_empty()
            || collateral.tcb_info_and_qe_identity_issuer_chain.len()
                > MAX_ISSUER_CHAIN_CERTIFICATES
        {
            return Err(IntelTdxDcapCollateralError::SourceMaterial(format!(
                "TCB Info and QE Identity issuer chain must contain 1 through {MAX_ISSUER_CHAIN_CERTIFICATES} certificates"
            )));
        }
        let tcb_info = collateral.tcb_info.get_tcb_info().map_err(|error| {
            IntelTdxDcapCollateralError::SourceMaterial(format!("parse signed TCB Info: {error:#}"))
        })?;
        tcb_info
            .validate_id_for_tee_type(TDX_TEE_TYPE)
            .map_err(|error| {
                IntelTdxDcapCollateralError::SourceMaterial(format!(
                    "validate TCB Info type: {error:#}"
                ))
            })?;
        let tcb_identity = IntelTdxQuoteCollateralIdentity {
            fmspc: decode_signed_hex::<6>("signed TCB Info fmspc", &tcb_info.fmspc)
                .map_err(IntelTdxDcapCollateralError::SourceMaterial)?,
            pce_id: decode_signed_hex::<2>("signed TCB Info pceId", &tcb_info.pce_id)
                .map_err(IntelTdxDcapCollateralError::SourceMaterial)?,
            pck_ca: key.identity.pck_ca,
        };
        if tcb_identity.fmspc != key.identity.fmspc || tcb_identity.pce_id != key.identity.pce_id {
            return Err(IntelTdxDcapCollateralError::QuoteMismatch(format!(
                "signed TCB Info selector {} does not match quote selector {}",
                display_identity(tcb_identity),
                display_identity(key.identity)
            )));
        }

        let pck_crl_issuer = collateral.pck_crl.tbs_cert_list.issuer.to_string();
        let expected_pck_issuer = key.identity.pck_ca.expected_issuer_common_name();
        if !pck_crl_issuer.contains(expected_pck_issuer) {
            return Err(IntelTdxDcapCollateralError::QuoteMismatch(format!(
                "PCK certificate revocation list issuer {pck_crl_issuer:?} does not match {}",
                key.identity.pck_ca.pcs_query_value()
            )));
        }

        let qe_identity = collateral
            .qe_identity
            .get_enclave_identity()
            .map_err(|error| {
                IntelTdxDcapCollateralError::SourceMaterial(format!(
                    "parse signed QE Identity: {error:#}"
                ))
            })?;
        qe_identity
            .validate_id_for_tee_type(TDX_TEE_TYPE)
            .map_err(|error| {
                IntelTdxDcapCollateralError::SourceMaterial(format!(
                    "validate QE Identity type: {error:#}"
                ))
            })?;
        if tcb_info.tcb_evaluation_data_number != qe_identity.tcb_evaluation_data_number {
            return Err(IntelTdxDcapCollateralError::SourceMaterial(format!(
                "TCB Info evaluation data number {} does not match QE Identity evaluation data number {}",
                tcb_info.tcb_evaluation_data_number, qe_identity.tcb_evaluation_data_number
            )));
        }

        Ok(Self {
            key,
            tcb_evaluation_data_number: tcb_info.tcb_evaluation_data_number,
            qe_identity_evaluation_data_number: qe_identity.tcb_evaluation_data_number,
            collateral: Arc::new(collateral),
        })
    }

    pub fn key(&self) -> IntelTdxCollateralKey {
        self.key
    }

    pub fn tcb_evaluation_data_number(&self) -> u32 {
        self.tcb_evaluation_data_number
    }

    pub fn qe_identity_evaluation_data_number(&self) -> u32 {
        self.qe_identity_evaluation_data_number
    }

    pub fn parsed(&self) -> &Collateral {
        &self.collateral
    }

    pub fn ensure_quote_matches(&self, quote: &[u8]) -> Result<(), IntelTdxDcapCollateralError> {
        let identity = intel_tdx_quote_collateral_identity(quote)?;
        if identity == self.key.identity {
            return Ok(());
        }
        Err(IntelTdxDcapCollateralError::QuoteMismatch(format!(
            "collateral selector {} does not match quote selector {}",
            display_identity(self.key.identity),
            display_identity(identity)
        )))
    }
}

pub fn intel_tdx_quote_collateral_identity(
    raw_quote: &[u8],
) -> Result<IntelTdxQuoteCollateralIdentity, IntelTdxDcapCollateralError> {
    if raw_quote.len() > MAX_TDX_QUOTE_BYTES {
        return Err(IntelTdxDcapCollateralError::Quote(format!(
            "quote exceeds {MAX_TDX_QUOTE_BYTES} bytes"
        )));
    }
    let mut quote_bytes = raw_quote;
    let quote = Quote::read(&mut quote_bytes)
        .map_err(|error| IntelTdxDcapCollateralError::Quote(error.to_string()))?;
    if quote.header.tee_type != TDX_TEE_TYPE || !matches!(quote.header.version.get(), 4 | 5) {
        return Err(IntelTdxDcapCollateralError::Quote(format!(
            "expected a TDX quote with version 4 or 5, got tee_type 0x{:x} and version {}",
            quote.header.tee_type,
            quote.header.version.get()
        )));
    }
    let nonzero_trailing_bytes = quote_bytes.iter().filter(|byte| **byte != 0).count();
    if nonzero_trailing_bytes != 0 {
        return Err(IntelTdxDcapCollateralError::Quote(format!(
            "quote has {nonzero_trailing_bytes} non-zero trailing bytes"
        )));
    }
    let pck_data = quote.signature.get_pck_cert_chain().map_err(|error| {
        IntelTdxDcapCollateralError::Quote(format!("extract PCK certificate chain: {error:#}"))
    })?;
    if pck_data.pck_cert_chain.len() < 2 {
        return Err(IntelTdxDcapCollateralError::Quote(format!(
            "PCK certificate chain must contain at least 2 certificates, got {}",
            pck_data.pck_cert_chain.len()
        )));
    }
    let pck_leaf = &pck_data.pck_cert_chain[0];
    let issuer = pck_leaf.tbs_certificate.issuer.to_string();
    let pck_ca = if issuer.contains(INTEL_PCK_PLATFORM_CA_CN) {
        IntelTdxPckCa::Platform
    } else if issuer.contains(INTEL_PCK_PROCESSOR_CA_CN) {
        IntelTdxPckCa::Processor
    } else {
        return Err(IntelTdxDcapCollateralError::Quote(format!(
            "unrecognized PCK certificate issuer: {issuer}"
        )));
    };
    Ok(IntelTdxQuoteCollateralIdentity {
        fmspc: pck_data.pck_extension.fmspc,
        pce_id: pck_data.pck_extension.pceid,
        pck_ca,
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntelTdxCollateralFileV1 {
    schema: String,
    version: u8,
    selector: IntelTdxCollateralFileSelectorV1,
    payload: IntelTdxCollateralFilePayloadV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntelTdxCollateralFileSelectorV1 {
    fmspc: String,
    pce_id: String,
    pck_ca: IntelTdxPckCa,
    tcb_evaluation_data_number: u32,
    qe_identity_evaluation_data_number: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntelTdxCollateralFilePayloadV1 {
    root_ca_crl_der: String,
    pck_crl_der: String,
    issuer_chain_der: Vec<String>,
    tcb_info_signed_json: String,
    qe_identity_signed_json: String,
}

fn decode_selector_hex<const N: usize>(
    field: &str,
    value: &str,
) -> Result<[u8; N], IntelTdxDcapCollateralError> {
    if value.len() != N * 2
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(IntelTdxDcapCollateralError::File(format!(
            "{field} must contain exactly {} lowercase hexadecimal characters",
            N * 2
        )));
    }
    let decoded = hex::decode(value)
        .map_err(|error| IntelTdxDcapCollateralError::File(format!("decode {field}: {error}")))?;
    decoded.try_into().map_err(|_| {
        IntelTdxDcapCollateralError::File(format!("{field} has an invalid decoded length"))
    })
}

fn decode_signed_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{field} must contain exactly {} hexadecimal characters",
            N * 2
        ));
    }
    let decoded = hex::decode(value).map_err(|error| format!("decode {field}: {error}"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{field} has an invalid decoded length"))
}

fn decode_component(field: &str, value: &str) -> Result<Vec<u8>, IntelTdxDcapCollateralError> {
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        IntelTdxDcapCollateralError::File(format!("{field} is not unpadded base64url: {error}"))
    })?;
    if decoded.len() > MAX_COLLATERAL_COMPONENT_BYTES {
        return Err(IntelTdxDcapCollateralError::File(format!(
            "{field} exceeds {MAX_COLLATERAL_COMPONENT_BYTES} decoded bytes"
        )));
    }
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(IntelTdxDcapCollateralError::File(format!(
            "{field} is not canonical unpadded base64url"
        )));
    }
    Ok(decoded)
}

fn decode_utf8_component(field: &str, value: &str) -> Result<String, IntelTdxDcapCollateralError> {
    String::from_utf8(decode_component(field, value)?).map_err(|error| {
        IntelTdxDcapCollateralError::File(format!("{field} is not UTF-8: {error}"))
    })
}

fn display_identity(identity: IntelTdxQuoteCollateralIdentity) -> String {
    format!(
        "fmspc={} pceId={} pckCa={}",
        hex::encode(identity.fmspc),
        hex::encode(identity.pce_id),
        identity.pck_ca.pcs_query_value()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_versioned_file_fields_before_quote_parsing() {
        let document = serde_json::json!({
            "schema": INTEL_TDX_COLLATERAL_SCHEMA,
            "version": 1,
            "selector": {
                "fmspc": "000000000000",
                "pceId": "0000",
                "pckCa": "processor",
                "tcbEvaluationDataNumber": 1,
                "qeIdentityEvaluationDataNumber": 1
            },
            "payload": {
                "rootCaCrlDer": "",
                "pckCrlDer": "",
                "issuerChainDer": [],
                "tcbInfoSignedJson": "",
                "qeIdentitySignedJson": "",
                "unexpected": true
            }
        });
        let error = IntelTdxDcapCollateral::from_file_json(&document.to_string(), &[])
            .expect_err("unknown fields must be rejected");
        assert!(error.to_string().contains("unknown field `unexpected`"));
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
        let error = IntelTdxDcapCollateral::from_file_json(&legacy.to_string(), &[])
            .expect_err("the former QuoteCollateralV3 JSON shape must not parse");
        assert!(matches!(error, IntelTdxDcapCollateralError::File(_)));
    }

    #[test]
    fn file_selector_requires_lowercase_but_signed_fields_allow_uppercase() {
        assert!(decode_selector_hex::<2>("selector.pceId", "00AF").is_err());
        assert_eq!(
            decode_signed_hex::<2>("signed TCB Info pceId", "00AF").unwrap(),
            [0x00, 0xaf]
        );
    }
}
