use dcap_rs::types::collateral::Collateral;
use serde::{Deserialize, Serialize};

/// Stable JSON form used in `collateral.gcpTdxDcap`.
///
/// This keeps the field names and byte-array encoding used by
/// `dcap_qvl::QuoteCollateralV3`. Existing collateral files therefore remain
/// valid after the verifier moves to Automata's `dcap-rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxDcapCollateral {
    pub pck_crl_issuer_chain: String,
    #[serde(with = "serde_bytes")]
    pub root_ca_crl: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    #[serde(with = "serde_bytes")]
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    #[serde(with = "serde_bytes")]
    pub qe_identity_signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pck_certificate_chain: Option<String>,
}

impl TdxDcapCollateral {
    /// Convert the stable transport form into Automata's verifier input.
    pub fn to_automata_collateral(&self) -> Result<Collateral, String> {
        if !issuer_chains_match(&self.tcb_info_issuer_chain, &self.qe_identity_issuer_chain) {
            return Err(
                "TCB info and QE identity issuer chains differ; Automata dcap-rs requires one shared issuer chain"
                    .to_string(),
            );
        }

        let tcb_info = signed_collateral_json("tcbInfo", &self.tcb_info, &self.tcb_info_signature)?;
        let qe_identity = signed_collateral_json(
            "enclaveIdentity",
            &self.qe_identity,
            &self.qe_identity_signature,
        )?;

        Collateral::new(
            &self.root_ca_crl,
            &self.pck_crl,
            self.tcb_info_issuer_chain.as_bytes(),
            &tcb_info,
            &qe_identity,
        )
        .map_err(|error| format!("build Automata DCAP collateral: {error:#}"))
    }
}

fn signed_collateral_json(
    body_field: &'static str,
    body: &str,
    signature: &[u8],
) -> Result<String, String> {
    let body: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| format!("{body_field} is not valid JSON: {error}"))?;
    let mut signed = serde_json::Map::new();
    signed.insert(body_field.to_string(), body);
    signed.insert(
        "signature".to_string(),
        serde_json::Value::String(hex::encode(signature)),
    );
    serde_json::to_string(&signed)
        .map_err(|error| format!("serialize signed {body_field}: {error}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_quote_collateral_v3_json_shape() {
        let collateral = TdxDcapCollateral {
            pck_crl_issuer_chain: "pck".to_string(),
            root_ca_crl: vec![1, 2],
            pck_crl: vec![3, 4],
            tcb_info_issuer_chain: "issuer".to_string(),
            tcb_info: "{}".to_string(),
            tcb_info_signature: vec![5, 6],
            qe_identity_issuer_chain: "issuer".to_string(),
            qe_identity: "{}".to_string(),
            qe_identity_signature: vec![7, 8],
            pck_certificate_chain: Some("pck-chain".to_string()),
        };

        let value = serde_json::to_value(collateral).expect("serialize collateral");
        assert_eq!(value["root_ca_crl"], serde_json::json!([1, 2]));
        assert_eq!(value["pck_crl"], serde_json::json!([3, 4]));
        assert_eq!(value["tcb_info_signature"], serde_json::json!([5, 6]));
        assert_eq!(value["qe_identity_signature"], serde_json::json!([7, 8]));
        assert_eq!(value["pck_certificate_chain"], "pck-chain");
    }

    #[test]
    fn rejects_different_signed_collateral_issuer_chains() {
        let collateral = TdxDcapCollateral {
            pck_crl_issuer_chain: String::new(),
            root_ca_crl: Vec::new(),
            pck_crl: Vec::new(),
            tcb_info_issuer_chain: "tcb".to_string(),
            tcb_info: "{}".to_string(),
            tcb_info_signature: Vec::new(),
            qe_identity_issuer_chain: "qe".to_string(),
            qe_identity: "{}".to_string(),
            qe_identity_signature: Vec::new(),
            pck_certificate_chain: None,
        };

        assert!(collateral.to_automata_collateral().is_err());
    }

    #[test]
    fn accepts_equivalent_issuer_chain_text() {
        let certificate = pem::encode(&pem::Pem::new("CERTIFICATE", vec![1, 2, 3]));
        let windows_line_endings = certificate.replace('\n', "\r\n");

        assert!(issuer_chains_match(&certificate, &windows_line_endings));
    }
}
