use dcap_rs::types::collateral::Collateral;

/// Parsed source material for Intel TDX DCAP quote verification.
///
/// This type is an in-process verifier input. It is not part of the portal
/// response wire format. The portal returns only the raw Intel TDQUOTE.
#[derive(Debug, Clone)]
pub struct IntelTdxDcapCollateral {
    root_ca_crl_der: Vec<u8>,
    pck_crl_der: Vec<u8>,
    tcb_info_and_qe_identity_issuer_chain_pem: String,
    tcb_info_json: String,
    qe_identity_json: String,
}

impl IntelTdxDcapCollateral {
    /// Validate and retain the five inputs required by Automata `dcap-rs`.
    pub fn new(
        root_ca_crl_der: Vec<u8>,
        pck_crl_der: Vec<u8>,
        tcb_info_and_qe_identity_issuer_chain_pem: String,
        tcb_info_json: String,
        qe_identity_json: String,
    ) -> Result<Self, String> {
        let collateral = Self {
            root_ca_crl_der,
            pck_crl_der,
            tcb_info_and_qe_identity_issuer_chain_pem,
            tcb_info_json,
            qe_identity_json,
        };
        collateral.to_dcap_collateral()?;
        Ok(collateral)
    }

    /// Build the owned value consumed by Automata `dcap-rs`.
    pub fn to_dcap_collateral(&self) -> Result<Collateral, String> {
        Collateral::new(
            &self.root_ca_crl_der,
            &self.pck_crl_der,
            self.tcb_info_and_qe_identity_issuer_chain_pem.as_bytes(),
            &self.tcb_info_json,
            &self.qe_identity_json,
        )
        .map_err(|error| format!("build Intel TDX DCAP collateral: {error:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_dcap_source_material() {
        let error = IntelTdxDcapCollateral::new(
            Vec::new(),
            Vec::new(),
            String::new(),
            "{}".to_string(),
            "{}".to_string(),
        )
        .expect_err("empty DCAP source material must fail");

        assert!(error.contains("build Intel TDX DCAP collateral"));
    }
}
