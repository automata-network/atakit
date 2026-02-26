//! [`DeviceProvider`] implementation backed by fixture attestation data.
//!
//! [`MockDeviceProvider`] can be constructed directly via [`MockDeviceProvider::new()`]
//! (which uses the embedded fixture), or via [`MockDataBuilder`](super::builder::MockDataBuilder)
//! for customised PCR/RTMR values.
//!
//! The mock on-chain contracts skip signature verification but still parse
//! the TPM/TDX structures, so the structural data must be genuine.

use alloy::primitives::Bytes;
use alloy::sol_types::SolValue;
use sha2::Digest;
use automata_tee_workload_measurement::stubs::{
    AkPubCollateral, AlgoId, PublicIdentity, TeeReport, TpmReport,
};

use crate::device::{DeviceProvider, PlatformInfo, TpmQuoteResult};
use crate::mock::builder::MockDataBuilder;

use super::builder::P256Key;
use super::evidence::{PcrValueSol, TpmCertifyReportSol, TpmQuoteReportSol};
use super::tpm;

/// Solidity verification backend (matches `VerificationBackendType.Solidity` = 0).
const VERIFICATION_BACKEND_SOLIDITY: u8 = 0;

/// AK pub collateral type for GCP certificate chains.
const AK_PUB_TYPE_GCP_CERT_CHAIN: u8 = 1;

// ---------------------------------------------------------------------------
// TPM report type constants
// ---------------------------------------------------------------------------

const TPM_REPORT_TYPE_QUOTE: u8 = 0;
const TPM_REPORT_TYPE_CERTIFY: u8 = 1;

/// Default TPM object attributes for mock signing keys.
///
/// Bits: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth
///       | adminWithPolicy | sign  (bit 18, NOT decrypt/bit 17).
///
/// Must satisfy `(attrs & TPMA_OBJECT_REQUIRED_CLEAR) == 0` on-chain,
/// where `TPMA_OBJECT_REQUIRED_CLEAR = 0xFFFBFB09`.
const MOCK_OBJECT_ATTRIBUTES: u32 = 0x000400F2;

// ---------------------------------------------------------------------------
// MockDeviceProvider
// ---------------------------------------------------------------------------

/// Mock implementation of [`DeviceProvider`] backed by fixture data.
///
/// - **AK public key**: auto-extracted from the leaf certificate DER
/// - **Signing keys**: in-memory P-256 keys simulating TPM signing keys
/// - **AK certs, PCRs, platform, TEE report**: loaded from fixture JSON
///
/// For customising PCR/RTMR values, use [`MockDataBuilder`](super::builder::MockDataBuilder).
pub struct MockDeviceProvider {
    data_builder: MockDataBuilder,
    /// Mock AK signing key — signs TPM2B_ATTEST structures (quote & certify).
    ak_signing_key: P256Key,
    signing_key: P256Key,
    tmp_signing_key: Option<P256Key>,
}

impl MockDeviceProvider {
    pub fn new(builder: MockDataBuilder) -> Self {
        Self {
            data_builder: builder,
            ak_signing_key: P256Key::random(),
            signing_key: P256Key::random(),
            tmp_signing_key: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_certify_report(ak_key: &P256Key, key: &P256Key, nonce: &[u8]) -> TpmReport {
    let tpmt_public = tpm::build_tpmt_public_ecc(&key.x, &key.y, MOCK_OBJECT_ATTRIBUTES);
    let tpm2b_attest = tpm::build_tpm_certify(nonce, &tpmt_public);

    let attest_digest = sha2::Sha256::digest(&tpm2b_attest);
    let (r, s) = ak_key.sign_digest_raw(&attest_digest);
    let tpm_signature = tpm::build_ecdsa_signature(&r, &s);

    let report_data = TpmCertifyReportSol {
        tpm2bAttest: Bytes::from(tpm2b_attest),
        tpmSignature: Bytes::from(tpm_signature),
        tpmtPublic: Bytes::from(tpmt_public),
    };

    TpmReport {
        verification_backend_type: VERIFICATION_BACKEND_SOLIDITY,
        tpm_report_type: TPM_REPORT_TYPE_CERTIFY,
        data: Bytes::from(report_data.abi_encode()),
    }
}

// ---------------------------------------------------------------------------
// DeviceProvider implementation
// ---------------------------------------------------------------------------

impl DeviceProvider for MockDeviceProvider {
    async fn get_tee_report(&self) -> anyhow::Result<TeeReport> {
        // let data_builder = self.data_builder.clone().set_tdx_report_data(report_data);
        Ok(self.data_builder.tee_report.clone())
    }

    async fn get_tpm_quote(&self, extra_data: &[u8]) -> anyhow::Result<TpmQuoteResult> {
        let indices = self.data_builder.pcr_bank.indices();
        let pcr_digest = self.data_builder.pcr_bank.digest(indices);
        let tpm2b_attest = tpm::build_tpm_quote(extra_data, indices, pcr_digest);

        let attest_digest = sha2::Sha256::digest(&tpm2b_attest);
        let (r, s) = self.ak_signing_key.sign_digest_raw(&attest_digest);
        let tpm_sig = tpm::build_ecdsa_signature(&r, &s);

        let pcr_values: Vec<PcrValueSol> = indices
            .iter()
            .map(|&i| PcrValueSol {
                pcrIndex: i as u8,
                value: *self.data_builder.pcr_bank.get(i),
                eventLogHashes: vec![],
            })
            .collect();

        let report_data = TpmQuoteReportSol {
            tpm2bAttest: Bytes::from(tpm2b_attest),
            tpmSignature: Bytes::from(tpm_sig.clone()),
            pcrValues: pcr_values,
        };

        let tpm_report = TpmReport {
            verification_backend_type: VERIFICATION_BACKEND_SOLIDITY,
            tpm_report_type: TPM_REPORT_TYPE_QUOTE,
            data: Bytes::from(report_data.abi_encode()),
        };

        Ok(TpmQuoteResult {
            tpm_report,
            tpm_signature: Bytes::from(tpm_sig),
        })
    }

    fn get_signing_key_public(&self) -> anyhow::Result<PublicIdentity> {
        Ok(PublicIdentity {
            type_id: AlgoId::Es256 as u8,
            key: Bytes::from(self.signing_key.uncompressed()),
        })
    }

    async fn sign_with_signing_key(&self, digest: &[u8]) -> anyhow::Result<Bytes> {
        Ok(Bytes::from(self.signing_key.sign_digest(digest)))
    }

    async fn certify_signing_key(&self) -> anyhow::Result<TpmReport> {
        Ok(build_certify_report(&self.ak_signing_key, &self.signing_key, &[0u8; 32]))
    }

    async fn get_ak_pub_collateral(&self) -> anyhow::Result<AkPubCollateral> {
        Ok(AkPubCollateral {
            ak_pub_collateral_type: AK_PUB_TYPE_GCP_CERT_CHAIN,
            data: self.data_builder.ak_certs_encoded(),
        })
    }

    fn get_ak_pub(&self) -> anyhow::Result<PublicIdentity> {
        Ok(PublicIdentity {
            type_id: AlgoId::Es256 as u8,
            key: Bytes::from(self.data_builder.ak_pub().uncompressed()),
        })
    }

    fn get_platform_info(&self) -> PlatformInfo {
        self.data_builder.platform_info.clone()
    }

    async fn create_tmp_signing_key(&mut self) -> anyhow::Result<()> {
        self.tmp_signing_key = Some(P256Key::random());
        Ok(())
    }

    fn get_tmp_signing_key_public(&self) -> anyhow::Result<PublicIdentity> {
        let key = self
            .tmp_signing_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no temporary signing key created"))?;
        Ok(PublicIdentity {
            type_id: AlgoId::Es256 as u8,
            key: Bytes::from(key.uncompressed()),
        })
    }

    async fn sign_with_tmp_key(&self, digest: &[u8]) -> anyhow::Result<Bytes> {
        let key = self
            .tmp_signing_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no temporary signing key created"))?;
        Ok(Bytes::from(key.sign_digest(digest)))
    }

    async fn certify_tmp_signing_key(&self) -> anyhow::Result<TpmReport> {
        let key = self
            .tmp_signing_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no temporary signing key created"))?;
        Ok(build_certify_report(&self.ak_signing_key, key, &[0u8; 32]))
    }

    async fn promote_tmp_key(&mut self) -> anyhow::Result<()> {
        let key = self
            .tmp_signing_key
            .take()
            .ok_or_else(|| anyhow::anyhow!("no temporary signing key to promote"))?;
        self.signing_key = key;
        Ok(())
    }
}
