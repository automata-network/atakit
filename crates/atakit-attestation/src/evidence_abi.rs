//! Solidity ABI payloads and discriminants for session attestation evidence.
//!
//! Adapted from atakit-portal-chain at 079cb59c3434926890f0017a19b9684f86dddfb5.
//! These byte payloads are distinct from the JSON evidence types used for verification.
use alloy_sol_types::{sol, SolValue};

// JSON ABI represents Solidity enums as uint8. Keep their named values here.
/// Backend used to verify an attestation report.
#[repr(u8)]
pub enum VerificationBackendType {
    Solidity = 0,
    ZkRiscZero = 1,
    ZkSuccinct = 2,
}
/// TEE report format accepted by the session registry.
#[repr(u8)]
pub enum TEEType {
    IntelTDX = 0,
    AmdSevSnp = 1,
}
/// TPM attestation command represented by a report.
#[repr(u8)]
pub enum TpmReportType {
    TpmQuote = 0,
    TpmCertify = 1,
}
/// Provider collateral used to authenticate an attestation key.
#[repr(u8)]
pub enum AkPubCollateralType {
    AzureMaaJwt = 0,
    GcpCertChain = 1,
    AwsNitroTpmProof = 2,
}

sol! {
    /// Inner TPM certify payload encoded according to Evidence.sol.
    struct TpmCertifyEvidence {
        bytes tpmsAttest;
        bytes tpmSignature;
        bytes tpmtPublic;
    }
}

/// Build the inner TPM certify payload.
pub fn tpm_certify_evidence(
    tpms_attest: Vec<u8>,
    tpm_signature: Vec<u8>,
    tpmt_public: Vec<u8>,
) -> TpmCertifyEvidence {
    TpmCertifyEvidence {
        tpmsAttest: tpms_attest.into(),
        tpmSignature: tpm_signature.into(),
        tpmtPublic: tpmt_public.into(),
    }
}

/// Encode TPM delegation and session-key possession signatures.
pub fn encode_session_key_authorization(
    tpm_delegation_signature: &[u8],
    session_key_possession_signature: &[u8],
) -> Vec<u8> {
    (
        tpm_delegation_signature.to_vec(),
        session_key_possession_signature.to_vec(),
    )
        .abi_encode_params()
}

/// Encode the GCP attestation key certificate chain.
pub fn encode_gcp_cert_chain_data(certs: &[Vec<u8>]) -> Vec<u8> {
    (certs.to_vec(),).abi_encode_params()
}
