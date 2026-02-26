//! ABI-encodable Solidity struct definitions for TPM report data.
//!
//! These types mirror the on-chain Solidity structs and are used by
//! [`MockDeviceProvider`](super::device::MockDeviceProvider) to produce
//! ABI-encoded TPM quote and certify reports.

// ---------------------------------------------------------------------------
// ABI-encodable types (match the Solidity structs)
// ---------------------------------------------------------------------------

alloy::sol! {
    struct TpmQuoteReportSol {
        bytes tpm2bAttest;
        bytes tpmSignature;
        PcrValueSol[] pcrValues;
    }

    #[derive(Debug)]
    struct PcrValueSol {
        uint8 pcrIndex;
        bytes32 value;
        bytes32[] eventLogHashes;
    }

    struct TpmCertifyReportSol {
        bytes tpm2bAttest;
        bytes tpmSignature;
        bytes tpmtPublic;
    }
}
