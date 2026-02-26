//! Mock attestation data generation for local development and testing.
//!
//! Constructs structurally valid TDX reports, TPM quotes/certify structures,
//! PCR banks, and AK collateral that the mock Solidity contracts will accept
//! without real signature verification.

pub mod builder;
pub mod mock_device;
pub mod evidence;
pub mod pcr;
pub mod tpm;
