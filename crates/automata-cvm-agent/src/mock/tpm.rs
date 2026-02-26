//! Mock TPM 2.0 structures (Quote and Certify).
//!
//! Builds structurally valid `TPM2B_ATTEST` blobs and dummy TPMT_SIGNATURE /
//! TPMT_PUBLIC structures.  The mock contract will skip real signature
//! verification, so signatures are filled with dummy bytes.

use alloy::primitives::{B256, Bytes};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// TPM constants (mirrors TPMConstants.sol)
// ---------------------------------------------------------------------------

/// TPM magic number: `\xffTCG` = 0xff544347
const TPM_MAGIC: u32 = 0xff544347;

/// TPM_ST_ATTEST_QUOTE = 0x8018
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// TPM_ST_ATTEST_CERTIFY = 0x8017
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;

/// TPM_ALG_SHA256 = 0x000B
const TPM_ALG_SHA256: u16 = 0x000B;

/// TPM_ALG_ECC = 0x0023
const TPM_ALG_ECC: u16 = 0x0023;

/// TPM_ALG_ECDSA = 0x0018
const TPM_ALG_ECDSA: u16 = 0x0018;

/// TPM_ALG_NULL = 0x0010
const TPM_ALG_NULL: u16 = 0x0010;

/// TPM_ECC_NIST_P256 = 0x0003
const TPM_ECC_NIST_P256: u16 = 0x0003;

// ---------------------------------------------------------------------------
// TPM2B_ATTEST builder (common header)
// ---------------------------------------------------------------------------

/// Build the common TPMS_ATTEST header shared by both Quote and Certify types.
///
/// Layout (big-endian):
/// ```text
/// magic                4 bytes  (0xff544347)
/// type                 2 bytes  (att_type)
/// qualifiedSigner      2+N bytes (TPM2B: length prefix + data)
/// extraData            2+M bytes (TPM2B: length prefix + data)
/// clockInfo           17 bytes  (clock:8 + resetCount:4 + restartCount:4 + safe:1)
/// firmwareVersion      8 bytes
/// ```
fn build_attest_header(att_type: u16, extra_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // magic
    buf.extend_from_slice(&TPM_MAGIC.to_be_bytes());
    // type
    buf.extend_from_slice(&att_type.to_be_bytes());

    // qualifiedSigner (TPM2B) - empty for mock
    buf.extend_from_slice(&0u16.to_be_bytes());

    // extraData (TPM2B)
    buf.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
    buf.extend_from_slice(extra_data);

    // clockInfo (17 bytes): clock=0, resetCount=0, restartCount=0, safe=1
    buf.extend_from_slice(&0u64.to_be_bytes()); // clock
    buf.extend_from_slice(&0u32.to_be_bytes()); // resetCount
    buf.extend_from_slice(&0u32.to_be_bytes()); // restartCount
    buf.push(1); // safe = true

    // firmwareVersion (8 bytes)
    buf.extend_from_slice(&0u64.to_be_bytes());

    buf
}

// ---------------------------------------------------------------------------
// TPM Quote
// ---------------------------------------------------------------------------

/// Build a mock TPM2B_ATTEST for a TPM2_Quote command.
///
/// The `extra_data` field carries the nonce used for replay protection.
/// `pcr_indices` and `pcr_digest` describe the PCR selection and composite
/// digest that the on-chain verifier will check.
///
/// # Arguments
///
/// * `extra_data`  - The nonce / extraData field
/// * `pcr_indices` - Sorted list of selected PCR indices
/// * `pcr_digest`  - 32-byte SHA-256 digest of the concatenated PCR values
pub fn build_tpm_quote(extra_data: &[u8], pcr_indices: &[usize], pcr_digest: B256) -> Bytes {
    let mut buf = build_attest_header(TPM_ST_ATTEST_QUOTE, extra_data);

    // TPMS_QUOTE_INFO:
    //   count: 4 bytes (must be 1 for the on-chain verifier)
    buf.extend_from_slice(&1u32.to_be_bytes());

    //   TPMS_PCR_SELECTION[0]:
    //     hash: 2 bytes (TPM_ALG_SHA256)
    buf.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());

    //     sizeofSelect: 1 byte
    let pcr_select_size: u8 = 4; // 4 bytes = 32 PCR bits
    buf.push(pcr_select_size);

    //     pcrSelect: 4 bytes (bitmap, little-endian byte order)
    let bitmap = super::pcr::PcrBank::selection_bitmap(pcr_indices);
    buf.extend_from_slice(&bitmap);

    //   pcrDigest (TPM2B): 2-byte length + 32-byte digest
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(pcr_digest.as_slice());

    buf.into()
}

/// Build a TPMT_SIGNATURE for ECDSA-P256-SHA256 with real (r, s) values.
///
/// Layout (big-endian):
/// ```text
/// scheme   2 bytes (TPM_ALG_ECDSA = 0x0018)
/// hashAlg  2 bytes (TPM_ALG_SHA256 = 0x000B)
/// r.size   2 bytes (32)
/// r        32 bytes
/// s.size   2 bytes (32)
/// s        32 bytes
/// ```
pub fn build_ecdsa_signature(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(72);
    buf.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
    buf.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(r);
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(s);
    buf
}

// ---------------------------------------------------------------------------
// TPM Certify
// ---------------------------------------------------------------------------

/// Build a mock TPM2B_ATTEST for a TPM2_Certify command.
///
/// The certified key name is `nameAlg(2) || SHA256(tpmt_public)` and is
/// embedded in the TPMS_CERTIFY_INFO portion of the structure.
///
/// # Arguments
///
/// * `extra_data`  - The nonce / extraData field
/// * `tpmt_public` - The marshalled TPMT_PUBLIC of the certified key
pub fn build_tpm_certify(extra_data: &[u8], tpmt_public: &[u8]) -> Vec<u8> {
    let mut buf = build_attest_header(TPM_ST_ATTEST_CERTIFY, extra_data);

    // TPMS_CERTIFY_INFO:
    //   name (TPM2B_NAME): nameAlg || Hash(tpmtPublic)
    let name_hash: [u8; 32] = Sha256::digest(tpmt_public).into();
    let name_len = 2 + 32; // nameAlg(2) + hash(32) = 34 bytes
    buf.extend_from_slice(&(name_len as u16).to_be_bytes());
    buf.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // nameAlg
    buf.extend_from_slice(&name_hash);

    //   qualifiedName (TPM2B_NAME): empty for mock
    buf.extend_from_slice(&0u16.to_be_bytes());

    buf
}

// ---------------------------------------------------------------------------
// TPMT_PUBLIC builder (ECC P-256)
// ---------------------------------------------------------------------------

/// Build a mock TPMT_PUBLIC structure for an ECC P-256 key.
///
/// Layout:
/// ```text
/// type            2 bytes (TPM_ALG_ECC = 0x0023)
/// nameAlg         2 bytes (TPM_ALG_SHA256 = 0x000B)
/// objectAttributes 4 bytes
/// authPolicy      2+0 bytes (TPM2B, empty)
/// [TPMS_ECC_PARMS]:
///   symmetric     2 bytes (TPM_ALG_NULL)
///   scheme        2 bytes (TPM_ALG_NULL)
///   curveID       2 bytes (TPM_ECC_NIST_P256 = 0x0003)
///   kdf           2 bytes (TPM_ALG_NULL)
/// [TPMS_ECC_POINT]:
///   x             2+32 bytes (TPM2B)
///   y             2+32 bytes (TPM2B)
/// ```
///
/// # Arguments
///
/// * `pub_x`            - 32-byte X coordinate of the EC public key
/// * `pub_y`            - 32-byte Y coordinate of the EC public key
/// * `object_attributes` - TPMA_OBJECT flags (e.g., `0x00060072` for sign+decrypt+fixedTPM+fixedParent)
pub fn build_tpmt_public_ecc(
    pub_x: &[u8; 32],
    pub_y: &[u8; 32],
    object_attributes: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);

    // type
    buf.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    // nameAlg
    buf.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    // objectAttributes
    buf.extend_from_slice(&object_attributes.to_be_bytes());
    // authPolicy (TPM2B, empty)
    buf.extend_from_slice(&0u16.to_be_bytes());

    // TPMS_ECC_PARMS
    buf.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
    buf.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme
    buf.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes()); // curveID
    buf.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf

    // TPMS_ECC_POINT (unique)
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(pub_x);
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(pub_y);

    buf
}
