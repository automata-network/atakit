//! Authorization digests for session registration and key rotation.
//!
//! Adapted from atakit-portal-chain at 079cb59c3434926890f0017a19b9684f86dddfb5.
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use sha2::{Digest, Sha256};

/// Compute the SHA-256 digest authorizing session registration.
#[allow(clippy::too_many_arguments)]
pub fn compute_owner_signature_payload(
    chain_id: u64,
    registry_address: Address,
    op_expires_at: u64,
    session_id: B256,
    workload_id: B256,
    base_image_id: B256,
    platform_profile_id: B256,
    variant_id: B256,
    session_key_fingerprint: B256,
) -> [u8; 32] {
    // abi.encode(bytes32, uint256, address, uint64, bytes32, bytes32,
    //            bytes32, bytes32, bytes32, bytes32) =
    //   10 * 32 = 320 bytes (all static; address + uint64 padded).
    let encoded = (
        keccak256("CVM_MSG_SESSION_REGISTER_V1"),
        U256::from(chain_id),
        registry_address,
        op_expires_at,
        session_id,
        workload_id,
        base_image_id,
        platform_profile_id,
        variant_id,
        session_key_fingerprint,
    )
        .abi_encode_params();
    let mut h = Sha256::new();
    h.update(&encoded);
    h.finalize().into()
}

/// Compute the digest authorizing replacement of a TPM signing key.
pub fn compute_rotate_key_tpm_payload(
    chain_id: u64,
    registry_address: Address,
    old_session_id: B256,
    new_tpm_signing_key_fingerprint: B256,
    new_session_key_fingerprint: B256,
    tee_report_bytes_hash: B256,
) -> B256 {
    keccak256(
        (
            keccak256("CVM_SESSION_ROTATE_KEY_V1"),
            U256::from(chain_id),
            registry_address,
            old_session_id,
            new_tpm_signing_key_fingerprint,
            new_session_key_fingerprint,
            tee_report_bytes_hash,
        )
            .abi_encode_params(),
    )
}

/// Compute the SHA-256 digest authorizing session rotation.
pub fn compute_rotate_key_owner_payload(
    chain_id: u64,
    registry_address: Address,
    op_expires_at: u64,
    old_session_id: B256,
    new_session_id: B256,
) -> [u8; 32] {
    Sha256::digest(
        (
            keccak256("CVM_MSG_SESSION_ROTATE_KEY_V1"),
            U256::from(chain_id),
            registry_address,
            op_expires_at,
            old_session_id,
            new_session_id,
        )
            .abi_encode_params(),
    )
    .into()
}
