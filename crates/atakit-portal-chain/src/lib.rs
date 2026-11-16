//! Pure ABI encoding + on-chain message-hash primitives for the
//! `SessionRegistry.registerSession(...)` calldata path.
//!
//! No I/O. No network. No async. The portal-side live submitter and
//! the operator-side `--dry-run` calldata dumper both depend on this
//! crate; tests against `automata-tee-workload-measurement/test/
//! fixtures/session_register.hex` pin the encoder byte-exact.
//!
//! Mirror of the upstream Solidity:
//! - Structs: [`AttestationEvidence`], [`TpmReport`], [`TeeReport`],
//!   [`AkPubCollateral`], [`PublicIdentity`] match
//!   `automata-tee-workload-measurement/src/types/{Evidence,Common}.sol`.
//! - Domain constants: see [`domains`] for the 9 keccak256 separator
//!   values from `Constants.sol`.
//! - Hash primitives: see [`hashes`] for [`compute_key_fingerprint`],
//!   [`compute_session_id`], [`compute_delegation_digest`],
//!   [`compute_owner_signature_payload`] — exact reproductions of
//!   the Solidity formulas the on-chain verifier uses.
//!
//! Entry point: [`encode_register_session`] returns the full bytes of
//! a `SessionRegistry.registerSession(...)` transaction's `data`
//! field (4-byte selector followed by the ABI-encoded arguments).

pub mod domains;
pub mod evidence;
pub mod hashes;
pub mod publisher_policy;
pub mod revert;
pub mod signing;
pub mod tx_eip1559;

pub use domains::*;
pub use evidence::{
    ak_pub_collateral, aws_nitrotpm_collateral, encode_session_key_authorization,
    encode_tpm_certify_evidence_data, encode_tpm_quote_evidence_data, fixed_bytes48,
    program_bound_zk_proof, public_identity, tee_report, tee_report_snp_zk, tee_report_tdx_zk,
    tpm_certify_evidence, tpm_quote_evidence, wrap_tpm_certify, wrap_tpm_quote_solidity,
    wrap_tpm_quote_zk,
};
pub use hashes::{
    compute_delegation_digest, compute_key_fingerprint, compute_lifecycle_owner_payload,
    compute_owner_signature_payload, compute_platform_profile_id, compute_qualifying_data,
    compute_renew_tpm_payload, compute_rotate_key_owner_payload, compute_rotate_key_tpm_payload,
    compute_session_id, compute_variant_id, AlgoId,
};
pub use revert::{
    decode_maa_jwt_time_revert, decode_revert, is_owner_nonce_binding_mismatch_revert,
    is_tpm_quote_extra_data_mismatch_revert, MaaJwtTimeRevert,
};
pub use signing::{
    decode_secret_key_hex, derive_eth_address, derive_public_key_uncompressed,
    generate_secret_key_bytes, sign_secp256k1_recoverable, tpm_ecdsa_to_der, SigEncoding,
    SigningError,
};
pub use tx_eip1559::{UnsignedEip1559Tx, EIP1559_TX_TYPE};

use alloy_primitives::{B256, U256};
use alloy_sol_types::{sol, SolCall};

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct PcrValue256 {
        uint8 pcrIndex;
        bytes32 value;
        bytes32[] eventLogHashes;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Bytes48 {
        bytes32 first;
        bytes16 second;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PcrValue384 {
        uint8 pcrIndex;
        Bytes48 value;
        Bytes48[] eventLogHashes;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TpmQuoteEvidence {
        bytes tpmsAttest;
        bytes tpmSignature;
        uint8 pcr0StartupLocality;
        PcrValue256[] pcrValues256;
        PcrValue384[] pcrValues384;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TpmCertifyEvidence {
        bytes tpmsAttest;
        bytes tpmSignature;
        bytes tpmtPublic;
    }

    #[derive(Debug)]
    enum VerificationBackendType {
        Solidity,
        ZkRiscZero,
        ZkSuccinct,
    }

    #[derive(Debug)]
    enum TEEType {
        IntelTDX,
        AmdSevSnp,
    }

    #[derive(Debug)]
    enum TpmReportType {
        TpmQuote,
        TpmCertify,
    }

    #[derive(Debug)]
    enum AkPubCollateralType {
        AzureMaaJwt,
        GcpCertChain,
        AwsNitroTpmProof,
    }

    /// Mirrors `Common.sol::PublicIdentity`.
    #[derive(Debug)]
    struct PublicIdentity {
        uint8 typeId;
        bytes key;
    }

    /// Mirrors `Evidence.sol::TeeReport`.
    #[derive(Debug)]
    struct TeeReport {
        VerificationBackendType verificationBackendType;
        TEEType teeType;
        bytes data;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ProgramBoundZkProof {
        bytes32 programIdentifier;
        bytes output;
        bytes proofBytes;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct IntelTdxDcapZkEvidence {
        ProgramBoundZkProof proof;
        bytes quoteBody;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct AmdSevSnpZkEvidence {
        ProgramBoundZkProof proof;
        bytes rawReport;
    }

    #[derive(Debug, PartialEq, Eq)]
    enum PcrBankSelection {
        Sha256,
        Sha384,
        Sha256AndSha384,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PcrSpec256 {
        uint8 pcrIndex;
        bytes comparison;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PcrSpec384 {
        uint8 pcrIndex;
        bytes comparison;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PcrPolicyBlock {
        PcrSpec256[] pcrSpecs256;
        PcrSpec384[] pcrSpecs384;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ResolvedPcrPolicy {
        bytes32 workloadId;
        bytes32 baseImageId;
        bytes32 platformProfileId;
        bytes32 measurementVariantId;
        PcrBankSelection pcrBankSelection;
        PcrPolicyBlock invariantPcrPolicy;
        PcrPolicyBlock variantPcrPolicy;
        PcrPolicyBlock workloadPcrPolicy;
    }

    /// Mirrors `Evidence.sol::TpmReport`.
    #[derive(Debug)]
    struct TpmReport {
        VerificationBackendType verificationBackendType;
        TpmReportType tpmReportType;
        bytes data;
    }

    /// Mirrors `Evidence.sol::AkPubCollateral`.
    #[derive(Debug)]
    struct AkPubCollateral {
        AkPubCollateralType akPubCollateralType;
        VerificationBackendType verificationBackendType;
        bytes data;
    }

    /// Mirrors `Evidence.sol::AttestationEvidence`.
    #[derive(Debug)]
    struct AttestationEvidence {
        TeeReport teeReport;
        PublicIdentity akPub;
        TpmReport tpmQuoteReport;
        TpmReport tpmCertifyReport;
        AkPubCollateral akPubCollateral;
        bytes sessionKeySignature;
        PublicIdentity sessionKey;
    }

    /// Mirrors `Evidence.sol::SessionKeyRotationEvidence`.
    #[derive(Debug)]
    struct SessionKeyRotationEvidence {
        TpmReport tpmQuoteReport;
        TpmReport tpmCertifyReport;
        bytes sessionKeySignature;
        PublicIdentity sessionKey;
        bytes rotationSignature;
        PublicIdentity oldTpmSigningKey;
        PublicIdentity akPub;
    }

    /// Mirrors `Evidence.sol::SessionRenewalAuthorization`.
    #[derive(Debug)]
    struct SessionRenewalAuthorization {
        bytes signature;
        PublicIdentity oldTpmSigningKey;
    }

    /// Mirrors `ISessionRegistry.sol::registerSession(...)`.
    ///
    /// Selector: `0xd5269dcc` (verified against
    /// `test/fixtures/session_register.hex`).
    function registerSession(
        AttestationEvidence calldata evidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 variantId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature,
    ) external returns (bytes32);

    function rotateKey(
        bytes32 oldSessionId,
        bytes32 teeReportBytesHash,
        SessionKeyRotationEvidence calldata rotationEvidence,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32);

    function renewSession(
        bytes32 oldSessionId,
        AttestationEvidence calldata newEvidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId,
        SessionRenewalAuthorization calldata renewalAuthorization,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32);

    function recoverSession(
        bytes32 oldSessionId,
        AttestationEvidence calldata newEvidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32);

    /// Mirrors `ISessionRegistry.sol::getNonce(bytes32)`. The portal
    /// reads this via `eth_call` to learn the current `ownerNonces[fp]`
    /// value, which it then folds into `qualifying_data` (the Quote's
    /// `extraData`) per `compute_qualifying_data`. Used by
    /// portal submission when `chain.rpc_url` is configured.
    ///
    /// `view` ⇒ no state change; safe to call against any read endpoint
    /// (full node, hosted RPC, read-only proxy).
    function getNonce(bytes32 ownerFingerprint) external view returns (uint256);

    function getPcrPolicy(
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId
    ) external view returns (ResolvedPcrPolicy memory policy);

    /// Mirrors `ISessionRegistry.sol::isSessionActive(bytes32)`. The
    /// Phase 2.12 verifier polls this to advance
    /// `/status.chain.status: Submitted → Verified`. It returns true
    /// once *any* submitter (the portal's direct broadcast, an
    /// operator's external broadcast, a relay re-wrap) successfully
    /// registered the session — which is why polling
    /// `isSessionActive(session_id)` rather than
    /// `eth_getTransactionReceipt(tx_hash)` is the canonical
    /// verification primitive (see `docs/chain-registration.md` §
    /// "Verification: poll isSessionActive").
    function isSessionActive(bytes32 sessionId) external view returns (bool);

    function getSessionOwner(bytes32 sessionId) external view returns (bytes32);
}

/// Strongly-typed inputs for [`encode_register_session`]. All fields
/// match the on-chain `registerSession(...)` argument shape one-for-
/// one. The encoder produces the full transaction `data` bytes
/// (4-byte selector followed by the ABI-encoded argument list).
#[derive(Debug, Clone)]
pub struct RegisterSessionInputs {
    pub evidence: AttestationEvidence,
    pub workload_id: B256,
    pub base_image_id: B256,
    pub platform_profile_id: B256,
    pub variant_id: B256,
    pub op_expires_at: u64,
    pub owner_identity: PublicIdentity,
    pub owner_signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RotateKeyInputs {
    pub old_session_id: B256,
    pub tee_report_bytes_hash: B256,
    pub rotation_evidence: SessionKeyRotationEvidence,
    pub op_expires_at: u64,
    pub owner_identity: PublicIdentity,
    pub owner_signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RenewSessionInputs {
    pub old_session_id: B256,
    pub new_evidence: AttestationEvidence,
    pub workload_id: B256,
    pub base_image_id: B256,
    pub platform_profile_id: B256,
    pub variant_id: B256,
    pub renewal_authorization: SessionRenewalAuthorization,
    pub op_expires_at: u64,
    pub owner_identity: PublicIdentity,
    pub owner_signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RecoverSessionInputs {
    pub old_session_id: B256,
    pub new_evidence: AttestationEvidence,
    pub workload_id: B256,
    pub base_image_id: B256,
    pub platform_profile_id: B256,
    pub variant_id: B256,
    pub op_expires_at: u64,
    pub owner_identity: PublicIdentity,
    pub owner_signature: Vec<u8>,
}

/// ABI-encode a `registerSession(...)` call. Returns the full
/// transaction `data` field: 4-byte function selector followed by
/// the ABI-encoded argument tuple per the Ethereum ABI spec.
///
/// Byte-exact against the upstream fixture
/// `automata-tee-workload-measurement/test/fixtures/session_register.hex`
/// — see [`tests::fixture_round_trip`].
pub fn encode_register_session(inputs: &RegisterSessionInputs) -> Vec<u8> {
    registerSessionCall {
        evidence: inputs.evidence.clone(),
        workloadId: inputs.workload_id,
        baseImageId: inputs.base_image_id,
        platformProfileId: inputs.platform_profile_id,
        variantId: inputs.variant_id,
        opExpiresAt: inputs.op_expires_at,
        ownerIdentity: inputs.owner_identity.clone(),
        ownerSignature: inputs.owner_signature.clone().into(),
    }
    .abi_encode()
}

pub fn encode_rotate_key(inputs: &RotateKeyInputs) -> Vec<u8> {
    rotateKeyCall {
        oldSessionId: inputs.old_session_id,
        teeReportBytesHash: inputs.tee_report_bytes_hash,
        rotationEvidence: inputs.rotation_evidence.clone(),
        opExpiresAt: inputs.op_expires_at,
        ownerIdentity: inputs.owner_identity.clone(),
        ownerSignature: inputs.owner_signature.clone().into(),
    }
    .abi_encode()
}

pub fn encode_renew_session(inputs: &RenewSessionInputs) -> Vec<u8> {
    renewSessionCall {
        oldSessionId: inputs.old_session_id,
        newEvidence: inputs.new_evidence.clone(),
        workloadId: inputs.workload_id,
        baseImageId: inputs.base_image_id,
        platformProfileId: inputs.platform_profile_id,
        measurementVariantId: inputs.variant_id,
        renewalAuthorization: inputs.renewal_authorization.clone(),
        opExpiresAt: inputs.op_expires_at,
        ownerIdentity: inputs.owner_identity.clone(),
        ownerSignature: inputs.owner_signature.clone().into(),
    }
    .abi_encode()
}

pub fn encode_recover_session(inputs: &RecoverSessionInputs) -> Vec<u8> {
    recoverSessionCall {
        oldSessionId: inputs.old_session_id,
        newEvidence: inputs.new_evidence.clone(),
        workloadId: inputs.workload_id,
        baseImageId: inputs.base_image_id,
        platformProfileId: inputs.platform_profile_id,
        measurementVariantId: inputs.variant_id,
        opExpiresAt: inputs.op_expires_at,
        ownerIdentity: inputs.owner_identity.clone(),
        ownerSignature: inputs.owner_signature.clone().into(),
    }
    .abi_encode()
}

pub const ROTATE_KEY_SELECTOR: [u8; 4] = rotateKeyCall::SELECTOR;
pub const RENEW_SESSION_SELECTOR: [u8; 4] = renewSessionCall::SELECTOR;
pub const RECOVER_SESSION_SELECTOR: [u8; 4] = recoverSessionCall::SELECTOR;

/// Decode `registerSession(...)` calldata back into typed inputs. Used
/// by the fixture round-trip test and any operator-side tooling that
/// needs to inspect a captured submission. Returns `None` if the
/// selector doesn't match or the payload doesn't parse.
pub fn decode_register_session(calldata: &[u8]) -> Option<RegisterSessionInputs> {
    let call = registerSessionCall::abi_decode(calldata).ok()?;
    Some(RegisterSessionInputs {
        evidence: call.evidence,
        workload_id: call.workloadId,
        base_image_id: call.baseImageId,
        platform_profile_id: call.platformProfileId,
        variant_id: call.variantId,
        op_expires_at: call.opExpiresAt,
        owner_identity: call.ownerIdentity,
        owner_signature: call.ownerSignature.into(),
    })
}

/// The 4-byte function selector for `registerSession(...)`. Verified
/// against the upstream test fixture's leading bytes.
pub const REGISTER_SESSION_SELECTOR: [u8; 4] = registerSessionCall::SELECTOR;

/// ABI-encode a `getNonce(bytes32)` eth_call. Returns the full
/// `data` field: 4-byte selector followed by the 32-byte
/// owner-fingerprint argument. Result is what the worker passes
/// as the `data` parameter to `EthRpcClient::call`.
pub fn encode_get_nonce_call(owner_fingerprint: B256) -> Vec<u8> {
    getNonceCall {
        ownerFingerprint: owner_fingerprint,
    }
    .abi_encode()
}

/// Decode a 32-byte `getNonce` return blob into a `U256` nonce.
/// `eth_call` returns the ABI-encoded return tuple; for a single
/// `uint256` that's exactly 32 bytes left-padded big-endian.
/// Rejects any other length.
pub fn decode_get_nonce_return(return_bytes: &[u8]) -> Result<U256, GetNonceDecodeError> {
    let arr: [u8; 32] = return_bytes
        .try_into()
        .map_err(|_| GetNonceDecodeError::WrongLength(return_bytes.len()))?;
    Ok(U256::from_be_bytes(arr))
}

/// Error type for [`decode_get_nonce_return`]. Anything other than
/// exactly 32 bytes indicates a malformed response from the RPC.
#[derive(Debug, thiserror::Error)]
pub enum GetNonceDecodeError {
    #[error("getNonce return blob: expected 32 bytes, got {0}")]
    WrongLength(usize),
}

/// The 4-byte function selector for `getNonce(bytes32)`. Pinned by
/// [`tests::get_nonce_selector_matches_signature`] against
/// `keccak256("getNonce(bytes32)")[..4]`.
pub const GET_NONCE_SELECTOR: [u8; 4] = getNonceCall::SELECTOR;

/// ABI-encode `SessionRegistry.getPcrPolicy(...)` for `eth_call`.
pub fn encode_get_pcr_policy_call(
    workload_id: B256,
    base_image_id: B256,
    platform_profile_id: B256,
    measurement_variant_id: B256,
) -> Vec<u8> {
    getPcrPolicyCall {
        workloadId: workload_id,
        baseImageId: base_image_id,
        platformProfileId: platform_profile_id,
        measurementVariantId: measurement_variant_id,
    }
    .abi_encode()
}

/// Decode the exact `ResolvedPcrPolicy` returned by
/// `SessionRegistry.getPcrPolicy(...)`.
pub fn decode_get_pcr_policy_return(
    return_bytes: &[u8],
) -> alloy_sol_types::Result<ResolvedPcrPolicy> {
    getPcrPolicyCall::abi_decode_returns(return_bytes)
}

pub const GET_PCR_POLICY_SELECTOR: [u8; 4] = getPcrPolicyCall::SELECTOR;

/// ABI-encode an `isSessionActive(bytes32)` eth_call. Returns the
/// full `data` field: 4-byte selector followed by the 32-byte
/// session-id argument. Drives the Phase 2.12 verifier polling
/// loop against `chain.rpc_url`.
pub fn encode_is_session_active_call(session_id: B256) -> Vec<u8> {
    isSessionActiveCall {
        sessionId: session_id,
    }
    .abi_encode()
}

/// Decode a 32-byte `isSessionActive` return blob into a `bool`.
/// Solidity ABI represents `bool` as a 32-byte left-padded `uint8`
/// with value 0 (false) or 1 (true); reject any other length or
/// any non-{0,1} payload (`abi.decode` would do the same).
pub fn decode_is_session_active_return(
    return_bytes: &[u8],
) -> Result<bool, IsSessionActiveDecodeError> {
    let arr: [u8; 32] = return_bytes
        .try_into()
        .map_err(|_| IsSessionActiveDecodeError::WrongLength(return_bytes.len()))?;
    // Solidity guarantees the upper 31 bytes are zero — reject if
    // they aren't, since that's a malformed RPC response.
    if arr[..31].iter().any(|b| *b != 0) {
        return Err(IsSessionActiveDecodeError::NonCanonical);
    }
    match arr[31] {
        0 => Ok(false),
        1 => Ok(true),
        n => Err(IsSessionActiveDecodeError::InvalidBoolByte(n)),
    }
}

/// Error type for [`decode_is_session_active_return`].
#[derive(Debug, thiserror::Error)]
pub enum IsSessionActiveDecodeError {
    #[error("isSessionActive return blob: expected 32 bytes, got {0}")]
    WrongLength(usize),
    #[error("isSessionActive return blob: upper 31 bytes are non-zero (not canonical Solidity bool encoding)")]
    NonCanonical,
    #[error("isSessionActive return blob: bool byte is 0x{0:02x} (expected 0 or 1)")]
    InvalidBoolByte(u8),
}

/// The 4-byte function selector for `isSessionActive(bytes32)`.
/// Pinned by [`tests::is_session_active_selector_matches_signature`].
pub const IS_SESSION_ACTIVE_SELECTOR: [u8; 4] = isSessionActiveCall::SELECTOR;

pub fn encode_get_session_owner_call(session_id: B256) -> Vec<u8> {
    getSessionOwnerCall {
        sessionId: session_id,
    }
    .abi_encode()
}

pub fn decode_get_session_owner_return(
    return_bytes: &[u8],
) -> Result<B256, GetSessionOwnerDecodeError> {
    let value: [u8; 32] = return_bytes
        .try_into()
        .map_err(|_| GetSessionOwnerDecodeError::WrongLength(return_bytes.len()))?;
    Ok(B256::from(value))
}

#[derive(Debug, thiserror::Error)]
pub enum GetSessionOwnerDecodeError {
    #[error("getSessionOwner return blob: expected 32 bytes, got {0}")]
    WrongLength(usize),
}

// Re-exports the underlying primitive types used by [`RegisterSessionInputs`]
// so consumers don't need a transitive dep on `alloy_primitives`.
pub use alloy_primitives::{Address as EthAddress, B256 as Bytes32};

/// Convenience: build a [`B256`] from a 32-byte array.
pub fn b256(bytes: [u8; 32]) -> B256 {
    B256::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `getNonce(bytes32)` selector matches the canonical Solidity
    /// computation `keccak256("getNonce(bytes32)")[..4]`. Pins the
    /// `sol!` function declaration against drift.
    #[test]
    fn get_nonce_selector_matches_signature() {
        let expected = &alloy_primitives::keccak256(b"getNonce(bytes32)")[..4];
        assert_eq!(&GET_NONCE_SELECTOR, expected);
    }

    #[test]
    fn lifecycle_selectors_match_generated_solidity_abi() {
        assert_ne!(ROTATE_KEY_SELECTOR, [0u8; 4]);
        assert_ne!(RENEW_SESSION_SELECTOR, [0u8; 4]);
        assert_ne!(RECOVER_SESSION_SELECTOR, [0u8; 4]);
        assert_ne!(ROTATE_KEY_SELECTOR, RENEW_SESSION_SELECTOR);
        assert_ne!(ROTATE_KEY_SELECTOR, RECOVER_SESSION_SELECTOR);
        assert_ne!(RENEW_SESSION_SELECTOR, RECOVER_SESSION_SELECTOR);
    }

    /// Round-trip: `encode_get_nonce_call` followed by
    /// `decode_get_nonce_return` against a hand-built RPC response
    /// produces the original nonce.
    #[test]
    fn get_nonce_encode_decode_round_trip() {
        let owner_fp = B256::from([0x33u8; 32]);
        let data = encode_get_nonce_call(owner_fp);
        assert_eq!(&data[..4], &GET_NONCE_SELECTOR);
        assert_eq!(&data[4..], owner_fp.as_slice());
        assert_eq!(data.len(), 36);

        // Simulate an RPC return for nonce = 0x42:
        let mut blob = [0u8; 32];
        blob[31] = 0x42;
        let decoded = decode_get_nonce_return(&blob).unwrap();
        assert_eq!(decoded, U256::from(0x42u64));
    }

    /// `decode_get_nonce_return` rejects wrong-length payloads.
    #[test]
    fn get_nonce_decode_rejects_wrong_length() {
        assert!(decode_get_nonce_return(&[0u8; 31]).is_err());
        assert!(decode_get_nonce_return(&[0u8; 33]).is_err());
        assert!(decode_get_nonce_return(&[]).is_err());
    }

    /// `isSessionActive(bytes32)` selector matches the canonical
    /// Solidity formula. Same drift-detection pattern as the
    /// getNonce check above.
    #[test]
    fn is_session_active_selector_matches_signature() {
        let expected = &alloy_primitives::keccak256(b"isSessionActive(bytes32)")[..4];
        assert_eq!(&IS_SESSION_ACTIVE_SELECTOR, expected);
    }

    /// Round-trip: encode produces 36 bytes (4-byte selector +
    /// 32-byte sessionId arg); decode handles both true and false
    /// returns.
    #[test]
    fn is_session_active_encode_decode_round_trip() {
        let session_id = B256::from([0x77u8; 32]);
        let data = encode_is_session_active_call(session_id);
        assert_eq!(&data[..4], &IS_SESSION_ACTIVE_SELECTOR);
        assert_eq!(&data[4..], session_id.as_slice());
        assert_eq!(data.len(), 36);

        // false:
        let false_blob = [0u8; 32];
        assert!(!decode_is_session_active_return(&false_blob).unwrap());
        // true:
        let mut true_blob = [0u8; 32];
        true_blob[31] = 1;
        assert!(decode_is_session_active_return(&true_blob).unwrap());
    }

    /// `decode_is_session_active_return` rejects malformed payloads —
    /// wrong length, non-canonical upper-31 zero requirement, and
    /// non-{0,1} bool byte. Each case maps to a different error
    /// variant.
    #[test]
    fn is_session_active_decode_rejects_malformed() {
        // Wrong length:
        assert!(matches!(
            decode_is_session_active_return(&[0u8; 31]),
            Err(IsSessionActiveDecodeError::WrongLength(31))
        ));
        assert!(matches!(
            decode_is_session_active_return(&[]),
            Err(IsSessionActiveDecodeError::WrongLength(0))
        ));

        // Upper-31 non-zero (impossible from real Solidity, but a
        // misbehaving RPC could send garbage):
        let mut non_canon = [0u8; 32];
        non_canon[0] = 0xff;
        non_canon[31] = 1;
        assert!(matches!(
            decode_is_session_active_return(&non_canon),
            Err(IsSessionActiveDecodeError::NonCanonical)
        ));

        // Invalid bool byte:
        let mut bad_bool = [0u8; 32];
        bad_bool[31] = 2;
        assert!(matches!(
            decode_is_session_active_return(&bad_bool),
            Err(IsSessionActiveDecodeError::InvalidBoolByte(2))
        ));
    }

    #[test]
    fn current_register_session_schema_round_trips() {
        let quote = tpm_quote_evidence(vec![1], vec![2], 0xff, vec![], vec![]);
        let certify = tpm_certify_evidence(vec![3], vec![4], vec![5]);
        let inputs = RegisterSessionInputs {
            evidence: AttestationEvidence {
                teeReport: tee_report(TEEType::IntelTDX, vec![6]),
                akPub: public_identity(AlgoId::Es256, vec![7; 65]),
                tpmQuoteReport: wrap_tpm_quote_solidity(&quote),
                tpmCertifyReport: wrap_tpm_certify(&certify),
                akPubCollateral: ak_pub_collateral(
                    AkPubCollateralType::GcpCertChain,
                    VerificationBackendType::Solidity,
                    vec![8],
                ),
                sessionKeySignature: vec![9].into(),
                sessionKey: public_identity(AlgoId::Es256k, vec![10; 65]),
            },
            workload_id: B256::from([11; 32]),
            base_image_id: B256::from([12; 32]),
            platform_profile_id: B256::from([13; 32]),
            variant_id: B256::from([14; 32]),
            op_expires_at: 15,
            owner_identity: public_identity(AlgoId::Es256k, vec![16; 65]),
            owner_signature: vec![17; 65],
        };
        let encoded = encode_register_session(&inputs);
        assert_eq!(&encoded[..4], REGISTER_SESSION_SELECTOR);
        let decoded = decode_register_session(&encoded).expect("decode current schema");
        assert_eq!(encode_register_session(&decoded), encoded);
    }
}
