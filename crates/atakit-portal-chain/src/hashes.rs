//! Solidity-faithful hash primitives for the on-chain trust chain.
//!
//! Each function reproduces a single formula from
//! `automata-tee-workload-measurement/src/SessionRegistry.sol`.
//! Inputs are strongly typed; outputs are the exact bytes the
//! contract computes for the same inputs. The on-chain verifier is
//! the spec — every formula here has a unit test that pins one or
//! more known input/output pairs.

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use sha2::{Digest, Sha256};

use crate::domains::{
    DELEGATION_DOMAIN, KEY_DOMAIN, PLATFORM_PROFILE_DOMAIN, PLATFORM_VARIANT_DOMAIN,
    SESSION_DOMAIN, SESSION_NONCE_DOMAIN, SESSION_RECOVER_MSG, SESSION_REGISTER_MSG,
    SESSION_RENEW_DOMAIN, SESSION_RENEW_MSG, SESSION_ROTATE_KEY_DOMAIN, SESSION_ROTATE_KEY_MSG,
};
use crate::AttestationEvidence;

/// On-chain algorithm identifiers per
/// `automata-tee-workload-measurement/src/types/Constants.sol`.
/// Names follow JWT RFC 7518 conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgoId {
    Null = 0,
    /// RSA PKCS#1 v1.5 with SHA-256.
    Rs256 = 1,
    /// ECDSA P-256 with SHA-256.
    Es256 = 2,
    /// ECDSA secp256k1 with SHA-256 (Ethereum-style).
    Es256k = 3,
}

impl AlgoId {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Solidity: `LibKey.computeKeyFingerprint(PublicIdentity)` =
/// `keccak256(abi.encode(KEY_DOMAIN, identity.typeId, identity.key))`.
///
/// `key_bytes` is the public key in its algorithm-specific encoding
/// — uncompressed `04 || X || Y` for ES256/ES256K (65 bytes), or DER
/// for RS256. The fingerprint is what the SessionRegistry uses as
/// the on-chain identity for owner / session / signing keys.
///
/// abi.encode layout for `(bytes32, uint8, bytes)`:
///   slot 0: KEY_DOMAIN (32 bytes)
///   slot 1: uint256(typeId), left-padded — uint8 takes a full word
///   slot 2: offset to dynamic bytes data = 0x60 (96) — three slots
///   slot 3: bytes length
///   slot 4+: bytes data, padded to a 32-byte multiple with zeros
pub fn compute_key_fingerprint(algo: AlgoId, key_bytes: &[u8]) -> B256 {
    let mut buf = Vec::with_capacity(128 + ((key_bytes.len() + 31) & !31));
    buf.extend_from_slice(KEY_DOMAIN.as_slice());
    let mut type_word = [0u8; 32];
    type_word[31] = algo.as_u8();
    buf.extend_from_slice(&type_word);
    let mut offset_word = [0u8; 32];
    offset_word[31] = 0x60;
    buf.extend_from_slice(&offset_word);
    let mut len_word = [0u8; 32];
    len_word[24..].copy_from_slice(&(key_bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(&len_word);
    buf.extend_from_slice(key_bytes);
    let pad = (32 - (key_bytes.len() % 32)) % 32;
    buf.extend(std::iter::repeat_n(0u8, pad));
    keccak256(&buf)
}

/// Solidity: `_computeSessionId` =
/// `keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))`.
///
/// - `tpm_signature_hash` = `keccak256(tpmQuoteReport.tpmSignature)`,
///   where `tpmSignature` is the marshalled `TPMT_SIGNATURE` bytes
///   that come out of `TPM2_Quote`. Computed by the on-chain code
///   inside `_verifyTpmQuoteWithNonce`.
/// - `tee_report_bytes_hash` is the `teeReportBytesHash` returned in
///   `TeeVerificationResult`.
///
/// Three `bytes32` args under `abi.encode` is a flat 96-byte
/// concatenation (no offsets needed — all static).
pub fn compute_session_id(tpm_signature_hash: B256, tee_report_bytes_hash: B256) -> B256 {
    let encoded = (SESSION_DOMAIN, tpm_signature_hash, tee_report_bytes_hash).abi_encode_params();
    keccak256(&encoded)
}

/// Solidity: `delegationMessage` =
/// `keccak256(abi.encode(DELEGATION_DOMAIN, block.chainid, address(this),
///                       baseImageId, workloadId, sessionId,
///                       sessionKeyFingerprint))`.
///
/// This is the digest the TPM signing key signs to delegate signing
/// authority to the off-chain `sessionKey` (secp256k1). The signature
/// lands in `AttestationEvidence.sessionKeySignature`. `chain_id` +
/// `registry_address` bind the signature to one specific deployment
/// of the SessionRegistry, matching the same domain-separator
/// pattern as the owner-op messages — prevents a captured
/// delegation signature from being replayed against a different
/// chain or a different SessionRegistry contract.
///
/// abi.encode shape: `bytes32 || uint256 || address || bytes32 ||
/// bytes32 || bytes32 || bytes32` = 7 * 32 = 224 bytes (address
/// gets left-padded to a 32-byte slot).
pub fn compute_delegation_digest(
    chain_id: u64,
    registry_address: Address,
    base_image_id: B256,
    workload_id: B256,
    session_id: B256,
    session_key_fingerprint: B256,
) -> B256 {
    let encoded = (
        DELEGATION_DOMAIN,
        U256::from(chain_id),
        registry_address,
        base_image_id,
        workload_id,
        session_id,
        session_key_fingerprint,
    )
        .abi_encode_params();
    keccak256(&encoded)
}

/// Solidity:
/// `message = sha256(abi.encode(SESSION_REGISTER_MSG, block.chainid,
///                              address(this), opExpiresAt, sessionId,
///                              workloadId, baseImageId,
///                              platformProfileId, variantId,
///                              sessionKeyFingerprint))`.
///
/// **Note the hash function is SHA-256, NOT keccak256.** That matches
/// the on-chain contract's choice — see `SessionRegistry.sol`
/// `registerSession`.
///
/// The owner's signature is the operator's authorization of WHAT is
/// being registered: not just an opaque sessionId but the full
/// (workload, baseImage, profile, variant, sessionKey) tuple. This
/// prevents a compromised in-CVM agent from swapping in different
/// (W, B) values while the operator's wallet signs only against
/// the apparent sessionId. `sessionKeyFingerprint` is also bound by
/// the delegation signature (defense in depth here).
///
/// `chain_id` is the EIP-155 chain ID (mainnet=1, sepolia=11155111,
/// etc.). `registry_address` is the deployed SessionRegistry
/// contract address — `address(this)` from the contract's view.
/// `op_expires_at` is the operator-chosen signature-validity deadline
/// (unix seconds). `session_id` comes from [`compute_session_id`].
// Args mirror the on-chain `registerSession` ABI tuple 1:1; grouping
// them into a struct would obscure that mapping.
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
        SESSION_REGISTER_MSG,
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

/// TPM predecessor authorization for `rotateKey`.
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
            SESSION_ROTATE_KEY_DOMAIN,
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

/// TPM predecessor authorization for `renewSession`.
pub fn compute_renew_tpm_payload(
    chain_id: u64,
    registry_address: Address,
    old_session_id: B256,
    new_session_id: B256,
    new_evidence: &AttestationEvidence,
) -> B256 {
    let evidence_hash = keccak256(new_evidence.abi_encode());
    keccak256(
        (
            SESSION_RENEW_DOMAIN,
            U256::from(chain_id),
            registry_address,
            old_session_id,
            new_session_id,
            evidence_hash,
        )
            .abi_encode_params(),
    )
}

/// Owner authorization for `rotateKey`.
pub fn compute_rotate_key_owner_payload(
    chain_id: u64,
    registry_address: Address,
    op_expires_at: u64,
    old_session_id: B256,
    new_session_id: B256,
) -> [u8; 32] {
    Sha256::digest(
        (
            SESSION_ROTATE_KEY_MSG,
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

/// Owner authorization for `renewSession` and `recoverSession`.
#[allow(clippy::too_many_arguments)]
pub fn compute_lifecycle_owner_payload(
    recover: bool,
    chain_id: u64,
    registry_address: Address,
    op_expires_at: u64,
    old_session_id: B256,
    new_session_id: B256,
    workload_id: B256,
    base_image_id: B256,
    platform_profile_id: B256,
    variant_id: B256,
    session_key_fingerprint: B256,
) -> [u8; 32] {
    Sha256::digest(
        (
            if recover {
                SESSION_RECOVER_MSG
            } else {
                SESSION_RENEW_MSG
            },
            U256::from(chain_id),
            registry_address,
            op_expires_at,
            old_session_id,
            new_session_id,
            workload_id,
            base_image_id,
            platform_profile_id,
            variant_id,
            session_key_fingerprint,
        )
            .abi_encode_params(),
    )
    .into()
}

/// Solidity (`BaseImageRegistry.addPlatformVariants`):
/// `platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN,
///                                            baseImageId, profile.name))`.
///
/// `profile_name` is the on-chain string convention pinned by the
/// `atakit-imgbuild` toolchain when publishing platform profiles:
/// `format!("{cloud}-{tee}")` — i.e. cloud and TEE Display strings
/// joined by `-`. Concrete examples that round-trip with
/// `BaseImageRegistry.addPlatformVariants(...)` registrations:
///
/// | cloud | tee | `profile.name` |
/// |---|---|---|
/// | `gcp` | `sev-snp` | `"gcp-sev-snp"` |
/// | `azure` | `tdx` | `"azure-tdx"` |
/// | `aws` | `sev-snp` | `"aws-sev-snp"` |
///
/// The portal computes this id at submission time from its detected
/// `PlatformIdentity`; the base-image owner computed it the same way
/// when publishing profiles for the matching `baseImageId`. Mismatch
/// → on-chain `PlatformProfileNotFound` revert inside
/// `SessionRegistry.registerSession`.
///
/// abi.encode layout for `(bytes32, bytes32, string)`:
///   slot 0: PLATFORM_PROFILE_DOMAIN
///   slot 1: baseImageId
///   slot 2: offset to string data = 0x60 (two static slots before)
///   slot 3: profile_name length (uint256)
///   slot 4+: profile_name bytes, right-zero-padded to 32-byte multiple
pub fn compute_platform_profile_id(base_image_id: B256, profile_name: &str) -> B256 {
    let encoded = (
        PLATFORM_PROFILE_DOMAIN,
        base_image_id,
        profile_name.to_string(),
    )
        .abi_encode_params();
    keccak256(&encoded)
}

/// Solidity (`BaseImageRegistry.addPlatformVariants`):
/// `variantId = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN,
///                                    platformProfileId, variant.name))`.
///
/// `variant_name` is the cloud-specific instance `machine_type`
/// verbatim — e.g. `"n2d-standard-4"`, `"m6a.xlarge"`,
/// `"Standard_DC1s_v3"`. Same string the portal's platform-detection
/// reads from cloud metadata at boot and the base-image owner used
/// when publishing per-variant measurements via
/// `BaseImageRegistry.addPlatformVariants(...)`.
///
/// abi.encode layout identical to [`compute_platform_profile_id`].
pub fn compute_variant_id(platform_profile_id: B256, variant_name: &str) -> B256 {
    let encoded = (
        PLATFORM_VARIANT_DOMAIN,
        platform_profile_id,
        variant_name.to_string(),
    )
        .abi_encode_params();
    keccak256(&encoded)
}

/// Solidity (inside `_verifyTpmQuoteWithNonce`):
/// `expectedExtraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN,
///                                            block.chainid, address(this),
///                                            ownerFingerprint, nonce))`.
///
/// The portal embeds this 32-byte digest as the Quote's `extraData`
/// when calling `TPM2_Quote` for the trust-chain bundle, so the on-
/// chain verifier can confirm the quote was bound to this specific
/// owner's current registration nonce. `chain_id` + `registry_address`
/// scope the binding to one deployment — the same TPM quote
/// extraData cannot be replayed against a different chain or a
/// different SessionRegistry contract that happens to have the same
/// `(ownerFingerprint, nonce)` state.
///
/// Five args under abi.encode: `bytes32 || uint256 || address ||
/// bytes32 || uint256` = 5 * 32 = 160 bytes flat (address gets
/// left-padded to a 32-byte slot).
pub fn compute_qualifying_data(
    chain_id: u64,
    registry_address: Address,
    owner_fingerprint: B256,
    owner_nonce: U256,
) -> B256 {
    let encoded = (
        SESSION_NONCE_DOMAIN,
        U256::from(chain_id),
        registry_address,
        owner_fingerprint,
        owner_nonce,
    )
        .abi_encode_params();
    keccak256(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    /// Reproduction of `LibKey.computeKeyFingerprint` against the
    /// Solidity reference. Inputs: ALGO_ID_ES256 (= 2) and the
    /// uncompressed P-256 point with X=0x01..., Y=0x02....
    ///
    /// Expected value computed offline via a one-shot Solidity test
    /// running the same `keccak256(abi.encode(...))` formula on the
    /// same inputs. The single test vector here pins both: (a) the
    /// abi.encode layout of `(bytes32, uint8, bytes)` and (b) our
    /// KEY_DOMAIN constant.
    #[test]
    fn key_fingerprint_known_vector() {
        let mut key = [0u8; 65];
        key[0] = 0x04;
        for i in 0..32 {
            key[1 + i] = 0x01;
            key[33 + i] = 0x02;
        }
        let got = compute_key_fingerprint(AlgoId::Es256, &key);

        // Hand-computed reference using the abi.encode layout:
        //   slot0 = KEY_DOMAIN (32 bytes)
        //   slot1 = 0x00..02 (typeId padded)
        //   slot2 = 0x60 (offset to bytes)
        //   slot3 = 65 (length)
        //   slots 4..6 = key bytes padded to 96 bytes
        let mut reference = Vec::with_capacity(192);
        reference.extend_from_slice(KEY_DOMAIN.as_slice());
        reference.extend_from_slice(&[0u8; 31]);
        reference.push(2u8);
        let mut offset = [0u8; 32];
        offset[31] = 0x60;
        reference.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[31] = 65;
        reference.extend_from_slice(&len);
        reference.extend_from_slice(&key);
        // Pad to 32-byte multiple: 65 % 32 = 1, so 31 zero bytes.
        reference.extend_from_slice(&[0u8; 31]);
        let expected = keccak256(&reference);
        assert_eq!(got, expected);
    }

    /// `compute_session_id` for three known `bytes32` inputs.
    /// abi.encode for three bytes32 is flat concatenation, so the
    /// reference is just: `keccak256(SESSION_DOMAIN || tpm_sig || tee)`.
    #[test]
    fn session_id_known_vector() {
        let tpm_sig = B256::from([0xaau8; 32]);
        let tee = B256::from([0xbbu8; 32]);

        let got = compute_session_id(tpm_sig, tee);

        let mut reference = Vec::with_capacity(96);
        reference.extend_from_slice(SESSION_DOMAIN.as_slice());
        reference.extend_from_slice(tpm_sig.as_slice());
        reference.extend_from_slice(tee.as_slice());
        let expected = keccak256(&reference);
        assert_eq!(got, expected);
    }

    #[test]
    fn lifecycle_owner_and_rotation_vectors_match_spec() {
        let registry = address!("1111111111111111111111111111111111111111");
        let old = B256::repeat_byte(0x22);
        let new = B256::repeat_byte(0x33);
        let workload = B256::repeat_byte(0x44);
        let base_image = B256::repeat_byte(0x55);
        let profile = B256::repeat_byte(0x66);
        let variant = B256::repeat_byte(0x77);
        let session_key = B256::repeat_byte(0x88);
        let tee_hash = B256::repeat_byte(0x99);
        let tpm_key = B256::repeat_byte(0xaa);

        assert_eq!(
            compute_rotate_key_tpm_payload(1, registry, old, tpm_key, session_key, tee_hash,),
            decode_b256("ae9908640723734e9219d9acc48905d3df289be37a566587d9b8239cb9155231")
        );
        assert_eq!(
            compute_rotate_key_owner_payload(1, registry, 1_700_000_300, old, new),
            decode_32("0c49d50ea4eee1498327d44c7a80cdc5887e316d021ecc453a0fc0200dc54687")
        );
        assert_eq!(
            compute_lifecycle_owner_payload(
                false,
                1,
                registry,
                1_700_000_300,
                old,
                new,
                workload,
                base_image,
                profile,
                variant,
                session_key,
            ),
            decode_32("b72503371b44e12d543d931d19e920eb848634d45ea1ee0ec581f24c88cde69c")
        );
        assert_eq!(
            compute_lifecycle_owner_payload(
                true,
                1,
                registry,
                1_700_000_300,
                old,
                new,
                workload,
                base_image,
                profile,
                variant,
                session_key,
            ),
            decode_32("12c0cd5d65f95cad7b4abd452d6fa702834269cb3bb72489b1003da9a43e0fb0")
        );
    }

    fn decode_32(value: &str) -> [u8; 32] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn decode_b256(value: &str) -> B256 {
        B256::from(decode_32(value))
    }

    /// `compute_delegation_digest`: bytes32 + uint256 + address +
    /// 4*bytes32 inputs, flat 224-byte concat under abi.encode
    /// (address is left-padded to a 32-byte slot).
    #[test]
    fn delegation_digest_known_vector() {
        let chain_id: u64 = 1;
        let registry = address!("0102030405060708090a0b0c0d0e0f1011121314");
        let base = B256::from([0x01u8; 32]);
        let workload = B256::from([0x02u8; 32]);
        let session = B256::from([0x03u8; 32]);
        let sk_fp = B256::from([0x04u8; 32]);

        let got = compute_delegation_digest(chain_id, registry, base, workload, session, sk_fp);

        let mut reference = Vec::with_capacity(224);
        reference.extend_from_slice(DELEGATION_DOMAIN.as_slice());
        // uint256(chain_id), left-padded
        let mut chain_slot = [0u8; 32];
        chain_slot[24..].copy_from_slice(&chain_id.to_be_bytes());
        reference.extend_from_slice(&chain_slot);
        // address, left-padded to 32 bytes
        let mut addr_slot = [0u8; 32];
        addr_slot[12..].copy_from_slice(registry.as_slice());
        reference.extend_from_slice(&addr_slot);
        reference.extend_from_slice(base.as_slice());
        reference.extend_from_slice(workload.as_slice());
        reference.extend_from_slice(session.as_slice());
        reference.extend_from_slice(sk_fp.as_slice());
        let expected = keccak256(&reference);
        assert_eq!(got, expected);
    }

    /// `compute_owner_signature_payload` uses SHA-256 (not keccak).
    /// Pins both the abi.encode layout of (bytes32, uint256, address,
    /// uint64, bytes32, bytes32, bytes32, bytes32, bytes32, bytes32)
    /// and the hash-function choice. The owner sig binds the full
    /// (sessionId, workloadId, baseImageId, profileId, variantId,
    /// sessionKeyFingerprint) tuple — closes the front-run / social-
    /// engineering surface where a compromised in-CVM agent could
    /// swap (W, B) while the operator's wallet signed only against
    /// the apparent sessionId.
    #[test]
    fn owner_signature_payload_known_vector() {
        let chain_id: u64 = 1;
        let registry = address!("0102030405060708090a0b0c0d0e0f1011121314");
        let op_expires_at: u64 = 0x0123456789abcdef;
        let session_id = B256::from([0x55u8; 32]);
        let workload_id = B256::from([0x11u8; 32]);
        let base_image_id = B256::from([0x22u8; 32]);
        let platform_profile_id = B256::from([0x33u8; 32]);
        let variant_id = B256::from([0x44u8; 32]);
        let session_key_fingerprint = B256::from([0x66u8; 32]);

        let got = compute_owner_signature_payload(
            chain_id,
            registry,
            op_expires_at,
            session_id,
            workload_id,
            base_image_id,
            platform_profile_id,
            variant_id,
            session_key_fingerprint,
        );

        // Hand-built reference matching abi.encode shape:
        //   slot0 = SESSION_REGISTER_MSG
        //   slot1 = uint256(chain_id), left-padded
        //   slot2 = address (20 bytes), left-padded to 32
        //   slot3 = uint256(op_expires_at), left-padded
        //   slot4 = session_id
        //   slot5 = workload_id
        //   slot6 = base_image_id
        //   slot7 = platform_profile_id
        //   slot8 = variant_id
        //   slot9 = session_key_fingerprint
        let mut reference = Vec::with_capacity(320);
        reference.extend_from_slice(SESSION_REGISTER_MSG.as_slice());
        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
        reference.extend_from_slice(&chain_id_bytes);
        let mut addr_bytes = [0u8; 32];
        addr_bytes[12..].copy_from_slice(registry.as_slice());
        reference.extend_from_slice(&addr_bytes);
        let mut expire_bytes = [0u8; 32];
        expire_bytes[24..].copy_from_slice(&op_expires_at.to_be_bytes());
        reference.extend_from_slice(&expire_bytes);
        reference.extend_from_slice(session_id.as_slice());
        reference.extend_from_slice(workload_id.as_slice());
        reference.extend_from_slice(base_image_id.as_slice());
        reference.extend_from_slice(platform_profile_id.as_slice());
        reference.extend_from_slice(variant_id.as_slice());
        reference.extend_from_slice(session_key_fingerprint.as_slice());

        let expected: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&reference);
            h.finalize().into()
        };
        assert_eq!(got, expected);
    }

    /// `compute_platform_profile_id` for the pinned `{cloud}-{tee}`
    /// string convention. Hand-builds the abi.encode layout for
    /// `(bytes32, bytes32, string)` so a future drift in either the
    /// PLATFORM_PROFILE_DOMAIN constant or the alloy encoder fails
    /// independently. `"gcp-sev-snp"` is 11 bytes → 21 zero bytes of
    /// right-padding.
    #[test]
    fn platform_profile_id_known_vector() {
        let base_image_id = B256::from([0xabu8; 32]);
        let profile_name = "gcp-sev-snp";

        let got = compute_platform_profile_id(base_image_id, profile_name);

        let mut reference = Vec::with_capacity(160);
        reference.extend_from_slice(PLATFORM_PROFILE_DOMAIN.as_slice());
        reference.extend_from_slice(base_image_id.as_slice());
        let mut offset = [0u8; 32];
        offset[31] = 0x60;
        reference.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[24..].copy_from_slice(&(profile_name.len() as u64).to_be_bytes());
        reference.extend_from_slice(&len);
        reference.extend_from_slice(profile_name.as_bytes());
        let pad = (32 - (profile_name.len() % 32)) % 32;
        reference.extend(std::iter::repeat_n(0u8, pad));
        let expected = keccak256(&reference);
        assert_eq!(got, expected);
    }

    /// `compute_variant_id` for the pinned `machine_type` verbatim
    /// convention. Same abi.encode shape as
    /// [`platform_profile_id_known_vector`]; pins
    /// PLATFORM_VARIANT_DOMAIN. `"n2d-standard-4"` is 14 bytes →
    /// 18 zero bytes of right-padding.
    #[test]
    fn variant_id_known_vector() {
        let profile_id = B256::from([0xcdu8; 32]);
        let variant_name = "n2d-standard-4";

        let got = compute_variant_id(profile_id, variant_name);

        let mut reference = Vec::with_capacity(160);
        reference.extend_from_slice(PLATFORM_VARIANT_DOMAIN.as_slice());
        reference.extend_from_slice(profile_id.as_slice());
        let mut offset = [0u8; 32];
        offset[31] = 0x60;
        reference.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[24..].copy_from_slice(&(variant_name.len() as u64).to_be_bytes());
        reference.extend_from_slice(&len);
        reference.extend_from_slice(variant_name.as_bytes());
        let pad = (32 - (variant_name.len() % 32)) % 32;
        reference.extend(std::iter::repeat_n(0u8, pad));
        let expected = keccak256(&reference);
        assert_eq!(got, expected);
    }

    /// Round-trip: an empty `variant.name` still encodes correctly.
    /// Solidity allows zero-length strings; abi.encode lays them out
    /// with len=0 and no payload bytes. Pinning this case prevents
    /// future "what if name is empty" regressions.
    #[test]
    fn variant_id_empty_name() {
        let profile_id = B256::from([0xefu8; 32]);
        let got = compute_variant_id(profile_id, "");

        let mut reference = Vec::with_capacity(128);
        reference.extend_from_slice(PLATFORM_VARIANT_DOMAIN.as_slice());
        reference.extend_from_slice(profile_id.as_slice());
        let mut offset = [0u8; 32];
        offset[31] = 0x60;
        reference.extend_from_slice(&offset);
        reference.extend_from_slice(&[0u8; 32]);
        let expected = keccak256(&reference);
        assert_eq!(got, expected);
    }

    /// `compute_qualifying_data` for the trust-chain Quote's extraData.
    /// abi.encode shape: bytes32 + uint256 + address + bytes32 + uint256
    /// = 5 * 32 = 160 bytes flat (address left-padded to a 32-byte slot).
    #[test]
    fn qualifying_data_known_vector() {
        let chain_id: u64 = 1;
        let registry = address!("0102030405060708090a0b0c0d0e0f1011121314");
        let owner_fp = B256::from([0x77u8; 32]);
        let nonce = U256::from(42u64);

        let got = compute_qualifying_data(chain_id, registry, owner_fp, nonce);

        let mut reference = Vec::with_capacity(160);
        reference.extend_from_slice(SESSION_NONCE_DOMAIN.as_slice());
        // uint256(chain_id)
        let mut chain_slot = [0u8; 32];
        chain_slot[24..].copy_from_slice(&chain_id.to_be_bytes());
        reference.extend_from_slice(&chain_slot);
        // address, left-padded to 32 bytes
        let mut addr_slot = [0u8; 32];
        addr_slot[12..].copy_from_slice(registry.as_slice());
        reference.extend_from_slice(&addr_slot);
        reference.extend_from_slice(owner_fp.as_slice());
        let mut nonce_bytes = [0u8; 32];
        let n = nonce.to_be_bytes::<32>();
        nonce_bytes.copy_from_slice(&n);
        reference.extend_from_slice(&nonce_bytes);
        let expected = keccak256(&reference);
        assert_eq!(got, expected);
    }
}
