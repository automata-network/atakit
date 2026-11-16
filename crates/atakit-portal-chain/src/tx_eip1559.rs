//! Minimal EIP-1559 (type-2) transaction envelope encoder.
//!
//! Used by the portal's chain-registration submitter: build the
//! unsigned EIP-1559 transaction, take its [`UnsignedEip1559Tx::sighash`],
//! send to `SignWithGasWallet` (which returns 65 bytes with
//! [`SigEncoding::RawRecoveryId`] — `v ∈ {0, 1}`), then call
//! [`UnsignedEip1559Tx::assemble_signed`] to get the broadcast-ready
//! wire bytes.
//!
//! Reference: EIP-1559 §"Specification" — wire format is
//! `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
//! maxFeePerGas, gasLimit, to, value, data, accessList])` for
//! signing, and `0x02 || rlp([...same..., y_parity, r, s])` for
//! the signed envelope. `tx_hash = keccak256(signed_envelope)`.

use alloy_primitives::{keccak256, Address, U256};
use alloy_rlp::{BufMut, Encodable, Header};

/// Type byte for EIP-1559 ("type-2") transactions per EIP-2718.
pub const EIP1559_TX_TYPE: u8 = 0x02;

/// All fields of an unsigned EIP-1559 transaction. Access list is
/// fixed to empty — the portal's `registerSession` call doesn't use
/// access lists, and supporting them would just be dead surface.
/// Add it back if a future tx form needs it.
#[derive(Debug, Clone)]
pub struct UnsignedEip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    /// Destination contract. Use a zero address for contract
    /// creation if needed (and special-case the encoding — the
    /// portal only ever does contract calls so we don't bother).
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
}

impl UnsignedEip1559Tx {
    /// The keccak256 hash the signer signs. Equals
    /// `keccak256(0x02 || rlp([... 9 fields ...]))`.
    pub fn sighash(&self) -> [u8; 32] {
        let unsigned = self.encode_unsigned();
        keccak256(&unsigned).0
    }

    /// Pre-image of [`sighash`]: `0x02 || rlp_payload_unsigned`.
    /// Exposed so the supervisor (or tests) can introspect the
    /// exact bytes being hashed.
    pub fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = vec![EIP1559_TX_TYPE];
        self.rlp_encode_list(&mut out, /* with_sig = */ None);
        out
    }

    /// Assemble the signed wire-format envelope: prepends the type
    /// byte, RLP-encodes the 9 base fields plus `[y_parity, r, s]`,
    /// returns `(signed_bytes, tx_hash)` where `tx_hash =
    /// keccak256(signed_bytes)`.
    ///
    /// `sig` is the 65-byte `r || s || v` output from
    /// [`crate::sign_secp256k1_recoverable`]. **`v` must be the raw
    /// recovery id (0 or 1)** — EIP-1559 envelopes use raw y_parity,
    /// not the legacy `27 + recovery_id`. Use
    /// [`crate::SigEncoding::RawRecoveryId`] for `SignWithGasWallet`.
    pub fn assemble_signed(&self, sig: &[u8; 65]) -> (Vec<u8>, [u8; 32]) {
        let r = &sig[0..32];
        let s = &sig[32..64];
        let y_parity = sig[64];
        let mut out = vec![EIP1559_TX_TYPE];
        self.rlp_encode_list(&mut out, Some((y_parity, r, s)));
        let hash = keccak256(&out).0;
        (out, hash)
    }

    /// Internal: emit the `rlp([...])` portion. With `sig`, includes
    /// the 12-element signed list; without, the 9-element unsigned
    /// list.
    fn rlp_encode_list(&self, out: &mut Vec<u8>, sig: Option<(u8, &[u8], &[u8])>) {
        // First compute the inner payload length so we can emit the
        // list header. alloy-rlp's `Encodable` trait gives every
        // primitive a `.length()` method that returns its encoded
        // length, so summing them avoids a double-encode.
        let mut payload_len = 0usize;
        payload_len += self.chain_id.length();
        payload_len += self.nonce.length();
        payload_len += self.max_priority_fee_per_gas.length();
        payload_len += self.max_fee_per_gas.length();
        payload_len += self.gas_limit.length();
        // Address is RLP-encoded as its 20 raw bytes (no padding).
        payload_len += self.to.as_slice().length();
        payload_len += self.value.length();
        payload_len += self.data.as_slice().length();
        // Empty access list: a zero-element RLP list = single byte 0xc0.
        payload_len += empty_list_encoded_length();
        if let Some((y_parity, r, s)) = sig {
            payload_len += rlp_uint_byte_length(y_parity);
            payload_len += rlp_minimal_bytes_length(r);
            payload_len += rlp_minimal_bytes_length(s);
        }

        // List header (handles short/long-form internally).
        Header {
            list: true,
            payload_length: payload_len,
        }
        .encode(out);

        // Payload (must match the lengths above byte-for-byte).
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.as_slice().encode(out);
        self.value.encode(out);
        self.data.as_slice().encode(out);
        // Empty access list.
        out.put_u8(0xc0);
        if let Some((y_parity, r, s)) = sig {
            rlp_encode_uint_byte(out, y_parity);
            rlp_encode_minimal_bytes(out, r);
            rlp_encode_minimal_bytes(out, s);
        }
    }
}

// -- RLP helpers for fields alloy-rlp doesn't directly Encodable-derive --

/// Encoded length of the empty list (0xc0). Single byte.
const fn empty_list_encoded_length() -> usize {
    1
}

/// Encoded length of a uint encoded as a single byte under RLP:
/// 0 is `0x80` (length 1); 1..=0x7f is itself (length 1);
/// 0x80..=0xff requires a length prefix (length 2).
fn rlp_uint_byte_length(b: u8) -> usize {
    if b == 0 || b >= 0x80 {
        // 0 encodes as 0x80; values 0x80..=0xff encode as 0x81 || b.
        if b == 0 {
            1
        } else {
            2
        }
    } else {
        1
    }
}

fn rlp_encode_uint_byte(out: &mut Vec<u8>, b: u8) {
    if b == 0 {
        out.put_u8(0x80); // empty string = canonical RLP for uint 0
    } else if b < 0x80 {
        out.put_u8(b);
    } else {
        out.put_u8(0x81);
        out.put_u8(b);
    }
}

/// Encoded length of `r` / `s` as RLP-minimal-bytes — leading
/// zeros stripped, then standard RLP-string encoding. The result is
/// always at most 33 bytes (32 + 1 header byte) but typically 32–34
/// after canonical stripping; on the rare zero-leading case, fewer.
fn rlp_minimal_bytes_length(bytes: &[u8]) -> usize {
    let stripped = strip_leading_zeros(bytes);
    stripped.len_with_header()
}

fn rlp_encode_minimal_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let stripped = strip_leading_zeros(bytes);
    stripped.encode(out);
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    &bytes[i..]
}

/// Helper trait so we can call `.len_with_header()` on slices.
/// alloy-rlp's `Encodable` for `&[u8]` returns the full encoded
/// length via `.length()`; we just re-expose that under a clearer
/// name for the call sites above.
trait BytesRlpLen {
    fn len_with_header(&self) -> usize;
}
impl BytesRlpLen for &[u8] {
    fn len_with_header(&self) -> usize {
        (*self).length()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign_secp256k1_recoverable, SigEncoding};

    /// Build a known unsigned EIP-1559 transaction. Then:
    ///   1. Compute its sighash.
    ///   2. Sign with a hardcoded test secret using RawRecoveryId
    ///      encoding (the encoding EIP-1559 expects).
    ///   3. Assemble the signed envelope.
    ///   4. Confirm the resulting tx_hash matches keccak256 of the
    ///      signed bytes (round-trip; no external reference).
    ///   5. Recover the verifying key from the signature against the
    ///      sighash — confirms the sighash is consumable for
    ///      ecrecover-style verification.
    #[test]
    fn sign_and_assemble_round_trip() {
        let tx = UnsignedEip1559Tx {
            chain_id: 11155111, // sepolia
            nonce: 42,
            max_priority_fee_per_gas: U256::from(1_000_000_000u64), // 1 gwei
            max_fee_per_gas: U256::from(30_000_000_000u64),         // 30 gwei
            gas_limit: 1_500_000,
            to: Address::from([0x12u8; 20]),
            value: U256::ZERO,
            data: vec![0xab, 0xcd, 0xef], // dummy calldata
        };

        let sighash = tx.sighash();
        let unsigned = tx.encode_unsigned();
        assert_eq!(unsigned[0], EIP1559_TX_TYPE);

        // Hardcoded test secret. Valid secp256k1 scalar.
        let secret = [0x33u8; 32];
        let sig = sign_secp256k1_recoverable(&secret, sighash, SigEncoding::RawRecoveryId).unwrap();
        // y_parity should be 0 or 1 for EIP-1559.
        assert!(sig[64] <= 1, "y_parity must be 0 or 1, got {}", sig[64]);

        let (signed_bytes, tx_hash) = tx.assemble_signed(&sig);
        assert_eq!(signed_bytes[0], EIP1559_TX_TYPE);
        // Tx hash is keccak256 of the signed envelope.
        assert_eq!(tx_hash, keccak256(&signed_bytes).0);

        // Sanity-recover the verifying key — confirms the sighash
        // matches what k256's signature was produced over.
        use k256::ecdsa::{
            signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey,
        };
        let signing_key = SigningKey::from_slice(&secret).unwrap();
        let verifying_key: VerifyingKey = *signing_key.verifying_key();
        let parsed_sig = Signature::from_slice(&sig[..64]).unwrap();
        verifying_key.verify_prehash(&sighash, &parsed_sig).unwrap();
    }

    /// `UnsignedEip1559Tx::encode_unsigned()` for the all-zero
    /// transaction. Pins the canonical RLP encoding of "zero
    /// everywhere":
    ///   - chain_id=0 → 0x80 (empty string)
    ///   - nonce=0 → 0x80
    ///   - max_priority_fee=0 → 0x80
    ///   - max_fee=0 → 0x80
    ///   - gas_limit=0 → 0x80
    ///   - to=0x00..00 → 0x94 || (20 zero bytes)
    ///   - value=0 → 0x80
    ///   - data=[] → 0x80
    ///   - access_list=[] → 0xc0
    ///
    /// Inner payload = 5*1 + 21 + 1 + 1 + 1 = 29 bytes
    /// List header: short form (< 56 bytes), encoded as 0xc0 + 29 = 0xdd
    /// Full: 0x02 || 0xdd || 0x80 0x80 0x80 0x80 0x80 || 0x94 ||
    ///        00..00 (20) || 0x80 || 0x80 || 0xc0 = 32 bytes total.
    #[test]
    fn zero_tx_encodes_canonically() {
        let tx = UnsignedEip1559Tx {
            chain_id: 0,
            nonce: 0,
            max_priority_fee_per_gas: U256::ZERO,
            max_fee_per_gas: U256::ZERO,
            gas_limit: 0,
            to: Address::ZERO,
            value: U256::ZERO,
            data: Vec::new(),
        };
        let encoded = tx.encode_unsigned();
        let mut expected = vec![0x02u8, 0xdd];
        expected.extend(std::iter::repeat_n(0x80, 5));
        expected.push(0x94);
        expected.extend_from_slice(&[0u8; 20]);
        expected.push(0x80);
        expected.push(0x80);
        expected.push(0xc0);
        assert_eq!(encoded, expected, "got {}", hex::encode(&encoded));
    }

    /// `assemble_signed` for the zero-tx case: appends [y=0, r=0, s=0]
    /// which encode as 0x80 0x80 0x80 (three bytes). Inner payload
    /// grows from 29 to 32 bytes; list header still short-form
    /// (< 56), 0xc0 + 32 = 0xe0.
    #[test]
    fn zero_signed_tx_layout() {
        let tx = UnsignedEip1559Tx {
            chain_id: 0,
            nonce: 0,
            max_priority_fee_per_gas: U256::ZERO,
            max_fee_per_gas: U256::ZERO,
            gas_limit: 0,
            to: Address::ZERO,
            value: U256::ZERO,
            data: Vec::new(),
        };
        let sig = [0u8; 65];
        let (signed, _hash) = tx.assemble_signed(&sig);
        let mut expected = vec![0x02u8, 0xe0];
        expected.extend(std::iter::repeat_n(0x80, 5));
        expected.push(0x94);
        expected.extend_from_slice(&[0u8; 20]);
        expected.push(0x80);
        expected.push(0x80);
        expected.push(0xc0);
        // y_parity = 0 → 0x80, r = all zeros → 0x80, s = all zeros → 0x80
        expected.push(0x80);
        expected.push(0x80);
        expected.push(0x80);
        assert_eq!(signed, expected, "got {}", hex::encode(&signed));
    }

    /// Different field values change the sighash. Catches accidental
    /// field-omission bugs (where, e.g., gas_limit was forgotten in
    /// the encode list and changing it didn't affect the hash).
    #[test]
    fn each_field_affects_sighash() {
        let base = UnsignedEip1559Tx {
            chain_id: 1,
            nonce: 1,
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(2u64),
            gas_limit: 21000,
            to: Address::from([0x01u8; 20]),
            value: U256::from(100u64),
            data: vec![0xff],
        };
        let h0 = base.sighash();

        let mut t = base.clone();
        t.chain_id = 2;
        assert_ne!(t.sighash(), h0, "chain_id should affect sighash");

        let mut t = base.clone();
        t.nonce = 2;
        assert_ne!(t.sighash(), h0, "nonce should affect sighash");

        let mut t = base.clone();
        t.max_priority_fee_per_gas = U256::from(99u64);
        assert_ne!(t.sighash(), h0, "max_priority_fee should affect sighash");

        let mut t = base.clone();
        t.max_fee_per_gas = U256::from(99u64);
        assert_ne!(t.sighash(), h0, "max_fee should affect sighash");

        let mut t = base.clone();
        t.gas_limit = 99999;
        assert_ne!(t.sighash(), h0, "gas_limit should affect sighash");

        let mut t = base.clone();
        t.to = Address::from([0x02u8; 20]);
        assert_ne!(t.sighash(), h0, "to should affect sighash");

        let mut t = base.clone();
        t.value = U256::from(999u64);
        assert_ne!(t.sighash(), h0, "value should affect sighash");

        let mut t = base.clone();
        t.data = vec![0xee];
        assert_ne!(t.sighash(), h0, "data should affect sighash");
    }

    /// Determinism: same input → same sighash + same signed bytes.
    #[test]
    fn deterministic_encoding() {
        let tx = UnsignedEip1559Tx {
            chain_id: 1,
            nonce: 5,
            max_priority_fee_per_gas: U256::from(1_500_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            gas_limit: 100_000,
            to: Address::from([0xabu8; 20]),
            value: U256::from(1_000_000_000_000_000_000u64),
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let h1 = tx.sighash();
        let h2 = tx.sighash();
        assert_eq!(h1, h2);
        let e1 = tx.encode_unsigned();
        let e2 = tx.encode_unsigned();
        assert_eq!(e1, e2);

        let sig = [0xa5u8; 65];
        let (s1, _) = tx.assemble_signed(&sig);
        let (s2, _) = tx.assemble_signed(&sig);
        assert_eq!(s1, s2);
    }

    /// Helper-byte tests: RLP encoding of a single uint byte under
    /// the EIP-1559 y_parity field.
    #[test]
    fn rlp_uint_byte_encodings() {
        let mut out = Vec::new();
        rlp_encode_uint_byte(&mut out, 0);
        assert_eq!(out, vec![0x80]);
        assert_eq!(rlp_uint_byte_length(0), 1);

        let mut out = Vec::new();
        rlp_encode_uint_byte(&mut out, 1);
        assert_eq!(out, vec![0x01]);
        assert_eq!(rlp_uint_byte_length(1), 1);

        let mut out = Vec::new();
        rlp_encode_uint_byte(&mut out, 0x7f);
        assert_eq!(out, vec![0x7f]);

        let mut out = Vec::new();
        rlp_encode_uint_byte(&mut out, 0x80);
        assert_eq!(out, vec![0x81, 0x80]);
        assert_eq!(rlp_uint_byte_length(0x80), 2);

        let mut out = Vec::new();
        rlp_encode_uint_byte(&mut out, 0xff);
        assert_eq!(out, vec![0x81, 0xff]);
        assert_eq!(rlp_uint_byte_length(0xff), 2);
    }

    /// Leading-zero stripping for r/s components.
    #[test]
    fn leading_zero_stripping() {
        assert_eq!(strip_leading_zeros(&[0, 0, 0, 1]), &[1]);
        assert_eq!(strip_leading_zeros(&[0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_leading_zeros(&[1, 0, 0]), &[1, 0, 0]);
        assert_eq!(strip_leading_zeros(&[]), &[] as &[u8]);
    }
}
