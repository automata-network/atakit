//! secp256k1 ECDSA recoverable signing for owner-key / gas-wallet
//! flows.
//!
//! On-chain verifier `SignatureVerifier._verifySecp256k1` expects
//! Ethereum-style 65-byte signatures: `r (32) || s (32) || v (1)`
//! where `v ∈ {27, 28}` (the legacy range pre-EIP-155). EVM tx
//! signing for EIP-1559 envelopes uses the raw `recovery_id` ∈
//! {0, 1} instead — caller picks the right `v` encoding for the
//! consuming verifier via [`SigEncoding`].
//!
//! All work here is pure compute; no I/O, no secrets persisted, no
//! globals. Secret-key reading is the caller's responsibility
//! (lives in the supervisor where keys reside).

use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use thiserror::Error;

/// Pick how `v` is encoded in the trailing byte of the 65-byte
/// signature. The on-chain `_verifySecp256k1` verifier uses
/// [`Self::EthereumLegacyV`]; EIP-1559 tx envelopes use
/// [`Self::RawRecoveryId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigEncoding {
    /// `v = recovery_id + 27`, range {27, 28}. Required by Solidity
    /// `ecrecover` and the contract's `_verifySecp256k1`.
    EthereumLegacyV,
    /// `v = recovery_id`, range {0, 1}. Used inside EIP-1559 tx
    /// signatures; the legacy +27 offset is omitted there.
    RawRecoveryId,
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid secp256k1 secret key: {0}")]
    InvalidKey(String),
    #[error("ecdsa sign: {0}")]
    Sign(String),
}

/// Sign a 32-byte prehash with the secp256k1 secret key bytes. The
/// secret is consumed in raw form (32-byte big-endian scalar) —
/// callers loading from a hex-encoded persisted file should strip
/// the `0x` prefix and hex-decode before calling.
///
/// Returns the Ethereum-shape 65-byte signature `r || s || v`. `s`
/// is normalized to the low-half order (per BIP-62 / EIP-2 — the
/// on-chain verifier and most tooling reject the high-`s` form).
pub fn sign_secp256k1_recoverable(
    secret_bytes: &[u8],
    digest: [u8; 32],
    encoding: SigEncoding,
) -> Result<[u8; 65], SigningError> {
    if secret_bytes.len() != 32 {
        return Err(SigningError::InvalidKey(format!(
            "expected 32-byte secret, got {} bytes",
            secret_bytes.len()
        )));
    }
    let signing_key = SigningKey::from_slice(secret_bytes)
        .map_err(|e| SigningError::InvalidKey(e.to_string()))?;

    let (sig, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash(&digest)
        .map_err(|e| SigningError::Sign(e.to_string()))?;

    // k256's sign_prehash already normalizes `s` to the lower half.
    // (`Signature::normalize_s` would otherwise flip a high-`s` value
    //  and yield a different recovery_id; we don't need to redo it.)
    let r = sig.r().to_bytes();
    let s = sig.s().to_bytes();

    let v_byte = match encoding {
        SigEncoding::EthereumLegacyV => 27u8 + recovery_id.to_byte(),
        SigEncoding::RawRecoveryId => recovery_id.to_byte(),
    };

    let mut out = [0u8; 65];
    out[0..32].copy_from_slice(&r);
    out[32..64].copy_from_slice(&s);
    out[64] = v_byte;
    Ok(out)
}

/// Re-encode a TPM-marshalled `TPMT_SIGNATURE` (ECDSA) as the
/// DER-encoded `SEQUENCE { INTEGER r, INTEGER s }` form the on-chain
/// `SignatureVerifier._verifyP256` consumes.
///
/// TPM wire shape (from `TPM2_Sign` / `TPM2_Quote`):
/// - 2 bytes: TPMI_ALG_SIG_SCHEME (must be `TPM_ALG_ECDSA = 0x0018`)
/// - 2 bytes: TPMI_ALG_HASH (informational, not encoded in DER)
/// - 2 bytes: R length, then R bytes (32 for P-256)
/// - 2 bytes: S length, then S bytes (32 for P-256)
///
/// For P-256 with SHA-256 this is 72 bytes total. DER output is
/// 70-72 bytes depending on whether R / S need a leading `0x00`
/// to disambiguate from negative two's-complement.
///
/// Used by the chain submission orchestrator to convert the
/// `SignWithTrustChainKey` supervisor RPC response (TPM-native)
/// into the format the on-chain verifier accepts for
/// `AttestationEvidence.sessionKeySignature`.
pub fn tpm_ecdsa_to_der(tpm_sig: &[u8]) -> Result<Vec<u8>, SigningError> {
    if tpm_sig.len() < 8 {
        return Err(SigningError::InvalidKey(format!(
            "TPMT_SIGNATURE too short: {} bytes",
            tpm_sig.len()
        )));
    }
    let sig_alg = u16::from_be_bytes([tpm_sig[0], tpm_sig[1]]);
    if sig_alg != 0x0018 {
        return Err(SigningError::InvalidKey(format!(
            "expected TPM_ALG_ECDSA (0x0018), got 0x{:04x}",
            sig_alg
        )));
    }
    // hash_alg @ [2..4] — informational, not used here.

    let r_len = u16::from_be_bytes([tpm_sig[4], tpm_sig[5]]) as usize;
    let r_end = 6usize
        .checked_add(r_len)
        .ok_or_else(|| SigningError::InvalidKey("TPMT_SIGNATURE: r length overflow".into()))?;
    if r_end + 2 > tpm_sig.len() {
        return Err(SigningError::InvalidKey(
            "TPMT_SIGNATURE: r runs past buffer".into(),
        ));
    }
    let r = &tpm_sig[6..r_end];

    let s_len = u16::from_be_bytes([tpm_sig[r_end], tpm_sig[r_end + 1]]) as usize;
    let s_start = r_end + 2;
    let s_end = s_start
        .checked_add(s_len)
        .ok_or_else(|| SigningError::InvalidKey("TPMT_SIGNATURE: s length overflow".into()))?;
    if s_end != tpm_sig.len() {
        return Err(SigningError::InvalidKey(format!(
            "TPMT_SIGNATURE: trailing bytes ({} of {} consumed)",
            s_end,
            tpm_sig.len()
        )));
    }
    let s = &tpm_sig[s_start..s_end];
    let canonical_s = p256_low_s(s)?;

    Ok(ecdsa_der_encode(r, &canonical_s))
}

/// Return the mathematically equivalent low-s form for a P-256 ECDSA signature.
///
/// TPM firmware may return either valid s value. The on-chain verifier currently
/// accepts both. Normalizing here lets a future contract reject high-s signatures
/// without asking the TPM to sign again.
fn p256_low_s(s: &[u8]) -> Result<[u8; 32], SigningError> {
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];

    if s.is_empty() || s.len() > 32 {
        return Err(SigningError::InvalidKey(format!(
            "P-256 s must contain 1 to 32 bytes, got {}",
            s.len()
        )));
    }
    let mut value = [0u8; 32];
    value[32 - s.len()..].copy_from_slice(s);
    if value == [0u8; 32] || value >= ORDER {
        return Err(SigningError::InvalidKey(
            "P-256 s is outside the scalar range".into(),
        ));
    }
    if value <= HALF_ORDER {
        return Ok(value);
    }

    let mut low = [0u8; 32];
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let minuend = ORDER[index] as u16;
        let subtrahend = value[index] as u16 + borrow;
        if minuend >= subtrahend {
            low[index] = (minuend - subtrahend) as u8;
            borrow = 0;
        } else {
            low[index] = (minuend + 256 - subtrahend) as u8;
            borrow = 1;
        }
    }
    Ok(low)
}

/// Canonical DER encoding of an ECDSA signature: `SEQUENCE { INTEGER
/// r, INTEGER s }`. Each integer is canonicalised — leading zero
/// bytes stripped, then a single `0x00` prepended when the resulting
/// MSB is set (to keep the value positive in two's-complement).
///
/// Output length: 6 + r_canonical + s_canonical bytes. For P-256
/// this is 70-72 bytes.
fn ecdsa_der_encode(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn encode_int(v: &[u8]) -> Vec<u8> {
        // Strip leading zeros, leaving at least one byte (zero itself
        // encodes as a single-byte 0x00).
        let mut start = 0;
        while start + 1 < v.len() && v[start] == 0 {
            start += 1;
        }
        let stripped = &v[start..];
        let needs_pad = (stripped[0] & 0x80) != 0;
        let payload_len = stripped.len() + if needs_pad { 1 } else { 0 };
        let mut out = Vec::with_capacity(2 + payload_len);
        out.push(0x02); // INTEGER tag
        out.push(payload_len as u8);
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(stripped);
        out
    }

    let r_der = encode_int(r);
    let s_der = encode_int(s);
    let inner_len = r_der.len() + s_der.len();
    let mut out = Vec::with_capacity(2 + inner_len);
    out.push(0x30); // SEQUENCE tag
    out.push(inner_len as u8);
    out.extend(r_der);
    out.extend(s_der);
    out
}

/// Generate a fresh 32-byte secp256k1 secret key from the OS RNG.
/// Used by the supervisor when persisting a `self_generated` gas
/// wallet — the operator didn't supply a private key, so the
/// supervisor mints one, writes it under `gas-wallet.key`, and
/// returns the derived Ethereum address to the worker.
pub fn generate_secret_key_bytes() -> [u8; 32] {
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::SecretKey;
    let secret = SecretKey::random(&mut OsRng);
    let mut out = [0u8; 32];
    out.copy_from_slice(&secret.to_bytes());
    out
}

/// Derive the 65-byte SEC1-uncompressed public key
/// (`0x04 || X || Y`) from a 32-byte secp256k1 secret.
///
/// This is the `PublicIdentity.key` encoding used for ES256K keys
/// by the on-chain registry.
pub fn derive_public_key_uncompressed(secret_bytes: &[u8]) -> Result<[u8; 65], SigningError> {
    if secret_bytes.len() != 32 {
        return Err(SigningError::InvalidKey(format!(
            "expected 32-byte secret, got {} bytes",
            secret_bytes.len()
        )));
    }
    let signing_key = SigningKey::from_slice(secret_bytes)
        .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
    let point = signing_key.verifying_key().to_encoded_point(false);
    let bytes: [u8; 65] = point
        .as_bytes()
        .try_into()
        .expect("SEC1 uncompressed secp256k1 public key is always 65 bytes");
    Ok(bytes)
}

/// Derive an Ethereum address from a 32-byte secp256k1 secret:
/// `0x` + last 20 bytes of `keccak256(uncompressed_pubkey[1..65])`.
/// Mirrors the formula the operator-side tooling uses; the on-chain
/// `tx.origin` / `msg.sender` for a tx signed with this key matches
/// this value.
pub fn derive_eth_address(secret_bytes: &[u8; 32]) -> Result<String, SigningError> {
    let key_bytes = derive_public_key_uncompressed(secret_bytes)?;
    // `to_encoded_point(false)` returns `0x04 || X || Y` (65 bytes).
    // Drop the prefix before hashing.
    let hash = alloy_primitives::keccak256(&key_bytes[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

/// Parse a hex-encoded secret key (with optional `0x` prefix) into
/// the 32 raw bytes [`sign_secp256k1_recoverable`] expects.
pub fn decode_secret_key_hex(hex_str: &str) -> Result<[u8; 32], SigningError> {
    let stripped = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    let bytes = hex::decode(stripped).map_err(|e| SigningError::InvalidKey(format!("hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(SigningError::InvalidKey(format!(
            "expected 32-byte secret, got {} bytes after hex decode",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

    /// Deterministic round-trip: sign a digest, then ecrecover-style
    /// reverse — derive the verifying key from the secret and verify
    /// the signature against it. Pins:
    ///   - 32-byte secret consumption
    ///   - 65-byte output layout (r||s||v)
    ///   - `s` normalized to lower half (k256 guarantees this)
    ///   - `v_byte = 27 + recovery_id` under `EthereumLegacyV`
    ///   - `v_byte = recovery_id` under `RawRecoveryId`
    #[test]
    fn sign_and_verify_round_trip() {
        // Hardcoded test key — not a real secret. 32 bytes, valid
        // secp256k1 scalar (less than curve order).
        let secret = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];
        let digest = [0xa5u8; 32];

        let sig =
            sign_secp256k1_recoverable(&secret, digest, SigEncoding::EthereumLegacyV).unwrap();

        assert_eq!(sig.len(), 65);
        assert!(
            sig[64] == 27 || sig[64] == 28,
            "expected v ∈ {{27, 28}}, got {}",
            sig[64]
        );

        // Verify by recomputing the verifying key from the secret
        // and checking the signature.
        let signing_key = SigningKey::from_slice(&secret).unwrap();
        let verifying_key: VerifyingKey = *signing_key.verifying_key();
        let parsed_sig = Signature::from_slice(&sig[..64]).unwrap();
        verifying_key.verify_prehash(&digest, &parsed_sig).unwrap();

        // Same digest, RawRecoveryId encoding — v should be 0 or 1.
        let sig_raw =
            sign_secp256k1_recoverable(&secret, digest, SigEncoding::RawRecoveryId).unwrap();
        assert_eq!(
            &sig_raw[..64],
            &sig[..64],
            "r||s identical between encodings"
        );
        assert_eq!(
            sig_raw[64],
            sig[64] - 27,
            "RawRecoveryId v should be LegacyV - 27"
        );
    }

    /// Determinism: same input → same signature. k256 uses
    /// RFC 6979 deterministic nonces, so this is guaranteed.
    /// Pinning it catches accidental switch to random nonces.
    #[test]
    fn signing_is_deterministic() {
        let secret = [0x42u8; 32];
        let digest = [0x99u8; 32];
        let a = sign_secp256k1_recoverable(&secret, digest, SigEncoding::EthereumLegacyV).unwrap();
        let b = sign_secp256k1_recoverable(&secret, digest, SigEncoding::EthereumLegacyV).unwrap();
        assert_eq!(a, b);
    }

    /// Length validation: wrong-size secret keys are rejected.
    #[test]
    fn rejects_wrong_size_secret() {
        let too_short = [0u8; 16];
        let too_long = [0u8; 64];
        let digest = [0u8; 32];
        assert!(
            sign_secp256k1_recoverable(&too_short, digest, SigEncoding::EthereumLegacyV).is_err()
        );
        assert!(
            sign_secp256k1_recoverable(&too_long, digest, SigEncoding::EthereumLegacyV).is_err()
        );
    }

    /// Round-trip a synthetic TPM-marshalled signature through the DER encoder.
    /// Verifies:
    ///   - Header bytes `0018 000B 0020` (ECDSA / SHA-256 / 32-byte R)
    ///     parse correctly
    ///   - Output starts with `0x30` (DER SEQUENCE tag)
    ///   - Output length ∈ [70, 72] depending on canonicalisation
    ///   - First R byte 0xca has MSB set → needs a leading 0x00 pad
    ///     (so r INTEGER = 33 bytes)
    ///   - First S byte 0x78 has MSB clear → no pad (s INTEGER = 32 bytes)
    ///   - Total: 2 (SEQ) + 2 + 33 (r) + 2 + 32 (s) = 71 bytes
    #[test]
    fn tpm_ecdsa_to_der_synthetic_sig() {
        let mut tpm_sig = vec![0x00, 0x18, 0x00, 0x0b, 0x00, 0x20];
        tpm_sig.extend_from_slice(&[0xca; 32]);
        tpm_sig.extend_from_slice(&[0x00, 0x20]);
        tpm_sig.extend_from_slice(&[0x78; 32]);
        assert_eq!(tpm_sig.len(), 72);

        let der = tpm_ecdsa_to_der(&tpm_sig).unwrap();
        assert_eq!(der[0], 0x30, "DER SEQUENCE tag");
        assert_eq!(der.len(), 71, "expected 71 bytes (r needs pad, s does not)");
        assert_eq!(der[1] as usize, der.len() - 2, "outer length consistent");
        assert_eq!(der[2], 0x02, "first INTEGER tag");
        assert_eq!(der[3], 33, "r length (32 + 1 pad byte)");
        assert_eq!(der[4], 0x00, "r leading pad byte");
        // INTEGER s starts at offset 37 (2 + 2 + 33).
        assert_eq!(der[37], 0x02, "second INTEGER tag");
        assert_eq!(der[38], 32, "s length (no pad needed)");
    }

    #[test]
    fn tpm_ecdsa_to_der_normalizes_high_s() {
        let order_minus_one =
            hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550")
                .unwrap();
        let mut tpm_sig = vec![0x00, 0x18, 0x00, 0x0b, 0x00, 0x20];
        tpm_sig.extend_from_slice(&[0u8; 31]);
        tpm_sig.push(1);
        tpm_sig.extend_from_slice(&[0x00, 0x20]);
        tpm_sig.extend_from_slice(&order_minus_one);

        let der = tpm_ecdsa_to_der(&tpm_sig).unwrap();
        assert_eq!(der, hex::decode("3006020101020101").unwrap());
    }

    /// Rejects malformed inputs.
    #[test]
    fn tpm_ecdsa_to_der_rejects_garbage() {
        // Too short.
        assert!(tpm_ecdsa_to_der(&[0u8; 4]).is_err());
        // Wrong sigAlg (0x0014 = RSASSA, not ECDSA).
        let mut bogus = [0u8; 72];
        bogus[1] = 0x14;
        assert!(tpm_ecdsa_to_der(&bogus).is_err());
        // Trailing bytes.
        let mut overlong = vec![0x00, 0x18, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00];
        overlong.extend_from_slice(&[0xffu8; 16]); // trailing junk
        assert!(tpm_ecdsa_to_der(&overlong).is_err());
    }

    /// `derive_eth_address` matches a known test vector — the well-known
    /// ganache/hardhat secret key `0xac0974be...` produces address
    /// `0xf39Fd6e51aad88F6F4ce6aB8827279cfFFb92266` (case-insensitive).
    #[test]
    fn eth_address_known_vector() {
        let secret = decode_secret_key_hex(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();
        let address = derive_eth_address(&secret).unwrap();
        assert_eq!(
            address.to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    /// `generate_secret_key_bytes` produces a 32-byte key that's a
    /// valid secp256k1 secret (signing succeeds, address derivation
    /// succeeds).
    #[test]
    fn generated_secret_is_usable() {
        let secret = generate_secret_key_bytes();
        assert_eq!(secret.len(), 32);
        // Non-zero (vanishingly unlikely to be zero from OsRng).
        assert_ne!(secret, [0u8; 32]);
        // Can derive an address.
        let address = derive_eth_address(&secret).unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // "0x" + 40 hex chars
                                       // Can sign.
        let digest = [0x77u8; 32];
        let sig = sign_secp256k1_recoverable(&secret, digest, SigEncoding::RawRecoveryId).unwrap();
        assert_eq!(sig.len(), 65);
    }

    /// `decode_secret_key_hex` accepts both `0x`-prefixed and bare
    /// hex, ignores surrounding whitespace, rejects wrong-size and
    /// non-hex inputs.
    #[test]
    fn hex_secret_decoder() {
        let raw = "1122334455667788";
        let secret_hex = format!("{raw}{raw}{raw}{raw}");
        // 32 bytes = 64 hex chars.
        assert_eq!(secret_hex.len(), 64);
        let with_prefix = format!("0x{secret_hex}");
        let with_whitespace = format!("  {with_prefix}  ");

        let plain = decode_secret_key_hex(&secret_hex).unwrap();
        let prefixed = decode_secret_key_hex(&with_prefix).unwrap();
        let stripped = decode_secret_key_hex(&with_whitespace).unwrap();
        assert_eq!(plain, prefixed);
        assert_eq!(plain, stripped);

        assert!(decode_secret_key_hex("too-short").is_err());
        assert!(decode_secret_key_hex("0xzzzz").is_err());
        assert!(decode_secret_key_hex("0xff").is_err()); // only 1 byte
    }

    /// Two different secret keys should produce different signatures
    /// for the same digest. Guards against any wrong-key collision.
    #[test]
    fn different_keys_produce_different_signatures() {
        let secret_a = [0x11u8; 32];
        let secret_b = [0x22u8; 32];
        let digest = [0x00u8; 32];
        let sig_a =
            sign_secp256k1_recoverable(&secret_a, digest, SigEncoding::EthereumLegacyV).unwrap();
        let sig_b =
            sign_secp256k1_recoverable(&secret_b, digest, SigEncoding::EthereumLegacyV).unwrap();
        assert_ne!(sig_a, sig_b);
    }
}
