//! secp256k1 key and recoverable-signature helpers.
//!
//! Adapted from atakit-portal-chain at 079cb59c3434926890f0017a19b9684f86dddfb5.
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use thiserror::Error;

/// Recovery-byte format for a recoverable secp256k1 signature.
#[derive(Debug, Clone, Copy)]
pub enum SigEncoding {
    /// Ethereum r || s || v format with v equal to 27 or 28.
    EthereumLegacyV,
    /// r || s followed by the unadjusted recovery ID.
    RawRecoveryId,
}

/// Invalid key material or a failure to produce a signature.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid secp256k1 secret key: {0}")]
    InvalidKey(String),
    #[error("ecdsa sign: {0}")]
    Sign(String),
}

/// Generate a valid secp256k1 secret using operating-system randomness.
pub fn generate_secret_key_bytes() -> [u8; 32] {
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::SecretKey;
    let secret = SecretKey::random(&mut OsRng);
    let mut out = [0u8; 32];
    out.copy_from_slice(&secret.to_bytes());
    out
}

/// Derive the 65-byte SEC1 public key from a secp256k1 secret.
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

/// Sign a prehashed message and return a low-s recoverable signature.
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

/// Decode a 32-byte secret from hex with an optional 0x prefix.
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
