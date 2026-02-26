//! Device provider abstraction for TEE/TPM hardware operations.
//!
//! The [`DeviceProvider`] trait abstracts the low-level device I/O that differs
//! between real TPM/TEE hardware and mock implementations. The orchestration
//! logic (nonce binding, evidence assembly, delegation/rotation message
//! construction) lives outside the trait, in the registration module.
//!
//! **Principle**: if the operation talks to hardware (or simulates hardware),
//! it goes in the trait. If it's pure computation (hashing, ABI encoding,
//! message construction), it stays as a helper function.

use alloy::primitives::{B256, Bytes, keccak256};
use automata_tee_workload_measurement::stubs::{
    AkPubCollateral, PublicIdentity, TeeReport, TpmReport,
};
use std::sync::LazyLock;

// =========================================================================
// Domain constants (must match SessionRegistry.sol / Constants.sol)
// =========================================================================

/// KEY_DOMAIN = keccak256("KEY_RESOLVER_V1")
pub static KEY_DOMAIN: LazyLock<B256> = LazyLock::new(|| keccak256(b"KEY_RESOLVER_V1"));

/// SESSION_DOMAIN = keccak256("CVM_SESSION_V1")
pub static SESSION_DOMAIN: LazyLock<B256> = LazyLock::new(|| keccak256(b"CVM_SESSION_V1"));

/// DELEGATION_DOMAIN = keccak256("CVM_SESSION_KEY_DELEGATION")
pub static DELEGATION_DOMAIN: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"CVM_SESSION_KEY_DELEGATION"));

/// SESSION_NONCE_DOMAIN = keccak256("CVM_SESSION_REG_NONCE_V1")
pub static SESSION_NONCE_DOMAIN: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"CVM_SESSION_REG_NONCE_V1"));

/// ROTATION_DOMAIN = keccak256("CVM_SESSION_KEY_ROTATION")
pub static ROTATION_DOMAIN: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"CVM_SESSION_KEY_ROTATION"));

/// PLATFORM_PROFILE_DOMAIN = keccak256("CVM_PLATFORM_PROFILE_V1")
pub static PLATFORM_PROFILE_DOMAIN: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"CVM_PLATFORM_PROFILE_V1"));

/// PLATFORM_VARIANT_DOMAIN = keccak256("CVM_PLATFORM_VARIANT_V1")
pub static PLATFORM_VARIANT_DOMAIN: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"CVM_PLATFORM_VARIANT_V1"));

// =========================================================================
// Types returned by device operations
// =========================================================================

/// Result of a TPM quote operation.
///
/// The `tpm_report` is the ABI-encoded quote ready for on-chain submission.
/// The `tpm_signature` is the raw signature bytes needed separately for
/// session ID computation (`sessionId = keccak256(..., keccak256(tpmSignature), ...)`).
pub struct TpmQuoteResult {
    /// ABI-encoded TPM quote report, ready for on-chain use.
    pub tpm_report: TpmReport,
    /// Raw TPM signature bytes (needed for session ID computation).
    pub tpm_signature: Bytes,
}

/// Platform metadata describing the cloud/TEE environment.
#[derive(Default, Debug, Clone)]
pub struct PlatformInfo {
    /// Cloud provider name (e.g. "gcp", "azure").
    pub cloud_type: String,
    /// TEE type name (e.g. "tdx", "snp").
    pub tee_type: String,
    /// Machine type (e.g. "n2d-standard-2").
    pub machine_type: String,
}

// =========================================================================
// DeviceProvider trait
// =========================================================================

/// Low-level abstraction over TEE/TPM device operations.
///
/// Each method corresponds to a distinct hardware I/O operation. The
/// orchestration layer calls these methods step-by-step to compose the
/// full registration or rotation evidence.
///
/// - **Real implementation**: talks to `/dev/tpmrm0`, TDX IOCTL, cloud metadata
/// - **Mock implementation**: returns structurally valid dummy data
#[allow(async_fn_in_trait)]
pub trait DeviceProvider: Send + Sync {
    // === TEE Operations ===

    /// Get a TEE attestation report (e.g. TDX quote or SNP report).
    ///
    /// The `report_data` is embedded in the TEE report. For TDX this is
    /// typically `SHA256(AK_pub) || zeros` (64 bytes) placed in the
    /// REPORTDATA field.
    async fn get_tee_report(&self) -> anyhow::Result<TeeReport>;

    // === TPM Quote Operations ===

    /// Get a TPM quote with the given extra_data (nonce binding).
    ///
    /// The `extra_data` carries the nonce used for replay protection,
    /// typically `keccak256(SESSION_NONCE_DOMAIN, ownerFingerprint, nonce)`.
    /// PCR selection is determined by the device implementation based on
    /// the cloud platform.
    async fn get_tpm_quote(&self, extra_data: &[u8]) -> anyhow::Result<TpmQuoteResult>;

    // === TPM Signing Key Management ===

    /// Get the current TPM signing key's public identity (P-256).
    ///
    /// Returns 65-byte uncompressed public key (0x04 || x || y) with
    /// `AlgoId::Es256` type.
    fn get_signing_key_public(&self) -> anyhow::Result<PublicIdentity>;

    /// Sign a digest with the current TPM signing key (P-256).
    ///
    /// Returns a DER-encoded ECDSA signature suitable for on-chain
    /// P-256 verification.
    async fn sign_with_signing_key(&self, digest: &[u8]) -> anyhow::Result<Bytes>;

    /// Certify the current signing key with the AK.
    ///
    /// Returns the ABI-encoded TPM certify report ready for on-chain use.
    async fn certify_signing_key(&self) -> anyhow::Result<TpmReport>;

    // === AK Operations ===

    /// Get the AK public key collateral (certificate chain or Azure JSON).
    async fn get_ak_pub_collateral(&self) -> anyhow::Result<AkPubCollateral>;

    /// Get the AK public key identity.
    ///
    /// Typically P-256 on GCP, RSA on Azure.
    fn get_ak_pub(&self) -> anyhow::Result<PublicIdentity>;

    // === Platform Metadata ===

    /// Get platform metadata (cloud type, TEE type, machine type).
    ///
    /// Used by the orchestration layer to compute `platformProfileId`
    /// and `variantId`.
    fn get_platform_info(&self) -> PlatformInfo;

    // === Rotation: Temporary Key Management ===

    /// Create a new temporary signing key for rotation.
    ///
    /// The old key remains active for signing the rotation message.
    /// The temporary key will be used for the new session's delegation.
    async fn create_tmp_signing_key(&mut self) -> anyhow::Result<()>;

    /// Get the temporary signing key's public identity (P-256).
    fn get_tmp_signing_key_public(&self) -> anyhow::Result<PublicIdentity>;

    /// Sign a digest with the temporary signing key (P-256).
    ///
    /// Returns a DER-encoded ECDSA signature.
    async fn sign_with_tmp_key(&self, digest: &[u8]) -> anyhow::Result<Bytes>;

    /// Certify the temporary key with the AK.
    ///
    /// Returns the ABI-encoded TPM certify report ready for on-chain use.
    async fn certify_tmp_signing_key(&self) -> anyhow::Result<TpmReport>;

    /// Promote the temporary key to be the current signing key.
    ///
    /// Called after a successful rotation to finalize the key swap.
    async fn promote_tmp_key(&mut self) -> anyhow::Result<()>;
}

// =========================================================================
// Crypto helpers (used by orchestration layer)
// =========================================================================

/// Compute the TPM quote nonce (extraData) for owner binding.
///
/// `extraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN, ownerFingerprint, nonce))`
///
/// where `abi.encode(bytes32, bytes32, uint256)` = 96 bytes.
pub fn compute_nonce_extra_data(owner_fingerprint: B256, nonce: u64) -> B256 {
    let mut input = [0u8; 96];
    input[0..32].copy_from_slice(SESSION_NONCE_DOMAIN.as_slice());
    input[32..64].copy_from_slice(owner_fingerprint.as_slice());
    // uint256 nonce at bytes 64-96 (big-endian, right-aligned)
    input[88..96].copy_from_slice(&nonce.to_be_bytes());
    keccak256(input)
}

/// Compute session ID from TEE report data and TPM signature.
///
/// `sessionId = keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))`
pub fn compute_session_id(tee_report_data: &[u8], tpm_signature: &[u8]) -> B256 {
    let tee_report_hash = keccak256(tee_report_data);
    let tpm_sig_hash = keccak256(tpm_signature);
    compute_session_id_from_hashes(tee_report_hash, tpm_sig_hash)
}

/// Compute session ID from pre-computed hashes (used during rotation).
///
/// `sessionId = keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))`
pub fn compute_session_id_from_hashes(tee_report_hash: B256, tpm_signature_hash: B256) -> B256 {
    let mut encoded = [0u8; 96];
    encoded[0..32].copy_from_slice(SESSION_DOMAIN.as_slice());
    encoded[32..64].copy_from_slice(tpm_signature_hash.as_slice());
    encoded[64..96].copy_from_slice(tee_report_hash.as_slice());
    keccak256(encoded)
}

/// Compute the delegation message digest that the TPM key signs.
///
/// `digest = keccak256(abi.encode(DELEGATION_DOMAIN, baseImageId, workloadId, sessionId, sessionKeyFingerprint))`
pub fn compute_delegation_digest(
    base_image_id: B256,
    workload_id: B256,
    session_id: B256,
    session_key_fingerprint: B256,
) -> B256 {
    let mut msg = [0u8; 160];
    msg[0..32].copy_from_slice(DELEGATION_DOMAIN.as_slice());
    msg[32..64].copy_from_slice(base_image_id.as_slice());
    msg[64..96].copy_from_slice(workload_id.as_slice());
    msg[96..128].copy_from_slice(session_id.as_slice());
    msg[128..160].copy_from_slice(session_key_fingerprint.as_slice());
    keccak256(msg)
}

/// Compute the rotation message digest that the old TPM key signs.
///
/// `digest = keccak256(abi.encode(ROTATION_DOMAIN, oldSessionId, newKeyFingerprint, sessionKeyFingerprint, teeReportHash))`
pub fn compute_rotation_digest(
    old_session_id: B256,
    new_key_fingerprint: B256,
    session_key_fingerprint: B256,
    tee_report_hash: B256,
) -> B256 {
    let mut msg = [0u8; 160];
    msg[0..32].copy_from_slice(ROTATION_DOMAIN.as_slice());
    msg[32..64].copy_from_slice(old_session_id.as_slice());
    msg[64..96].copy_from_slice(new_key_fingerprint.as_slice());
    msg[96..128].copy_from_slice(session_key_fingerprint.as_slice());
    msg[128..160].copy_from_slice(tee_report_hash.as_slice());
    keccak256(msg)
}

/// Compute the platform profile ID.
///
/// `platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profileName))`
///
/// where `profileName = "{cloudType}-{teeType}"`.
pub fn compute_platform_profile_id(base_image_id: B256, cloud_type: &str, tee_type: &str) -> B256 {
    let profile_name = format!("{cloud_type}-{tee_type}");
    // abi.encode(bytes32, bytes32, string)
    // Static part: domain(32) + baseImageId(32) + offset(32) = 96 bytes
    // Dynamic part: length(32) + padded string data
    let name_bytes = profile_name.as_bytes();
    let padded_len = ((name_bytes.len() + 31) / 32) * 32;
    let total = 96 + 32 + padded_len;
    let mut encoded = vec![0u8; total];
    encoded[0..32].copy_from_slice(PLATFORM_PROFILE_DOMAIN.as_slice());
    encoded[32..64].copy_from_slice(base_image_id.as_slice());
    // offset to string data = 96 (3 * 32), as big-endian u256
    encoded[95] = 96;
    // string length as big-endian u256
    encoded[120..128].copy_from_slice(&(name_bytes.len() as u64).to_be_bytes());
    // string data
    encoded[128..128 + name_bytes.len()].copy_from_slice(name_bytes);
    keccak256(&encoded)
}

/// Compute the variant ID.
///
/// `variantId = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variantName))`
///
/// where `variantName = "{machineType}"`.
pub fn compute_variant_id(platform_profile_id: B256, machine_type: &str) -> B256 {
    let name_bytes = machine_type.as_bytes();
    let padded_len = ((name_bytes.len() + 31) / 32) * 32;
    let total = 96 + 32 + padded_len;
    let mut encoded = vec![0u8; total];
    encoded[0..32].copy_from_slice(PLATFORM_VARIANT_DOMAIN.as_slice());
    encoded[32..64].copy_from_slice(platform_profile_id.as_slice());
    // offset to string data = 96
    encoded[95] = 96;
    // string length
    encoded[120..128].copy_from_slice(&(name_bytes.len() as u64).to_be_bytes());
    // string data
    encoded[128..128 + name_bytes.len()].copy_from_slice(name_bytes);
    keccak256(&encoded)
}
