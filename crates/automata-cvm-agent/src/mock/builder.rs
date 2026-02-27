//! Fluent builder for [`MockDeviceProvider`].
//!
//! [`MockDataBuilder`] is the central data-management layer for mock
//! attestation data.  It loads base data from the JSON fixture file,
//! exposes a TPM-semantic mutation API (reset/extend PCRs, set RTMR3),
//! auto-computes derived values (AK public key, PCR digest, ABI encoding),
//! and builds a ready-to-use [`MockDeviceProvider`].
//!
//! # Example
//!
//! ```rust,no_run
//! use automata_cvm_agent::mock::builder::MockDataBuilder;
//! use automata_cvm_agent::mock::mock_device::MockDeviceProvider;
//!
//! let builder = MockDataBuilder::new()
//!     .reset_pcr(15)
//!     .extend_pcr(15, alloy::primitives::B256::repeat_byte(0xAB))
//!     .set_tdx_rtmr3([0xCD; 48]);
//! let device = MockDeviceProvider::new(builder);
//! ```

use alloy::primitives::{B256, Bytes};
use alloy::sol_types::SolValue;
use automata_tee_workload_measurement::stubs::TeeReport;
use std::collections::BTreeMap;
use std::path::Path;

use crate::device::PlatformInfo;

use super::pcr::PcrBank;

// ---------------------------------------------------------------------------
// TDX quote layout constants
// ---------------------------------------------------------------------------

/// Byte offset of RTMR3 in a TDX V4 quote (48-byte header + 480 body offset).
const TDX_RTMR3_OFFSET: usize = 528;
const TDX_RTMR3_LEN: usize = 48;

/// Byte offset of reportData in a TDX V4 quote (48-byte header + 528 body offset).
const TDX_REPORT_DATA_OFFSET: usize = 576;
const TDX_REPORT_DATA_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Fixture data types (deserialized from JSON)
// ---------------------------------------------------------------------------

/// Fixture data loaded from `mock_device_data.json`.
///
/// Only contains data that comes from the real device.  Derivable fields
/// (AK public key coordinates, signing key) are computed automatically.
#[derive(serde::Deserialize, Clone)]
pub struct MockDeviceData {
    /// DER-encoded certificate chain (hex strings with optional `0x` prefix).
    /// The AK P-256 public key is auto-extracted from the leaf cert (`certs[0]`).
    pub ak_certs: Vec<Bytes>,
    pub pcr_values: BTreeMap<String, B256>,
    /// TEE attestation report (e.g. TDX quote).
    pub tee_report: TeeReport,
}

#[derive(serde::Deserialize, Clone)]
pub struct PlatformData {
    pub cloud_type: String,
    pub tee_type: String,
    pub machine_type: String,
}

// ---------------------------------------------------------------------------
// Minimal DER parser -- extract EC P-256 public key from X.509 certificate
// ---------------------------------------------------------------------------

/// Read a DER tag+length at `pos`, return `(content_start, content_len)`.
fn der_tl(der: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= der.len() {
        return None;
    }
    let _tag = der[pos];
    let mut idx = pos + 1;
    if idx >= der.len() {
        return None;
    }
    let first = der[idx] as usize;
    idx += 1;
    let len = if first < 0x80 {
        first
    } else {
        let num_bytes = first & 0x7F;
        let mut len = 0usize;
        for _ in 0..num_bytes {
            if idx >= der.len() {
                return None;
            }
            len = (len << 8) | der[idx] as usize;
            idx += 1;
        }
        len
    };
    Some((idx, len))
}

/// Skip past the TLV node at `pos`, returning the position of the next sibling.
fn der_next(der: &[u8], pos: usize) -> Option<usize> {
    let (content_start, content_len) = der_tl(der, pos)?;
    Some(content_start + content_len)
}

/// Enter a constructed (SEQUENCE) node at `pos`, returning the content start.
fn der_child(der: &[u8], pos: usize) -> Option<usize> {
    let (content_start, _) = der_tl(der, pos)?;
    Some(content_start)
}

/// Extract the EC P-256 public key (x, y) from a DER-encoded X.509 certificate.
///
/// Navigates: Certificate -> TBSCertificate -> SubjectPublicKeyInfo -> BIT STRING
pub(crate) fn extract_ec_p256_pubkey(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let cert_content = der_child(der, 0)?;
    let tbs_content = der_child(der, cert_content)?;

    let mut ptr = tbs_content;
    if der.get(ptr).copied() == Some(0xA0) {
        ptr = der_next(der, ptr)?;
    }
    for _ in 0..5 {
        ptr = der_next(der, ptr)?;
    }
    let spki_content = der_child(der, ptr)?;
    let bitstring_pos = der_next(der, spki_content)?;
    let (bs_content, bs_len) = der_tl(der, bitstring_pos)?;
    if bs_len < 66 || der.get(bs_content).copied() != Some(0x00) {
        return None;
    }
    let key_data = &der[bs_content + 1..bs_content + bs_len];
    if key_data.len() >= 65 && key_data[0] == 0x04 {
        let x: [u8; 32] = key_data[1..33].try_into().ok()?;
        let y: [u8; 32] = key_data[33..65].try_into().ok()?;
        Some((x, y))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// P-256 key helper (real ECDSA key pair)
// ---------------------------------------------------------------------------

/// A real NIST P-256 key pair capable of producing valid ECDSA signatures.
///
/// Public coordinates (x, y) are derived from the private key and used in
/// TPMT_PUBLIC structures.  The private key is used by
/// [`MockDeviceProvider`](super::mock_device::MockDeviceProvider) to sign
/// delegation digests that the on-chain `SignatureVerifier` can verify.
#[derive(Clone)]
pub struct P256Key {
    pub x: [u8; 32],
    pub y: [u8; 32],
    signing_key: p256::ecdsa::SigningKey,
}

impl P256Key {
    /// Generate a random P-256 key pair.
    pub fn random() -> Self {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x: [u8; 32] = point
            .x()
            .expect("x coordinate")
            .to_vec()
            .try_into()
            .unwrap();
        let y: [u8; 32] = point
            .y()
            .expect("y coordinate")
            .to_vec()
            .try_into()
            .unwrap();
        Self { x, y, signing_key }
    }

    /// Create a key from public coordinates only (no signing capability).
    ///
    /// Used for AK public keys extracted from certificates, where we only
    /// need the public point for TPMT_PUBLIC structures.
    pub fn from_public(x: [u8; 32], y: [u8; 32]) -> Self {
        // Use a dummy signing key — sign_digest() should not be called on
        // AK keys (the AK never signs delegation messages).
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        Self { x, y, signing_key }
    }

    /// 65-byte SEC1 uncompressed public key: `0x04 || x || y`.
    pub fn uncompressed(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(65);
        key.push(0x04);
        key.extend_from_slice(&self.x);
        key.extend_from_slice(&self.y);
        key
    }

    /// Sign a 32-byte digest and return a DER-encoded ECDSA signature.
    pub fn sign_digest(&self, digest: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::DerSignature = self
            .signing_key
            .sign_prehash(digest)
            .expect("P-256 signing should not fail");
        sig.as_bytes().to_vec()
    }

    /// Sign a 32-byte digest and return raw (r, s) as 32-byte big-endian arrays.
    ///
    /// This is the format expected by TPMT_SIGNATURE structures.
    pub fn sign_digest_raw(&self, digest: &[u8]) -> ([u8; 32], [u8; 32]) {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self
            .signing_key
            .sign_prehash(digest)
            .expect("P-256 signing should not fail");
        let (r_bytes, s_bytes) = sig.split_bytes();
        (r_bytes.into(), s_bytes.into())
    }
}

// ---------------------------------------------------------------------------
// MockDataBuilder
// ---------------------------------------------------------------------------

/// Fluent builder for constructing a [`MockDeviceProvider`] from fixture data.
///
/// Loads base attestation data from JSON, allows TPM-semantic mutations
/// (reset/extend PCR slots, set RTMR3), and auto-computes all derived
/// values when [`build`](Self::build) is called.
///
/// The TEE report must be provided (from JSON fixture or via
/// [`set_tee_report`](Self::set_tee_report)) — it is never auto-generated.
#[derive(Clone, Debug)]
pub struct MockDataBuilder {
    pub pcr_bank: PcrBank,
    /// Raw DER-encoded AK certificate chain.
    pub ak_certs_raw: Vec<Bytes>,
    pub platform_info: PlatformInfo,
    /// TEE attestation report (required, provided by user or fixture).
    pub tee_report: TeeReport,
}

impl MockDataBuilder {
    /// Create a new builder from the embedded `mock_device_data.json` fixture.
    pub fn new() -> Self {
        let json = include_str!("mock_device_data.json");
        Self::from_json(json)
    }

    /// Create a new builder from a JSON string.
    pub fn from_json(json: &str) -> Self {
        let data: MockDeviceData =
            serde_json::from_str(json).expect("failed to parse mock device data JSON");
        Self::from_data(data)
    }

    /// Create a new builder from a file path.
    pub fn from_file(path: &Path) -> Self {
        let json = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        Self::from_json(&json)
    }

    /// Create a new builder from parsed fixture data.
    fn from_data(data: MockDeviceData) -> Self {
        let mut pcr_bank = PcrBank::new();
        for (key, value) in &data.pcr_values {
            let idx: usize = key.parse().expect("PCR index must be a number");
            pcr_bank.set_slot(idx, *value);
        }

        Self {
            pcr_bank,
            ak_certs_raw: data.ak_certs,
            platform_info: PlatformInfo::default(),
            tee_report: data.tee_report.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // TPM-semantic mutation API (all return Self for chaining)
    // -----------------------------------------------------------------------

    /// Reset a single PCR slot to all-zeros.
    pub fn reset_pcr(mut self, index: usize) -> Self {
        self.pcr_bank.reset(index);
        self
    }

    /// Extend a PCR slot: `PCR[i] = SHA256(PCR[i] || data)`.
    pub fn extend_pcr(mut self, index: usize, data: B256) -> Self {
        self.pcr_bank.extend(index, data);
        self
    }

    /// Extend a PCR slot with raw (unhashed) bytes.
    ///
    /// The data is first hashed with SHA-256 to produce the 32-byte event
    /// hash, then the PCR is extended as normal.
    pub fn extend_pcr_raw(mut self, index: usize, data: &[u8]) -> Self {
        self.pcr_bank.extend_raw(index, data);
        self
    }

    /// Set the RTMR3 value (TDX workload measurement, 48 bytes).
    pub fn set_tdx_rtmr3(mut self, value: [u8; 48]) -> Self {
        let mut data = self.tee_report.data.to_vec();
        data[TDX_RTMR3_OFFSET..TDX_RTMR3_OFFSET + TDX_RTMR3_LEN].copy_from_slice(&value);
        self.tee_report.data = Bytes::from(data);
        self
    }

    pub fn set_tdx_report_data(mut self, report_data: [u8; 64]) -> Self {
        let mut data = self.tee_report.data.to_vec();
        data[TDX_REPORT_DATA_OFFSET..TDX_REPORT_DATA_OFFSET + TDX_REPORT_DATA_LEN]
            .copy_from_slice(&report_data);
        self.tee_report.data = Bytes::from(data);
        self
    }

    /// Set the TEE attestation report (e.g. a real TDX/SEV-SNP quote).
    ///
    /// This replaces the report loaded from the JSON fixture.
    pub fn set_tee_report(
        mut self,
        verification_backend_type: u8,
        tee_type: u8,
        data: Bytes,
    ) -> Self {
        self.tee_report = TeeReport {
            verification_backend_type,
            tee_type,
            data,
        };
        self
    }

    // -----------------------------------------------------------------------
    // Mutable (non-chaining) mutation API
    // -----------------------------------------------------------------------

    /// Reset a PCR slot to all-zeros (mutable reference version).
    pub fn reset_pcr_mut(&mut self, index: usize) {
        self.pcr_bank.reset(index);
    }

    /// Extend a PCR slot (mutable reference version).
    pub fn extend_pcr_mut(&mut self, index: usize, data: B256) {
        self.pcr_bank.extend(index, data);
    }

    /// Extend a PCR slot with raw bytes (mutable reference version).
    pub fn extend_pcr_raw_mut(&mut self, index: usize, data: &[u8]) {
        self.pcr_bank.extend_raw(index, data);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Access the underlying PCR bank for inspection.
    pub fn pcr_bank(&self) -> &PcrBank {
        &self.pcr_bank
    }

    pub fn ak_pub(&self) -> P256Key {
        let (x, y) = extract_ec_p256_pubkey(&self.ak_certs_raw[0])
            .expect("failed to extract EC P-256 public key from leaf certificate");
        P256Key::from_public(x, y)
    }

    pub fn ak_certs_encoded(&self) -> Bytes {
        self.ak_certs_raw.abi_encode().into()
    }
}

impl Default for MockDataBuilder {
    fn default() -> Self {
        Self::new()
    }
}
