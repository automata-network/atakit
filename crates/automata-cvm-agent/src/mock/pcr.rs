//! Mock PCR (Platform Configuration Register) bank.
//!
//! Simulates a TPM PCR bank with 24 SHA-256 slots, supporting `reset` and
//! `extend` operations.  The resulting values are used to build TPM quote
//! structures and on-chain PCR verification data.

use alloy::primitives::B256;
use sha2::{Digest, Sha256};

/// Number of PCR slots in a standard TPM 2.0 bank.
pub const PCR_COUNT: usize = 24;

/// SHA-256 digest length in bytes.
const HASH_LEN: usize = 32;

/// Simulated PCR bank (SHA-256).
///
/// Automatically tracks which PCR indices have been written to (via `set_slot`,
/// `extend`, or `extend_raw`).  The tracked indices are kept sorted and
/// deduplicated, ready for use in TPM quote selection bitmaps.
#[derive(Clone, Debug)]
pub struct PcrBank {
    slots: [B256; PCR_COUNT],
    /// Sorted, deduplicated list of PCR indices that have been written to.
    indices: Vec<usize>,
}

impl Default for PcrBank {
    fn default() -> Self {
        Self::new()
    }
}

impl PcrBank {
    /// Create a new bank with all PCR slots initialised to zero.
    pub fn new() -> Self {
        Self {
            slots: [B256::ZERO; PCR_COUNT],
            indices: Vec::new(),
        }
    }

    /// Record that a PCR index has been written to (sorted insert, no duplicates).
    fn track(&mut self, index: usize) {
        if let Err(pos) = self.indices.binary_search(&index) {
            self.indices.insert(pos, index);
        }
    }

    /// Reset a single PCR slot to all-zeros.
    pub fn reset(&mut self, index: usize) {
        assert!(index < PCR_COUNT, "PCR index out of range");
        self.slots[index] = B256::ZERO;
        self.track(index);
    }

    /// Extend a PCR slot: `PCR[i] = SHA256(PCR[i] || data)`.
    pub fn extend(&mut self, index: usize, data: B256) {
        assert!(index < PCR_COUNT, "PCR index out of range");
        let mut hasher = Sha256::new();
        hasher.update(self.slots[index].as_slice());
        hasher.update(data.as_slice());
        let hash: [u8; HASH_LEN] = hasher.finalize().into();
        self.slots[index] = hash.into();
        self.track(index);
    }

    /// Extend a PCR slot using raw (unhashed) bytes.
    ///
    /// This first hashes `data` with SHA-256 to produce a 32-byte event
    /// hash, then calls [`extend`](Self::extend).
    pub fn extend_raw(&mut self, index: usize, data: &[u8]) {
        let event_hash: [u8; HASH_LEN] = Sha256::digest(data).into();
        self.extend(index, event_hash.into());
    }

    /// Directly set a PCR slot to a specific value.
    ///
    /// This bypasses normal TPM extend semantics and is intended for loading
    /// fixture data where the final PCR values are already known.
    pub fn set_slot(&mut self, index: usize, value: B256) {
        assert!(index < PCR_COUNT, "PCR index out of range");
        self.slots[index] = value;
        self.track(index);
    }

    /// Read the current value of a PCR slot.
    pub fn get(&self, index: usize) -> &B256 {
        assert!(index < PCR_COUNT, "PCR index out of range");
        &self.slots[index]
    }

    /// Export all 24 PCR values as a flat array.
    pub fn values(&self) -> &[B256; PCR_COUNT] {
        &self.slots
    }

    /// Sorted, deduplicated list of PCR indices that have been written to.
    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    /// Compute the PCR digest for a given selection of PCR indices.
    ///
    /// `digest = SHA256(PCR[indices[0]] || PCR[indices[1]] || ...)`
    ///
    /// Indices must be sorted in ascending order (as required by the TPM spec
    /// and the on-chain verifier).
    pub fn digest(&self, indices: &[usize]) -> B256 {
        let mut concatenated = Vec::with_capacity(indices.len() * HASH_LEN);
        for &i in indices {
            assert!(i < PCR_COUNT, "PCR index out of range");
            concatenated.extend_from_slice(self.slots[i].as_slice());
        }
        let hash: [u8; HASH_LEN] = Sha256::digest(&concatenated).into();
        hash.into()
    }

    /// Build the 4-byte PCR selection bitmap for the given indices.
    ///
    /// The bitmap is encoded in little-endian byte order (as used in the
    /// TPM2 TPMS_PCR_SELECTION structure and verified on-chain).
    pub fn selection_bitmap(indices: &[usize]) -> [u8; 4] {
        let mut bitmap: u32 = 0;
        for &i in indices {
            assert!(i < 32, "PCR index out of range for 32-bit bitmap");
            bitmap |= 1 << i;
        }
        // Little-endian byte order for the bitmap
        bitmap.to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_extend() {
        let mut bank = PcrBank::new();
        bank.extend(0, B256::repeat_byte(0xAB));
        // PCR[0] should no longer be zero
        assert_ne!(bank.get(0), &B256::ZERO);
    }

    #[test]
    fn test_pcr_reset() {
        let mut bank = PcrBank::new();
        bank.extend(5, B256::repeat_byte(1));
        bank.reset(5);
        assert_eq!(bank.get(5), &B256::ZERO);
    }

    #[test]
    fn test_selection_bitmap() {
        // PCR indices 0 and 2 -> bits 0 and 2 set -> 0b101 = 5
        let bitmap = PcrBank::selection_bitmap(&[0, 2]);
        assert_eq!(bitmap, [5, 0, 0, 0]);
    }
}
