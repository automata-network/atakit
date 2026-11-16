//! Domain separator constants mirroring
//! `automata-tee-workload-measurement/src/types/Constants.sol`.
//!
//! Each constant is `keccak256(<solidity literal>)`. The Solidity
//! definition is the spec; these Rust values are validated against
//! it in [`tests`] via a recomputed keccak256.

use alloy_primitives::B256;

/// Solidity: `keccak256("KEY_RESOLVER_V1")`.
/// Used inside [`crate::compute_key_fingerprint`].
pub const KEY_DOMAIN: B256 = B256::new(hex_literal_32(
    "600fb55be89383d97dd7818b7397d8cf7527df5a09a3b23715a048d3b63fb28b",
));

/// Solidity: `keccak256("CVM_SESSION_V1")`.
/// Used inside [`crate::compute_session_id`].
pub const SESSION_DOMAIN: B256 = B256::new(hex_literal_32(
    "697b3cd47b0644a2b1c05579cf2c5893fe4360d2564fd6ee9b81e77079b96293",
));

/// Solidity: `keccak256("CVM_SESSION_KEY_DELEGATION")`.
/// Used inside [`crate::compute_delegation_digest`].
pub const DELEGATION_DOMAIN: B256 = B256::new(hex_literal_32(
    "5fe31136e14cc6c571c5f2246a7abab90086469a7717fd6b4fe1bac11aa81f4a",
));

/// Solidity: `keccak256("CVM_SESSION_ROTATE_KEY_V1")`.
pub const SESSION_ROTATE_KEY_DOMAIN: B256 = B256::new(hex_literal_32(
    "55997df232b2d66bd3186581c7f2e14645eaab4f3f2639094d98fcec722262bb",
));

/// Solidity: `keccak256("CVM_SESSION_RENEW_V1")`.
pub const SESSION_RENEW_DOMAIN: B256 = B256::new(hex_literal_32(
    "37c7a989c0f449c8a96b989e27657c5da4e742cd5b0e3dc9d7cb92e21176570e",
));

/// Solidity: `keccak256("CVM_BASEIMAGE_V1")`.
pub const BASEIMAGE_DOMAIN: B256 = B256::new(hex_literal_32(
    "46115c7a685052185279e890e6f7a6a18da12a094f9824557ef4c1a4590736a4",
));

/// Solidity: `keccak256("CVM_WORKLOAD_V1")`.
pub const WORKLOAD_DOMAIN: B256 = B256::new(hex_literal_32(
    "43c428a4f06ab11fb82aac2f7486ab616b80c1323a446638b7f62715d4c8e5b2",
));

/// Solidity: `keccak256("CVM_PLATFORM_PROFILE_V1")`.
pub const PLATFORM_PROFILE_DOMAIN: B256 = B256::new(hex_literal_32(
    "eacf668b9583f4b0aee6edca41b26825013d1300ffcb4eac13c8a66d994f2004",
));

/// Solidity: `keccak256("CVM_PLATFORM_VARIANT_V1")`.
pub const PLATFORM_VARIANT_DOMAIN: B256 = B256::new(hex_literal_32(
    "4b62f45cd642ea0f66f5f9aa66cfce11da39afb41198be966251911363dafe7f",
));

/// Solidity: `keccak256("CVM_SESSION_REG_NONCE_V1")`.
/// Used by the portal to derive `qualifying_data` for the Quote's
/// `extraData` per `project_trust_chain_qualifying_data` memory.
pub const SESSION_NONCE_DOMAIN: B256 = B256::new(hex_literal_32(
    "59caedc634c00f5b35e1a73edff6e757849c0fb82094480db9c66e9ea92f64e9",
));

/// Solidity: `keccak256("CVM_MSG_SESSION_REGISTER_V1")`.
/// Used inside [`crate::compute_owner_signature_payload`].
pub const SESSION_REGISTER_MSG: B256 = B256::new(hex_literal_32(
    "ea255740ebc8b92dd501a7abe06ca898a3cafd61398ebb4714aa43e8af8e8aee",
));

/// Solidity: `keccak256("CVM_MSG_SESSION_ROTATE_KEY_V1")`.
pub const SESSION_ROTATE_KEY_MSG: B256 = B256::new(hex_literal_32(
    "35bc7dbc6065f16ec1a121e394b4def21af016a19a4807eae353231a7b644326",
));

/// Solidity: `keccak256("CVM_MSG_SESSION_RENEW_V1")`.
pub const SESSION_RENEW_MSG: B256 = B256::new(hex_literal_32(
    "af6e7c37d438349d2dd85f2d2507703ad2f6893900bae598146eec2dfb6746e8",
));

/// Solidity: `keccak256("CVM_MSG_SESSION_RECOVER_V1")`.
pub const SESSION_RECOVER_MSG: B256 = B256::new(hex_literal_32(
    "1382594f92a7140bab1abb4fa585ff7bcd5c3f416a89a7538e819666e0e0d37a",
));

// -- Internal helpers --

/// `const fn` hex decoder: parses a 64-char hex string into a 32-byte
/// array at compile time. Panics with a descriptive message if the
/// string isn't exactly 64 ASCII hex chars. Used so the domain
/// constants can be `pub const` and inlined at every call site.
const fn hex_literal_32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        panic!("hex_literal_32 expects 64 hex chars");
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (decode_hex_nibble(bytes[2 * i]) << 4) | decode_hex_nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn decode_hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => panic!("hex_literal_32 saw a non-hex character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    /// Diagnostic helper: prints `keccak256(literal)` for every
    /// domain string so constants can be regenerated when upstream
    /// adds or renames one. Run with
    /// `cargo test -p atakit-portal-chain print_domain_keccaks --
    ///   --nocapture --ignored`.
    #[test]
    #[ignore]
    fn print_domain_keccaks() {
        let literals = [
            "KEY_RESOLVER_V1",
            "CVM_SESSION_V1",
            "CVM_SESSION_KEY_DELEGATION",
            "CVM_SESSION_ROTATE_KEY_V1",
            "CVM_SESSION_RENEW_V1",
            "CVM_BASEIMAGE_V1",
            "CVM_WORKLOAD_V1",
            "CVM_PLATFORM_PROFILE_V1",
            "CVM_PLATFORM_VARIANT_V1",
            "CVM_SESSION_REG_NONCE_V1",
            "CVM_MSG_SESSION_REGISTER_V1",
            "CVM_MSG_SESSION_ROTATE_KEY_V1",
            "CVM_MSG_SESSION_RENEW_V1",
            "CVM_MSG_SESSION_RECOVER_V1",
        ];
        for s in literals {
            let d = keccak256(s.as_bytes());
            println!("{}: {}", s, hex::encode(d.as_slice()));
        }
    }

    /// Validates each compile-time domain constant against a runtime
    /// `keccak256(<solidity literal>)`. If this passes, our `bytes32`
    /// constants are exactly what `Constants.sol` says they are.
    /// If this fails, the upstream Solidity literal changed (or our
    /// hex value drifted) — fix here first, then run the rest of
    /// the suite to catch downstream consumers.
    #[test]
    fn domains_match_solidity_keccak() {
        let cases: &[(&str, B256)] = &[
            ("KEY_RESOLVER_V1", KEY_DOMAIN),
            ("CVM_SESSION_V1", SESSION_DOMAIN),
            ("CVM_SESSION_KEY_DELEGATION", DELEGATION_DOMAIN),
            ("CVM_SESSION_ROTATE_KEY_V1", SESSION_ROTATE_KEY_DOMAIN),
            ("CVM_SESSION_RENEW_V1", SESSION_RENEW_DOMAIN),
            ("CVM_BASEIMAGE_V1", BASEIMAGE_DOMAIN),
            ("CVM_WORKLOAD_V1", WORKLOAD_DOMAIN),
            ("CVM_PLATFORM_PROFILE_V1", PLATFORM_PROFILE_DOMAIN),
            ("CVM_PLATFORM_VARIANT_V1", PLATFORM_VARIANT_DOMAIN),
            ("CVM_SESSION_REG_NONCE_V1", SESSION_NONCE_DOMAIN),
            ("CVM_MSG_SESSION_REGISTER_V1", SESSION_REGISTER_MSG),
            ("CVM_MSG_SESSION_ROTATE_KEY_V1", SESSION_ROTATE_KEY_MSG),
            ("CVM_MSG_SESSION_RENEW_V1", SESSION_RENEW_MSG),
            ("CVM_MSG_SESSION_RECOVER_V1", SESSION_RECOVER_MSG),
        ];
        for (literal, expected) in cases {
            let computed = keccak256(literal.as_bytes());
            assert_eq!(
                computed,
                *expected,
                "domain `{literal}` mismatch: computed 0x{} expected 0x{}",
                hex::encode(computed),
                hex::encode(expected.as_slice()),
            );
        }
    }
}
