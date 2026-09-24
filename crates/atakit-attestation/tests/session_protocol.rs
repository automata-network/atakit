use alloy_primitives::{Address, B256, U256};
use atakit_attestation::session_protocol::*;
use atakit_attestation::signing::*;
use atakit_attestation::{
    compute_key_fingerprint, compute_session_id, compute_session_qualifying_data, delegation_digest,
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

// Captured and compared byte-for-byte with atakit-portal-chain revision
// 079cb59c3434926890f0017a19b9684f86dddfb5 before removing that dependency.
const EXPECTED: [[&str; 9]; 2] = [
[
"0x493238de31c3255f74c3fef24f383f078e8abeb54686f0b328c5f6172e50cd92",
"0xca2650deb7fa57dd4e640724381394d415c8a604a8282396bb133df04869b06c",
"0x7d82ea18ed47d1a5070dd22123552a654ae0f741004f25f229110d2c899cd165",
"0xd0726ebae894922c7f2bf2aac17075f5b75508f7b6475cdc39701d5b5858dd41",
"0x64b5eb02469e4d2028b02bab7b83cd931aaf392dd620e0f2dbce7c96adc5c50c",
"0x0b888cb994bec1945c92d0e274fe26ab0343237f7e626177cc790f2f862514c0",
"0xe605fbfef8b2c3b80719ead48b54e1f5e199b511ddda19f7704e470bbcfb546b",
"041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1",
"5b6a8319ca75509315f66be1aed8ba4663c50901eb4ccd503dd5aa2878c305f16040e5a1fc8e4b36b3c5288af89f7f15255dfa0228f393c1de2f7fc13f043a421b",
],
[
"0x493238de31c3255f74c3fef24f383f078e8abeb54686f0b328c5f6172e50cd92",
"0x6549cfc6d2981c5dbb4a4c024a3da6ca9d0ebcd098ff5435b2bb9edacfe1599c",
"0xed783be3168aa198d513fcce703fc998a182b5fe34b5b694f5d61a6436a6da83",
"0x749c428519fa1b09d4d0165a8bef3f71309886b67d2f9c03c6e7514eafbc54ef",
"0x90cf499118c1f1eb2a0f7580a72caf126e55b774e581f3dae4ba627c04e9602f",
"0x96824e457f9ba57b44270628d3572de0ba6b721c56e6dd8a11f324ab0d6a48d3",
"0x363644656e45c9398c61528d448877c6b62e3e2187231d2f03e1e3ac14e0a9c3",
"044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0",
"3dff5ea1cc9ebc178d53dd82486cf926119c3436d4292d9a008bde109731a58254b083e4021d26661b82908044d8fec8179d3416d809b4900b4eefa120154c051b",
],
];
#[test]
fn digests_and_signatures_match_fixed_vectors() {
    for ((i, chain, nonce, expiry), expected) in [
        (1u8, 560048u64, U256::from(123456), 789012u64),
        (2, u64::MAX, U256::MAX, u64::MAX),
    ]
    .into_iter()
    .zip(EXPECTED)
    {
        let registry = Address::from([i; 20]);
        let b = |v| B256::from([v; 32]);
        let digests = [
            compute_session_id([3; 32], [4; 32]).into(),
            delegation_digest(chain, registry.into(), [3; 32], [4; 32], [5; 32], [6; 32]).into(),
            compute_session_qualifying_data(chain, registry.into(), [3; 32], nonce.to_be_bytes())
                .into(),
            compute_owner_signature_payload(
                chain,
                registry,
                expiry,
                b(3),
                b(4),
                b(5),
                b(6),
                b(7),
                b(8),
            )
            .into(),
            compute_rotate_key_tpm_payload(chain, registry, b(3), b(4), b(5), b(6)),
            compute_rotate_key_owner_payload(chain, registry, expiry, b(3), b(4)).into(),
        ];
        for (actual, expected) in digests.iter().zip(&expected[..6]) {
            assert_eq!(actual.to_string(), *expected);
        }
        let public = derive_public_key_uncompressed(&[i; 32]).unwrap();
        assert_eq!(
            B256::from(compute_key_fingerprint(3, &public)).to_string(),
            expected[6]
        );
        assert_eq!(hex::encode(public), expected[7]);
        let sig =
            sign_secp256k1_recoverable(&[i; 32], [42; 32], SigEncoding::EthereumLegacyV).unwrap();
        assert_eq!(hex::encode(sig), expected[8]);
        let signature = Signature::from_slice(&sig[..64]).unwrap();
        assert!(signature.normalize_s().is_none());
        let id = RecoveryId::try_from(sig[64] - 27).unwrap();
        let recovered = VerifyingKey::recover_from_prehash(&[42; 32], &signature, id).unwrap();
        assert_eq!(recovered.to_encoded_point(false).as_bytes(), public);
    }
}

#[test]
fn key_helpers_validate_inputs_and_generate_valid_distinct_keys() {
    for invalid in [vec![], vec![1; 31], vec![1; 33], vec![0; 32], vec![255; 32]] {
        assert!(derive_public_key_uncompressed(&invalid).is_err());
        assert!(
            sign_secp256k1_recoverable(&invalid, [42; 32], SigEncoding::EthereumLegacyV).is_err()
        );
    }
    assert_eq!(
        decode_secret_key_hex(&format!("  0x{}\n", "01".repeat(32))).unwrap(),
        [1; 32]
    );
    assert_eq!(decode_secret_key_hex(&"01".repeat(32)).unwrap(), [1; 32]);
    for invalid in ["xyz", "0x01", ""] {
        assert!(decode_secret_key_hex(invalid).is_err());
    }
    let keys = [generate_secret_key_bytes(), generate_secret_key_bytes()];
    assert_ne!(keys[0], keys[1]);
    for key in keys {
        assert_eq!(derive_public_key_uncompressed(&key).unwrap()[0], 4);
    }
}
