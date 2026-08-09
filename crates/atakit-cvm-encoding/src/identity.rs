use alloy_primitives::{keccak256, Bytes, B256};
use alloy_sol_types::{sol_data, SolType, SolValue};
use atakit_cvm_types::AppRef;

pub const KEY_DOMAIN_NAME: &str = "KEY_RESOLVER_V1";
pub const BASE_IMAGE_DOMAIN_NAME: &str = "CVM_BASEIMAGE_V1";
pub const PLATFORM_PROFILE_DOMAIN_NAME: &str = "CVM_PLATFORM_PROFILE_V1";
pub const PLATFORM_VARIANT_DOMAIN_NAME: &str = "CVM_PLATFORM_VARIANT_V1";
pub const WORKLOAD_DOMAIN_NAME: &str = "CVM_WORKLOAD_V1";

type KeyFingerprintArgs = (sol_data::FixedBytes<32>, sol_data::Uint<8>, sol_data::Bytes);

pub fn base_image_id(app_ref: &AppRef) -> [u8; 32] {
    app_id(BASE_IMAGE_DOMAIN_NAME, app_ref)
}

pub fn workload_id(app_ref: &AppRef) -> [u8; 32] {
    app_id(WORKLOAD_DOMAIN_NAME, app_ref)
}

pub fn platform_profile_id(base_image_id: [u8; 32], profile_name: &str) -> [u8; 32] {
    keccak256(
        (
            keccak256(PLATFORM_PROFILE_DOMAIN_NAME),
            B256::from(base_image_id),
            profile_name.to_owned(),
        )
            .abi_encode_params(),
    )
    .into()
}

pub fn variant_id(platform_profile_id: [u8; 32], variant_name: &str) -> [u8; 32] {
    keccak256(
        (
            keccak256(PLATFORM_VARIANT_DOMAIN_NAME),
            B256::from(platform_profile_id),
            variant_name.to_owned(),
        )
            .abi_encode_params(),
    )
    .into()
}

pub fn key_fingerprint(type_id: u8, key: &[u8]) -> [u8; 32] {
    keccak256(KeyFingerprintArgs::abi_encode_params(&(
        keccak256(KEY_DOMAIN_NAME),
        type_id,
        Bytes::copy_from_slice(key),
    )))
    .into()
}

fn app_id(domain_name: &str, app_ref: &AppRef) -> [u8; 32] {
    keccak256(
        (
            keccak256(domain_name),
            B256::from(app_ref.publisher),
            app_ref.name.clone(),
            app_ref.version.clone(),
        )
            .abi_encode_params(),
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publisher() -> [u8; 32] {
        hex::decode("aef8fc89416f01494ec6534de68d30aab26d7598db8a05967b0ba7d3ecb259d2")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn campaign_base_image_id_matches_the_specification_vector() {
        let reference = AppRef::new(publisher(), "automata-linux", "v0.2.8-debug");
        assert_eq!(
            hex::encode(base_image_id(&reference)),
            "c885d7a0420ea15dd59fe99ba5fcb6c66b62f51ac808fd8bfc040e033bff6d53"
        );
    }

    #[test]
    fn campaign_workload_id_matches_the_specification_vector() {
        let reference = AppRef::new(publisher(), "iperf-benchmark", "v0.1.2");
        assert_eq!(
            hex::encode(workload_id(&reference)),
            "8dc6a606e11a52b61a2431226716b0b429d2f6ad476057ecf1e9b0e536a6f2c8"
        );
    }

    #[test]
    fn campaign_platform_profile_id_matches_the_specification_vector() {
        let reference = AppRef::new(publisher(), "automata-linux", "v0.2.8-debug");
        assert_eq!(
            hex::encode(platform_profile_id(base_image_id(&reference), "azure-tdx")),
            "83d2d9454032c121548d1e27eead0358a4ccd10a3450bda51566b79d5b2acdc8"
        );
    }

    #[test]
    fn publisher_and_domain_change_the_identifier() {
        let reference = AppRef::new(publisher(), "shared-name", "v1");
        let other_publisher = AppRef::new([0xab; 32], "shared-name", "v1");
        assert_ne!(base_image_id(&reference), base_image_id(&other_publisher));
        assert_ne!(base_image_id(&reference), workload_id(&reference));
    }

    #[test]
    fn key_fingerprint_handles_a_multiword_dynamic_key_length() {
        let key = (0u8..=255).collect::<Vec<_>>();
        let fingerprint = key_fingerprint(1, &key);
        let padded_key_len = key.len().div_ceil(32) * 32;
        let mut reference_encoding = vec![0u8; 128 + padded_key_len];
        reference_encoding[..32].copy_from_slice(keccak256(KEY_DOMAIN_NAME).as_slice());
        reference_encoding[63] = 1;
        reference_encoding[95] = 96;
        reference_encoding[120..128].copy_from_slice(&(key.len() as u64).to_be_bytes());
        reference_encoding[128..128 + key.len()].copy_from_slice(&key);

        assert_eq!(fingerprint, <[u8; 32]>::from(keccak256(reference_encoding)));
        assert_ne!(fingerprint, key_fingerprint(2, &key));
    }
}
