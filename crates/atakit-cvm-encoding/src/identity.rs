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
        hex::decode("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn synthetic_base_image_id_matches_the_specification_vector() {
        let reference = AppRef::new(publisher(), "example-image", "v1.0.0");
        assert_eq!(
            hex::encode(base_image_id(&reference)),
            "6868dc0ec5c8668552e730b2c6a3fcc6889638397ac0ed367f70563474f878df"
        );
    }

    #[test]
    fn synthetic_workload_id_matches_the_specification_vector() {
        let reference = AppRef::new(publisher(), "example-workload", "v1.0.0");
        assert_eq!(
            hex::encode(workload_id(&reference)),
            "04cd58e22842dc0ba399ed4c5ae9685a84d11a7c0fdf91666525eb2a8f1d1a5b"
        );
    }

    #[test]
    fn synthetic_platform_profile_id_matches_the_specification_vector() {
        let reference = AppRef::new(publisher(), "example-image", "v1.0.0");
        assert_eq!(
            hex::encode(platform_profile_id(base_image_id(&reference), "azure-tdx")),
            "d2d25df86b1c5b443711ec7f7ecee06fd1dc7abd73144185f4a3b2501cb883ac"
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
