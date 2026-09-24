use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub const TEE_ATTRIBUTE_NAMESPACE: &str = "atakit.attestation.v1.tee.";
pub const INTEL_TDX_DEBUG_NAME: &str = "atakit.attestation.v1.tee.intel-tdx.debug.enabled";
pub const INTEL_TDX_TCB_STATUS_ALLOWED_NAME: &str =
    "atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed";
pub const AMD_SEV_SNP_DEBUG_NAME: &str = "atakit.attestation.v1.tee.amd-sev-snp.debug.enabled";
pub const AMD_SEV_SNP_MIGRATE_MA_NAME: &str =
    "atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled";
pub const AMD_SEV_SNP_TCB_MINIMUM_NAME: &str = "atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum";
pub const AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME: &str =
    "atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy";

pub const INTEL_TDX_DEBUG_KEY: [u8; 32] = [
    0xe9, 0x60, 0x23, 0x94, 0x6a, 0x6a, 0xd6, 0x12, 0x75, 0xcb, 0x45, 0xa7, 0x96, 0xa2, 0x90, 0x5e,
    0x3d, 0x92, 0x31, 0x39, 0xce, 0x33, 0xb7, 0x73, 0x4f, 0x3b, 0xea, 0x4e, 0xec, 0x3d, 0x72, 0xcd,
];
pub const INTEL_TDX_TCB_STATUS_ALLOWED_KEY: [u8; 32] = [
    0xbc, 0x50, 0x5e, 0xab, 0x3c, 0xf5, 0x64, 0x3b, 0xdf, 0x24, 0xf1, 0xde, 0xe8, 0x69, 0x98, 0xcd,
    0x93, 0xd0, 0x5a, 0x29, 0x7e, 0x4c, 0x34, 0xf5, 0xe8, 0xf3, 0x7b, 0xba, 0x76, 0x4a, 0x81, 0x16,
];
pub const AMD_SEV_SNP_DEBUG_KEY: [u8; 32] = [
    0xe3, 0x51, 0x76, 0x80, 0xfe, 0x2d, 0x4f, 0x15, 0x75, 0x1d, 0xa8, 0x5b, 0x04, 0x00, 0xea, 0x90,
    0x9b, 0xb3, 0xd5, 0xae, 0x76, 0x23, 0x2c, 0x10, 0xa6, 0xc4, 0x47, 0x03, 0x1d, 0x63, 0x89, 0xb9,
];
pub const AMD_SEV_SNP_MIGRATE_MA_KEY: [u8; 32] = [
    0x90, 0x90, 0xb9, 0x94, 0xea, 0x40, 0x98, 0xb5, 0x65, 0xee, 0x0d, 0xa0, 0x1c, 0x4b, 0xca, 0xa0,
    0x83, 0xa5, 0xbf, 0xb1, 0x9c, 0x0a, 0x79, 0x7c, 0x7f, 0xfe, 0x3d, 0xe7, 0xce, 0x02, 0x51, 0xe1,
];
pub const AMD_SEV_SNP_TCB_MINIMUM_KEY: [u8; 32] = [
    0x15, 0x64, 0x76, 0x16, 0x16, 0x56, 0x18, 0xc3, 0xcf, 0xed, 0x2a, 0xb7, 0xf0, 0x83, 0xf2, 0xf7,
    0xee, 0xf7, 0xf5, 0x75, 0x19, 0xe4, 0x3d, 0x97, 0xab, 0x22, 0x0f, 0xf7, 0x86, 0x01, 0x57, 0xd2,
];
pub const AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY: [u8; 32] = [
    0x27, 0x9f, 0xd9, 0xa3, 0x17, 0xa2, 0xdc, 0x8d, 0xfe, 0xea, 0x12, 0x39, 0x1e, 0xa7, 0x95, 0xac,
    0x6c, 0x21, 0xff, 0x52, 0x97, 0x7c, 0x49, 0x9f, 0x91, 0x0f, 0x07, 0xa2, 0x7a, 0xfb, 0xed, 0x7d,
];

pub const ATTRIBUTE_FALSE: [u8; 32] = [0; 32];
pub const ATTRIBUTE_TRUE: [u8; 32] = {
    let mut value = [0; 32];
    value[31] = 1;
    value
};

pub const TDX_TCB_STATUS_NAMES: [(&str, u16); 8] = [
    ("ok", 1 << 0),
    ("sw-hardening-needed", 1 << 1),
    ("configuration-and-sw-hardening-needed", 1 << 2),
    ("configuration-needed", 1 << 3),
    ("out-of-date", 1 << 4),
    ("out-of-date-configuration-needed", 1 << 5),
    ("relaunch-advised", 1 << 8),
    ("relaunch-advised-configuration-needed", 1 << 9),
];
pub const TDX_TCB_STATUS_CONFIGURABLE_MASK: u16 = 0x33f;
pub const TDX_TCB_STATUS_OK: u16 = 1;
pub const AMD_SEV_SNP_PLATFORM_INFO_SUPPORTED_MASK: u64 = 0x3f;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    Boolean(bool),
    String(String),
}

pub type AttributeRequirements = BTreeMap<String, Vec<AttributeValue>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeePlatform {
    IntelTdx,
    AmdSevSnp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedAttributeValueKind {
    Boolean,
    IntelTdxTcbStatusMask,
    AmdSevSnpTcb,
    AmdSevSnpPlatformInfoPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedTeeAttribute {
    IntelTdxDebug,
    IntelTdxTcbStatusAllowed,
    AmdSevSnpDebug,
    AmdSevSnpMigrateMa,
    AmdSevSnpTcbMinimum,
    AmdSevSnpPlatformInfoPolicy,
}

impl VerifiedTeeAttribute {
    pub const ALL: [Self; 6] = [
        Self::IntelTdxDebug,
        Self::IntelTdxTcbStatusAllowed,
        Self::AmdSevSnpDebug,
        Self::AmdSevSnpMigrateMa,
        Self::AmdSevSnpTcbMinimum,
        Self::AmdSevSnpPlatformInfoPolicy,
    ];
    pub const BOOLEAN: [Self; 3] = [
        Self::IntelTdxDebug,
        Self::AmdSevSnpDebug,
        Self::AmdSevSnpMigrateMa,
    ];

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            INTEL_TDX_DEBUG_NAME => Some(Self::IntelTdxDebug),
            INTEL_TDX_TCB_STATUS_ALLOWED_NAME => Some(Self::IntelTdxTcbStatusAllowed),
            AMD_SEV_SNP_DEBUG_NAME => Some(Self::AmdSevSnpDebug),
            AMD_SEV_SNP_MIGRATE_MA_NAME => Some(Self::AmdSevSnpMigrateMa),
            AMD_SEV_SNP_TCB_MINIMUM_NAME => Some(Self::AmdSevSnpTcbMinimum),
            AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME => Some(Self::AmdSevSnpPlatformInfoPolicy),
            _ => None,
        }
    }

    pub fn from_key(key: &[u8; 32]) -> Option<Self> {
        match *key {
            INTEL_TDX_DEBUG_KEY => Some(Self::IntelTdxDebug),
            INTEL_TDX_TCB_STATUS_ALLOWED_KEY => Some(Self::IntelTdxTcbStatusAllowed),
            AMD_SEV_SNP_DEBUG_KEY => Some(Self::AmdSevSnpDebug),
            AMD_SEV_SNP_MIGRATE_MA_KEY => Some(Self::AmdSevSnpMigrateMa),
            AMD_SEV_SNP_TCB_MINIMUM_KEY => Some(Self::AmdSevSnpTcbMinimum),
            AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY => Some(Self::AmdSevSnpPlatformInfoPolicy),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::IntelTdxDebug => INTEL_TDX_DEBUG_NAME,
            Self::IntelTdxTcbStatusAllowed => INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
            Self::AmdSevSnpDebug => AMD_SEV_SNP_DEBUG_NAME,
            Self::AmdSevSnpMigrateMa => AMD_SEV_SNP_MIGRATE_MA_NAME,
            Self::AmdSevSnpTcbMinimum => AMD_SEV_SNP_TCB_MINIMUM_NAME,
            Self::AmdSevSnpPlatformInfoPolicy => AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
        }
    }

    pub const fn key(self) -> [u8; 32] {
        match self {
            Self::IntelTdxDebug => INTEL_TDX_DEBUG_KEY,
            Self::IntelTdxTcbStatusAllowed => INTEL_TDX_TCB_STATUS_ALLOWED_KEY,
            Self::AmdSevSnpDebug => AMD_SEV_SNP_DEBUG_KEY,
            Self::AmdSevSnpMigrateMa => AMD_SEV_SNP_MIGRATE_MA_KEY,
            Self::AmdSevSnpTcbMinimum => AMD_SEV_SNP_TCB_MINIMUM_KEY,
            Self::AmdSevSnpPlatformInfoPolicy => AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
        }
    }

    pub const fn platform(self) -> TeePlatform {
        match self {
            Self::IntelTdxDebug | Self::IntelTdxTcbStatusAllowed => TeePlatform::IntelTdx,
            Self::AmdSevSnpDebug
            | Self::AmdSevSnpMigrateMa
            | Self::AmdSevSnpTcbMinimum
            | Self::AmdSevSnpPlatformInfoPolicy => TeePlatform::AmdSevSnp,
        }
    }

    pub const fn value_kind(self) -> ReservedAttributeValueKind {
        match self {
            Self::IntelTdxTcbStatusAllowed => ReservedAttributeValueKind::IntelTdxTcbStatusMask,
            Self::AmdSevSnpTcbMinimum => ReservedAttributeValueKind::AmdSevSnpTcb,
            Self::AmdSevSnpPlatformInfoPolicy => {
                ReservedAttributeValueKind::AmdSevSnpPlatformInfoPolicy
            }
            Self::IntelTdxDebug | Self::AmdSevSnpDebug | Self::AmdSevSnpMigrateMa => {
                ReservedAttributeValueKind::Boolean
            }
        }
    }
}

pub fn validate_boolean_allowed_values(values: &[bool]) -> bool {
    values == [false] || values == [false, true]
}

pub fn attribute_key(name: &str) -> [u8; 32] {
    Keccak256::digest(name.as_bytes()).into()
}

pub fn attribute_string_value(value: &str) -> [u8; 32] {
    Keccak256::digest(value.as_bytes()).into()
}

pub fn bool_value(value: bool) -> [u8; 32] {
    if value {
        ATTRIBUTE_TRUE
    } else {
        ATTRIBUTE_FALSE
    }
}

pub fn tdx_tcb_status_bit(name: &str) -> Option<u16> {
    TDX_TCB_STATUS_NAMES
        .iter()
        .find_map(|(candidate, bit)| (*candidate == name).then_some(*bit))
}

pub fn tdx_tcb_status_mask<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<u16> {
    let mut mask = 0u16;
    for name in names {
        let bit = tdx_tcb_status_bit(name)?;
        if mask & bit != 0 {
            return None;
        }
        mask |= bit;
    }
    ((mask & TDX_TCB_STATUS_OK) != 0 && mask & !TDX_TCB_STATUS_CONFIGURABLE_MASK == 0)
        .then_some(mask)
}

pub fn tdx_tcb_status_names(mask: u16) -> Option<Vec<&'static str>> {
    if mask & TDX_TCB_STATUS_OK == 0 || mask & !TDX_TCB_STATUS_CONFIGURABLE_MASK != 0 {
        return None;
    }
    Some(
        TDX_TCB_STATUS_NAMES
            .iter()
            .filter_map(|(name, bit)| (mask & bit != 0).then_some(*name))
            .collect(),
    )
}

pub fn u16_value(value: u16) -> [u8; 32] {
    let mut encoded = [0; 32];
    encoded[30..].copy_from_slice(&value.to_be_bytes());
    encoded
}

pub fn u16_from_value(value: &[u8; 32]) -> Option<u16> {
    value[..30]
        .iter()
        .all(|byte| *byte == 0)
        .then(|| u16::from_be_bytes([value[30], value[31]]))
}

pub fn bytes32_hex(value: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(value))
}

pub fn parse_bytes32_hex(value: &str) -> Option<[u8; 32]> {
    let raw = value.strip_prefix("0x")?;
    hex::decode(raw).ok()?.try_into().ok()
}

pub fn valid_amd_sev_snp_tcb(value: &[u8; 32]) -> bool {
    value
        .as_chunks::<8>()
        .0
        .iter()
        .all(|lane| lane[..4].iter().all(|byte| *byte == 0))
}

pub fn amd_sev_snp_tcb_meets_minimum(actual: &[u8; 32], minimum: &[u8; 32]) -> bool {
    valid_amd_sev_snp_tcb(actual)
        && valid_amd_sev_snp_tcb(minimum)
        && actual
            .as_chunks::<8>()
            .0
            .iter()
            .zip(minimum.as_chunks::<8>().0)
            .all(|(actual_lane, minimum_lane)| {
                actual_lane[4..].iter().zip(&minimum_lane[4..]).all(
                    |(actual_component, minimum_component)| actual_component >= minimum_component,
                )
            })
}

pub fn amd_sev_snp_tcb_max(left: &[u8; 32], right: &[u8; 32]) -> Option<[u8; 32]> {
    if !valid_amd_sev_snp_tcb(left) || !valid_amd_sev_snp_tcb(right) {
        return None;
    }
    Some(std::array::from_fn(|index| left[index].max(right[index])))
}

pub fn valid_amd_sev_snp_platform_info_policy(value: &[u8; 32]) -> bool {
    if value[..16].iter().any(|byte| *byte != 0) {
        return false;
    }
    let required_clear = u64::from_be_bytes(value[16..24].try_into().expect("fixed slice"));
    let required_set = u64::from_be_bytes(value[24..32].try_into().expect("fixed slice"));
    required_set & !AMD_SEV_SNP_PLATFORM_INFO_SUPPORTED_MASK == 0
        && required_clear & !AMD_SEV_SNP_PLATFORM_INFO_SUPPORTED_MASK == 0
        && required_set & required_clear == 0
}

pub fn merge_amd_sev_snp_platform_info_policies(
    left: &[u8; 32],
    right: &[u8; 32],
) -> Option<[u8; 32]> {
    if !valid_amd_sev_snp_platform_info_policy(left)
        || !valid_amd_sev_snp_platform_info_policy(right)
    {
        return None;
    }
    let left_clear = u64::from_be_bytes(left[16..24].try_into().expect("fixed slice"));
    let left_set = u64::from_be_bytes(left[24..32].try_into().expect("fixed slice"));
    let right_clear = u64::from_be_bytes(right[16..24].try_into().expect("fixed slice"));
    let right_set = u64::from_be_bytes(right[24..32].try_into().expect("fixed slice"));
    let required_clear = left_clear | right_clear;
    let required_set = left_set | right_set;
    if required_clear & required_set != 0 {
        return None;
    }
    let mut merged = [0u8; 32];
    merged[16..24].copy_from_slice(&required_clear.to_be_bytes());
    merged[24..32].copy_from_slice(&required_set.to_be_bytes());
    Some(merged)
}

pub fn amd_sev_snp_platform_info_matches(actual: u64, policy: &[u8; 32]) -> bool {
    if !valid_amd_sev_snp_platform_info_policy(policy) {
        return false;
    }
    let required_clear = u64::from_be_bytes(policy[16..24].try_into().expect("fixed slice"));
    let required_set = u64::from_be_bytes(policy[24..32].try_into().expect("fixed slice"));
    actual & required_set == required_set && actual & required_clear == 0
}

pub fn readable_reserved_value(
    attribute: VerifiedTeeAttribute,
    value: &[u8; 32],
) -> Option<String> {
    match attribute.value_kind() {
        ReservedAttributeValueKind::Boolean if *value == ATTRIBUTE_FALSE => {
            Some("false".to_string())
        }
        ReservedAttributeValueKind::Boolean if *value == ATTRIBUTE_TRUE => Some("true".to_string()),
        ReservedAttributeValueKind::Boolean => None,
        ReservedAttributeValueKind::IntelTdxTcbStatusMask => {
            Some(tdx_tcb_status_names(u16_from_value(value)?)?.join(", "))
        }
        ReservedAttributeValueKind::AmdSevSnpTcb if valid_amd_sev_snp_tcb(value) => {
            Some(bytes32_hex(value))
        }
        ReservedAttributeValueKind::AmdSevSnpPlatformInfoPolicy
            if valid_amd_sev_snp_platform_info_policy(value) =>
        {
            Some(bytes32_hex(value))
        }
        ReservedAttributeValueKind::AmdSevSnpTcb
        | ReservedAttributeValueKind::AmdSevSnpPlatformInfoPolicy => None,
    }
}

pub fn encode_requirement(
    name: &str,
    values: &[AttributeValue],
) -> Result<([u8; 32], Vec<[u8; 32]>), String> {
    let key = attribute_key(name);
    let Some(reserved) = VerifiedTeeAttribute::from_name(name) else {
        if name.starts_with(TEE_ATTRIBUTE_NAMESPACE) {
            return Err(format!(
                "unknown attribute name `{name}` in the reserved namespace"
            ));
        }
        let encoded = values
            .iter()
            .map(|value| match value {
                AttributeValue::String(value) => Ok(attribute_string_value(value)),
                AttributeValue::Boolean(_) => {
                    Err(format!("custom attribute `{name}` values must be strings"))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok((key, encoded));
    };

    match reserved.value_kind() {
        ReservedAttributeValueKind::Boolean => {
            let bools = values
                .iter()
                .map(|value| match value {
                    AttributeValue::Boolean(value) => Ok(*value),
                    AttributeValue::String(_) => Err(format!(
                        "reserved Boolean attribute `{name}` values must be Booleans"
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !validate_boolean_allowed_values(&bools) {
                return Err(format!(
                    "reserved Boolean attribute `{name}` must be [false] or [false, true]"
                ));
            }
            Ok((key, bools.into_iter().map(bool_value).collect()))
        }
        ReservedAttributeValueKind::IntelTdxTcbStatusMask => {
            let names = values
                .iter()
                .map(|value| match value {
                    AttributeValue::String(value) => Ok(value.as_str()),
                    AttributeValue::Boolean(_) => Err(format!(
                        "Intel TDX TCB status attribute `{name}` values must be strings"
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mask = tdx_tcb_status_mask(names).ok_or_else(|| {
                format!(
                    "Intel TDX TCB status attribute `{name}` must contain unique supported status names and include \"ok\""
                )
            })?;
            Ok((key, vec![u16_value(mask)]))
        }
        ReservedAttributeValueKind::AmdSevSnpTcb
        | ReservedAttributeValueKind::AmdSevSnpPlatformInfoPolicy => {
            if values.len() != 1 {
                return Err(format!(
                    "reserved packed attribute `{name}` must contain exactly one 0x-prefixed bytes32 string"
                ));
            }
            let AttributeValue::String(value) = &values[0] else {
                return Err(format!(
                    "reserved packed attribute `{name}` value must be a 0x-prefixed bytes32 string"
                ));
            };
            let encoded = parse_bytes32_hex(value).ok_or_else(|| {
                format!(
                    "reserved packed attribute `{name}` value must be a 0x-prefixed bytes32 string"
                )
            })?;
            let valid = match reserved.value_kind() {
                ReservedAttributeValueKind::AmdSevSnpTcb => valid_amd_sev_snp_tcb(&encoded),
                ReservedAttributeValueKind::AmdSevSnpPlatformInfoPolicy => {
                    valid_amd_sev_snp_platform_info_policy(&encoded)
                }
                _ => unreachable!(),
            };
            if !valid {
                return Err(format!(
                    "reserved packed attribute `{name}` value is invalid"
                ));
            }
            Ok((key, vec![encoded]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_keys_round_trip() {
        for attribute in VerifiedTeeAttribute::ALL {
            assert_eq!(attribute_key(attribute.name()), attribute.key());
            assert_eq!(
                VerifiedTeeAttribute::from_name(attribute.name()),
                Some(attribute)
            );
            assert_eq!(
                VerifiedTeeAttribute::from_key(&attribute.key()),
                Some(attribute)
            );
        }
        assert_eq!(
            VerifiedTeeAttribute::from_name("atakit.attestation.v1.tee.unknown"),
            None
        );
    }

    #[test]
    fn allowed_values_are_canonical() {
        assert!(validate_boolean_allowed_values(&[false]));
        assert!(validate_boolean_allowed_values(&[false, true]));
        assert!(!validate_boolean_allowed_values(&[]));
        assert!(!validate_boolean_allowed_values(&[true]));
        assert!(!validate_boolean_allowed_values(&[false, false]));
        assert!(!validate_boolean_allowed_values(&[true, false]));
        assert!(!validate_boolean_allowed_values(&[true, true]));
    }

    #[test]
    fn tdx_tcb_statuses_use_one_hot_dcap_codes() {
        assert_eq!(tdx_tcb_status_bit("ok"), Some(1));
        assert_eq!(tdx_tcb_status_bit("configuration-needed"), Some(8));
        assert_eq!(tdx_tcb_status_bit("relaunch-advised"), Some(256));
        assert_eq!(tdx_tcb_status_mask(["ok", "configuration-needed"]), Some(9));
        assert_eq!(
            tdx_tcb_status_names(9),
            Some(vec!["ok", "configuration-needed"])
        );
        assert_eq!(tdx_tcb_status_mask(["configuration-needed"]), None);
        assert_eq!(tdx_tcb_status_mask(["ok", "ok"]), None);
        assert_eq!(tdx_tcb_status_mask(["ok", "unknown"]), None);
        assert_eq!(tdx_tcb_status_names(0), None);
        assert_eq!(tdx_tcb_status_names(0x401), None);
        assert_eq!(u16_value(0x101)[30..], [1, 1]);
    }

    #[test]
    fn ordinary_attribute_names_and_values_are_hashed() {
        assert_ne!(attribute_key("example.attribute"), [0; 32]);
        assert_ne!(attribute_string_value("example-value"), [0; 32]);
    }

    #[test]
    fn requirements_encode_custom_boolean_and_tcb_values() {
        let (custom_key, custom_values) = encode_requirement(
            "example.environment",
            &[AttributeValue::String("production".to_string())],
        )
        .unwrap();
        assert_eq!(custom_key, attribute_key("example.environment"));
        assert_eq!(custom_values, vec![attribute_string_value("production")]);

        let (_, boolean_values) = encode_requirement(
            INTEL_TDX_DEBUG_NAME,
            &[
                AttributeValue::Boolean(false),
                AttributeValue::Boolean(true),
            ],
        )
        .unwrap();
        assert_eq!(boolean_values, vec![ATTRIBUTE_FALSE, ATTRIBUTE_TRUE]);

        let (_, tcb_values) = encode_requirement(
            INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
            &[
                AttributeValue::String("ok".to_string()),
                AttributeValue::String("configuration-needed".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(tcb_values, vec![u16_value(0x9)]);
    }

    #[test]
    fn requirements_reject_unknown_reserved_and_invalid_tcb_values() {
        assert!(encode_requirement(
            "atakit.attestation.v1.tee.intel-tdx.unknown",
            &[AttributeValue::String("value".to_string())],
        )
        .unwrap_err()
        .contains("unknown attribute name"));
        assert!(encode_requirement(
            INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
            &[AttributeValue::String("configuration-needed".to_string())],
        )
        .unwrap_err()
        .contains("include \"ok\""));
    }

    #[test]
    fn amd_sev_snp_packed_values_validate_and_compare() {
        let minimum =
            parse_bytes32_hex("0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004")
                .unwrap();
        let stronger =
            parse_bytes32_hex("0x00000000df1e000500000000de1d000400000000de1d000400000000de1d0004")
                .unwrap();
        assert!(valid_amd_sev_snp_tcb(&minimum));
        assert!(amd_sev_snp_tcb_meets_minimum(&stronger, &minimum));
        assert!(!amd_sev_snp_tcb_meets_minimum(&minimum, &stronger));
        assert_eq!(amd_sev_snp_tcb_max(&minimum, &stronger), Some(stronger));

        let platform_policy =
            parse_bytes32_hex("0x0000000000000000000000000000000000000000000000010000000000000020")
                .unwrap();
        assert!(valid_amd_sev_snp_platform_info_policy(&platform_policy));
        assert!(amd_sev_snp_platform_info_matches(0x20, &platform_policy));
        assert!(!amd_sev_snp_platform_info_matches(0x21, &platform_policy));
        let required_set =
            parse_bytes32_hex("0x0000000000000000000000000000000000000000000000000000000000000020")
                .unwrap();
        let required_clear =
            parse_bytes32_hex("0x0000000000000000000000000000000000000000000000010000000000000000")
                .unwrap();
        assert_eq!(
            merge_amd_sev_snp_platform_info_policies(&required_set, &required_clear),
            Some(platform_policy)
        );
        assert_eq!(
            merge_amd_sev_snp_platform_info_policies(&required_set, &conflict_policy(0x20)),
            None
        );

        let conflict =
            parse_bytes32_hex("0x0000000000000000000000000000000000000000000000010000000000000001")
                .unwrap();
        assert!(!valid_amd_sev_snp_platform_info_policy(&conflict));
    }

    fn conflict_policy(bit: u64) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[16..24].copy_from_slice(&bit.to_be_bytes());
        value
    }

    #[test]
    fn amd_sev_snp_packed_requirements_encode_exact_hex() {
        let tcb = "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004";
        let (key, values) = encode_requirement(
            AMD_SEV_SNP_TCB_MINIMUM_NAME,
            &[AttributeValue::String(tcb.to_string())],
        )
        .unwrap();
        assert_eq!(key, AMD_SEV_SNP_TCB_MINIMUM_KEY);
        assert_eq!(bytes32_hex(&values[0]), tcb);

        assert!(encode_requirement(
            AMD_SEV_SNP_TCB_MINIMUM_NAME,
            &[
                AttributeValue::String(tcb.to_string()),
                AttributeValue::String(tcb.to_string())
            ],
        )
        .unwrap_err()
        .contains("exactly one"));
    }
}
