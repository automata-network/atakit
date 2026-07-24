pub const TEE_ATTRIBUTE_NAMESPACE: &str = "atakit.attestation.v1.tee.";
pub const INTEL_TDX_DEBUG_NAME: &str = "atakit.attestation.v1.tee.intel-tdx.debug.enabled";
pub const AMD_SEV_SNP_DEBUG_NAME: &str = "atakit.attestation.v1.tee.amd-sev-snp.debug.enabled";
pub const AMD_SEV_SNP_MIGRATE_MA_NAME: &str =
    "atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled";

pub const INTEL_TDX_DEBUG_KEY: [u8; 32] = [
    0xe9, 0x60, 0x23, 0x94, 0x6a, 0x6a, 0xd6, 0x12, 0x75, 0xcb, 0x45, 0xa7, 0x96, 0xa2, 0x90, 0x5e,
    0x3d, 0x92, 0x31, 0x39, 0xce, 0x33, 0xb7, 0x73, 0x4f, 0x3b, 0xea, 0x4e, 0xec, 0x3d, 0x72, 0xcd,
];
pub const AMD_SEV_SNP_DEBUG_KEY: [u8; 32] = [
    0xe3, 0x51, 0x76, 0x80, 0xfe, 0x2d, 0x4f, 0x15, 0x75, 0x1d, 0xa8, 0x5b, 0x04, 0x00, 0xea, 0x90,
    0x9b, 0xb3, 0xd5, 0xae, 0x76, 0x23, 0x2c, 0x10, 0xa6, 0xc4, 0x47, 0x03, 0x1d, 0x63, 0x89, 0xb9,
];
pub const AMD_SEV_SNP_MIGRATE_MA_KEY: [u8; 32] = [
    0x90, 0x90, 0xb9, 0x94, 0xea, 0x40, 0x98, 0xb5, 0x65, 0xee, 0x0d, 0xa0, 0x1c, 0x4b, 0xca, 0xa0,
    0x83, 0xa5, 0xbf, 0xb1, 0x9c, 0x0a, 0x79, 0x7c, 0x7f, 0xfe, 0x3d, 0xe7, 0xce, 0x02, 0x51, 0xe1,
];

pub const ATTRIBUTE_FALSE: [u8; 32] = [0; 32];
pub const ATTRIBUTE_TRUE: [u8; 32] = {
    let mut value = [0; 32];
    value[31] = 1;
    value
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedTeeAttribute {
    IntelTdxDebug,
    AmdSevSnpDebug,
    AmdSevSnpMigrateMa,
}

impl VerifiedTeeAttribute {
    pub const ALL: [Self; 3] = [
        Self::IntelTdxDebug,
        Self::AmdSevSnpDebug,
        Self::AmdSevSnpMigrateMa,
    ];

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            INTEL_TDX_DEBUG_NAME => Some(Self::IntelTdxDebug),
            AMD_SEV_SNP_DEBUG_NAME => Some(Self::AmdSevSnpDebug),
            AMD_SEV_SNP_MIGRATE_MA_NAME => Some(Self::AmdSevSnpMigrateMa),
            _ => None,
        }
    }

    pub fn from_key(key: &[u8; 32]) -> Option<Self> {
        match *key {
            INTEL_TDX_DEBUG_KEY => Some(Self::IntelTdxDebug),
            AMD_SEV_SNP_DEBUG_KEY => Some(Self::AmdSevSnpDebug),
            AMD_SEV_SNP_MIGRATE_MA_KEY => Some(Self::AmdSevSnpMigrateMa),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::IntelTdxDebug => INTEL_TDX_DEBUG_NAME,
            Self::AmdSevSnpDebug => AMD_SEV_SNP_DEBUG_NAME,
            Self::AmdSevSnpMigrateMa => AMD_SEV_SNP_MIGRATE_MA_NAME,
        }
    }

    pub const fn key(self) -> [u8; 32] {
        match self {
            Self::IntelTdxDebug => INTEL_TDX_DEBUG_KEY,
            Self::AmdSevSnpDebug => AMD_SEV_SNP_DEBUG_KEY,
            Self::AmdSevSnpMigrateMa => AMD_SEV_SNP_MIGRATE_MA_KEY,
        }
    }
}

pub fn validate_allowed_values(values: &[bool]) -> bool {
    values == [false] || values == [false, true]
}

pub fn bool_value(value: bool) -> [u8; 32] {
    if value {
        ATTRIBUTE_TRUE
    } else {
        ATTRIBUTE_FALSE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_keys_round_trip() {
        for attribute in VerifiedTeeAttribute::ALL {
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
        assert!(validate_allowed_values(&[false]));
        assert!(validate_allowed_values(&[false, true]));
        assert!(!validate_allowed_values(&[]));
        assert!(!validate_allowed_values(&[true]));
        assert!(!validate_allowed_values(&[false, false]));
        assert!(!validate_allowed_values(&[true, false]));
        assert!(!validate_allowed_values(&[true, true]));
    }
}
