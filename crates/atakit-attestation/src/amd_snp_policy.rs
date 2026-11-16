use std::collections::BTreeSet;

use serde::Deserialize;
use thiserror::Error;

use crate::AmdSnpSecurityPolicy;

const AMD_SNP_SECURITY_POLICY_SCHEMA: &str = "atakit.amd-sev-snp-security-policy";
const AMD_SNP_SECURITY_POLICY_VERSION: u8 = 1;
const MAX_AMD_SNP_SECURITY_POLICY_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum AmdSnpSecurityPolicyFileError {
    #[error("invalid AMD SEV-SNP security policy file: {0}")]
    File(String),
    #[error(
        "unsupported AMD SEV-SNP security policy file schema {schema:?} version {version}; expected {expected_schema:?} version {expected_version}"
    )]
    UnsupportedFileFormat {
        schema: String,
        version: u8,
        expected_schema: &'static str,
        expected_version: u8,
    },
}

/// Parse an atakit AMD SEV-SNP security policy version 1 JSON document.
pub fn parse_amd_snp_security_policy_file_json(
    input: &[u8],
) -> Result<Vec<AmdSnpSecurityPolicy>, AmdSnpSecurityPolicyFileError> {
    if input.len() > MAX_AMD_SNP_SECURITY_POLICY_FILE_BYTES {
        return Err(AmdSnpSecurityPolicyFileError::File(format!(
            "document exceeds {MAX_AMD_SNP_SECURITY_POLICY_FILE_BYTES} bytes"
        )));
    }
    let file: AmdSnpSecurityPolicyFileV1 = serde_json::from_slice(input)
        .map_err(|error| AmdSnpSecurityPolicyFileError::File(error.to_string()))?;
    if file.schema != AMD_SNP_SECURITY_POLICY_SCHEMA
        || file.version != AMD_SNP_SECURITY_POLICY_VERSION
    {
        return Err(AmdSnpSecurityPolicyFileError::UnsupportedFileFormat {
            schema: file.schema,
            version: file.version,
            expected_schema: AMD_SNP_SECURITY_POLICY_SCHEMA,
            expected_version: AMD_SNP_SECURITY_POLICY_VERSION,
        });
    }
    if file.policies.is_empty() {
        return Err(AmdSnpSecurityPolicyFileError::File(
            "policies must contain at least one entry".to_string(),
        ));
    }

    let mut cpuids = BTreeSet::new();
    file.policies
        .into_iter()
        .map(|policy| {
            let cpuid_bytes = decode_fixed_hex::<3>("policies[].cpuid", &policy.cpuid)?;
            let cpuid = u32::from_be_bytes([0, cpuid_bytes[0], cpuid_bytes[1], cpuid_bytes[2]]);
            if cpuid_bytes[0] != 0x19 || cpuid_bytes[1] > 0x1f {
                return Err(AmdSnpSecurityPolicyFileError::File(format!(
                    "policies[].cpuid {} is not a supported Milan or Genoa processor",
                    policy.cpuid
                )));
            }
            if !cpuids.insert(cpuid) {
                return Err(AmdSnpSecurityPolicyFileError::File(format!(
                    "policies contains duplicate CPUID {}",
                    policy.cpuid
                )));
            }

            let minimum_tcb = decode_fixed_hex::<32>("policies[].minimumTcb", &policy.minimum_tcb)?;
            if !atakit_core::tee_attributes::valid_amd_sev_snp_tcb(&minimum_tcb) {
                return Err(AmdSnpSecurityPolicyFileError::File(
                    "policies[].minimumTcb contains unsupported TCB fields".to_string(),
                ));
            }
            let platform_info_policy = decode_fixed_hex::<32>(
                "policies[].platformInfoPolicy",
                &policy.platform_info_policy,
            )?;
            if !atakit_core::tee_attributes::valid_amd_sev_snp_platform_info_policy(
                &platform_info_policy,
            ) {
                return Err(AmdSnpSecurityPolicyFileError::File(
                    "policies[].platformInfoPolicy is invalid".to_string(),
                ));
            }

            Ok(AmdSnpSecurityPolicy {
                cpuid,
                minimum_tcb,
                platform_info_policy,
                required_launch_mitigation_vector: u64::from_be_bytes(decode_fixed_hex::<8>(
                    "policies[].requiredLaunchMitigationVector",
                    &policy.required_launch_mitigation_vector,
                )?),
                required_current_mitigation_vector: u64::from_be_bytes(decode_fixed_hex::<8>(
                    "policies[].requiredCurrentMitigationVector",
                    &policy.required_current_mitigation_vector,
                )?),
            })
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AmdSnpSecurityPolicyFileV1 {
    schema: String,
    version: u8,
    policies: Vec<AmdSnpSecurityPolicyEntryV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AmdSnpSecurityPolicyEntryV1 {
    cpuid: String,
    minimum_tcb: String,
    platform_info_policy: String,
    required_launch_mitigation_vector: String,
    required_current_mitigation_vector: String,
}

fn decode_fixed_hex<const N: usize>(
    field: &str,
    value: &str,
) -> Result<[u8; N], AmdSnpSecurityPolicyFileError> {
    let Some(raw) = value.strip_prefix("0x") else {
        return Err(AmdSnpSecurityPolicyFileError::File(format!(
            "{field} must be a 0x-prefixed lowercase hexadecimal string containing exactly {} bytes",
            N
        )));
    };
    if raw.len() != N * 2
        || raw
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(AmdSnpSecurityPolicyFileError::File(format!(
            "{field} must be a 0x-prefixed lowercase hexadecimal string containing exactly {} bytes",
            N
        )));
    }
    hex::decode(raw)
        .map_err(|_| {
            AmdSnpSecurityPolicyFileError::File(format!(
                "{field} must contain only lowercase hexadecimal digits"
            ))
        })?
        .try_into()
        .map_err(|_| AmdSnpSecurityPolicyFileError::File(format!("{field} has an invalid length")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMUM_TCB: &str = "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004";
    const PLATFORM_INFO_POLICY: &str =
        "0x0000000000000000000000000000000000000000000000010000000000000020";

    fn document(cpuid: &str) -> String {
        format!(
            r#"{{
  "schema": "atakit.amd-sev-snp-security-policy",
  "version": 1,
  "policies": [{{
    "cpuid": "{cpuid}",
    "minimumTcb": "{MINIMUM_TCB}",
    "platformInfoPolicy": "{PLATFORM_INFO_POLICY}",
    "requiredLaunchMitigationVector": "0x0000000000000001",
    "requiredCurrentMitigationVector": "0x0000000000000002"
  }}]
}}"#
        )
    }

    #[test]
    fn parses_version_one_policy_file() {
        let policies = parse_amd_snp_security_policy_file_json(document("0x191101").as_bytes())
            .expect("valid policy file");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].cpuid, 0x191101);
        assert_eq!(policies[0].required_launch_mitigation_vector, 1);
        assert_eq!(policies[0].required_current_mitigation_vector, 2);
    }

    #[test]
    fn rejects_unsupported_cpuid_and_unknown_fields() {
        let error =
            parse_amd_snp_security_policy_file_json(document("0x1a0000").as_bytes()).unwrap_err();
        assert!(error.to_string().contains("not a supported Milan or Genoa"));

        let with_unknown = document("0x191101")
            .replace(r#""version": 1,"#, r#""version": 1, "unexpected": true,"#);
        assert!(parse_amd_snp_security_policy_file_json(with_unknown.as_bytes()).is_err());
    }

    #[test]
    fn rejects_duplicate_cpuid() {
        let entry = format!(
            r#"{{
    "cpuid": "0x191101",
    "minimumTcb": "{MINIMUM_TCB}",
    "platformInfoPolicy": "{PLATFORM_INFO_POLICY}",
    "requiredLaunchMitigationVector": "0x0000000000000000",
    "requiredCurrentMitigationVector": "0x0000000000000000"
  }}"#
        );
        let document = format!(
            r#"{{
  "schema": "atakit.amd-sev-snp-security-policy",
  "version": 1,
  "policies": [{entry}, {entry}]
}}"#
        );
        let error = parse_amd_snp_security_policy_file_json(document.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("duplicate CPUID"));
    }
}
