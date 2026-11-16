use std::collections::BTreeSet;
use std::path::Path;

use alloy::primitives::{Address, B256};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::CloudError;
use crate::init::InitChainConfig;

const MAX_PCR_POLICY_BYTES: u64 = 1024 * 1024;
const SUPPORTED_PCR_INDEXES: [u8; 18] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 23];

sol! {
    #[derive(Debug)]
    enum ChainPcrBankSelection {
        Sha256,
        Sha384,
        Sha256AndSha384,
    }

    #[derive(Debug)]
    struct ChainPcrSpec256 {
        uint8 pcrIndex;
        bytes comparison;
    }

    #[derive(Debug)]
    struct ChainPcrSpec384 {
        uint8 pcrIndex;
        bytes comparison;
    }

    #[derive(Debug)]
    struct ChainPcrPolicyBlock {
        ChainPcrSpec256[] pcrSpecs256;
        ChainPcrSpec384[] pcrSpecs384;
    }

    #[derive(Debug)]
    struct ChainResolvedPcrPolicy {
        bytes32 workloadId;
        bytes32 baseImageId;
        bytes32 platformProfileId;
        bytes32 measurementVariantId;
        ChainPcrBankSelection pcrBankSelection;
        ChainPcrPolicyBlock invariantPcrPolicy;
        ChainPcrPolicyBlock variantPcrPolicy;
        ChainPcrPolicyBlock workloadPcrPolicy;
    }

    #[sol(rpc)]
    interface PcrPolicySessionRegistry {
        function getPcrPolicy(
            bytes32 workloadId,
            bytes32 baseImageId,
            bytes32 platformProfileId,
            bytes32 measurementVariantId
        ) external view returns (ChainResolvedPcrPolicy memory policy);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PcrBankSelectionConfig {
    Sha256,
    Sha384,
    Sha256AndSha384,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcrSpec256Config {
    pub pcr_index: u8,
    pub comparison: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcrSpec384Config {
    pub pcr_index: u8,
    pub comparison: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcrPolicyBlockConfig {
    pub pcr_specs256: Vec<PcrSpec256Config>,
    pub pcr_specs384: Vec<PcrSpec384Config>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedPcrPolicyConfig {
    pub workload_id: String,
    pub base_image_id: String,
    pub platform_profile_id: String,
    pub measurement_variant_id: String,
    pub pcr_bank_selection: PcrBankSelectionConfig,
    pub invariant_pcr_policy: PcrPolicyBlockConfig,
    pub variant_pcr_policy: PcrPolicyBlockConfig,
    pub workload_pcr_policy: PcrPolicyBlockConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcrPolicyIdentifiers {
    pub workload_id: [u8; 32],
    pub base_image_id: [u8; 32],
    pub platform_profile_id: [u8; 32],
    pub measurement_variant_id: [u8; 32],
}

pub async fn resolve_init_pcr_policy(
    registration_off: bool,
    explicit_path: Option<&Path>,
    chain: &InitChainConfig,
    identifiers: Option<PcrPolicyIdentifiers>,
    platform: &str,
) -> Result<Option<ResolvedPcrPolicyConfig>, CloudError> {
    if !registration_off {
        if explicit_path.is_some() {
            return Err(policy_error(
                "--pcr-policy requires effective chain registration = \"off\"",
            ));
        }
        return Ok(None);
    }

    if let Some(identifiers) = identifiers {
        if chain_policy_available(chain) {
            match read_chain_policy(chain, identifiers).await {
                Ok(policy) => {
                    validate_policy(&policy, identifiers, platform)?;
                    return Ok(Some(policy));
                }
                Err(error) => warn!(
                    error = %error,
                    "SessionRegistry.getPcrPolicy failed; trying --pcr-policy"
                ),
            }
        }

        if let Some(path) = explicit_path {
            let policy = read_policy_file(path)?;
            validate_policy(&policy, identifiers, platform)?;
            return Ok(Some(policy));
        }
    } else if explicit_path.is_some() {
        return Err(policy_error(
            "--pcr-policy requires verified base-image, platform-profile, and measurement-variant identifiers",
        ));
    }

    Ok(None)
}

fn chain_policy_available(chain: &InitChainConfig) -> bool {
    !chain.rpc_url.trim().is_empty()
        && chain.session_registry != "0x0000000000000000000000000000000000000000"
}

async fn read_chain_policy(
    chain: &InitChainConfig,
    identifiers: PcrPolicyIdentifiers,
) -> Result<ResolvedPcrPolicyConfig, String> {
    let rpc_url = chain
        .rpc_url
        .parse()
        .map_err(|error| format!("parse chain.rpc_url: {error}"))?;
    let address: Address = chain
        .session_registry
        .parse()
        .map_err(|error| format!("parse chain.contracts.session_registry: {error}"))?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let registry = PcrPolicySessionRegistry::new(address, provider);
    let result = registry
        .getPcrPolicy(
            B256::from(identifiers.workload_id),
            B256::from(identifiers.base_image_id),
            B256::from(identifiers.platform_profile_id),
            B256::from(identifiers.measurement_variant_id),
        )
        .call()
        .await
        .map_err(|error| format!("call SessionRegistry.getPcrPolicy: {error}"))?;
    Ok(convert_chain_policy(result))
}

fn convert_chain_policy(policy: ChainResolvedPcrPolicy) -> ResolvedPcrPolicyConfig {
    ResolvedPcrPolicyConfig {
        workload_id: format!("{:#x}", policy.workloadId),
        base_image_id: format!("{:#x}", policy.baseImageId),
        platform_profile_id: format!("{:#x}", policy.platformProfileId),
        measurement_variant_id: format!("{:#x}", policy.measurementVariantId),
        pcr_bank_selection: match policy.pcrBankSelection {
            ChainPcrBankSelection::Sha256 => PcrBankSelectionConfig::Sha256,
            ChainPcrBankSelection::Sha384 => PcrBankSelectionConfig::Sha384,
            ChainPcrBankSelection::Sha256AndSha384 => PcrBankSelectionConfig::Sha256AndSha384,
            _ => unreachable!("Solidity enum decoder rejects invalid values"),
        },
        invariant_pcr_policy: convert_chain_block(policy.invariantPcrPolicy),
        variant_pcr_policy: convert_chain_block(policy.variantPcrPolicy),
        workload_pcr_policy: convert_chain_block(policy.workloadPcrPolicy),
    }
}

fn convert_chain_block(block: ChainPcrPolicyBlock) -> PcrPolicyBlockConfig {
    PcrPolicyBlockConfig {
        pcr_specs256: convert_chain_specs256(block.pcrSpecs256),
        pcr_specs384: convert_chain_specs384(block.pcrSpecs384),
    }
}

fn convert_chain_specs256(rules: Vec<ChainPcrSpec256>) -> Vec<PcrSpec256Config> {
    rules
        .into_iter()
        .map(|rule| PcrSpec256Config {
            pcr_index: rule.pcrIndex,
            comparison: format!("0x{}", hex::encode(rule.comparison)),
        })
        .collect()
}

fn convert_chain_specs384(rules: Vec<ChainPcrSpec384>) -> Vec<PcrSpec384Config> {
    rules
        .into_iter()
        .map(|rule| PcrSpec384Config {
            pcr_index: rule.pcrIndex,
            comparison: format!("0x{}", hex::encode(rule.comparison)),
        })
        .collect()
}

fn read_policy_file(path: &Path) -> Result<ResolvedPcrPolicyConfig, CloudError> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| policy_error(format!("read --pcr-policy {}: {error}", path.display())))?;
    if metadata.len() > MAX_PCR_POLICY_BYTES {
        return Err(policy_error(format!(
            "--pcr-policy {} exceeds {MAX_PCR_POLICY_BYTES} bytes",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| policy_error(format!("read --pcr-policy {}: {error}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| policy_error(format!("parse --pcr-policy {}: {error}", path.display())))
}

fn validate_policy(
    policy: &ResolvedPcrPolicyConfig,
    expected: PcrPolicyIdentifiers,
    platform: &str,
) -> Result<(), CloudError> {
    let observed = PcrPolicyIdentifiers {
        workload_id: decode_hex::<32>("workloadId", &policy.workload_id)?,
        base_image_id: decode_hex::<32>("baseImageId", &policy.base_image_id)?,
        platform_profile_id: decode_hex::<32>("platformProfileId", &policy.platform_profile_id)?,
        measurement_variant_id: decode_hex::<32>(
            "measurementVariantId",
            &policy.measurement_variant_id,
        )?,
    };
    if observed != expected {
        return Err(policy_error(
            "pcr_policy identifiers do not match the workload and verified TLS identity",
        ));
    }

    validate_policy_block("invariantPcrPolicy", &policy.invariant_pcr_policy)?;
    validate_policy_block("variantPcrPolicy", &policy.variant_pcr_policy)?;
    validate_policy_block("workloadPcrPolicy", &policy.workload_pcr_policy)?;
    reject_overlap(
        "invariantPcrPolicy.pcrSpecs256",
        policy
            .invariant_pcr_policy
            .pcr_specs256
            .iter()
            .map(|rule| rule.pcr_index),
        "variantPcrPolicy.pcrSpecs256",
        policy
            .variant_pcr_policy
            .pcr_specs256
            .iter()
            .map(|rule| rule.pcr_index),
    )?;
    reject_overlap(
        "invariantPcrPolicy.pcrSpecs384",
        policy
            .invariant_pcr_policy
            .pcr_specs384
            .iter()
            .map(|rule| rule.pcr_index),
        "variantPcrPolicy.pcrSpecs384",
        policy
            .variant_pcr_policy
            .pcr_specs384
            .iter()
            .map(|rule| rule.pcr_index),
    )?;

    match platform {
        "aws" if policy.pcr_bank_selection == PcrBankSelectionConfig::Sha256 => {
            return Err(policy_error("AWS pcrBankSelection must include SHA-384"));
        }
        "gcp" if policy.pcr_bank_selection == PcrBankSelectionConfig::Sha384 => {
            return Err(policy_error("GCP pcrBankSelection must include SHA-256"));
        }
        _ => {}
    }
    Ok(())
}

fn validate_policy_block(field: &str, block: &PcrPolicyBlockConfig) -> Result<(), CloudError> {
    validate_rules256(&format!("{field}.pcrSpecs256"), &block.pcr_specs256)?;
    validate_rules384(&format!("{field}.pcrSpecs384"), &block.pcr_specs384)
}

fn validate_rules256(field: &str, rules: &[PcrSpec256Config]) -> Result<(), CloudError> {
    validate_rule_order(field, rules.iter().map(|rule| rule.pcr_index))?;
    for rule in rules {
        validate_comparison(field, rule.pcr_index, &rule.comparison)?;
    }
    Ok(())
}

fn validate_rules384(field: &str, rules: &[PcrSpec384Config]) -> Result<(), CloudError> {
    validate_rule_order(field, rules.iter().map(|rule| rule.pcr_index))?;
    for rule in rules {
        validate_comparison(field, rule.pcr_index, &rule.comparison)?;
    }
    Ok(())
}

fn validate_rule_order(field: &str, indexes: impl Iterator<Item = u8>) -> Result<(), CloudError> {
    let indexes = indexes.collect::<Vec<_>>();
    if indexes.windows(2).any(|pair| pair[0] >= pair[1])
        || indexes
            .iter()
            .any(|index| SUPPORTED_PCR_INDEXES.binary_search(index).is_err())
    {
        return Err(policy_error(format!(
            "{field} must be sorted, unique, and limited to PCR0 through PCR16 and PCR23"
        )));
    }
    Ok(())
}

fn validate_comparison(field: &str, index: u8, value: &str) -> Result<(), CloudError> {
    let clean = value.strip_prefix("0x").unwrap_or(value);
    let comparison = hex::decode(clean).map_err(|error| {
        policy_error(format!(
            "{field} PCR{index} comparison is not valid hex: {error}"
        ))
    })?;
    if comparison.is_empty() {
        return Err(policy_error(format!(
            "{field} PCR{index} comparison is empty"
        )));
    }
    Ok(())
}

fn reject_overlap(
    left_name: &str,
    left: impl Iterator<Item = u8>,
    right_name: &str,
    mut right: impl Iterator<Item = u8>,
) -> Result<(), CloudError> {
    let left = left.collect::<BTreeSet<_>>();
    if let Some(index) = right.find(|index| left.contains(index)) {
        return Err(policy_error(format!(
            "{left_name} and {right_name} both contain PCR{index}"
        )));
    }
    Ok(())
}

fn decode_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], CloudError> {
    let encoded = value
        .strip_prefix("0x")
        .ok_or_else(|| policy_error(format!("{field} must start with 0x")))?;
    let bytes =
        hex::decode(encoded).map_err(|error| policy_error(format!("parse {field}: {error}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        policy_error(format!(
            "{field} must contain {N} bytes, got {}",
            bytes.len()
        ))
    })
}

fn policy_error(message: impl Into<String>) -> CloudError {
    CloudError::PortalInitFailed {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ResolvedPcrPolicyConfig {
        ResolvedPcrPolicyConfig {
            workload_id: format!("0x{}", "11".repeat(32)),
            base_image_id: format!("0x{}", "22".repeat(32)),
            platform_profile_id: format!("0x{}", "33".repeat(32)),
            measurement_variant_id: format!("0x{}", "44".repeat(32)),
            pcr_bank_selection: PcrBankSelectionConfig::Sha256AndSha384,
            invariant_pcr_policy: PcrPolicyBlockConfig {
                pcr_specs256: vec![PcrSpec256Config {
                    pcr_index: 0,
                    comparison: "0x1234".into(),
                }],
                pcr_specs384: vec![PcrSpec384Config {
                    pcr_index: 0,
                    comparison: "0x5678".into(),
                }],
            },
            variant_pcr_policy: PcrPolicyBlockConfig {
                pcr_specs256: Vec::new(),
                pcr_specs384: Vec::new(),
            },
            workload_pcr_policy: PcrPolicyBlockConfig {
                pcr_specs256: Vec::new(),
                pcr_specs384: Vec::new(),
            },
        }
    }

    fn identifiers() -> PcrPolicyIdentifiers {
        PcrPolicyIdentifiers {
            workload_id: [0x11; 32],
            base_image_id: [0x22; 32],
            platform_profile_id: [0x33; 32],
            measurement_variant_id: [0x44; 32],
        }
    }

    #[test]
    fn strict_policy_accepts_exact_dual_bank_shape() {
        validate_policy(&policy(), identifiers(), "aws").unwrap();
    }

    #[test]
    fn strict_policy_rejects_unknown_fields() {
        let mut value = serde_json::to_value(policy()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ResolvedPcrPolicyConfig>(value).is_err());
    }

    #[test]
    fn strict_policy_rejects_unsorted_rules_and_malformed_comparison() {
        let mut value = policy();
        value
            .invariant_pcr_policy
            .pcr_specs256
            .push(PcrSpec256Config {
                pcr_index: 0,
                comparison: "0xxyz".into(),
            });
        assert!(validate_policy(&value, identifiers(), "gcp").is_err());

        let mut value = policy();
        value.invariant_pcr_policy.pcr_specs256[0].comparison = "0x".into();
        assert!(validate_policy(&value, identifiers(), "gcp").is_err());
    }

    #[test]
    fn provider_bank_rules_are_exact() {
        let mut value = policy();
        value.pcr_bank_selection = PcrBankSelectionConfig::Sha256;
        assert!(validate_policy(&value, identifiers(), "aws").is_err());
        value.pcr_bank_selection = PcrBankSelectionConfig::Sha384;
        assert!(validate_policy(&value, identifiers(), "gcp").is_err());
        assert!(validate_policy(&value, identifiers(), "azure").is_ok());
    }
}
