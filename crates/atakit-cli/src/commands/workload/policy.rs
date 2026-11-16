//! One workload policy projection for chain publication and offline packs.
//!
//! Both outputs must describe the same measured workload. Keeping the policy
//! construction here prevents `workload publish` and `trust-pack build
//! workload` from encoding PCR or attribute rules independently.

use alloy_ext::core::primitives::B256;
use anyhow::{bail, Context, Result};
use atakit_attestation_client::pack::workload::{
    BaseImageMode, PackedAttributeRequirement, PackedPcrSpec, PackedWorkloadSpec,
};
use atakit_cvm_encoding::pcr_comparison::{encode_static256, encode_static384};
use automata_tee_workload_measurement::stubs::WorkloadRegistry::{
    AttributeRequirement, PcrPolicyBlock, PcrSpec256, PcrSpec384, WorkloadSpec,
};

use super::compute_base_image_id;

/// The same workload policy in its contract and trust-pack representations.
pub struct ResolvedWorkloadPolicy {
    pub chain: WorkloadSpec,
    pub packed: PackedWorkloadSpec,
}

/// Build policy from the exact measured manifest carried by an `.atawl`.
pub fn resolve(
    inspected: &atakit_workload::InspectResult,
    publisher: B256,
    session_ttl: Option<u64>,
    base_image_id_overrides: &[String],
) -> Result<ResolvedWorkloadPolicy> {
    let manifest = &inspected.manifest;
    let publisher_hex = hex0x(publisher.as_slice());
    if manifest.meta.publisher != publisher_hex {
        bail!(
            "workload archive publisher {} does not match signing key publisher {}; rebuild the workload with the same signing key",
            manifest.meta.publisher,
            publisher_hex
        );
    }

    let pcr23_sha256 = fixed_hex::<32>(&inspected.pcr23_sha256, "workload SHA-256 PCR23")?;
    let pcr23_sha384 = fixed_hex::<48>(&inspected.pcr23_sha384, "workload SHA-384 PCR23")?;
    let comparison256 = encode_static256(pcr23_sha256);
    let comparison384 = encode_static384(pcr23_sha384);

    let base_image_ids = if base_image_id_overrides.is_empty() {
        manifest
            .config
            .base_image
            .iter()
            .map(|entry| {
                let reference: automata_tee_workload_measurement::types::AppRef =
                    entry.parse().map_err(|error| {
                        anyhow::anyhow!("invalid base-image entry '{entry}': {error}")
                    })?;
                Ok(compute_base_image_id(&reference))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        base_image_id_overrides
            .iter()
            .map(|value| parse_id(value, "base image ID"))
            .collect::<Result<Vec<_>>>()?
    };

    let (base_image_mode, packed_base_image_mode) = match manifest.config.base_image_mode.as_str() {
        "any" => (0, BaseImageMode::Any),
        "blacklist" => (1, BaseImageMode::Blacklist),
        "whitelist" => (2, BaseImageMode::Whitelist),
        other => bail!("unknown base-image-mode: {other}"),
    };
    if base_image_mode == 2 && base_image_ids.is_empty() {
        bail!(
            "base-image-mode is \"whitelist\" but no base images are listed; add entries to the workload manifest or supply base-image IDs"
        );
    }

    let mut chain_requirements = Vec::new();
    let mut packed_requirements = Vec::new();
    for (name, allowed_values) in &manifest.config.attributes {
        let (key, values) = atakit_core::tee_attributes::encode_requirement(name, allowed_values)
            .map_err(anyhow::Error::msg)?;
        chain_requirements.push(AttributeRequirement {
            key: B256::from(key),
            allowedValues: values.iter().copied().map(B256::from).collect(),
        });
        packed_requirements.push(PackedAttributeRequirement {
            key: hex0x(&key),
            allowed_values: values.iter().map(|value| hex0x(value)).collect(),
        });
    }

    let packed_ids = base_image_ids
        .iter()
        .map(|value| hex0x(value.as_slice()))
        .collect();
    let chain = WorkloadSpec {
        name: manifest.meta.name.clone(),
        version: manifest.meta.version.clone(),
        sessionTtl: session_ttl.unwrap_or(manifest.config.session_ttl),
        baseImageMode: base_image_mode,
        baseImageIds: base_image_ids,
        requirements: chain_requirements,
        workloadPcrPolicy: PcrPolicyBlock {
            pcrSpecs256: vec![PcrSpec256 {
                pcrIndex: 23,
                comparison: comparison256.clone().into(),
            }],
            pcrSpecs384: vec![PcrSpec384 {
                pcrIndex: 23,
                comparison: comparison384.clone().into(),
            }],
        },
    };
    let packed = PackedWorkloadSpec {
        publisher: publisher_hex,
        name: manifest.meta.name.clone(),
        version: manifest.meta.version.clone(),
        base_image_mode: packed_base_image_mode,
        base_image_ids: packed_ids,
        requirements: packed_requirements,
        workload_pcrs256: vec![PackedPcrSpec {
            pcr_index: 23,
            comparison: hex0x(&comparison256),
        }],
        workload_pcrs384: vec![PackedPcrSpec {
            pcr_index: 23,
            comparison: hex0x(&comparison384),
        }],
    };
    Ok(ResolvedWorkloadPolicy { chain, packed })
}

fn fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let raw = value
        .strip_prefix("0x")
        .with_context(|| format!("{field} must start with 0x"))?;
    hex::decode(raw)
        .with_context(|| format!("{field} is not hexadecimal"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must be {N} bytes"))
}

fn parse_id(value: &str, field: &str) -> Result<B256> {
    if !atakit_core::is_canonical_id(value) {
        bail!("{field} must be canonical 0x-prefixed lowercase bytes32: {value}");
    }
    Ok(B256::from(fixed_hex::<32>(value, field)?))
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_and_pack_projections_use_identical_policy_bytes() {
        let publisher = B256::from([0x11; 32]);
        let base_publisher = format!("0x{}", "22".repeat(32));
        let manifest = serde_json::from_value(serde_json::json!({
            "meta": {
                "format": atakit_workload::FORMAT_VERSION,
                "publisher": hex0x(publisher.as_slice()),
                "name": "example-workload",
                "version": "v1"
            },
            "config": {
                "image": "example-workload:v1",
                "base-image-mode": "whitelist",
                "base-image": [format!("{base_publisher}/automata-linux:v1")],
                "depends_on": [],
                "attributes": {
                    atakit_core::tee_attributes::INTEL_TDX_DEBUG_NAME: [false]
                },
                "session-ttl": 3600,
                "gid-group": "workload",
                "logging": {
                    "driver": "journald",
                    "options": {},
                    "log-readers": []
                },
                "workload-logs": false
            },
            "hashes": {}
        }))
        .unwrap();
        let inspected = atakit_workload::InspectResult {
            sha256: format!("0x{}", "33".repeat(32)),
            pcr23_sha256: format!("0x{}", "44".repeat(32)),
            pcr23_sha384: format!("0x{}", "55".repeat(48)),
            sha384: format!("0x{}", "66".repeat(48)),
            manifest_hash: format!("sha256:{}", "33".repeat(32)),
            manifest,
            manifest_raw: "{}".to_string(),
        };

        let resolved = resolve(&inspected, publisher, None, &[]).unwrap();

        assert_eq!(resolved.chain.name, resolved.packed.name);
        assert_eq!(resolved.chain.version, resolved.packed.version);
        assert_eq!(
            hex0x(resolved.chain.baseImageIds[0].as_slice()),
            resolved.packed.base_image_ids[0]
        );
        assert_eq!(
            hex0x(resolved.chain.requirements[0].key.as_slice()),
            resolved.packed.requirements[0].key
        );
        assert_eq!(
            hex0x(resolved.chain.requirements[0].allowedValues[0].as_slice()),
            resolved.packed.requirements[0].allowed_values[0]
        );
        assert_eq!(
            hex0x(
                resolved.chain.workloadPcrPolicy.pcrSpecs256[0]
                    .comparison
                    .as_ref()
            ),
            resolved.packed.workload_pcrs256[0].comparison
        );
        assert_eq!(
            hex0x(
                resolved.chain.workloadPcrPolicy.pcrSpecs384[0]
                    .comparison
                    .as_ref()
            ),
            resolved.packed.workload_pcrs384[0].comparison
        );
    }
}
