//! Synthesize witnesses for existing policies; contradictory rules remain errors.
use crate::abi::SessionRegistry::PcrPolicyBlock;
use anyhow::{bail, Context, Result};
use atakit_cvm_encoding::pcr_comparison::*;
use automata_tee_workload_measurement::stubs::{Bytes48, PcrValue256, PcrValue384};
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;

fn witness256(raw: &[u8]) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    use PcrComparison256::*;
    let events = match decode256(raw)? {
        Static(v) => return Ok((v, vec![])),
        ExtendFromZero(v) => {
            return Ok((
                Sha256::digest([vec![0; 32], v.to_vec()].concat()).into(),
                vec![],
            ))
        }
        DynamicSubset(v) | DynamicSubsequence(v) => v,
        DynamicIndexedEventSets(rule) => {
            if rule.expected_event_count > 4096 {
                bail!("PCR event count exceeds emulator limit");
            }
            let mut events = vec![[0; 32]; rule.expected_event_count as usize];
            for event in rule.checked_events {
                *events
                    .get_mut(event.event_index as usize)
                    .context("PCR event index out of bounds")? = *event
                    .allowed_values
                    .first()
                    .context("empty PCR allowed event values")?;
            }
            events
        }
    };
    let mut value = [0; 32];
    for event in &events {
        value = Sha256::digest([value.as_slice(), event].concat()).into();
    }
    Ok((value, events))
}

fn witness384(raw: &[u8]) -> Result<([u8; 48], Vec<[u8; 48]>)> {
    use PcrComparison384::*;
    let events = match decode384(raw)? {
        Static(v) => return Ok((v, vec![])),
        ExtendFromZero(v) => {
            return Ok((
                Sha384::digest([vec![0; 48], v.to_vec()].concat()).into(),
                vec![],
            ))
        }
        DynamicSubset(v) | DynamicSubsequence(v) => v,
        DynamicIndexedEventSets(rule) => {
            if rule.expected_event_count > 4096 {
                bail!("PCR event count exceeds emulator limit");
            }
            let mut events = vec![[0; 48]; rule.expected_event_count as usize];
            for event in rule.checked_events {
                *events
                    .get_mut(event.event_index as usize)
                    .context("PCR event index out of bounds")? = *event
                    .allowed_values
                    .first()
                    .context("empty PCR allowed event values")?;
            }
            events
        }
    };
    let mut value = [0; 48];
    for event in &events {
        value = Sha384::digest([value.as_slice(), event].concat()).into();
    }
    Ok((value, events))
}

pub fn synthesize(
    blocks: &[&PcrPolicyBlock],
    binding: [u8; 32],
) -> Result<(Vec<PcrValue256>, Vec<PcrValue384>)> {
    let mut p256 = BTreeMap::new();
    let mut p384 = BTreeMap::new();
    for block in blocks {
        for spec in &block.pcrSpecs256 {
            if spec.pcrIndex > 23 {
                bail!("PCR index exceeds 23");
            }
            let v = witness256(&spec.comparison)?;
            if let Some(old) = p256.insert(spec.pcrIndex, v.clone()) {
                if old != v {
                    bail!("conflicting SHA256 PCR {} policies", spec.pcrIndex);
                }
            }
        }
        for spec in &block.pcrSpecs384 {
            if spec.pcrIndex > 23 {
                bail!("PCR index exceeds 23");
            }
            let v = witness384(&spec.comparison)?;
            if let Some(old) = p384.insert(spec.pcrIndex, v.clone()) {
                if old != v {
                    bail!("conflicting SHA384 PCR {} policies", spec.pcrIndex);
                }
            }
        }
    }
    let provider: [u8; 32] = Sha256::digest([vec![0; 32], binding.to_vec()].concat()).into();
    if let Some((old, _)) = p256.get(&15) {
        if old != &provider {
            bail!("PCR15 policy conflicts with GCP provider binding");
        }
    }
    p256.entry(15).or_insert((provider, vec![]));
    Ok((
        p256.into_iter()
            .map(|(pcr_index, (value, events))| PcrValue256 {
                pcrIndex: pcr_index,
                value: value.into(),
                eventLogHashes: events.into_iter().map(Into::into).collect(),
            })
            .collect(),
        p384.into_iter()
            .map(|(pcr_index, (value, events))| PcrValue384 {
                pcrIndex: pcr_index,
                value: fixed_bytes48(value),
                eventLogHashes: events.into_iter().map(fixed_bytes48).collect(),
            })
            .collect(),
    ))
}

fn fixed_bytes48(value: [u8; 48]) -> Bytes48 {
    Bytes48 {
        first: value[..32].try_into().expect("32-byte prefix"),
        second: value[32..].try_into().expect("16-byte suffix"),
    }
}
