use atakit_cvm_encoding::pcr_comparison::*;
use atakit_emulator::abi::SessionRegistry::{PcrPolicyBlock, PcrSpec256};
use atakit_emulator::pcr::synthesize;
use sha2::{Digest, Sha256};
#[test]
fn static_dynamic_and_provider_binding_are_all_present() {
    let block = PcrPolicyBlock {
        pcrSpecs256: vec![
            PcrSpec256 {
                pcrIndex: 7,
                comparison: encode_static256([7; 32]).into(),
            },
            PcrSpec256 {
                pcrIndex: 20,
                comparison: encode_indexed_event_sets256(IndexedEventSets256 {
                    expected_event_count: 2,
                    checked_events: vec![IndexedEventSet256 {
                        event_index: 1,
                        allowed_values: vec![[3; 32]],
                    }],
                })
                .into(),
            },
        ],
        pcrSpecs384: vec![],
    };
    let (pcrs, _) = synthesize(&[&block], [9; 32]).unwrap();
    assert_eq!(
        pcrs.iter().map(|p| p.pcrIndex).collect::<Vec<_>>(),
        vec![7, 15, 20]
    );
    assert_eq!(pcrs[0].value.0, [7; 32]);
    assert_eq!(
        pcrs[1].value.as_slice(),
        Sha256::digest([vec![0; 32], vec![9; 32]].concat()).as_slice()
    );
    assert_eq!(pcrs[2].eventLogHashes.len(), 2);
    assert_eq!(pcrs[2].eventLogHashes[1].0, [3; 32]);
}
#[test]
fn contradictory_provider_policy_is_rejected() {
    let block = PcrPolicyBlock {
        pcrSpecs256: vec![PcrSpec256 {
            pcrIndex: 15,
            comparison: encode_static256([0; 32]).into(),
        }],
        pcrSpecs384: vec![],
    };
    assert!(synthesize(&[&block], [9; 32]).is_err());
}
#[test]
fn sha256_profile_omits_inactive_sha384_rules_from_the_quote() {
    use alloy_primitives::{Address, B256, U256};
    use alloy_sol_types::SolValue;
    use atakit_emulator::abi::SessionRegistry::{PcrSpec384, ResolvedPcrPolicy};
    use automata_tee_workload_measurement::stubs::TpmQuoteEvidence;
    let empty = PcrPolicyBlock {
        pcrSpecs256: vec![],
        pcrSpecs384: vec![],
    };
    let policy = ResolvedPcrPolicy {
        workloadId: B256::ZERO,
        baseImageId: B256::ZERO,
        platformProfileId: B256::ZERO,
        measurementVariantId: B256::ZERO,
        pcrBankSelection: 0, // Sha256
        invariantPcrPolicy: empty.clone(),
        variantPcrPolicy: empty.clone(),
        workloadPcrPolicy: PcrPolicyBlock {
            pcrSpecs256: vec![],
            pcrSpecs384: vec![PcrSpec384 {
                pcrIndex: 7,
                comparison: encode_static384([7; 48]).into(),
            }],
        },
    };
    let evidence = atakit_emulator::evidence::build(
        31337,
        Address::ZERO,
        B256::ZERO,
        U256::ZERO,
        &policy,
        &[1; 32],
    )
    .unwrap();
    let quote = TpmQuoteEvidence::abi_decode(&evidence.evidence.tpmQuoteReport.data).unwrap();
    assert!(quote.pcrValues384.is_empty());
    assert_eq!(quote.pcrValues256.len(), 1); // Required GCP binding PCR15 remains.
}
