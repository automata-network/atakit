//! Synthetic publisher policy vectors with test-only signing identities.
//! No network is used by these tests.
use alloy_primitives::{Bytes, B256};
use alloy_sol_types::SolCall;
use atakit_portal_chain::publisher_policy::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

const IMAGE: &str = "0x9f54fde30212fc2318f9d1a22d2e8ac59e3b97f36c0d5d648b233a63ef51864b";
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/publisher-policies.json")).unwrap()
}
fn id(v: &Value) -> B256 {
    v.as_str().unwrap().parse().unwrap()
}
fn bytes(v: &Value) -> Bytes {
    v.as_str().unwrap().parse().unwrap()
}
fn workload(v: &Value) -> SignedWorkload {
    getSignedWorkloadCall::abi_decode_returns_validate(&bytes(&v["workload"]["rawGetterResult"]))
        .unwrap()
}
fn variant(v: &Value) -> SignedBaseImageVariant {
    getSignedVariantCall::abi_decode_returns_validate(&bytes(&v["rawGetterResult"])).unwrap()
}

#[test]
fn synthetic_contract_getters_verify_with_separate_publishers() {
    let f = fixture();
    let w = workload(&f);
    let wid = id(&f["workload"]["id"]);
    verify_workload(wid, &w).unwrap();
    assert_eq!(
        B256::from_slice(&Sha256::digest(workload_payload(wid, &w.spec))),
        id(&f["workload"]["digest"])
    );
    for v in f["variants"].as_array().unwrap() {
        let image = variant(v);
        let image_id = IMAGE.parse().unwrap();
        assert_ne!(w.ownerFingerprint, image.ownerFingerprint);
        verify_variant(image_id, id(&v["profileId"]), id(&v["id"]), &image).unwrap();
        assert_eq!(
            B256::from_slice(&Sha256::digest(variant_payload(
                image_id,
                &image.platformProfile,
                &image.measurementVariant
            ))),
            id(&v["digest"])
        );
        let selected = verify_selected_policy(
            wid,
            image_id,
            id(&v["profileId"]),
            id(&v["id"]),
            w.clone(),
            image.clone(),
        );
        if image.platformProfile.name == "aws-sev-snp" {
            let selected = selected.unwrap();
            assert_eq!(
                selected.pcr_policy().invariantPcrPolicy,
                image.platformProfile.invariantPcrPolicy
            );
            assert_eq!(
                selected.pcr_policy().variantPcrPolicy,
                image.measurementVariant.variantPcrPolicy
            );
            assert_eq!(
                selected.pcr_policy().workloadPcrPolicy,
                w.spec.workloadPcrPolicy
            );
        } else {
            assert!(matches!(selected, Err(PolicyError::Attribute(_))));
        }
    }
}

#[test]
fn changed_workload_data_or_identity_is_rejected() {
    let f = fixture();
    let original = workload(&f);
    let wid = id(&f["workload"]["id"]);
    type WorkloadChange = Box<dyn Fn(&mut SignedWorkload)>;
    let changes: Vec<WorkloadChange> = vec![
        Box::new(|w| w.spec.name.push('x')),
        Box::new(|w| w.spec.version.push('x')),
        Box::new(|w| w.spec.sessionTtl += 1),
        Box::new(|w| w.spec.baseImageIds.clear()),
        Box::new(|w| w.spec.baseImageMode = AccessMode::ANY),
        Box::new(|w| w.spec.requirements.clear()),
        Box::new(|w| w.spec.workloadPcrPolicy.pcrSpecs256.clear()),
        Box::new(|w| w.ownerFingerprint = B256::ZERO),
        Box::new(|w| w.ownerIdentity.key = Bytes::new()),
        Box::new(|w| w.workloadSignature = Bytes::new()),
        Box::new(|w| {
            let mut s = w.workloadSignature.to_vec();
            s[64] = 0;
            w.workloadSignature = s.into();
        }),
    ];
    for (i, change) in changes.into_iter().enumerate() {
        let mut w = original.clone();
        change(&mut w);
        assert!(
            verify_workload(wid, &w).is_err(),
            "accepted workload mutation {i}"
        );
    }
    assert!(verify_workload(B256::ZERO, &original).is_err());
}

#[test]
fn changed_variant_data_or_identity_is_rejected() {
    let f = fixture();
    let v = &f["variants"][0];
    let original = variant(v);
    type VariantChange = Box<dyn Fn(&mut SignedBaseImageVariant)>;
    let changes: Vec<VariantChange> = vec![
        Box::new(|b| b.baseImage.name.push('x')),
        Box::new(|b| b.baseImage.version.push('x')),
        Box::new(|b| b.platformProfile.name.push('x')),
        Box::new(|b| b.measurementVariant.name.push('x')),
        Box::new(|b| b.platformProfile.pcrBankSelection = 2),
        Box::new(|b| b.platformProfile.invariantPcrPolicy.pcrSpecs256.clear()),
        Box::new(|b| b.measurementVariant.variantPcrPolicy.pcrSpecs256.clear()),
        Box::new(|b| b.platformProfile.attributes.clear()),
        Box::new(|b| b.measurementVariant.attributes.clear()),
        Box::new(|b| b.ownerFingerprint = B256::ZERO),
        Box::new(|b| b.ownerIdentity.key = Bytes::new()),
        Box::new(|b| b.variantSignature = Bytes::new()),
    ];
    for (i, change) in changes.into_iter().enumerate() {
        let mut image = original.clone();
        change(&mut image);
        assert!(
            verify_variant(
                IMAGE.parse().unwrap(),
                id(&v["profileId"]),
                id(&v["id"]),
                &image
            )
            .is_err(),
            "accepted variant mutation {i}"
        );
    }
    let mut swapped = original.clone();
    swapped.variantSignature = variant(&f["variants"][1]).variantSignature;
    assert!(verify_variant(
        IMAGE.parse().unwrap(),
        id(&v["profileId"]),
        id(&v["id"]),
        &swapped
    )
    .is_err());
    for (image, profile, variant_id) in [
        (B256::ZERO, id(&v["profileId"]), id(&v["id"])),
        (IMAGE.parse().unwrap(), B256::ZERO, id(&v["id"])),
        (IMAGE.parse().unwrap(), id(&v["profileId"]), B256::ZERO),
    ] {
        assert!(verify_variant(image, profile, variant_id, &original).is_err());
    }
    // URI is descriptive metadata, deliberately outside the signed policy.
    let mut uri = original;
    uri.baseImage.uri = "https://untrusted.invalid".into();
    verify_variant(
        IMAGE.parse().unwrap(),
        id(&v["profileId"]),
        id(&v["id"]),
        &uri,
    )
    .unwrap();
}
