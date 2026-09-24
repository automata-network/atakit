use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use atakit_emulator::{abi::SessionRegistry as registry, evidence};
use automata_tee_workload_measurement::stubs::TpmQuoteEvidence;

fn policy() -> registry::ResolvedPcrPolicy {
    let empty = registry::PcrPolicyBlock {
        pcrSpecs256: vec![],
        pcrSpecs384: vec![],
    };
    registry::ResolvedPcrPolicy {
        workloadId: B256::from([1; 32]),
        baseImageId: B256::from([2; 32]),
        platformProfileId: B256::from([3; 32]),
        measurementVariantId: B256::from([4; 32]),
        pcrBankSelection: 2, // Sha256AndSha384
        invariantPcrPolicy: registry::PcrPolicyBlock {
            pcrSpecs256: vec![registry::PcrSpec256 {
                pcrIndex: 7,
                comparison: atakit_cvm_encoding::pcr_comparison::encode_static256([5; 32]).into(),
            }],
            pcrSpecs384: vec![registry::PcrSpec384 {
                pcrIndex: 8,
                comparison: atakit_cvm_encoding::pcr_comparison::encode_static384([6; 48]).into(),
            }],
        },
        variantPcrPolicy: empty.clone(),
        workloadPcrPolicy: empty,
    }
}

fn fixture_evidence() -> registry::AttestationEvidence {
    registry::AttestationEvidence {
        teeReport: registry::TeeReport {
            verificationBackendType: 0,
            teeType: 0,
            data: vec![1; 67].into(),
        },
        akPub: registry::PublicIdentity {
            typeId: 2,
            key: vec![2; 65].into(),
        },
        tpmQuoteReport: registry::TpmReport {
            verificationBackendType: 0,
            tpmReportType: 0,
            data: vec![3; 35].into(),
        },
        tpmCertifyReport: registry::TpmReport {
            verificationBackendType: 0,
            tpmReportType: 1,
            data: vec![4; 45].into(),
        },
        akPubCollateral: registry::AkPubCollateral {
            akPubCollateralType: 0,
            verificationBackendType: 0,
            data: vec![5; 80].into(),
        },
        sessionKeySignature: vec![6; 71].into(),
        sessionKey: registry::PublicIdentity {
            typeId: 3,
            key: vec![7; 65].into(),
        },
    }
}

// Frozen ABI hashes were checked against Portal chain revision 079cb59c3434926890f0017a19b9684f86dddfb5.
// Keep these independent of the generated bindings to detect encoding drift.
#[test]
fn checkpoint_policy_encoding_and_generated_evidence_are_compatible() {
    let policy = policy();
    assert_eq!(
        keccak256(policy.abi_encode()).to_string(),
        "0xf8e09cfbb6a96a16ccfd7db17b28e9f411948b635497a6872cc3fffb3d711bff"
    );
    let generated = evidence::build(
        31337,
        Address::ZERO,
        B256::ZERO,
        U256::ZERO,
        &policy,
        &[7; 32],
    )
    .unwrap();
    let decoded =
        registry::AttestationEvidence::abi_decode(&generated.evidence.abi_encode()).unwrap();
    let quote = TpmQuoteEvidence::abi_decode(&decoded.tpmQuoteReport.data).unwrap();
    assert_eq!(quote.pcrValues256.len(), 2);
    assert_eq!(quote.pcrValues384.len(), 1);
    assert_eq!(quote.pcrValues256[0].value, B256::from([5; 32]));
    assert_eq!(quote.pcrValues384[0].value.first, B256::from([6; 32]));
    assert_eq!(decoded.teeReport.teeType, 0); // IntelTDX
    assert_eq!(decoded.tpmQuoteReport.tpmReportType, 0); // TpmQuote
    assert_eq!(decoded.tpmCertifyReport.tpmReportType, 1); // TpmCertify
}

#[test]
fn registration_and_rotation_calldata_match_frozen_vectors() {
    let policy = policy();
    let evidence = fixture_evidence();
    let identity = registry::PublicIdentity {
        typeId: 3,
        key: vec![4; 65].into(),
    };
    let call = registry::registerSessionCall {
        evidence: evidence.clone(),
        workloadId: policy.workloadId,
        baseImageId: policy.baseImageId,
        platformProfileId: policy.platformProfileId,
        variantId: policy.measurementVariantId,
        opExpiresAt: 123456,
        ownerIdentity: identity.clone(),
        ownerSignature: vec![8; 65].into(),
    };
    let encoded = call.abi_encode();
    assert_eq!(
        keccak256(&encoded).to_string(),
        "0xd2af31934b2118a5a5fe4b97cb352ddf3a8f0fab41cdf863f2c9fb53e45a1c04"
    );

    let rotate = registry::rotateKeyCall {
        oldSessionId: B256::from([9; 32]),
        teeReportBytesHash: B256::from([13; 32]),
        rotationEvidence: registry::SessionKeyRotationEvidence {
            tpmQuoteReport: evidence.tpmQuoteReport,
            tpmCertifyReport: evidence.tpmCertifyReport,
            sessionKeySignature: evidence.sessionKeySignature,
            sessionKey: evidence.sessionKey,
            rotationSignature: vec![10; 70].into(),
            oldTpmSigningKey: registry::PublicIdentity {
                typeId: 2,
                key: vec![11; 65].into(),
            },
            akPub: evidence.akPub,
        },
        opExpiresAt: 654321,
        ownerIdentity: identity,
        ownerSignature: vec![12; 65].into(),
    };
    let encoded = rotate.abi_encode();
    assert_eq!(
        keccak256(&encoded).to_string(),
        "0x5ca0d283ccc9e88ef9f89e1ea3bee2d8af675b458cb0293751a6665892dfa142"
    );
}

#[test]
fn session_result_preserves_workload_and_expiration_positions() {
    let encoded: Vec<u8> = (1..=9u8)
        .flat_map(|v| {
            let mut word = [0; 32];
            word[31] = v;
            word
        })
        .collect();
    let session = registry::getSessionCall::abi_decode_returns(&encoded).unwrap();
    assert_eq!(session.workloadId[31], 5);
    assert_eq!(session.registeredAt, 8);
    assert_eq!(session.sessionExpiresAt, 9);
}
