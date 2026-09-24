use alloy_primitives::{keccak256, B256};
use alloy_sol_types::SolValue;
use atakit_attestation::session_protocol;
use atakit_attestation::signing;
use atakit_emulator::{
    abi,
    chain::{hexbytes, read, RegistryContext, SessionEngine},
    config::ResolvedWorkload,
    fork::{AnvilFork, ForkOptions},
};
use automata_tee_workload_measurement::stubs::AlgoId;
use serde_json::Value;
#[tokio::test]
#[ignore = "requires local real-contract fixture; EMULATOR_FIXTURE_JSON and EMULATOR_FIXTURE_RPC"]
async fn real_registries_validate_session_and_message_signatures() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("EMULATOR_FIXTURE_JSON").unwrap()).unwrap(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut fork = AnvilFork::spawn(ForkOptions {
        upstream_url: std::env::var("EMULATOR_FIXTURE_RPC").unwrap(),
        block_number: None,
        port,
        log_path: dir.path().join("anvil.log"),
        load_state: None,
    })
    .await
    .unwrap();
    let registry = RegistryContext::patch(
        &fork.rpc,
        fixture["sessionRegistry"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        31337,
    )
    .await
    .unwrap();
    let engine = SessionEngine::new(fork.rpc.clone(), registry)
        .await
        .unwrap();
    let owner = signing::decode_secret_key_hex(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .unwrap();
    let fp = B256::from(atakit_cvm_encoding::key_fingerprint(
        AlgoId::Es256K as u8,
        &signing::derive_public_key_uncompressed(&owner).unwrap(),
    ));
    let file = dir.path().join("atakit-workload.toml");
    std::fs::write(&file,format!("format=7\n[workload]\nname='emulator-test'\nversion='v1'\nbase-image-mode='whitelist'\nbase-image=['{fp}/emulator-gcp-tdx:1']\nimage='example:test'\n")).unwrap();
    let input = ResolvedWorkload {
        name: "test".into(),
        config_file: file,
        workload_dir: dir.path().into(),
        output_socket: dir.path().join("portal.sock"),
        owner_key: None,
        platform_profile: None,
        measurement_variant: None,
    };
    let session = engine.register(&input, &owner).await.unwrap();
    // A fresh candidate is valid, then each independent authorization layer is tampered.
    let policy = read(
        &engine.rpc,
        engine.registry.session,
        abi::getPcrPolicyCall {
            workloadId: session.workload_id,
            baseImageId: session.base_image_id,
            platformProfileId: session.profile_id,
            measurementVariantId: session.variant_id,
        },
    )
    .await
    .unwrap();
    let nonce = read(
        &engine.rpc,
        engine.registry.session,
        abi::getNonceCall {
            ownerFingerprint: session.owner_fp,
        },
    )
    .await
    .unwrap();
    let candidate = atakit_emulator::evidence::build(
        31337,
        engine.registry.session,
        session.owner_fp,
        nonce,
        &policy,
        &signing::generate_secret_key_bytes(),
    )
    .unwrap();
    let expiry = engine.timestamp().await.unwrap() + 3600;
    let fp = B256::from(atakit_cvm_encoding::key_fingerprint(
        AlgoId::Es256K as u8,
        &candidate.evidence.sessionKey.key,
    ));
    let payload = session_protocol::compute_owner_signature_payload(
        31337,
        engine.registry.session,
        expiry,
        candidate.session_id,
        session.workload_id,
        session.base_image_id,
        session.profile_id,
        session.variant_id,
        fp,
    );
    let signed =
        signing::sign_secp256k1_recoverable(&owner, payload, signing::SigEncoding::EthereumLegacyV)
            .unwrap();
    let valid = abi::registerSessionCall {
        evidence: candidate.evidence,
        workloadId: session.workload_id,
        baseImageId: session.base_image_id,
        platformProfileId: session.profile_id,
        variantId: session.variant_id,
        opExpiresAt: expiry,
        ownerIdentity: abi::SessionRegistry::PublicIdentity {
            typeId: 3,
            key: session.owner_public.clone().into(),
        },
        ownerSignature: signed.to_vec().into(),
    };
    read(&engine.rpc, engine.registry.session, valid.clone())
        .await
        .unwrap();
    let mut bad = valid.clone();
    let mut sig = bad.ownerSignature.to_vec();
    sig[0] ^= 1;
    bad.ownerSignature = sig.into();
    assert!(read(&engine.rpc, engine.registry.session, bad)
        .await
        .is_err());
    let (delegation, possession) =
        <(alloy_primitives::Bytes, alloy_primitives::Bytes)>::abi_decode_params(
            &valid.evidence.sessionKeySignature,
        )
        .unwrap();
    let mut bad = valid.clone();
    let mut sig = delegation.to_vec();
    let last = sig.len() - 1;
    sig[last] ^= 1;
    bad.evidence.sessionKeySignature =
        atakit_attestation::evidence_abi::encode_session_key_authorization(&sig, &possession)
            .into();
    assert!(read(&engine.rpc, engine.registry.session, bad)
        .await
        .is_err());
    let mut bad = valid.clone();
    let mut sig = possession.to_vec();
    sig[0] ^= 1;
    bad.evidence.sessionKeySignature =
        atakit_attestation::evidence_abi::encode_session_key_authorization(&delegation, &sig)
            .into();
    assert!(read(&engine.rpc, engine.registry.session, bad)
        .await
        .is_err());
    let mut bad = valid.clone();
    let mut quote = automata_tee_workload_measurement::stubs::TpmQuoteEvidence::abi_decode(
        &bad.evidence.tpmQuoteReport.data,
    )
    .unwrap();
    quote.pcrValues256[0].value[0] ^= 1;
    bad.evidence.tpmQuoteReport.data = quote.abi_encode().into();
    assert!(read(&engine.rpc, engine.registry.session, bad)
        .await
        .is_err());
    let message = keccak256(b"ATAKIT_SESSION_SIGN_V1hello");
    let sig = signing::sign_secp256k1_recoverable(
        &session.session_secret,
        message.0,
        signing::SigEncoding::EthereumLegacyV,
    )
    .unwrap();
    let public = signing::derive_public_key_uncompressed(&session.session_secret).unwrap();
    let call = abi::verifySessionSignatureCall {
        sessionId: session.session_id,
        message,
        sessionKey: abi::SessionRegistry::PublicIdentity {
            typeId: 3,
            key: public.to_vec().into(),
        },
        signature: sig.to_vec().into(),
    };
    assert!(read(&engine.rpc, engine.registry.session, call.clone())
        .await
        .unwrap());
    let mut wrong = call.clone();
    wrong.message = B256::ZERO;
    assert!(!read(&engine.rpc, engine.registry.session, wrong)
        .await
        .unwrap());
    let mut selected = input.clone();
    selected.platform_profile = Some("gcp-tdx".into());
    selected.measurement_variant = Some("missing-machine".into());
    let error = engine
        .register(&selected, &owner)
        .await
        .err()
        .expect("unsupported variant must fail");
    assert!(error.to_string().contains("found 0"));
    selected.measurement_variant = Some("default".into());
    let other = engine.register(&selected, &owner).await.unwrap();
    assert_ne!(other.session_id, session.session_id);
    let rotated = engine.rotate(&session, &owner).await.unwrap();
    assert_ne!(rotated.session_id, session.session_id);
    assert!(!engine.active(session.session_id).await.unwrap());
    assert!(engine.active(rotated.session_id).await.unwrap());
    engine.revoke(&rotated, &owner).await.unwrap();
    assert!(!engine.active(session.session_id).await.unwrap());
    assert!(engine.active(other.session_id).await.unwrap());
    let rejected = read(&engine.rpc, engine.registry.session, call).await;
    assert!(rejected.is_err() || !rejected.unwrap());
    println!(
        "session registration + real message verification + per-session revocation passed: {}",
        hexbytes(session.session_id)
    );
    fork.stop().await.unwrap();
}
