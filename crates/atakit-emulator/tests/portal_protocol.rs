use alloy_primitives::{Address, B256};
use atakit_emulator::portal::{serve, PortalSession, PortalState};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{watch, RwLock};

async fn fixture() -> (
    tempfile::TempDir,
    reqwest::Client,
    PortalState,
    Arc<AtomicBool>,
    watch::Sender<bool>,
) {
    let active = Arc::new(AtomicBool::new(true));
    let flag = active.clone();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", tcp.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(tcp,axum::Router::new().route("/",axum::routing::post(move |axum::Json(v):axum::Json<Value>| {let flag=flag.clone();async move {assert_eq!(v["method"],"eth_call"); axum::Json(json!({"jsonrpc":"2.0","id":v["id"],"result":format!("0x{:064x}",u8::from(flag.load(Ordering::SeqCst)))}))}}))).await.unwrap();
    });
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32])
        .unwrap()
        .verifying_key()
        .to_encoded_point(false);
    let session = PortalSession {
        session_id: B256::repeat_byte(1),
        secret_key: [7; 32],
        owner_fingerprint: B256::repeat_byte(2),
        workload_id: B256::repeat_byte(3),
        session_registry: Address::repeat_byte(4),
        chain_id: 31337,
        rpc_url,
        evidence_bundle: json!({"session_key":{"bytes":format!("0x{}",hex::encode(key.as_bytes())),"type_id":3},"z":true,"a":{"n":1}}),
    };
    let state = Arc::new(RwLock::new(Some(session)));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("p.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let (tx, rx) = watch::channel(false);
    let shared = state.clone();
    tokio::spawn(async move {
        serve(listener, shared, rx).await.unwrap();
    });
    (
        dir,
        reqwest::Client::builder()
            .unix_socket(socket)
            .build()
            .unwrap(),
        state,
        active,
        tx,
    )
}
fn recover(v: &Value, digest: [u8; 32]) -> Vec<u8> {
    let bytes = hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
    let sig = k256::ecdsa::Signature::from_slice(&bytes[..64]).unwrap();
    k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest,
        &sig,
        k256::ecdsa::RecoveryId::from_byte(bytes[64] - 27).unwrap(),
    )
    .unwrap()
    .to_encoded_point(false)
    .as_bytes()
    .to_vec()
}
#[tokio::test]
async fn signs_current_domains_and_rejects_stale_malformed_and_inactive_sessions() {
    let (_dir, c, s, active, _tx) = fixture().await;
    for hash in ["sha256", "keccak256"] {
        let r = c
            .post("http://localhost/sign-message")
            .json(&json!({"message":"0x6869","hash_fn":hash}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let v: Value = r.json().await.unwrap();
        let data = b"ATAKIT_SESSION_SIGN_V1hi";
        let digest: [u8; 32] = if hash == "sha256" {
            Sha256::digest(data).into()
        } else {
            alloy_primitives::keccak256(data).0
        };
        assert_eq!(v["message_hash"], format!("0x{}", hex::encode(digest)));
        assert_eq!(
            format!("0x{}", hex::encode(recover(&v["signature"], digest))),
            v["session_pubkey"]["key"]
        );
    }
    for id in [json!(null), json!("0xAA"), json!(1)] {
        assert_eq!(
            c.post("http://localhost/sign-message")
                .json(&json!({"message":"0x","expected_session_id":id}))
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    assert_eq!(
        c.post("http://localhost/sign-message")
            .json(&json!({"message":"0x","expected_session_id":B256::ZERO}))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    active.store(false, Ordering::SeqCst);
    let r = c
        .post("http://localhost/sign-message")
        .json(&json!({"message":"0x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["retry-after"], "1");
    *s.write().await = None;
    assert_eq!(
        c.get("http://localhost/portal-external-api/status")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        c.post("http://localhost/session/rotate")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}
#[tokio::test]
async fn evidence_jcs_challenge_binding_is_recoverable_and_sensitive_to_tampering() {
    use base64::Engine;
    let (_d, c, _s, _a, _tx) = fixture().await;
    let challenge = [42; 32];
    let q = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    let v: Value = c
        .get(format!(
            "http://localhost/portal-external-api/session/evidence-bundle?challenge={q}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["request_binding"]["challenge"], q);
    let canonical = serde_json_canonicalizer::to_vec(&v["evidence_bundle"]).unwrap();
    let mut payload =
        alloy_primitives::keccak256(b"ATAKIT_PORTAL_SESSION_REQUEST_BINDING_EVIDENCE_BUNDLE_V1")
            .to_vec();
    payload.extend(challenge);
    payload.extend(Sha256::digest(canonical));
    let digest = Sha256::digest(&payload).into();
    let key = recover(&v["request_binding"]["signature"], digest);
    assert_eq!(
        format!("0x{}", hex::encode(&key)),
        v["evidence_bundle"]["session_key"]["bytes"]
    );
    payload[32] ^= 1;
    assert_ne!(
        recover(
            &v["request_binding"]["signature"],
            Sha256::digest(payload).into()
        ),
        key
    );
    for q in ["AA", "invalid=", ""] {
        assert_eq!(
            c.get(format!(
                "http://localhost/portal-external-api/session/evidence-bundle?challenge={q}"
            ))
            .send()
            .await
            .unwrap()
            .status(),
            400
        );
    }
}
#[tokio::test]
async fn socket_identity_isolated_rotation_atomic_and_status_public() {
    let (_d, c, s, _a, _tx) = fixture().await;
    let (_d2, c2, s2, _a2, _tx2) = fixture().await;
    {
        let mut second = s2.write().await;
        second.as_mut().unwrap().session_id = B256::repeat_byte(9);
        second.as_mut().unwrap().secret_key = [8; 32];
    }
    let status: Value = c
        .get("http://localhost/portal-external-api/status")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["emulated"], true);
    assert_eq!(status["chain"]["session_id"], json!(B256::repeat_byte(1)));
    assert!(!status.to_string().contains("secret_key"));
    assert!(!status.to_string().contains(&hex::encode([7; 32])));
    let request = json!({"message":"0x01","expected_session_id":B256::repeat_byte(1)});
    assert_eq!(
        c2.post("http://localhost/sign-message")
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    let before: Value = c
        .post("http://localhost/sign-message")
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let again: Value = c
        .post("http://localhost/sign-message")
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(before, again);
    {
        let mut current = s.write().await;
        current.as_mut().unwrap().session_id = B256::repeat_byte(6);
        current.as_mut().unwrap().secret_key = [6; 32];
    }
    assert_eq!(
        c.post("http://localhost/sign-message")
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    let after: Value = c
        .post("http://localhost/sign-message")
        .json(&json!({"message":"0x01"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after["session_id"], json!(B256::repeat_byte(6)));
    assert_ne!(before["session_pubkey"], after["session_pubkey"]);
    for request in [
        json!({"message":"hi"}),
        json!({"message":"0x1"}),
        json!({"message":"0x","hash_fn":"SHA256"}),
    ] {
        assert_eq!(
            c.post("http://localhost/sign-message")
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    assert_eq!(
        c.post("http://localhost/sign-message")
            .json(&json!({"message":format!("0x{}","00".repeat(1024*1024+1))}))
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
}

#[tokio::test]
async fn status_remains_available_without_chain_or_session_and_denied_service_cannot_sign() {
    let (_dir, client, state, active, _tx) = fixture().await;
    active.store(false, Ordering::SeqCst);
    let response = client
        .get("http://localhost/portal-external-api/status")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.json::<Value>().await.unwrap()["state"], "Running");
    *state.write().await = None;
    let response = client
        .get("http://localhost/portal-external-api/status")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.json::<Value>().await.unwrap()["state"],
        "InitializingWorkload"
    );
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("denied.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let (_stop, rx) = watch::channel(false);
    tokio::spawn(atakit_emulator::portal::serve_configured(
        listener, state, None, false, rx,
    ));
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .build()
        .unwrap();
    let response = client
        .post("http://localhost/sign-message")
        .json(&json!({"message":"0x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "sign-message is disabled for this service"
    );
}

#[test]
fn status_cloud_provenance_matches_portal_wire_shape() {
    let status = atakit_emulator::portal::status_document(None);
    let provenance = &status["platform"]["cloud_provenance"];
    assert_eq!(provenance["source"], "user_provided");
    assert_eq!(provenance["user_provided"], "gcp");
    assert_eq!(provenance["detection"]["dmi"]["detected_cloud"], "unknown");
    for provider in ["gcp", "azure", "aws"] {
        let probe = &provenance["detection"]["metadata"][provider];
        assert_eq!(probe["attempted"], false);
        assert_eq!(probe["matched"], false);
        assert!(probe["response_headers"].is_object());
    }
    assert_eq!(provenance["detection"]["metadata"]["conflict"], false);
}
