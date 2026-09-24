//! Workload-only Portal API. The runtime owns listener permissions and lifecycle.
use crate::abi::isSessionActiveCall;
use alloy_primitives::{keccak256, Address, B256};
use alloy_sol_types::SolCall;
use atakit_attestation::signing;
use automata_tee_workload_measurement::stubs::AlgoId;
use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        DefaultBodyLimit, Query, State,
    },
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{watch, RwLock};

#[derive(Clone, Serialize, Deserialize)]
pub struct PortalSession {
    pub session_id: B256,
    pub secret_key: [u8; 32],
    pub owner_fingerprint: B256,
    pub workload_id: B256,
    pub session_registry: Address,
    pub chain_id: u64,
    pub rpc_url: String,
    pub evidence_bundle: Value,
}
pub type PortalState = Arc<RwLock<Option<PortalSession>>>;
pub type PublicStatus = Arc<RwLock<Value>>;
#[derive(Clone)]
struct ApiState {
    session: PortalState,
    public_status: Option<PublicStatus>,
    allow_sign_message: bool,
}

const MAX_MESSAGE: usize = 1024 * 1024;

pub async fn serve(
    listener: tokio::net::UnixListener,
    state: PortalState,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    serve_configured(listener, state, None, true, shutdown).await
}

pub async fn serve_configured(
    listener: tokio::net::UnixListener,
    state: PortalState,
    public_status: Option<PublicStatus>,
    allow_sign_message: bool,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/portal-external-api/status", get(status))
        .route("/sign-message", post(sign_message))
        .route(
            "/portal-external-api/session/evidence-bundle",
            get(evidence),
        )
        .layer(DefaultBodyLimit::max(MAX_MESSAGE * 2 + 4096))
        .with_state(ApiState {
            session: state,
            public_status,
            allow_sign_message,
        });
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            while !*shutdown.borrow_and_update() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await?;
    Ok(())
}
fn error(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"error":msg}))).into_response()
}
fn not_ready() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1")],
        Json(json!({"code":"session_not_ready","state":"initializing_session","retryable":true})),
    )
        .into_response()
}
async fn active(session: &PortalSession) -> bool {
    let Ok(rpc) = crate::rpc::ReadRpc::new(&session.rpc_url) else {
        return false;
    };
    let call = isSessionActiveCall {
        sessionId: session.session_id,
    };
    let Ok(result) = rpc
        .call(
            &session.session_registry.to_string(),
            &format!("0x{}", hex::encode(call.abi_encode())),
        )
        .await
    else {
        return false;
    };
    let Ok(bytes) = hex::decode(result.strip_prefix("0x").unwrap_or("")) else {
        return false;
    };
    matches!(isSessionActiveCall::abi_decode_returns(&bytes), Ok(true))
}
pub fn status_document(session: Option<&PortalSession>) -> Value {
    json!({"init_schema_version":3,"state":if session.is_some(){"Running"}else{"InitializingWorkload"},
        "emulated":true,"workload_id":session.map(|s|s.workload_id),
        "base_image_id":session.and_then(|s|s.evidence_bundle.get("base_image_id")),
        "base_image_ref":null,"workload_ref":null,"gas_wallet_address":null,
        "started_at":"","detail":null,"prover":null,
        "platform":{"build_profile":"emulator","cloud_type":"gcp","cloud_provenance": {
    "source": "user_provided",
    "user_provided": "gcp",
    "detection": {
        "dmi": {"sys_vendor": null, "product_name": null, "bios_vendor": null, "detected_cloud": "unknown"},
        "metadata": {
            "gcp": {"attempted": false, "matched": false, "http_status": null, "response_headers": {}, "response_body": null, "error": null},
            "azure": {"attempted": false, "matched": false, "http_status": null, "response_headers": {}, "response_body": null, "error": null},
            "aws": {"attempted": false, "matched": false, "http_status": null, "response_headers": {}, "response_body": null, "error": null},
            "detected_cloud": "unknown", "conflict": false
        }
    }
}
,"attestation_mode":"emulation","tee_type":"tdx","machine_type":"unknown"},
        "chain":{"registration":"required","tee_backend":"solidity","status":if session.is_some(){"verified"}else{"pending"},
            "registry_address":session.map(|s|s.session_registry),"chain_id":session.map(|s|s.chain_id),
            "session_id":session.map(|s|s.session_id),"tx_hash":null,"block_number":null,"submitted_at":null,"verified_at":null,"detail":null}})
}
async fn status(State(state): State<ApiState>) -> Response {
    // Like Portal, status is a cached lifecycle snapshot, available even while
    // signing is gated or the chain RPC is unavailable.
    if let Some(status) = &state.public_status {
        return Json(status.read().await.clone()).into_response();
    }
    Json(status_document(state.session.read().await.as_ref())).into_response()
}
#[derive(Deserialize)]
struct SignRequest {
    message: String,
    hash_fn: Option<String>,
    #[serde(default, deserialize_with = "expected_id")]
    expected_session_id: Option<B256>,
}
fn expected_id<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<B256>, D::Error> {
    let value = String::deserialize(d)?;
    if value.len() != 66
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(serde::de::Error::custom(
            "expected_session_id must be canonical 0x-prefixed 32-byte lowercase hex",
        ));
    }
    value.parse().map(Some).map_err(serde::de::Error::custom)
}
fn signature(s: &PortalSession, digest: [u8; 32]) -> anyhow::Result<String> {
    Ok(format!(
        "0x{}",
        hex::encode(signing::sign_secp256k1_recoverable(
            &s.secret_key,
            digest,
            signing::SigEncoding::EthereumLegacyV
        )?)
    ))
}
async fn sign_message(
    State(state): State<ApiState>,
    body: Result<Json<SignRequest>, JsonRejection>,
) -> Response {
    if !state.allow_sign_message {
        return error(
            StatusCode::FORBIDDEN,
            "sign-message is disabled for this service",
        );
    }
    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return error(
                if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    e.status()
                } else {
                    StatusCode::BAD_REQUEST
                },
                "invalid signing request",
            )
        }
    };
    let Some(raw) = req
        .message
        .strip_prefix("0x")
        .or_else(|| req.message.strip_prefix("0X"))
    else {
        return error(StatusCode::BAD_REQUEST, "message must be 0x-prefixed hex");
    };
    if raw.len() > MAX_MESSAGE * 2 {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "message exceeds 1048576 bytes",
        );
    }
    let Ok(message) = hex::decode(raw) else {
        return error(StatusCode::BAD_REQUEST, "invalid message hex");
    };
    let hash_fn = req.hash_fn.as_deref().unwrap_or("keccak256");
    let data = [b"ATAKIT_SESSION_SIGN_V1".as_slice(), &message].concat();
    let digest = match hash_fn {
        "sha256" => Sha256::digest(&data).into(),
        "keccak256" => keccak256(&data).0,
        _ => return error(StatusCode::BAD_REQUEST, "unsupported hash_fn"),
    };
    // Keep the read guard through the chain check and signing: rotation cannot
    // publish a replacement snapshot while this request signs the current key.
    let guard = state.session.read().await;
    let Some(s) = guard.as_ref() else {
        return not_ready();
    };
    if req.expected_session_id.is_some_and(|id| id != s.session_id) {
        return error(StatusCode::CONFLICT, "session_id_mismatch");
    }
    if !active(s).await {
        return not_ready();
    }
    let Ok(sig) = signature(s, digest) else {
        return not_ready();
    };
    let Ok(key) = k256::ecdsa::SigningKey::from_slice(&s.secret_key) else {
        return not_ready();
    };
    let key = key.verifying_key().to_encoded_point(false);
    let fp = B256::from(atakit_cvm_encoding::key_fingerprint(
        AlgoId::Es256K as u8,
        key.as_bytes(),
    ));
    Json(json!({"hash_fn":hash_fn,"message_hash":format!("0x{}",hex::encode(digest)),"signature":sig,"session_id":s.session_id,"session_pubkey":{"type_id":3,"key":format!("0x{}",hex::encode(key.as_bytes())),"fingerprint":fp}})).into_response()
}
#[derive(Deserialize)]
struct Challenge {
    challenge: String,
}
async fn evidence(
    State(state): State<ApiState>,
    query: Result<Query<Challenge>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return error(StatusCode::BAD_REQUEST, "missing challenge");
    };
    let Ok(challenge) = URL_SAFE_NO_PAD.decode(&query.challenge) else {
        return error(
            StatusCode::BAD_REQUEST,
            "challenge must be unpadded base64url",
        );
    };
    let Ok(challenge) = <[u8; 32]>::try_from(challenge) else {
        return error(
            StatusCode::BAD_REQUEST,
            "challenge must decode to exactly 32 bytes",
        );
    };
    let guard = state.session.read().await;
    let Some(s) = guard.as_ref() else {
        return not_ready();
    };
    if !active(s).await {
        return not_ready();
    }
    let Ok(canonical) = serde_json_canonicalizer::to_vec(&s.evidence_bundle) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "canonicalize evidence bundle failed",
        );
    };
    let digest = atakit_attestation::request_binding_digest(
        "ATAKIT_PORTAL_SESSION_REQUEST_BINDING_EVIDENCE_BUNDLE_V1",
        challenge,
        &canonical,
    );
    let Ok(sig) = signature(s, digest) else {
        return not_ready();
    };
    Json(json!({"evidence_bundle":s.evidence_bundle,"request_binding":{"challenge":query.challenge,"signature":sig}})).into_response()
}
