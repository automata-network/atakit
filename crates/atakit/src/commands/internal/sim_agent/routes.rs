use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/sign", post(sign_handler))
        .route("/session", get(session_handler))
        .route("/attestation", get(attestation_handler))
}

async fn health_handler() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "agent": "sim-agent"
    }))
}

async fn sign_handler(Json(body): Json<Value>) -> Json<Value> {
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("0x");

    // Generate a deterministic mock signature from the message.
    Json(json!({
        "session_id": "0x00000000000000000000000000000000000000000000000000000000deadbeef",
        "signature": format!("0x{}", "ab".repeat(65)),
        "session_public_key": format!("0x{}", "cd".repeat(33)),
        "message": message
    }))
}

async fn session_handler() -> Json<Value> {
    Json(json!({
        "session_id": "0x00000000000000000000000000000000000000000000000000000000deadbeef",
        "is_active": true,
        "expires_at": "2099-12-31T23:59:59Z"
    }))
}

async fn attestation_handler() -> Json<Value> {
    Json(json!({
        "attestation_report": "mock-attestation-base64-data",
        "platform": "sim",
        "tdx_version": "simulated"
    }))
}
