//! Unix-socket HTTP server for the simulated CVM agent.
//!
//! Exposes `/sign-message` and `/rotate-key` endpoints over a Unix domain
//! socket, delegating cryptographic operations to [`ServiceState`].

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use tokio::net::UnixListener;

use super::state::ServiceState;
use crate::client::cvm_agent::{RotateKeyRequest, SignMessageRequest};

/// Bind a Unix socket at `socket_path` and serve requests forever.
///
/// The caller is responsible for creating the [`ServiceState`] and wrapping it
/// in an [`Arc`]; the server only borrows the shared reference.
pub(crate) async fn serve_socket(socket_path: &Path, state: Arc<ServiceState>) -> Result<()> {
    // Clean up old socket
    let _ = std::fs::remove_file(socket_path);

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create socket directory: {}", parent.display()))?;
    }

    let app = Router::new()
        .route("/sign-message", post(handle_sign))
        .route("/rotate-key", post(handle_rotate))
        .with_state(state);

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind Unix socket: {}", socket_path.display()))?;

    axum::serve(listener, app)
        .await
        .context("Sim agent server error")
}

async fn handle_sign(
    State(state): State<Arc<ServiceState>>,
    Json(req): Json<SignMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resp = state.sign(&req.message).await?;
    Ok(Json(resp))
}

async fn handle_rotate(
    State(state): State<Arc<ServiceState>>,
    Json(_req): Json<RotateKeyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resp = state.rotate_session_key().await?;
    Ok(Json(resp))
}

/// Wrapper to convert `anyhow::Error` into an axum response.
struct AppError(anyhow::Error);

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        Self(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "error": self.0.to_string() });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
    }
}
