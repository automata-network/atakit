//! Session client for communicating with the CVM agent via Unix socket.
//!
//! This module provides functionality to sign messages and rotate session keys
//! using the CVM agent's internal API endpoints.

use alloy::primitives::{B256, Bytes};
use anyhow::{Context, Result};
use automata_tee_workload_measurement::stubs::PublicIdentity;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

/// Request for signing a message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignMessageRequest {
    /// Message to sign (hex with 0x prefix)
    pub message: Bytes,
}

/// Response from the sign-message endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignMessageResponse {
    /// secp256k1 signature (65 bytes: r || s || v)
    pub signature: Bytes,
    /// Current session ID
    pub session_id: B256,
    /// Session key public identity
    pub session_key_public: PublicIdentity,
    /// Session key fingerprint
    pub session_key_fingerprint: B256,
    /// Owner key public identity
    pub owner_key_public: PublicIdentity,
    /// Owner identity fingerprint
    pub owner_fingerprint: B256,
    /// Workload ID
    pub workload_id: B256,
    /// Base image ID
    pub base_image_id: B256,
}

/// Request for rotating the session key (empty)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotateKeyRequest {}

/// Response from the rotate-key endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotateKeyResponse {
    /// New session ID after rotation
    pub session_id: B256,
    /// New session key fingerprint
    pub session_key_fingerprint: B256,
    /// New session key public identity
    pub session_key_public: PublicIdentity,
    /// Transaction hash (may be empty)
    #[serde(default)]
    pub tx_hash: Option<B256>,
}

/// CVM Agent session client using Unix socket
pub struct CvmAgent {
    socket_path: String,
}

impl CvmAgent {
    /// Create a new session client with the default socket path
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Sign a message using the session key
    ///
    /// The message is hashed with keccak256 before signing.
    /// Returns the signature and session information.
    pub async fn sign_message(&self, message: &[u8]) -> Result<SignMessageResponse> {
        let request = SignMessageRequest {
            message: Bytes::from(message.to_vec()),
        };
        let body = serde_json::to_vec(&request).context("Failed to serialize request")?;

        let response_bytes = self.post("/sign-message", body).await?;
        let response: SignMessageResponse = serde_json::from_slice(&response_bytes)
            .context("Failed to parse sign-message response")?;

        Ok(response)
    }

    pub async fn get_session_key_public(&self) -> Result<PublicIdentity> {
        let response = self.sign_message(&[]).await?;
        Ok(response.session_key_public)
    }

    /// Rotate the session key
    ///
    /// Triggers immediate session key rotation on-chain.
    /// Returns the new session information.
    pub async fn rotate_key(&self) -> Result<RotateKeyResponse> {
        let request = RotateKeyRequest::default();
        let body = serde_json::to_vec(&request).context("Failed to serialize request")?;

        let response_bytes = self.post("/rotate-key", body).await?;
        let response: RotateKeyResponse = serde_json::from_slice(&response_bytes)
            .context("Failed to parse rotate-key response")?;

        Ok(response)
    }

    /// Send a POST request to the CVM agent via Unix socket
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("Failed to connect to Unix socket: {}", self.socket_path))?;

        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("Failed to perform HTTP handshake")?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("Connection error: {}", e);
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .context("Failed to build request")?;

        let res = sender
            .send_request(req)
            .await
            .context("Failed to send request")?;

        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .context("Failed to read response body")?
            .to_bytes();

        if !status.is_success() {
            let error_msg = String::from_utf8_lossy(&body);
            anyhow::bail!("Request failed with status {}: {}", status, error_msg);
        }

        Ok(body.to_vec())
    }
}
