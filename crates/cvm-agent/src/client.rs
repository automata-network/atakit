//! HTTP client for communicating with the CVM agent.
//!
//! This module provides functionality to initialize a CVM instance by uploading
//! a workload package to the agent's `/init` endpoint.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{B256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use anyhow::{bail, Context, Result};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::info;

const INIT_PORT: u16 = 8000;
const INIT_ENDPOINT: &str = "/init";
const PING_ENDPOINT: &str = "/ping";

// Header names for operator authentication
const HEADER_SIGNATURE: &str = "X-Operator-Signature";
const HEADER_TIMESTAMP: &str = "X-Operator-Timestamp";

// Multipart boundary (fixed for reproducible hashing)
const MULTIPART_BOUNDARY: &str = "----AtakitFormBoundary7MA4YWxkTrZu0gW";

/// Response from the /init endpoint.
#[derive(Debug, serde::Deserialize)]
struct InitResponse {
    success: bool,
    message: String,
    #[serde(default)]
    error: Option<String>,
}

/// Initialize a CVM instance by uploading the workload package.
///
/// Sends a POST request to `http://<ip>:8000/init` with:
/// - `config`: empty JSON `{}`
/// - `workload`: the workload tar.gz file
///
/// If `signing_key` is provided, the request is signed with ECDSA using:
/// - `X-Operator-Timestamp`: Unix timestamp in seconds
/// - `X-Operator-Signature`: ECDSA signature over keccak256(timestamp || body)
///
/// The `cancel` token can be used to abort the operation early (e.g., when
/// the QEMU process exits before init completes).
pub async fn init_workload(
    ip: &str,
    workload_path: &Path,
    private_key: Option<B256>,
    cancel: CancellationToken,
) -> Result<()> {
    let url = format!("http://{}:{}{}", ip, INIT_PORT, INIT_ENDPOINT);

    info!(ip, "Waiting for CVM agent...");
    wait_for_agent(ip, INIT_PORT, Duration::from_secs(300), &cancel).await?;

    // Check if cancelled after wait
    if cancel.is_cancelled() {
        bail!("Init cancelled");
    }

    info!(workload = %workload_path.display(), "Uploading workload to CVM");

    // Read workload file
    let workload_bytes = tokio::fs::read(workload_path)
        .await
        .with_context(|| format!("Failed to read workload file: {}", workload_path.display()))?;

    let filename = workload_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workload.tar.gz");

    // Build multipart body manually so we can hash the exact bytes
    let body = build_multipart_body(filename, &workload_bytes);

    // Build request
    let client = reqwest::Client::new();
    let content_type = format!("multipart/form-data; boundary={}", MULTIPART_BOUNDARY);
    let mut request = client
        .post(&url)
        .header("Content-Type", content_type)
        .body(body.clone())
        .timeout(Duration::from_secs(300));

    // Add signature headers if signing key is provided
    if let Some(key) = private_key {
        let signer = PrivateKeySigner::from_bytes(&key)
            .context("Invalid private key")?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        // Sign: keccak256(timestamp || body)
        // Must match what Go middleware does: append([]byte(timestampStr), body...)
        let mut message = timestamp.as_bytes().to_vec();
        message.extend_from_slice(&body);
        let hash = keccak256(&message);

        let signature = signer.sign_hash(&hash).await
            .context("Failed to sign message")?;

        // Build 65-byte signature: [R || S || V]
        // go-ethereum's crypto.SigToPub expects V to be 0 or 1 (recovery id),
        // not 27 or 28. signature.v() returns bool (y-parity): false=0, true=1
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig_bytes[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig_bytes[64] = if signature.v() { 1 } else { 0 };

        let sig_hex = format!("0x{}", hex::encode(sig_bytes));

        request = request
            .header(HEADER_TIMESTAMP, &timestamp)
            .header(HEADER_SIGNATURE, sig_hex);

        info!("Request signed with operator key");
    }

    // Send request with cancellation support
    let response = tokio::select! {
        _ = cancel.cancelled() => {
            bail!("Init cancelled during upload");
        }
        result = request.send() => {
            result.with_context(|| format!("Failed to send init request to {}", url))?
        }
    };

    let status = response.status();
    let body: InitResponse = response
        .json()
        .await
        .context("Failed to parse init response")?;

    if !status.is_success() || !body.success {
        let err_msg = body.error.unwrap_or_else(|| body.message.clone());
        bail!("Init failed: {}", err_msg);
    }

    info!(message = %body.message, "CVM initialization complete");
    Ok(())
}

/// Wait for the CVM agent to become reachable via HTTP /ping.
///
/// Uses a 1s timeout per request. Any response (including 404) is treated as success,
/// indicating the HTTP server is up.
async fn wait_for_agent(ip: &str, port: u16, timeout: Duration, cancel: &CancellationToken) -> Result<()> {
    let url = format!("http://{}:{}{}", ip, port, PING_ENDPOINT);
    let start = std::time::Instant::now();
    let client = reqwest::Client::new();

    loop {
        if cancel.is_cancelled() {
            bail!("Cancelled while waiting for agent at {}", url);
        }

        if start.elapsed() > timeout {
            bail!(
                "Timeout waiting for agent at {} after {:?}",
                url,
                timeout
            );
        }

        // Try to ping with 1s timeout
        let result = client
            .get(&url)
            .timeout(Duration::from_secs(1))
            .send()
            .await;

        match result {
            Ok(_) => {
                // Any response (200, 404, etc.) means the server is up
                info!(url = %url, "Agent is reachable");
                return Ok(());
            }
            Err(_) => {
                // Connection failed, retry after a short delay
                tokio::select! {
                    _ = cancel.cancelled() => {
                        bail!("Cancelled while waiting for agent at {}", url);
                    }
                    _ = sleep(Duration::from_secs(2)) => {}
                }
            }
        }
    }
}

/// Build multipart form body manually.
///
/// This allows us to know the exact bytes that will be sent, so we can
/// compute the correct hash for signing (matching Go middleware behavior).
fn build_multipart_body(workload_filename: &str, workload_bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();

    // Config part (empty JSON)
    body.extend_from_slice(format!("--{}\r\n", MULTIPART_BOUNDARY).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"config\"; filename=\"config.json\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(b"{}");
    body.extend_from_slice(b"\r\n");

    // Workload part
    body.extend_from_slice(format!("--{}\r\n", MULTIPART_BOUNDARY).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"workload\"; filename=\"{}\"\r\n",
            workload_filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/gzip\r\n");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(workload_bytes);
    body.extend_from_slice(b"\r\n");

    // Final boundary
    body.extend_from_slice(format!("--{}--\r\n", MULTIPART_BOUNDARY).as_bytes());

    body
}
