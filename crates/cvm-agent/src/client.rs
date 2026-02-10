//! HTTP client for communicating with the CVM agent.
//!
//! This module provides functionality to initialize a CVM instance by uploading
//! a workload package to the agent's `/init` endpoint.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, keccak256};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail};
use automata_linux_release::ImageRef;
use serde::Serialize;
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

/// Agent environment configuration for session registry.
/// Sent as part of InitConfig to configure the CVM agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentEnv {
    /// Private key for relay operations
    pub relay_private_key: B256,
    /// RPC URL for blockchain connection
    pub rpc_url: String,
    /// Session registry contract address
    pub session_registry: Address,
    /// Owner private key for session registration
    pub owner_private_key: B256,
    /// Base image reference (e.g., "tee-base-image:v1")
    pub base_image_ref: ImageRef,
    /// Workload reference (e.g., "secure-signer:v1")
    pub workload_ref: ImageRef,
    /// Session expiration offset in seconds (default: 3600)
    pub expire_offset: u64,
}

/// Default expire offset: 1 hour
pub const DEFAULT_EXPIRE_OFFSET: u64 = 3600;

/// Configuration for the /init endpoint.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InitConfig {
    /// QEMU platform response for mock mode (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qemu_platform_response: Option<serde_json::Value>,
    /// List of additional file field names in the multipart form
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_files: Vec<String>,
    /// Agent environment configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_env: Option<AgentEnv>,
}

/// An additional file to include in the /init request.
#[derive(Debug, Clone)]
pub struct AdditionalFile {
    /// Original filename
    pub source: String,
    /// Destination filename in the multipart form
    pub dest: String,
    /// File contents
    pub data: Vec<u8>,
}

/// Initialize a CVM instance by uploading the workload package.
///
/// Sends a POST request to `http://<ip>:8000/init` with:
/// - `config`: JSON configuration (agent_env, additional_files, etc.)
/// - `workload`: the workload tar.gz file
/// - Additional files specified in config.additional_files
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
    agent_env: Option<AgentEnv>,
    qemu_platform_response: Option<serde_json::Value>,
    additional_files: Vec<AdditionalFile>,
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

    // Prepare config with additional_files list
    let mut additional_files_list = Vec::new();
    for file in &additional_files {
        additional_files_list.push(file.dest.clone());
    }
    let config = InitConfig {
        qemu_platform_response,
        additional_files: additional_files_list,
        agent_env,
    };

    // Build multipart body manually so we can hash the exact bytes
    let body = build_multipart_body(filename, &workload_bytes, &config, &additional_files)?;

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
        let signer = PrivateKeySigner::from_bytes(&key).context("Invalid private key")?;

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

        let signature = signer
            .sign_hash(&hash)
            .await
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
async fn wait_for_agent(
    ip: &str,
    port: u16,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<()> {
    let url = format!("http://{}:{}{}", ip, port, PING_ENDPOINT);
    let start = std::time::Instant::now();
    let client = reqwest::Client::new();

    loop {
        if cancel.is_cancelled() {
            bail!("Cancelled while waiting for agent at {}", url);
        }

        if start.elapsed() > timeout {
            bail!("Timeout waiting for agent at {} after {:?}", url, timeout);
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
fn build_multipart_body(
    workload_filename: &str,
    workload_bytes: &[u8],
    config: &InitConfig,
    additional_files: &[AdditionalFile],
) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    // Config part (JSON with agent_env, additional_files, etc.)
    let config_json = serde_json::to_string(config).context("Failed to serialize config")?;
    body.extend_from_slice(format!("--{}\r\n", MULTIPART_BOUNDARY).as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"config\"; filename=\"config.json\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(config_json.as_bytes());
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

    // Additional files
    for file in additional_files {
        body.extend_from_slice(format!("--{}\r\n", MULTIPART_BOUNDARY).as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                file.dest, file.source
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&file.data);
        body.extend_from_slice(b"\r\n");
    }

    // Final boundary
    body.extend_from_slice(format!("--{}--\r\n", MULTIPART_BOUNDARY).as_bytes());

    Ok(body)
}
