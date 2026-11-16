//! A counting JSON-RPC endpoint, for asserting on the transport rather than on
//! a return value.
//!
//! Some properties of the exclusive-source rule cannot be checked by looking at
//! what a verification returned. "Explicit mode performed no chain read" is one
//! of them: a verification that wrongly consulted a chain and then succeeded
//! looks exactly like one that never consulted it. The only honest assertion is
//! on the transport, so this serves a real endpoint and counts what arrives.
//!
//! It answers just enough JSON-RPC for `AttestationClient::connect` to succeed,
//! which is the point: the client under test must be genuinely reachable, or
//! "the client was untouched" proves nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A JSON-RPC endpoint that records how many requests reached it.
pub(crate) struct CountingRpcEndpoint {
    url: String,
    requests: Arc<AtomicUsize>,
}

impl CountingRpcEndpoint {
    /// Bind an endpoint on an ephemeral port and serve until dropped.
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind counting RPC endpoint");
        let address = listener.local_addr().expect("endpoint address");
        let requests = Arc::new(AtomicUsize::new(0));
        let served = Arc::clone(&requests);

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                // Count at accept, not after parsing. A request still in
                // flight when the assertion runs would otherwise go unseen,
                // and these counters are used for must-be-zero assertions
                // where undercounting is the dangerous direction.
                served.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    // Read headers, then exactly `Content-Length` body bytes.
                    let body = loop {
                        let read = match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => read,
                        };
                        buffer.extend_from_slice(&chunk[..read]);
                        let Some(header_end) = find_header_end(&buffer) else {
                            continue;
                        };
                        let length = content_length(&buffer[..header_end]);
                        if buffer.len() >= header_end + length {
                            break buffer[header_end..header_end + length].to_vec();
                        }
                    };

                    let payload = serde_json::from_slice::<serde_json::Value>(&body)
                        .unwrap_or(serde_json::Value::Null);
                    let response = match &payload {
                        serde_json::Value::Array(batch) => {
                            serde_json::Value::Array(batch.iter().map(answer).collect::<Vec<_>>())
                        }
                        single => answer(single),
                    };
                    let encoded = response.to_string();
                    let http = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        encoded.len(),
                        encoded
                    );
                    let _ = stream.write_all(http.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });

        Self {
            url: format!("http://{address}"),
            requests,
        }
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// How many connections have reached the endpoint so far.
    pub(crate) fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

/// A plausible answer for anything `connect` asks.
///
/// `eth_call` returns a 32-byte word whose low 20 bytes are a non-zero address,
/// which is what the registry-address decoders expect. Everything else gets a
/// chain id.
fn answer(request: &serde_json::Value) -> serde_json::Value {
    let id = request.get("id").cloned().unwrap_or(serde_json::json!(1));
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let result = match method {
        "eth_call" => format!("0x{}{}", "00".repeat(12), "11".repeat(20)),
        _ => "0x7a69".to_string(),
    };
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}
