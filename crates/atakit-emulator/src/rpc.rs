//! JSON-RPC transport with a read-only upstream surface and a separate owned-node surface.
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Clone)]
struct Transport {
    url: String,
    client: reqwest::Client,
    id: Arc<AtomicU64>,
}
impl Transport {
    fn new(url: &str) -> Result<Self> {
        let parsed = url::Url::parse(url).context("invalid RPC URL")?;
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("RPC URL must use HTTP or HTTPS");
        }
        Ok(Self {
            url: url.into(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()?,
            id: Arc::new(AtomicU64::new(1)),
        })
    }
    async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let mut reply = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "{method}: {}",
                    if e.is_timeout() {
                        "RPC request timed out"
                    } else {
                        "RPC connection failed"
                    }
                )
            })?;
        let code = reply.status();
        if !code.is_success() {
            bail!("{method}: RPC HTTP {code}");
        }
        let mut body = Vec::new();
        while let Some(chunk) = reply.chunk().await.context("read RPC response")? {
            if body.len() + chunk.len() > 64 * 1024 * 1024 {
                bail!("RPC response exceeds 64 MiB");
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body).context("invalid RPC JSON response")?;
        if value.get("id") != Some(&json!(id)) {
            bail!("{method}: RPC response id mismatch");
        }
        if let Some(error) = value.get("error") {
            bail!("{method}: RPC error {error}");
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: RPC result is missing"))
    }
}

/// Only allows reads. The upstream supplied by the user never gets a write-capable handle.
#[derive(Clone)]
pub struct ReadRpc(Transport);
impl ReadRpc {
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self(Transport::new(url)?))
    }
    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        if !matches!(
            method,
            "eth_chainId"
                | "eth_blockNumber"
                | "eth_getBlockByNumber"
                | "eth_getBlockByHash"
                | "eth_getCode"
                | "eth_getStorageAt"
                | "eth_getBalance"
                | "eth_getTransactionCount"
                | "eth_getTransactionReceipt"
                | "eth_call"
                | "eth_estimateGas"
                | "eth_gasPrice"
                | "eth_maxPriorityFeePerGas"
                | "eth_accounts"
                | "web3_clientVersion"
                | "anvil_nodeInfo"
                | "anvil_metadata"
        ) {
            bail!("upstream RPC method is not read-only: {method}");
        }
        self.0.request(method, params).await
    }
    pub async fn chain_id(&self) -> Result<u64> {
        quantity(&self.request("eth_chainId", json!([])).await?)
    }
    pub async fn call(&self, to: &str, data: &str) -> Result<String> {
        string(
            self.request("eth_call", json!([{"to":to,"data":data},"latest"]))
                .await?,
        )
    }
}

/// Created only after spawning a node we own; never constructed from a user-supplied URL.
#[derive(Clone)]
pub struct LocalRpc(Transport);
impl LocalRpc {
    pub(crate) fn owned(port: u16) -> Result<Self> {
        Ok(Self(Transport::new(&format!("http://127.0.0.1:{port}"))?))
    }
    pub fn reads_url(&self) -> String {
        self.0.url.clone()
    }
    pub fn reads(&self) -> ReadRpc {
        ReadRpc(self.0.clone())
    }
    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        self.0.request(method, params).await
    }
    pub async fn call(&self, to: &str, data: &str) -> Result<String> {
        self.reads().call(to, data).await
    }
    pub async fn receipt(&self, hash: &str) -> Result<Value> {
        for _ in 0..120 {
            let receipt = self
                .request("eth_getTransactionReceipt", json!([hash]))
                .await?;
            if !receipt.is_null() {
                if receipt["status"] != "0x1" {
                    bail!("local transaction reverted: {hash}");
                }
                return Ok(receipt);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        bail!("local transaction receipt timeout: {hash}")
    }
    pub async fn send(&self, from: &str, to: Option<&str>, data: &str) -> Result<Value> {
        let mut tx = json!({"from":from,"data":data,"gas":"0x1c9c380"});
        if let Some(to) = to {
            tx["to"] = json!(to);
        }
        let hash = string(self.request("eth_sendTransaction", json!([tx])).await?)?;
        self.receipt(&hash).await
    }
}

pub fn string(value: Value) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .context("RPC result must be a string")
}
pub fn quantity(value: &Value) -> Result<u64> {
    let raw = value.as_str().context("RPC quantity must be a string")?;
    u64::from_str_radix(
        raw.strip_prefix("0x")
            .context("RPC quantity missing 0x prefix")?,
        16,
    )
    .context("invalid RPC quantity")
}
