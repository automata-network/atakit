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

// The owned Anvil runs Osaka, which caps each transaction at 2^24 gas.
const TRANSACTION_GAS_CAP: u64 = 1 << 24;

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
            self.request(
                "eth_call",
                json!([{"to":to,"data":data,"gas":format!("0x{TRANSACTION_GAS_CAP:x}")},"latest"]),
            )
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
        let block = self
            .request("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let cap = quantity(&block["gasLimit"])
            .context("read local block gas limit")?
            .min(TRANSACTION_GAS_CAP);
        let mut tx = json!({"from":from,"data":data,"gas":format!("0x{cap:x}")});
        if let Some(to) = to {
            tx["to"] = json!(to);
        }
        let estimate = quantity(
            &self
                .request("eth_estimateGas", json!([tx.clone()]))
                .await
                .context("estimate local transaction gas")?,
        )?;
        if estimate > cap {
            bail!("estimated gas {estimate} exceeds local transaction gas limit {cap}");
        }
        // Leave 20% headroom without exceeding the transaction or block limit.
        let limit = estimate.saturating_add(estimate.div_ceil(5)).min(cap);
        tx["gas"] = json!(format!("0x{limit:x}"));
        eprintln!(
            "transaction to={} gas_estimate={estimate} gas_limit={limit}",
            to.unwrap_or("contract-creation")
        );
        let hash = string(self.request("eth_sendTransaction", json!([tx])).await?)?;
        let receipt = self.receipt(&hash).await?;
        let used = quantity(&receipt["gasUsed"]).context("read transaction gas used")?;
        eprintln!("transaction={hash} gas_estimate={estimate} gas_limit={limit} gas_used={used}");
        Ok(receipt)
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

#[cfg(test)]
mod gas_tests {
    use super::*;
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::Mutex;

    #[tokio::test]
    async fn send_estimates_gas_before_submitting_and_stops_on_estimation_failure() {
        async fn reply(
            State(calls): State<Arc<Mutex<Vec<Value>>>>,
            Json(request): Json<Value>,
        ) -> Json<Value> {
            calls.lock().unwrap().push(request.clone());
            let result = match request["method"].as_str().unwrap() {
                "eth_getBlockByNumber" => json!({"gasLimit":"0x3938700"}),
                "eth_estimateGas" if request["params"][0]["data"] == "0xff" => {
                    return Json(json!({"jsonrpc":"2.0","id":request["id"],
                        "error":{"code":-32000,"message":"execution reverted"}}));
                }
                "eth_estimateGas" if request["params"][0]["data"] == "0xaa" => json!("0x1000000"),
                "eth_estimateGas" if request["params"][0]["data"] == "0xbb" => json!("0x1000001"),
                "eth_estimateGas" => json!("0x186a0"),
                "eth_call" => json!("0x"),
                "eth_sendTransaction" => json!("0x1234"),
                "eth_getTransactionReceipt" => json!({"status":"0x1","gasUsed":"0x13880"}),
                _ => panic!("unexpected RPC method"),
            };
            Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }
        let calls = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc = LocalRpc::owned(listener.local_addr().unwrap().port()).unwrap();
        let app = Router::new()
            .route("/", post(reply))
            .with_state(calls.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        rpc.send("0x01", Some("0x02"), "0x00").await.unwrap();
        {
            let requests = calls.lock().unwrap();
            let estimate = requests
                .iter()
                .position(|r| r["method"] == "eth_estimateGas")
                .expect("must estimate gas before sending");
            let send = requests
                .iter()
                .position(|r| r["method"] == "eth_sendTransaction")
                .unwrap();
            assert!(estimate < send);
            assert_eq!(requests[estimate]["params"][0]["gas"], "0x1000000");
            assert_eq!(requests[send]["params"][0]["gas"], "0x1d4c0");
            assert_eq!(requests[send]["params"][0]["to"], "0x02");
        }
        calls.lock().unwrap().clear();
        assert!(rpc.send("0x01", None, "0xff").await.is_err());
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "eth_sendTransaction"));
        calls.lock().unwrap().clear();
        rpc.send("0x01", None, "0xaa").await.unwrap();
        {
            let requests = calls.lock().unwrap();
            let sent = requests
                .iter()
                .find(|r| r["method"] == "eth_sendTransaction")
                .unwrap();
            assert_eq!(sent["params"][0]["gas"], "0x1000000");
            assert!(sent["params"][0].get("to").is_none());
        }
        calls.lock().unwrap().clear();
        let error = rpc.send("0x01", None, "0xbb").await.unwrap_err();
        assert!(error
            .to_string()
            .contains("exceeds local transaction gas limit"));
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "eth_sendTransaction"));
        calls.lock().unwrap().clear();
        rpc.call("0x02", "0x00").await.unwrap();
        assert_eq!(calls.lock().unwrap()[0]["params"][0]["gas"], "0x1000000");
        server.abort();
    }
}
