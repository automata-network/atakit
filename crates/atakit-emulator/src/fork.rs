//! Process ownership and snapshot boundary for the emulator's secondary Anvil.
use crate::rpc::{quantity, string, LocalRpc, ReadRpc};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs::OpenOptions, net::TcpListener, os::unix::fs::OpenOptionsExt, path::PathBuf, process::Stdio,
    time::Duration,
};
use tokio::process::{Child, Command};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForkSnapshot {
    pub upstream_url: String,
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: String,
    pub upstream_instance_id: String,
}
#[derive(Clone, Debug)]
pub struct ForkOptions {
    pub upstream_url: String,
    pub block_number: Option<u64>,
    pub port: u16,
    pub hardfork: String,
    pub log_path: PathBuf,
    /// Opaque anvil_dumpState output from a matching emulator checkpoint.
    pub load_state: Option<String>,
}
pub struct AnvilFork {
    pub rpc: LocalRpc,
    pub snapshot: ForkSnapshot,
    child: Child,
}
impl AnvilFork {
    pub async fn spawn(options: ForkOptions) -> Result<Self> {
        let port_guard = TcpListener::bind(("127.0.0.1", options.port))
            .context("internal Anvil port unavailable")?;
        let upstream = ReadRpc::new(&options.upstream_url)?;
        let version = string(upstream.request("web3_clientVersion", json!([])).await.with_context(|| format!(
            "cannot connect to upstream Anvil at {}; start your development Anvil first, or set --fork-url to its RPC endpoint",
            crate::endpoints::redact_url(&options.upstream_url)
        ))?)?;
        if !version.to_lowercase().contains("anvil") {
            bail!("fork source must be the user's development Anvil; got a different client");
        }
        let chain_id = upstream.chain_id().await?;
        let block_tag = options
            .block_number
            .map(|n| format!("0x{n:x}"))
            .unwrap_or_else(|| "latest".into());
        let block = upstream
            .request("eth_getBlockByNumber", json!([block_tag, false]))
            .await?;
        let snapshot = ForkSnapshot {
            upstream_url: options.upstream_url.clone(),
            chain_id,
            block_number: quantity(&block["number"])
                .context("upstream snapshot block unavailable")?,
            block_hash: string(block["hash"].clone())
                .context("upstream snapshot hash unavailable")?,
            upstream_instance_id: string(
                upstream.request("anvil_metadata", json!([])).await?["instanceId"].clone(),
            )
            .context("Anvil instance identity unavailable; update Anvil")?,
        };
        if let Some(parent) = options.log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&options.log_path)?;
        let mut cmd = Command::new("anvil");
        cmd.args([
            "--host",
            "127.0.0.1",
            "--port",
            &options.port.to_string(),
            "--fork-url",
            &options.upstream_url,
            "--fork-block-number",
            &snapshot.block_number.to_string(),
            "--chain-id",
            &chain_id.to_string(),
            "--hardfork",
            &options.hardfork,
            "--preserve-historical-states",
            "--no-rate-limit",
            "--quiet",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .kill_on_drop(true);
        drop(port_guard);
        let mut child = cmd
            .spawn()
            .context("start internal Anvil (install Foundry's anvil)")?;
        let rpc = LocalRpc::owned(options.port)?;
        let ready = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(status) = child.try_wait()? {
                    bail!(
                        "internal Anvil exited {status}; see {}",
                        options.log_path.display()
                    );
                }
                if rpc.reads().chain_id().await.ok() == Some(chain_id) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("internal Anvil startup timed out")?;
        ready?;
        if let Some(state) = options.load_state {
            if rpc.request("anvil_loadState", json!([state])).await? != true {
                bail!("internal Anvil rejected checkpoint state");
            }
        }
        let fork = Self {
            rpc,
            snapshot,
            child,
        };
        fork.check_upstream().await?;
        Ok(fork)
    }
    pub fn is_running(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }
    pub async fn dump(&self) -> Result<String> {
        string(self.rpc.request("anvil_dumpState", json!([])).await?)
    }
    pub async fn stop(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.start_kill()?;
        }
        self.child.wait().await?;
        Ok(())
    }
    pub async fn check_upstream(&self) -> Result<()> {
        let upstream = ReadRpc::new(&self.snapshot.upstream_url)?;
        let block = upstream
            .request(
                "eth_getBlockByNumber",
                json!([format!("0x{:x}", self.snapshot.block_number), false]),
            )
            .await
            .context("UpstreamSnapshotUnavailable: cannot read fork anchor")?;
        let identity = upstream.request("anvil_metadata", json!([])).await?;
        if identity["instanceId"].as_str() != Some(&self.snapshot.upstream_instance_id)
            || block["hash"].as_str() != Some(&self.snapshot.block_hash)
            || upstream.chain_id().await? != self.snapshot.chain_id
        {
            bail!("UpstreamSnapshotUnavailable: upstream fork anchor or chain ID changed");
        }
        Ok(())
    }
}
