use anyhow::{Context, Result};
use atakit_emulator::{fork, rpc};
use fork::{AnvilFork, ForkOptions};
use serde_json::{json, Value};
use std::{net::TcpListener, process::Stdio, time::Duration};
use tokio::process::{Child, Command};

fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
async fn raw(url: &str, method: &str, params: Value) -> Result<Value> {
    let v: Value = reqwest::Client::new()
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await?
        .json()
        .await?;
    anyhow::ensure!(v.get("error").is_none(), "{v}");
    Ok(v["result"].clone())
}
async fn upstream() -> Result<(Child, String)> {
    let port = port();
    let child = Command::new("anvil")
        .args([
            "--port",
            &port.to_string(),
            "--host",
            "127.0.0.1",
            "--chain-id",
            "31337",
            "--preserve-historical-states",
            "--quiet",
        ])
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start test Anvil; install Foundry and ensure anvil is on PATH")?;
    let url = format!("http://127.0.0.1:{port}");
    for _ in 0..100 {
        if raw(&url, "eth_chainId", json!([])).await.is_ok() {
            return Ok((child, url));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("fixture Anvil failed to start")
}
const ACCOUNT: &str = "0x000000000000000000000000000000000000a123";
const SLOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
fn word(n: u64) -> String {
    format!("0x{n:064x}")
}

#[tokio::test]
async fn upstream_handle_rejects_writes_before_sending() -> Result<()> {
    let reader = rpc::ReadRpc::new("http://127.0.0.1:1")?;
    let err = reader
        .request("anvil_setCode", json!([ACCOUNT, "0x00"]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not read-only"));
    Ok(())
}

#[tokio::test]
async fn nested_fork_executes_inherited_code_and_keeps_upstream_unchanged() -> Result<()> {
    let (_a, url) = upstream().await?;
    raw(
        &url,
        "anvil_setCode",
        json!([ACCOUNT, "0x60005460005260206000f3"]),
    )
    .await?;
    raw(&url, "anvil_setStorageAt", json!([ACCOUNT, SLOT, word(7)])).await?;
    raw(&url, "evm_mine", json!([])).await?;
    let temp = tempfile::tempdir()?;
    let mut b = AnvilFork::spawn(ForkOptions {
        hardfork: "osaka".into(),
        upstream_url: url.clone(),
        block_number: None,
        port: port(),
        log_path: temp.path().join("anvil.log"),
        load_state: None,
    })
    .await?;
    assert_eq!(b.snapshot.chain_id, 31337);
    assert_eq!(b.rpc.call(ACCOUNT, "0x").await?, word(7));
    b.rpc
        .request("anvil_setStorageAt", json!([ACCOUNT, SLOT, word(9)]))
        .await?;
    assert_eq!(b.rpc.call(ACCOUNT, "0x").await?, word(9));
    assert_eq!(
        raw(
            &url,
            "eth_call",
            json!([{"to":ACCOUNT,"data":"0x"},"latest"])
        )
        .await?,
        word(7)
    );
    b.check_upstream().await?;
    b.stop().await?;
    assert_eq!(raw(&url, "eth_chainId", json!([])).await?, "0x7a69");
    Ok(())
}

#[tokio::test]
async fn fork_keeps_its_anchor_after_upstream_transactions_and_restores_local_state() -> Result<()>
{
    let (_a, url) = upstream().await?;
    raw(
        &url,
        "anvil_setCode",
        json!([
            ACCOUNT,
            "0x3615600c57600035600055005b60005460005260206000f3"
        ]),
    )
    .await?;
    raw(&url, "anvil_setStorageAt", json!([ACCOUNT, SLOT, word(7)])).await?;
    raw(&url, "evm_mine", json!([])).await?;
    let temp = tempfile::tempdir()?;
    let mut b = AnvilFork::spawn(ForkOptions {
        hardfork: "osaka".into(),
        upstream_url: url.clone(),
        block_number: None,
        port: port(),
        log_path: temp.path().join("b.log"),
        load_state: None,
    })
    .await?;
    let accounts = raw(&url, "eth_accounts", json!([])).await?;
    let tx = raw(
        &url,
        "eth_sendTransaction",
        json!([{"from":accounts[0],"to":ACCOUNT,"data":word(12),"gas":"0x186a0"}]),
    )
    .await?;
    for _ in 0..100 {
        let receipt = raw(&url, "eth_getTransactionReceipt", json!([tx])).await?;
        if !receipt.is_null() {
            assert_eq!(receipt["status"], "0x1");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        raw(
            &url,
            "eth_call",
            json!([{"to":ACCOUNT,"data":"0x"},"latest"])
        )
        .await?,
        word(12)
    );
    // This is the first B read of this slot, so the test exercises lazy historical fetching.
    assert_eq!(b.rpc.call(ACCOUNT, "0x").await?, word(7));
    b.rpc
        .send(accounts[0].as_str().unwrap(), Some(ACCOUNT), &word(9))
        .await?;
    let saved = b.dump().await?;
    let anchor = b.snapshot.block_number;
    b.stop().await?;
    let mut restored = AnvilFork::spawn(ForkOptions {
        hardfork: "osaka".into(),
        upstream_url: url.clone(),
        block_number: Some(anchor),
        port: port(),
        log_path: temp.path().join("restored.log"),
        load_state: Some(saved),
    })
    .await?;
    assert_eq!(restored.rpc.call(ACCOUNT, "0x").await?, word(9));
    assert_eq!(
        raw(
            &url,
            "eth_call",
            json!([{"to":ACCOUNT,"data":"0x"},"latest"])
        )
        .await?,
        word(12)
    );
    restored.stop().await?;
    Ok(())
}

#[tokio::test]
async fn occupied_port_is_not_adopted_or_modified() -> Result<()> {
    let (_a, url) = upstream().await?;
    let occupied = TcpListener::bind("127.0.0.1:0")?;
    let temp = tempfile::tempdir()?;
    let result = AnvilFork::spawn(ForkOptions {
        hardfork: "osaka".into(),
        upstream_url: url,
        block_number: None,
        port: occupied.local_addr()?.port(),
        log_path: temp.path().join("b.log"),
        load_state: None,
    })
    .await;
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("port unavailable"));
    Ok(())
}

#[tokio::test]
async fn upstream_reset_invalidates_the_recorded_snapshot() -> Result<()> {
    let (_a, url) = upstream().await?;
    raw(&url, "evm_mine", json!([])).await?;
    let temp = tempfile::tempdir()?;
    let mut b = AnvilFork::spawn(ForkOptions {
        hardfork: "osaka".into(),
        upstream_url: url.clone(),
        block_number: None,
        port: port(),
        log_path: temp.path().join("b.log"),
        load_state: None,
    })
    .await?;
    raw(&url, "anvil_reset", json!([])).await?;
    assert!(b
        .check_upstream()
        .await
        .unwrap_err()
        .to_string()
        .contains("UpstreamSnapshotUnavailable"));
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn reset_at_the_same_block_hash_is_detected_by_instance_id() -> Result<()> {
    let (_a, url) = upstream().await?;
    raw(
        &url,
        "anvil_setCode",
        json!([ACCOUNT, "0x60005460005260206000f3"]),
    )
    .await?;
    let temp = tempfile::tempdir()?;
    let mut b = AnvilFork::spawn(ForkOptions {
        hardfork: "osaka".into(),
        upstream_url: url.clone(),
        block_number: None,
        port: port(),
        log_path: temp.path().join("b.log"),
        load_state: None,
    })
    .await?;
    let hash = b.snapshot.block_hash.clone();
    raw(&url, "anvil_reset", json!([])).await?;
    assert_eq!(
        raw(&url, "eth_getBlockByNumber", json!(["latest", false])).await?["hash"],
        hash
    );
    assert!(b.check_upstream().await.is_err());
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn owned_fork_supports_real_p256_precompile_without_patching_signature_verifiers(
) -> Result<()> {
    let (_a, url) = upstream().await?;
    let temp = tempfile::tempdir()?;
    let mut b = AnvilFork::spawn(ForkOptions {
        hardfork: "osaka".into(),
        upstream_url: url.clone(),
        block_number: None,
        port: port(),
        log_path: temp.path().join("p256.log"),
        load_state: None,
    })
    .await?;
    // Public vector from the contract repository's script/utils/P256Config.sol.
    use sha2::{Digest, Sha256};
    let message = hex::decode("a9b4ac5fb82203536c408b1db1d0338c61fd0064ea2471794d435fc0e03c217f")?;
    let signature = "8c6a3bb0346ec08d01b6351eeff099fd7131de48e5e569dbcd9dc3f29e08995692db2eaebd633a52fff4915d274859bbc241967c6ce3a6831e754b88066fc534";
    let key = "710f9d7cb59f86798aaf92138320831b778016d02cf0f5b416a76917f85edd4d7440615935921eaaa33c66c6cf4b745e70176a391610ab14f845d7ff39b112a3";
    let data = format!(
        "0x{}{signature}{key}",
        hex::encode(Sha256::digest(&message))
    );
    let address = "0x0000000000000000000000000000000000000100";
    let valid = b.rpc.call(address, &data).await?;
    let invalid = b
        .rpc
        .call(address, &format!("0x{}{signature}{key}", "00".repeat(32)))
        .await?;
    b.stop().await?;
    assert_eq!(valid, word(1));
    assert_ne!(invalid, word(1));
    let mut older = AnvilFork::spawn(ForkOptions {
        hardfork: "prague".into(),
        upstream_url: url,
        block_number: None,
        port: port(),
        log_path: temp.path().join("prague.log"),
        load_state: None,
    })
    .await?;
    assert_eq!(older.rpc.call(address, &data).await?, "0x");
    older.stop().await?;

    Ok(())
}

#[tokio::test]
async fn embedded_dcap_mock_supports_v1_and_v2_quote_commitments() -> Result<()> {
    use alloy_sol_types::{sol, SolCall};
    sol! {
        function verifyAndAttestOnChainV2(bytes quote, uint32 tcb, bool minCheck)
            external returns (bool success, bytes output, bytes body);
        function verifyAndAttestOnChain(bytes quote) external returns (bool success, bytes output);
    }
    let (_upstream, url) = upstream().await?;
    raw(
        &url,
        "anvil_setCode",
        json!([
            ACCOUNT,
            format!(
                "0x{}",
                include_str!("../assets/EmulatorDcapAttestation.runtime.hex").trim()
            )
        ]),
    )
    .await?;
    let reader = rpc::ReadRpc::new(&url)?;
    let mut quote = vec![0u8; 636];
    quote[0] = 4;
    quote[4] = 0x81;
    for min_check in [false, true] {
        let call = verifyAndAttestOnChainV2Call {
            quote: quote.clone().into(),
            tcb: 0,
            minCheck: min_check,
        };
        let output = reader
            .call(ACCOUNT, &format!("0x{}", hex::encode(call.abi_encode())))
            .await?;
        let result = verifyAndAttestOnChainV2Call::abi_decode_returns(&hex::decode(&output[2..])?)?;
        assert!(result.success);
        assert_eq!(result.output.len(), 317);
        assert_eq!(&result.output[..5], &[0, 2, 0, 1, 6]);
        assert_eq!(&result.body[..], &quote[48..632]);
        assert_eq!(
            &result.output[253..285],
            alloy_primitives::keccak256(&quote).as_slice()
        );
        assert_eq!(
            &result.output[285..317],
            alloy_primitives::keccak256(&result.body).as_slice()
        );
    }
    let legacy = verifyAndAttestOnChainCall {
        quote: quote.clone().into(),
    };
    let output = reader
        .call(ACCOUNT, &format!("0x{}", hex::encode(legacy.abi_encode())))
        .await?;
    let result = verifyAndAttestOnChainCall::abi_decode_returns(&hex::decode(&output[2..])?)?;
    assert!(result.success);
    assert_eq!(&result.output[11..], &quote[48..632]);
    quote.push(0);
    let malformed = verifyAndAttestOnChainV2Call {
        quote: quote.into(),
        tcb: 0,
        minCheck: true,
    };
    assert!(reader
        .call(
            ACCOUNT,
            &format!("0x{}", hex::encode(malformed.abi_encode()))
        )
        .await
        .is_err());
    Ok(())
}
