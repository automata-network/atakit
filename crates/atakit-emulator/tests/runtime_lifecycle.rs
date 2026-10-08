use alloy_primitives::B256;
use anyhow::{Context, Result};
use atakit_attestation::signing;
use atakit_emulator::{
    config::{LaunchConfig, ResolvedWorkload},
    fork::{AnvilFork, ForkOptions},
    runtime::{self, PreparedLaunch},
};
use automata_tee_workload_measurement::stubs::AlgoId;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, time::Duration};
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
async fn ready(dir: &Path) -> Result<Value> {
    for _ in 0..200 {
        if let Ok(e) = runtime::control(dir, "status", None).await {
            if e["state"] == "ready" {
                return Ok(e);
            }
            if e["state"] == "degraded" {
                anyhow::bail!("{e}");
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("runtime readiness timeout")
}
async fn setup(root: &Path) -> Result<(AnvilFork, PreparedLaunch)> {
    let fixture: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("EMULATOR_FIXTURE_JSON")?)?)?;
    let a = AnvilFork::spawn(ForkOptions {
        hardfork: "osaka".into(),
        upstream_url: std::env::var("EMULATOR_FIXTURE_RPC")?,
        block_number: None,
        port: port(),
        log_path: root.join("a.log"),
        load_state: None,
    })
    .await?;
    let owner = signing::decode_secret_key_hex(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;
    let fp = B256::from(atakit_cvm_encoding::key_fingerprint(
        AlgoId::Es256K as u8,
        &signing::derive_public_key_uncompressed(&owner)?,
    ));
    let mut workloads = vec![];
    for name in ["first", "second"] {
        let dir = root.join(name);
        std::fs::create_dir_all(dir.join("measured-data"))?;
        std::fs::write(dir.join("measured-data/input"), "v1")?;
        let file = dir.join("atakit-workload.toml");
        std::fs::write(&file,format!("format=7\n[package]\nmeasured-data=['/input']\n[workload]\nname='runtime-e2e'\nversion='1'\nbase-image-mode='whitelist'\nbase-image=['{fp}/emulator-gcp-tdx:1']\nimage='example:test'\natakit-portal=true\n"))?;
        workloads.push(ResolvedWorkload {
            name: name.into(),
            config_file: file,
            workload_dir: dir.clone(),
            output_socket: dir.join("portal.sock"),
            owner_key: None,
            platform_profile: None,
            measurement_variant: None,
        });
    }
    let upstream_url = a.rpc.reads_url();
    Ok((
        a,
        PreparedLaunch {
            launch: LaunchConfig {
                hardfork: "osaka".into(),
                target: None,
                chain: Some("fixture".into()),
                fork_url: upstream_url,
                fork_block: None,
                anvil_port: port(),
                runtime_dir: root.join("runtime"),
                foreground: true,
                owner_key: None,
                workloads,
            },
            session_registry: fixture["sessionRegistry"]
                .as_str()
                .context("fixture registry")?
                .into(),
            workload_registry: None,
            base_image_registry: None,
            publisher_secret: owner,
            owners: BTreeMap::from([("first".into(), owner), ("second".into(), owner)]),
        },
    ))
}
#[tokio::test]
#[ignore = "requires EMULATOR_FIXTURE_JSON and EMULATOR_FIXTURE_RPC local real-contract fixture"]
async fn restart_preserves_sessions_branch_and_omitted_instance_metadata() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().canonicalize()?;
    let (mut a, p) = setup(&root).await?;
    let dir = p.launch.runtime_dir.clone();
    let launch = p.clone();
    let task = tokio::spawn(runtime::run_foreground(launch));
    let first = ready(&dir).await?;
    let sid = first["workloads"]["first"]["session_id"].clone();
    let client = reqwest::Client::new();
    let marker = "0x000000000000000000000000000000000000a001";
    let reply:Value=client.post(first["rpc_url"].as_str().unwrap()).json(&json!({"jsonrpc":"2.0","id":1,"method":"anvil_setBalance","params":[marker,"0x12345"]})).send().await?.json().await?;
    assert!(reply.get("error").is_none());
    runtime::control(&dir, "stop", None).await?;
    task.await??;
    let mut changed_selection = p.clone();
    changed_selection.launch.workloads[0].platform_profile = Some("gcp-tdx".into());
    let error = runtime::run_foreground(changed_selection)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("Cannot resume emulator checkpoint"));
    let mut one = p.clone();
    one.launch.workloads.retain(|w| w.name == "first");
    one.owners.remove("second");
    let task = tokio::spawn(runtime::run_foreground(one));
    let resumed = ready(&dir).await?;
    assert_eq!(resumed["workloads"]["first"]["session_id"], sid);
    let balance: Value = client
        .post(resumed["rpc_url"].as_str().unwrap())
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":[marker,"latest"]}))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(balance["result"], "0x12345");
    assert_eq!(
        a.rpc
            .request("eth_getBalance", json!([marker, "latest"]))
            .await?,
        "0x0"
    );
    runtime::control(&dir, "stop", None).await?;
    task.await??;
    std::fs::write(root.join("second/measured-data/input"), "changed")?;
    let error = runtime::run_foreground(p).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Cannot resume emulator checkpoint"),
        "{error:#}"
    );
    a.stop().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires EMULATOR_FIXTURE_JSON and EMULATOR_FIXTURE_RPC local real-contract fixture"]
async fn failed_refresh_preserves_the_last_consistent_checkpoint() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().canonicalize()?;
    let (mut a, p) = setup(&root).await?;
    let dir = p.launch.runtime_dir.clone();
    let registry = p.session_registry.clone();
    let task = tokio::spawn(runtime::run_foreground(p));
    ready(&dir).await?;
    let old: Value = serde_json::from_slice(&std::fs::read(dir.join("checkpoint.json"))?)?;
    a.rpc
        .request("anvil_setCode", json!([registry, "0x"]))
        .await?;
    a.rpc.request("evm_mine", json!([])).await?;
    assert!(runtime::control(&dir, "refresh", None).await.is_err());
    assert_eq!(
        runtime::control(&dir, "status", None).await?["state"],
        "refresh_failed"
    );
    assert!(runtime::control(&dir, "rotate", Some("first"))
        .await
        .is_err());
    runtime::control(&dir, "stop", None).await?;
    task.await??;
    let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("checkpoint.json"))?)?;
    assert_eq!(old["snapshot"], saved["snapshot"]);
    assert_eq!(old["sessions"], saved["sessions"]);
    a.stop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires EMULATOR_FIXTURE_JSON and EMULATOR_FIXTURE_RPC local real-contract fixture"]
async fn upstream_reset_cannot_be_bypassed_by_session_rotation() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().canonicalize()?;
    let (mut a, p) = setup(&root).await?;
    let dir = p.launch.runtime_dir.clone();
    let socket = p.launch.workloads[0].output_socket.clone();
    let task = tokio::spawn(runtime::run_foreground(p));
    let before = ready(&dir).await?;
    a.rpc
        .request(
            "anvil_reset",
            json!([{"forking": {
                "jsonRpcUrl": std::env::var("EMULATOR_FIXTURE_RPC")?,
                "blockNumber": a.snapshot.block_number,
            }}]),
        )
        .await?;
    // Attempt immediately, so the control path must validate even before the monitor ticks.
    let result = runtime::control(&dir, "rotate", Some("first")).await;
    let after = runtime::control(&dir, "status", None).await?;
    let portal = reqwest::Client::builder().unix_socket(socket).build()?;
    let response = portal
        .post("http://localhost/sign-message")
        .json(&json!({"message":"0x68656c6c6f", "hash_fn":"sha256"}))
        .send()
        .await?;
    runtime::control(&dir, "stop", None).await?;
    task.await??;
    a.stop().await?;
    assert!(
        result.is_err(),
        "rotation must reject an invalid upstream snapshot"
    );
    assert_eq!(after["state"], "upstream_unavailable");
    assert_eq!(
        after["workloads"]["first"]["session_id"],
        before["workloads"]["first"]["session_id"]
    );
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}
