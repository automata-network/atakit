use atakit_emulator::lifecycle::shutdown;
use fs2::FileExt;
use std::fs;
fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)
}

#[tokio::test]
async fn stop_keeps_checkpoint_and_down_cleans_only_runtime_artifacts() {
    let root = tempdir().unwrap();
    let dir = root.path();
    for name in [
        "checkpoint.json",
        "checkpoint.previous.json",
        "launch.private.json",
        "endpoints.json",
        "emulator.log",
        "anvil.log",
        "compose.yaml",
        "checkpoint.tmp-123",
    ] {
        fs::write(dir.join(name), "test state").unwrap();
    }
    for name in ["data", "workloads", "bridges", "compose"] {
        fs::create_dir(dir.join(name)).unwrap();
        fs::write(dir.join(name).join("test"), "keep or remove").unwrap();
    }
    fs::write(dir.join("user-notes.txt"), "keep").unwrap();
    shutdown(dir, false, false).await.unwrap();
    assert!(dir.join("checkpoint.json").exists());
    shutdown(dir, true, false).await.unwrap();
    for name in [
        "checkpoint.json",
        "checkpoint.previous.json",
        "launch.private.json",
        "endpoints.json",
        "emulator.log",
        "anvil.log",
        "compose.yaml",
        "compose",
        "workloads",
        "bridges",
        "checkpoint.tmp-123",
    ] {
        assert!(!dir.join(name).exists(), "{name} survived down");
    }
    assert!(dir.join("data/test").exists());
    assert!(dir.join("user-notes.txt").exists());
    shutdown(dir, true, true).await.unwrap();
    assert!(!dir.join("data").exists());
    assert!(dir.join("user-notes.txt").exists());
    shutdown(dir, true, true).await.unwrap();
}

#[tokio::test]
async fn down_does_not_clean_an_unreachable_running_environment() {
    let root = tempdir().unwrap();
    let dir = root.path();
    let lock = fs::File::create(dir.join("runtime.lock")).unwrap();
    lock.lock_exclusive().unwrap();
    fs::write(dir.join("checkpoint.json"), "keep").unwrap();
    assert!(shutdown(dir, true, false).await.is_err());
    assert!(dir.join("checkpoint.json").exists());
}

#[tokio::test]
async fn down_refuses_unrecognized_directories_and_does_not_follow_symlinks() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("workloads")).unwrap();
    assert!(shutdown(root.path(), true, false).await.is_err());
    assert!(root.path().join("workloads").exists());
    fs::write(root.path().join("checkpoint.json"), "state").unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("keep"), "keep").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("data")).unwrap();
    shutdown(root.path(), true, true).await.unwrap();
    assert!(outside.path().join("keep").exists());
}

#[tokio::test]
async fn down_on_absent_runtime_does_not_create_it() {
    let root = tempdir().unwrap();
    let dir = root.path().join("missing");
    shutdown(&dir, true, false).await.unwrap();
    assert!(!dir.exists());
}

#[tokio::test]
async fn lifecycle_waits_for_daemon_lock_release_before_returning_or_cleaning() {
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixListener,
    };
    for clean in [false, true] {
        let root = tempdir().unwrap();
        let dir = root.path();
        let lock = fs::File::create(dir.join("runtime.lock")).unwrap();
        lock.lock_exclusive().unwrap();
        fs::write(dir.join("checkpoint.json"), "before shutdown").unwrap();
        let endpoint = serde_json::json!({"environment_id":"test", "upstream_rpc_url":"http://localhost:8545",
            "anchor_number":1,"anchor_hash":"0x00","rpc_url":"http://localhost:8546","chain_id":1,
            "session_registry":"0x1","workload_registry":"0x2","base_image_registry":"0x3","state":"ready","workloads":{}});
        fs::write(
            dir.join("endpoints.json"),
            serde_json::to_vec(&endpoint).unwrap(),
        )
        .unwrap();
        let listener = UnixListener::bind(dir.join("control.sock")).unwrap();
        let checkpoint = dir.join("checkpoint.json");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["operation"], if clean { "down" } else { "stop" });
            reader
                .get_mut()
                .write_all(b"{\"state\":\"stopping\"}\n")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(checkpoint.exists(), "cleanup raced ahead of daemon exit");
            fs::write(checkpoint, "saved on exit").unwrap();
            drop(lock);
        });
        shutdown(dir, clean, false).await.unwrap();
        server.await.unwrap();
        if clean {
            assert!(!dir.join("checkpoint.json").exists());
        } else {
            assert_eq!(
                fs::read_to_string(dir.join("checkpoint.json")).unwrap(),
                "saved on exit"
            );
        }
    }
}

#[tokio::test]
async fn down_removes_recorded_workload_roots_without_following_data_links() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    fs::write(dir.join("checkpoint.json"), "{}").unwrap();
    fs::write(dir.join("workload-dirs.private.json"), r#"["signer"]"#).unwrap();
    fs::create_dir_all(dir.join("signer/root/run")).unwrap();
    fs::create_dir_all(dir.join("data/signer/disk")).unwrap();
    fs::write(dir.join("data/signer/disk/keep"), "persist").unwrap();
    std::os::unix::fs::symlink(dir.join("data/signer/disk"), dir.join("signer/root/data")).unwrap();
    fs::create_dir_all(dir.join("unrelated")).unwrap();
    shutdown(dir, false, false).await.unwrap();
    assert!(dir.join("signer/root").exists());
    shutdown(dir, true, false).await.unwrap();
    assert!(!dir.join("signer").exists());
    assert!(!dir.join("workload-dirs.private.json").exists());
    assert!(dir.join("data/signer/disk/keep").exists());
    assert!(dir.join("unrelated").exists());
}

#[tokio::test]
async fn cleanup_rejects_reserved_names_in_workload_directory_manifest() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    fs::write(dir.join("checkpoint.json"), "{}").unwrap();
    fs::write(dir.join("workload-dirs.private.json"), r#"["data"]"#).unwrap();
    fs::create_dir(dir.join("data")).unwrap();
    assert!(shutdown(dir, true, false).await.is_err());
    assert!(dir.join("data").exists());
}
