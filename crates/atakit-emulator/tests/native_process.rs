use atakit_emulator::runtime::{private_dir, OwnedSocket};
#[tokio::test]
async fn socket_ownership_never_removes_a_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("portal.sock");
    let owned = OwnedSocket::bind(&path).unwrap();
    assert!(OwnedSocket::bind(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, "replacement").unwrap();
    drop(owned);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
}
#[test]
fn private_directory_rejects_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(dir.path(), dir.path().join("link")).unwrap();
    assert!(private_dir(&dir.path().join("link/runtime")).is_err());
}
#[tokio::test]
async fn socket_rejects_regular_file_without_altering_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("portal.sock");
    std::fs::write(&path, "user data").unwrap();
    assert!(OwnedSocket::bind(&path).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "user data");
}
#[test]
fn exported_url_has_no_credentials_or_tokens() {
    assert_eq!(
        atakit_emulator::endpoints::redact_url(
            "http://user:password@localhost:8545/?token=secret#secret"
        ),
        "http://localhost:8545/"
    );
}

#[tokio::test]
async fn recovery_removes_only_a_recorded_dead_socket() {
    use atakit_emulator::runtime::recover_stale_socket;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("owned.sock");
    let mut owned = OwnedSocket::bind(&path).unwrap();
    let record = owned.ownership();
    assert!(!recover_stale_socket(&record).unwrap());
    drop(owned.listener.take());
    std::mem::forget(owned); // Simulate process death without the ownership destructor.
    assert!(recover_stale_socket(&record).unwrap());
    assert!(!path.exists());
}
#[tokio::test]
async fn recovery_preserves_replacement_and_unknown_sockets() {
    use atakit_emulator::runtime::recover_stale_socket;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let path = root.join("owned.sock");
    let owned = OwnedSocket::bind(&path).unwrap();
    let record = owned.ownership();
    std::fs::remove_file(&path).unwrap();
    let replacement = OwnedSocket::bind(&path).unwrap();
    assert!(!recover_stale_socket(&record).unwrap());
    assert!(path.exists());
    let unknown = OwnedSocket::bind(&root.join("unknown.sock")).unwrap();
    assert!(!recover_stale_socket(&record).unwrap());
    assert!(root.join("unknown.sock").exists());
    drop((owned, replacement, unknown));
}
