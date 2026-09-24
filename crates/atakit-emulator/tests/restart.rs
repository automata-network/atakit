use atakit_emulator::runtime::{private_dir, write_private};
use std::os::unix::fs::PermissionsExt;
#[test]
fn checkpoint_replacement_is_atomic_and_private() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().canonicalize().unwrap().join("runtime");
    private_dir(&dir).unwrap();
    let path = dir.join("checkpoint.json");
    write_private(&path, &serde_json::json!({"branch":"old","keys":[1,2,3]})).unwrap();
    write_private(&path, &serde_json::json!({"branch":"new","keys":[4,5,6]})).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(value["branch"], "new");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
