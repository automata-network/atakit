use std::process::Command;

fn inspect(metadata: Option<&str>, json: bool) -> std::process::Output {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("config.toml"), "").unwrap();
    let image = root.path().join("data/images/example/v1");
    if let Some(metadata) = metadata {
        std::fs::create_dir_all(image.join("disk_images")).unwrap();
        std::fs::write(image.join("baseimage.toml"), metadata).unwrap();
        std::fs::write(image.join("disk_images/gcp_disk.tar.gz"), b"fixture").unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_atakit"));
    command
        .args(["image", "inspect", "example:v1"])
        .env("ATAKIT_CONFIG_DIR", config)
        .env("ATAKIT_DATA_DIR", root.path().join("data"))
        .env("ATAKIT_CACHE_DIR", root.path().join("cache"));
    if json {
        command.arg("--json");
    }
    command.output().unwrap()
}

#[test]
fn inspect_returns_publisher_qualified_identity_and_local_platforms() {
    let metadata = "[meta]\nformat=2\nbase-image-ref='0xaef8fc89416f01494ec6534de68d30aab26d7598db8a05967b0ba7d3ecb259d2/automata-linux:v0.2.8-debug'\n";
    let output = inspect(Some(metadata), true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json["publisher_fingerprint"],
        "0xaef8fc89416f01494ec6534de68d30aab26d7598db8a05967b0ba7d3ecb259d2"
    );
    assert_eq!(
        json["base_image_id"],
        "0xc885d7a0420ea15dd59fe99ba5fcb6c66b62f51ac808fd8bfc040e033bff6d53"
    );
    assert_eq!(json["name"], "automata-linux");
    assert_eq!(json["local_platforms"], serde_json::json!(["gcp"]));
    let text = inspect(Some(metadata), false);
    assert!(text.status.success());
    assert!(String::from_utf8_lossy(&text.stdout).contains("Publisher"));
}

#[test]
fn inspect_reports_missing_or_invalid_metadata_without_inventing_identity() {
    for metadata in [
        None,
        Some("[meta]\nformat=2\n"),
        Some("[meta]\nbase-image-ref='example:v1'\n"),
        Some("[broken"),
    ] {
        let output = inspect(metadata, true);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("baseimage.toml"));
        assert!(output.stdout.is_empty());
    }
}
