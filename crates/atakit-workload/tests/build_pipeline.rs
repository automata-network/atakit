use std::io::Read;

use atakit_core::NullReporter;
use atakit_workload::{build_workload, BuildOptions};
use flate2::read::GzDecoder;

/// Set up a minimal workload directory using `image = { file = "..." }` so the
/// build pipeline can run without Docker/Podman.
fn setup_workload_dir(tmp: &std::path::Path) -> std::path::PathBuf {
    let wl_dir = tmp.join("my-workload");
    std::fs::create_dir_all(wl_dir.join("config")).unwrap();

    // Fake image tar -- content doesn't matter, pipeline just copies it
    std::fs::write(wl_dir.join("app.tar"), b"fake-image-tar-content").unwrap();

    // Measured-data file
    std::fs::write(wl_dir.join("config/cert.pem"), b"fake-cert").unwrap();

    let config = r#"
format = 1

[workload]
name = "my-workload"
version = "v0.1.0"
base-image-mode = "blacklist"
image = { file = "./app.tar" }
ports = ["3000:3000"]
measured-data = ["./config/cert.pem"]

[workload.environment]
RUST_LOG = "info"
"#;
    std::fs::write(wl_dir.join("atakit-workload.toml"), config).unwrap();
    wl_dir
}

#[tokio::test]
async fn build_produces_valid_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let wl_dir = setup_workload_dir(tmp.path());
    let out_dir = tmp.path().join("output");
    std::fs::create_dir_all(&out_dir).unwrap();

    let result = build_workload(
        &BuildOptions {
            workload_dir: wl_dir,
            output_dir: Some(out_dir.clone()),
            engine: None,
        },
        &NullReporter,
    )
    .await
    .unwrap();

    assert_eq!(result.name, "my-workload");
    assert_eq!(result.version, "v0.1.0");
    assert_eq!(result.image_count, 1);
    assert_eq!(result.measured_file_count, 1);
    assert!(result.archive_path.exists());
    assert!(result.archive_path.to_string_lossy().ends_with(".atawl"));
    assert!(!result.archive_hash.is_empty());

    // Verify archive contents
    let file = std::fs::File::open(&result.archive_path).unwrap();
    let gz = GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    let mut entry_names: Vec<String> = archive
        .entries()
        .unwrap()
        .filter_map(|e| {
            let e = e.unwrap();
            Some(e.path().unwrap().to_string_lossy().into_owned())
        })
        .collect();
    entry_names.sort();

    assert!(
        entry_names.iter().any(|n| n.ends_with("manifest.toml")),
        "archive must contain manifest.toml, got: {entry_names:?}"
    );
    assert!(
        entry_names
            .iter()
            .any(|n| n.contains("images/") && n.ends_with(".tar")),
        "archive must contain image tar, got: {entry_names:?}"
    );
    assert!(
        entry_names
            .iter()
            .any(|n| n.contains("measured-data/") && n.ends_with("cert.pem")),
        "archive must contain measured-data, got: {entry_names:?}"
    );

    // Verify manifest.toml content
    let file = std::fs::File::open(&result.archive_path).unwrap();
    let gz = GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().to_string_lossy().ends_with("manifest.toml") {
            let mut content = String::new();
            entry.read_to_string(&mut content).unwrap();
            assert!(content.contains("name = \"my-workload\""));
            assert!(content.contains("version = \"v0.1.0\""));
            assert!(content.contains("RUST_LOG"));
            assert!(content.contains("[hashes]"));
            break;
        }
    }
}

#[tokio::test]
async fn build_defaults_output_to_workload_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let wl_dir = setup_workload_dir(tmp.path());

    let result = build_workload(
        &BuildOptions {
            workload_dir: wl_dir.clone(),
            output_dir: None,
            engine: None,
        },
        &NullReporter,
    )
    .await
    .unwrap();

    assert_eq!(result.archive_path.parent().unwrap(), wl_dir);
}

#[tokio::test]
async fn build_is_deterministic() {
    let tmp = tempfile::tempdir().unwrap();
    let wl_dir = setup_workload_dir(tmp.path());

    let out1 = tmp.path().join("out1");
    let out2 = tmp.path().join("out2");
    std::fs::create_dir_all(&out1).unwrap();
    std::fs::create_dir_all(&out2).unwrap();

    let r1 = build_workload(
        &BuildOptions {
            workload_dir: wl_dir.clone(),
            output_dir: Some(out1),
            engine: None,
        },
        &NullReporter,
    )
    .await
    .unwrap();

    let r2 = build_workload(
        &BuildOptions {
            workload_dir: wl_dir,
            output_dir: Some(out2),
            engine: None,
        },
        &NullReporter,
    )
    .await
    .unwrap();

    assert_eq!(r1.name, r2.name);
    assert_eq!(r1.version, r2.version);
    assert_eq!(r1.image_count, r2.image_count);
    assert_eq!(r1.measured_file_count, r2.measured_file_count);
    assert_eq!(
        r1.archive_hash, r2.archive_hash,
        "archive hashes must be identical for deterministic builds"
    );
}
