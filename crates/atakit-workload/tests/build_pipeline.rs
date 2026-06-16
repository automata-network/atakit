use std::io::Read;

use atakit_core::{ArchiveCompression, NullReporter};
use atakit_workload::{build_workload, inspect_workload, BuildOptions, InspectOptions};
use sha2::{Digest, Sha256};

/// Build a minimal but valid docker-archive tar containing a single image
/// with a config blob made unique by `marker`. Returns the tar bytes.
///
/// The build pipeline now extracts the image config digest ("image ID")
/// from each staged image tar; stub byte fixtures no longer parse, so
/// tests must produce real tar streams.
fn make_docker_archive_tar(marker: &str) -> Vec<u8> {
    let config_blob = format!(
        r#"{{"architecture":"amd64","os":"linux","config":{{}},"rootfs":{{"type":"layers","diff_ids":[]}},"_marker":"{marker}"}}"#
    );
    let digest = format!("{:x}", Sha256::digest(config_blob.as_bytes()));
    let manifest = format!(
        r#"[{{"Config":"blobs/sha256/{digest}","RepoTags":["{marker}:latest"],"Layers":[]}}]"#
    );

    let mut buf = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut buf);
        let mut h = tar::Header::new_gnu();
        h.set_size(manifest.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, "manifest.json", manifest.as_bytes())
            .unwrap();

        let mut h = tar::Header::new_gnu();
        h.set_size(config_blob.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(
            &mut h,
            format!("blobs/sha256/{digest}"),
            config_blob.as_bytes(),
        )
        .unwrap();
        tar.finish().unwrap();
    }
    buf
}

/// Set up a minimal workload directory using `image = { file = "..." }` so the
/// build pipeline can run without Docker/Podman.
fn setup_workload_dir(tmp: &std::path::Path) -> std::path::PathBuf {
    let wl_dir = tmp.join("my-workload");
    std::fs::create_dir_all(wl_dir.join("config")).unwrap();

    // Real (minimal) docker-archive tar so the build pipeline can extract
    // the image config digest. Content is otherwise unused.
    std::fs::write(
        wl_dir.join("app.tar"),
        make_docker_archive_tar("my-workload"),
    )
    .unwrap();

    // Measured-data file
    std::fs::write(wl_dir.join("config/cert.pem"), b"fake-cert").unwrap();

    let config = r#"
format = 2

[package]
measured-data = ["./config/cert.pem"]

[workload]
name = "my-workload"
version = "v0.1.0"
base-image-mode = "blacklist"
image = { file = "./app.tar" }
ports = ["3000:3000"]
measured-data = true

[workload.environment]
RUST_LOG = "info"
"#;
    std::fs::write(wl_dir.join("atakit-workload.toml"), config).unwrap();
    wl_dir
}

fn setup_baby_container_workload_dir(tmp: &std::path::Path) -> std::path::PathBuf {
    let wl_dir = tmp.join("baby-workload");
    std::fs::create_dir_all(&wl_dir).unwrap();
    std::fs::write(
        wl_dir.join("app.tar"),
        make_docker_archive_tar("baby-workload"),
    )
    .unwrap();

    let config = r#"
format = 2

[workload]
name = "baby-workload"
version = "v0.1.0"
base-image-mode = "blacklist"
image = { file = "./app.tar" }
atakit-portal = true
gid-group = "app"

[workload.disks]
data = "/data"

[baby-container]
enabled = true
max-instances = 2

[baby-container.slots.analysis-job]
parent-service = "baby-workload"
image-selection = "single"
max-instances = 1
trust-policy = "user-helper-image"

[baby-container.slots.analysis-job.lifecycle]
image-retention = "disk"
instance-retention = "ephemeral"
restart = "manual"
rootfs = "read-only"

[baby-container.slots.analysis-job.storage.workspace]
disk = "data"
base-path = "/analysis-job/instances"
mount-path = "/workspace"
retention = "disk"
scope = "instance"
read-only = false

[baby-container.slots.analysis-job.storage.workspace.permissions]
baby = "rw"
parent = "ro"

[disks.data]
index = 10
size = "10GB"
encryption = { unlock_method = [], bind = [] }
"#;
    std::fs::write(wl_dir.join("atakit-workload.toml"), config).unwrap();
    wl_dir
}

fn read_manifest_json(archive_path: &std::path::Path) -> serde_json::Value {
    let file = std::fs::File::open(archive_path).unwrap();
    let dec = zstd::Decoder::new(file).unwrap();
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry
            .path()
            .unwrap()
            .to_string_lossy()
            .ends_with("manifest.json")
        {
            let mut content = String::new();
            entry.read_to_string(&mut content).unwrap();
            return serde_json::from_str(&content).unwrap();
        }
    }
    panic!("archive did not contain manifest.json");
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
            verbose: false,
            compression: ArchiveCompression::default(),
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
    assert!(result
        .archive_path
        .to_string_lossy()
        .ends_with("my-workload-v0.1.0.atawl"));
    assert!(!result.archive_hash.is_empty());

    // Verify archive contents
    let file = std::fs::File::open(&result.archive_path).unwrap();
    let dec = zstd::Decoder::new(file).unwrap();
    let mut archive = tar::Archive::new(dec);

    let mut entry_names: Vec<String> = archive
        .entries()
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            e.path().unwrap().to_string_lossy().into_owned()
        })
        .collect();
    entry_names.sort();

    assert!(
        entry_names.iter().any(|n| n.ends_with("manifest.json")),
        "archive must contain manifest.json, got: {entry_names:?}"
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

    // Verify manifest.json content
    let file = std::fs::File::open(&result.archive_path).unwrap();
    let dec = zstd::Decoder::new(file).unwrap();
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry
            .path()
            .unwrap()
            .to_string_lossy()
            .ends_with("manifest.json")
        {
            let mut content = String::new();
            entry.read_to_string(&mut content).unwrap();
            assert!(content.contains("\"name\":\"my-workload\""));
            assert!(content.contains("\"version\":\"v0.1.0\""));
            assert!(content.contains("RUST_LOG"));
            assert!(content.contains("\"hashes\""));
            break;
        }
    }
}

#[tokio::test]
async fn build_materializes_baby_container_slots_in_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let wl_dir = setup_baby_container_workload_dir(tmp.path());
    let out_dir = tmp.path().join("output");
    std::fs::create_dir_all(&out_dir).unwrap();

    let result = build_workload(
        &BuildOptions {
            workload_dir: wl_dir,
            output_dir: Some(out_dir),
            engine: None,
            verbose: false,
            compression: ArchiveCompression::default(),
        },
        &NullReporter,
    )
    .await
    .unwrap();

    let manifest = read_manifest_json(&result.archive_path);
    let baby = &manifest["config"]["baby-container"];
    assert_eq!(baby["enabled"], true);
    assert_eq!(baby["max_instances"], 2);
    assert_eq!(
        baby["slots"]["analysis-job"]["parent_service"],
        "baby-workload"
    );
    assert_eq!(baby["slots"]["analysis-job"]["gid_group"], "app");
    assert_eq!(baby["slots"]["analysis-job"]["image_selection"], "single");
    assert_eq!(
        baby["slots"]["analysis-job"]["lifecycle"]["image_retention"],
        "disk"
    );
    assert_eq!(
        baby["slots"]["analysis-job"]["lifecycle"]["rootfs"],
        "read_only"
    );
    assert_eq!(
        baby["slots"]["analysis-job"]["storage"]["workspace"]["base_path"],
        "/analysis-job/instances"
    );
    assert_eq!(
        baby["slots"]["analysis-job"]["storage"]["workspace"]["permissions"]["parent"],
        "ro"
    );
    assert_eq!(
        baby["slots"]["analysis-job"]["trust_policy"],
        "user-helper-image"
    );
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
            verbose: false,
            compression: ArchiveCompression::default(),
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
            verbose: false,
            compression: ArchiveCompression::default(),
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
            verbose: false,
            compression: ArchiveCompression::default(),
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

#[tokio::test]
async fn inspect_archive_matches_build() {
    let tmp = tempfile::tempdir().unwrap();
    let wl_dir = setup_workload_dir(tmp.path());
    let out_dir = tmp.path().join("output");
    std::fs::create_dir_all(&out_dir).unwrap();

    let build_result = build_workload(
        &BuildOptions {
            workload_dir: wl_dir,
            output_dir: Some(out_dir),
            engine: None,
            verbose: false,
            compression: ArchiveCompression::default(),
        },
        &NullReporter,
    )
    .await
    .unwrap();

    let inspect_result = inspect_workload(&InspectOptions {
        archive: Some(build_result.archive_path),
        workload_dir: None,
        engine: None,
        verbose: false,
    })
    .await
    .unwrap();

    assert_eq!(inspect_result.manifest.meta.name, "my-workload");
    assert_eq!(inspect_result.manifest.meta.version, "v0.1.0");
    assert!(!inspect_result.sha256.is_empty());
    assert!(inspect_result.sha256.starts_with("0x"));
    assert!(!inspect_result.manifest_hash.is_empty());
    assert!(inspect_result.manifest_hash.starts_with("sha256:"));
    assert!(inspect_result
        .manifest_raw
        .contains("\"name\":\"my-workload\""));
}

#[tokio::test]
async fn inspect_dir_matches_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let wl_dir = setup_workload_dir(tmp.path());
    let out_dir = tmp.path().join("output");
    std::fs::create_dir_all(&out_dir).unwrap();

    let build_result = build_workload(
        &BuildOptions {
            workload_dir: wl_dir.clone(),
            output_dir: Some(out_dir),
            engine: None,
            verbose: false,
            compression: ArchiveCompression::default(),
        },
        &NullReporter,
    )
    .await
    .unwrap();

    let archive_result = inspect_workload(&InspectOptions {
        archive: Some(build_result.archive_path),
        workload_dir: None,
        engine: None,
        verbose: false,
    })
    .await
    .unwrap();

    let dir_result = inspect_workload(&InspectOptions {
        archive: None,
        workload_dir: Some(wl_dir),
        engine: None,
        verbose: false,
    })
    .await
    .unwrap();

    assert_eq!(archive_result.sha256, dir_result.sha256);
    assert_eq!(archive_result.manifest_hash, dir_result.manifest_hash);
}

/// Set up a workload with a dependency using `image = { file = "..." }`.
fn setup_workload_with_dependency(tmp: &std::path::Path) -> std::path::PathBuf {
    let wl_dir = tmp.join("multi-container");
    std::fs::create_dir_all(&wl_dir).unwrap();

    // Real (minimal) docker-archive tars with distinct config blobs so the
    // build pipeline can extract a different image-id for each.
    std::fs::write(wl_dir.join("app.tar"), make_docker_archive_tar("multi-app")).unwrap();
    std::fs::write(
        wl_dir.join("sidecar.tar"),
        make_docker_archive_tar("redis-sidecar"),
    )
    .unwrap();

    let config = r#"
format = 2

[workload]
name = "multi-app"
version = "v0.2.0"
base-image-mode = "blacklist"
image = { file = "./app.tar" }
ports = ["3000:3000"]

[dependencies.redis]
image = { file = "./sidecar.tar" }
ports = ["6379:6379"]
restart = "unless-stopped"

[dependencies.redis.environment]
REDIS_MAX_MEMORY = "256mb"
"#;
    std::fs::write(wl_dir.join("atakit-workload.toml"), config).unwrap();
    wl_dir
}

#[tokio::test]
async fn build_with_dependency() {
    let tmp = tempfile::tempdir().unwrap();
    let wl_dir = setup_workload_with_dependency(tmp.path());
    let out_dir = tmp.path().join("output");
    std::fs::create_dir_all(&out_dir).unwrap();

    let result = build_workload(
        &BuildOptions {
            workload_dir: wl_dir,
            output_dir: Some(out_dir),
            engine: None,
            verbose: false,
            compression: ArchiveCompression::default(),
        },
        &NullReporter,
    )
    .await
    .unwrap();

    assert_eq!(result.name, "multi-app");
    assert_eq!(result.version, "v0.2.0");
    assert_eq!(result.image_count, 2);

    // Verify archive contains both image tars
    let file = std::fs::File::open(&result.archive_path).unwrap();
    let dec = zstd::Decoder::new(file).unwrap();
    let mut archive = tar::Archive::new(dec);
    let entry_names: Vec<String> = archive
        .entries()
        .unwrap()
        .filter_map(|e| Some(e.ok()?.path().ok()?.to_string_lossy().into_owned()))
        .collect();

    assert!(
        entry_names
            .iter()
            .any(|n| n.contains("images/multi-app.tar")),
        "archive must contain main image tar, got: {entry_names:?}"
    );
    assert!(
        entry_names.iter().any(|n| n.contains("images/redis.tar")),
        "archive must contain dependency image tar, got: {entry_names:?}"
    );

    // Verify manifest has dependency populated
    let inspect_result = inspect_workload(&InspectOptions {
        archive: Some(result.archive_path),
        workload_dir: None,
        engine: None,
        verbose: false,
    })
    .await
    .unwrap();

    let deps = inspect_result
        .manifest
        .config
        .dependencies
        .as_ref()
        .expect("manifest should have dependencies");
    assert!(deps.contains_key("redis"));
    let redis = &deps["redis"];
    assert_eq!(redis.image, "redis:v0.2.0"); // auto-tagged from file source
    assert_eq!(redis.ports, vec!["6379:6379"]);
    assert_eq!(redis.restart, "unless-stopped");
    assert_eq!(redis.environment.get("REDIS_MAX_MEMORY").unwrap(), "256mb");

    // The `images` section must hold one entry per service, each with the
    // archive path and a sha256 image-id extracted from the staged tar.
    let images = &inspect_result.manifest.images;
    assert_eq!(images.len(), 2, "expected one image entry per service");
    let main = images.get("multi-app").expect("primary image-id missing");
    assert_eq!(main.archive, "images/multi-app.tar");
    assert!(main.image_id.starts_with("sha256:"));
    assert_eq!(main.image_id.len(), 7 + 64);
    let dep = images.get("redis").expect("dependency image-id missing");
    assert_eq!(dep.archive, "images/redis.tar");
    assert!(dep.image_id.starts_with("sha256:"));
    // Distinct config blobs => distinct image-ids.
    assert_ne!(main.image_id, dep.image_id);
}

#[tokio::test]
async fn build_with_dependency_is_deterministic() {
    let tmp = tempfile::tempdir().unwrap();
    let wl_dir = setup_workload_with_dependency(tmp.path());

    let out1 = tmp.path().join("out1");
    let out2 = tmp.path().join("out2");
    std::fs::create_dir_all(&out1).unwrap();
    std::fs::create_dir_all(&out2).unwrap();

    let r1 = build_workload(
        &BuildOptions {
            workload_dir: wl_dir.clone(),
            output_dir: Some(out1),
            engine: None,
            verbose: false,
            compression: ArchiveCompression::default(),
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
            verbose: false,
            compression: ArchiveCompression::default(),
        },
        &NullReporter,
    )
    .await
    .unwrap();

    assert_eq!(
        r1.archive_hash, r2.archive_hash,
        "dependency builds must be deterministic"
    );
}
