use sha2::{Digest, Sha256};
use std::{io::Write, os::unix::fs::PermissionsExt, process::Command};

fn fixture(engine: &str, image: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("bin")).unwrap();
    std::fs::write(root.path().join("owner.key"), format!("{:064x}", 1)).unwrap();
    std::fs::write(root.path().join("config.toml"), format!("[build]\ncontainer_engine='{engine}'\n[publish]\nowner_key='owner'\n[keys.owner]\ntype='es256k'\nmode='provisioned'\nfile='{}'\n", root.path().join("owner.key").display())).unwrap();
    std::fs::write(root.path().join("atakit-workload.toml"), format!("format=7\n[workload]\nname='fixture'\nversion='v1'\nbase-image-mode='blacklist'\nimage={image}\n[dependencies.worker]\nimage={image}\n")).unwrap();
    std::fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    let config = br#"{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":[]}}"#;
    let hash = hex::encode(Sha256::digest(config));
    let manifest = format!(r#"[{{"Config":"{hash}.json","RepoTags":["fixture:v1"],"Layers":[]}}]"#);
    let mut archive = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("manifest.json".to_owned(), manifest.as_bytes()),
        (format!("{hash}.json"), config.as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive.append_data(&mut header, name, bytes).unwrap();
    }
    std::fs::write(root.path().join("image.tar"), archive.into_inner().unwrap()).unwrap();
    let script = r#"#!/bin/sh
root=${0%/*}/..
printf '%s\n' "$*" >> "$root/calls"
case "$1 $2" in
 'buildx ls') printf '%s\n' '{"Name":"fixture-builder","Driver":"docker-container","Current":true,"Nodes":[{"Endpoint":"local","Status":"running","Platforms":["linux/amd64","linux/arm64"]}]}' ;;
 'buildx build')
   for arg in "$@"; do
     case "$arg" in type=docker,*) dest=${arg#*dest=}; dest=${dest%%,*}; /bin/cp "$root/image.tar" "$dest";; esac
   done ;;
 'save -o') /bin/cp "$root/image.tar" "$3" ;;
 'load -i'|'pull --platform'|'build -t') exit 0 ;;
 *) echo "unexpected command: $*" >&2; exit 90 ;;
esac
"#;
    let binary = root.path().join("bin").join(engine);
    let mut file = std::fs::File::create(&binary).unwrap();
    file.write_all(script.as_bytes()).unwrap();
    std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    root
}

fn build(root: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_atakit"))
        .args(["workload", "build", "--no-store"])
        .current_dir(root)
        .env("PATH", root.join("bin"))
        .env("ATAKIT_CONFIG_DIR", root)
        .env("ATAKIT_DATA_DIR", root.join("data"))
        .env("ATAKIT_CACHE_DIR", root.join("cache"))
        .env_remove("ATAKIT_CONTAINER_ENGINE")
        .env_remove("BUILDX_BUILDER")
        .output()
        .unwrap()
}

#[test]
fn docker_builder_is_forwarded_to_main_and_dependency_builds() {
    let root = fixture("docker", "{build='.'}");
    let output = build(root.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.path().join("fixture-v1.atawl").is_file());
    let calls = std::fs::read_to_string(root.path().join("calls")).unwrap();
    let builds: Vec<_> = calls
        .lines()
        .filter(|line| line.starts_with("buildx build"))
        .collect();
    assert_eq!(builds.len(), 3); // Capability probe, main image, dependency.
    assert!(builds
        .iter()
        .all(|line| line.contains("--builder fixture-builder")));
    assert!(!calls.contains("--platform"));
    assert!(!calls.contains("--use"));
}

#[test]
fn podman_and_registry_or_file_images_do_not_run_builder_preflight() {
    for (engine, image) in [
        ("podman", "{build='.'}"),
        ("docker", "'example:latest'"),
        ("docker", "{file='image.tar'}"),
    ] {
        let root = fixture(engine, image);
        let output = build(root.path());
        assert!(
            output.status.success(),
            "{engine}/{image}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let calls = std::fs::read_to_string(root.path().join("calls")).unwrap_or_default();
        assert!(!calls.contains("buildx"));
        assert!(!calls.contains("--builder"));
    }
}
