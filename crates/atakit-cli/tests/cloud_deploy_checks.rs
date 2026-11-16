#![cfg(unix)]
use atakit_core::ProgressReporter;
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, process::Command};

struct Fixture {
    root: tempfile::TempDir,
}
impl Fixture {
    fn new(extra: &str, denied: bool) -> Self {
        let f = Self {
            root: tempfile::tempdir().unwrap(),
        };
        let root = f.root.path();
        std::fs::create_dir(root.join("config")).unwrap();
        std::fs::create_dir(root.join("bin")).unwrap();
        std::fs::write(
            root.join("config/config.toml"),
            format!(
                r#"
[cloud.providers.test]
platform = "aws"
region = "us-east-2"
[cloud.targets.first]
provider = "test"
vmtype = "m6a.large"
image = "existing-image"
registration = "off"
{extra}
[cloud.targets.second]
provider = "test"
vmtype = "m6a.large"
image = "existing-image"
registration = "off"
"#
            ),
        )
        .unwrap();
        let calls = shell_escape::escape(root.join("calls").display().to_string().into());
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> {calls}
case "$1 $2" in
  'sts get-caller-identity') {} ;;
  'ec2 describe-instance-types') printf '%s\n' '{{"InstanceTypes":[{{"InstanceType":"m6a.large","VCpuInfo":{{"DefaultVCpus":2}}}}]}}' ;;
  'service-quotas get-service-quota') exit 1 ;;
  *) printf '%s\n' 'UNEXPECTED_MUTATING_COMMAND' >&2; exit 99 ;;
esac
"#,
            if denied {
                "exit 1"
            } else {
                "printf '%s\\n' '{\"Account\":\"123456789012\"}'"
            }
        );
        std::fs::write(root.join("bin/aws"), script).unwrap();
        std::fs::set_permissions(root.join("bin/aws"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        f
    }
    fn local_image(&self) {
        let store = atakit_image::ImageStore::new(self.root.path().join("data/images"));
        let image: atakit_image::ImageRef = "cached:v1".parse().unwrap();
        std::fs::create_dir_all(store.disk_images_dir(&image)).unwrap();
        std::fs::write(
            store.image_path(&image, atakit_image::Platform::Aws),
            "test disk",
        )
        .unwrap();
        std::fs::write(
            store.tag_dir(&image).join("baseimage.toml"),
            format!(
                "[meta]\nbase-image-ref = '0x{}/image:v1'\n",
                "bb".repeat(32)
            ),
        )
        .unwrap();
        let path = self.root.path().join("config/config.toml");
        let config = std::fs::read_to_string(&path)
            .unwrap()
            .replace("existing-image", "cached:v1");
        std::fs::write(path, config).unwrap();
    }
    fn workload(&self) -> std::path::PathBuf {
        let manifest = json!({"meta":{"format":atakit_workload::FORMAT_VERSION,"publisher":format!("0x{}","aa".repeat(32)),"name":"test","version":"v1"},
            "config":{"image":"test:v1","base-image-mode":"any","depends_on":[],"gid-group":"test","workload-logs":false,
              "logging":{"driver":"k8s-file","options":{"max-file":"5","max-size":"50m"},"log-readers":[]}},
            "hashes":{}});
        let staging =
            atakit_workload::archive::StagingDir::create(self.root.path(), "test").unwrap();
        staging.write_manifest(&manifest.to_string()).unwrap();
        let progress = atakit_core::NullReporter.create("test", 0);
        atakit_workload::archive::create_archive(
            &staging.root,
            "test",
            "v1",
            self.root.path(),
            progress.as_ref(),
            Default::default(),
        )
        .unwrap()
    }
    fn run(&self, args: &[&str]) -> std::process::Output {
        let result = Command::new(env!("CARGO_BIN_EXE_atakit"))
            .args(["cloud", "deploy"])
            .args(args)
            .env("PATH", self.root.path().join("bin"))
            .env("ATAKIT_CONFIG_DIR", self.root.path().join("config"))
            .env("ATAKIT_DATA_DIR", self.root.path().join("data"))
            .env("ATAKIT_CACHE_DIR", self.root.path().join("cache"))
            .output()
            .unwrap();
        assert!(
            !self.root.path().join("data/cloud/init-keys").exists(),
            "created initialization credentials"
        );
        let deployments = self.root.path().join("data/cloud/deployments");
        fn no_records(path: &std::path::Path) {
            if !path.exists() {
                return;
            }
            for entry in std::fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    no_records(&path);
                } else {
                    assert!(
                        !path.to_string_lossy().ends_with(".state.json"),
                        "created deployment record: {path:?}"
                    );
                }
            }
        }
        no_records(&deployments);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!stderr.contains("UNEXPECTED_MUTATING_COMMAND"), "{stderr}");
        result
    }
    fn calls(&self) -> String {
        std::fs::read_to_string(self.root.path().join("calls")).unwrap_or_default()
    }
}
#[test]
fn deploy_check_only_image_without_chain_keys_or_confirmation() {
    let f = Fixture::new("", false);
    let result = f.run(&[
        "--target",
        "first",
        "--image-only",
        "--name",
        "test",
        "--check-only",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(f.calls().lines().count(), 3);
    assert!(!f.root.path().join("data/cloud").exists());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("Proceed?"));
}

#[test]
fn disk_profile_preview_and_rejections_precede_cloud_writes() {
    let profile = "boot_disk = { profile = 'fast', size = '32GB' }\n[cloud.disk_profiles.fast]\ndisk_type = 'aws-gp3'\niops = 6000\nthroughput_mibps = 250";
    let f = Fixture::new(profile, false);
    let args = [
        "--target",
        "first",
        "--image-only",
        "--name",
        "test",
        "--check-only",
    ];
    let result = f.run(&args);
    let text = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "{text}");
    assert!(
        text.contains("Boot disk: 32GB; profile=fast, type=gp3, IOPS=6000, throughput=250 MiB/s"),
        "{text}"
    );
    assert!(
        text.contains("NOT CHECKED: AWS shared disk performance limit unavailable"),
        "{text}"
    );
    for bad in [
        profile.replace("disk_type = 'aws-gp3'", "disk_type = 'gcp-pd-ssd'"),
        profile.replace("iops = 6000", "iops = 90000"),
        "disks.unknown = { encryption_workqueues = 'bypass' }".into(),
    ] {
        let f = Fixture::new(&bad, false);
        let result = f.run(&args);
        assert!(!result.status.success());
        assert!(
            f.calls().is_empty(),
            "invalid disk configuration contacted the cloud"
        );
    }
}
#[test]
fn deploy_check_only_checks_every_target_without_pre_upload() {
    let f = Fixture::new("", false);
    f.local_image();
    let result = f.run(&["--target", "first,second", "--image-only", "--check-only"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(f.calls().lines().count(), 6);
    assert!(!f.root.path().join("data/cloud").exists());
}
#[test]
fn deploy_auth_failure_stops_normal_and_check_only_before_credentials() {
    for mode in [true, false] {
        let f = Fixture::new("", true);
        let mut args = vec![
            "--target",
            "first",
            "--image-only",
            "--name",
            "test",
            "--yes",
        ];
        if mode {
            args.push("--check-only");
        }
        let result = f.run(&args);
        assert!(!result.status.success());
        assert_eq!(f.calls().lines().count(), 1);
    }
}
#[test]
fn deploy_registration_off_resolves_archive_and_keys_without_chain() {
    let f = Fixture::new("", false);
    let archive = f.workload();
    let result = f.run(&[
        archive.to_str().unwrap(),
        "--target",
        "first",
        "--check-only",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("registry records (registration is off)")
    );
    assert_eq!(f.calls().lines().count(), 3);
}
#[test]
fn deploy_invalid_archive_stops_before_cloud_access() {
    let f = Fixture::new("", false);
    let path = f.root.path().join("invalid.atawl");
    std::fs::write(&path, "invalid archive").unwrap();
    let result = f.run(&[path.to_str().unwrap(), "--target", "first", "--check-only"]);
    assert!(!result.status.success());
    assert!(f.calls().is_empty());
}

#[test]
fn deploy_cpu_policy_rejection_precedes_cloud_access_in_both_modes() {
    for check_only in [false, true] {
        for (extra, flags, expected) in [
            ("", vec!["--cpuset", "0"], "did not allow operator cpuset"),
            (
                "",
                vec!["--dependency-cpuset", "missing=0"],
                "unknown CPU dependency",
            ),
            (
                "[cloud.targets.first.runtime]\ncpuset = '0'",
                vec![],
                "did not allow operator cpuset",
            ),
        ] {
            let f = Fixture::new(extra, false);
            let archive = f.workload();
            let mut args = vec![
                archive.to_str().unwrap(),
                "--target",
                "first,second",
                "--yes",
            ];
            args.extend(flags);
            if check_only {
                args.push("--check-only");
            }
            let result = f.run(&args);
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(!result.status.success(), "{stderr}");
            assert!(stderr.contains(expected), "{stderr}");
            assert!(
                f.calls().is_empty(),
                "CPU rejection must precede cloud access"
            );
        }
    }
}
#[test]
fn deploy_unresolvable_configured_key_stops_before_cloud_access() {
    let f=Fixture::new("owner_key = 'owner'\n[keys.owner]\ntype = 'es256k'\nmode = 'provisioned'\nfile = '/nonexistent/atakit-test-key'",false);
    let archive = f.workload();
    let result = f.run(&[
        archive.to_str().unwrap(),
        "--target",
        "first",
        "--check-only",
    ]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("atakit-test-key"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(f.calls().is_empty());
}

#[test]
fn deploy_check_only_leaves_existing_state_directory_untouched() {
    let f = Fixture::new("", false);
    let old = f.root.path().join("data/deployments/first");
    std::fs::create_dir_all(&old).unwrap();
    let file = old.join("test.state.json");
    std::fs::write(&file, "existing record").unwrap();
    let result = f.run(&[
        "--target",
        "first",
        "--image-only",
        "--name",
        "test",
        "--check-only",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("already exists"));
    assert_eq!(std::fs::read_to_string(file).unwrap(), "existing record");
    assert!(!f.root.path().join("data/cloud").exists());
    assert!(f.calls().is_empty());
}

#[test]
fn deploy_checks_all_targets_before_shared_image_uploads() {
    let f = Fixture::new("", false);
    f.local_image();
    let path = f.root.path().join("config/config.toml");
    let config = std::fs::read_to_string(&path).unwrap();
    let (before, second) = config.split_once("[cloud.targets.second]").unwrap();
    std::fs::write(
        path,
        format!(
            "{before}[cloud.targets.second]{}",
            second.replace("m6a.large", "m6a.2xlarge")
        ),
    )
    .unwrap();
    let result = f.run(&["--target", "first,second", "--image-only", "--yes"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("m6a.2xlarge"));
    assert_eq!(f.calls().lines().count(), 5);
    assert!(!f.root.path().join("data/cloud").exists());
}
