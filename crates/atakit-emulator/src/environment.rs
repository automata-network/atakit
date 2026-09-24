//! Portal-compatible application environment resolution for native and Compose runs.
use anyhow::{bail, Context, Result};
use atakit_workload::{config::WorkloadConfig, manifest};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

type Allowlists = BTreeMap<String, Vec<String>>;
pub type ServiceEnvironments = BTreeMap<String, BTreeMap<String, String>>;

pub fn validate_features(config: &WorkloadConfig) -> Result<()> {
    if !matches!(&config.workload.image, atakit_workload::config::ImageSource::Build { build, .. } if !build.trim().is_empty())
    {
        bail!("workload `{}` is not supported by emulator: workload.image must include a nonempty build source (e.g. image = {{ build = \".\" }}). Registry images, image archives, and packages downloaded by `atakit workload pull` are not yet supported as the main workload; use the source project's atakit-workload.toml", config.workload.name);
    }
    if config.workload.ip_env {
        bail!("workload.ip-env=true is not supported by emulator: no VM public/internal network identity is available; disable ip-env for local emulation");
    }
    for (name, dependency) in &config.dependencies {
        if dependency.ip_env {
            bail!("dependencies.{name}.ip-env=true is not supported by emulator: no VM public/internal network identity is available");
        }
    }
    Ok(())
}

fn optional_path(root: &Path, file: &str) -> Result<Option<PathBuf>> {
    let relative = Path::new(file.trim_start_matches('/'));
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("invalid unmeasured env file path {file:?}");
    }
    let path = root.join(relative);
    let resolved = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("resolve env file {}", path.display()))
        }
    };
    if !resolved.starts_with(root.canonicalize()?) || !resolved.is_file() {
        bail!(
            "unmeasured env file {file:?} must be a regular file inside {}",
            root.display()
        );
    }
    Ok(Some(resolved))
}

pub fn load(config: &WorkloadConfig, root: &Path, snapshot: &Path) -> Result<ServiceEnvironments> {
    validate_features(config)?;
    let services = std::iter::once((
        config.workload.name.as_str(),
        &config.workload.env_file,
        &config.workload.environment,
        &config.workload.unmeasured_env_file,
    ))
    .chain(config.dependencies.iter().map(|(name, dep)| {
        (
            name.as_str(),
            &dep.env_file,
            &dep.environment,
            &dep.unmeasured_env_file,
        )
    }))
    .collect::<Vec<_>>();
    let unmeasured = root.join("unmeasured-data");
    let allowlists: Allowlists = if snapshot.exists() {
        serde_json::from_slice(&std::fs::read(snapshot)?)
            .context("read frozen unmeasured env name allowlists")?
    } else {
        let mut names = BTreeMap::new();
        for (_, _, _, files) in &services {
            if let Some(files) = files {
                for file in files.as_vec() {
                    let allowed = match optional_path(&unmeasured, &file)? {
                        Some(path) => manifest::parse_unmeasured_env_file_names(
                            &path,
                            &std::fs::read_to_string(&path)?,
                        )?,
                        None => Vec::new(),
                    };
                    names.insert(file, allowed);
                }
            }
        }
        if let Some(parent) = snapshot.parent() {
            crate::runtime::private_dir(parent)?;
        }
        crate::runtime::write_private(snapshot, &names)?;
        names
    };
    let mut result = BTreeMap::new();
    for (name, env_files, explicit, files) in services {
        let mut env = BTreeMap::new();
        if let Some(files) = files {
            for file in files.as_vec() {
                let allowed = allowlists.get(&file).with_context(|| format!("unmeasured env file {file:?} has no frozen name allowlist; use a fresh emulator runtime after changing the workload"))?;
                if let Some(path) = optional_path(&unmeasured, &file)? {
                    let content = std::fs::read_to_string(&path)?;
                    // This also rejects invalid/reserved names and duplicates, just like Portal.
                    for key in manifest::parse_unmeasured_env_file_names(&path, &content)? {
                        if !allowed.contains(&key) {
                            bail!(
                                "env file {}: variable {key:?} is not in its frozen name allowlist",
                                path.display()
                            );
                        }
                    }
                    env.extend(manifest::parse_env_file(&path, &content)?);
                }
            }
        }
        // Portal's measured manifest environment wins over runtime env files.
        env.extend(manifest::resolve_environment(env_files, explicit, root)?);
        result.insert(name.to_owned(), env);
    }
    Ok(result)
}

/// Export host paths for native development without replacing application variables.
pub(crate) fn native(
    config: &WorkloadConfig,
    mut application: BTreeMap<String, String>,
    storage_root: &Path,
    snapshot_root: &Path,
    workload_root: &Path,
    rpc_url: &str,
) -> Result<BTreeMap<String, String>> {
    let prefix = snapshot_root.join("root");
    let generated = BTreeMap::from([
        ("EMULATOR_ROOTFS".to_owned(), prefix.display().to_string()),
        ("EMULATOR_RPC_URL".to_owned(), rpc_url.to_owned()),
    ]);
    let mut mounts = vec![
        (
            PathBuf::from("atakit-portal/measured-data"),
            snapshot_root.join("measured-data"),
        ),
        (
            PathBuf::from("atakit-portal/unmeasured-data"),
            workload_root.join("unmeasured-data"),
        ),
    ];

    let mut directories = Vec::new();

    for (name, storage) in &config.workload.storage {
        if storage.disk.is_empty()
            || storage.disk.contains('/')
            || storage.disk == "."
            || storage.disk == ".."
            || storage.base_path.split('/').any(|c| c == "..")
        {
            bail!("invalid local storage path for workload.storage.{name}");
        }
        let path = storage_root
            .join(&storage.disk)
            .join(storage.base_path.trim_start_matches('/'));
        let mount = Path::new(&storage.mount_path);
        if !mount.is_absolute()
            || mount
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            bail!("workload.storage.{name}: mount-path must be absolute without '..'");
        }
        let relative: PathBuf = mount
            .components()
            .filter_map(|c| match c {
                Component::Normal(value) => Some(value),
                _ => None,
            })
            .collect();
        if relative.as_os_str().is_empty()
            || mounts.iter().any(|(existing, _)| {
                relative.starts_with(existing) || existing.starts_with(&relative)
            })
        {
            bail!("workload.storage.{name}: overlapping mount-path {} is not supported by native emulator", storage.mount_path);
        }
        mounts.push((relative, path.clone()));

        directories.push(path);
    }
    for key in generated.keys() {
        if application.contains_key(key) {
            bail!("application environment variable {key} conflicts with an emulator export; rename the application variable");
        }
    }
    for directory in directories {
        crate::runtime::private_dir(&directory)?;
    }
    crate::runtime::private_dir(&prefix)?;
    for (relative, source) in mounts {
        let destination = prefix.join(relative);
        crate::runtime::private_dir(destination.parent().unwrap())?;
        match std::fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink()
                && std::fs::read_link(&destination)? == source => {}
            Ok(_) => bail!("native mount {} already exists with a different source; use a fresh emulator runtime", destination.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::os::unix::fs::symlink(source, &destination)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    application.extend(generated);

    Ok(application)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> WorkloadConfig {
        toml::from_str("format=7\n[workload]\nname='app'\nversion='1'\nbase-image-mode='locked'\nimage={build='.'}\nunmeasured-env-file='/runtime.env'\n[workload.environment]\nSHARED='measured'\n").unwrap()
    }
    #[test]
    fn native_exports_all_storage_and_preserves_application_values() {
        let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let mut cfg = config();
        cfg.workload.atakit_portal = true;
        for (name, disk, base, mount) in [
            ("data", "disk-a", "/db", "/data"),
            ("cache-files", "disk-b", "/", "/cache"),
        ] {
            cfg.workload.storage.insert(
                name.into(),
                atakit_workload::config::ServiceStorageSection {
                    disk: disk.into(),
                    base_path: base.into(),
                    mount_path: mount.into(),
                    read_only: false,
                },
            );
        }
        let original = BTreeMap::from([
            ("PORTAL_SOCKET".into(), "/run/atakit-portal.sock".into()),
            ("RPC_URL".into(), "http://business-chain".into()),
            ("DATA_DIR".into(), "/data".into()),
        ]);
        let env = native(
            &cfg,
            original.clone(),
            dir.path(),
            &dir.path().join("snapshot"),
            Path::new("/project"),
            "http://localhost:8546",
        )
        .unwrap();
        for (key, value) in original {
            assert_eq!(env[&key], value);
        }
        assert_eq!(env["EMULATOR_RPC_URL"], "http://localhost:8546");
        assert!(!env.contains_key("EMULATOR_PORTAL_SOCKET"));
        assert_eq!(
            env.keys()
                .filter(|key| key.starts_with("EMULATOR_"))
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["EMULATOR_ROOTFS", "EMULATOR_RPC_URL"]
        );
        let prefix = Path::new(&env["EMULATOR_ROOTFS"]);

        assert_eq!(
            std::fs::read_link(prefix.join("atakit-portal/measured-data")).unwrap(),
            dir.path().join("snapshot/measured-data")
        );
        assert_eq!(
            std::fs::read_link(prefix.join("atakit-portal/unmeasured-data")).unwrap(),
            Path::new("/project/unmeasured-data")
        );

        std::fs::write(prefix.join("data/probe"), "persistent").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("disk-a/db/probe")).unwrap(),
            "persistent"
        );
        assert_eq!(
            std::fs::read_link(prefix.join("cache")).unwrap(),
            dir.path().join("disk-b/")
        );

        cfg.workload.atakit_portal = false;
        let env = native(
            &cfg,
            BTreeMap::new(),
            dir.path(),
            dir.path(),
            dir.path(),
            "rpc",
        )
        .unwrap();
        assert!(!env.contains_key("EMULATOR_PORTAL_SOCKET"));
        assert!(std::fs::symlink_metadata(
            Path::new(&env["EMULATOR_ROOTFS"]).join("run/atakit-portal.sock")
        )
        .is_err());
        cfg.workload.storage.insert(
            "CACHE_FILES".into(),
            atakit_workload::config::ServiceStorageSection {
                disk: "other".into(),
                base_path: "/".into(),
                mount_path: "/other".into(),
                read_only: false,
            },
        );
        let env = native(
            &cfg,
            BTreeMap::new(),
            dir.path(),
            dir.path(),
            dir.path(),
            "rpc",
        )
        .unwrap();
        assert_eq!(env.len(), 2);
        assert!(Path::new(&env["EMULATOR_ROOTFS"]).join("other").is_dir());
    }

    #[test]
    fn native_mounts_survive_restart_and_reject_overlapping_paths() {
        let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let mut cfg = config();
        cfg.workload.storage.insert(
            "data".into(),
            atakit_workload::config::ServiceStorageSection {
                disk: "disk".into(),
                base_path: "/".into(),
                mount_path: "/data".into(),
                read_only: false,
            },
        );
        let export = |cfg: &WorkloadConfig| {
            native(
                cfg,
                BTreeMap::new(),
                &dir.path().join("storage"),
                &dir.path().join("snapshot"),
                dir.path(),
                "rpc",
            )
        };
        let first = export(&cfg).unwrap();
        let file = Path::new(&first["EMULATOR_ROOTFS"]).join("data/saved");
        std::fs::write(&file, "persistent").unwrap();
        assert_eq!(export(&cfg).unwrap(), first);
        assert_eq!(std::fs::read_to_string(file).unwrap(), "persistent");
        for mount in [
            "/data/nested",
            "/atakit-portal",
            "/",
            "/../escape",
            "relative",
        ] {
            cfg.workload.storage.insert(
                "second".into(),
                atakit_workload::config::ServiceStorageSection {
                    disk: "second".into(),
                    base_path: "/".into(),
                    mount_path: mount.into(),
                    read_only: false,
                },
            );
            assert!(export(&cfg).is_err(), "{mount}");
        }
    }

    #[test]
    fn native_environment_preserves_a_direct_root_socket() {
        let dir =
            tempfile::tempdir_in(std::path::Path::new("/tmp").canonicalize().unwrap()).unwrap();
        let socket = dir.path().join("root/run/atakit-portal.sock");
        crate::runtime::private_dir(socket.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let mut cfg = config();
        cfg.workload.atakit_portal = true;
        let env = native(
            &cfg,
            BTreeMap::new(),
            &dir.path().join("data"),
            dir.path(),
            dir.path(),
            "rpc",
        )
        .unwrap();
        let client = std::os::unix::net::UnixStream::connect(
            Path::new(&env["EMULATOR_ROOTFS"]).join("run/atakit-portal.sock"),
        )
        .unwrap();
        listener.set_nonblocking(true).unwrap();
        let (_server, _) = listener.accept().unwrap();
        drop(client);
        assert!(!std::fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(env.len(), 2);
    }

    #[test]
    fn native_rejects_application_export_collisions() {
        let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let env = BTreeMap::from([("EMULATOR_RPC_URL".into(), "custom".into())]);
        let error = native(&config(), env, dir.path(), dir.path(), dir.path(), "rpc").unwrap_err();
        assert!(error.to_string().contains("EMULATOR_RPC_URL conflicts"));
    }

    #[test]
    fn measured_values_win_and_missing_runtime_file_is_optional() {
        let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let env = dir.path().join("unmeasured-data/runtime.env");
        std::fs::create_dir_all(env.parent().unwrap()).unwrap();
        std::fs::write(&env, "SHARED=runtime\nOTHER=value\n").unwrap();
        let snapshot = dir.path().join("snapshot/names.json");
        let resolved = load(&config(), dir.path(), &snapshot).unwrap();
        assert_eq!(resolved["app"]["SHARED"], "measured");
        assert_eq!(resolved["app"]["OTHER"], "value");
        std::fs::remove_file(env).unwrap();
        assert_eq!(
            load(&config(), dir.path(), &snapshot).unwrap()["app"].len(),
            1
        );
    }
    #[test]
    fn frozen_names_reject_additions_but_allow_value_changes() {
        let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let env = dir.path().join("unmeasured-data/runtime.env");
        std::fs::create_dir_all(env.parent().unwrap()).unwrap();
        let snapshot = dir.path().join("snapshot/names.json");
        std::fs::write(&env, "OTHER=old\n").unwrap();
        load(&config(), dir.path(), &snapshot).unwrap();
        std::fs::write(&env, "OTHER=new\n").unwrap();
        assert_eq!(
            load(&config(), dir.path(), &snapshot).unwrap()["app"]["OTHER"],
            "new"
        );
        for text in [
            "NEW=value",
            "OTHER=a\nOTHER=b",
            "ATAKIT_BAD=value",
            "VERIFIERD_BAD=value",
            "1INVALID=value",
        ] {
            std::fs::write(&env, text).unwrap();
            assert!(load(&config(), dir.path(), &snapshot).is_err(), "{text}");
        }
    }
    #[test]
    fn ip_env_and_escaping_paths_are_rejected() {
        let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let mut cfg = config();
        cfg.workload.ip_env = true;
        assert!(load(&cfg, dir.path(), &dir.path().join("names"))
            .unwrap_err()
            .to_string()
            .contains("ip-env"));
        assert!(optional_path(dir.path(), "../outside").is_err());
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
        assert!(optional_path(dir.path(), "escape").is_err());
    }
}
