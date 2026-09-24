//! Optional Docker Compose projection; the Emulator itself remains a native process.
use crate::{cli::PortalTransport, endpoints::EndpointInfo};
use anyhow::{bail, Context, Result};
use atakit_attestation::signing;
use serde_json::{json, Map, Value};
use sha2::Digest;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use tokio::{
    net::{TcpListener, UnixStream},
    task::JoinHandle,
};

pub async fn start_bridge(socket: PathBuf) -> Result<(u16, String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let token = hex::encode(signing::generate_secret_key_bytes());
    let expected = token.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let socket = socket.clone();
            let expected = expected.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut provided = [0; 65];
                if !matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        tcp.read_exact(&mut provided)
                    )
                    .await,
                    Ok(Ok(_))
                ) {
                    return;
                }
                let mut diff = provided[64] ^ b'\n';
                for (a, b) in provided[..64].iter().zip(expected.as_bytes()) {
                    diff |= a ^ b;
                }
                if diff != 0 {
                    return;
                }
                if let Ok(mut unix) = UnixStream::connect(socket).await {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(300),
                        tokio::io::copy_bidirectional(&mut tcp, &mut unix),
                    )
                    .await;
                }
            });
        }
    });
    Ok((port, token, task))
}

fn selected_workloads(endpoints: &EndpointInfo, names: &[String]) -> Result<Vec<String>> {
    if names.is_empty() {
        Ok(vec![endpoints.select(None)?.0.clone()])
    } else {
        Ok(names.to_vec())
    }
}

fn normalized_selection(names: &[String]) -> Result<Vec<&str>> {
    if names.is_empty() {
        bail!("--workload is required to select a Compose project");
    }
    let mut selected = BTreeSet::new();
    for name in names {
        crate::config::validate_name(name)?;
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            bail!("Compose workload names must contain only letters, digits, _ and -");
        }
        if !selected.insert(name.as_str()) {
            bail!("duplicate workload `{name}`");
        }
    }
    Ok(selected.into_iter().collect())
}

/// Returns the default Compose file for a workload or an order-independent group.
pub fn default_output(runtime_dir: &Path, names: &[String]) -> Result<PathBuf> {
    let names = normalized_selection(names)?;
    if names.len() == 1 {
        return Ok(runtime_dir.join(names[0]).join("compose.yaml"));
    }
    let key = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&names)?));
    Ok(runtime_dir.join("compose").join(key).join("compose.yaml"))
}

/// Locates a saved Compose file without requiring a running emulator.
pub fn existing_output(
    runtime_dir: &Path,
    names: &[String],
    output: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(output) = output {
        return Ok(output.to_path_buf());
    }
    let selected;
    let names = if names.is_empty() {
        let endpoints: EndpointInfo = serde_json::from_slice(
            &std::fs::read(runtime_dir.join("endpoints.json")).context(
                "cannot infer workload; specify --workload NAME or --output PATH; generate a file with `atakit emulator workload-compose up` first"
            )?
        )?;
        selected = selected_workloads(&endpoints, names)?;
        &selected
    } else {
        names
    };
    default_output(runtime_dir, names)
}

fn project_name(runtime_dir: &Path, names: &[String], project_dir: &Path) -> Result<String> {
    let runtime_dir = std::fs::canonicalize(runtime_dir)?;
    let scope = default_output(&runtime_dir, names)?;
    let digest = hex::encode(sha2::Sha256::digest(scope.as_os_str().as_encoded_bytes()));
    let raw = project_dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let slug = raw
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let slug = slug.trim_matches(['-', '_']);
    let slug = if slug.is_empty() { "project" } else { slug };
    Ok(format!("aemu-{slug}-{}", &digest[..6]))
}

pub async fn generate(
    runtime_dir: &Path,
    names: &[String],
    output: Option<&Path>,
    transport: PortalTransport,
    platform: Option<&str>,
) -> Result<PathBuf> {
    let runtime_path = std::fs::canonicalize(runtime_dir)?;
    let runtime_dir = runtime_path.as_path();
    let endpoints: EndpointInfo =
        serde_json::from_value(crate::runtime::control(runtime_dir, "status", None).await?)?;
    let names = selected_workloads(&endpoints, names)?;
    let mut ports = Map::new();
    for name in &names {
        let (_, endpoint) = endpoints.select(Some(name))?;
        let config = atakit_workload::config::WorkloadConfig::from_file(&endpoint.config_file)?;
        crate::environment::validate_features(&config)?;
        if !config.workload.atakit_portal
            && !config.dependencies.values().any(|dep| dep.atakit_portal)
        {
            continue;
        }
        if transport == PortalTransport::Native {
            continue;
        }
        let bridge = crate::runtime::control(runtime_dir, "bridge", Some(name)).await?;
        ports.insert(name.clone(), bridge);
    }
    let mut document = project_with_transport(&endpoints, &names, &ports, runtime_dir, transport)?;
    apply_platform(&mut document, platform);
    let output = match output {
        Some(path) => path.to_path_buf(),
        None => default_output(runtime_dir, &names)?,
    };
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_compose(&output, &document)?;
    Ok(output)
}

/// Writes a Compose document as YAML while preserving private file permissions.
pub fn write_compose(path: &Path, document: &Value) -> Result<()> {
    let yaml = serde_yaml::to_string(document)?;
    crate::runtime::write_private_bytes(path, yaml.as_bytes())
}

pub fn project(
    endpoints: &EndpointInfo,
    names: &[String],
    bridge_ports: &Map<String, Value>,
    runtime_dir: &Path,
) -> Result<Value> {
    project_with_transport(
        endpoints,
        names,
        bridge_ports,
        runtime_dir,
        PortalTransport::Bridge,
    )
}

pub fn project_with_transport(
    endpoints: &EndpointInfo,
    names: &[String],
    bridge_ports: &Map<String, Value>,
    runtime_dir: &Path,
    transport: PortalTransport,
) -> Result<Value> {
    let names = selected_workloads(endpoints, names)?;
    let mut services = Map::new();
    let mut volumes = Map::new();
    let rpc_url = container_rpc_url(&endpoints.rpc_url, cfg!(target_os = "linux"))?;
    let mut host_ports = BTreeSet::new();
    let mut selected = BTreeSet::new();
    for name in &names {
        if !selected.insert(name) {
            bail!("duplicate workload `{name}`");
        }
        let (_, endpoint) = endpoints.select(Some(name))?;
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            bail!("Compose workload names must contain only letters, digits, _ and -");
        }
        let text = std::fs::read_to_string(&endpoint.config_file)?;
        let config: toml::Value = toml::from_str(&text)?;
        let cfg = atakit_workload::config::WorkloadConfig::from_file(&endpoint.config_file)?;
        if cfg.baby_container.as_ref().is_some_and(|baby| {
            baby.enabled || !baby.slots.is_empty() || baby.max_instances.is_some()
        }) {
            bail!("workload `{name}`: baby-container requirements are not supported by Compose emulation");
        }
        // Local disks are directories: encryption policy remains in the source
        // workload but does not require TPM or disk unlocking in the emulator.
        let service_envs = crate::environment::load(
            &cfg,
            &endpoint.workload_dir,
            &runtime_dir.join(name).join("env-allowlists.json"),
        )?;
        let volume = format!("{name}-portal");
        let bridge_name = format!("{name}-portal-bridge");
        let host = if cfg!(target_os = "linux") {
            "127.0.0.1"
        } else {
            "host.docker.internal"
        };
        if transport == PortalTransport::Bridge
            && (cfg.workload.atakit_portal
                || cfg.dependencies.values().any(|dep| dep.atakit_portal))
        {
            volumes.insert(volume.clone(), json!({}));
            let port = bridge_ports
                .get(name)
                .and_then(|b| b["portal_port"].as_u64())
                .context("missing live Portal bridge port")?;
            let token = bridge_ports[name]["token"]
                .as_str()
                .context("missing bridge credential")?;
            let scripts = runtime_dir.join("bridges");
            std::fs::create_dir_all(&scripts)?;
            let script = scripts.join(format!("{name}-connect.sh"));
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o700)
                .open(&script)?;
            // BusyBox cat can buffer the open request stream; socat forwards bytes immediately.
            file.write_all(b"#!/bin/sh\n{ printf '%s\\n' \"$PORTAL_BRIDGE_TOKEN\"; exec socat -u STDIN STDOUT; } | socat STDIO \"TCP:$PORTAL_BRIDGE_HOST:$PORTAL_BRIDGE_PORT\"\n")?;
            services.insert(bridge_name.clone(),json!({"image":"alpine/socat@sha256:ef6c281978dcd6927d9b3829484e4c4fdfc5d98de5acbd6312c04565d2d58cbf","entrypoint":["/bin/sh","-c"],"command":["rm -f /portal/atakit-portal.sock; exec socat UNIX-LISTEN:/portal/atakit-portal.sock,fork,mode=0660,group=65530 EXEC:/bridge/connect.sh"],"environment":{"PORTAL_BRIDGE_TOKEN":token,"PORTAL_BRIDGE_HOST":host,"PORTAL_BRIDGE_PORT":port.to_string()},"volumes":[format!("{volume}:/portal"),format!("{}:/bridge/connect.sh:ro",script.display())],"extra_hosts":["host.docker.internal:host-gateway"],"healthcheck":{"test":["CMD-SHELL","test -S /portal/atakit-portal.sock"],"interval":"1s","timeout":"1s","retries":30}}));
            if cfg!(target_os = "linux") {
                services.get_mut(&bridge_name).unwrap()["network_mode"] = json!("host");
            }
        }
        let mut entries = vec![(
            name.clone(),
            config.get("workload").context("missing workload table")?,
            true,
        )];
        if let Some(deps) = config.get("dependencies").and_then(toml::Value::as_table) {
            for (dep, table) in deps {
                entries.push((format!("{name}-{dep}"), table, false));
            }
        }
        for (service_name, table, is_main) in entries {
            if services.contains_key(&service_name) {
                bail!("duplicate Compose service {service_name}");
            }
            let mut service = Map::new();
            image(
                table.get("image").context("missing image")?,
                &endpoint.workload_dir,
                &mut service,
            )?;
            for field in ["command", "entrypoint", "restart"] {
                if let Some(v) = table.get(field) {
                    service.insert(field.into(), serde_json::to_value(v)?);
                }
            }
            let source_name = if is_main {
                cfg.workload.name.as_str()
            } else {
                service_name
                    .strip_prefix(&format!("{name}-"))
                    .context("dependency service name")?
            };
            let mut env: Map<String, Value> = service_envs[source_name]
                .iter()
                .map(|(key, value)| (key.clone(), json!(value.replace('$', "$$"))))
                .collect();
            if env.contains_key("EMULATOR_RPC_URL") {
                bail!("service `{service_name}` declares reserved environment variable EMULATOR_RPC_URL; remove it so emulator can supply its fork RPC");
            }
            env.insert("EMULATOR_RPC_URL".into(), json!(rpc_url.replace('$', "$$")));
            let uses_portal = table
                .get("atakit-portal")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            let mut mounts = vec![];
            let mut depends = Map::new();
            if uses_portal && transport == PortalTransport::Native {
                use std::os::unix::fs::FileTypeExt;
                let socket = &endpoint.portal_socket;
                if !std::fs::metadata(socket)
                    .with_context(|| {
                        format!(
                            "cannot access Portal socket {}; start the emulator first",
                            socket.display()
                        )
                    })?
                    .file_type()
                    .is_socket()
                {
                    bail!("Portal socket {} is not a Unix socket", socket.display());
                }
                // Omitting create_host_path allows Docker Desktop to prepare its socket forwarding path.
                mounts.push(json!({"type":"bind","source":socket,"target":"/run/atakit-portal.sock","read_only":true}));
            } else if uses_portal {
                service.insert("group_add".into(), json!(["65530"]));
                // Mount only the socket file; mounting a volume over /run would
                // hide files supplied by the workload image. Requires volume subpath.
                mounts.push(json!({"type":"volume","source":volume,"target":"/run/atakit-portal.sock","read_only":true,"volume":{"subpath":"atakit-portal.sock","nocopy":true}}));
                depends.insert(bridge_name.clone(), json!({"condition":"service_healthy"}));
            }
            for (field, root) in [
                ("measured-data", "measured-data"),
                ("unmeasured-data", "unmeasured-data"),
            ] {
                if let Some(access) = table.get(field) {
                    let paths = if access.as_bool() == Some(false) {
                        vec![]
                    } else if access.as_bool() == Some(true) {
                        config
                            .get("package")
                            .and_then(|p| p.get(field))
                            .map(strings)
                            .transpose()?
                            .unwrap_or_default()
                    } else {
                        strings(access)?
                    };
                    for logical in paths {
                        if logical.split('/').any(|p| p == "..") {
                            bail!("data path traversal");
                        }
                        let source_root = if field == "measured-data" {
                            endpoint
                                .env
                                .get("EMULATOR_ROOTFS")
                                .map(|root| PathBuf::from(root).join("atakit-portal/measured-data"))
                                .unwrap_or_else(|| endpoint.workload_dir.join(root))
                        } else {
                            endpoint.workload_dir.join(root)
                        };
                        let relative = logical.trim_start_matches('/');
                        let source = source_root.join(relative);
                        if !source.exists() {
                            bail!("missing service data {}", source.display());
                        }
                        mounts.push(json!({"type":"bind","source":source,"target":format!("/atakit-portal/{root}/{relative}"),"read_only":true}));
                    }
                }
            }
            if let Some(storage) = table.get("storage").and_then(toml::Value::as_table) {
                for (_, v) in storage {
                    let disk = v
                        .get("disk")
                        .and_then(toml::Value::as_str)
                        .context("storage disk missing")?;
                    if disk.is_empty() || disk.contains('/') || disk == ".." {
                        bail!("invalid storage disk name");
                    }
                    let base = v
                        .get("base-path")
                        .and_then(toml::Value::as_str)
                        .unwrap_or("/");
                    let source = runtime_dir
                        .join("data")
                        .join(name)
                        .join(disk)
                        .join(base.trim_start_matches('/'));
                    if base.split('/').any(|s| s == "..") {
                        bail!("storage base-path traversal");
                    }
                    std::fs::create_dir_all(&source)?;
                    let target = v
                        .get("mount-path")
                        .and_then(toml::Value::as_str)
                        .context("storage mount-path missing")?;
                    mounts.push(json!({"type":"bind","source":source,"target":target,"read_only":v.get("read-only").and_then(toml::Value::as_bool).unwrap_or(false)}));
                }
            }
            if let Some(deps) = table.get("depends_on") {
                for dep in strings(deps)? {
                    depends.insert(
                        format!("{name}-{dep}"),
                        json!({"condition":"service_started"}),
                    );
                }
            }
            let port_specs = if is_main {
                &cfg.workload.ports
            } else {
                let dep = service_name.strip_prefix(&format!("{name}-")).unwrap();
                &cfg.dependencies[dep].ports
            };
            for port in port_specs {
                if cfg!(target_os = "linux") {
                    let parsed = atakit_workload::config::parse_port_spec(port)
                        .map_err(anyhow::Error::msg)?;
                    if parsed
                        .container
                        .is_some_and(|container| container != parsed.host)
                    {
                        bail!("Linux Compose uses host networking and cannot remap port `{port}` for `{service_name}`; use equal host/container ports");
                    }
                }
                let key = port.split(':').next().unwrap();
                if !host_ports.insert(key.to_string()) {
                    bail!("duplicate Compose host port {key}");
                }
            }
            service.insert("ports".into(), json!(port_specs));
            service.insert("environment".into(), Value::Object(env));
            service.insert("volumes".into(), json!(mounts));
            service.insert("depends_on".into(), Value::Object(depends));
            service.insert(
                "extra_hosts".into(),
                json!(["host.docker.internal:host-gateway"]),
            );
            if cfg!(target_os = "linux") {
                service.insert("network_mode".into(), json!("host"));
                service.remove("ports");
                // Host networking has no Compose DNS; retain workload/dependency names locally.
                let mut aliases = vec![
                    format!("{name}:127.0.0.1"),
                    "host.docker.internal:127.0.0.1".into(),
                ];
                for dep in cfg.dependencies.keys() {
                    aliases.push(format!("{dep}:127.0.0.1"));
                    aliases.push(format!("{name}-{dep}:127.0.0.1"));
                }
                service.insert("extra_hosts".into(), json!(aliases));
            }
            services.insert(service_name, Value::Object(service));
        }
    }
    let first = names.iter().min().context("no workload selected")?;
    let project_dir = &endpoints.select(Some(first))?.1.workload_dir;
    Ok(
        json!({"name":project_name(runtime_dir, &names, project_dir)?,"services":services,"volumes":volumes}),
    )
}
fn strings(v: &toml::Value) -> Result<Vec<&str>> {
    if let Some(s) = v.as_str() {
        return Ok(vec![s]);
    }
    v.as_array()
        .context("expected string or array")?
        .iter()
        .map(|s| s.as_str().context("expected string"))
        .collect()
}
fn image(value: &toml::Value, dir: &Path, out: &mut Map<String, Value>) -> Result<()> {
    if let Some(s) = value.as_str() {
        out.insert("image".into(), json!(s));
        return Ok(());
    }
    let table = value.as_table().context("invalid image source")?;
    if let Some(context) = table.get("build").and_then(toml::Value::as_str) {
        let mut build = json!({"context":dir.join(context)});
        if let Some(file) = table.get("containerfile").and_then(toml::Value::as_str) {
            build["dockerfile"] = json!(dir.join(file));
        }
        if let Some(args) = table.get("args") {
            build["args"] = serde_json::to_value(args)?;
        }
        out.insert("build".into(), build);
        Ok(())
    } else {
        bail!("Compose needs a registry image or build source; load a file image and give it a tag first")
    }
}

fn apply_platform(document: &mut Value, platform: Option<&str>) {
    if let Some(platform) = platform {
        if let Some(services) = document["services"].as_object_mut() {
            for service in services.values_mut() {
                service["platform"] = json!(platform);
            }
        }
    }
}

#[cfg(test)]
mod platform_tests {
    use super::*;

    #[test]
    fn platform_applies_to_builds_dependencies_and_bridges_only_when_selected() {
        let original = json!({"services": {
            "app": {"build": {"context": "."}},
            "dependency": {"image": "redis:7"},
            "bridge": {"image": "alpine:3"}
        }});
        let mut document = original.clone();
        apply_platform(&mut document, None);
        assert_eq!(document, original);
        apply_platform(&mut document, Some("linux/amd64"));
        for service in document["services"].as_object().unwrap().values() {
            assert_eq!(service["platform"], "linux/amd64");
        }
        assert_eq!(
            document["services"]["app"]["build"],
            original["services"]["app"]["build"]
        );
    }
}

fn container_rpc_url(raw: &str, host_network: bool) -> Result<String> {
    let mut url = url::Url::parse(raw).context("invalid emulator RPC URL")?;
    if !host_network {
        url.set_host(Some("host.docker.internal"))
            .map_err(|_| anyhow::anyhow!("cannot set container host for emulator RPC URL"))?;
    }
    Ok(url.into())
}

#[cfg(test)]
mod rpc_tests {
    use super::*;

    #[test]
    fn rpc_uses_host_network_or_container_gateway_and_preserves_port_and_path() {
        let rpc = "http://127.0.0.1:18546/rpc";
        assert_eq!(container_rpc_url(rpc, true).unwrap(), rpc);
        assert_eq!(
            container_rpc_url(rpc, false).unwrap(),
            "http://host.docker.internal:18546/rpc"
        );
        assert!(container_rpc_url("invalid", false).is_err());
    }
}

#[cfg(test)]
mod project_name_tests {
    use super::*;

    #[test]
    fn project_name_includes_sanitized_directory_and_six_hex_digits() {
        let runtime = tempfile::tempdir().unwrap();
        for (path, expected) in [
            ("/work/Validator Guardian", "validator-guardian"),
            ("/work/My_Project", "my_project"),
            ("/work/项目", "project"),
        ] {
            let name = project_name(runtime.path(), &["app".into()], Path::new(path)).unwrap();
            let prefix = format!("aemu-{expected}-");
            let hash = name.strip_prefix(&prefix).unwrap();
            assert_eq!(hash.len(), 6);
            assert!(hash.bytes().all(|c| c.is_ascii_hexdigit()));
        }
        let a = ["app".into(), "other".into()];
        let b = ["other".into(), "app".into()];
        let project = Path::new("/work/example");
        assert_eq!(
            project_name(runtime.path(), &a, project).unwrap(),
            project_name(runtime.path(), &b, project).unwrap()
        );
        assert_ne!(
            project_name(runtime.path(), &a, project).unwrap(),
            project_name(runtime.path(), &["app".into()], project).unwrap()
        );
        let second = tempfile::tempdir().unwrap();
        assert_ne!(
            project_name(runtime.path(), &a, project).unwrap(),
            project_name(second.path(), &a, project).unwrap()
        );
    }
}
