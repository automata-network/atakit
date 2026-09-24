//! Owned native daemon, private control protocol and paired chain/key checkpoints.
use crate::{
    chain::{RegisteredSession, RegistryContext, SessionEngine},
    config::LaunchConfig,
    endpoints::{redact_url, EndpointInfo, WorkloadEndpoint},
    fork::{AnvilFork, ForkOptions, ForkSnapshot},
    portal::{self, PortalState},
};
use alloy_primitives::B256;
use anyhow::{bail, Context, Result};
use atakit_attestation::signing;
use automata_tee_workload_measurement::stubs::AlgoId;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{watch, RwLock},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct PreparedLaunch {
    pub launch: LaunchConfig,
    pub session_registry: String,
    pub workload_registry: Option<String>,
    pub base_image_registry: Option<String>,
    pub publisher_secret: [u8; 32],
    pub owners: BTreeMap<String, [u8; 32]>,
}
#[derive(Serialize, Deserialize)]
struct Checkpoint {
    version: u32,
    prepared: PreparedLaunch,
    snapshot: ForkSnapshot,
    dump: String,
    sessions: BTreeMap<String, RegisteredSession>,
    disabled: Vec<String>,
    config_hashes: BTreeMap<String, String>,
}
pub fn private_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("empty runtime path");
    }
    let mut prefix = PathBuf::new();
    for c in path.components() {
        prefix.push(c);
        if let Ok(m) = std::fs::symlink_metadata(&prefix) {
            if m.file_type().is_symlink() {
                bail!("symlink directory is not allowed: {}", prefix.display());
            }
        }
    }
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub fn write_private(path: &Path, value: &impl Serialize) -> Result<()> {
    write_private_bytes(path, &serde_json::to_vec_pretty(value)?)
}

/// Atomically writes private runtime data with owner-only permissions.
pub(crate) fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
/// Persisted while holding the runtime lock; only exact, non-listening sockets may be recovered.
#[derive(Clone, Serialize, Deserialize)]
pub struct SocketOwnership {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
}
pub fn recover_stale_socket(record: &SocketOwnership) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(&record.path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != record.device
        || metadata.ino() != record.inode
    {
        return Ok(false);
    }
    match std::os::unix::net::UnixStream::connect(&record.path) {
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    let current = std::fs::symlink_metadata(&record.path)?;
    if current.file_type().is_socket()
        && current.dev() == record.device
        && current.ino() == record.inode
    {
        std::fs::remove_file(&record.path)?;
        return Ok(true);
    }
    Ok(false)
}
pub struct OwnedSocket {
    pub listener: Option<UnixListener>,
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl OwnedSocket {
    pub fn ownership(&self) -> SocketOwnership {
        SocketOwnership {
            path: self.path.clone(),
            device: self.device,
            inode: self.inode,
        }
    }
    pub fn bind(path: &Path) -> Result<Self> {
        if path.as_os_str().is_empty() {
            bail!("empty socket path");
        }
        // Inspect parents, but never change permissions on workload directories.
        for parent in path.ancestors().skip(1) {
            if std::fs::symlink_metadata(parent)?.file_type().is_symlink() {
                bail!("socket parent is a symlink");
            }
        }
        let listener = UnixListener::bind(path).with_context(|| {
            format!(
                "cannot bind {}; use --output-socket for another path",
                path.display()
            )
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let m = std::fs::symlink_metadata(path)?;
        Ok(Self {
            listener: Some(listener),
            path: path.into(),
            device: m.dev(),
            inode: m.ino(),
        })
    }
}
impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if let Ok(m) = std::fs::symlink_metadata(&self.path) {
            if m.dev() == self.device && m.ino() == self.inode {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}
pub async fn control(dir: &Path, operation: &str, workload: Option<&str>) -> Result<Value> {
    let endpoints: EndpointInfo =
        serde_json::from_slice(&std::fs::read(dir.join("endpoints.json"))?)?;
    let mut stream = UnixStream::connect(dir.join("control.sock"))
        .await
        .context("emulator is not running")?;
    let mut message = serde_json::to_vec(
        &json!({"environment_id":endpoints.environment_id,"operation":operation,"workload":workload}),
    )?;
    message.push(b'\n');
    stream.write_all(&message).await?;
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(180),
        BufReader::new(stream).read_line(&mut line),
    )
    .await??;
    let value: Value = serde_json::from_str(&line)?;
    if let Some(e) = value.get("error") {
        bail!("{}", e.as_str().unwrap_or("control failed"));
    }
    Ok(value)
}
fn hashes(launch: &LaunchConfig) -> Result<BTreeMap<String, String>> {
    launch
        .workloads
        .iter()
        .map(|w| {
            Ok((w.name.clone(), {
                let measurement = crate::inputs::measurement(&w.config_file, &w.workload_dir)?;
                if w.platform_profile.is_none() && w.measurement_variant.is_none() {
                    hex::encode(measurement)
                } else {
                    use sha2::{Digest, Sha256};
                    hex::encode(Sha256::digest(serde_json::to_vec(&(
                        measurement,
                        &w.platform_profile,
                        &w.measurement_variant,
                    ))?))
                }
            }))
        })
        .collect()
}
fn compatible(old: &PreparedLaunch, new: &PreparedLaunch) -> bool {
    old.session_registry == new.session_registry
        && old.workload_registry == new.workload_registry
        && old.base_image_registry == new.base_image_registry
        && old.launch.chain == new.launch.chain
        && old.launch.fork_url == new.launch.fork_url
        && old.publisher_secret == new.publisher_secret
}
fn validate_checkpoint(
    old: &Checkpoint,
    new: &PreparedLaunch,
    hashes: &BTreeMap<String, String>,
) -> Result<()> {
    let mut changes = Vec::new();
    if old.version != 1 {
        changes.push(format!(
            "checkpoint format: saved {}, supported 1",
            old.version
        ));
    }
    if let Some(block) = new.launch.fork_block {
        if block != old.snapshot.block_number {
            changes.push(format!(
                "fork-block: saved {}, requested {block}",
                old.snapshot.block_number
            ));
        }
    }
    if !compatible(&old.prepared, new) {
        let previous = &old.prepared;
        for (name, before, after) in [
            (
                "chain",
                format!("{:?}", previous.launch.chain),
                format!("{:?}", new.launch.chain),
            ),
            (
                "fork-url",
                redact_url(&previous.launch.fork_url),
                redact_url(&new.launch.fork_url),
            ),
            (
                "SessionRegistry",
                previous.session_registry.clone(),
                new.session_registry.clone(),
            ),
            (
                "WorkloadRegistry",
                format!("{:?}", previous.workload_registry),
                format!("{:?}", new.workload_registry),
            ),
            (
                "BaseImageRegistry",
                format!("{:?}", previous.base_image_registry),
                format!("{:?}", new.base_image_registry),
            ),
        ] {
            if before != after {
                changes.push(format!("{name}: saved {before}, requested {after}"));
            }
        }
        if previous.launch.fork_url != new.launch.fork_url
            && redact_url(&previous.launch.fork_url) == redact_url(&new.launch.fork_url)
        {
            changes.push("fork-url credentials or query changed (values omitted)".into());
        }
        if previous.publisher_secret != new.publisher_secret {
            changes.push("publisher signing key changed (values omitted)".into());
        }
    }
    for w in &new.launch.workloads {
        let previous = old
            .prepared
            .launch
            .workloads
            .iter()
            .find(|p| p.name == w.name);
        let mut selection_changed = false;
        if let Some(previous) = previous {
            for (field, before, after) in [
                (
                    "platform-profile",
                    &previous.platform_profile,
                    &w.platform_profile,
                ),
                (
                    "measurement-variant",
                    &previous.measurement_variant,
                    &w.measurement_variant,
                ),
            ] {
                if before != after {
                    selection_changed = true;
                    changes.push(format!(
                        "workload `{}` {field}: saved {}, requested {}",
                        w.name,
                        before.as_deref().unwrap_or("<not specified>"),
                        after.as_deref().unwrap_or("<not specified>")
                    ));
                }
            }
        }
        if old
            .config_hashes
            .get(&w.name)
            .is_some_and(|h| Some(h) != hashes.get(&w.name))
            && !selection_changed
        {
            changes.push(format!(
                "workload `{}` TOML or measured-data changed",
                w.name
            ));
        }
        if old
            .prepared
            .owners
            .get(&w.name)
            .is_some_and(|key| Some(key) != new.owners.get(&w.name))
        {
            changes.push(format!(
                "workload `{}` owner signing key changed (values omitted)",
                w.name
            ));
        }
    }
    if !changes.is_empty() {
        bail!("Cannot resume emulator checkpoint:\n  - {}\n\nRestore the saved configuration to resume the existing session. To start fresh, run `atakit emulator down --runtime-dir {}` (removes local chain/session state; keeps data/), then run `emulator up` again, or choose a new --runtime-dir. `stop` preserves the checkpoint and does not resolve configuration conflicts.", changes.join("\n  - "), new.launch.runtime_dir.display());
    }
    Ok(())
}

async fn checkpoint(
    dir: &Path,
    p: &PreparedLaunch,
    b: &AnvilFork,
    s: &BTreeMap<String, RegisteredSession>,
    disabled: &[String],
    config_hashes: &BTreeMap<String, String>,
) -> Result<()> {
    write_private(
        &dir.join("checkpoint.json"),
        &Checkpoint {
            version: 1,
            prepared: p.clone(),
            snapshot: b.snapshot.clone(),
            dump: b.dump().await?,
            sessions: s.clone(),
            disabled: disabled.to_vec(),
            config_hashes: config_hashes.clone(),
        },
    )
}
pub async fn engine(b: &AnvilFork, p: &PreparedLaunch) -> Result<SessionEngine> {
    let r =
        RegistryContext::patch(&b.rpc, p.session_registry.parse()?, b.snapshot.chain_id).await?;
    if p.workload_registry
        .as_ref()
        .is_some_and(|a| a.parse().ok() != Some(r.workload))
        || p.base_image_registry
            .as_ref()
            .is_some_and(|a| a.parse().ok() != Some(r.base_image))
    {
        bail!("configured Registry addresses disagree with SessionRegistry getters");
    }
    SessionEngine::new(b.rpc.clone(), r).await
}
pub async fn run_foreground(p: PreparedLaunch) -> Result<()> {
    run_foreground_with_startup_lock(p, None).await
}
pub async fn run_foreground_with_startup_lock(
    p: PreparedLaunch,
    startup_lock: Option<std::fs::File>,
) -> Result<()> {
    let dir = &p.launch.runtime_dir;
    private_dir(dir)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("runtime.lock"))?;
    lock.try_lock_exclusive()
        .context("another emulator owns this runtime directory")?;
    drop(startup_lock);
    let manifest = dir.join("sockets.private.json");
    if manifest.exists() {
        let records: Vec<SocketOwnership> = serde_json::from_slice(&std::fs::read(&manifest)?)?;
        for record in records {
            recover_stale_socket(&record)?;
        }
    }
    let workload_names: Vec<_> = p.launch.workloads.iter().map(|w| w.name.clone()).collect();
    for name in &workload_names {
        crate::config::validate_name(name)?;
    }
    write_private(&dir.join("workload-dirs.private.json"), &workload_names)?;
    let mut control_socket = OwnedSocket::bind(&dir.join("control.sock"))?;

    let mut sockets = Vec::new();
    for w in &p.launch.workloads {
        let config = atakit_workload::config::WorkloadConfig::from_file(&w.config_file)?;
        crate::environment::validate_features(&config)?;
        sockets.push(
            if config.workload.atakit_portal
                || config.dependencies.values().any(|dep| dep.atakit_portal)
            {
                if w.output_socket == dir.join(&w.name).join("root/run/atakit-portal.sock") {
                    private_dir(w.output_socket.parent().unwrap())?;
                }
                Some(OwnedSocket::bind(&w.output_socket)?)
            } else {
                None
            },
        );
    }
    let records: Vec<_> = std::iter::once(control_socket.ownership())
        .chain(
            sockets
                .iter()
                .filter_map(|socket| socket.as_ref().map(OwnedSocket::ownership)),
        )
        .collect();
    write_private(&manifest, &records)?;
    let mut config_hashes = hashes(&p.launch)?;
    let mut frozen = p.launch.workloads.clone();
    for w in &mut frozen {
        let source = w.workload_dir.clone();
        let target = dir.join(&w.name);
        private_dir(&target)?;
        let parsed = atakit_workload::config::WorkloadConfig::from_file(&w.config_file)?;
        let config_bytes = std::fs::read(&w.config_file)?;
        w.config_file = target.join("atakit-workload.toml");
        std::fs::write(&w.config_file, config_bytes)?;
        for relative in crate::inputs::measured_files(
            &source.join("measured-data"),
            parsed.measured_data_paths(),
        )? {
            let relative = relative.as_path();
            if relative
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                bail!("measured data traversal is not supported");
            }
            let dest = target.join("measured-data").join(relative);
            private_dir(dest.parent().unwrap())?;
            std::fs::copy(source.join("measured-data").join(relative), dest)?;
        }
        w.workload_dir = target;
    }
    let mut application_envs = BTreeMap::new();
    for w in &p.launch.workloads {
        let parsed = atakit_workload::config::WorkloadConfig::from_file(&w.config_file)?;
        let all = crate::environment::load(
            &parsed,
            &w.workload_dir,
            &dir.join(&w.name).join("env-allowlists.json"),
        )?;
        let environment = all[&parsed.workload.name].clone();
        application_envs.insert(w.name.clone(), environment);
    }
    let saved = if dir.join("checkpoint.json").exists() {
        Some(serde_json::from_slice::<Checkpoint>(&std::fs::read(
            dir.join("checkpoint.json"),
        )?)?)
    } else {
        None
    };
    if let Some(old) = &saved {
        validate_checkpoint(old, &p, &config_hashes)?;
    }
    // Checkpoints keep metadata for omitted sessions, although the live launch list stays fixed.
    let mut checkpoint_prepared = p.clone();
    if let Some(old) = &saved {
        for (name, owner) in &old.prepared.owners {
            checkpoint_prepared
                .owners
                .entry(name.clone())
                .or_insert(*owner);
        }
        for (name, hash) in &old.config_hashes {
            config_hashes
                .entry(name.clone())
                .or_insert_with(|| hash.clone());
        }
    }
    let mut b = AnvilFork::spawn(ForkOptions {
        upstream_url: p.launch.fork_url.clone(),
        block_number: saved
            .as_ref()
            .map(|s| s.snapshot.block_number)
            .or(p.launch.fork_block),
        port: p.launch.anvil_port,
        log_path: dir.join("anvil.log"),
        load_state: None,
    })
    .await?;
    if saved.as_ref().is_some_and(|s| {
        s.snapshot.block_hash != b.snapshot.block_hash
            || s.snapshot.chain_id != b.snapshot.chain_id
            || s.snapshot.upstream_instance_id != b.snapshot.upstream_instance_id
    }) {
        bail!("UpstreamSnapshotUnavailable: saved fork anchor changed");
    }
    if let Some(old) = &saved {
        if b.rpc.request("anvil_loadState", json!([old.dump])).await? != true {
            bail!("B rejected saved chain state");
        }
    }
    let mut engine = engine(&b, &p).await?;
    let mut sessions = saved
        .as_ref()
        .map(|s| s.sessions.clone())
        .unwrap_or_default();
    let mut disabled = saved
        .as_ref()
        .map(|s| s.disabled.clone())
        .unwrap_or_default();
    let rpc_url = format!("http://127.0.0.1:{}", p.launch.anvil_port);
    let public = signing::derive_public_key_uncompressed(&p.publisher_secret)?;
    let publisher_fp = B256::from(atakit_cvm_encoding::key_fingerprint(
        AlgoId::Es256K as u8,
        &public,
    ))
    .to_string();
    let mut endpoints = EndpointInfo {
        environment_id: format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ),
        upstream_rpc_url: redact_url(&p.launch.fork_url),
        anchor_number: b.snapshot.block_number,
        anchor_hash: b.snapshot.block_hash.clone(),
        rpc_url: rpc_url.clone(),
        chain_id: b.snapshot.chain_id,
        session_registry: engine.registry.session.to_string(),
        workload_registry: engine.registry.workload.to_string(),
        base_image_registry: engine.registry.base_image.to_string(),
        state: "initializing".into(),
        workloads: BTreeMap::new(),
    };
    let (shutdown, rx) = watch::channel(false);
    let mut states: BTreeMap<String, PortalState> = BTreeMap::new();
    let mut public_states: BTreeMap<String, portal::PublicStatus> = BTreeMap::new();
    for (w, socket) in p.launch.workloads.iter().zip(&mut sockets) {
        private_dir(&dir.join("data").join(&w.name))?;
        let state = Arc::new(RwLock::new(None));
        let mut document = portal::status_document(None);
        let parsed = atakit_workload::config::WorkloadConfig::from_file(&w.config_file)?;
        document["started_at"] = json!(chrono::Utc::now().to_rfc3339());
        document["workload_ref"] = json!(format!(
            "{}/{}:{}",
            publisher_fp, parsed.workload.name, parsed.workload.version
        ));
        document["platform"]["machine_type"] =
            json!(w.measurement_variant.as_deref().unwrap_or("unknown"));
        let public_status = Arc::new(RwLock::new(document));
        public_states.insert(w.name.clone(), public_status.clone());
        if let Some(socket) = socket {
            tokio::spawn(portal::serve_configured(
                socket.listener.take().unwrap(),
                state.clone(),
                Some(public_status),
                true,
                rx.clone(),
            ));
        }
        states.insert(w.name.clone(), state);
        endpoints.workloads.insert(
            w.name.clone(),
            WorkloadEndpoint {
                version: Some(parsed.workload.version.clone()),
                config_file: w.config_file.clone(),
                workload_dir: w.workload_dir.clone(),
                portal_socket: w.output_socket.clone(),
                owner_fingerprint: None,
                publisher_fingerprint: publisher_fp.clone(),
                workload_id: None,
                session_id: None,
                state: "initializing".into(),
                error: None,
                env: BTreeMap::new(),
            },
        );
    }
    for w in &p.launch.workloads {
        let parsed = atakit_workload::config::WorkloadConfig::from_file(&w.config_file)?;
        let snapshot = &frozen
            .iter()
            .find(|f| f.name == w.name)
            .unwrap()
            .workload_dir;
        let exported = endpoints.workloads.get_mut(&w.name).unwrap();
        exported.env = crate::environment::native(
            &parsed,
            application_envs[&w.name].clone(),
            &dir.join("data").join(&w.name),
            snapshot,
            &w.workload_dir,
            &rpc_url,
        )?;
        let result = async {
            if disabled.contains(&w.name) {
                bail!("session is revoked; refresh creates fresh sessions");
            }
            if let Some(s) = sessions.get(&w.name) {
                if !engine.active(s.session_id).await? {
                    bail!("saved session is inactive; rotate explicitly");
                }
                // Validates the saved signing key against the registered session identifier.
                let owner_public = signing::derive_public_key_uncompressed(&p.owners[&w.name])?;
                if B256::from(atakit_cvm_encoding::key_fingerprint(
                    AlgoId::Es256K as u8,
                    &owner_public,
                )) != s.owner_fp
                {
                    bail!("saved session owner differs from selected signing source");
                }
                let config = atakit_workload::config::WorkloadConfig::from_file(&w.config_file)?;
                let publisher = B256::from(atakit_cvm_encoding::key_fingerprint(
                    AlgoId::Es256K as u8,
                    &public,
                ));
                let expected = atakit_cvm_encoding::workload_id(&atakit_cvm_types::AppRef::new(
                    publisher.0,
                    &config.workload.name,
                    &config.workload.version,
                ));
                if s.workload_id.0 != expected {
                    bail!("saved session workload differs from launch input");
                }
                validate_saved(&engine, s).await?;
                s.portal_session(&engine.registry, &rpc_url)?;
            } else {
                let s = engine
                    .register_with_publisher(
                        frozen.iter().find(|f| f.name == w.name).unwrap(),
                        &p.publisher_secret,
                        &p.owners[&w.name],
                    )
                    .await?;
                sessions.insert(w.name.clone(), s);
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        publish(&w.name, result, &sessions, &states, &mut endpoints, &engine).await;
    }
    endpoints.state = readiness(&endpoints);
    write_endpoints(dir, &endpoints, &public_states, &sessions, &p).await?;
    checkpoint(
        dir,
        &checkpoint_prepared,
        &b,
        &sessions,
        &disabled,
        &config_hashes,
    )
    .await?;
    eprintln!(
        "emulator state={} rpc={}",
        endpoints.state, endpoints.rpc_url
    );
    if p.launch.foreground {
        println!("{}", serde_json::to_string_pretty(&endpoints)?);
    }
    let listener = control_socket.listener.take().unwrap();
    let mut bridges: BTreeMap<String, (u16, String, tokio::task::JoinHandle<()>)> = BTreeMap::new();
    let mut checkpoint_valid = true;
    let mut clean_shutdown = false;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=term.recv()=>break,
            _=tick.tick()=> {
                if !checkpoint_valid { continue; }
                if !b.is_running()? || b.check_upstream().await.is_err() || b.rpc.reads().chain_id().await.is_err() {
                    for s in states.values(){*s.write().await=None;}
                    endpoints.state="upstream_unavailable".into();
                    for w in endpoints.workloads.values_mut(){w.state="not_ready".into();}
                    write_endpoints(dir,&endpoints,&public_states,&sessions,&p).await?;
                } else {
                    for (name,endpoint) in &mut endpoints.workloads {
                        if endpoint.state=="ready" {
                            if let Some(session)=sessions.get(name) {
                                if !engine.active(session.session_id).await.unwrap_or(false){
                                    *states[name].write().await=None;endpoint.state="inactive".into();
                                }
                            }
                        }
                    }
                    if !matches!(endpoints.state.as_str(),"upstream_unavailable"|"refresh_failed") {endpoints.state=readiness(&endpoints);}
                    write_endpoints(dir,&endpoints,&public_states,&sessions,&p).await?;
                }
            },
            accepted=listener.accept()=> {
                let (stream,_)=accepted?;
                let mut reader=BufReader::new(stream); let mut line=String::new();
                if tokio::time::timeout(Duration::from_secs(2),reader.read_line(&mut line)).await.is_err(){continue;}
                let request:Value=serde_json::from_str(&line).unwrap_or(Value::Null);
                let op=request["operation"].as_str().unwrap_or("");
                let result=async {
                    if request["environment_id"].as_str()!=Some(&endpoints.environment_id){bail!("environment identity mismatch");}
                    match op {
                        "status"=>Ok(serde_json::to_value(&endpoints)?),
                        "bridge"=>{
                            let (name,w)=endpoints.select(request["workload"].as_str())?;
                            let input=frozen.iter().find(|input| &input.name==name).context("missing frozen workload")?;
                            let cfg=atakit_workload::config::WorkloadConfig::from_file(&input.config_file)?;
                            if !cfg.workload.atakit_portal && !cfg.dependencies.values().any(|dep| dep.atakit_portal) {bail!("workload `{name}` has no service with atakit-portal=true");}
                            if !bridges.contains_key(name){bridges.insert(name.clone(),crate::compose::start_bridge(w.portal_socket.clone()).await?);}
                            Ok(json!({"portal_port":bridges[name].0,"token":bridges[name].1}))
                        },
                        "stop"=>{if checkpoint_valid {checkpoint(dir,&checkpoint_prepared,&b,&sessions,&disabled,&config_hashes).await.context("could not save state; use emulator down to discard runtime state")?;}Ok(json!({"state":"stopping"}))},
                        "down"=>{clean_shutdown=true;Ok(json!({"state":"stopping"}))},
                        "rotate"|"revoke"=>{
                            if !checkpoint_valid || endpoints.state=="refresh_failed" {bail!("refresh failed; complete refresh before session operations");}
                            if endpoints.state=="upstream_unavailable" || !b.is_running()? || b.check_upstream().await.is_err() {
                                for state in states.values(){*state.write().await=None;}
                                endpoints.state="upstream_unavailable".into();
                                for workload in endpoints.workloads.values_mut(){workload.state="not_ready".into();}
                                write_endpoints(dir,&endpoints,&public_states,&sessions,&p).await?;
                                bail!("upstream snapshot unavailable; complete refresh before session operations");
                            }
                            let name=endpoints.select(request["workload"].as_str())?.0.clone();
                            eprintln!("workload={} operation={}",name,op);
                            let old=sessions.get(&name).context("instance has no committed session")?;
                            if op=="revoke" {engine.revoke(old,&p.owners[&name]).await?;disabled.push(name.clone());*states[&name].write().await=None;endpoints.workloads.get_mut(&name).unwrap().state="revoked".into();}
                            else {if disabled.contains(&name){bail!("revoked sessions cannot rotate; refresh creates fresh sessions");}let next=engine.rotate(old,&p.owners[&name]).await?;sessions.insert(name.clone(),next);disabled.retain(|n|n!=&name);publish(&name,Ok(()),&sessions,&states,&mut endpoints,&engine).await;}
                            checkpoint(dir,&checkpoint_prepared,&b,&sessions,&disabled,&config_hashes).await?;
                            endpoints.state=readiness(&endpoints);write_endpoints(dir,&endpoints,&public_states,&sessions,&p).await?;Ok(serde_json::to_value(&endpoints)?)
                        },
                        "refresh"=>{
                            eprintln!("emulator operation=refresh");
                            for s in states.values(){*s.write().await=None;}
                            endpoints.state="refreshing".into();
                            for w in endpoints.workloads.values_mut(){w.state="not_ready".into();}
                            write_endpoints(dir,&endpoints,&public_states,&sessions,&p).await?;
                            if checkpoint_valid {
                                checkpoint(dir,&checkpoint_prepared,&b,&sessions,&disabled,&config_hashes).await?;
                                std::fs::copy(dir.join("checkpoint.json"),dir.join("checkpoint.previous.json"))?;
                            }
                            checkpoint_valid=false;
                            sessions.clear();disabled.clear();
                            for w in endpoints.workloads.values_mut(){w.session_id=None;w.workload_id=None;}
                            b.stop().await?;
                            b=AnvilFork::spawn(ForkOptions{upstream_url:p.launch.fork_url.clone(),block_number:None,port:p.launch.anvil_port,log_path:dir.join("anvil.log"),load_state:None}).await?;
                            engine=self::engine(&b,&p).await?;
                            checkpoint_valid=true;
                            for w in &p.launch.workloads {
                                let result=engine.register_with_publisher(frozen.iter().find(|f|f.name==w.name).unwrap(),&p.publisher_secret,&p.owners[&w.name]).await.map(|s|{sessions.insert(w.name.clone(),s);});
                                publish(&w.name,result,&sessions,&states,&mut endpoints,&engine).await;
                            }
                            endpoints.anchor_number=b.snapshot.block_number;endpoints.anchor_hash=b.snapshot.block_hash.clone();endpoints.chain_id=b.snapshot.chain_id;endpoints.state=readiness(&endpoints);
                            checkpoint(dir,&checkpoint_prepared,&b,&sessions,&disabled,&config_hashes).await?;write_endpoints(dir,&endpoints,&public_states,&sessions,&p).await?;Ok(serde_json::to_value(&endpoints)?)
                        },
                        _=>bail!("unknown control operation"),
                    }
                }.await;
                if op=="refresh" && result.is_err(){
                    endpoints.state="refresh_failed".into();
                    write_endpoints(dir,&endpoints,&public_states,&sessions,&p).await?;
                }
                let should_stop=matches!(op,"stop"|"down") && result.is_ok();
                let response=result.unwrap_or_else(|e|json!({"error":e.to_string()}));
                let mut bytes=serde_json::to_vec(&response)?;bytes.push(b'\n');let _=reader.get_mut().write_all(&bytes).await;
                if should_stop {break;}
            }
        }
    }
    for s in states.values() {
        *s.write().await = None;
    }
    let saved = if checkpoint_valid && !clean_shutdown {
        checkpoint(
            dir,
            &checkpoint_prepared,
            &b,
            &sessions,
            &disabled,
            &config_hashes,
        )
        .await
    } else {
        Ok(())
    };
    for (_, _, handle) in bridges.values() {
        handle.abort();
    }
    let _ = shutdown.send(true);
    b.stop().await?;
    drop(listener);
    drop(control_socket);
    drop(sockets);
    if clean_shutdown {
        crate::lifecycle::cleanup(dir, false)?;
    } else {
        endpoints.state = "stopped".into();
        write_endpoints(dir, &endpoints, &public_states, &sessions, &p).await?;
    }
    saved
}
fn readiness(e: &EndpointInfo) -> String {
    if e.workloads.values().all(|w| w.state == "ready") {
        "ready"
    } else {
        "degraded"
    }
    .into()
}
async fn write_endpoints(
    dir: &Path,
    endpoints: &EndpointInfo,
    public: &BTreeMap<String, portal::PublicStatus>,
    sessions: &BTreeMap<String, RegisteredSession>,
    prepared: &PreparedLaunch,
) -> Result<()> {
    for (name, endpoint) in &endpoints.workloads {
        let mut document = public[name].write().await;
        let failed = matches!(endpoint.state.as_str(), "failed" | "inactive" | "revoked")
            || matches!(
                endpoints.state.as_str(),
                "upstream_unavailable" | "refresh_failed"
            );
        document["state"] = json!(if endpoint.state == "ready" {
            "Running"
        } else if failed {
            "Failed"
        } else {
            "InitializingWorkload"
        });
        let detail = endpoint.error.clone().or_else(|| {
            failed.then(|| {
                format!(
                    "emulator state={}, workload state={}",
                    endpoints.state, endpoint.state
                )
            })
        });
        document["detail"] = json!(detail);
        document["workload_id"] = json!(endpoint.workload_id);
        document["chain"]["registry_address"] = json!(endpoints.session_registry);
        document["chain"]["chain_id"] = json!(endpoints.chain_id);
        document["chain"]["session_id"] = json!(endpoint.session_id);
        document["chain"]["status"] = json!(if endpoint.state == "ready" {
            "verified"
        } else if failed {
            "failed"
        } else {
            "pending"
        });
        document["chain"]["detail"] = json!(detail);
        document["chain"]["tx_hash"] = sessions
            .get(name)
            .map(|session| json!(session.registration_tx))
            .unwrap_or(Value::Null);
        document["base_image_id"] = sessions
            .get(name)
            .map(|session| json!(session.base_image_id))
            .unwrap_or(Value::Null);
        if let Some(session) = sessions.get(name) {
            // Read the startup-frozen manifest, never a newly edited source TOML.
            let path = dir.join(name).join("atakit-workload.toml");
            let config = atakit_workload::config::WorkloadConfig::from_file(&path)?;
            document["base_image_ref"] = config
                .workload
                .base_image
                .iter()
                .find(|reference| {
                    reference
                        .parse::<atakit_cvm_types::AppRef>()
                        .ok()
                        .is_some_and(|reference| {
                            atakit_cvm_encoding::base_image_id(&reference)
                                == session.base_image_id.0
                        })
                })
                .map(|reference| json!(reference))
                .unwrap_or(Value::Null);
            if let Some(input) = prepared.launch.workloads.iter().find(|w| &w.name == name) {
                if let Some(variant) = &input.measurement_variant {
                    document["platform"]["machine_type"] = json!(variant);
                }
            }
        }
    }
    write_private(&dir.join("endpoints.json"), endpoints)
}

async fn publish(
    name: &str,
    result: Result<()>,
    sessions: &BTreeMap<String, RegisteredSession>,
    states: &BTreeMap<String, PortalState>,
    e: &mut EndpointInfo,
    engine: &SessionEngine,
) {
    let w = e.workloads.get_mut(name).unwrap();
    match result.and_then(|()| sessions[name].portal_session(&engine.registry, &e.rpc_url)) {
        Ok(s) => {
            w.owner_fingerprint = Some(s.owner_fingerprint.to_string());
            w.workload_id = Some(s.workload_id.to_string());
            w.session_id = Some(s.session_id.to_string());
            w.state = "ready".into();
            w.error = None;
            eprintln!(
                "workload={} state=ready session={} transaction={}",
                name, s.session_id, sessions[name].registration_tx
            );
            *states[name].write().await = Some(s);
        }
        Err(err) => {
            w.state = "failed".into();
            w.error = Some(format!("{err:#}"));
            eprintln!("workload={} state=failed error={err:#}", name);
            *states[name].write().await = None;
        }
    }
}

async fn validate_saved(engine: &SessionEngine, s: &RegisteredSession) -> Result<()> {
    use crate::abi::getSessionOwnerCall;
    use alloy_sol_types::SolValue;
    let actual = crate::chain::read(
        &engine.rpc,
        engine.registry.session,
        crate::abi::getSessionCall {
            sessionId: s.session_id,
        },
    )
    .await?;
    let public = signing::derive_public_key_uncompressed(&s.session_secret)?;
    let fp = B256::from(atakit_cvm_encoding::key_fingerprint(
        AlgoId::Es256K as u8,
        &public,
    ));
    let evidence = crate::abi::SessionRegistry::AttestationEvidence::abi_decode(&s.evidence_abi)?;
    if evidence.sessionKey.key.as_ref() != public.as_slice() {
        bail!("checkpoint evidence session key mismatch");
    }
    let tpm = p256::ecdsa::SigningKey::from_slice(&s.tpm_secret)?;
    let tpm_public = tpm.verifying_key().to_encoded_point(false);
    let tpm_fp = B256::from(atakit_cvm_encoding::key_fingerprint(
        AlgoId::Es256 as u8,
        tpm_public.as_bytes(),
    ));
    let owner = crate::chain::read(
        &engine.rpc,
        engine.registry.session,
        getSessionOwnerCall {
            sessionId: s.session_id,
        },
    )
    .await?;
    if actual.sessionKeyFingerprint != fp
        || actual.tpmSigningKeyFingerprint != tpm_fp
        || owner != s.owner_fp
        || actual.workloadId != s.workload_id
        || actual.baseImageId != s.base_image_id
        || actual.platformProfileId != s.profile_id
        || actual.measurementVariantId != s.variant_id
    {
        bail!("checkpoint key or session identity does not match B");
    }
    Ok(())
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;
    fn saved() -> Checkpoint {
        serde_json::from_value(json!({
            "version":1,
            "prepared":{
                "launch":{"chain":"hoodi","fork_url":"http://localhost:8545","fork_block":null,"anvil_port":8546,
                    "runtime_dir":"/tmp/runtime","foreground":false,"owner_key":null,
                    "workloads":[{"name":"signer","config_file":"/app/atakit-workload.toml","workload_dir":"/app",
                        "output_socket":"/app/portal.sock","owner_key":null,"platform_profile":"gcp-tdx","measurement_variant":"c3-standard-4"}]},
                "session_registry":"0x1","workload_registry":null,"base_image_registry":null,
                "publisher_secret":vec![1;32],"owners":{"signer":vec![2;32]}},
            "snapshot":{"upstream_url":"http://localhost:8545","chain_id":560048,"block_number":100,
                "block_hash":"0xabc","upstream_instance_id":"instance"},
            "dump":"0x00","sessions":{},"disabled":[],"config_hashes":{"signer":"old"}
        })).unwrap()
    }
    #[test]
    fn omitted_platform_flags_show_saved_and_requested_values() {
        let old = saved();
        let mut new = old.prepared.clone();
        new.launch.workloads[0].platform_profile = None;
        new.launch.workloads[0].measurement_variant = None;
        let hashes = BTreeMap::from([("signer".into(), "new".into())]);
        let message = validate_checkpoint(&old, &new, &hashes)
            .unwrap_err()
            .to_string();
        assert!(message.contains("platform-profile: saved gcp-tdx, requested <not specified>"));
        assert!(
            message.contains("measurement-variant: saved c3-standard-4, requested <not specified>")
        );
        assert!(!message.contains("owner signing key changed"));
        assert!(message.contains("emulator down --runtime-dir"));
    }
    #[test]
    fn identifies_measured_input_and_owner_changes_without_printing_keys() {
        let old = saved();
        let mut new = old.prepared.clone();
        new.owners.insert("signer".into(), [77; 32]);
        let hashes = BTreeMap::from([("signer".into(), "new".into())]);
        let message = validate_checkpoint(&old, &new, &hashes)
            .unwrap_err()
            .to_string();
        assert!(message.contains("TOML or measured-data changed"));
        assert!(message.contains("owner signing key changed"));
        assert!(!message.contains("77"));
    }
    #[test]
    fn unchanged_checkpoint_is_accepted_and_rpc_credentials_are_redacted() {
        let mut old = saved();
        assert!(validate_checkpoint(&old, &old.prepared, &old.config_hashes).is_ok());
        old.prepared.launch.fork_url = "http://old-secret@localhost:8545?token=old-token".into();
        let mut new = old.prepared.clone();
        new.launch.fork_url = "http://new-secret@localhost:8545?token=new-token".into();
        let message = validate_checkpoint(&old, &new, &old.config_hashes)
            .unwrap_err()
            .to_string();
        assert!(message.contains("credentials or query changed"));
        for secret in ["old-secret", "new-secret", "old-token", "new-token"] {
            assert!(!message.contains(secret));
        }
    }
}
