use crate::config::{Config, KeyMode, KeyType};
use anyhow::{bail, Context, Result};
use atakit_cloud::cli::DiskUnlockArgs;
use atakit_core::Env;
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    time::Duration,
};
use zeroize::Zeroizing;

const MAX_MEASUREMENT_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn prompt_label(destination: &str, disk: &str) -> String {
    format!("Passphrase for disk '{disk}' on {destination}: ")
}

// Bytes retains this owner until the HTTP body (including all clones) drops.
// Do not copy the JSON into an ordinary Vec before handing it to reqwest.
struct SecretBody(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for SecretBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
fn secret_http_body(body: Zeroizing<Vec<u8>>) -> bytes::Bytes {
    bytes::Bytes::from_owner(SecretBody(body))
}

fn erase_last_character(secret: &mut Vec<u8>) {
    use zeroize::Zeroize;
    if secret.is_empty() {
        return;
    }
    let mut start = secret.len() - 1;
    while start > 0 && secret[start] & 0xc0 == 0x80 {
        start -= 1;
    }
    secret[start..].zeroize();
    secret.truncate(start);
}

pub async fn run(args: DiskUnlockArgs, env: &Env, config: &Config) -> Result<()> {
    validate_disk_name(&args.disk)?;
    let access = super::session_access::resolve_disk_unlock_access(
        &args.instance,
        args.target.as_deref(),
        &args.verification,
        env,
        config,
    )
    .await?;
    if access.verified_tls.manual_override().is_some() {
        bail!("disk unlock requires verified TLS attestation without a manual override");
    }
    let target = config
        .cloud
        .targets
        .get(&access.target_name)
        .context("target not found")?;
    let key_name = args
        .owner_key
        .as_deref()
        .or((!access.state.init_env.owner_key.is_empty())
            .then_some(access.state.init_env.owner_key.as_str()))
        .or(target.owner_key.as_deref())
        .context("configure a provisioned owner key or use --owner-key")?;
    let key = resolve_owner_key(key_name, config)?;
    let expected = crate::commands::workload::parse_workload_ref(
        &format!(
            "{}/{}:{}",
            access.state.workload_publisher,
            access.state.workload_name,
            access.state.workload_version
        ),
        &config.alias,
    )?
    .workload_id();
    let archive = std::path::Path::new(&access.state.archive_path);
    let actual = atakit_workload::hash::hash_file(archive)?;
    if access.state.archive_hash.is_empty()
        || !atakit_workload::hex_equal(&actual, &access.state.archive_hash)
    {
        bail!("local workload archive does not match the saved deployment hash");
    }
    unlock_verified(
        &access.verified_tls,
        &access.host,
        access.status_port,
        &args.disk,
        &expected,
        archive,
        &key,
    )
    .await
}

pub async fn run_host(
    args: atakit_workload::cli::WorkloadDiskUnlockArgs,
    env: &Env,
    config: &Config,
) -> Result<()> {
    validate_disk_name(&args.disk)?;
    let key = resolve_owner_key(&args.owner_key, config)?;
    let workload = super::resolve_workload(&Some(args.workload), &None, env, config, false)?;
    let expected = crate::commands::workload::parse_workload_ref(
        &format!(
            "{:#x}/{}:{}",
            workload.publisher, workload.name, workload.version
        ),
        &config.alias,
    )?
    .workload_id();
    let chain_name = args
        .verification
        .chain
        .as_deref()
        .or(config.cloud.defaults.chain.as_deref());
    let registration = config.cloud.defaults.registration.as_deref();
    let chain = match chain_name {
        Some(name) => {
            let chain = config
                .chains
                .get(name)
                .context("chain not found in [chains]")?;
            if args.verification.measurements.is_none() && chain.base_image_registry.is_none() {
                super::init_chain_from_config(name, chain, registration, None).await?
            } else {
                super::session_access::verification_chain_without_registry_derivation(
                    chain,
                    registration,
                )
            }
        }
        None if args.verification.measurements.is_some() => super::synthesize_off_init_chain(),
        None => bail!("provide --chain or --measurements to verify portal attestation"),
    };
    let host = args.host.trim_start_matches('[').trim_end_matches(']');
    let verified = super::session_access::verify_disk_portal_tls(
        host,
        args.port,
        &args.verification,
        env,
        &chain,
        &atakit_cloud::init::workload_tls_attestation_report_path(&env.cache_dir, host, args.port),
    )
    .await?;
    unlock_verified(
        &verified,
        host,
        args.port,
        &args.disk,
        &expected,
        &workload.archive_path,
        &key,
    )
    .await
}

fn validate_disk_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        bail!("invalid disk name");
    }
    Ok(())
}

fn resolve_owner_key(key_name: &str, config: &Config) -> Result<SigningKey> {
    let key_spec = config.keys.get(key_name).context("owner key not found")?;
    if key_spec.key_type != KeyType::Es256k || key_spec.mode != KeyMode::Provisioned {
        bail!("disk unlock requires a provisioned es256k owner key");
    }
    let key_text = Zeroizing::new(
        key_spec
            .resolve(key_name)
            .map_err(|_| anyhow::anyhow!("could not resolve owner key"))?,
    );
    let key_bytes = Zeroizing::new(
        hex::decode(key_text.trim().trim_start_matches("0x"))
            .context("invalid owner key encoding")?,
    );
    SigningKey::from_slice(&key_bytes).context("invalid owner key")
}

async fn unlock_verified(
    verified: &atakit_cloud::init::VerifiedPortalTls,
    host: &str,
    port: u16,
    disk: &str,
    expected: &str,
    archive: &std::path::Path,
    key: &SigningKey,
) -> Result<()> {
    if verified.manual_override().is_some() {
        bail!("disk unlock requires verified TLS attestation without a manual override");
    }
    let client = verified.client();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let base = format!("https://{host}:{port}");
    let status = read_json(
        client
            .get(format!("{base}/status"))
            .timeout(Duration::from_secs(15))
            .send()
            .await?,
    )
    .await?;
    // The attested portal verifies and binds this exact workload before it
    // exposes a waiting disk. Do not use an unverified /status connection.
    validate_workload_identity(&status, expected)?;
    if status["disks"][disk]["state"] == "mounted" {
        eprintln!("Disk '{disk}' on {base} is already mounted.");
        return Ok(());
    }
    if status["disks"][disk]["state"] != "awaiting_passphrase" {
        bail!("disk '{disk}' is not waiting for a passphrase");
    }
    let tls = hex::encode(verified.identity().cert_sha256);
    check_workload_measurement(client, &base, archive).await?;
    unlock_one(client, &base, &tls, disk, key).await
}

fn validate_workload_identity(status: &serde_json::Value, expected: &str) -> Result<()> {
    // WorkloadRef::workload_id already returns an encoded identifier.
    if !status["workload_id"].as_str().is_some_and(|id| {
        id.trim_start_matches("0x")
            .eq_ignore_ascii_case(expected.trim_start_matches("0x"))
    }) {
        bail!("portal workload does not match the selected workload");
    }
    Ok(())
}

/// Read measurements through the attested portal's pinned TLS connection.
/// This trusts the approved portal to report its supervisor's current PCRs;
/// it does not treat an unauthenticated status response as attestation.
async fn check_workload_measurement(
    client: &reqwest::Client,
    base: &str,
    archive: &std::path::Path,
) -> Result<()> {
    let expected =
        atakit_workload::inspect::inspect_workload(&atakit_workload::inspect::InspectOptions {
            publisher: None,
            archive: Some(archive.to_path_buf()),
            workload_dir: None,
            engine: None,
            verbose: false,
            measured_data_root: None,
            unmeasured_data_root: None,
        })
        .await?;
    let measurements = read_json_limited(
        client
            .get(format!("{base}/platform-measurements"))
            .timeout(Duration::from_secs(15))
            .send()
            .await?,
        MAX_MEASUREMENT_RESPONSE_BYTES,
    )
    .await?;
    validate_workload_measurement(
        &measurements,
        &expected.pcr23_sha256,
        &expected.pcr23_sha384,
    )
}

fn validate_workload_measurement(
    measurements: &serde_json::Value,
    sha256: &str,
    sha384: &str,
) -> Result<()> {
    let pcr = measurements["pcrs"]
        .as_array()
        .and_then(|pcrs| pcrs.iter().find(|pcr| pcr["index"] == 23))
        .context("attested portal did not report workload PCR23")?;
    for (bank, value) in [("sha256", sha256), ("sha384", sha384)] {
        if !pcr[bank]
            .as_str()
            .is_some_and(|actual| atakit_workload::hex_equal(actual, &value))
        {
            bail!("portal workload measurement does not match the selected archive ({bank})");
        }
    }
    Ok(())
}

async fn unlock_one(
    client: &reqwest::Client,
    base: &str,
    tls: &str,
    name: &str,
    key: &SigningKey,
) -> Result<()> {
    let passphrase = prompt_passphrase(&prompt_label(base, name)).await?;
    // Fetch the challenge after prompting so it cannot expire while the
    // operator is entering the passphrase.
    let url = format!("{base}/disks/{}/unlock", name);
    let challenge = read_json(
        client
            .get(&url)
            .timeout(Duration::from_secs(15))
            .send()
            .await?,
    )
    .await?;
    let nonce = challenge["challenge"]
        .as_str()
        .context("missing disk challenge")?;
    if nonce.len() != 64 || hex::decode(nonce).is_err() {
        bail!("invalid disk challenge");
    }
    #[derive(serde::Serialize)]
    struct Body<'a> {
        passphrase: &'a str,
    }
    let body = Zeroizing::new(serde_json::to_vec(&Body {
        passphrase: &passphrase,
    })?);
    let digest = request_digest(tls, name, nonce, &body);
    let (signature, recovery) = key
        .sign_prehash_recoverable(&digest)
        .context("sign disk-unlock request")?;
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    let result = read_json(
        client
            .post(url)
            .timeout(Duration::from_secs(120))
            .header("content-type", "application/json")
            .header("atakit-disk-challenge", nonce)
            .header(
                "atakit-owner-signature",
                format!("0x{}", hex::encode(bytes)),
            )
            .body(secret_http_body(body))
            .send()
            .await?,
    )
    .await?;
    if result["state"] != "mounted" {
        bail!("disk did not reach mounted state");
    }
    eprintln!("Disk '{}' is mounted.", name);
    Ok(())
}

pub(crate) async fn wait_for_running(
    client: &reqwest::Client,
    host: &str,
    port: u16,
    deadline: atakit_cloud::init::PortalInitDeadline,
    verified: Option<&atakit_cloud::init::VerifiedPortalTls>,
    config: &atakit_cloud::init::InitConfig,
    archive: &std::path::Path,
    on_transition: impl FnMut(&str),
) -> Result<atakit_cloud::init::PortalTerminalState, atakit_cloud::CloudError> {
    let waiting = atakit_cloud::init::wait_for_portal_terminal_until_with_client(
        client,
        host,
        port,
        deadline,
        on_transition,
    );
    tokio::pin!(waiting);
    tokio::select! {
        result = &mut waiting => result,
        result = unlock_waiting(client, host, port, verified, config, archive) => {
            result.map_err(|error| atakit_cloud::CloudError::PortalInitFailed {
                message: format!("{error}; initialization is not resent. Use atakit cloud disk unlock for a saved deployment, or atakit workload disk unlock HOST for an existing portal, to supply remaining passphrases"),
            })?;
            waiting.await
        }
    }
}

async fn unlock_waiting(
    client: &reqwest::Client,
    host: &str,
    port: u16,
    verified: Option<&atakit_cloud::init::VerifiedPortalTls>,
    config: &atakit_cloud::init::InitConfig,
    archive: &std::path::Path,
) -> Result<()> {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let base = format!("https://{host}:{port}");
    loop {
        let status = poll_status(client, &format!("{base}/status")).await;
        if matches!(
            status["state"].as_str(),
            Some("Running" | "Failed" | "CleanHalt")
        ) {
            return Ok(());
        }
        if let Some(disks) = status["disks"].as_object() {
            for (name, disk) in disks {
                if disk["state"] != "awaiting_passphrase" {
                    continue;
                }
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                {
                    bail!("invalid disk name in portal status");
                }
                let verified = verified.context("disk unlock requires verified TLS attestation")?;
                if verified.manual_override().is_some() {
                    bail!("disk unlock does not allow a TLS manual override");
                }
                check_workload_measurement(client, &base, archive).await?;
                let text = config
                    .owner_key
                    .private_key
                    .as_deref()
                    .context("disk unlock requires a provisioned owner key")?;
                let bytes = Zeroizing::new(
                    hex::decode(text.trim().trim_start_matches("0x"))
                        .context("invalid owner key")?,
                );
                let key = SigningKey::from_slice(&bytes).context("invalid owner key")?;
                let tls = hex::encode(verified.identity().cert_sha256);
                unlock_one(client, &base, &tls, name, &key).await?;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn request_digest(tls: &str, disk: &str, challenge: &str, body: &[u8]) -> [u8; 32] {
    let body_hash = Sha256::digest(body);
    let mut hash = Sha256::new();
    for part in [
        b"ATAKIT_DISK_UNLOCK_V1".as_slice(),
        tls.as_bytes(),
        disk.as_bytes(),
        challenge.as_bytes(),
        body_hash.as_slice(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn prompts_identify_the_destination_even_for_identical_disk_names() {
        let first = prompt_label("https://192.0.2.1:2024", "data");
        let second = prompt_label("https://192.0.2.2:2024", "data");
        assert_ne!(first, second);
        assert!(first.contains("192.0.2.1:2024"));
        assert!(first.contains("'data'"));
    }

    #[test]
    fn secret_http_body_transfers_the_original_allocation() {
        let source = Zeroizing::new(b"{\"passphrase\":\"secret\"}".to_vec());
        let pointer = source.as_ptr();
        let body = secret_http_body(source);
        assert_eq!(body.as_ptr(), pointer);
        let copy = body.clone();
        drop(body);
        assert_eq!(copy.as_ptr(), pointer);
        assert_eq!(copy.as_ref(), b"{\"passphrase\":\"secret\"}");
    }

    #[test]
    fn backspace_erases_a_whole_utf8_character() {
        let mut input = Zeroizing::new("aé🔑".as_bytes().to_vec());
        erase_last_character(&mut input);
        assert_eq!(&**input, "aé".as_bytes());
        erase_last_character(&mut input);
        assert_eq!(&**input, b"a");
        erase_last_character(&mut input);
        erase_last_character(&mut input);
        assert!(input.is_empty());
    }
    #[test]
    fn workload_identity_uses_the_encoded_reference_id() {
        let reference = crate::commands::workload::parse_workload_ref(
            "0xaef8fc89416f01494ec6534de68d30aab26d7598db8a05967b0ba7d3ecb259d2/disk-unlock-test:v0.0.1",
            &Default::default(),
        ).unwrap();
        let expected = reference.workload_id();
        let status = serde_json::json!({"workload_id":
            "0x621243d364889972213ec48c4fc6d6c9f8bad7a3447474ac4a21bc8106a7e2e7"});
        assert!(super::validate_workload_identity(&status, &expected).is_ok());
        assert!(super::validate_workload_identity(&status, &hex::encode(expected)).is_err());
        assert!(super::validate_workload_identity(&serde_json::json!({}), "0x1234").is_err());
    }
    use super::*;

    async fn responses(values: Vec<(u16, String)>) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/status", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for (status, body) in values {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                socket.read(&mut request).await.unwrap();
                if status == 0 {
                    continue;
                } // Simulate a dropped connection.
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        (url, server)
    }

    #[tokio::test]
    async fn status_poll_retries_transport_http_and_json_failures() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let (url, server) = responses(vec![
            (0, String::new()),
            (503, "unavailable".into()),
            (200, "not json".into()),
            (200, r#"{"state":"AwaitingDiskUnlock"}"#.into()),
        ])
        .await;
        let status = tokio::time::timeout(Duration::from_secs(5), poll_status(&client, &url))
            .await
            .unwrap();
        assert_eq!(status["state"], "AwaitingDiskUnlock");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn measurement_limit_accepts_large_logs_but_remains_bounded() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let body = serde_json::json!({"pcrs":[], "event_log": "x".repeat(100_000)}).to_string();
        let (url, server) =
            responses(vec![(200, body.clone()), (200, body.clone()), (200, body)]).await;
        assert!(read_json_limited(
            client.get(&url).send().await.unwrap(),
            MAX_MEASUREMENT_RESPONSE_BYTES
        )
        .await
        .is_ok());
        assert!(read_json(client.get(&url).send().await.unwrap())
            .await
            .is_err());
        assert!(
            read_json_limited(client.get(&url).send().await.unwrap(), 1024)
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn terminal_wait_is_cancellable_and_restores_settings() {
        use nix::sys::termios::tcgetattr;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let pty = nix::pty::openpty(None, None).unwrap();
        let mut master = std::fs::File::from(pty.master);
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{}", pty.slave.as_raw_fd()))
            .unwrap();
        let original = tcgetattr(&tty).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(30),
            prompt_on_terminal("data", tty.try_clone().unwrap())
        )
        .await
        .is_err());
        assert_eq!(tcgetattr(&tty).unwrap().local_flags, original.local_flags);
        let input = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            master.write_all("é\u{7f}secret\n".as_bytes()).unwrap();
        };
        let (result, ()) =
            tokio::join!(prompt_on_terminal("data", tty.try_clone().unwrap()), input);
        assert_eq!(result.unwrap().as_str(), "secret");
        assert_eq!(tcgetattr(&tty).unwrap().local_flags, original.local_flags);
    }
    #[test]
    fn workload_measurement_requires_both_banks_of_pcr23() {
        let valid = serde_json::json!({"pcrs":[{"index":23,"sha256":"0x1234","sha384":"0x5678"}]});
        assert!(validate_workload_measurement(&valid, "0x1234", "0x5678").is_ok());
        assert!(validate_workload_measurement(&valid, "0xabcd", "0x5678").is_err());
        assert!(validate_workload_measurement(&valid, "0x1234", "0xabcd").is_err());
        assert!(validate_workload_measurement(&serde_json::json!({}), "0x1234", "0x5678").is_err());
    }
    #[test]
    fn disk_signature_matches_portal_protocol_vector() {
        assert_eq!(
            hex::encode(request_digest("tls", "database", "nonce", b"secret")),
            "c4b475ddcd87caabad702569a9b323abdb6f901724c74aade026ad10726419e5"
        );
    }
}

async fn poll_status(client: &reqwest::Client, url: &str) -> serde_json::Value {
    loop {
        if let Ok(response) = client
            .get(url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
        {
            if let Ok(status) = read_json(response).await {
                return status;
            }
        }
        // The caller's initialization deadline cancels this future. A temporary
        // status failure must not cancel the main terminal-state watcher.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn read_json(response: reqwest::Response) -> Result<serde_json::Value> {
    read_json_limited(response, 64 * 1024).await
}

async fn read_json_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<serde_json::Value> {
    let status = response.status();
    if !status.is_success() {
        bail!(
            "disk API returned HTTP {status}; check disk status and retry with a fresh challenge"
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > limit {
            bail!("portal response exceeds {limit} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).context("invalid disk API response")
}

async fn prompt_passphrase(name: &str) -> Result<Zeroizing<String>> {
    use std::os::unix::fs::OpenOptionsExt;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open("/dev/tty")
        .context("disk unlock requires an interactive terminal")?;
    prompt_on_terminal(name, tty).await
}

async fn prompt_on_terminal(name: &str, mut tty: std::fs::File) -> Result<Zeroizing<String>> {
    // Multi-target deployments share one terminal. Keep prompts and terminal
    // settings separate, without blocking other deployments or their deadlines.
    static PROMPT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _prompt = PROMPT.lock().await;
    use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg, SpecialCharacterIndices};
    let original = tcgetattr(&tty)?;
    struct Restore(std::fs::File, nix::sys::termios::Termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ =
                nix::sys::termios::tcsetattr(&self.0, nix::sys::termios::SetArg::TCSANOW, &self.1);
        }
    }
    let _restore = Restore(tty.try_clone()?, original.clone());
    let mut settings = original;
    settings
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ICANON | LocalFlags::ISIG);
    settings.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    settings.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
    tcsetattr(&tty, SetArg::TCSANOW, &settings)?;
    write!(tty, "{name}")?;
    tty.flush()?;
    let input = tokio::io::unix::AsyncFd::new(tty.try_clone()?)?;
    let mut secret = Zeroizing::new(Vec::new());
    loop {
        let mut byte = [0];
        loop {
            let mut ready = input.readable().await?;
            match ready.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(&mut byte)
            }) {
                Ok(Ok(0)) => bail!("terminal closed during passphrase entry"),
                Ok(Ok(_)) => break,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => continue,
            }
        }
        match byte[0] {
            b'\n' | b'\r' => break,
            3 | 4 => {
                writeln!(tty)?;
                bail!("passphrase entry cancelled");
            }
            8 | 127 => {
                erase_last_character(&mut secret);
            }
            b => {
                if secret.len() >= 4096 {
                    bail!("passphrase exceeds 4096 bytes");
                }
                secret.push(b);
            }
        }
    }
    writeln!(tty)?;
    if secret.is_empty() {
        bail!("passphrase cannot be empty");
    }
    Ok(Zeroizing::new(
        std::str::from_utf8(&secret)
            .context("passphrase must be UTF-8")?
            .to_string(),
    ))
}
