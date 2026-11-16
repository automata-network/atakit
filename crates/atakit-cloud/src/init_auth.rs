//! Dedicated local initialization credentials. Private keys never enter plans.
pub use atakit_init_auth::{Bootstrap, Challenge, Intent};
use k256::{
    ecdsa::SigningKey,
    elliptic_curve::rand_core::{OsRng, RngCore},
};
use std::{
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct ClientAuth {
    pub key_file: PathBuf,
    pub workload_id: String,
    pub tls_fingerprint: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    bootstrap: Bootstrap,
    private_key: String,
}

pub fn create(data_dir: &Path) -> Result<(PathBuf, Bootstrap), String> {
    let dir = data_dir.join("cloud/init-keys");
    std::fs::create_dir_all(&dir).map_err(|_| "create init credential directory")?;
    if std::fs::symlink_metadata(&dir)
        .map_err(|_| "inspect init credential directory")?
        .file_type()
        .is_symlink()
    {
        return Err("init credential directory must not be a symlink".into());
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| "protect init credential directory")?;
    let key = SigningKey::random(&mut OsRng);
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    let bootstrap = Bootstrap {
        format: 1,
        scheme: atakit_init_auth::SCHEME.into(),
        public_key: hex::encode(key.verifying_key().to_encoded_point(true).as_bytes()),
        deployment_id: hex::encode(id),
    };
    let path = dir.join(format!("{}.json", bootstrap.deployment_id));
    let credential = Credential {
        bootstrap: bootstrap.clone(),
        private_key: hex::encode(key.to_bytes()),
    };
    let bytes = serde_json::to_vec(&credential).map_err(|_| "encode init credential")?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| "create init credential")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "save init credential")?;
    std::fs::File::open(&dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "sync init credential directory")?;
    Ok((path, bootstrap))
}

/// Delete only a credential created in this data directory, never an arbitrary
/// path supplied by a deployment state file.
pub fn retire(state: &mut crate::state::DeployState, data_dir: &Path) -> Result<(), String> {
    let Some(saved) = &state.init_auth_key_file else {
        return Ok(());
    };
    let path = Path::new(saved);
    let stem = path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or("invalid init credential path")?;
    if path.parent() != Some(data_dir.join("cloud/init-keys").as_path())
        || path.extension().and_then(|v| v.to_str()) != Some("json")
        || stem.len() != 64
        || hex::decode(stem).is_err()
    {
        return Err("refusing to remove an init credential outside cloud/init-keys".into());
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("remove completed init credential".into()),
    }
    state.init_auth_key_file = None;
    state
        .save(data_dir)
        .map_err(|_| "save retired init credential".to_string())
}

/// Remove a newly generated key if planning or confirmation fails. Once the
/// deployment state is saved, the deployment owns the credential instead.
pub struct PendingCredential(pub Option<PathBuf>);
impl Drop for PendingCredential {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn load(path: &Path) -> Result<(SigningKey, Bootstrap), String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "open init credential")?;
    let metadata = file.metadata().map_err(|_| "inspect init credential")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("init credential must be a private regular file (0600)".into());
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "read init credential")?;
    if bytes.len() > 4096 {
        return Err("init credential too large".into());
    }
    let credential: Credential =
        serde_json::from_slice(&bytes).map_err(|_| "invalid init credential")?;
    let raw = hex::decode(&credential.private_key).map_err(|_| "invalid init key")?;
    let key = SigningKey::from_slice(&raw).map_err(|_| "invalid init key")?;
    let public = credential.bootstrap.validate().map_err(str::to_string)?;
    if &public != key.verifying_key() {
        return Err("init key pair mismatch".into());
    }
    Ok((key, credential.bootstrap))
}

pub async fn authorize(
    client: &reqwest::Client,
    host: &str,
    port: u16,
    auth: &ClientAuth,
    mut intent: Intent,
) -> Result<String, String> {
    let (key, bootstrap) = load(&auth.key_file)?;
    let response = client
        .get(format!("https://{host}:{port}/init/challenge"))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| "request init challenge")?;
    if !response.status().is_success() {
        return Err("portal does not accept authenticated initialization".into());
    }
    let bytes = crate::init::read_response_bytes_limited(response, 4096, "init challenge")
        .await
        .map_err(|_| "read init challenge")?;
    let challenge: Challenge =
        serde_json::from_slice(&bytes).map_err(|_| "invalid init challenge")?;
    validate_challenge(&bootstrap, &auth.tls_fingerprint, &challenge)?;
    intent.deployment_id = bootstrap.deployment_id;
    intent.tls_fingerprint = auth.tls_fingerprint.clone();
    intent.challenge = challenge.challenge;
    intent.workload_id = auth.workload_id.trim_start_matches("0x").to_string();
    atakit_init_auth::sign(&intent, &key).map_err(str::to_string)
}

fn validate_challenge(
    bootstrap: &Bootstrap,
    tls_fingerprint: &str,
    challenge: &Challenge,
) -> Result<(), String> {
    if challenge.scheme != atakit_init_auth::SCHEME
        || challenge.deployment_id != bootstrap.deployment_id
        || challenge.key_fingerprint != bootstrap.fingerprint().map_err(str::to_string)?
        || challenge.tls_fingerprint != tls_fingerprint
    {
        return Err("portal init identity does not match deployment".into());
    }
    if challenge.challenge.len() != 64
        || hex::decode(&challenge.challenge).is_err()
        || challenge.expires_in_seconds == 0
        || challenge.expires_in_seconds > 120
    {
        return Err("invalid init challenge".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_checks_deployment_key_and_verified_tls_before_signing() {
        let dir = tempfile::tempdir().unwrap();
        let (_, bootstrap) = create(dir.path()).unwrap();
        let challenge = Challenge {
            scheme: atakit_init_auth::SCHEME.into(),
            deployment_id: bootstrap.deployment_id.clone(),
            key_fingerprint: bootstrap.fingerprint().unwrap(),
            tls_fingerprint: "22".repeat(32),
            challenge: "33".repeat(32),
            expires_in_seconds: 120,
        };
        assert!(validate_challenge(&bootstrap, &"22".repeat(32), &challenge).is_ok());
        let original = serde_json::to_value(&challenge).unwrap();
        for name in [
            "scheme",
            "deployment_id",
            "key_fingerprint",
            "tls_fingerprint",
            "challenge",
            "expires_in_seconds",
        ] {
            let mut changed = original.clone();
            changed[name] = if name == "expires_in_seconds" {
                serde_json::json!(0)
            } else {
                serde_json::json!("wrong")
            };
            assert!(
                validate_challenge(
                    &bootstrap,
                    &"22".repeat(32),
                    &serde_json::from_value(changed).unwrap()
                )
                .is_err(),
                "{name}"
            );
        }
    }
    #[test]
    fn credentials_survive_reload_without_exposing_private_key_in_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let (path, bootstrap) = create(dir.path()).unwrap();
        let (key, restored) = load(&path).unwrap();
        assert_eq!(bootstrap, restored);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let public_json = serde_json::to_string(&bootstrap).unwrap();
        assert!(!public_json.contains("private_key"));
        assert!(!public_json.contains(&hex::encode(key.to_bytes())));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn credentials_reject_symlinks_and_pending_keys_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = create(dir.path()).unwrap();
        let link = dir.path().join("key-link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load(&link).is_err());
        drop(PendingCredential(Some(path.clone())));
        assert!(!path.exists());
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("cloud")).unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("cloud/init-keys")).unwrap();
        assert!(create(dir.path()).is_err());
    }
}
