//! Typed client for the owner-authorized portal session lifecycle API.

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use crate::error::CloudError;
use crate::init::{VerifiedPortalTls, PORTAL_PROOF_TIMEOUT_SECONDS};

const CHALLENGE_DOMAIN: &str = "ATAKIT_PORTAL_CHALLENGE_AUTHORIZE_V1";
pub const LIFECYCLE_COMPLETION_BUFFER_SECONDS: u64 = 60;

/// Resolve the complete owner-authorization window. The configured owner
/// operation window remains available for transaction submission after the
/// portal's maximum supported proof time.
pub fn lifecycle_operation_window_seconds(
    explicit_window: Option<u64>,
    owner_operation_window: u64,
) -> u64 {
    explicit_window
        .unwrap_or_else(|| PORTAL_PROOF_TIMEOUT_SECONDS.saturating_add(owner_operation_window))
}

pub fn lifecycle_wait_timeout_seconds(explicit_timeout: Option<u64>, operation_window: u64) -> u64 {
    explicit_timeout
        .unwrap_or_else(|| operation_window.saturating_add(LIFECYCLE_COMPLETION_BUFFER_SECONDS))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleOperation {
    New,
    RotateKey,
    Renew,
    Recover,
}

impl LifecycleOperation {
    pub fn path(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::RotateKey => "rotate-key",
            Self::Renew => "renew",
            Self::Recover => "recover",
        }
    }

    pub fn status_name(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::RotateKey => "rotate_key",
            Self::Renew => "renew",
            Self::Recover => "recover",
        }
    }

    fn domain(self) -> &'static str {
        match self {
            Self::New => "ATAKIT_PORTAL_SESSION_NEW_V1",
            Self::RotateKey => "ATAKIT_PORTAL_SESSION_ROTATE_KEY_V1",
            Self::Renew => "ATAKIT_PORTAL_SESSION_RENEW_V1",
            Self::Recover => "ATAKIT_PORTAL_SESSION_RECOVER_V1",
        }
    }

    pub fn requires_old_session(self) -> bool {
        !matches!(self, Self::New)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStatus {
    pub request_hash: Option<String>,
    pub command: Option<String>,
    pub state: String,
    pub session_id: Option<String>,
    pub error_code: Option<String>,
    pub created_at: Option<u64>,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
}

impl LifecycleStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self.state.as_str(), "completed" | "failed")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedLifecycleRequest {
    pub request_hash: String,
    pub challenge: String,
    pub challenge_expires_at: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareOutcome {
    Waiting(PreparedLifecycleRequest),
    Existing(LifecycleStatus),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    Started(LifecycleStatus),
    Busy,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PortalChainStatus {
    pub status: String,
    pub session_id: Option<String>,
    pub tx_hash: Option<String>,
    pub block_number: Option<u64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PortalStatus {
    pub state: String,
    pub chain: PortalChainStatus,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PrepareResponse {
    Waiting(PreparedLifecycleRequest),
    Existing(LifecycleStatus),
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct NewRequest<'a> {
    op_expires_at: u64,
    owner_intent_signature: &'a str,
}

#[derive(Serialize)]
struct ExistingRequest<'a> {
    op_expires_at: u64,
    owner_intent_signature: &'a str,
    old_session_id: &'a str,
}

#[derive(Serialize)]
struct AuthorizeRequest<'a> {
    request_hash: &'a str,
    challenge: &'a str,
    owner_authorization_signature: &'a str,
}

pub struct LifecycleClient<'a> {
    verified_tls: &'a VerifiedPortalTls,
    base_url: String,
}

impl<'a> LifecycleClient<'a> {
    pub fn new(verified_tls: &'a VerifiedPortalTls, host: &str, status_port: u16) -> Self {
        Self {
            verified_tls,
            base_url: format!("https://{host}:{status_port}"),
        }
    }

    pub async fn prepare(
        &self,
        operation: LifecycleOperation,
        op_expires_at: u64,
        old_session_id: Option<[u8; 32]>,
        owner_key: &SigningKey,
    ) -> Result<PrepareOutcome, CloudError> {
        let request_hash = lifecycle_request_hash(operation, op_expires_at, old_session_id)?;
        let signature = sign_digest(owner_key, request_hash)?;
        let signature = hex0x(signature);
        let response = if let Some(old_session_id) = old_session_id {
            self.verified_tls
                .client
                .post(format!("{}/session/{}", self.base_url, operation.path()))
                .json(&ExistingRequest {
                    op_expires_at,
                    owner_intent_signature: &signature,
                    old_session_id: &hex0x(old_session_id),
                })
                .send()
                .await
        } else {
            self.verified_tls
                .client
                .post(format!("{}/session/{}", self.base_url, operation.path()))
                .json(&NewRequest {
                    op_expires_at,
                    owner_intent_signature: &signature,
                })
                .send()
                .await
        }
        .map_err(|error| {
            lifecycle_error(format!("prepare {} request: {error}", operation.path()))
        })?;

        let response =
            decode_success::<PrepareResponse>(response, "prepare lifecycle request").await?;
        match response {
            PrepareResponse::Waiting(prepared) => {
                validate_hash(
                    &prepared.request_hash,
                    request_hash,
                    "prepared request hash",
                )?;
                decode_challenge(&prepared.challenge)?;
                if prepared.state != "waiting" {
                    return Err(lifecycle_error(format!(
                        "prepared request returned state {:?}, expected waiting",
                        prepared.state
                    )));
                }
                Ok(PrepareOutcome::Waiting(prepared))
            }
            PrepareResponse::Existing(status) => {
                validate_status(&status, Some(request_hash), Some(operation))?;
                Ok(PrepareOutcome::Existing(status))
            }
        }
    }

    pub async fn authorize(
        &self,
        prepared: &PreparedLifecycleRequest,
        owner_key: &SigningKey,
    ) -> Result<AuthorizeOutcome, CloudError> {
        let request_hash = decode_hex_32(&prepared.request_hash, "request_hash")?;
        let challenge = decode_challenge(&prepared.challenge)?;
        let digest =
            challenge_authorization_hash(challenge, request_hash, prepared.challenge_expires_at);
        let signature = hex0x(sign_digest(owner_key, digest)?);
        let response = self
            .verified_tls
            .client
            .post(format!("{}/challenge/authorize", self.base_url))
            .json(&AuthorizeRequest {
                request_hash: &prepared.request_hash,
                challenge: &prepared.challenge,
                owner_authorization_signature: &signature,
            })
            .send()
            .await
            .map_err(|error| lifecycle_error(format!("authorize lifecycle request: {error}")))?;

        if response.status() == reqwest::StatusCode::CONFLICT {
            let body = response.text().await.unwrap_or_default();
            if serde_json::from_str::<ErrorResponse>(&body)
                .ok()
                .is_some_and(|body| body.error == "session_operation_already_running")
            {
                return Ok(AuthorizeOutcome::Busy);
            }
            return Err(lifecycle_error(format!(
                "authorize lifecycle request returned 409 Conflict: {body}"
            )));
        }

        let status =
            decode_success::<LifecycleStatus>(response, "authorize lifecycle request").await?;
        validate_status(&status, Some(request_hash), None)?;
        Ok(AuthorizeOutcome::Started(status))
    }

    pub async fn request_status(&self, request_hash: &str) -> Result<LifecycleStatus, CloudError> {
        let expected = decode_hex_32(request_hash, "request_hash")?;
        let response = self
            .verified_tls
            .client
            .get(format!("{}/requests/{request_hash}", self.base_url))
            .send()
            .await
            .map_err(|error| lifecycle_error(format!("read lifecycle request status: {error}")))?;
        let status =
            decode_success::<LifecycleStatus>(response, "read lifecycle request status").await?;
        validate_status(&status, Some(expected), None)?;
        Ok(status)
    }

    pub async fn selected_status(&self) -> Result<LifecycleStatus, CloudError> {
        let response = self
            .verified_tls
            .client
            .get(format!("{}/session/status", self.base_url))
            .send()
            .await
            .map_err(|error| lifecycle_error(format!("read selected lifecycle status: {error}")))?;
        let status =
            decode_success::<LifecycleStatus>(response, "read selected lifecycle status").await?;
        validate_status(&status, None, None)?;
        Ok(status)
    }

    pub async fn portal_status(&self) -> Result<PortalStatus, CloudError> {
        let response = self
            .verified_tls
            .client
            .get(format!("{}/status", self.base_url))
            .send()
            .await
            .map_err(|error| lifecycle_error(format!("read portal status: {error}")))?;
        decode_success::<PortalStatus>(response, "read portal status").await
    }

    pub async fn wait_for_request(
        &self,
        request_hash: &str,
        timeout: Duration,
        mut on_transition: impl FnMut(&LifecycleStatus),
    ) -> Result<LifecycleStatus, CloudError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_state = None;
        loop {
            let status = self.request_status(request_hash).await?;
            if last_state.as_deref() != Some(status.state.as_str()) {
                on_transition(&status);
                last_state = Some(status.state.clone());
            }
            if status.is_terminal() {
                return Ok(status);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(lifecycle_error(format!(
                    "request {request_hash} did not reach a terminal state within {} seconds",
                    timeout.as_secs()
                )));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

pub fn lifecycle_request_hash(
    operation: LifecycleOperation,
    op_expires_at: u64,
    old_session_id: Option<[u8; 32]>,
) -> Result<[u8; 32], CloudError> {
    if operation.requires_old_session() != old_session_id.is_some() {
        return Err(lifecycle_error(format!(
            "{} {} old_session_id",
            operation.path(),
            if operation.requires_old_session() {
                "requires"
            } else {
                "rejects"
            }
        )));
    }
    let mut encoded = Vec::with_capacity(if old_session_id.is_some() { 96 } else { 64 });
    encoded.extend_from_slice(&keccak256(operation.domain().as_bytes()));
    encoded.extend_from_slice(&u64_word(op_expires_at));
    if let Some(old_session_id) = old_session_id {
        encoded.extend_from_slice(&old_session_id);
    }
    Ok(Sha256::digest(encoded).into())
}

pub fn challenge_authorization_hash(
    challenge: [u8; 32],
    request_hash: [u8; 32],
    challenge_expires_at: u64,
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(&keccak256(CHALLENGE_DOMAIN.as_bytes()));
    encoded.extend_from_slice(&challenge);
    encoded.extend_from_slice(&request_hash);
    encoded.extend_from_slice(&u64_word(challenge_expires_at));
    Sha256::digest(encoded).into()
}

pub fn decode_hex_32(value: &str, field: &str) -> Result<[u8; 32], CloudError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| lifecycle_error(format!("{field} must use 0x hex")))?;
    let decoded =
        hex::decode(raw).map_err(|error| lifecycle_error(format!("invalid {field}: {error}")))?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        lifecycle_error(format!(
            "{field} must contain exactly 32 bytes, got {}",
            decoded.len()
        ))
    })
}

fn decode_challenge(value: &str) -> Result<[u8; 32], CloudError> {
    if value.contains('=') {
        return Err(lifecycle_error("challenge must be unpadded base64url"));
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| lifecycle_error(format!("invalid challenge: {error}")))?
        .try_into()
        .map_err(|decoded: Vec<u8>| {
            lifecycle_error(format!(
                "challenge must contain exactly 32 bytes, got {}",
                decoded.len()
            ))
        })
}

fn sign_digest(owner_key: &SigningKey, digest: [u8; 32]) -> Result<[u8; 65], CloudError> {
    let (signature, recovery_id) = owner_key
        .sign_prehash_recoverable(&digest)
        .map_err(|error| lifecycle_error(format!("sign lifecycle digest: {error}")))?;
    let mut encoded = [0u8; 65];
    encoded[..64].copy_from_slice(&signature.to_bytes());
    encoded[64] = recovery_id.to_byte();
    Ok(encoded)
}

fn validate_hash(value: &str, expected: [u8; 32], field: &str) -> Result<(), CloudError> {
    let observed = decode_hex_32(value, field)?;
    if observed != expected {
        return Err(lifecycle_error(format!(
            "{field} does not match the locally calculated hash"
        )));
    }
    Ok(())
}

fn validate_status(
    status: &LifecycleStatus,
    expected_hash: Option<[u8; 32]>,
    expected_operation: Option<LifecycleOperation>,
) -> Result<(), CloudError> {
    match (status.request_hash.as_deref(), expected_hash) {
        (Some(value), Some(expected)) => validate_hash(value, expected, "request_hash")?,
        (None, Some(_)) => return Err(lifecycle_error("lifecycle status omitted request_hash")),
        (Some(value), None) => {
            decode_hex_32(value, "request_hash")?;
        }
        (None, None) if status.state != "idle" => {
            return Err(lifecycle_error(
                "non-idle lifecycle status omitted request_hash",
            ))
        }
        (None, None) => {}
    }
    if let Some(operation) = expected_operation {
        if status.command.as_deref() != Some(operation.status_name()) {
            return Err(lifecycle_error(format!(
                "lifecycle status command {:?} does not match {}",
                status.command,
                operation.status_name()
            )));
        }
    }
    if !matches!(
        status.state.as_str(),
        "idle" | "waiting" | "running" | "completed" | "failed"
    ) {
        return Err(lifecycle_error(format!(
            "unknown lifecycle request state {:?}",
            status.state
        )));
    }
    if let Some(session_id) = &status.session_id {
        decode_hex_32(session_id, "session_id")?;
    }
    Ok(())
}

async fn decode_success<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    action: &str,
) -> Result<T, CloudError> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(lifecycle_error(format!(
            "{action} returned {status}: {body}"
        )));
    }
    response
        .json::<T>()
        .await
        .map_err(|error| lifecycle_error(format!("decode {action} response: {error}")))
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn keccak256(value: &[u8]) -> [u8; 32] {
    Keccak256::digest(value).into()
}

fn hex0x(value: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(value))
}

fn lifecycle_error(message: impl Into<String>) -> CloudError {
    CloudError::PortalSessionLifecycleFailed {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_lifecycle_window_covers_proof_and_transaction_submission() {
        assert_eq!(lifecycle_operation_window_seconds(None, 300), 1_200);
        assert_eq!(lifecycle_wait_timeout_seconds(None, 1_200), 1_260);
    }

    #[test]
    fn explicit_lifecycle_windows_replace_calculated_defaults() {
        assert_eq!(lifecycle_operation_window_seconds(Some(1_500), 300), 1_500);
        assert_eq!(lifecycle_wait_timeout_seconds(Some(1_600), 1_500), 1_600);
    }

    #[test]
    fn request_hashes_match_portal_canonical_vectors() {
        let expiry = 1_700_000_300;
        let new = lifecycle_request_hash(LifecycleOperation::New, expiry, None).unwrap();
        let renew =
            lifecycle_request_hash(LifecycleOperation::Renew, expiry, Some([0x22; 32])).unwrap();
        assert_eq!(
            hex0x(new),
            "0x0786170f67db0f8e294618e4d290daaa2527185674f87d2d50e442dcfb0d86fe"
        );
        assert_eq!(
            hex0x(renew),
            "0x968953c3b83a02886f534869f51f900b6d98fd939e9aae4fd3ee0188e1df1d60"
        );
        let challenge: [u8; 32] = std::array::from_fn(|index| index as u8);
        let digest = challenge_authorization_hash(challenge, renew, 1_700_000_060);
        assert_eq!(
            hex0x(digest),
            "0xa223e36fdbb9999aebc75e8af0f98a45736a63b9a9f0696f874b5aa2753c7efd"
        );
    }

    #[test]
    fn operation_old_session_rules_are_strict() {
        assert!(lifecycle_request_hash(LifecycleOperation::New, 1, Some([0; 32])).is_err());
        assert!(lifecycle_request_hash(LifecycleOperation::Renew, 1, None).is_err());
        let old_session_id = Some([0x44; 32]);
        let rotate =
            lifecycle_request_hash(LifecycleOperation::RotateKey, 10, old_session_id).unwrap();
        let renew = lifecycle_request_hash(LifecycleOperation::Renew, 10, old_session_id).unwrap();
        let recover =
            lifecycle_request_hash(LifecycleOperation::Recover, 10, old_session_id).unwrap();
        assert_ne!(rotate, renew);
        assert_ne!(renew, recover);
        assert_ne!(rotate, recover);
    }

    #[test]
    fn response_json_is_strict_and_preserves_null_fields() {
        let status: LifecycleStatus = serde_json::from_value(serde_json::json!({
            "request_hash": format!("0x{}", "11".repeat(32)),
            "command": "renew",
            "state": "completed",
            "session_id": format!("0x{}", "22".repeat(32)),
            "error_code": null,
            "created_at": 1,
            "started_at": 2,
            "completed_at": 3
        }))
        .unwrap();
        validate_status(&status, None, Some(LifecycleOperation::Renew)).unwrap();
        let unknown = serde_json::json!({
            "request_hash": null,
            "command": null,
            "state": "idle",
            "session_id": null,
            "error_code": null,
            "created_at": null,
            "started_at": null,
            "completed_at": null,
            "extra": true
        });
        assert!(serde_json::from_value::<LifecycleStatus>(unknown).is_err());
    }

    #[test]
    fn signature_is_recoverable_and_uses_zero_or_one_recovery_id() {
        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let digest = [0x77; 32];
        let signature = sign_digest(&key, digest).unwrap();
        assert!(signature[64] <= 1);
        let signature_rs = k256::ecdsa::Signature::from_slice(&signature[..64]).unwrap();
        let recovery_id = k256::ecdsa::RecoveryId::from_byte(signature[64]).unwrap();
        let recovered =
            k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &signature_rs, recovery_id)
                .unwrap();
        assert_eq!(recovered, *key.verifying_key());
    }

    #[test]
    fn status_rejects_unknown_states_and_bad_identifiers() {
        let mut status = LifecycleStatus {
            request_hash: Some(hex0x([0x11; 32])),
            command: Some("new".into()),
            state: "running".into(),
            session_id: None,
            error_code: None,
            created_at: Some(1),
            started_at: Some(1),
            completed_at: None,
        };
        validate_status(&status, None, None).unwrap();
        status.state = "mystery".into();
        assert!(validate_status(&status, None, None).is_err());
    }
}
