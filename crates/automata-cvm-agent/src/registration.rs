//! Registration and rotation orchestration.
//!
//! The [`RegistrationManager`] is generic over [`DeviceProvider`] and drives
//! the complete session registration and rotation flows by calling the
//! low-level device methods step by step, assembling evidence, computing
//! digests, and submitting transactions via [`WorkloadMeasurement`].

use std::sync::Arc;

use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail};
use k256::ecdsa::SigningKey;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use automata_tee_workload_measurement::WorkloadMeasurement;
use automata_tee_workload_measurement::base_image_registry::BaseImageRegistry;
use automata_tee_workload_measurement::stubs::{
    AttestationEvidence, PublicIdentity, SessionRotationEvidence, sign_message,
};
use automata_tee_workload_measurement::types::{
    AppRef, RegisterSessionRequest, RegisterSessionResponse, RotateSessionRequest,
    RotateSessionResponse,
};
use automata_tee_workload_measurement::workload_registry::WorkloadRegistry;

use crate::device::{
    DeviceProvider, compute_delegation_digest, compute_nonce_extra_data,
    compute_platform_profile_id, compute_rotation_digest, compute_session_id,
    compute_session_id_from_hashes, compute_variant_id,
};

// =========================================================================
// Configuration
// =========================================================================

/// Configuration for the registration manager.
#[derive(Clone, Debug)]
pub struct RegistrationConfig {
    /// Workload reference ("name:version").
    pub workload_ref: AppRef,
    /// Base image reference ("name:version").
    pub base_image_ref: AppRef,
    /// Owner secp256k1 private key bytes.
    pub owner_private_key: B256,
    /// SessionRegistry contract address (needed for message signing).
    pub session_registry_address: Address,
    /// Session expiry offset in seconds (default: 3600).
    pub expire_offset: u64,
}

impl RegistrationConfig {
    pub fn expire_offset(&self) -> u64 {
        if self.expire_offset == 0 {
            3600
        } else {
            self.expire_offset
        }
    }
}

// =========================================================================
// RegistrationManager
// =========================================================================

/// Orchestrates session registration and rotation against the on-chain
/// SessionRegistry contract.
///
/// Generic over `D: DeviceProvider` so it works with both real TEE/TPM
/// hardware and a mock implementation.
pub struct RegistrationManager<D: DeviceProvider> {
    device: D,
    measurement: Arc<WorkloadMeasurement>,
    config: RegistrationConfig,

    // Derived from config (computed once in new())
    owner_signer: PrivateKeySigner,
    owner_identity: PublicIdentity,
    owner_fingerprint: B256,
    workload_id: B256,
    base_image_id: B256,

    // Session state (populated after register/rotate)
    current_session_id: Option<B256>,
    tee_report_hash: Option<B256>,
    session_key: Option<SigningKey>,
    session_key_public: Option<PublicIdentity>,
}

impl<D: DeviceProvider> RegistrationManager<D> {
    /// Create a new registration manager.
    pub fn new(
        device: D,
        measurement: Arc<WorkloadMeasurement>,
        config: RegistrationConfig,
    ) -> Result<Self> {
        let owner_signer = PrivateKeySigner::from_bytes(&config.owner_private_key)
            .context("invalid owner private key")?;
        let owner_identity = PublicIdentity::secp256k1(&owner_signer);
        let owner_fingerprint = owner_identity.fingerprint();
        let workload_id = WorkloadRegistry::get_workload_id(&config.workload_ref);
        let base_image_id = BaseImageRegistry::get_image_id(&config.base_image_ref);

        Ok(Self {
            device,
            measurement,
            config,
            owner_signer,
            owner_identity,
            owner_fingerprint,
            workload_id,
            base_image_id,
            current_session_id: None,
            tee_report_hash: None,
            session_key: None,
            session_key_public: None,
        })
    }

    /// Return the current session ID, if registered.
    pub fn current_session_id(&self) -> Option<B256> {
        self.current_session_id
    }

    /// Return the current session key public identity, if registered.
    pub fn session_key_public(&self) -> Option<&PublicIdentity> {
        self.session_key_public.as_ref()
    }

    // =====================================================================
    // Registration
    // =====================================================================

    /// Perform a full session registration on-chain.
    ///
    /// Follows the Go `Register()` flow step-by-step, calling into the
    /// `DeviceProvider` for all hardware operations.
    pub async fn register(&mut self) -> Result<RegisterSessionResponse> {
        info!("Starting session registration...");

        // 1. Get chain ID
        let chain_id = self.measurement.chain_id().await;

        // 2. Query nonce
        let nonce_u256 = self
            .measurement
            .session_nonce(&self.owner_identity)
            .await
            .context("get session nonce")?;
        let nonce = nonce_u256.to::<u64>();
        info!(nonce, "Current nonce");

        // 3. Generate new session key (secp256k1)
        let session_key = SigningKey::random(&mut rand::rngs::OsRng);
        let session_pub = session_key_public_identity(&session_key);
        let session_key_fingerprint = session_pub.fingerprint();

        // 4. Get AK public key (needed for report_data)
        // let ak_pub = self.device.get_ak_pub().context("get AK public key")?;

        // 5. Compute report_data = SHA256(ak_pub.key) || zeros (64 bytes)
        // let ak_hash: [u8; 32] = Sha256::digest(&ak_pub.key).into();
        // let mut report_data = [0u8; 64];
        // report_data[..32].copy_from_slice(&ak_hash);

        // 6. Get TEE report
        let tee_report = self
            .device
            .get_tee_report()
            .await
            .context("get TEE report")?;

        // 7. Compute tee_report_hash before moving tee_report into the request
        let tee_report_hash = keccak256(&tee_report.data);

        // 8. Compute nonce extra_data for TPM quote
        let extra_data = compute_nonce_extra_data(self.owner_fingerprint, nonce);

        // 9. Get TPM quote with nonce binding
        let tpm_quote = self
            .device
            .get_tpm_quote(extra_data.as_ref())
            .await
            .context("get TPM quote")?;

        // 10. Certify signing key with AK
        let tpm_certify_report = self
            .device
            .certify_signing_key()
            .await
            .context("certify signing key")?;

        // 11. Get AK collateral
        let ak_pub_collateral = self
            .device
            .get_ak_pub_collateral()
            .await
            .context("get AK pub collateral")?;

        // 12. Compute session ID from TEE report data + TPM signature
        let session_id = compute_session_id(&tee_report.data, &tpm_quote.tpm_signature);
        info!(%session_id, "Computed session ID");

        // 13. Compute delegation digest
        let delegation_digest = compute_delegation_digest(
            self.base_image_id,
            self.workload_id,
            session_id,
            session_key_fingerprint,
        );

        // 14. Sign delegation with TPM signing key (P-256)
        let session_key_signature = self
            .device
            .sign_with_signing_key(delegation_digest.as_ref())
            .await
            .context("sign delegation digest")?;

        // 15. Get platform info and compute profile/variant IDs
        let platform_info = self.device.get_platform_info();
        let platform_profile_id = compute_platform_profile_id(
            self.base_image_id,
            &platform_info.cloud_type,
            &platform_info.tee_type,
        );
        let variant_id = compute_variant_id(platform_profile_id, &platform_info.machine_type);

        // 16. Compute expiry
        let expire_at = current_timestamp() + self.config.expire_offset();

        // 17. Sign registration message with owner key (SHA256, not keccak!)
        let owner_signature = sign_registration_message(
            chain_id,
            self.config.session_registry_address,
            expire_at,
            session_id,
            &self.owner_signer,
        )
        .await
        .context("sign registration message")?;

        // 18. Build request and submit
        let request = RegisterSessionRequest {
            evidence: AttestationEvidence {
                tee_report,
                tpm_quote_report: tpm_quote.tpm_report,
                tpm_certify_report,
                ak_pub_collateral,
                session_key_signature,
                session_key: session_pub.clone(),
            },
            workload_id: self.workload_id,
            base_image_id: self.base_image_id,
            platform_profile_id,
            variant_id,
            expire_at,
            owner_identity: self.owner_identity.clone(),
            owner_signature,
        };

        info!("Submitting registration to blockchain...");
        let response = self
            .measurement
            .register_session(request)
            .await
            .context("register session")?;

        // 19. Store session state
        self.current_session_id = Some(response.session_id);
        self.tee_report_hash = Some(tee_report_hash);
        self.session_key = Some(session_key);
        self.session_key_public = Some(session_pub);

        info!(
            session_id = %response.session_id,
            tx_hash = %response.tx_hash,
            "Session registered successfully"
        );

        Ok(response)
    }

    // =====================================================================
    // Rotation
    // =====================================================================

    /// Perform a session rotation on-chain.
    ///
    /// Follows the Go `Rotate()` flow step-by-step.
    pub async fn rotate(&mut self) -> Result<RotateSessionResponse> {
        let old_session_id = self
            .current_session_id
            .ok_or_else(|| anyhow::anyhow!("no current session to rotate"))?;
        let tee_report_hash = self
            .tee_report_hash
            .ok_or_else(|| anyhow::anyhow!("no TEE report hash from registration"))?;

        info!(%old_session_id, "Starting session rotation...");

        // 1. Get chain ID
        let chain_id = self.measurement.chain_id().await;

        // 2. Query new nonce
        let nonce_u256 = self
            .measurement
            .session_nonce(&self.owner_identity)
            .await
            .context("get session nonce")?;
        let nonce = nonce_u256.to::<u64>();
        info!(nonce, "Current nonce");

        // 3. Generate new session key (secp256k1)
        let new_session_key = SigningKey::random(&mut rand::rngs::OsRng);
        let new_session_pub = session_key_public_identity(&new_session_key);
        let session_key_fingerprint = new_session_pub.fingerprint();

        // 4. Create temporary signing key for rotation
        self.device
            .create_tmp_signing_key()
            .await
            .context("create tmp signing key")?;

        // 5. Get old and new signing key public identities
        let old_tpm_signing_key = self
            .device
            .get_signing_key_public()
            .context("get old signing key public")?;

        let tmp_signing_key_pub = self
            .device
            .get_tmp_signing_key_public()
            .context("get tmp signing key public")?;

        // 6. Compute nonce extra_data
        let extra_data = compute_nonce_extra_data(self.owner_fingerprint, nonce);

        // 7. Get TPM quote with new nonce binding
        let tpm_quote = self
            .device
            .get_tpm_quote(extra_data.as_ref())
            .await
            .context("get TPM quote")?;

        // 8. Certify tmp key with AK
        let tpm_certify_report = self
            .device
            .certify_tmp_signing_key()
            .await
            .context("certify tmp signing key")?;

        // 9. Get AK public key
        let ak_pub = self.device.get_ak_pub().context("get AK public key")?;

        // 10. Compute new session ID from tee_report_hash + new TPM signature
        let new_tpm_sig_hash = keccak256(&tpm_quote.tpm_signature);
        let new_session_id = compute_session_id_from_hashes(tee_report_hash, new_tpm_sig_hash);
        info!(%new_session_id, "Computed new session ID");

        // 11. Compute new TPM key fingerprint
        let new_key_fingerprint = tmp_signing_key_pub.fingerprint();

        // 12. Compute rotation digest and sign with OLD key
        let rotation_digest = compute_rotation_digest(
            old_session_id,
            new_key_fingerprint,
            session_key_fingerprint,
            tee_report_hash,
        );

        let rotation_signature = self
            .device
            .sign_with_signing_key(rotation_digest.as_ref())
            .await
            .context("sign rotation digest")?;

        // 13. Compute delegation digest with new session_id
        let delegation_digest = compute_delegation_digest(
            self.base_image_id,
            self.workload_id,
            new_session_id,
            session_key_fingerprint,
        );

        // 14. Sign delegation with NEW tmp key
        let session_key_signature = self
            .device
            .sign_with_tmp_key(delegation_digest.as_ref())
            .await
            .context("sign delegation with tmp key")?;

        // 15. Compute expiry
        let expire_at = current_timestamp() + self.config.expire_offset();

        // 16. Sign rotation message with owner key (SHA256)
        let owner_signature = sign_rotation_message(
            chain_id,
            self.config.session_registry_address,
            expire_at,
            old_session_id,
            new_session_id,
            &self.owner_signer,
        )
        .await
        .context("sign rotation message")?;

        // 17. Build request and submit
        let request = RotateSessionRequest {
            old_session_id,
            tee_report_bytes_hash: tee_report_hash,
            rotation_evidence: SessionRotationEvidence {
                tpm_quote_report: tpm_quote.tpm_report,
                tpm_certify_report,
                session_key_signature,
                session_key: new_session_pub.clone(),
                rotation_signature,
                old_tpm_signing_key,
                ak_pub,
            },
            expire_at,
            owner_identity: self.owner_identity.clone(),
            owner_signature,
        };

        info!("Submitting rotation to blockchain...");
        let response = self
            .measurement
            .rotate_session(request)
            .await
            .context("rotate session")?;

        // 18. Promote the temporary key to be the current signing key
        self.device
            .promote_tmp_key()
            .await
            .context("promote tmp key")?;

        // 19. Update session state
        self.current_session_id = Some(response.new_session_id);
        // tee_report_hash stays the same for rotation
        self.session_key = Some(new_session_key);
        self.session_key_public = Some(new_session_pub);

        info!(
            new_session_id = %response.new_session_id,
            tx_hash = %response.tx_hash,
            "Session rotated successfully"
        );

        Ok(response)
    }

    // =====================================================================
    // Auto-rotation loop
    // =====================================================================

    /// Run the registration + auto-rotation loop.
    ///
    /// 1. Registers a new session
    /// 2. Sleeps for 80% of the expire offset
    /// 3. Rotates the session
    /// 4. Repeats until `shutdown` is cancelled
    pub async fn run(&mut self, shutdown: CancellationToken) -> Result<()> {
        info!("Starting registration/rotation loop...");

        // Initial registration with retries
        self.register_with_retries(&shutdown).await?;

        // Compute rotation interval (80% of expire offset, minimum 60 seconds)
        let expire_secs = self.config.expire_offset();
        let rotation_secs = ((expire_secs as f64) * 0.8) as u64;
        let rotation_secs = rotation_secs.max(60);
        let rotation_interval = std::time::Duration::from_secs(rotation_secs);
        info!(?rotation_interval, "Rotation interval");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("Registration loop stopped by shutdown signal");
                    return Ok(());
                }
                _ = tokio::time::sleep(rotation_interval) => {
                    info!("Time to rotate session...");
                    if let Err(e) = self.rotate_with_retries(&shutdown).await {
                        warn!(error = %e, "Rotation failed, will retry next interval");
                    }
                }
            }
        }
    }

    /// Attempt registration with exponential backoff.
    async fn register_with_retries(&mut self, shutdown: &CancellationToken) -> Result<()> {
        const MAX_RETRIES: u32 = 5;

        for attempt in 0..MAX_RETRIES {
            if shutdown.is_cancelled() {
                bail!("registration cancelled by shutdown");
            }

            match self.register().await {
                Ok(resp) => {
                    info!(session_id = %resp.session_id, "Session registered");
                    return Ok(());
                }
                Err(e) => {
                    let delay_secs = 60u64 * (1 << attempt);
                    warn!(
                        attempt = attempt + 1,
                        max_retries = MAX_RETRIES,
                        error = ?e,
                        retry_delay_secs = delay_secs,
                        "Registration attempt failed"
                    );

                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            bail!("registration cancelled by shutdown");
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {}
                    }
                }
            }
        }

        bail!("registration failed after {MAX_RETRIES} attempts");
    }

    /// Attempt rotation with exponential backoff.
    async fn rotate_with_retries(&mut self, shutdown: &CancellationToken) -> Result<()> {
        const MAX_RETRIES: u32 = 3;

        for attempt in 0..MAX_RETRIES {
            if shutdown.is_cancelled() {
                bail!("rotation cancelled by shutdown");
            }

            match self.rotate().await {
                Ok(resp) => {
                    info!(new_session_id = %resp.new_session_id, "Session rotated");
                    return Ok(());
                }
                Err(e) => {
                    let delay_secs = 10u64 * (1 << attempt);
                    warn!(
                        attempt = attempt + 1,
                        max_retries = MAX_RETRIES,
                        error = %e,
                        retry_delay_secs = delay_secs,
                        "Rotation attempt failed"
                    );

                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            bail!("rotation cancelled by shutdown");
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {}
                    }
                }
            }
        }

        bail!("rotation failed after {MAX_RETRIES} attempts");
    }
}

// =========================================================================
// Helper functions
// =========================================================================

/// Derive the session key's `PublicIdentity` (secp256k1, 65-byte uncompressed).
fn session_key_public_identity(signing_key: &SigningKey) -> PublicIdentity {
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false); // uncompressed
    let public_key_bytes = encoded_point.as_bytes(); // 65 bytes: 0x04 || x || y

    PublicIdentity {
        type_id: 3, // Es256K = secp256k1
        key: Bytes::copy_from_slice(public_key_bytes),
    }
}

/// Get the current unix timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Sign a registration message with SHA256 (matching the Go `SignRegistrationMessage`).
///
/// message = abi.encode(MSG_REGISTER_DOMAIN, chainId, contractAddr, expireAt, sessionId)
/// hash = SHA256(message)
/// signature = secp256k1_sign(hash, owner_key)
async fn sign_registration_message(
    chain_id: u64,
    contract_addr: Address,
    expire_at: u64,
    session_id: B256,
    signer: &PrivateKeySigner,
) -> Result<Bytes> {
    sign_message(
        &(
            keccak256(b"CVM_MSG_SESSION_REGISTER_V1"),
            U256::from(chain_id),
            contract_addr,
            U256::from(expire_at),
            session_id,
        ),
        signer,
    )
    .await
    .context("sign registration message")
}

/// Sign a rotation message with SHA256 (matching the Go `SignRotationMessage`).
///
/// message = abi.encode(MSG_ROTATE_DOMAIN, chainId, contractAddr, expireAt, oldSessionId, newSessionId)
/// hash = SHA256(message)
/// signature = secp256k1_sign(hash, owner_key)
async fn sign_rotation_message(
    chain_id: u64,
    contract_addr: Address,
    expire_at: u64,
    old_session_id: B256,
    new_session_id: B256,
    signer: &PrivateKeySigner,
) -> Result<Bytes> {
    sign_message(
        &(
            keccak256(b"CVM_MSG_SESSION_ROTATE_V1"),
            U256::from(chain_id),
            contract_addr,
            U256::from(expire_at),
            old_session_id,
            new_session_id,
        ),
        signer,
    )
    .await
    .context("sign rotation message")
}
