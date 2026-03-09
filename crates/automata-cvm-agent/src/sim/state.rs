//! Per-service cryptographic state for the simulated CVM agent.
//!
//! Holds session and owner key pairs, and provides signing / key-rotation
//! methods that are independent of the HTTP transport layer.

use std::sync::Arc;

use alloy::primitives::{B256, Bytes, keccak256};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail};
use automata_tee_workload_measurement::stubs::PublicIdentity;

use crate::client::cvm_agent::{RotateKeyResponse, SignMessageResponse};
use crate::mock::mock_device::MockDeviceProvider;
use crate::registration::RegistrationManager;

/// Shared cryptographic state for a single simulated service.
pub struct ServiceState {
    owner_signer: PrivateKeySigner,
    workload_id: B256,
    base_image_id: B256,
    registration: Arc<RegistrationManager<MockDeviceProvider>>,
}

impl ServiceState {
    /// Create a new `ServiceState` with a random session key and the given owner key.
    pub fn new(
        workload_id: B256,
        base_image_id: B256,
        owner_private_key: B256,
        registration: Arc<RegistrationManager<MockDeviceProvider>>,
    ) -> Result<Self> {
        if owner_private_key == B256::ZERO {
            bail!("owner_private_key must not be zero");
        }
        let owner_signer = PrivateKeySigner::from_bytes(&owner_private_key)
            .context("invalid owner_private_key")?;
        Ok(Self {
            owner_signer,
            workload_id,
            base_image_id,
            registration,
        })
    }

    /// Public identity of the owner key.
    pub fn owner_public(&self) -> PublicIdentity {
        PublicIdentity::secp256k1(&self.owner_signer)
    }

    /// Sign `message` with the current session key and return a full
    /// [`SignMessageResponse`] including both public identities.
    pub async fn sign(&self, message: &[u8]) -> Result<SignMessageResponse> {
        let session = self
            .registration
            .current_session()
            .await
            .context("No active session - registration may not have completed yet")?;

        let hash = keccak256(message);

        let signature = session
            .session_signing_key
            .sign_hash(&hash)
            .await
            .context("Failed to sign message")?;

        // Build 65-byte signature: [R || S || V]
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig_bytes[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig_bytes[64] = if signature.v() { 28 } else { 27 };

        let owner_public = PublicIdentity::secp256k1(&self.owner_signer);
        let owner_fingerprint = owner_public.fingerprint();

        Ok(SignMessageResponse {
            signature: Bytes::from(sig_bytes.to_vec()),
            session_id: session.session_id,
            session_key_public: session.session_key_public.clone(),
            session_key_fingerprint: session.session_key_public.fingerprint(),
            owner_key_public: owner_public,
            owner_fingerprint,
            workload_id: self.workload_id,
            base_image_id: self.base_image_id,
        })
    }

    /// Generate a fresh session key and return the new public identity.
    pub async fn rotate_session_key(&self) -> Result<RotateKeyResponse> {
        let resp = self
            .registration
            .rotate()
            .await
            .context("session rotation failed")?;

        let session = self
            .registration
            .current_session()
            .await
            .context("no session after rotation")?;

        Ok(RotateKeyResponse {
            session_id: resp.new_session_id,
            session_key_fingerprint: session.session_key_fingerprint(),
            session_key_public: session.session_key_public,
            tx_hash: Some(resp.tx_hash),
        })
    }
}
