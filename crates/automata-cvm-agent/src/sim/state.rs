//! Per-service cryptographic state for the simulated CVM agent.
//!
//! Holds session and owner key pairs, and provides signing / key-rotation
//! methods that are independent of the HTTP transport layer.

use alloy::primitives::{B256, Bytes, keccak256};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use automata_tee_workload_measurement::stubs::PublicIdentity;
use tokio::sync::RwLock;

use crate::client::cvm_agent::{RotateKeyResponse, SignMessageResponse};

/// Shared cryptographic state for a single simulated service.
pub struct ServiceState {
    session_signer: RwLock<PrivateKeySigner>,
    owner_signer: PrivateKeySigner,
    workload_id: B256,
    base_image_id: B256,
}

impl ServiceState {
    /// Create a new `ServiceState` with random session and owner keys.
    pub fn new(workload_id: B256, base_image_id: B256) -> Self {
        Self {
            session_signer: RwLock::new(PrivateKeySigner::random()),
            owner_signer: PrivateKeySigner::random(),
            workload_id,
            base_image_id,
        }
    }

    /// Public identity of the current session key.
    pub async fn session_public(&self) -> PublicIdentity {
        let signer = self.session_signer.read().await;
        PublicIdentity::secp256k1(&*signer)
    }

    /// Public identity of the owner key.
    pub fn owner_public(&self) -> PublicIdentity {
        PublicIdentity::secp256k1(&self.owner_signer)
    }

    /// Sign `message` with the current session key and return a full
    /// [`SignMessageResponse`] including both public identities.
    pub async fn sign(&self, message: &[u8]) -> Result<SignMessageResponse> {
        let signer = self.session_signer.read().await;

        let hash = keccak256(message);

        let signature = signer
            .sign_hash(&hash)
            .await
            .context("Failed to sign message")?;

        // Build 65-byte signature: [R || S || V]
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig_bytes[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig_bytes[64] = if signature.v() { 1 } else { 0 };

        let session_public = PublicIdentity::secp256k1(&*signer);
        let session_fingerprint = session_public.fingerprint();
        let owner_public = PublicIdentity::secp256k1(&self.owner_signer);
        let owner_fingerprint = owner_public.fingerprint();

        Ok(SignMessageResponse {
            signature: Bytes::from(sig_bytes.to_vec()),
            session_id: session_fingerprint,
            session_key_public: session_public,
            session_key_fingerprint: session_fingerprint,
            owner_key_public: owner_public,
            owner_fingerprint,
            workload_id: self.workload_id,
            base_image_id: self.base_image_id,
        })
    }

    /// Generate a fresh session key and return the new public identity.
    pub async fn rotate_session_key(&self) -> Result<RotateKeyResponse> {
        let new_signer = PrivateKeySigner::random();

        let session_public = PublicIdentity::secp256k1(&new_signer);
        let session_fingerprint = session_public.fingerprint();

        let response = RotateKeyResponse {
            session_id: session_fingerprint,
            session_key_fingerprint: session_fingerprint,
            session_key_public: session_public,
            tx_hash: None,
        };

        *self.session_signer.write().await = new_signer;

        Ok(response)
    }
}
