//! Register session command implementation.
//!
//! Fetches attestation evidence from a CVM agent and registers it
//! to the SessionRegistry contract. Then tests session rotation.

use std::time::Duration;

use alloy::ext::NetworkProvider;
use alloy::primitives::{Address, B256, Bytes, keccak256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use automata_tee_workload_measurement::base_image_registry::BaseImageRegistry;
use automata_tee_workload_measurement::stubs::{AlgoId, PublicIdentity};
use automata_tee_workload_measurement::types::AppRef;
use automata_tee_workload_measurement::workload_registry::WorkloadRegistry;
use clap::Args;
use serde::{Deserialize, Serialize};
use tracing::info;

use automata_tee_workload_measurement::session_registry::SessionRegistry;
use automata_tee_workload_measurement::stubs::{
    AkPubCollateral, AttestationEvidence, SessionRotationEvidence, TeeReport, TpmReport,
};

#[derive(Args)]
pub struct RegisterSession {
    /// CVM agent IP address
    ip: String,

    /// Ethereum RPC URL
    #[arg(long, env = "ATAKIT_RPC_URL")]
    rpc_url: String,

    /// Private key for signing transactions
    #[arg(long, env = "ATAKIT_PRIVATE_KEY")]
    private_key: String,

    /// SessionRegistry contract address
    #[arg(long, env = "ATAKIT_SESSION_REGISTRY_ADDRESS")]
    registry_address: String,

    /// Chain ID (sent to CVM agent for attestation)
    #[arg(long)]
    chain_id: String,

    /// Workload name (e.g., "secure-signer:v0.0.1")
    /// ID computed as: keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))
    #[arg(long)]
    workload: String,

    /// Base image name:version (e.g., "automata-linux:v0.0.1")
    /// ID computed as: keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))
    #[arg(long)]
    base_image: String,

    /// Signature expiration offset in seconds
    #[arg(long, default_value = "3600")]
    expire_offset: u64,
}

// ============================================================================
// Session Evidence Request/Response (for registration)
// ============================================================================

#[derive(Debug, Serialize)]
struct SessionEvidenceRequest {
    chain_id: String,
    report_type: u8,
    base_image_id: B256,
    workload_id: B256,
    owner_type_id: u8,
    owner_pub_key: Bytes,
    owner_nonce: u64,
}

#[derive(Debug, Deserialize)]
struct SessionEvidenceResponse {
    tee_report: TeeReportData,
    tpm_quote_report: TpmReportData,
    tpm_certify_report: TpmReportData,
    ak_pub_collateral: AkPubCollateralData,
    session_key_signature: String,
    session_key: PublicIdentityData,
    platform_profile_id: String,
    variant_id: String,
}

// ============================================================================
// Rotation Evidence Request/Response (for rotation)
// ============================================================================

#[derive(Debug, Serialize)]
struct RotationEvidenceRequest {
    chain_id: String,
    report_type: u8,
    old_session_id: B256,
    tee_report_hash: B256,
    base_image_id: B256,
    workload_id: B256,
    owner_type_id: u8,
    owner_pub_key: Bytes,
    owner_nonce: u64,
}

#[derive(Debug, Deserialize)]
struct RotationEvidenceResponse {
    tpm_quote_report: TpmReportData,
    tpm_certify_report: TpmReportData,
    session_key_signature: String,
    session_key: PublicIdentityData,
    rotation_signature: String,
    old_tpm_signing_key: PublicIdentityData,
    ak_pub: PublicIdentityData,
}

// ============================================================================
// Shared Data Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct TeeReportData {
    verification_backend_type: u8,
    tee_type: u8,
    data: String,
}

#[derive(Debug, Deserialize)]
struct TpmReportData {
    verification_backend_type: u8,
    tpm_report_type: u8,
    data: String,
}

#[derive(Debug, Deserialize)]
struct AkPubCollateralData {
    ak_pub_collateral_type: u8,
    data: String,
}

#[derive(Debug, Deserialize)]
struct PublicIdentityData {
    type_id: u8,
    key: String,
}

/// Decode hex string, stripping optional "0x" prefix (for hexutil.Bytes compatibility)
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).context("Failed to decode hex")
}

impl SessionEvidenceResponse {
    fn into_attestation_evidence(self) -> Result<AttestationEvidence> {
        Ok(AttestationEvidence {
            tee_report: TeeReport {
                verification_backend_type: self.tee_report.verification_backend_type,
                tee_type: self.tee_report.tee_type,
                data: decode_hex(&self.tee_report.data)
                    .context("Failed to decode tee_report.data")?
                    .into(),
            },
            tpm_quote_report: TpmReport {
                verification_backend_type: self.tpm_quote_report.verification_backend_type,
                tpm_report_type: self.tpm_quote_report.tpm_report_type,
                data: decode_hex(&self.tpm_quote_report.data)
                    .context("Failed to decode tpm_quote_report.data")?
                    .into(),
            },
            tpm_certify_report: TpmReport {
                verification_backend_type: self.tpm_certify_report.verification_backend_type,
                tpm_report_type: self.tpm_certify_report.tpm_report_type,
                data: decode_hex(&self.tpm_certify_report.data)
                    .context("Failed to decode tpm_certify_report.data")?
                    .into(),
            },
            ak_pub_collateral: AkPubCollateral {
                ak_pub_collateral_type: self.ak_pub_collateral.ak_pub_collateral_type,
                data: decode_hex(&self.ak_pub_collateral.data)
                    .context("Failed to decode ak_pub_collateral.data")?
                    .into(),
            },
            session_key_signature: decode_hex(&self.session_key_signature)
                .context("Failed to decode session_key_signature")?
                .into(),
            session_key: PublicIdentity {
                type_id: self.session_key.type_id,
                key: decode_hex(&self.session_key.key)
                    .context("Failed to decode session_key.key")?
                    .into(),
            },
        })
    }

    /// Get the tee_report_hash for rotation (keccak256 of tee_report.data)
    fn tee_report_hash(&self) -> Result<B256> {
        let data = decode_hex(&self.tee_report.data)?;
        Ok(keccak256(&data))
    }
}

impl RotationEvidenceResponse {
    fn into_rotation_evidence(self) -> Result<SessionRotationEvidence> {
        Ok(SessionRotationEvidence {
            tpm_quote_report: TpmReport {
                verification_backend_type: self.tpm_quote_report.verification_backend_type,
                tpm_report_type: self.tpm_quote_report.tpm_report_type,
                data: decode_hex(&self.tpm_quote_report.data)
                    .context("Failed to decode tpm_quote_report.data")?
                    .into(),
            },
            tpm_certify_report: TpmReport {
                verification_backend_type: self.tpm_certify_report.verification_backend_type,
                tpm_report_type: self.tpm_certify_report.tpm_report_type,
                data: decode_hex(&self.tpm_certify_report.data)
                    .context("Failed to decode tpm_certify_report.data")?
                    .into(),
            },
            session_key_signature: decode_hex(&self.session_key_signature)
                .context("Failed to decode session_key_signature")?
                .into(),
            session_key: PublicIdentity {
                type_id: self.session_key.type_id,
                key: decode_hex(&self.session_key.key)
                    .context("Failed to decode session_key.key")?
                    .into(),
            },
            rotation_signature: decode_hex(&self.rotation_signature)
                .context("Failed to decode rotation_signature")?
                .into(),
            old_tpm_signing_key: PublicIdentity {
                type_id: self.old_tpm_signing_key.type_id,
                key: decode_hex(&self.old_tpm_signing_key.key)
                    .context("Failed to decode old_tpm_signing_key.key")?
                    .into(),
            },
            ak_pub: PublicIdentity {
                type_id: self.ak_pub.type_id,
                key: decode_hex(&self.ak_pub.key)
                    .context("Failed to decode ak_pub.key")?
                    .into(),
            },
        })
    }
}

impl RegisterSession {
    pub async fn run(self) -> Result<()> {
        // 1. Parse workload and base-image names, compute IDs
        let workload_ref: AppRef = self.workload.parse().context("Invalid --workload format")?;
        let base_image_ref: AppRef = self
            .base_image
            .parse()
            .context("Invalid --base-image format")?;

        let workload_id = WorkloadRegistry::get_workload_id(&workload_ref);
        let base_image_id = BaseImageRegistry::get_image_id(&base_image_ref);

        info!(
            workload = %self.workload,
            workload_id = %workload_id,
            base_image = %self.base_image,
            base_image_id = %base_image_id,
            "Computed registration IDs"
        );

        // 2. Create provider and registry client first (need to query nonce)
        let registry_address: Address = self
            .registry_address
            .parse()
            .context("Invalid registry_address format")?;
        let signer: PrivateKeySigner = self
            .private_key
            .parse()
            .context("Invalid private_key format")?;

        let provider = NetworkProvider::with_http(
            &self.rpc_url,
            Some(Duration::from_secs(12)),
            Some(Duration::from_secs(36)),
            100,
        )
        .await
        .context("Failed to create network provider")?
        .with_signer(signer.clone());

        let registry = SessionRegistry::new(registry_address, provider);

        // 3. Get owner identity and compute fingerprint
        let owner_identity = PublicIdentity::secp256k1(&signer);
        let owner_fingerprint = owner_identity.fingerprint();
        let owner_pub_key: Bytes = owner_identity.key.clone();
        let owner_type_id = AlgoId::Es256K as u8;

        info!(
            owner_fingerprint = %owner_fingerprint,
            "Computed owner fingerprint"
        );

        // 4. Query nonce from contract
        let owner_nonce = registry
            .get_nonce(owner_fingerprint)
            .await
            .context("Failed to query owner nonce")?;
        let owner_nonce_u64: u64 = owner_nonce.to();

        info!(
            owner_nonce = owner_nonce_u64,
            "Queried owner nonce from contract"
        );

        // 5. Fetch attestation evidence from CVM agent (with owner info for nonce binding)
        info!(ip = %self.ip, "Fetching attestation evidence from CVM agent");
        let response = fetch_session_evidence(
            &self.ip,
            &self.chain_id,
            base_image_id,
            workload_id,
            owner_type_id,
            owner_pub_key.clone(),
            owner_nonce_u64,
        )
        .await?;

        // 6. Parse IDs from CVM agent response (platform_profile_id and variant_id)
        let platform_profile_id: B256 = response
            .platform_profile_id
            .parse()
            .context("Invalid platform_profile_id from CVM agent")?;
        let variant_id: B256 = response
            .variant_id
            .parse()
            .context("Invalid variant_id from CVM agent")?;

        // Save tee_report_hash for rotation
        let tee_report_hash = response.tee_report_hash()?;

        info!(
            platform_profile_id = %platform_profile_id,
            variant_id = %variant_id,
            tee_report_hash = %tee_report_hash,
            "Received computed IDs from CVM agent"
        );

        let evidence = response.into_attestation_evidence()?;

        info!("Registering session on-chain");

        // 7. Register session
        let register_response = registry
            .register_session(
                &signer,
                evidence,
                workload_ref.clone(),
                base_image_ref.clone(),
                platform_profile_id,
                variant_id,
                self.expire_offset,
            )
            .await?;

        let session_id = register_response.session_id;
        println!("Session registered: 0x{}", hex::encode(session_id));

        // ========================================================================
        // Test Session Rotation
        // ========================================================================

        info!("Testing session rotation...");

        // Query updated nonce (should be incremented after registration)
        let rotation_nonce = registry
            .get_nonce(owner_fingerprint)
            .await
            .context("Failed to query owner nonce for rotation")?;
        let rotation_nonce_u64: u64 = rotation_nonce.to();

        info!(
            rotation_nonce = rotation_nonce_u64,
            "Queried nonce for rotation"
        );

        // Fetch rotation evidence from CVM agent
        info!(ip = %self.ip, "Fetching rotation evidence from CVM agent");
        let rotation_response = fetch_rotation_evidence(
            &self.ip,
            &self.chain_id,
            session_id,
            tee_report_hash,
            base_image_id,
            workload_id,
            owner_type_id,
            owner_pub_key,
            rotation_nonce_u64,
        )
        .await?;

        let rotation_evidence = rotation_response.into_rotation_evidence()?;

        info!("Rotating session on-chain");

        // Rotate session
        let rotate_response = registry
            .rotate_session(
                &signer,
                session_id,
                tee_report_hash,
                rotation_evidence,
                self.expire_offset,
            )
            .await?;

        let new_session_id = rotate_response.new_session_id;
        println!("Session rotated: 0x{}", hex::encode(new_session_id));
        println!(
            "  Old session: 0x{}\n  New session: 0x{}",
            hex::encode(session_id),
            hex::encode(new_session_id)
        );

        Ok(())
    }
}

async fn fetch_session_evidence(
    ip: &str,
    chain_id: &str,
    base_image_id: B256,
    workload_id: B256,
    owner_type_id: u8,
    owner_pub_key: Bytes,
    owner_nonce: u64,
) -> Result<SessionEvidenceResponse> {
    let url = format!("https://{}:8000/session-evidence", ip);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to build HTTP client")?;

    let request = SessionEvidenceRequest {
        chain_id: chain_id.to_string(),
        report_type: 0, // Solidity verification
        base_image_id,
        workload_id,
        owner_type_id,
        owner_pub_key,
        owner_nonce,
    };

    info!(url = %url, "Sending session evidence request");

    let response = client
        .post(&url)
        .json(&request)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .context("Failed to send session evidence request")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Session evidence request failed: {} - {}", status, body);
    }

    response
        .json()
        .await
        .context("Failed to parse session evidence response")
}

async fn fetch_rotation_evidence(
    ip: &str,
    chain_id: &str,
    old_session_id: B256,
    tee_report_hash: B256,
    base_image_id: B256,
    workload_id: B256,
    owner_type_id: u8,
    owner_pub_key: Bytes,
    owner_nonce: u64,
) -> Result<RotationEvidenceResponse> {
    let url = format!("https://{}:8000/rotation-evidence", ip);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to build HTTP client")?;

    let request = RotationEvidenceRequest {
        chain_id: chain_id.to_string(),
        report_type: 0, // Solidity verification
        old_session_id,
        tee_report_hash,
        base_image_id,
        workload_id,
        owner_type_id,
        owner_pub_key,
        owner_nonce,
    };

    info!(url = %url, "Sending rotation evidence request");

    let response = client
        .post(&url)
        .json(&request)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .context("Failed to send rotation evidence request")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Rotation evidence request failed: {} - {}", status, body);
    }

    response
        .json()
        .await
        .context("Failed to parse rotation evidence response")
}
