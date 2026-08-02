//! Read-only retrieval of trusted inputs for atakit attestation verification.
//!
//! [`AttestationClient`] reads verifier-selected contract state. It never
//! signs or submits a transaction. The caller selects the RPC endpoint and
//! `SessionRegistry`; portal evidence cannot select either value.

pub mod session;

pub use session::{
    verify_current_session, PortalSessionVerificationContext, TlsManualOverride, VerifiedPortalTls,
};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_ext::core::primitives::{Address, B256};
use alloy_ext::ext::{NetworkProvider, ProviderEx};
use atakit_attestation::{
    AmdSnpSecurityPolicy, AzureMaaTrustKey, BaseImage, MeasurementPack, MeasurementPolicy,
    MeasurementProfile, MeasurementVariant, PcrBankSelection, PcrSpec256, PcrSpec384,
    SessionAttributeRequirement, SessionPcrPolicy, SessionPcrPolicy384, SessionPcrVerifyType,
    TrustedSessionBinding,
};
use automata_tee_workload_measurement::base_image_registry::{
    BaseImageHierarchy, BaseImageRegistry,
};
use automata_tee_workload_measurement::stubs::SessionRegistry::SessionRegistryInstance;
use automata_tee_workload_measurement::stubs::WorkloadRegistry::WorkloadSpec;
use automata_tee_workload_measurement::types::AppRef;
use automata_tee_workload_measurement::workload_registry::WorkloadRegistry;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(37);
const REQUEST_RETRIES: u64 = 100;

/// Configuration selected by the verifier.
///
/// `rpc_url` is a trusted data source. This client uses ordinary JSON-RPC
/// calls; it does not verify consensus or storage proofs.
#[derive(Debug, Clone)]
pub struct AttestationClientConfig {
    pub rpc_url: String,
    pub session_registry: String,
    pub expected_chain_id: Option<u64>,
    /// Optional independent expectation. When present, it must match the
    /// address returned by `SessionRegistry.baseImageRegistry()`.
    pub expected_base_image_registry: Option<String>,
    /// Optional independent expectation. When present, it must match the
    /// address returned by `SessionRegistry.workloadRegistry()`.
    pub expected_workload_registry: Option<String>,
}

/// Contract coordinates established from the verifier-selected chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerificationContext {
    pub chain_id: u64,
    pub session_registry: String,
    pub base_image_registry: String,
    pub workload_registry: String,
    pub amd_snp_security_policy_registry: String,
}

/// Trusted workload policy resolved from `WorkloadRegistry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedWorkloadSessionPolicy {
    pub workload_id: [u8; 32],
    pub pcr_specs256: Vec<SessionPcrPolicy>,
    pub pcr_specs384: Vec<SessionPcrPolicy384>,
    pub attribute_requirements: Vec<SessionAttributeRequirement>,
}

/// Read-only client for verifier-selected chain state.
#[derive(Debug, Clone)]
pub struct AttestationClient {
    config: AttestationClientConfig,
    context: ChainVerificationContext,
}

#[derive(Debug, Error)]
pub enum AttestationClientError {
    #[error("invalid attestation client configuration: {0}")]
    Config(String),
    #[error("connect to verifier-selected RPC endpoint: {0}")]
    Connect(String),
    #[error("read verifier-selected chain state: {0}")]
    Rpc(String),
    #[error("invalid trusted base-image policy: {0}")]
    BaseImagePolicy(String),
    #[error("invalid trusted workload policy: {0}")]
    WorkloadPolicy(String),
    #[error("Azure MAA signing key is not registered for kid {kid}")]
    AzureMaaKeyNotRegistered { kid: String },
    #[error("Azure MAA signing key is revoked for kid {kid}")]
    AzureMaaKeyRevoked { kid: String },
    #[error("Azure MAA issuer does not match the registry entry for kid {kid}")]
    AzureMaaIssuerMismatch { kid: String },
    #[error("Azure MAA signing key for kid {kid} expired at Unix time {not_after}")]
    AzureMaaKeyExpired { kid: String, not_after: u64 },
    #[error("portal request failed: {0}")]
    Portal(String),
    #[error("session verification failed: {0}")]
    Verification(String),
    #[error("generate request challenge: {0}")]
    Challenge(String),
}

impl AttestationClient {
    /// Connect to the verifier-selected RPC endpoint and establish the
    /// registry graph rooted at the verifier-selected `SessionRegistry`.
    pub async fn connect(config: AttestationClientConfig) -> Result<Self, AttestationClientError> {
        if config.rpc_url.trim().is_empty() {
            return Err(AttestationClientError::Config(
                "rpc_url must not be empty".to_string(),
            ));
        }
        let session_registry = parse_address("session_registry", &config.session_registry)?;
        let provider = connect_provider(&config.rpc_url).await?;
        let chain_id = provider.chain_id();
        if let Some(expected) = config.expected_chain_id {
            if expected != chain_id {
                return Err(AttestationClientError::Config(format!(
                    "expected_chain_id is {expected}, but rpc_url reports {chain_id}"
                )));
            }
        }

        let registry = SessionRegistryInstance::new(session_registry, provider);
        let workload_registry = registry.workloadRegistry().call().await.map_err(|error| {
            AttestationClientError::Rpc(format!("call SessionRegistry.workloadRegistry(): {error}"))
        })?;
        let base_image_registry = registry.baseImageRegistry().call().await.map_err(|error| {
            AttestationClientError::Rpc(format!(
                "call SessionRegistry.baseImageRegistry(): {error}"
            ))
        })?;
        let amd_snp_security_policy_registry = {
            let result = raw_eth_call(
                &config.rpc_url,
                &session_registry.to_string(),
                encode_no_arg_call("amdSnpSecurityPolicyRegistry()"),
                "SessionRegistry.amdSnpSecurityPolicyRegistry",
            )
            .await?;
            decode_address_return(&result, "SessionRegistry.amdSnpSecurityPolicyRegistry")?
        };

        validate_expected_address(
            "expected_workload_registry",
            config.expected_workload_registry.as_deref(),
            workload_registry,
        )?;
        validate_expected_address(
            "expected_base_image_registry",
            config.expected_base_image_registry.as_deref(),
            base_image_registry,
        )?;

        let context = ChainVerificationContext {
            chain_id,
            session_registry: session_registry.to_string(),
            base_image_registry: base_image_registry.to_string(),
            workload_registry: workload_registry.to_string(),
            amd_snp_security_policy_registry,
        };
        Ok(Self { config, context })
    }

    pub fn context(&self) -> &ChainVerificationContext {
        &self.context
    }

    /// Coordinates used to compare a chain-bound evidence bundle with the
    /// verifier-selected chain.
    pub fn trusted_session_binding(&self) -> TrustedSessionBinding {
        TrustedSessionBinding {
            chain_id: self.context.chain_id,
            registry: parse_context_address(&self.context.session_registry),
        }
    }

    /// Fetch the complete registered base-image hierarchy and convert it to
    /// the policy type consumed by atakit attestation verification.
    pub async fn resolve_base_image_measurement_policy(
        &self,
        base_image: &str,
    ) -> Result<MeasurementPolicy, AttestationClientError> {
        let app_ref: AppRef = base_image.parse().map_err(|error| {
            AttestationClientError::BaseImagePolicy(format!(
                "parse canonical base-image reference {base_image:?}: {error}"
            ))
        })?;
        let base_image_id = BaseImageRegistry::get_image_id(&app_ref);
        let registry_address = parse_address(
            "resolved BaseImageRegistry",
            &self.context.base_image_registry,
        )?;
        let provider = connect_provider(&self.config.rpc_url).await?;
        let hierarchy = BaseImageRegistry::new(registry_address, provider)
            .get_hierarchy(base_image_id)
            .await
            .map_err(|error| {
                AttestationClientError::Rpc(format!(
                    "fetch BaseImageRegistry hierarchy for {base_image}: {error}"
                ))
            })?;
        hierarchy_to_measurement_policy(&hierarchy, &self.context.base_image_registry)
    }

    /// Fetch and validate the exact registered workload policy.
    pub async fn resolve_workload_policy(
        &self,
        workload: &str,
        selected_base_image_id: [u8; 32],
    ) -> Result<TrustedWorkloadSessionPolicy, AttestationClientError> {
        let app_ref: AppRef = workload.parse().map_err(|error| {
            AttestationClientError::WorkloadPolicy(format!(
                "parse canonical workload reference {workload:?}: {error}"
            ))
        })?;
        let workload_id = WorkloadRegistry::get_workload_id(&app_ref);
        let registry_address =
            parse_address("resolved WorkloadRegistry", &self.context.workload_registry)?;
        let provider = connect_provider(&self.config.rpc_url).await?;
        let spec = WorkloadRegistry::new(registry_address, provider)
            .get_workload_spec(workload_id)
            .await
            .map_err(|error| {
                AttestationClientError::Rpc(format!(
                    "fetch WorkloadRegistry policy for {workload}: {error}"
                ))
            })?;
        trusted_workload_policy(&app_ref, workload_id.0, selected_base_image_id, &spec)
    }

    /// Fetch and verify the current evidence bundle after portal TLS has been
    /// independently verified. This method resolves the registered workload
    /// policy and binds chain-mode evidence to this client's chain context.
    pub async fn verify_current_session(
        &self,
        verified_tls: &VerifiedPortalTls,
        host: &str,
        status_port: u16,
        workload: &str,
        required_binding: Option<atakit_attestation::BindingMode>,
    ) -> Result<atakit_attestation::VerifiedSession, AttestationClientError> {
        let base_image_id = verified_tls.identity.base_image_id.ok_or_else(|| {
            AttestationClientError::Verification(
                "verified portal TLS identity has no base-image ID".to_string(),
            )
        })?;
        let workload_policy = self
            .resolve_workload_policy(workload, base_image_id)
            .await?;
        let mut verified_tls = verified_tls.clone();
        let context = verified_tls.session_verification.as_mut().ok_or_else(|| {
            AttestationClientError::Verification(
                "verified portal TLS context has no session verification inputs".to_string(),
            )
        })?;
        context.chain_client = Some(self.clone());
        session::verify_current_session(
            &verified_tls,
            host,
            status_port,
            workload_policy,
            required_binding,
            Some(self.trusted_session_binding()),
        )
        .await
    }

    /// Require the GCP vTPM AK root certificate to be approved by the
    /// `TpmAttestation` contract reached from the selected `SessionRegistry`.
    /// Returns the trusted Keccak-256 root hash used by the verifier.
    pub async fn resolve_gcp_ak_root(
        &self,
        root_der: &[u8],
    ) -> Result<[u8; 32], AttestationClientError> {
        let root_hash: [u8; 32] = Keccak256::digest(root_der).into();
        let ak_collateral_verifier = self.resolve_ak_collateral_verifier().await?;
        let tpm_attestation = self
            .resolve_address_call(
                &ak_collateral_verifier,
                "tpmAttestation()",
                "AkCollateralVerifier.tpmAttestation",
            )
            .await?;
        let trusted = self
            .resolve_bool_call(
                &tpm_attestation,
                encode_bytes32_arg_call("verifiedCA(bytes32)", root_hash),
                "TpmAttestation.verifiedCA",
            )
            .await?;
        if !trusted {
            return Err(AttestationClientError::Rpc(format!(
                "TpmAttestation {tpm_attestation} does not trust GCP AK root keccak256(root_der)={} ",
                hex0x(root_hash)
            )));
        }
        Ok(root_hash)
    }

    /// Require the AMD ARK certificate to be approved by the `SnpAttestation`
    /// contract reached from the selected `SessionRegistry`. Returns the
    /// trusted SHA-256 root hash used by the verifier.
    pub async fn resolve_amd_ark_root(
        &self,
        ark_der: &[u8],
    ) -> Result<[u8; 32], AttestationClientError> {
        let ark_hash: [u8; 32] = Sha256::digest(ark_der).into();
        let tee_verifier = self
            .resolve_address_call(
                &self.context.session_registry,
                "teeVerifier()",
                "SessionRegistry.teeVerifier",
            )
            .await?;
        let snp_attestation = self
            .resolve_address_call(
                &tee_verifier,
                "snpAttestation()",
                "TeeVerifier.snpAttestation",
            )
            .await?;
        for processor_model in 0..8u64 {
            let result = self
                .eth_call(
                    &snp_attestation,
                    encode_uint_arg_call("rootCerts(uint8)", processor_model),
                    "SnpAttestation.rootCerts",
                )
                .await?;
            if result.len() != 32 {
                return Err(AttestationClientError::Rpc(format!(
                    "SnpAttestation.rootCerts returned {} bytes; expected 32",
                    result.len()
                )));
            }
            if result.as_slice() == ark_hash {
                return Ok(ark_hash);
            }
        }
        Err(AttestationClientError::Rpc(format!(
            "SnpAttestation {snp_attestation} does not trust AMD ARK sha256(ark_der)={}",
            hex0x(ark_hash)
        )))
    }

    /// Read the active AMD SEV-SNP policy defaults for the report's exact
    /// family, model, and stepping value.
    pub async fn resolve_amd_snp_security_policy(
        &self,
        cpuid: u32,
    ) -> Result<AmdSnpSecurityPolicy, AttestationClientError> {
        if cpuid > 0x00ff_ffff {
            return Err(AttestationClientError::Config(format!(
                "AMD SEV-SNP CPUID 0x{cpuid:x} does not fit uint24"
            )));
        }
        let result = self
            .eth_call(
                &self.context.amd_snp_security_policy_registry,
                encode_uint_arg_call("getActivePolicy(uint24)", u64::from(cpuid)),
                "AmdSnpSecurityPolicyRegistry.getActivePolicy",
            )
            .await?;
        decode_amd_snp_security_policy_return(&result, cpuid)
    }

    /// Resolve and validate the exact Azure MAA signing key selected by the
    /// JWT `kid` and `iss` claims.
    pub async fn resolve_azure_maa_signing_key(
        &self,
        kid: &str,
        issuer: &str,
    ) -> Result<AzureMaaTrustKey, AttestationClientError> {
        if kid.is_empty() || issuer.is_empty() {
            return Err(AttestationClientError::Config(
                "Azure MAA kid and issuer must not be empty".to_string(),
            ));
        }
        let ak_collateral_verifier = self.resolve_ak_collateral_verifier().await?;
        let maa_key_registry = self
            .resolve_address_call(
                &ak_collateral_verifier,
                "maaKeyRegistry()",
                "AkCollateralVerifier.maaKeyRegistry",
            )
            .await?;
        let kid_hash: [u8; 32] = Keccak256::digest(kid.as_bytes()).into();
        let result = self
            .eth_call(
                &maa_key_registry,
                encode_bytes32_arg_call("getMaaSigningKey(bytes32)", kid_hash),
                "MaaKeyRegistry.getMaaSigningKey",
            )
            .await?;
        let entry = decode_maa_signing_key_return(&result)?;
        if entry.public_key.is_empty() {
            return Err(AttestationClientError::AzureMaaKeyNotRegistered {
                kid: kid.to_string(),
            });
        }
        if entry.revoked {
            return Err(AttestationClientError::AzureMaaKeyRevoked {
                kid: kid.to_string(),
            });
        }
        let expected_issuer_hash: [u8; 32] = Keccak256::digest(issuer.as_bytes()).into();
        if entry.issuer_hash != expected_issuer_hash {
            return Err(AttestationClientError::AzureMaaIssuerMismatch {
                kid: kid.to_string(),
            });
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| AttestationClientError::Config(error.to_string()))?
            .as_secs();
        if now > entry.not_after {
            return Err(AttestationClientError::AzureMaaKeyExpired {
                kid: kid.to_string(),
                not_after: entry.not_after,
            });
        }
        Ok(AzureMaaTrustKey {
            kid: kid.to_string(),
            issuer: issuer.to_string(),
            not_after: entry.not_after,
            public_key: entry.public_key,
        })
    }

    /// Resolve the exact Azure MAA signing key referenced by an
    /// `azure-maa-jwt` AK binding.
    pub async fn resolve_azure_maa_signing_key_from_binding(
        &self,
        binding: &atakit_attestation::AkBinding,
    ) -> Result<AzureMaaTrustKey, AttestationClientError> {
        let (kid, issuer) = azure_maa_identity(binding)?;
        self.resolve_azure_maa_signing_key(&kid, &issuer).await
    }

    async fn resolve_ak_collateral_verifier(&self) -> Result<String, AttestationClientError> {
        self.resolve_address_call(
            &self.context.session_registry,
            "akCollateralVerifier()",
            "SessionRegistry.akCollateralVerifier",
        )
        .await
    }

    async fn resolve_address_call(
        &self,
        contract: &str,
        signature: &str,
        label: &str,
    ) -> Result<String, AttestationClientError> {
        let result = self
            .eth_call(contract, encode_no_arg_call(signature), label)
            .await?;
        decode_address_return(&result, label)
    }

    async fn resolve_bool_call(
        &self,
        contract: &str,
        calldata: Vec<u8>,
        label: &str,
    ) -> Result<bool, AttestationClientError> {
        let result = self.eth_call(contract, calldata, label).await?;
        abi_word_bool(&result).map_err(AttestationClientError::Rpc)
    }

    async fn eth_call(
        &self,
        contract: &str,
        calldata: Vec<u8>,
        label: &str,
    ) -> Result<Vec<u8>, AttestationClientError> {
        raw_eth_call(&self.config.rpc_url, contract, calldata, label).await
    }
}

async fn raw_eth_call(
    rpc_url: &str,
    contract: &str,
    calldata: Vec<u8>,
    label: &str,
) -> Result<Vec<u8>, AttestationClientError> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {
                "to": contract,
                "data": hex0x(calldata),
                "value": "0x0"
            },
            "latest"
        ]
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|error| AttestationClientError::Connect(error.to_string()))?;
    let response: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|error| AttestationClientError::Rpc(format!("call {label}: {error}")))?
        .json()
        .await
        .map_err(|error| {
            AttestationClientError::Rpc(format!("decode {label} response: {error}"))
        })?;
    if let Some(error) = response.get("error") {
        return Err(AttestationClientError::Rpc(format!(
            "{label} returned JSON-RPC error: {error}"
        )));
    }
    let result = response
        .get("result")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            AttestationClientError::Rpc(format!("{label} response is missing result"))
        })?;
    hex::decode(result.strip_prefix("0x").unwrap_or(result)).map_err(|error| {
        AttestationClientError::Rpc(format!("decode {label} result as hex: {error}"))
    })
}

fn decode_amd_snp_security_policy_return(
    bytes: &[u8],
    cpuid: u32,
) -> Result<AmdSnpSecurityPolicy, AttestationClientError> {
    if bytes.len() != 160 && bytes.len() != 224 {
        return Err(AttestationClientError::Rpc(format!(
            "AmdSnpSecurityPolicyRegistry.getActivePolicy returned {} bytes; expected 160 or 224",
            bytes.len()
        )));
    }
    let mut minimum_tcb = [0u8; 32];
    minimum_tcb.copy_from_slice(&bytes[..32]);
    let mut platform_info_policy = [0u8; 32];
    platform_info_policy.copy_from_slice(&bytes[32..64]);
    let revision = abi_word_to_u64(&bytes[96..128])?;
    let active = abi_word_bool(&bytes[128..160]).map_err(AttestationClientError::Rpc)?;
    let required_launch_mitigation_vector = if bytes.len() == 224 {
        abi_word_to_u64(&bytes[160..192])?
    } else {
        0
    };
    let required_current_mitigation_vector = if bytes.len() == 224 {
        abi_word_to_u64(&bytes[192..224])?
    } else {
        0
    };
    if revision == 0 || !active {
        return Err(AttestationClientError::Rpc(format!(
            "AmdSnpSecurityPolicyRegistry returned inactive or revision-zero policy for CPUID 0x{cpuid:06x}"
        )));
    }
    if !atakit_core::tee_attributes::valid_amd_sev_snp_tcb(&minimum_tcb)
        || !atakit_core::tee_attributes::valid_amd_sev_snp_platform_info_policy(
            &platform_info_policy,
        )
    {
        return Err(AttestationClientError::Rpc(format!(
            "AmdSnpSecurityPolicyRegistry returned malformed policy for CPUID 0x{cpuid:06x}"
        )));
    }
    Ok(AmdSnpSecurityPolicy {
        cpuid,
        minimum_tcb,
        platform_info_policy,
        required_launch_mitigation_vector,
        required_current_mitigation_vector,
    })
}

#[derive(Debug)]
struct MaaSigningKeyEntry {
    public_key: Vec<u8>,
    issuer_hash: [u8; 32],
    not_after: u64,
    revoked: bool,
}

async fn connect_provider(rpc_url: &str) -> Result<NetworkProvider, AttestationClientError> {
    NetworkProvider::with_http(
        rpc_url,
        Some(CONNECT_TIMEOUT),
        Some(REQUEST_TIMEOUT),
        REQUEST_RETRIES,
    )
    .await
    .map_err(|error| AttestationClientError::Connect(error.to_string()))
}

fn parse_address(field: &str, value: &str) -> Result<Address, AttestationClientError> {
    value.parse().map_err(|error| {
        AttestationClientError::Config(format!("invalid {field} address {value:?}: {error}"))
    })
}

fn parse_context_address(value: &str) -> [u8; 20] {
    value
        .parse::<Address>()
        .expect("stored chain context address was validated")
        .into_array()
}

fn validate_expected_address(
    field: &str,
    expected: Option<&str>,
    resolved: Address,
) -> Result<(), AttestationClientError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected = parse_address(field, expected)?;
    if expected != resolved {
        return Err(AttestationClientError::Config(format!(
            "{field} is {expected}, but SessionRegistry returns {resolved}"
        )));
    }
    Ok(())
}

fn hierarchy_to_measurement_policy(
    hierarchy: &BaseImageHierarchy,
    registry: &str,
) -> Result<MeasurementPolicy, AttestationClientError> {
    let profiles = hierarchy
        .profiles
        .iter()
        .map(|profile| {
            let (cloud, tee) = infer_cloud_tee_from_profile_name(&profile.profile.name)?;
            let variants = profile
                .variants
                .iter()
                .map(|(variant_id, variant)| MeasurementVariant {
                    name: variant.name.clone(),
                    id: hex0x(variant_id),
                    machine_types: vec![variant.name.clone()],
                    variant_pcrs256: variant
                        .variantPcrs256
                        .iter()
                        .map(chain_pcr_spec256_to_measurement)
                        .collect(),
                    variant_pcrs384: variant
                        .variantPcrs384
                        .iter()
                        .map(chain_pcr_spec384_to_measurement)
                        .collect(),
                    attributes: variant
                        .attributes
                        .iter()
                        .map(|attribute| {
                            serde_json::json!({
                                "key": hex0x(attribute.key),
                                "value": hex0x(attribute.value),
                            })
                        })
                        .collect(),
                })
                .collect();
            Ok(MeasurementProfile {
                name: profile.profile.name.clone(),
                id: hex0x(profile.profile_id),
                cloud: cloud.to_string(),
                tee: tee.to_string(),
                pcr_bank_selection: chain_pcr_bank_selection(profile.profile.pcrBankSelection),
                invariants256: profile
                    .profile
                    .invariants256
                    .iter()
                    .map(chain_pcr_spec256_to_measurement)
                    .collect(),
                invariants384: profile
                    .profile
                    .invariants384
                    .iter()
                    .map(chain_pcr_spec384_to_measurement)
                    .collect(),
                variants,
                attributes: profile
                    .profile
                    .attributes
                    .iter()
                    .map(|attribute| {
                        serde_json::json!({
                            "key": hex0x(attribute.key),
                            "value": hex0x(attribute.value),
                        })
                    })
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, AttestationClientError>>()?;

    Ok(MeasurementPolicy {
        source: format!("chain:{registry}:{}", hex0x(hierarchy.base_image_id)),
        pack: MeasurementPack {
            schema: "atakit.measurement-pack.v2".to_string(),
            revision: 1,
            published_at: chrono::Utc::now().to_rfc3339(),
            base_image: BaseImage {
                name: hierarchy.spec.name.clone(),
                version: hierarchy.spec.version.clone(),
                id: hex0x(hierarchy.base_image_id),
                uri: (!hierarchy.spec.uri.is_empty()).then(|| hierarchy.spec.uri.clone()),
                archive_sha256: None,
            },
            profiles,
        },
    })
}

fn chain_pcr_spec256_to_measurement(
    spec: &automata_tee_workload_measurement::stubs::BaseImageRegistry::PcrSpec256,
) -> PcrSpec256 {
    PcrSpec256 {
        pcr_index: spec.pcrIndex,
        verify_type: match spec.verifyType {
            0 => "static".to_string(),
            1 => "dynamicSubset".to_string(),
            2 => "dynamicSubsequence".to_string(),
            other => format!("unknown-{other}"),
        },
        match_data: spec.matchData.iter().map(hex0x).collect(),
        event_indices: Vec::new(),
        total_events: None,
    }
}

fn chain_pcr_spec384_to_measurement(
    spec: &automata_tee_workload_measurement::stubs::BaseImageRegistry::PcrSpec384,
) -> PcrSpec384 {
    PcrSpec384 {
        pcr_index: spec.pcrIndex,
        verify_type: chain_verify_type(spec.verifyType as u8),
        match_data: spec
            .matchData
            .iter()
            .map(|value| {
                let mut bytes = [0u8; 48];
                bytes[..32].copy_from_slice(value.first.as_slice());
                bytes[32..].copy_from_slice(value.second.as_slice());
                hex0x(&bytes)
            })
            .collect(),
        event_indices: Vec::new(),
        total_events: None,
    }
}

fn chain_verify_type(value: u8) -> String {
    match value {
        0 => "static".to_string(),
        1 => "dynamicSubset".to_string(),
        2 => "dynamicSubsequence".to_string(),
        other => format!("unknown-{other}"),
    }
}

fn chain_pcr_bank_selection(value: u8) -> PcrBankSelection {
    match value {
        0 => PcrBankSelection::Sha256,
        1 => PcrBankSelection::Sha384,
        2 => PcrBankSelection::Sha256AndSha384,
        _ => unreachable!("Solidity enum decoder rejects invalid values"),
    }
}

fn infer_cloud_tee_from_profile_name(
    name: &str,
) -> Result<(&'static str, &'static str), AttestationClientError> {
    let normalized = name.to_ascii_lowercase().replace('_', "-");
    let cloud = if normalized.starts_with("gcp-") || normalized.contains("-gcp-") {
        "gcp"
    } else if normalized.starts_with("azure-") || normalized.contains("-azure-") {
        "azure"
    } else if normalized.starts_with("aws-") || normalized.contains("-aws-") {
        "aws"
    } else {
        return Err(AttestationClientError::BaseImagePolicy(format!(
            "cannot infer cloud from BaseImageRegistry platform profile name {name:?}"
        )));
    };
    let tee = if normalized.contains("tdx") {
        "tdx"
    } else if normalized.contains("sev-snp") || normalized.contains("snp") {
        "sev-snp"
    } else if normalized.contains("nitro") {
        "nitro"
    } else {
        return Err(AttestationClientError::BaseImagePolicy(format!(
            "cannot infer TEE from BaseImageRegistry platform profile name {name:?}"
        )));
    };
    Ok((cloud, tee))
}

fn trusted_workload_policy(
    expected: &AppRef,
    workload_id: [u8; 32],
    selected_base_image_id: [u8; 32],
    spec: &WorkloadSpec,
) -> Result<TrustedWorkloadSessionPolicy, AttestationClientError> {
    if spec.name != expected.name || spec.version != expected.version {
        return Err(AttestationClientError::WorkloadPolicy(format!(
            "trusted WorkloadSpec identity {}/{} does not match expected workload {}/{}",
            spec.name, spec.version, expected.name, expected.version
        )));
    }
    ensure_base_image_allowed(
        spec.baseImageMode,
        &spec.baseImageIds,
        B256::from(selected_base_image_id),
    )?;

    let pcr_specs256 = spec
        .workloadPcrs256
        .iter()
        .map(|spec| {
            let verify_type = match spec.verifyType {
                0 => SessionPcrVerifyType::Static,
                1 => SessionPcrVerifyType::DynamicSubset,
                2 => SessionPcrVerifyType::DynamicSubsequence,
                value => {
                    return Err(AttestationClientError::WorkloadPolicy(format!(
                        "trusted WorkloadSpec has unsupported PCR verifyType {value} for PCR{}",
                        spec.pcrIndex
                    )))
                }
            };
            Ok(SessionPcrPolicy {
                pcr_index: spec.pcrIndex,
                verify_type,
                match_data: spec.matchData.iter().map(hex0x).collect(),
            })
        })
        .collect::<Result<Vec<_>, AttestationClientError>>()?;
    let pcr_specs384 = spec
        .workloadPcrs384
        .iter()
        .map(|spec| {
            let verify_type = match spec.verifyType {
                0 => SessionPcrVerifyType::Static,
                1 => SessionPcrVerifyType::DynamicSubset,
                2 => SessionPcrVerifyType::DynamicSubsequence,
                value => {
                    return Err(AttestationClientError::WorkloadPolicy(format!(
                    "trusted WorkloadSpec has unsupported SHA-384 PCR verifyType {value} for PCR{}",
                    spec.pcrIndex
                )))
                }
            };
            Ok(SessionPcrPolicy384 {
                pcr_index: spec.pcrIndex,
                verify_type,
                match_data: spec
                    .matchData
                    .iter()
                    .map(|value| {
                        let mut bytes = [0u8; 48];
                        bytes[..32].copy_from_slice(value.first.as_slice());
                        bytes[32..].copy_from_slice(value.second.as_slice());
                        hex0x(&bytes)
                    })
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let attribute_requirements = spec
        .requirements
        .iter()
        .map(|requirement| SessionAttributeRequirement {
            key: requirement.key.0,
            allowed_values: requirement
                .allowedValues
                .iter()
                .map(|value| value.0)
                .collect(),
        })
        .collect();

    Ok(TrustedWorkloadSessionPolicy {
        workload_id,
        pcr_specs256,
        pcr_specs384,
        attribute_requirements,
    })
}

fn ensure_base_image_allowed(
    mode: u8,
    configured: &[B256],
    selected: B256,
) -> Result<(), AttestationClientError> {
    let allowed = match mode {
        0 => true,
        1 => !configured.contains(&selected),
        2 => configured.contains(&selected),
        value => {
            return Err(AttestationClientError::WorkloadPolicy(format!(
                "trusted WorkloadSpec has unsupported baseImageMode {value}"
            )))
        }
    };
    if !allowed {
        return Err(AttestationClientError::WorkloadPolicy(format!(
            "TLS-selected base image {} is not allowed by the trusted WorkloadSpec",
            hex0x(selected)
        )));
    }
    Ok(())
}

fn hex0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn azure_maa_identity(
    binding: &atakit_attestation::AkBinding,
) -> Result<(String, String), AttestationClientError> {
    if !binding.kind.eq_ignore_ascii_case("azure-maa-jwt") {
        return Err(AttestationClientError::Verification(format!(
            "AK binding kind is {}; expected azure-maa-jwt",
            binding.kind
        )));
    }
    let binding_bytes = URL_SAFE_NO_PAD.decode(&binding.data).map_err(|error| {
        AttestationClientError::Verification(format!("decode Azure MAA AK binding: {error}"))
    })?;
    let binding_json: serde_json::Value =
        serde_json::from_slice(&binding_bytes).map_err(|error| {
            AttestationClientError::Verification(format!(
                "parse Azure MAA AK binding JSON: {error}"
            ))
        })?;
    let jwt = binding_json
        .get("jwt")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AttestationClientError::Verification(
                "Azure MAA AK binding is missing a non-empty jwt".to_string(),
            )
        })?;
    let mut parts = jwt.split('.');
    let header = parts.next().ok_or_else(|| {
        AttestationClientError::Verification("Azure MAA JWT is missing its header".to_string())
    })?;
    let claims = parts.next().ok_or_else(|| {
        AttestationClientError::Verification("Azure MAA JWT is missing its claims".to_string())
    })?;
    let signature = parts.next().ok_or_else(|| {
        AttestationClientError::Verification("Azure MAA JWT is missing its signature".to_string())
    })?;
    if parts.next().is_some() || signature.is_empty() {
        return Err(AttestationClientError::Verification(
            "Azure MAA JWT must have exactly three non-empty parts".to_string(),
        ));
    }
    let header_json = decode_jwt_part(header, "header")?;
    let claims_json = decode_jwt_part(claims, "claims")?;
    let kid = header_json
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AttestationClientError::Verification(
                "Azure MAA JWT header is missing a non-empty kid".to_string(),
            )
        })?;
    let issuer = claims_json
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AttestationClientError::Verification(
                "Azure MAA JWT claims are missing a non-empty iss".to_string(),
            )
        })?;
    Ok((kid.to_string(), issuer.to_string()))
}

fn decode_jwt_part(
    encoded: &str,
    label: &str,
) -> Result<serde_json::Value, AttestationClientError> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        AttestationClientError::Verification(format!("decode Azure MAA JWT {label}: {error}"))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        AttestationClientError::Verification(format!("parse Azure MAA JWT {label}: {error}"))
    })
}

fn function_selector(signature: &str) -> [u8; 4] {
    let hash = Keccak256::digest(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

fn encode_no_arg_call(signature: &str) -> Vec<u8> {
    function_selector(signature).to_vec()
}

fn encode_bytes32_arg_call(signature: &str, argument: [u8; 32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(36);
    output.extend_from_slice(&function_selector(signature));
    output.extend_from_slice(&argument);
    output
}

fn encode_uint_arg_call(signature: &str, argument: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(36);
    output.extend_from_slice(&function_selector(signature));
    output.extend_from_slice(&abi_word_u64(argument));
    output
}

fn decode_address_return(bytes: &[u8], label: &str) -> Result<String, AttestationClientError> {
    if bytes.len() != 32 {
        return Err(AttestationClientError::Rpc(format!(
            "{label} returned {} bytes for an ABI address; expected 32",
            bytes.len()
        )));
    }
    if bytes[..12].iter().any(|byte| *byte != 0) {
        return Err(AttestationClientError::Rpc(format!(
            "{label} returned non-zero ABI address padding"
        )));
    }
    let address = &bytes[12..];
    if address.iter().all(|byte| *byte == 0) {
        return Err(AttestationClientError::Rpc(format!(
            "{label} returned the zero address"
        )));
    }
    Ok(hex0x(address))
}

fn decode_maa_signing_key_return(
    bytes: &[u8],
) -> Result<MaaSigningKeyEntry, AttestationClientError> {
    if bytes.len() < 32 {
        return Err(AttestationClientError::Rpc(format!(
            "MaaKeyRegistry.getMaaSigningKey returned {} bytes; expected at least 32",
            bytes.len()
        )));
    }
    let tuple_offset = abi_word_usize(&bytes[..32])?;
    let tuple_end = tuple_offset.checked_add(128).ok_or_else(|| {
        AttestationClientError::Rpc("Azure MAA tuple offset overflow".to_string())
    })?;
    if tuple_end > bytes.len() {
        return Err(AttestationClientError::Rpc(format!(
            "Azure MAA tuple offset {tuple_offset} is outside {} response bytes",
            bytes.len()
        )));
    }
    let tuple = &bytes[tuple_offset..];
    let public_key_offset = abi_word_usize(&tuple[..32])?;
    let mut issuer_hash = [0u8; 32];
    issuer_hash.copy_from_slice(&tuple[32..64]);
    let not_after = abi_word_to_u64(&tuple[64..96])?;
    let revoked = abi_word_bool(&tuple[96..128]).map_err(AttestationClientError::Rpc)?;
    let length_position = tuple_offset
        .checked_add(public_key_offset)
        .ok_or_else(|| AttestationClientError::Rpc("Azure MAA key offset overflow".to_string()))?;
    let length_end = length_position
        .checked_add(32)
        .ok_or_else(|| AttestationClientError::Rpc("Azure MAA key length overflow".to_string()))?;
    if length_end > bytes.len() {
        return Err(AttestationClientError::Rpc(
            "Azure MAA public-key offset is outside the response".to_string(),
        ));
    }
    let public_key_length = abi_word_usize(&bytes[length_position..length_end])?;
    let data_end = length_end
        .checked_add(public_key_length)
        .ok_or_else(|| AttestationClientError::Rpc("Azure MAA key data overflow".to_string()))?;
    if data_end > bytes.len() {
        return Err(AttestationClientError::Rpc(
            "Azure MAA public-key bytes are outside the response".to_string(),
        ));
    }
    Ok(MaaSigningKeyEntry {
        public_key: bytes[length_end..data_end].to_vec(),
        issuer_hash,
        not_after,
        revoked,
    })
}

fn abi_word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn abi_word_to_u64(word: &[u8]) -> Result<u64, AttestationClientError> {
    if word.len() != 32 || word[..24].iter().any(|byte| *byte != 0) {
        return Err(AttestationClientError::Rpc(
            "ABI uint value does not fit in u64".to_string(),
        ));
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(value))
}

fn abi_word_usize(word: &[u8]) -> Result<usize, AttestationClientError> {
    let value = abi_word_to_u64(word)?;
    usize::try_from(value).map_err(|_| {
        AttestationClientError::Rpc("ABI uint value does not fit in usize".to_string())
    })
}

fn abi_word_bool(word: &[u8]) -> Result<bool, String> {
    if word.len() != 32 || word[..31].iter().any(|byte| *byte != 0) {
        return Err("ABI bool value has invalid padding or length".to_string());
    }
    match word[31] {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(format!("ABI bool value is {value}; expected 0 or 1")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_selects_exact_platform() {
        assert_eq!(
            infer_cloud_tee_from_profile_name("gcp-tdx").unwrap(),
            ("gcp", "tdx")
        );
        assert_eq!(
            infer_cloud_tee_from_profile_name("azure-sev-snp").unwrap(),
            ("azure", "sev-snp")
        );
    }

    #[test]
    fn profile_name_rejects_unknown_cloud() {
        let error = infer_cloud_tee_from_profile_name("custom-tdx").unwrap_err();
        assert!(error.to_string().contains("cannot infer cloud"));
    }

    #[test]
    fn expected_registry_must_match_session_registry_result() {
        let resolved = "0x0000000000000000000000000000000000000001"
            .parse::<Address>()
            .unwrap();
        let error = validate_expected_address(
            "expected_workload_registry",
            Some("0x0000000000000000000000000000000000000002"),
            resolved,
        )
        .unwrap_err();
        assert!(error.to_string().contains("SessionRegistry returns"));
    }

    #[test]
    fn maa_signing_key_return_decodes_dynamic_struct() {
        let public_key = vec![0x30, 0x82, 0x01, 0x0a];
        let issuer_hash = [0x42u8; 32];
        let mut returned = Vec::new();
        returned.extend_from_slice(&abi_word_u64(32));
        returned.extend_from_slice(&abi_word_u64(128));
        returned.extend_from_slice(&issuer_hash);
        returned.extend_from_slice(&abi_word_u64(1_811_611_165));
        returned.extend_from_slice(&abi_word_u64(0));
        returned.extend_from_slice(&abi_word_u64(public_key.len() as u64));
        returned.extend_from_slice(&public_key);
        returned.extend_from_slice(&[0; 28]);

        let decoded = decode_maa_signing_key_return(&returned).unwrap();
        assert_eq!(decoded.public_key, public_key);
        assert_eq!(decoded.issuer_hash, issuer_hash);
        assert_eq!(decoded.not_after, 1_811_611_165);
        assert!(!decoded.revoked);
    }

    #[test]
    fn amd_snp_security_policy_return_decodes_static_struct() {
        let minimum_tcb = [0x11u8; 32];
        let platform_info_policy = [0x22u8; 32];
        let mut returned = Vec::new();
        returned.extend_from_slice(&minimum_tcb);
        returned.extend_from_slice(&platform_info_policy);
        returned.extend_from_slice(&[0x33; 32]);
        returned.extend_from_slice(&abi_word_u64(7));
        returned.extend_from_slice(&abi_word_u64(1));

        let error = decode_amd_snp_security_policy_return(&returned, 0x190100).unwrap_err();
        assert!(error.to_string().contains("malformed policy"));

        returned[..32].fill(0);
        returned[32..64].fill(0);
        let decoded = decode_amd_snp_security_policy_return(&returned, 0x190100).unwrap();
        assert_eq!(decoded.cpuid, 0x190100);
        assert_eq!(decoded.minimum_tcb, [0; 32]);
        assert_eq!(decoded.platform_info_policy, [0; 32]);
        assert_eq!(decoded.required_launch_mitigation_vector, 0);
        assert_eq!(decoded.required_current_mitigation_vector, 0);

        returned.extend_from_slice(&abi_word_u64(0x1234));
        returned.extend_from_slice(&abi_word_u64(0x5678));
        let decoded = decode_amd_snp_security_policy_return(&returned, 0x190100).unwrap();
        assert_eq!(decoded.required_launch_mitigation_vector, 0x1234);
        assert_eq!(decoded.required_current_mitigation_vector, 0x5678);
    }

    #[test]
    fn azure_maa_binding_selects_kid_and_issuer_from_jwt() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-key"}"#);
        let claims = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://maa.example.test"}"#);
        let jwt = format!("{header}.{claims}.signature");
        let data =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({ "jwt": jwt })).unwrap());
        let binding = atakit_attestation::AkBinding {
            kind: "azure-maa-jwt".into(),
            data,
        };

        let identity = azure_maa_identity(&binding).unwrap();
        assert_eq!(identity.0, "test-key");
        assert_eq!(identity.1, "https://maa.example.test");
    }
}
