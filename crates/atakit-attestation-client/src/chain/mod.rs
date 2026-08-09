//! Read-only access to verifier-selected registry state.
//!
//! [`AttestationClient`] never signs or submits a transaction. The caller
//! selects the RPC endpoint and `SessionRegistry`; portal evidence cannot
//! select either value.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_ext::core::primitives::{Address, B256};
use alloy_ext::ext::{NetworkProvider, ProviderEx};
use atakit_attestation::{
    AmdSnpSecurityPolicy, AzureMaaTrustKey, MeasurementPack, MeasurementPolicy, MeasurementProfile,
    MeasurementVariant, PcrBankSelection, PcrSpec256, PcrSpec384, SessionAttributeRequirement,
    SessionPcrPolicy, SessionPcrPolicy384, SessionVerificationFailure, Subject,
    TrustedSessionBinding,
};
use atakit_cvm_encoding::pcr_comparison::{encode_static256, encode_static384};
use atakit_cvm_types::AppRef;
use automata_tee_workload_measurement::base_image_registry::{
    BaseImageHierarchy, BaseImageRegistry,
};
use automata_tee_workload_measurement::stubs::SessionRegistry::SessionRegistryInstance;
use automata_tee_workload_measurement::stubs::WorkloadRegistry::WorkloadSpec;
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
const AMD_SEV_SNP_V1_PROGRAM_IDENTIFIER: [u8; 32] = [
    0x00, 0xbc, 0x5b, 0xae, 0x7f, 0x7c, 0x20, 0x0e, 0xc9, 0x1f, 0x86, 0x6e, 0xe2, 0xf2, 0x92, 0x7c,
    0xc0, 0x1f, 0xcf, 0x36, 0x5a, 0x55, 0xf7, 0x6c, 0x81, 0x96, 0x48, 0xe5, 0x27, 0x7d, 0x12, 0x86,
];

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

/// Parse a canonical `<publisher>/<name>:<version>` workload reference.
///
/// This carries stricter grammar rules than `AppRef::from_str` and keeps them,
/// gaining a publisher rule alongside. A two-part `name:version` reference is
/// rejected outright rather than accepted with a defaulted publisher: tolerating
/// the old form would leave references parsing while nothing was bound.
fn parse_canonical_workload_ref(workload: &str) -> Result<AppRef, AttestationClientError> {
    let Some((publisher, rest)) = workload.split_once('/') else {
        return Err(AttestationClientError::WorkloadPolicy(format!(
            "canonical workload reference must use <publisher>/<name>:<version>, got {workload:?}; \
             a reference without a publisher is no longer accepted"
        )));
    };
    if !atakit_core::is_canonical_id(publisher) {
        return Err(AttestationClientError::WorkloadPolicy(format!(
            "canonical workload publisher must be '0x' followed by 64 lowercase hexadecimal characters, got {publisher:?}"
        )));
    }
    let publisher: alloy_ext::core::primitives::B256 = publisher.parse().map_err(|error| {
        AttestationClientError::WorkloadPolicy(format!(
            "canonical workload publisher {publisher:?} is not a valid fingerprint: {error}"
        ))
    })?;
    let Some((name, version)) = rest.split_once(':') else {
        return Err(AttestationClientError::WorkloadPolicy(format!(
            "canonical workload reference must use <publisher>/<name>:<version>, got {workload:?}"
        )));
    };
    if !atakit_core::is_valid_ref_name(name) {
        return Err(AttestationClientError::WorkloadPolicy(format!(
            "canonical workload name must be nonempty, must not start with '-', and must contain only ASCII alphanumeric characters or '-', got {name:?}"
        )));
    }
    if !atakit_core::is_valid_ref_version(version) {
        return Err(AttestationClientError::WorkloadPolicy(format!(
            "canonical workload version must start with 'v' and may contain only ASCII alphanumeric characters, '.', '-', or '_' after it, got {version:?}"
        )));
    }
    Ok(AppRef::new(publisher.into(), name, version))
}

impl TrustedWorkloadSessionPolicy {
    /// Construct an explicit policy that accepts exactly one SHA-256 PCR23
    /// value and one SHA-384 PCR23 value from a workload manifest. The
    /// canonical workload reference determines the workload ID; portal
    /// evidence cannot select it.
    pub fn from_manifest_pcr23(
        workload: &str,
        manifest_pcr23_sha256: [u8; 32],
        manifest_pcr23_sha384: [u8; 48],
    ) -> Result<Self, AttestationClientError> {
        let app_ref = parse_canonical_workload_ref(workload)?;
        Ok(Self {
            workload_id: atakit_cvm_encoding::workload_id(&app_ref),
            pcr_specs256: vec![SessionPcrPolicy {
                pcr_index: 23,
                comparison: hex0x(encode_static256(manifest_pcr23_sha256)),
            }],
            pcr_specs384: vec![SessionPcrPolicy384 {
                pcr_index: 23,
                comparison: hex0x(encode_static384(manifest_pcr23_sha384)),
            }],
            attribute_requirements: Vec::new(),
        })
    }
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
    #[error("session verification failed: {0:?}")]
    SessionVerification(Box<SessionVerificationFailure>),
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

    /// Verify a current session against a caller-supplied typed workload
    /// policy, binding it to this client's own chain context.
    ///
    /// The binding comes from the same client, so it is chain-mode evidence
    /// bound to chain-mode coordinates. Explicit verification uses the free
    /// `session::verify_current_session`, which has no binding parameter at all.
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
        self.resolve_base_image_measurement_policy_by_id(
            atakit_cvm_encoding::base_image_id(&app_ref),
            base_image,
        )
        .await
    }

    /// The same registry read, for a caller that has an identifier rather than
    /// a reference.
    ///
    /// `atakit cloud init`, `deploy`, and `workload init` reach a portal before
    /// the operator has necessarily named a base image, and take the identifier
    /// from the portal's untrusted `GET /status`. That identifier selects which
    /// registry record is read; it never decides what that record says, and the
    /// measured PCRs still have to match the policy the registry returns.
    ///
    /// `described_as` appears in failure messages only.
    pub async fn resolve_base_image_measurement_policy_by_id(
        &self,
        base_image_id: [u8; 32],
        described_as: &str,
    ) -> Result<MeasurementPolicy, AttestationClientError> {
        let base_image_id = B256::from(base_image_id);
        let registry_address = parse_address(
            "resolved BaseImageRegistry",
            &self.context.base_image_registry,
        )?;
        let provider = connect_provider(&self.config.rpc_url).await?;
        let registry = BaseImageRegistry::new(registry_address, provider);
        let hierarchy = registry
            .get_hierarchy(base_image_id)
            .await
            .map_err(|error| {
                AttestationClientError::Rpc(format!(
                    "fetch BaseImageRegistry hierarchy for {described_as}: {error}"
                ))
            })?;
        // The subject carries the publisher, and a verifier recomputes the id
        // from it. The hierarchy does not include the owner, so it is read
        // separately rather than left blank, which would fail that check.
        let owner = registry
            .get_base_image_owner(base_image_id)
            .await
            .map_err(|error| {
                AttestationClientError::Rpc(format!(
                    "fetch BaseImageRegistry owner for {described_as}: {error}"
                ))
            })?;
        hierarchy_to_measurement_policy(&hierarchy, owner, &self.context.base_image_registry)
    }

    /// Fetch and validate the exact registered workload policy.
    pub async fn resolve_workload_policy(
        &self,
        workload: &str,
        selected_base_image_id: [u8; 32],
    ) -> Result<TrustedWorkloadSessionPolicy, AttestationClientError> {
        let app_ref = parse_canonical_workload_ref(workload)?;
        let workload_id = B256::from(atakit_cvm_encoding::workload_id(&app_ref));
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
}

impl AttestationClient {
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
        let zk_verifier_registry = self
            .resolve_address_call(
                &tee_verifier,
                "zkVerifierRegistry()",
                "TeeVerifier.zkVerifierRegistry",
            )
            .await?;
        let adapter_result = self
            .eth_call(
                &zk_verifier_registry,
                encode_zk_verifier_adapter_call(1, 2, AMD_SEV_SNP_V1_PROGRAM_IDENTIFIER),
                "ZkVerifierRegistry.resolveVerifierAdapter for amd_sev_snp.v1",
            )
            .await?;
        let amd_sev_snp_adapter = decode_address_return(
            &adapter_result,
            "ZkVerifierRegistry.resolveVerifierAdapter for amd_sev_snp.v1",
        )?;
        let snp_attestation = self
            .resolve_address_call(
                &amd_sev_snp_adapter,
                "snpAttestation()",
                "AmdSevSnpZkVerifierAdapter.snpAttestation",
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

    /// Require the AWS Nitro root certificate to be approved by the selected
    /// `SessionRegistry`. Returns the trusted Keccak-256 root hash.
    pub async fn resolve_aws_nitro_root(
        &self,
        root_der: &[u8],
    ) -> Result<[u8; 32], AttestationClientError> {
        let root_hash: [u8; 32] = Keccak256::digest(root_der).into();
        let trusted = self
            .resolve_bool_call(
                &self.context.session_registry,
                encode_bytes32_arg_call("trustedAwsNitroRootCertHashes(bytes32)", root_hash),
                "SessionRegistry.trustedAwsNitroRootCertHashes",
            )
            .await?;
        if !trusted {
            return Err(AttestationClientError::Rpc(format!(
                "SessionRegistry {} does not trust AWS Nitro root keccak256(root_der)={}",
                self.context.session_registry,
                hex0x(root_hash)
            )));
        }
        Ok(root_hash)
    }

    /// Read the exact AWS NitroTPM document freshness limits from the
    /// verifier-selected `SessionRegistry`.
    pub async fn resolve_aws_document_freshness_limits(
        &self,
    ) -> Result<(u64, u64), AttestationClientError> {
        let maximum_age = self
            .eth_call(
                &self.context.session_registry,
                encode_no_arg_call("awsDocumentMaximumAgeSeconds()"),
                "SessionRegistry.awsDocumentMaximumAgeSeconds",
            )
            .await?;
        let allowed_future = self
            .eth_call(
                &self.context.session_registry,
                encode_no_arg_call("awsDocumentAllowedFutureClockDifferenceSeconds()"),
                "SessionRegistry.awsDocumentAllowedFutureClockDifferenceSeconds",
            )
            .await?;
        Ok((
            abi_word_to_u64(&maximum_age)?,
            abi_word_to_u64(&allowed_future)?,
        ))
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
    owner: alloy_ext::core::primitives::B256,
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
                        .variantPcrPolicy
                        .pcrSpecs256
                        .iter()
                        .map(chain_pcr_spec256_to_measurement)
                        .collect(),
                    variant_pcrs384: variant
                        .variantPcrPolicy
                        .pcrSpecs384
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
                invariant_pcrs256: profile
                    .profile
                    .invariantPcrPolicy
                    .pcrSpecs256
                    .iter()
                    .map(chain_pcr_spec256_to_measurement)
                    .collect(),
                invariant_pcrs384: profile
                    .profile
                    .invariantPcrPolicy
                    .pcrSpecs384
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
            schema: atakit_attestation::BASE_IMAGE_MEASUREMENT_PACK_SCHEMA.to_string(),
            revision: 1,
            published_at: chrono::Utc::now().timestamp().max(0) as u64,
            subject: Subject {
                publisher: hex0x(owner),
                name: hierarchy.spec.name.clone(),
                version: hierarchy.spec.version.clone(),
                id: hex0x(hierarchy.base_image_id),
                uri: (!hierarchy.spec.uri.is_empty()).then(|| hierarchy.spec.uri.clone()),
                archive_sha256: None,
            },
            measurements: serde_json::to_value(atakit_attestation::BaseImageMeasurements {
                profiles,
            })
            .map_err(|error| {
                AttestationClientError::Rpc(format!("serialize measurements: {error}"))
            })?,
        },
    })
}

fn chain_pcr_spec256_to_measurement(
    spec: &automata_tee_workload_measurement::stubs::BaseImageRegistry::PcrSpec256,
) -> PcrSpec256 {
    PcrSpec256 {
        pcr_index: spec.pcrIndex,
        comparison: hex0x(&spec.comparison),
    }
}

fn chain_pcr_spec384_to_measurement(
    spec: &automata_tee_workload_measurement::stubs::BaseImageRegistry::PcrSpec384,
) -> PcrSpec384 {
    PcrSpec384 {
        pcr_index: spec.pcrIndex,
        comparison: hex0x(&spec.comparison),
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
        .workloadPcrPolicy
        .pcrSpecs256
        .iter()
        .map(|spec| SessionPcrPolicy {
            pcr_index: spec.pcrIndex,
            comparison: hex0x(&spec.comparison),
        })
        .collect();
    let pcr_specs384 = spec
        .workloadPcrPolicy
        .pcrSpecs384
        .iter()
        .map(|spec| SessionPcrPolicy384 {
            pcr_index: spec.pcrIndex,
            comparison: hex0x(&spec.comparison),
        })
        .collect();
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

/// Apply a `WorkloadSpec`'s base-image access mode to the base image that
/// verified portal TLS selected.
///
/// Shared with the `.atatp` `workload-trust` path so both resolve the mode
/// through one implementation. A pack whose access rule disagreed with the
/// chain's would be precisely the weakening the trust-pack format forbids.
pub(crate) fn ensure_base_image_allowed(
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

fn encode_zk_verifier_adapter_call(
    proof_type: u8,
    verification_backend_type: u8,
    program_identifier: [u8; 32],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(100);
    output.extend_from_slice(&function_selector(
        "resolveVerifierAdapter(uint8,uint8,bytes32)",
    ));
    output.extend_from_slice(&abi_word_u64(u64::from(proof_type)));
    output.extend_from_slice(&abi_word_u64(u64::from(verification_backend_type)));
    output.extend_from_slice(&program_identifier);
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
    fn explicit_manifest_pcr23_policy_uses_canonical_workload_reference() {
        let policy = TrustedWorkloadSessionPolicy::from_manifest_pcr23(
            "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f/storage-service:v0.1.0",
            [0x55; 32],
            [0x66; 48],
        )
        .unwrap();

        assert_eq!(policy.pcr_specs256.len(), 1);
        assert_eq!(policy.pcr_specs256[0].pcr_index, 23);
        assert_eq!(
            policy.pcr_specs256[0].comparison,
            hex0x(encode_static256([0x55; 32]))
        );
        assert_eq!(policy.pcr_specs384.len(), 1);
        assert_eq!(policy.pcr_specs384[0].pcr_index, 23);
        assert_eq!(
            policy.pcr_specs384[0].comparison,
            hex0x(encode_static384([0x66; 48]))
        );
        assert!(policy.attribute_requirements.is_empty());
    }

    #[test]
    fn explicit_manifest_pcr23_policy_rejects_noncanonical_workload_references() {
        for workload in [
            "",
            "storage-service",
            ":v0.1.0",
            "storage-service:",
            "-storage-service:v0.1.0",
            "storage/service:v0.1.0",
            "storage-service:0.1.0",
            "storage-service:v",
            "storage-service:v0/1",
            "storage-service:v0:1",
        ] {
            assert!(
                TrustedWorkloadSessionPolicy::from_manifest_pcr23(
                    workload,
                    [0x55; 32],
                    [0x66; 48],
                )
                .is_err(),
                "accepted noncanonical workload reference {workload:?}"
            );
        }
    }

    #[test]
    fn registered_workload_policy_converts_all_rules() {
        use atakit_cvm_encoding::pcr_comparison::{encode_dynamic256, DYNAMIC_SUBSEQUENCE};
        use automata_tee_workload_measurement::stubs::WorkloadRegistry::{
            AttributeRequirement, PcrPolicyBlock, PcrSpec256 as WorkloadPcrSpec256,
            PcrSpec384 as WorkloadPcrSpec384,
        };

        let dynamic_comparison = encode_dynamic256(DYNAMIC_SUBSEQUENCE, vec![[0x20; 32]]).unwrap();
        let static_comparison = encode_static256([0x23; 32]);
        let static_comparison384 = encode_static384([0x38; 48]);

        let selected_base_image = B256::repeat_byte(0x44);
        let spec = WorkloadSpec {
            name: "test".into(),
            version: "v0.0.1".into(),
            sessionTtl: 0,
            baseImageMode: 2,
            baseImageIds: vec![selected_base_image],
            requirements: vec![AttributeRequirement {
                key: B256::repeat_byte(0xaa),
                allowedValues: vec![B256::repeat_byte(0xbb)],
            }],
            workloadPcrPolicy: PcrPolicyBlock {
                pcrSpecs256: vec![
                    WorkloadPcrSpec256 {
                        pcrIndex: 20,
                        comparison: dynamic_comparison.clone().into(),
                    },
                    WorkloadPcrSpec256 {
                        pcrIndex: 23,
                        comparison: static_comparison.clone().into(),
                    },
                ],
                pcrSpecs384: vec![WorkloadPcrSpec384 {
                    pcrIndex: 23,
                    comparison: static_comparison384.clone().into(),
                }],
            },
        };
        let app_ref: AppRef =
            "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f/test:v0.0.1"
                .parse()
                .unwrap();

        let policy =
            trusted_workload_policy(&app_ref, [0x11; 32], selected_base_image.0, &spec).unwrap();

        assert_eq!(policy.workload_id, [0x11; 32]);
        assert_eq!(policy.pcr_specs256.len(), 2);
        assert_eq!(policy.pcr_specs256[0].comparison, hex0x(dynamic_comparison));
        assert_eq!(policy.pcr_specs256[1].comparison, hex0x(static_comparison));
        assert_eq!(policy.pcr_specs384.len(), 1);
        assert_eq!(
            policy.pcr_specs384[0].comparison,
            hex0x(static_comparison384)
        );
        assert_eq!(policy.attribute_requirements[0].key, [0xaa; 32]);
        assert_eq!(
            policy.attribute_requirements[0].allowed_values,
            [[0xbb; 32]]
        );
    }

    #[test]
    fn registered_workload_base_image_modes_are_enforced() {
        let selected = B256::repeat_byte(0x11);
        let other = B256::repeat_byte(0x22);
        ensure_base_image_allowed(0, &[], selected).unwrap();
        ensure_base_image_allowed(1, &[other], selected).unwrap();
        ensure_base_image_allowed(2, &[selected], selected).unwrap();
        assert!(ensure_base_image_allowed(1, &[selected], selected).is_err());
        assert!(ensure_base_image_allowed(2, &[other], selected).is_err());
        assert!(ensure_base_image_allowed(3, &[], selected).is_err());
    }

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
    fn amd_sev_snp_v1_adapter_call_uses_exact_route() {
        let call = encode_zk_verifier_adapter_call(1, 2, AMD_SEV_SNP_V1_PROGRAM_IDENTIFIER);
        assert_eq!(call.len(), 100);
        assert_eq!(
            &call[..4],
            &function_selector("resolveVerifierAdapter(uint8,uint8,bytes32)")
        );
        assert_eq!(&call[4..36], &abi_word_u64(1));
        assert_eq!(&call[36..68], &abi_word_u64(2));
        assert_eq!(&call[68..], &AMD_SEV_SNP_V1_PROGRAM_IDENTIFIER);
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

/// Tests for the chain-derived measurement policy conversion.
///
/// These moved here from `atakit-cli` on 2026-08-09. The CLI carried a second
/// copy of this conversion and the tests exercised that copy, so the
/// implementation the commands actually run had none — precisely the drift the
/// consolidation exists to remove. The CLI copy is deleted; this is the only
/// implementation left, and these are its tests.
#[cfg(test)]
mod chain_measurement_policy_conversion {
    use super::*;

    #[test]
    fn infers_cloud_and_tee_from_supported_profile_names() {
        for (name, expected) in [
            ("gcp-tdx", ("gcp", "tdx")),
            ("gcp-sev-snp", ("gcp", "sev-snp")),
            ("azure_snp_westus", ("azure", "sev-snp")),
            ("aws-nitro", ("aws", "nitro")),
        ] {
            assert_eq!(
                infer_cloud_tee_from_profile_name(name).unwrap(),
                expected,
                "{name}"
            );
        }
    }

    /// An unmappable name fails closed rather than guessing. The chain does not
    /// store cloud and TEE as first-class fields, so the profile name is the
    /// only thing that carries them.
    #[test]
    fn rejects_unmappable_chain_profile_names() {
        let error = infer_cloud_tee_from_profile_name("production-profile").unwrap_err();
        assert!(error.to_string().contains("cannot infer cloud"), "{error}");

        let error = infer_cloud_tee_from_profile_name("gcp-production").unwrap_err();
        assert!(error.to_string().contains("cannot infer TEE"), "{error}");
    }

    /// The opaque comparison bytes pass through unchanged. Re-encoding them
    /// here would be a second encoder to keep in step with the TPM verifier.
    #[test]
    fn converts_chain_pcr_spec_to_measurement_pack_shape() {
        let comparison = atakit_cvm_encoding::pcr_comparison::encode_static256([0xaa; 32]);
        let spec = automata_tee_workload_measurement::stubs::BaseImageRegistry::PcrSpec256 {
            pcrIndex: 4,
            comparison: comparison.clone().into(),
        };

        let got = chain_pcr_spec256_to_measurement(&spec);

        assert_eq!(got.pcr_index, 4);
        assert_eq!(got.comparison, hex0x(comparison));
    }
}
