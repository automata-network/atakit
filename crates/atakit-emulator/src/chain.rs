use crate::{abi::*, config::ResolvedWorkload, rpc::LocalRpc};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use anyhow::{bail, Context, Result};
use atakit_attestation::session_protocol;
use atakit_attestation::signing;
use atakit_attestation::{evidence_abi, PcrBankSelection};
use atakit_cvm_types::AppRef;
use automata_tee_workload_measurement::stubs::AlgoId;
use automata_tee_workload_measurement::stubs::{Bytes48, TpmQuoteEvidence};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn hexbytes(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}
pub async fn read<C: SolCall>(rpc: &LocalRpc, address: Address, call: C) -> Result<C::Return> {
    let raw = rpc
        .call(&address.to_string(), &hexbytes(call.abi_encode()))
        .await?;
    let data = hex::decode(raw.trim_start_matches("0x"))?;
    C::abi_decode_returns(&data).context("Registry ABI mismatch")
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryContext {
    pub session: Address,
    pub workload: Address,
    pub base_image: Address,
    pub chain_id: u64,
    pub patched: Vec<Address>,
}
impl RegistryContext {
    pub async fn patch(rpc: &LocalRpc, session: Address, expected_chain: u64) -> Result<Self> {
        let chain_id = rpc.reads().chain_id().await?;
        if chain_id != expected_chain {
            bail!("configured chain ID {expected_chain} does not match Anvil {chain_id}");
        }
        let workload = read(rpc, session, workloadRegistryCall {}).await?;
        let base_image = read(rpc, session, baseImageRegistryCall {}).await?;
        let tee = read(rpc, session, teeVerifierCall {}).await?;
        let tpm = read(rpc, session, tpmVerifierCall {}).await?;
        let ak = read(rpc, session, akCollateralVerifierCall {}).await?;
        let signature = read(rpc, session, signatureVerifierCall {}).await?;
        let security = read(rpc, session, teeSecurityPolicyVerifierCall {}).await?;
        let dcap = read(rpc, tee, dcapAttestationCall {}).await?;
        let t1 = read(rpc, tpm, tpmAttestationCall {}).await?;
        let t2 = read(rpc, ak, tpmAttestationCall {}).await?;
        let protected = [
            session, workload, base_image, tee, tpm, ak, signature, security,
        ];
        for addr in protected.iter().chain([dcap, t1, t2].iter()) {
            if addr.is_zero() || rpc.request("eth_getCode", json!([addr, "latest"])).await? == "0x"
            {
                bail!("required contract missing at {addr}");
            }
        }
        let mut patched = vec![];
        for (addr, code) in [
            (
                dcap,
                include_str!("../assets/EmulatorDcapAttestation.runtime.hex"),
            ),
            (
                t1,
                include_str!("../assets/EmulatorTpmAttestation.runtime.hex"),
            ),
            (
                t2,
                include_str!("../assets/EmulatorTpmAttestation.runtime.hex"),
            ),
        ] {
            if protected.contains(&addr) || (addr == dcap && (addr == t1 || addr == t2)) {
                bail!("unsupported aliased hardware verifier dependency");
            }
            if patched.contains(&addr) {
                continue;
            }
            rpc.request(
                "anvil_setCode",
                json!([addr, format!("0x{}", code.trim().trim_start_matches("0x"))]),
            )
            .await?;
            patched.push(addr);
        }
        Ok(Self {
            session,
            workload,
            base_image,
            chain_id,
            patched,
        })
    }
}

/// Private checkpoint data. Never serialize this object into status/env output.
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisteredSession {
    pub owner_nonce: U256,
    pub op_expires_at: u64,
    pub policy_abi: Vec<u8>,
    pub rotated: bool,
    pub session_id: B256,
    pub session_secret: [u8; 32],
    pub tpm_secret: [u8; 32],
    pub tee_hash: B256,
    pub workload_id: B256,
    pub base_image_id: B256,
    pub profile_id: B256,
    pub variant_id: B256,
    pub owner_fp: B256,
    pub owner_public: Vec<u8>,
    pub owner_payload: [u8; 32],
    pub owner_signature: Vec<u8>,
    pub registration_tx: String,
    pub expires_at: u64,
    pub evidence_abi: Vec<u8>,
    pub emulated_measurement: B256,
}

pub struct SessionEngine {
    pub rpc: LocalRpc,
    pub registry: RegistryContext,
    pub sender: String,
}
impl SessionEngine {
    pub async fn new(rpc: LocalRpc, registry: RegistryContext) -> Result<Self> {
        let sender = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string();
        rpc.request("anvil_setBalance", json!([sender, "0x3635c9adc5dea00000"]))
            .await?;
        rpc.request("anvil_impersonateAccount", json!([sender]))
            .await?;
        Ok(Self {
            rpc,
            registry,
            sender,
        })
    }
    pub async fn send<C: SolCall>(&self, to: Address, call: C) -> Result<Value> {
        self.rpc
            .send(
                &self.sender,
                Some(&to.to_string()),
                &hexbytes(call.abi_encode()),
            )
            .await
    }
    pub async fn timestamp(&self) -> Result<u64> {
        crate::rpc::quantity(
            &self
                .rpc
                .request("eth_getBlockByNumber", json!(["latest", false]))
                .await?["timestamp"],
        )
    }
    pub async fn active(&self, sid: B256) -> Result<bool> {
        read(
            &self.rpc,
            self.registry.session,
            isSessionActiveCall { sessionId: sid },
        )
        .await
    }
    async fn whitelist(&self, fp: B256) -> Result<()> {
        let wr = self.registry.workload;
        if !read(&self.rpc, wr, pausedCall {}).await?
            || read(&self.rpc, wr, isWhitelistedCall { fingerprint: fp }).await?
        {
            return Ok(());
        }
        let admin = read(&self.rpc, wr, ownerCall {}).await?;
        self.rpc
            .request("anvil_setBalance", json!([admin, "0x3635c9adc5dea00000"]))
            .await?;
        self.rpc
            .request("anvil_impersonateAccount", json!([admin]))
            .await?;
        let result = self
            .rpc
            .send(
                &admin.to_string(),
                Some(&wr.to_string()),
                &hexbytes(
                    addToWhitelistCall {
                        fingerprints: vec![fp],
                    }
                    .abi_encode(),
                ),
            )
            .await;
        self.rpc
            .request("anvil_stopImpersonatingAccount", json!([admin]))
            .await?;
        result?;
        Ok(())
    }
    pub async fn register(
        &self,
        input: &ResolvedWorkload,
        owner: &[u8; 32],
    ) -> Result<RegisteredSession> {
        self.register_with_publisher(input, owner, owner).await
    }
    pub async fn register_with_publisher(
        &self,
        input: &ResolvedWorkload,
        publisher: &[u8; 32],
        owner: &[u8; 32],
    ) -> Result<RegisteredSession> {
        let mut choices = self.policy_candidates(input, publisher).await?;
        let owner_public = signing::derive_public_key_uncompressed(owner)?.to_vec();
        let owner_fp = B256::from(atakit_cvm_encoding::key_fingerprint(
            AlgoId::Es256K as u8,
            &owner_public,
        ));
        let emulated_measurement = B256::from(crate::inputs::measurement(
            &input.config_file,
            &input.workload_dir,
        )?);
        if choices.len() != 1 {
            let candidates = choices
                .iter()
                .map(|(policy, profile, variant)| {
                    format!("{} / {profile} / {variant}", policy.baseImageId)
                })
                .collect::<Vec<_>>()
                .join(", ");
            bail!("expected one compatible GCP/TDX base image/profile/variant, found {}; select --target <cloud-target> or --platform-profile and --measurement-variant (NAME=VALUE for multiple workloads); selected profile={:?}, variant={:?}; candidates: [{candidates}]",choices.len(), input.platform_profile, input.measurement_variant);
        }
        let (policy, _, _) = choices.remove(0);
        self.register_policy(owner, owner_fp, owner_public, policy, emulated_measurement)
            .await
    }
    /// Prepare the development workload on an owned fork and resolve its actual
    /// Registry policies, without creating sessions or binding Portal sockets.
    pub async fn policy_candidates(
        &self,
        input: &ResolvedWorkload,
        publisher: &[u8; 32],
    ) -> Result<Vec<(SessionRegistry::ResolvedPcrPolicy, String, String)>> {
        let config = atakit_workload::config::WorkloadConfig::from_file(&input.config_file)?;
        let publisher_public = signing::derive_public_key_uncompressed(publisher)?.to_vec();
        let publisher_fp = B256::from(atakit_cvm_encoding::key_fingerprint(
            AlgoId::Es256K as u8,
            &publisher_public,
        ));
        let wid = B256::from(atakit_cvm_encoding::workload_id(&AppRef::new(
            publisher_fp.0,
            &config.workload.name,
            &config.workload.version,
        )));
        let refs = config
            .workload
            .base_image
            .iter()
            .map(|r| r.parse::<AppRef>())
            .collect::<Result<Vec<_>, _>>()?;
        if config.workload.base_image_mode != "whitelist" || refs.is_empty() {
            bail!("emulator needs explicit allowed base-image references in workload TOML");
        }
        let ids: Vec<B256> = refs
            .iter()
            .map(|r| B256::from(atakit_cvm_encoding::base_image_id(r)))
            .collect();
        let emulated_measurement = B256::from(crate::inputs::measurement(
            &input.config_file,
            &input.workload_dir,
        )?);
        let mut requirements = Vec::new();
        for (name, values) in &config.workload.attributes {
            let (key, values) = atakit_core::tee_attributes::encode_requirement(name, values)
                .map_err(anyhow::Error::msg)?;
            requirements.push(AttributeRequirement {
                key: key.into(),
                allowedValues: values.into_iter().map(Into::into).collect(),
            });
        }
        requirements.sort_by_key(|r| r.key);
        let spec = WorkloadSpec {
            name: config.workload.name.clone(),
            version: config.workload.version.clone(),
            sessionTtl: config.workload.session_ttl,
            baseImageMode: 2,
            baseImageIds: ids.clone(),
            requirements,
            workloadPcrPolicy: PcrPolicyBlock {
                pcrSpecs256: vec![PcrSpec256 {
                    pcrIndex: 23,
                    comparison: atakit_cvm_encoding::pcr_comparison::encode_extend_from_zero256(
                        emulated_measurement.0,
                    )
                    .into(),
                }],
                pcrSpecs384: vec![],
            },
        };
        if let Ok(existing) = read(
            &self.rpc,
            self.registry.workload,
            getWorkloadCall { workloadId: wid },
        )
        .await
        {
            if existing.name != spec.name
                || existing.version != spec.version
                || existing.baseImageMode != spec.baseImageMode
                || existing.baseImageIds != spec.baseImageIds
                || existing.requirements.abi_encode() != spec.requirements.abi_encode()
                || existing.sessionTtl != spec.sessionTtl
            {
                bail!("published workload {wid} conflicts with this TOML; choose a new version");
            }
        } else {
            self.whitelist(publisher_fp).await?;
            let expires = self.timestamp().await? + 3600;
            let digest: [u8; 32] = Sha256::digest(
                (
                    keccak256("CVM_MSG_WORKLOAD_REGISTER_V1"),
                    U256::from(self.registry.chain_id),
                    self.registry.workload,
                    expires,
                    spec.clone(),
                )
                    .abi_encode_params(),
            )
            .into();
            let signature = signing::sign_secp256k1_recoverable(
                publisher,
                digest,
                signing::SigEncoding::EthereumLegacyV,
            )?;
            self.send(
                self.registry.workload,
                registerWorkloadCall {
                    spec,
                    opExpiresAt: expires,
                    ownerIdentity: PublicIdentity {
                        typeId: 3,
                        key: publisher_public.into(),
                    },
                    ownerSignature: signature.to_vec().into(),
                },
            )
            .await
            .context("register development workload on B")?;
        }
        if read(
            &self.rpc,
            self.registry.workload,
            isWorkloadRevokedCall { workloadId: wid },
        )
        .await?
        {
            bail!("workload is revoked; choose a new version");
        }
        let mut choices = vec![];
        for base in ids {
            if read(
                &self.rpc,
                self.registry.base_image,
                isBaseImageRevokedCall { baseImageId: base },
            )
            .await?
            {
                continue;
            }
            let profiles = read(
                &self.rpc,
                self.registry.base_image,
                getPlatformProfileIdsCall { baseImageId: base },
            )
            .await?;
            for profile in profiles {
                let p = read(
                    &self.rpc,
                    self.registry.base_image,
                    getPlatformProfileCall {
                        platformProfileId: profile,
                    },
                )
                .await?;
                if !p.name.starts_with("gcp-tdx")
                    || p.pcrBankSelection == PcrBankSelection::Sha384 as u8
                    || input
                        .platform_profile
                        .as_ref()
                        .is_some_and(|name| name != &p.name)
                {
                    continue;
                }
                for variant in read(
                    &self.rpc,
                    self.registry.base_image,
                    getMeasurementVariantIdsCall {
                        platformProfileId: profile,
                    },
                )
                .await?
                {
                    let variant_spec = read(
                        &self.rpc,
                        self.registry.base_image,
                        getMeasurementVariantCall { variantId: variant },
                    )
                    .await?;
                    if input
                        .measurement_variant
                        .as_ref()
                        .is_some_and(|name| name != &variant_spec.name)
                    {
                        continue;
                    }
                    if let Ok(policy) = read(
                        &self.rpc,
                        self.registry.session,
                        getPcrPolicyCall {
                            workloadId: wid,
                            baseImageId: base,
                            platformProfileId: profile,
                            measurementVariantId: variant,
                        },
                    )
                    .await
                    {
                        choices.push((policy, p.name.clone(), variant_spec.name));
                    }
                }
            }
        }
        Ok(choices)
    }

    async fn register_policy(
        &self,
        owner: &[u8; 32],
        owner_fp: B256,
        owner_public: Vec<u8>,
        policy: SessionRegistry::ResolvedPcrPolicy,
        emulated_measurement: B256,
    ) -> Result<RegisteredSession> {
        let nonce = read(
            &self.rpc,
            self.registry.session,
            getNonceCall {
                ownerFingerprint: owner_fp,
            },
        )
        .await?;
        let secret = signing::generate_secret_key_bytes();
        let evidence = crate::evidence::build(
            self.registry.chain_id,
            self.registry.session,
            owner_fp,
            nonce,
            &policy,
            &secret,
        )?;
        let fp = B256::from(atakit_cvm_encoding::key_fingerprint(
            AlgoId::Es256K as u8,
            &evidence.evidence.sessionKey.key,
        ));
        let expires = self.timestamp().await? + 3600;
        let payload = session_protocol::compute_owner_signature_payload(
            self.registry.chain_id,
            self.registry.session,
            expires,
            evidence.session_id,
            policy.workloadId,
            policy.baseImageId,
            policy.platformProfileId,
            policy.measurementVariantId,
            fp,
        );
        let signature = signing::sign_secp256k1_recoverable(
            owner,
            payload,
            signing::SigEncoding::EthereumLegacyV,
        )?
        .to_vec();
        let call = registerSessionCall {
            evidence: evidence.evidence.clone(),
            workloadId: policy.workloadId,
            baseImageId: policy.baseImageId,
            platformProfileId: policy.platformProfileId,
            variantId: policy.measurementVariantId,
            opExpiresAt: expires,
            ownerIdentity: crate::evidence::public_identity(AlgoId::Es256K, owner_public.clone()),
            ownerSignature: signature.clone().into(),
        };
        // Simulate through the same real Registry first to surface precise reverts.
        read(&self.rpc, self.registry.session, call.clone())
            .await
            .context("session registration preflight")?;
        let receipt = self
            .send(self.registry.session, call)
            .await
            .context("register session on B")?;
        if !self.active(evidence.session_id).await? {
            bail!("registration receipt succeeded but session is inactive");
        }
        let session = read(
            &self.rpc,
            self.registry.session,
            getSessionCall {
                sessionId: evidence.session_id,
            },
        )
        .await?;
        if session.sessionKeyFingerprint != fp || session.workloadId != policy.workloadId {
            bail!("registered session identity mismatch");
        }
        Ok(RegisteredSession {
            owner_nonce: nonce,
            op_expires_at: expires,
            policy_abi: policy.abi_encode(),
            rotated: false,
            session_id: evidence.session_id,
            session_secret: secret,
            tpm_secret: evidence.tpm_secret,
            tee_hash: evidence.tee_hash,
            workload_id: policy.workloadId,
            base_image_id: policy.baseImageId,
            profile_id: policy.platformProfileId,
            variant_id: policy.measurementVariantId,
            owner_fp,
            owner_public,
            owner_payload: payload,
            owner_signature: signature,
            registration_tx: receipt["transactionHash"]
                .as_str()
                .context("receipt missing hash")?
                .into(),
            expires_at: session.sessionExpiresAt,
            evidence_abi: evidence.evidence.abi_encode(),
            emulated_measurement,
        })
    }
    pub async fn rotate(
        &self,
        old: &RegisteredSession,
        owner: &[u8; 32],
    ) -> Result<RegisteredSession> {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
        let policy = read(
            &self.rpc,
            self.registry.session,
            getPcrPolicyCall {
                workloadId: old.workload_id,
                baseImageId: old.base_image_id,
                platformProfileId: old.profile_id,
                measurementVariantId: old.variant_id,
            },
        )
        .await?;
        let nonce = read(
            &self.rpc,
            self.registry.session,
            getNonceCall {
                ownerFingerprint: old.owner_fp,
            },
        )
        .await?;
        let secret = signing::generate_secret_key_bytes();
        let previous_evidence =
            SessionRegistry::AttestationEvidence::abi_decode(&old.evidence_abi)?;
        let next = crate::evidence::build_with_quote(
            self.registry.chain_id,
            self.registry.session,
            old.owner_fp,
            nonce,
            &policy,
            &secret,
            Some(&previous_evidence.teeReport.data),
            true,
        )?;
        let old_tpm = SigningKey::from_slice(&old.tpm_secret)?;
        let new_tpm = SigningKey::from_slice(&next.tpm_secret)?;
        let new_tpm_pub = new_tpm.verifying_key().to_encoded_point(false);
        let fp = B256::from(atakit_cvm_encoding::key_fingerprint(
            AlgoId::Es256K as u8,
            &next.evidence.sessionKey.key,
        ));
        let rotation_digest = session_protocol::compute_rotate_key_tpm_payload(
            self.registry.chain_id,
            self.registry.session,
            old.session_id,
            B256::from(atakit_cvm_encoding::key_fingerprint(
                AlgoId::Es256 as u8,
                new_tpm_pub.as_bytes(),
            )),
            fp,
            next.tee_hash,
        );
        let proof: Signature = old_tpm.sign_prehash(rotation_digest.as_slice())?;
        let proof = proof.normalize_s().unwrap_or(proof);
        let expires = self.timestamp().await? + 3600;
        let payload = session_protocol::compute_rotate_key_owner_payload(
            self.registry.chain_id,
            self.registry.session,
            expires,
            old.session_id,
            next.session_id,
        );
        let signature = signing::sign_secp256k1_recoverable(
            owner,
            payload,
            signing::SigEncoding::EthereumLegacyV,
        )?
        .to_vec();
        let rotation = SessionRegistry::SessionKeyRotationEvidence {
            tpmQuoteReport: next.evidence.tpmQuoteReport.clone(),
            tpmCertifyReport: next.evidence.tpmCertifyReport.clone(),
            sessionKeySignature: next.evidence.sessionKeySignature.clone(),
            sessionKey: next.evidence.sessionKey.clone(),
            rotationSignature: proof.to_der().as_bytes().to_vec().into(),
            oldTpmSigningKey: crate::evidence::public_identity(
                AlgoId::Es256,
                old_tpm
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            ),
            akPub: next.evidence.akPub.clone(),
        };
        let call = rotateKeyCall {
            oldSessionId: old.session_id,
            teeReportBytesHash: next.tee_hash,
            rotationEvidence: rotation,
            opExpiresAt: expires,
            ownerIdentity: crate::evidence::public_identity(
                AlgoId::Es256K,
                old.owner_public.clone(),
            ),
            ownerSignature: signature.clone().into(),
        };
        read(&self.rpc, self.registry.session, call.clone())
            .await
            .context("rotate preflight")?;
        let receipt = self.send(self.registry.session, call).await?;
        anyhow::ensure!(
            !self.active(old.session_id).await? && self.active(next.session_id).await?,
            "rotation session state mismatch"
        );
        let registered = read(
            &self.rpc,
            self.registry.session,
            getSessionCall {
                sessionId: next.session_id,
            },
        )
        .await?;
        let mut result = old.clone();
        result.owner_nonce = nonce;
        result.op_expires_at = expires;
        result.policy_abi = policy.abi_encode();
        result.rotated = true;
        result.session_id = next.session_id;
        result.session_secret = secret;
        result.tpm_secret = next.tpm_secret;
        result.tee_hash = next.tee_hash;
        result.owner_payload = payload;
        result.owner_signature = signature;
        result.registration_tx = receipt["transactionHash"]
            .as_str()
            .context("receipt missing hash")?
            .into();
        result.expires_at = registered.sessionExpiresAt;
        result.evidence_abi = next.evidence.abi_encode();
        Ok(result)
    }
    pub async fn revoke(&self, session: &RegisteredSession, owner: &[u8; 32]) -> Result<()> {
        let expires = self.timestamp().await? + 3600;
        let digest: [u8; 32] = Sha256::digest(
            (
                keccak256("CVM_MSG_SESSION_REVOKE_V1"),
                U256::from(self.registry.chain_id),
                self.registry.session,
                expires,
                session.session_id,
            )
                .abi_encode_params(),
        )
        .into();
        let signature = signing::sign_secp256k1_recoverable(
            owner,
            digest,
            signing::SigEncoding::EthereumLegacyV,
        )?;
        self.send(
            self.registry.session,
            revokeSessionCall {
                sessionId: session.session_id,
                opExpiresAt: expires,
                ownerIdentity: SessionRegistry::PublicIdentity {
                    typeId: 3,
                    key: session.owner_public.clone().into(),
                },
                ownerSignature: signature.to_vec().into(),
            },
        )
        .await?;
        if self.active(session.session_id).await? {
            bail!("session still active after revoke");
        }
        Ok(())
    }
}

impl RegisteredSession {
    pub fn portal_session(
        &self,
        registry: &RegistryContext,
        rpc_url: &str,
    ) -> Result<crate::portal::PortalSession> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
        let evidence = SessionRegistry::AttestationEvidence::abi_decode(&self.evidence_abi)?;
        let quote = TpmQuoteEvidence::abi_decode(&evidence.tpmQuoteReport.data)?;
        let certify =
            evidence_abi::TpmCertifyEvidence::abi_decode(&evidence.tpmCertifyReport.data)?;
        let pubkey = signing::derive_public_key_uncompressed(&self.session_secret)?;
        let fp = B256::from(atakit_cvm_encoding::key_fingerprint(
            AlgoId::Es256K as u8,
            &pubkey,
        ));
        let tpm = p256::ecdsa::SigningKey::from_slice(&self.tpm_secret)?;
        let tpm_public = tpm.verifying_key().to_encoded_point(false);
        let signatures = <(alloy_primitives::Bytes, alloy_primitives::Bytes)>::abi_decode_params(
            &evidence.sessionKeySignature,
        )?;
        let policy = SessionRegistry::ResolvedPcrPolicy::abi_decode(&self.policy_abi)?;
        let indexes = quote
            .pcrValues256
            .iter()
            .map(|p| p.pcrIndex)
            .chain(quote.pcrValues384.iter().map(|p| p.pcrIndex))
            .collect::<std::collections::BTreeSet<_>>();
        let bytes48 = |v: &Bytes48| hexbytes([v.first.as_slice(), v.second.as_slice()].concat());
        let values=indexes.iter().map(|i|json!({"index":i,"sha256":quote.pcrValues256.iter().find(|p|p.pcrIndex==*i).map(|p|hexbytes(p.value)),"sha384":quote.pcrValues384.iter().find(|p|p.pcrIndex==*i).map(|p|bytes48(&p.value))})).collect::<Vec<_>>();
        let events=indexes.iter().map(|i|json!({"pcr_index":i,"sha256":quote.pcrValues256.iter().find(|p|p.pcrIndex==*i).map(|p|p.eventLogHashes.iter().map(hexbytes).collect::<Vec<_>>()).unwrap_or_default(),"sha384":quote.pcrValues384.iter().find(|p|p.pcrIndex==*i).map(|p|p.eventLogHashes.iter().map(bytes48).collect::<Vec<_>>()).unwrap_or_default()})).collect::<Vec<_>>();
        let block = |p: &SessionRegistry::PcrPolicyBlock| json!({"pcr_specs256":p.pcrSpecs256.iter().map(|p|json!({"pcr_index":p.pcrIndex,"comparison":hexbytes(&p.comparison)})).collect::<Vec<_>>(),"pcr_specs384":p.pcrSpecs384.iter().map(|p|json!({"pcr_index":p.pcrIndex,"comparison":hexbytes(&p.comparison)})).collect::<Vec<_>>()});
        let mut provider = SessionRegistry::PcrPolicyBlock {
            pcrSpecs256: vec![],
            pcrSpecs384: vec![],
        };
        if !self.rotated {
            let mut binding = [0; 32];
            binding[16..].copy_from_slice(&evidence.teeReport.data[48 + 520..48 + 536]);
            provider.pcrSpecs256.push(SessionRegistry::PcrSpec256 {
                pcrIndex: 15,
                comparison: atakit_cvm_encoding::pcr_comparison::encode_extend_from_zero256(
                    binding,
                )
                .into(),
            });
        }
        let qualifying_data = B256::from(atakit_attestation::compute_session_qualifying_data(
            registry.chain_id,
            registry.session.into(),
            self.owner_fp.0,
            self.owner_nonce.to_be_bytes(),
        ));
        let tpm_fingerprint = B256::from(atakit_cvm_encoding::key_fingerprint(
            AlgoId::Es256 as u8,
            tpm_public.as_bytes(),
        ));
        let delegation_digest = B256::from(atakit_attestation::delegation_digest(
            registry.chain_id,
            registry.session.into(),
            self.base_image_id.0,
            self.workload_id.0,
            self.session_id.0,
            fp.0,
        ));
        let bundle = json!({
            "format":2,"emulated":true,"attestation_mode":"emulation",
            "binding":{"mode":"chain","chain_id":registry.chain_id,"registry":registry.session,"owner_nonce":hexbytes(self.owner_nonce.to_be_bytes::<32>()),"qualifying_data":qualifying_data},
            "platform":{"cloud_type":"gcp","tee_type":"tdx","attestation_mode":"emulation"},
            "tee_evidence":{"kind":"emulation","report":B64.encode(&evidence.teeReport.data),"auxiliary":null},
            "ak_evidence":{"kind":"gcp_cert_chain","ak_public":B64.encode(&evidence.akPub.key),"collateral":B64.encode(&evidence.akPubCollateral.data)},
            "tpm_quote":{"tpms_attest":B64.encode(&quote.tpmsAttest),"tpm_signature":B64.encode(&quote.tpmSignature),"signature_hash":keccak256(&quote.tpmSignature),"pcr0_startup_locality":quote.pcr0StartupLocality},
            "tpm_certify":{"tpms_attest":B64.encode(&certify.tpmsAttest),"tpm_signature":B64.encode(&certify.tpmSignature),"tpmt_public":B64.encode(&certify.tpmtPublic)},
            "session_key":{"type_id":3,"bytes":hexbytes(pubkey),"fingerprint":fp},
            "session_key_delegation":{"tpm_signing_key":{"type_id":2,"bytes":hexbytes(tpm_public.as_bytes()),"fingerprint":tpm_fingerprint},"digest":delegation_digest,"signature":hexbytes(signatures.0),"session_key_possession_signature":hexbytes(signatures.1)},
            "session_id":self.session_id,"base_image_id":self.base_image_id,"workload_id":self.workload_id,
            "policy":{"base_image_id":self.base_image_id,"workload_id":self.workload_id,"platform_profile_id":self.profile_id,"measurement_variant_id":self.variant_id,"pcr_bank_selection":if quote.pcrValues384.is_empty(){"sha256"}else{"sha256_and_sha384"},"invariant_pcr_policy":block(&policy.invariantPcrPolicy),"variant_pcr_policy":block(&policy.variantPcrPolicy),"workload_pcr_policy":block(&policy.workloadPcrPolicy),"provider_pcr_policy":block(&provider)},
            "owner":{"fingerprint":self.owner_fp,"contract_authorization":{"op_expires_at":self.op_expires_at,"payload":hexbytes(self.owner_payload),"signature":hexbytes(&self.owner_signature)}},
            "local_build":null,"build_status":"not_built","emulated_measurement":self.emulated_measurement,
            "pcr_values":values,"event_log_hashes":events
        });
        Ok(crate::portal::PortalSession {
            session_id: self.session_id,
            secret_key: self.session_secret,
            owner_fingerprint: self.owner_fp,
            workload_id: self.workload_id,
            session_registry: registry.session,
            chain_id: registry.chain_id,
            rpc_url: rpc_url.into(),
            evidence_bundle: bundle,
        })
    }
}
