//! Local verification of publisher-approved policy data from any transport.
//! Signatures prove approval, not current registration, freshness, or non-revocation.
use crate::{PcrBankSelection, PcrPolicyBlock, PublicIdentity, ResolvedPcrPolicy};
use alloy_primitives::{keccak256, B256};
use alloy_sol_types::{sol, sol_data, SolType, SolValue};
use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, RSA_PKCS1_2048_8192_SHA256};
use sha2::{Digest, Sha256};

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct Attribute { bytes32 key; bytes32 value; }
    #[derive(Debug, PartialEq, Eq)]
    struct AttributeRequirement { bytes32 key; bytes32[] allowedValues; }
    #[derive(Debug, PartialEq, Eq)]
    struct BaseImageSpec { string name; string version; string uri; }
    #[derive(Debug, PartialEq, Eq)]
    struct PlatformProfile {
        string name;
        uint8 pcrBankSelection;
        PcrPolicyBlock invariantPcrPolicy;
        Attribute[] attributes;
    }
    #[derive(Debug, PartialEq, Eq)]
    struct MeasurementVariant { string name; PcrPolicyBlock variantPcrPolicy; Attribute[] attributes; }
    #[derive(Debug, PartialEq, Eq)]
    enum AccessMode { ANY, BLACKLIST, WHITELIST }
    #[derive(Debug, PartialEq, Eq)]
    struct WorkloadSpec {
        string name;
        string version;
        uint64 sessionTtl;
        AccessMode baseImageMode;
        bytes32[] baseImageIds;
        AttributeRequirement[] requirements;
        PcrPolicyBlock workloadPcrPolicy;
    }
    #[derive(Debug)]
    struct SignedBaseImageVariant {
        BaseImageSpec baseImage;
        bytes32 ownerFingerprint;
        PublicIdentity ownerIdentity;
        PlatformProfile platformProfile;
        MeasurementVariant measurementVariant;
        bytes variantSignature;
    }
    #[derive(Debug)]
    struct SignedWorkload {
        WorkloadSpec spec;
        bytes32 ownerFingerprint;
        PublicIdentity ownerIdentity;
        bytes workloadSignature;
    }
    function getSignedWorkload(bytes32 workloadId) external view returns (SignedWorkload);
    function getSignedVariant(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId) external view returns (SignedBaseImageVariant);
    function workloadRegistry() external view returns (address);
    function baseImageRegistry() external view returns (address);
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("publisher fingerprint does not match its public key")]
    Fingerprint,
    #[error("signed policy does not match the requested {0}")]
    Identifier(&'static str),
    #[error("publisher signature is missing or invalid")]
    Signature,
    #[error("unsupported publisher key algorithm {0}")]
    Algorithm(u8),
    #[error("invalid PCR bank selection")]
    PcrBank,
    #[error("the signed workload policy does not allow this base image")]
    BaseImageAccess,
    #[error("signed base-image attributes do not satisfy workload requirement {0}")]
    Attribute(B256),
    #[error("duplicate signed attribute key {0}")]
    DuplicateAttribute(B256),
}

/// Retains every authenticated policy field, including requirements and both
/// attribute sets. TEE-specific requirements still need authenticated hardware
/// evidence; they cannot be established from publisher metadata alone.
pub struct VerifiedPublisherPolicies {
    workload: SignedWorkload,
    base_image: SignedBaseImageVariant,
    pcr_policy: ResolvedPcrPolicy,
}

impl VerifiedPublisherPolicies {
    pub fn workload(&self) -> &WorkloadSpec {
        &self.workload.spec
    }
    pub fn base_image(&self) -> &SignedBaseImageVariant {
        &self.base_image
    }
    pub fn pcr_policy(&self) -> &ResolvedPcrPolicy {
        &self.pcr_policy
    }
    pub fn into_pcr_policy(self) -> ResolvedPcrPolicy {
        self.pcr_policy
    }
}

pub fn workload_payload(id: B256, spec: &WorkloadSpec) -> Vec<u8> {
    (
        keccak256("CVM_WORKLOAD_POLICY_SIGNATURE_V1"),
        id,
        spec.clone(),
    )
        .abi_encode_params()
}
pub fn variant_payload(
    id: B256,
    profile: &PlatformProfile,
    variant: &MeasurementVariant,
) -> Vec<u8> {
    (
        keccak256("CVM_BASEIMAGE_VARIANT_SIGNATURE_V1"),
        id,
        profile.clone(),
        variant.clone(),
    )
        .abi_encode_params()
}

fn fingerprint(identity: &PublicIdentity) -> B256 {
    keccak256(<(
        sol_data::FixedBytes<32>,
        sol_data::Uint<8>,
        sol_data::Bytes,
    )>::abi_encode_params(&(
        keccak256("KEY_RESOLVER_V1"),
        identity.typeId,
        identity.key.clone(),
    )))
}
fn qualified_id(domain: &str, owner: B256, name: &str, version: &str) -> B256 {
    keccak256((keccak256(domain), owner, name, version).abi_encode_params())
}

/// Verify the exact contract signature format without calling a registry or
/// SignatureVerifier contract. The input is the ABI message before SHA-256.
fn verify_signature(
    identity: &PublicIdentity,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), PolicyError> {
    if signature.is_empty() {
        return Err(PolicyError::Signature);
    }
    match identity.typeId {
        1 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &identity.key)
            .verify(payload, signature)
            .map_err(|_| PolicyError::Signature),
        2 => {
            if identity.key.len() != 65 || identity.key[0] != 4 {
                return Err(PolicyError::Signature);
            }
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &identity.key)
                .verify(payload, signature)
                .map_err(|_| PolicyError::Signature)
        }
        3 => {
            if identity.key.len() != 65 || identity.key[0] != 4 || signature.len() != 65 {
                return Err(PolicyError::Signature);
            }
            let recovery = match signature[64] {
                27 => k256::ecdsa::RecoveryId::from_byte(0),
                28 => k256::ecdsa::RecoveryId::from_byte(1),
                _ => None,
            }
            .ok_or(PolicyError::Signature)?;
            let signature = k256::ecdsa::Signature::from_slice(&signature[..64])
                .map_err(|_| PolicyError::Signature)?;
            if signature.normalize_s().is_some() {
                return Err(PolicyError::Signature);
            }
            let expected = k256::ecdsa::VerifyingKey::from_sec1_bytes(&identity.key)
                .map_err(|_| PolicyError::Signature)?;
            let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
                &Sha256::digest(payload),
                &signature,
                recovery,
            )
            .map_err(|_| PolicyError::Signature)?;
            if recovered != expected {
                return Err(PolicyError::Signature);
            }
            Ok(())
        }
        other => Err(PolicyError::Algorithm(other)),
    }
}

pub fn verify_workload(id: B256, signed: &SignedWorkload) -> Result<(), PolicyError> {
    let owner = fingerprint(&signed.ownerIdentity);
    if owner != signed.ownerFingerprint {
        return Err(PolicyError::Fingerprint);
    }
    if qualified_id(
        "CVM_WORKLOAD_V1",
        owner,
        &signed.spec.name,
        &signed.spec.version,
    ) != id
    {
        return Err(PolicyError::Identifier("workloadId"));
    }
    verify_signature(
        &signed.ownerIdentity,
        &workload_payload(id, &signed.spec),
        &signed.workloadSignature,
    )
}

pub fn verify_variant(
    image_id: B256,
    profile_id: B256,
    variant_id: B256,
    signed: &SignedBaseImageVariant,
) -> Result<(), PolicyError> {
    let owner = fingerprint(&signed.ownerIdentity);
    if owner != signed.ownerFingerprint {
        return Err(PolicyError::Fingerprint);
    }
    if qualified_id(
        "CVM_BASEIMAGE_V1",
        owner,
        &signed.baseImage.name,
        &signed.baseImage.version,
    ) != image_id
    {
        return Err(PolicyError::Identifier("baseImageId"));
    }
    if keccak256(
        (
            keccak256("CVM_PLATFORM_PROFILE_V1"),
            image_id,
            &signed.platformProfile.name,
        )
            .abi_encode_params(),
    ) != profile_id
    {
        return Err(PolicyError::Identifier("platformProfileId"));
    }
    if keccak256(
        (
            keccak256("CVM_PLATFORM_VARIANT_V1"),
            profile_id,
            &signed.measurementVariant.name,
        )
            .abi_encode_params(),
    ) != variant_id
    {
        return Err(PolicyError::Identifier("measurementVariantId"));
    }
    verify_signature(
        &signed.ownerIdentity,
        &variant_payload(
            image_id,
            &signed.platformProfile,
            &signed.measurementVariant,
        ),
        &signed.variantSignature,
    )
}

/// Match the contract's ordinary metadata checks. Reserved TEE attributes are
/// authenticated here but their meaning is checked against hardware evidence
/// by the attestation path, not inferred from this metadata.
fn check_metadata(
    workload: &WorkloadSpec,
    image: &SignedBaseImageVariant,
) -> Result<(), PolicyError> {
    for attrs in [
        &image.platformProfile.attributes,
        &image.measurementVariant.attributes,
    ] {
        let mut keys = std::collections::BTreeSet::new();
        for attr in attrs {
            if !keys.insert(attr.key) {
                return Err(PolicyError::DuplicateAttribute(attr.key));
            }
        }
    }
    let reserved = [
        "atakit.attestation.v1.tee.intel-tdx.debug.enabled",
        "atakit.attestation.v1.tee.amd-sev-snp.debug.enabled",
        "atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled",
        "atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed",
        "atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum",
        "atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum.by-cpuid",
        "atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy",
    ]
    .map(keccak256);
    for requirement in &workload.requirements {
        if reserved.contains(&requirement.key) {
            continue;
        }
        let actual = image
            .measurementVariant
            .attributes
            .iter()
            .chain(&image.platformProfile.attributes)
            .find(|a| a.key == requirement.key)
            .ok_or(PolicyError::Attribute(requirement.key))?;
        if !requirement.allowedValues.is_empty()
            && !requirement.allowedValues.contains(&actual.value)
        {
            return Err(PolicyError::Attribute(requirement.key));
        }
    }
    Ok(())
}

pub fn verify_selected_policy(
    workload_id: B256,
    image_id: B256,
    profile_id: B256,
    variant_id: B256,
    workload: SignedWorkload,
    image: SignedBaseImageVariant,
) -> Result<VerifiedPublisherPolicies, PolicyError> {
    verify_workload(workload_id, &workload)?;
    verify_variant(image_id, profile_id, variant_id, &image)?;
    let listed = workload.spec.baseImageIds.contains(&image_id);
    let allowed = match workload.spec.baseImageMode {
        AccessMode::ANY => true,
        AccessMode::BLACKLIST => !listed,
        AccessMode::WHITELIST => listed,
        _ => false,
    };
    if !allowed {
        return Err(PolicyError::BaseImageAccess);
    }
    check_metadata(&workload.spec, &image)?;
    let pcr_policy = ResolvedPcrPolicy {
        workloadId: workload_id,
        baseImageId: image_id,
        platformProfileId: profile_id,
        measurementVariantId: variant_id,
        pcrBankSelection: match image.platformProfile.pcrBankSelection {
            0 => PcrBankSelection::Sha256,
            1 => PcrBankSelection::Sha384,
            2 => PcrBankSelection::Sha256AndSha384,
            _ => return Err(PolicyError::PcrBank),
        },
        invariantPcrPolicy: image.platformProfile.invariantPcrPolicy.clone(),
        variantPcrPolicy: image.measurementVariant.variantPcrPolicy.clone(),
        workloadPcrPolicy: workload.spec.workloadPcrPolicy.clone(),
    };
    Ok(VerifiedPublisherPolicies {
        workload,
        base_image: image,
        pcr_policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };

    #[test]
    fn rsa_and_p256_verify_the_sha256_message_once() {
        let rng = SystemRandom::new();
        let message = b"publisher policy ABI bytes";
        let rsa = signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let mut rsa_sig = vec![0; rsa.public_modulus_len()];
        rsa.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut rsa_sig)
            .unwrap();
        let p256 =
            signature::EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let p256_sig = p256.sign(&rng, message).unwrap();
        for (type_id, key, sig) in [
            (1, rsa.public_key().as_ref(), rsa_sig.as_slice()),
            (2, p256.public_key().as_ref(), p256_sig.as_ref()),
        ] {
            let identity = PublicIdentity {
                typeId: type_id,
                key: key.to_vec().into(),
            };
            verify_signature(&identity, message, sig).unwrap();
            assert_eq!(
                verify_signature(&identity, b"modified policy", sig),
                Err(PolicyError::Signature)
            );
            assert_eq!(
                verify_signature(&identity, message, &[]),
                Err(PolicyError::Signature)
            );
        }
        assert_eq!(
            verify_signature(
                &PublicIdentity {
                    typeId: 42,
                    key: Default::default()
                },
                message,
                &[1]
            ),
            Err(PolicyError::Algorithm(42))
        );
    }

    #[test]
    fn signed_access_rules_and_attribute_overrides_are_enforced() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/publisher-policies.json"))
                .unwrap();
        let bytes = |v: &serde_json::Value| {
            v.as_str()
                .unwrap()
                .parse::<alloy_primitives::Bytes>()
                .unwrap()
        };
        let mut workload = getSignedWorkloadCall::abi_decode_returns_validate(&bytes(
            &f["workload"]["rawGetterResult"],
        ))
        .unwrap();
        let image = getSignedVariantCall::abi_decode_returns_validate(&bytes(
            &f["variants"][0]["rawGetterResult"],
        ))
        .unwrap();
        let wid = f["workload"]["id"].as_str().unwrap().parse().unwrap();
        let image_id = workload.spec.baseImageIds[0];
        let pid = f["variants"][0]["profileId"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let vid = f["variants"][0]["id"].as_str().unwrap().parse().unwrap();
        let key = k256::ecdsa::SigningKey::from_slice(
            &hex::decode(format!("{:064x}", 0xA11CEu64)).unwrap(),
        )
        .unwrap();
        let resign = |w: &mut SignedWorkload| {
            let (sig, rec) = key
                .sign_prehash_recoverable(&Sha256::digest(workload_payload(wid, &w.spec)))
                .unwrap();
            let mut bytes = sig.to_bytes().to_vec();
            bytes.push(rec.to_byte() + 27);
            w.workloadSignature = bytes.into();
        };
        workload.spec.baseImageMode = AccessMode::BLACKLIST;
        resign(&mut workload);
        assert!(matches!(
            verify_selected_policy(wid, image_id, pid, vid, workload.clone(), image.clone()),
            Err(PolicyError::BaseImageAccess)
        ));
        workload.spec.baseImageMode = AccessMode::WHITELIST;
        workload.spec.baseImageIds.clear();
        resign(&mut workload);
        assert!(matches!(
            verify_selected_policy(wid, image_id, pid, vid, workload.clone(), image.clone()),
            Err(PolicyError::BaseImageAccess)
        ));

        let key = image.platformProfile.attributes[0].key;
        let value = image.platformProfile.attributes[0].value;
        workload.spec.requirements = vec![AttributeRequirement {
            key,
            allowedValues: vec![value],
        }];
        check_metadata(&workload.spec, &image).unwrap();
        let mut overridden = image.clone();
        overridden
            .measurementVariant
            .attributes
            .retain(|a| a.key != key);
        overridden.measurementVariant.attributes.push(Attribute {
            key,
            value: B256::repeat_byte(0xff),
        });
        assert_eq!(
            check_metadata(&workload.spec, &overridden),
            Err(PolicyError::Attribute(key))
        );
        workload.spec.requirements[0].allowedValues.clear();
        check_metadata(&workload.spec, &overridden).unwrap();
        overridden
            .measurementVariant
            .attributes
            .push(Attribute { key, value });
        assert_eq!(
            check_metadata(&workload.spec, &overridden),
            Err(PolicyError::DuplicateAttribute(key))
        );
        workload.spec.requirements[0].key = B256::repeat_byte(0xee);
        assert!(matches!(
            check_metadata(&workload.spec, &image),
            Err(PolicyError::Attribute(_))
        ));
    }
}
