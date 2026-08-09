//! Converting a `workload-trust` pack into measurement and session policy.
//!
//! This module carries the authority separation the format depends on. On the
//! chain path two parties decide two different things: the workload publisher
//! decides *which* base images may run their workload, and each base-image
//! publisher decides *what their own image measures*. A pack is signed by one
//! party, so the second decision has to be re-established from the signed bytes
//! — which is what the identifier recomputation below does.
//!
//! Every check here exists because removing it collapses those two authorities
//! into one. That collapse is the defect recorded under "Base-image publisher
//! authority" in `docs/specs/atatp-archive-spec.md`, which blocked this kind
//! until publisher-qualified identifiers landed on 2026-08-08.

use alloy_ext::core::primitives::B256;
use atakit_attestation::{
    verify_measurement_pack, MeasurementPack, MeasurementPolicy, SessionAttributeRequirement,
    SessionPcrPolicy, SessionPcrPolicy384,
};
use atakit_cvm_types::AppRef;

use crate::chain::{ensure_base_image_allowed, TrustedWorkloadSessionPolicy};
use crate::pack::read::TrustPack;
use crate::pack::{TrustPackError, TrustPackKind};

/// ECDSA secp256k1, matching `ALGO_ID_ES256K` in the contract constants and
/// `AlgoId::Es256K` in its Rust bindings. Publisher keys are ES256K
/// throughout, so this is the only algorithm a pack's owner fingerprint can be
/// computed under.
const ES256K_TYPE_ID: u8 = 3;

/// `payload/workload-spec.json`.
///
/// `publisher` has no on-chain counterpart: `WorkloadRegistry` stores a spec
/// under a `workloadId` that already contains the publisher, so the chain path
/// recovers it from the key it looked the spec up by. A file has no such key,
/// so the reference carries it.
///
/// Keys are `snake_case`, matching `trust-pack.json` and measurement pack
/// version 4.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackedWorkloadSpec {
    /// Owner fingerprint, `0x` and 64 lowercase hexadecimal characters.
    pub publisher: String,
    pub name: String,
    pub version: String,
    pub base_image_mode: BaseImageMode,
    #[serde(default)]
    pub base_image_ids: Vec<String>,
    #[serde(default)]
    pub requirements: Vec<PackedAttributeRequirement>,
    #[serde(default)]
    pub workload_pcrs256: Vec<PackedPcrSpec>,
    #[serde(default)]
    pub workload_pcrs384: Vec<PackedPcrSpec>,
}

/// How `base_image_ids` is interpreted, spelled out rather than carried as the
/// contract's `uint8`. A JSON file has no ABI to make `2` self-describing, and
/// an off-by-one between `blacklist` and `whitelist` inverts an access rule
/// silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaseImageMode {
    Any,
    Blacklist,
    Whitelist,
}

impl BaseImageMode {
    /// The contract's `AccessMode` discriminant, so the pack path and the
    /// chain path evaluate one implementation of the rule.
    fn access_mode(self) -> u8 {
        match self {
            Self::Any => 0,
            Self::Blacklist => 1,
            Self::Whitelist => 2,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackedAttributeRequirement {
    pub key: String,
    /// Empty means any value is accepted, matching the contract.
    #[serde(default)]
    pub allowed_values: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackedPcrSpec {
    pub pcr_index: u8,
    /// The exact canonical ABI comparison bytes, `0x` prefixed. Opaque here:
    /// the TPM verifier is the only thing that interprets them, and re-encoding
    /// them on the way through would be a second encoder to keep in step.
    pub comparison: String,
}

/// What a `workload-trust` pack resolves to for one verification.
#[derive(Debug, Clone)]
pub struct WorkloadTrustInputs {
    pub workload_policy: TrustedWorkloadSessionPolicy,
    pub measurement_policy: MeasurementPolicy,
}

/// Resolve workload and base-image policy from a verified pack.
///
/// `expected_workload` is what the caller asked to verify and
/// `selected_base_image_id` is what verified portal TLS selected — neither is
/// taken from the pack, because a pack that chose either would be answering a
/// question it also asked.
pub fn workload_trust_inputs(
    pack: &TrustPack,
    expected_workload: &AppRef,
    selected_base_image_id: [u8; 32],
) -> Result<WorkloadTrustInputs, TrustPackError> {
    Ok(WorkloadTrustInputs {
        measurement_policy: packed_measurement_policy(pack, selected_base_image_id)?,
        workload_policy: packed_workload_policy(pack, expected_workload, selected_base_image_id)?,
    })
}

/// The base-image measurement policy for one base image.
///
/// Separate from [`packed_workload_policy`] because the two are needed at
/// different moments: portal TLS verification consumes the measurement policy
/// in order to *produce* the verified base-image identity that the workload
/// policy is then checked against. Chain mode has the same split, resolving
/// `--base-image` policy before the connection and the registered
/// `WorkloadSpec` after it.
pub fn packed_measurement_policy(
    pack: &TrustPack,
    base_image_id: [u8; 32],
) -> Result<MeasurementPolicy, TrustPackError> {
    require_workload_kind(pack)?;
    let (mode, declared) = declared_base_images(pack)?;
    // Applied here as well as in `packed_workload_policy` because this call
    // happens first and against an operator-declared base image. A base image
    // the workload spec forbids should be reported as forbidden, not as one
    // whose measurement pack happens to be absent.
    ensure_base_image_allowed(mode, &declared, B256::from(base_image_id)).map_err(|error| {
        TrustPackError::Authority {
            message: error.to_string(),
        }
    })?;
    select_measurement_pack(pack, base_image_id, &declared)
}

fn require_workload_kind(pack: &TrustPack) -> Result<(), TrustPackError> {
    if pack.kind != TrustPackKind::WorkloadTrust {
        return Err(TrustPackError::KindMismatch {
            expected: TrustPackKind::WorkloadTrust.as_str(),
            found: pack.kind.as_str().to_string(),
        });
    }
    Ok(())
}

fn declared_base_images(pack: &TrustPack) -> Result<(u8, Vec<B256>), TrustPackError> {
    let spec: PackedWorkloadSpec =
        serde_json::from_slice(pack.entry("payload/workload-spec.json")?).map_err(|error| {
            TrustPackError::Payload {
                path: "payload/workload-spec.json".to_string(),
                message: error.to_string(),
            }
        })?;
    let ids = spec
        .base_image_ids
        .iter()
        .map(|value| parse_fingerprint("payload/workload-spec.json", "base_image_ids[]", value))
        .collect::<Result<Vec<B256>, _>>()?;
    Ok((spec.base_image_mode.access_mode(), ids))
}

/// The session policy for the workload the caller asked about.
pub fn packed_workload_policy(
    pack: &TrustPack,
    expected_workload: &AppRef,
    selected_base_image_id: [u8; 32],
) -> Result<TrustedWorkloadSessionPolicy, TrustPackError> {
    require_workload_kind(pack)?;

    let spec_bytes = pack.entry("payload/workload-spec.json")?;
    let spec: PackedWorkloadSpec =
        serde_json::from_slice(spec_bytes).map_err(|error| TrustPackError::Payload {
            path: "payload/workload-spec.json".to_string(),
            message: error.to_string(),
        })?;

    let publisher = parse_fingerprint("payload/workload-spec.json", "publisher", &spec.publisher)?;
    let spec_ref = AppRef::new(publisher.0, spec.name.clone(), spec.version.clone());

    // The pack answers for the workload the caller asked about, and no other.
    let expected_id = atakit_cvm_encoding::workload_id(expected_workload);
    let spec_id = atakit_cvm_encoding::workload_id(&spec_ref);
    if spec_id != expected_id {
        return Err(TrustPackError::Authority {
            message: format!(
                "trust pack workload spec is {} and derives workload id 0x{}, but the requested \
                 workload {} derives 0x{}",
                spec_ref,
                hex::encode(spec_id),
                expected_workload,
                hex::encode(expected_id)
            ),
        });
    }

    // The key that signed the pack must be the publisher the spec names.
    // Without this, a verifier configured with publisher A's key would accept
    // a pack in which A names publisher B's workload reference, deriving B's
    // workload id while applying policy A chose.
    let signer_fingerprint =
        atakit_cvm_encoding::key_fingerprint(ES256K_TYPE_ID, &pack.publisher_key);
    if signer_fingerprint != publisher.0 {
        return Err(TrustPackError::Authority {
            message: format!(
                "the configured workload-trust key has owner fingerprint 0x{}, but the workload \
                 spec names publisher {}; a pack may not speak for a publisher whose key it was \
                 not signed with",
                hex::encode(signer_fingerprint),
                spec.publisher
            ),
        });
    }

    let base_image_ids = spec
        .base_image_ids
        .iter()
        .map(|value| parse_fingerprint("payload/workload-spec.json", "base_image_ids[]", value))
        .collect::<Result<Vec<B256>, _>>()?;
    ensure_base_image_allowed(
        spec.base_image_mode.access_mode(),
        &base_image_ids,
        B256::from(selected_base_image_id),
    )
    .map_err(|error| TrustPackError::Authority {
        message: error.to_string(),
    })?;

    Ok(TrustedWorkloadSessionPolicy {
        workload_id: spec_id,
        pcr_specs256: spec
            .workload_pcrs256
            .iter()
            .map(|entry| SessionPcrPolicy {
                pcr_index: entry.pcr_index,
                comparison: entry.comparison.clone(),
            })
            .collect(),
        pcr_specs384: spec
            .workload_pcrs384
            .iter()
            .map(|entry| SessionPcrPolicy384 {
                pcr_index: entry.pcr_index,
                comparison: entry.comparison.clone(),
            })
            .collect(),
        attribute_requirements: spec
            .requirements
            .iter()
            .map(|requirement| {
                Ok(SessionAttributeRequirement {
                    key: parse_fingerprint(
                        "payload/workload-spec.json",
                        "requirements[].key",
                        &requirement.key,
                    )?
                    .0,
                    allowed_values: requirement
                        .allowed_values
                        .iter()
                        .map(|value| {
                            parse_fingerprint(
                                "payload/workload-spec.json",
                                "requirements[].allowed_values[]",
                                value,
                            )
                            .map(|value| value.0)
                        })
                        .collect::<Result<Vec<_>, TrustPackError>>()?,
                })
            })
            .collect::<Result<Vec<_>, TrustPackError>>()?,
    })
}

/// Find the measurement pack describing the selected base image, and establish
/// that its publisher is the one the identifier names.
///
/// The four steps below are the whole authority argument. Each entry's signing
/// key arrives inside the archive the *workload* publisher signed, so nothing
/// may be believed on its account until the key has been shown to hash to the
/// fingerprint the expected `base_image_id` already pins.
fn select_measurement_pack(
    pack: &TrustPack,
    selected_base_image_id: [u8; 32],
    declared: &[B256],
) -> Result<MeasurementPolicy, TrustPackError> {
    let mut selected: Option<(String, MeasurementPack)> = None;

    for (path, bytes) in pack.entries_under("payload/measurement-packs/") {
        let Some(stem) = path.strip_suffix(".json") else {
            continue;
        };
        let signature = pack.entry(&format!("{stem}.sig"))?;
        let key = parse_public_key(
            &format!("{stem}.pubkey"),
            pack.entry(&format!("{stem}.pubkey"))?,
        )?;

        // Step 1: the supplied key must be the publisher the pack claims.
        // Forging a pack for a base image the signer does not publish needs a
        // key whose owner fingerprint collides with the real publisher's.
        let subject = peek_subject(path, bytes)?;
        let publisher = parse_fingerprint(path, "subject.publisher", &subject.publisher)?;
        let key_fingerprint = atakit_cvm_encoding::key_fingerprint(ES256K_TYPE_ID, &key);
        if key_fingerprint != publisher.0 {
            return Err(TrustPackError::Authority {
                message: format!(
                    "{stem}.pubkey has owner fingerprint 0x{}, but {path} claims publisher {}",
                    hex::encode(key_fingerprint),
                    subject.publisher
                ),
            });
        }

        // Step 2: the identifier must derive from that publisher, name, and
        // version.
        let subject_ref = AppRef::new(publisher.0, subject.name.clone(), subject.version.clone());
        let derived = atakit_cvm_encoding::base_image_id(&subject_ref);
        let claimed = parse_fingerprint(path, "subject.id", &subject.id)?;
        if derived != claimed.0 {
            return Err(TrustPackError::Authority {
                message: format!(
                    "{path} declares subject.id {} but publisher, name, and version derive 0x{}",
                    subject.id,
                    hex::encode(derived)
                ),
            });
        }

        // Content selects, filenames address: this entry is chosen by the
        // identifier its own signed bytes derive, never by its stem.
        if derived != selected_base_image_id {
            continue;
        }

        // Step 3: the measurements must actually be signed by that publisher.
        // Without this the pack would merely name a publisher rather than
        // carry their statement.
        let verified = verify_measurement_pack(bytes, signature, std::slice::from_ref(&key))
            .map_err(|error| TrustPackError::Payload {
                path: path.to_string(),
                message: error.to_string(),
            })?;

        if let Some((first, _)) = &selected {
            return Err(TrustPackError::Authority {
                message: format!(
                    "{first} and {path} both describe base image 0x{}; duplicate claims are \
                     fatal, because silently choosing one would make the winner invisible",
                    hex::encode(selected_base_image_id)
                ),
            });
        }
        selected = Some((path.to_string(), verified));
    }

    // Step 4: the selected identifier must be one the workload publisher
    // chose. `ensure_base_image_allowed` already applied the access mode; this
    // reports the more useful failure when a whitelist entry has no pack.
    let Some((path, verified)) = selected else {
        let known: Vec<String> = declared
            .iter()
            .map(|id| format!("0x{}", hex::encode(id.0)))
            .collect();
        return Err(TrustPackError::Authority {
            message: format!(
                "the trust pack carries no measurement pack for base image 0x{}; the workload \
                 spec names {}",
                hex::encode(selected_base_image_id),
                if known.is_empty() {
                    "no base image ids".to_string()
                } else {
                    known.join(", ")
                }
            ),
        });
    };

    Ok(MeasurementPolicy {
        source: format!("trust pack {path}"),
        pack: verified,
    })
}

/// Read `subject` without trusting anything else in the document.
///
/// Deliberately parsed before the signature check: the subject decides which
/// key is even allowed to have signed it, so the order cannot be reversed. The
/// values are used for recomputation only, and every one of them is compared
/// against something derived independently.
fn peek_subject(path: &str, bytes: &[u8]) -> Result<atakit_attestation::Subject, TrustPackError> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        subject: atakit_attestation::Subject,
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|error| TrustPackError::Payload {
            path: path.to_string(),
            message: format!("measurement pack has no readable subject: {error}"),
        })?;
    Ok(envelope.subject)
}

fn parse_public_key(path: &str, bytes: &[u8]) -> Result<Vec<u8>, TrustPackError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| TrustPackError::Payload {
            path: path.to_string(),
            message: format!("not UTF-8: {error}"),
        })?
        .trim();
    let raw = text.strip_prefix("0x").unwrap_or(text);
    let key = hex::decode(raw).map_err(|error| TrustPackError::Payload {
        path: path.to_string(),
        message: format!("not hexadecimal: {error}"),
    })?;
    if key.len() != 65 || key[0] != 0x04 {
        return Err(TrustPackError::Payload {
            path: path.to_string(),
            message: format!(
                "expected a 65-byte uncompressed SEC1 secp256k1 point beginning 0x04, got {} bytes",
                key.len()
            ),
        });
    }
    Ok(key)
}

fn parse_fingerprint(path: &str, field: &str, value: &str) -> Result<B256, TrustPackError> {
    if !atakit_core::is_canonical_id(value) {
        return Err(TrustPackError::Payload {
            path: path.to_string(),
            message: format!(
                "{field} must be '0x' followed by 64 lowercase hexadecimal characters, got \
                 {value:?}"
            ),
        });
    }
    value.parse().map_err(|error| TrustPackError::Payload {
        path: path.to_string(),
        message: format!("{field} {value:?} is not a valid 32-byte value: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::fixture::{
        consistent_measurement_pack, insert_measurement_triple, measurement_pack_json, round_trip,
        workload_builder, workload_spec_json, Publisher,
    };
    use crate::pack::write::TrustPackBuilder;

    const WORKLOAD_NAME: &str = "peer-attestation-demo";
    const WORKLOAD_VERSION: &str = "v1.0.0";

    fn workload_ref(publisher: &Publisher) -> AppRef {
        AppRef::new(publisher.fingerprint(), WORKLOAD_NAME, WORKLOAD_VERSION)
    }

    /// A pack whose contents are all consistent resolves both policies.
    #[test]
    fn a_consistent_pack_resolves_workload_and_measurement_policy() {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let (builder, base_image_id) = workload_builder(
            &workload_publisher,
            &base_publisher,
            WORKLOAD_NAME,
            WORKLOAD_VERSION,
        );
        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher)
            .expect("round trip");

        let inputs =
            workload_trust_inputs(&pack, &workload_ref(&workload_publisher), base_image_id)
                .expect("consistent inputs resolve");

        assert_eq!(
            inputs.workload_policy.workload_id,
            atakit_cvm_encoding::workload_id(&workload_ref(&workload_publisher))
        );
        assert_eq!(inputs.workload_policy.pcr_specs256.len(), 1);
        assert_eq!(inputs.workload_policy.pcr_specs256[0].pcr_index, 23);
        assert_eq!(
            inputs.measurement_policy.pack.subject.id,
            format!("0x{}", hex::encode(base_image_id))
        );
    }

    /// **The attack this kind was blocked on.**
    ///
    /// The workload publisher generates a fresh key, signs a measurement pack
    /// with it, and ships that key in the archive. Every signature verifies and
    /// nothing leaves the namespace. It must still be refused, because the key
    /// does not hash to the publisher the pack claims — which is the check that
    /// replaced `payload/measurement-publisher-pubkey.pem`.
    #[test]
    fn a_fabricated_measurement_pack_signed_with_a_fresh_key_is_refused() {
        let workload_publisher = Publisher::new(0x31);
        let real_base_publisher = Publisher::new(0x32);
        let impostor = Publisher::new(0x33);

        // The identity the workload spec names, and which the verifier expects.
        let (_, real_base_image_id) =
            consistent_measurement_pack(&real_base_publisher, "automata-linux", "v0.2.8-debug");

        // A pack claiming the real publisher's identity, signed by a key the
        // workload publisher just made up and shipped alongside.
        let fabricated = measurement_pack_json(
            &real_base_publisher.fingerprint_hex(),
            "automata-linux",
            "v0.2.8-debug",
            &format!("0x{}", hex::encode(real_base_image_id)),
        );

        let mut builder = TrustPackBuilder::new(
            TrustPackKind::WorkloadTrust,
            "example-workload-publisher",
            1,
            crate::pack::fixture::NOT_BEFORE,
            crate::pack::fixture::NOT_AFTER,
        );
        builder
            .insert(
                "payload/workload-spec.json",
                workload_spec_json(
                    &workload_publisher,
                    WORKLOAD_NAME,
                    WORKLOAD_VERSION,
                    &[real_base_image_id],
                ),
            )
            .unwrap();
        insert_measurement_triple(&mut builder, "automata-linux", &fabricated, &impostor);

        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher)
            .expect("the archive itself is well formed and correctly signed");

        let error = workload_trust_inputs(
            &pack,
            &workload_ref(&workload_publisher),
            real_base_image_id,
        )
        .expect_err("a fabricated measurement pack must be refused");
        let message = error.to_string();
        assert!(
            message.contains("owner fingerprint"),
            "the failure must be the fingerprint recomputation, not something incidental; got \
             {message}"
        );
    }

    /// A pack whose declared `subject.id` does not derive from its own
    /// publisher, name, and version is refused before any measurement is read.
    #[test]
    fn a_subject_id_that_does_not_derive_is_refused() {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let (_, real_id) =
            consistent_measurement_pack(&base_publisher, "automata-linux", "v0.2.8-debug");

        // Correct publisher and key, but an id claiming to be another image.
        let inconsistent = measurement_pack_json(
            &base_publisher.fingerprint_hex(),
            "automata-linux",
            "v0.2.8-debug",
            &format!("0x{}", hex::encode([0xcd; 32])),
        );

        let mut builder = TrustPackBuilder::new(
            TrustPackKind::WorkloadTrust,
            "example-workload-publisher",
            1,
            crate::pack::fixture::NOT_BEFORE,
            crate::pack::fixture::NOT_AFTER,
        );
        builder
            .insert(
                "payload/workload-spec.json",
                workload_spec_json(
                    &workload_publisher,
                    WORKLOAD_NAME,
                    WORKLOAD_VERSION,
                    &[real_id],
                ),
            )
            .unwrap();
        insert_measurement_triple(
            &mut builder,
            "automata-linux",
            &inconsistent,
            &base_publisher,
        );

        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher).unwrap();
        let error = workload_trust_inputs(&pack, &workload_ref(&workload_publisher), real_id)
            .expect_err("a non-deriving subject.id must be refused");
        assert!(error.to_string().contains("derive"), "got {error}");
    }

    /// The measurements must be signed by the publisher, not merely attributed
    /// to them. A correct key with a signature over other bytes fails.
    #[test]
    fn a_measurement_pack_with_a_broken_signature_is_refused() {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let (pack_json, base_image_id) =
            consistent_measurement_pack(&base_publisher, "automata-linux", "v0.2.8-debug");

        let mut builder = TrustPackBuilder::new(
            TrustPackKind::WorkloadTrust,
            "example-workload-publisher",
            1,
            crate::pack::fixture::NOT_BEFORE,
            crate::pack::fixture::NOT_AFTER,
        );
        builder
            .insert(
                "payload/workload-spec.json",
                workload_spec_json(
                    &workload_publisher,
                    WORKLOAD_NAME,
                    WORKLOAD_VERSION,
                    &[base_image_id],
                ),
            )
            .unwrap();
        builder
            .insert(
                "payload/measurement-packs/automata-linux.json",
                pack_json.clone(),
            )
            .unwrap();
        builder
            .insert(
                "payload/measurement-packs/automata-linux.sig",
                base_publisher.sign(b"different bytes"),
            )
            .unwrap();
        builder
            .insert(
                "payload/measurement-packs/automata-linux.pubkey",
                base_publisher.public_key_hex().into_bytes(),
            )
            .unwrap();

        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher).unwrap();
        let error = workload_trust_inputs(&pack, &workload_ref(&workload_publisher), base_image_id)
            .expect_err("a signature over other bytes must be refused");
        assert!(
            matches!(error, TrustPackError::Payload { .. }),
            "got {error}"
        );
    }

    /// A pack signed by publisher A must not answer for publisher B's
    /// workload, even though the archive itself is valid and A's key is the
    /// configured one.
    #[test]
    fn a_pack_may_not_speak_for_a_publisher_it_was_not_signed_with() {
        let signer = Publisher::new(0x31);
        let other_publisher = Publisher::new(0x41);
        let base_publisher = Publisher::new(0x32);

        let (_, base_image_id) =
            consistent_measurement_pack(&base_publisher, "automata-linux", "v0.2.8-debug");
        let (mut builder, _) = workload_builder(
            &other_publisher,
            &base_publisher,
            WORKLOAD_NAME,
            WORKLOAD_VERSION,
        );
        // The spec names `other_publisher`, but `signer` signs the archive and
        // is the key the verifier is configured with.
        builder
            .insert(
                "payload/workload-spec.json",
                workload_spec_json(
                    &other_publisher,
                    WORKLOAD_NAME,
                    WORKLOAD_VERSION,
                    &[base_image_id],
                ),
            )
            .unwrap();

        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &signer)
            .expect("the archive verifies under the configured key");
        let error = workload_trust_inputs(&pack, &workload_ref(&other_publisher), base_image_id)
            .expect_err("the signing key must be the publisher the spec names");
        assert!(
            error.to_string().contains("may not speak for a publisher"),
            "got {error}"
        );
    }

    /// A pack answers for the workload the caller asked about, and no other.
    #[test]
    fn a_pack_for_another_workload_is_refused() {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let (builder, base_image_id) = workload_builder(
            &workload_publisher,
            &base_publisher,
            WORKLOAD_NAME,
            WORKLOAD_VERSION,
        );
        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher).unwrap();

        let requested = AppRef::new(workload_publisher.fingerprint(), WORKLOAD_NAME, "v2.0.0");
        let error = workload_trust_inputs(&pack, &requested, base_image_id)
            .expect_err("a pack for another version must be refused");
        assert!(error.to_string().contains("workload id"), "got {error}");
    }

    /// The access mode is evaluated through the same implementation the chain
    /// path uses, so a base image outside the whitelist is refused.
    #[test]
    fn a_base_image_outside_the_whitelist_is_refused() {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let (builder, _) = workload_builder(
            &workload_publisher,
            &base_publisher,
            WORKLOAD_NAME,
            WORKLOAD_VERSION,
        );
        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher).unwrap();

        let error = workload_trust_inputs(&pack, &workload_ref(&workload_publisher), [0x99; 32])
            .expect_err("an unlisted base image must be refused");
        assert!(error.to_string().contains("not allowed"), "got {error}");
    }

    /// Content selects, filenames address: a measurement pack stored under a
    /// misleading stem is still selected by the identifier its signed bytes
    /// derive.
    #[test]
    fn selection_follows_signed_content_rather_than_the_filename() {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let (pack_json, base_image_id) =
            consistent_measurement_pack(&base_publisher, "automata-linux", "v0.2.8-debug");

        let mut builder = TrustPackBuilder::new(
            TrustPackKind::WorkloadTrust,
            "example-workload-publisher",
            1,
            crate::pack::fixture::NOT_BEFORE,
            crate::pack::fixture::NOT_AFTER,
        );
        builder
            .insert(
                "payload/workload-spec.json",
                workload_spec_json(
                    &workload_publisher,
                    WORKLOAD_NAME,
                    WORKLOAD_VERSION,
                    &[base_image_id],
                ),
            )
            .unwrap();
        // Deliberately misleading stem.
        insert_measurement_triple(
            &mut builder,
            "some-other-image",
            &pack_json,
            &base_publisher,
        );

        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher).unwrap();
        let inputs =
            workload_trust_inputs(&pack, &workload_ref(&workload_publisher), base_image_id)
                .expect("the entry is selected by its content, not its name");
        assert_eq!(
            inputs.measurement_policy.pack.subject.id,
            format!("0x{}", hex::encode(base_image_id))
        );
    }

    /// A whitelisted base image with no measurement pack fails closed naming
    /// the missing image, rather than verifying with no measurement policy.
    #[test]
    fn a_selected_base_image_with_no_measurement_pack_fails_closed() {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let other_base = Publisher::new(0x42);
        let (_, absent_id) =
            consistent_measurement_pack(&other_base, "automata-linux", "v0.2.9-debug");

        let (mut builder, present_id) = workload_builder(
            &workload_publisher,
            &base_publisher,
            WORKLOAD_NAME,
            WORKLOAD_VERSION,
        );
        builder
            .insert(
                "payload/workload-spec.json",
                workload_spec_json(
                    &workload_publisher,
                    WORKLOAD_NAME,
                    WORKLOAD_VERSION,
                    &[present_id, absent_id],
                ),
            )
            .unwrap();

        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher).unwrap();
        let error = workload_trust_inputs(&pack, &workload_ref(&workload_publisher), absent_id)
            .expect_err("a whitelisted image with no pack must fail closed");
        let message = error.to_string();
        assert!(
            message.contains(&hex::encode(absent_id)),
            "the failure must name the missing base image; got {message}"
        );
    }

    /// A `.pubkey` that is not an uncompressed SEC1 point is refused with a
    /// message about the key rather than a downstream signature failure.
    #[test]
    fn a_malformed_public_key_entry_is_refused() {
        let workload_publisher = Publisher::new(0x31);
        let base_publisher = Publisher::new(0x32);
        let (pack_json, base_image_id) =
            consistent_measurement_pack(&base_publisher, "automata-linux", "v0.2.8-debug");

        let mut builder = TrustPackBuilder::new(
            TrustPackKind::WorkloadTrust,
            "example-workload-publisher",
            1,
            crate::pack::fixture::NOT_BEFORE,
            crate::pack::fixture::NOT_AFTER,
        );
        builder
            .insert(
                "payload/workload-spec.json",
                workload_spec_json(
                    &workload_publisher,
                    WORKLOAD_NAME,
                    WORKLOAD_VERSION,
                    &[base_image_id],
                ),
            )
            .unwrap();
        builder
            .insert("payload/measurement-packs/x.json", pack_json.clone())
            .unwrap();
        builder
            .insert(
                "payload/measurement-packs/x.sig",
                base_publisher.sign(&pack_json),
            )
            .unwrap();
        builder
            .insert("payload/measurement-packs/x.pubkey", b"0xdeadbeef".to_vec())
            .unwrap();

        let pack = round_trip(&builder, TrustPackKind::WorkloadTrust, &workload_publisher).unwrap();
        let error = workload_trust_inputs(&pack, &workload_ref(&workload_publisher), base_image_id)
            .expect_err("a malformed public key must be refused");
        assert!(
            error.to_string().contains("SEC1"),
            "the failure must name the key format; got {error}"
        );
    }
}
