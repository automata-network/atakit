//! Shared material for the trust-pack tests.
//!
//! Everything here is generated rather than committed, so a test asserts what
//! the code produces rather than what a fixture author believed it produced.
//! The two are different exactly where a format bug lives.

use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature, SigningKey};
use rcgen::{
    date_time_ymd, CertificateParams, CertificateRevocationListParams, DistinguishedName, DnType,
    KeyIdMethod, KeyPair, SerialNumber,
};

use crate::pack::read::{read_trust_pack, TrustPack, TrustPackReadOptions};
use crate::pack::write::TrustPackBuilder;
use crate::pack::{TrustPackError, TrustPackKind};

/// ECDSA secp256k1, matching `ALGO_ID_ES256K`.
pub const ES256K_TYPE_ID: u8 = 3;

/// A publisher: its signing key and the uncompressed SEC1 point a verifier is
/// configured with.
pub struct Publisher {
    pub signing_key: SigningKey,
    pub public_key: Vec<u8>,
}

impl Publisher {
    /// Deterministic per `seed`, so one test can hold two distinct publishers
    /// and name which is which.
    pub fn new(seed: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&[seed; 32].into()).expect("es256k signing key");
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self {
            signing_key,
            public_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// The owner fingerprint the registries derive from this key.
    pub fn fingerprint(&self) -> [u8; 32] {
        atakit_cvm_encoding::key_fingerprint(ES256K_TYPE_ID, &self.public_key)
    }

    pub fn fingerprint_hex(&self) -> String {
        format!("0x{}", hex::encode(self.fingerprint()))
    }

    pub fn public_key_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.public_key))
    }
}

/// Inside the window every fixture builds.
pub const NOW: u64 = 1_786_000_000;
pub const NOT_BEFORE: u64 = 1_785_000_000;
pub const NOT_AFTER: u64 = 1_790_000_000;

pub fn options(kind: TrustPackKind, publisher: &Publisher) -> TrustPackReadOptions {
    TrustPackReadOptions::new(kind, publisher.public_key.clone(), NOW)
}

/// Build an archive and read it straight back under the same publisher.
pub fn round_trip(
    builder: &TrustPackBuilder,
    kind: TrustPackKind,
    publisher: &Publisher,
) -> Result<TrustPack, TrustPackError> {
    let archive = builder
        .build(|bytes| Ok::<_, std::convert::Infallible>(publisher.sign(bytes)))
        .expect("build archive");
    read_trust_pack(&archive, &options(kind, publisher))
}

/// A `collateral-trust` builder carrying one root and the AWS document limits.
pub fn collateral_builder(publisher_label: &str) -> TrustPackBuilder {
    let mut builder = TrustPackBuilder::new(
        TrustPackKind::CollateralTrust,
        publisher_label,
        7,
        NOT_BEFORE,
        NOT_AFTER,
    );
    builder
        .insert("payload/roots/gcp-ak-root.pem", certificate_pem("gcp-ak"))
        .expect("root entry");
    builder
        .insert(
            "payload/aws-document-limits.json",
            br#"{"maximum_age_seconds":300,"allowed_future_clock_difference_seconds":60}"#.to_vec(),
        )
        .expect("aws limits entry");
    builder
}

/// A self-signed certificate in PEM, with a validity window that outlives
/// [`NOT_AFTER`] so it does not silently shorten a pack under test.
pub fn certificate_pem(common_name: &str) -> Vec<u8> {
    certificate_pem_expiring(common_name, 2100, 1, 1)
}

/// 2026-09-01T00:00:00Z: after [`NOW`] so a pack carrying it is still valid,
/// and before [`NOT_AFTER`] so it shortens the requested window.
pub const EARLY_EXPIRY: u64 = 1_788_220_800;

pub fn certificate_pem_expiring(common_name: &str, year: i32, month: u8, day: u8) -> Vec<u8> {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name);
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("certificate parameters");
    params.distinguished_name = distinguished_name;
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(year, month, day);
    let key_pair = KeyPair::generate().expect("certificate key");
    params
        .self_signed(&key_pair)
        .expect("self-signed certificate")
        .pem()
        .into_bytes()
}

/// A DER certificate revocation list whose `nextUpdate` outlives
/// [`NOT_AFTER`], so carrying one does not silently shorten a pack under test.
pub fn crl_der() -> Vec<u8> {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "AMD SEV-SNP issuer");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("certificate parameters");
    params.distinguished_name = distinguished_name;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let key_pair = KeyPair::generate().expect("issuer key");
    let issuer = params.self_signed(&key_pair).expect("issuer certificate");
    CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 1, 1),
        next_update: date_time_ymd(2027, 1, 1),
        crl_number: SerialNumber::from(1),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer, &key_pair)
    .expect("certificate revocation list")
    .der()
    .to_vec()
}

/// Write the header's name field directly, bypassing every rule
/// `tar::Builder` enforces.
///
/// The negative tests need archives a conforming producer cannot make.
/// `tar::Builder` refuses to *write* an absolute or traversing path, which is
/// exactly why a reader cannot rely on it: a hostile producer does not use
/// this crate. Patching the name bytes and recomputing the checksum produces
/// the archive such a producer would emit, so the reader's own path rules are
/// what gets exercised.
pub fn header_with_raw_path(path: &str, size: usize, entry_type: tar::EntryType) -> tar::Header {
    let mut header = tar::Header::new_old();
    header.set_size(size as u64);
    header.set_mode(0o644);
    header.set_entry_type(entry_type);
    let name = &mut header.as_old_mut().name;
    name.fill(0);
    let bytes = path.as_bytes();
    assert!(bytes.len() <= name.len(), "test path is too long for tar");
    name[..bytes.len()].copy_from_slice(bytes);
    header.set_cksum();
    header
}

pub fn raw_archive(entries: &[(String, Vec<u8>, tar::EntryType)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes, entry_type) in entries {
        let mut header = header_with_raw_path(path, bytes.len(), *entry_type);
        if matches!(entry_type, tar::EntryType::Symlink | tar::EntryType::Link) {
            header
                .set_link_name("trust-pack.json")
                .expect("link target");
            header.set_cksum();
        }
        builder.append(&header, bytes.as_slice()).expect("append");
    }
    let tar = builder.into_inner().expect("finish tar");
    zstd::stream::encode_all(tar.as_slice(), 3).expect("compress")
}

/// Sign an index over an arbitrary payload map, bypassing the builder's
/// content validation. Used where a test needs the *reader* to reject
/// something the writer would have caught first.
pub fn unchecked_archive(
    kind: TrustPackKind,
    publisher: &Publisher,
    payload: &[(&str, Vec<u8>)],
) -> Vec<u8> {
    use std::collections::BTreeMap;

    let hashes: BTreeMap<String, String> = payload
        .iter()
        .map(|(path, bytes)| ((*path).to_string(), crate::pack::write::sha256_hex(bytes)))
        .collect();
    let index = crate::pack::TrustPackIndex {
        format: crate::pack::TRUST_PACK_FORMAT,
        kind: kind.as_str().to_string(),
        issuer: "example-publisher".to_string(),
        revision: 1,
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        hashes,
    };
    let index_bytes = serde_json_canonicalizer::to_vec(&index).expect("canonical index");
    let mut entries = vec![
        (
            "trust-pack.json".to_string(),
            index_bytes.clone(),
            tar::EntryType::Regular,
        ),
        (
            "trust-pack.sig".to_string(),
            publisher.sign(&index_bytes),
            tar::EntryType::Regular,
        ),
    ];
    entries.extend(
        payload
            .iter()
            .map(|(path, bytes)| ((*path).to_string(), bytes.clone(), tar::EntryType::Regular)),
    );
    raw_archive(&entries)
}

/// A base-image measurement pack, version 4, as canonical JSON.
///
/// `publisher` and `id` are supplied rather than derived so a test can produce
/// the inconsistent packs the authority checks exist to catch.
pub fn measurement_pack_json(publisher: &str, name: &str, version: &str, id: &str) -> Vec<u8> {
    let value = serde_json::json!({
        "schema": "atakit.base_image_measurement_pack.v4",
        "revision": 1,
        "published_at": 1_786_000_000u64,
        "subject": {
            "publisher": publisher,
            "name": name,
            "version": version,
            "id": id,
        },
        "measurements": { "profiles": [] },
    });
    serde_json_canonicalizer::to_vec(&value).expect("canonical measurement pack")
}

/// A consistent measurement pack for `publisher`: the id is what the publisher,
/// name, and version actually derive.
pub fn consistent_measurement_pack(
    publisher: &Publisher,
    name: &str,
    version: &str,
) -> (Vec<u8>, [u8; 32]) {
    let app_ref = atakit_cvm_types::AppRef::new(publisher.fingerprint(), name, version);
    let id = atakit_cvm_encoding::base_image_id(&app_ref);
    let json = measurement_pack_json(
        &publisher.fingerprint_hex(),
        name,
        version,
        &format!("0x{}", hex::encode(id)),
    );
    (json, id)
}

/// `payload/workload-spec.json` naming one whitelisted base image.
pub fn workload_spec_json(
    workload_publisher: &Publisher,
    name: &str,
    version: &str,
    base_image_ids: &[[u8; 32]],
) -> Vec<u8> {
    let ids: Vec<String> = base_image_ids
        .iter()
        .map(|id| format!("0x{}", hex::encode(id)))
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "publisher": workload_publisher.fingerprint_hex(),
        "name": name,
        "version": version,
        "base_image_mode": "whitelist",
        "base_image_ids": ids,
        "requirements": [],
        "workload_pcrs256": [
            { "pcr_index": 23, "comparison": "0x00" }
        ],
        "workload_pcrs384": [],
    }))
    .expect("workload spec")
}

/// A complete `workload-trust` builder: one workload spec and one consistent,
/// correctly signed base-image measurement pack triple.
///
/// Returns the builder and the base-image id the pack describes.
pub fn workload_builder(
    workload_publisher: &Publisher,
    base_image_publisher: &Publisher,
    workload_name: &str,
    workload_version: &str,
) -> (TrustPackBuilder, [u8; 32]) {
    let (pack_json, base_image_id) =
        consistent_measurement_pack(base_image_publisher, "automata-linux", "v0.2.8-debug");
    let mut builder = TrustPackBuilder::new(
        TrustPackKind::WorkloadTrust,
        "example-workload-publisher",
        1,
        NOT_BEFORE,
        NOT_AFTER,
    );
    builder
        .insert(
            "payload/workload-spec.json",
            workload_spec_json(
                workload_publisher,
                workload_name,
                workload_version,
                &[base_image_id],
            ),
        )
        .expect("workload spec entry");
    insert_measurement_triple(
        &mut builder,
        "automata-linux",
        &pack_json,
        base_image_publisher,
    );
    (builder, base_image_id)
}

/// Insert a `<stem>.json`, `<stem>.sig`, `<stem>.pubkey` triple.
pub fn insert_measurement_triple(
    builder: &mut TrustPackBuilder,
    stem: &str,
    pack_json: &[u8],
    signer: &Publisher,
) {
    builder
        .insert(
            format!("payload/measurement-packs/{stem}.json"),
            pack_json.to_vec(),
        )
        .expect("measurement pack entry");
    builder
        .insert(
            format!("payload/measurement-packs/{stem}.sig"),
            signer.sign(pack_json),
        )
        .expect("measurement pack signature");
    builder
        .insert(
            format!("payload/measurement-packs/{stem}.pubkey"),
            signer.public_key_hex().into_bytes(),
        )
        .expect("measurement pack public key");
}

/// An `atakit.intel-tdx-dcap-collateral` version 1 document.
///
/// Only the fields the writer reads to derive an expiry carry real values; the
/// collateral bodies stay empty because a reader cannot parse one without the
/// quote it is selected for, so nothing else in this crate looks at them until
/// a verification supplies that quote. `nextUpdate` is far future so carrying
/// one does not shorten a pack under test.
pub fn tdx_dcap_document() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": "atakit.intel-tdx-dcap-collateral",
        "version": 1,
        "selector": {
            "fmspc": "00806f050000",
            "pceId": "0000",
            "pckCa": "platform",
            "tcbEvaluationDataNumber": 17,
            "qeIdentityEvaluationDataNumber": 17,
        },
        "payload": {
            "rootCaCrlDer": "",
            "pckCrlDer": "",
            "issuerChainDer": [],
            "tcbInfoSignedJson": r#"{"tcbInfo":{"nextUpdate":"2027-01-01T00:00:00Z"}}"#,
            "qeIdentitySignedJson":
                r#"{"enclaveIdentity":{"nextUpdate":"2027-02-01T00:00:00Z"}}"#,
        },
    }))
    .expect("collateral document")
}

/// The reviewed AMD SEV-SNP security policy document form, one policy.
pub fn amd_snp_policy_document(cpuid: &str) -> Vec<u8> {
    format!(
        r#"{{
  "schema": "atakit.amd-sev-snp-security-policy",
  "version": 1,
  "policies": [
    {{
      "cpuid": "{cpuid}",
      "minimumTcb": "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
      "platformInfoPolicy": "0x0000000000000000000000000000000000000000000000000000000000000020",
      "requiredLaunchMitigationVector": "0x0000000000000000",
      "requiredCurrentMitigationVector": "0x0000000000000000"
    }}
  ]
}}"#
    )
    .into_bytes()
}
