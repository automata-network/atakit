//! Current evidence framing with synthetic hardware and real software signatures.
use crate::abi::SessionRegistry::{
    AkPubCollateral, AttestationEvidence, ResolvedPcrPolicy, TeeReport, TpmReport,
};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use anyhow::{Context, Result};
use atakit_attestation::evidence_abi::{
    encode_session_key_authorization, tpm_certify_evidence, AkPubCollateralType, TEEType,
    TpmReportType, VerificationBackendType,
};
use atakit_attestation::signing::{
    derive_public_key_uncompressed, generate_secret_key_bytes, sign_secp256k1_recoverable,
    SigEncoding,
};
use atakit_attestation::PcrBankSelection;
use automata_tee_workload_measurement::stubs::AlgoId;
use automata_tee_workload_measurement::stubs::TpmQuoteEvidence;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha256, Sha384};

pub struct SyntheticEvidence {
    pub evidence: AttestationEvidence,
    pub session_id: B256,
    pub tpm_secret: [u8; 32],
    pub tee_hash: B256,
}

pub fn build(
    chain_id: u64,
    registry: Address,
    owner_fp: B256,
    nonce: U256,
    policy: &ResolvedPcrPolicy,
    session_secret: &[u8; 32],
) -> Result<SyntheticEvidence> {
    build_with_quote(
        chain_id,
        registry,
        owner_fp,
        nonce,
        policy,
        session_secret,
        None,
        false,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn build_with_quote(
    chain_id: u64,
    registry: Address,
    owner_fp: B256,
    nonce: U256,
    policy: &ResolvedPcrPolicy,
    session_secret: &[u8; 32],
    retained_quote: Option<&[u8]>,
    rotation: bool,
) -> Result<SyntheticEvidence> {
    let tpm_secret = generate_secret_key_bytes();
    let tpm = SigningKey::from_slice(&tpm_secret)?;
    let tpm_pub = tpm.verifying_key().to_encoded_point(false);
    let uuid = generate_secret_key_bytes();
    let mut binding = [0u8; 32];
    binding[16..].copy_from_slice(&uuid[..16]);

    let mut quote = vec![0; 636];
    quote[..2].copy_from_slice(&4u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x81u32.to_le_bytes());
    quote[48 + 123] = 0x10;
    quote[48 + 520..48 + 536].copy_from_slice(&uuid[..16]);
    let rtmr = Sha384::digest([vec![0; 48], vec![0; 32], uuid[..16].to_vec()].concat());
    quote[48 + 472..48 + 520].copy_from_slice(&rtmr);
    if let Some(retained) = retained_quote {
        anyhow::ensure!(retained.len() == 636, "invalid retained emulator TDX quote");
        quote = retained.to_vec();
        binding[16..].copy_from_slice(&quote[48 + 520..48 + 536]);
    }
    anyhow::ensure!(
        policy.pcrBankSelection != PcrBankSelection::Sha384 as u8,
        "GCP/TDX emulation requires the SHA256 bank for provider binding"
    );
    let mut blocks = [
        policy.invariantPcrPolicy.clone(),
        policy.variantPcrPolicy.clone(),
        policy.workloadPcrPolicy.clone(),
    ];
    if policy.pcrBankSelection == PcrBankSelection::Sha256 as u8 {
        for block in &mut blocks {
            block.pcrSpecs384.clear();
        }
    }
    let (mut pcr256, pcr384) =
        crate::pcr::synthesize(&[&blocks[0], &blocks[1], &blocks[2]], binding)?;
    // This Registry revision verifies the named policy only during rotateKey.
    if rotation
        && ![
            &policy.invariantPcrPolicy,
            &policy.variantPcrPolicy,
            &policy.workloadPcrPolicy,
        ]
        .iter()
        .any(|p| p.pcrSpecs256.iter().any(|s| s.pcrIndex == 15))
    {
        pcr256.retain(|p| p.pcrIndex != 15);
    }
    let tee_hash = keccak256(&quote);
    let qualifying = B256::from(atakit_attestation::compute_session_qualifying_data(
        chain_id,
        registry.into(),
        owner_fp.0,
        nonce.to_be_bytes(),
    ));
    let mut attest = attest_header(0x8018, qualifying.as_slice());
    let banks = 1 + usize::from(!pcr384.is_empty());
    attest.extend_from_slice(&(banks as u32).to_be_bytes());
    let mut digest_input = vec![];
    selection(&mut attest, 0x000b, pcr256.iter().map(|p| p.pcrIndex));
    for p in &pcr256 {
        digest_input.extend_from_slice(p.value.as_slice());
    }
    if !pcr384.is_empty() {
        selection(&mut attest, 0x000c, pcr384.iter().map(|p| p.pcrIndex));
        for p in &pcr384 {
            digest_input.extend_from_slice(p.value.first.as_slice());
            digest_input.extend_from_slice(p.value.second.as_slice());
        }
    }
    sized(&mut attest, &Sha256::digest(&digest_input));
    let tpm_signature = fake_hardware_signature();
    let session_id = B256::from(atakit_attestation::compute_session_id(
        keccak256(&tpm_signature).0,
        tee_hash.0,
    ));
    let mut public = hex::decode("0023000b0004007200000010001000030010")?;
    sized(&mut public, &tpm_pub.as_bytes()[1..33]);
    sized(&mut public, &tpm_pub.as_bytes()[33..65]);
    let mut certify = attest_header(0x8017, &[0; 32]);
    sized(
        &mut certify,
        &[vec![0, 11], Sha256::digest(&public).to_vec()].concat(),
    );
    sized(&mut certify, &[]);
    let session_pub = derive_public_key_uncompressed(session_secret)?;
    let session_fp = B256::from(atakit_cvm_encoding::key_fingerprint(
        AlgoId::Es256K as u8,
        &session_pub,
    ));
    let delegation = B256::from(atakit_attestation::delegation_digest(
        chain_id,
        registry.into(),
        policy.baseImageId.0,
        policy.workloadId.0,
        session_id.0,
        session_fp.0,
    ));
    let sig: Signature = tpm.sign_prehash(delegation.as_slice())?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let possession =
        sign_secp256k1_recoverable(session_secret, delegation.0, SigEncoding::EthereumLegacyV)?;
    let cert_hex: Vec<String> = serde_json::from_str(include_str!("../assets/gcp-ak-certs.json"))?;
    let certs = cert_hex
        .iter()
        .map(|s| hex::decode(s.trim_start_matches("0x")))
        .collect::<Result<Vec<_>, _>>()?;
    let ak = hex::decode(include_str!("../assets/gcp-ak-pub.hex").trim())
        .context("invalid packaged AK public key")?;
    let evidence = AttestationEvidence {
        teeReport: TeeReport {
            verificationBackendType: VerificationBackendType::Solidity as u8,
            teeType: TEEType::IntelTDX as u8,
            data: quote.into(),
        },
        akPub: public_identity(AlgoId::Es256, ak),
        tpmQuoteReport: TpmReport {
            verificationBackendType: VerificationBackendType::Solidity as u8,
            tpmReportType: TpmReportType::TpmQuote as u8,
            data: TpmQuoteEvidence {
                tpmsAttest: attest.into(),
                tpmSignature: tpm_signature.into(),
                pcr0StartupLocality: 0xff,
                pcrValues256: pcr256,
                pcrValues384: pcr384,
            }
            .abi_encode()
            .into(),
        },
        tpmCertifyReport: TpmReport {
            verificationBackendType: VerificationBackendType::Solidity as u8,
            tpmReportType: TpmReportType::TpmCertify as u8,
            // The measurement crate does not export the inner certify evidence type.
            data: tpm_certify_evidence(certify, fake_hardware_signature(), public)
                .abi_encode()
                .into(),
        },
        akPubCollateral: AkPubCollateral {
            akPubCollateralType: AkPubCollateralType::GcpCertChain as u8,
            verificationBackendType: VerificationBackendType::Solidity as u8,
            data: atakit_attestation::evidence_abi::encode_gcp_cert_chain_data(&certs).into(),
        },
        sessionKeySignature: encode_session_key_authorization(sig.to_der().as_bytes(), &possession)
            .into(),
        sessionKey: public_identity(AlgoId::Es256K, session_pub.to_vec()),
    };
    Ok(SyntheticEvidence {
        evidence,
        session_id,
        tpm_secret,
        tee_hash,
    })
}
fn sized(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn attest_header(kind: u16, extra: &[u8]) -> Vec<u8> {
    let mut out = 0xff544347u32.to_be_bytes().to_vec();
    out.extend_from_slice(&kind.to_be_bytes());
    sized(&mut out, &[]);
    sized(&mut out, extra);
    out.extend_from_slice(&[0; 16]);
    out.push(1);
    out.extend_from_slice(&[0; 8]);
    out
}
fn selection(out: &mut Vec<u8>, algo: u16, indices: impl Iterator<Item = u8>) {
    out.extend_from_slice(&algo.to_be_bytes());
    out.push(3);
    let mut bitmap = [0; 3];
    for i in indices {
        bitmap[(i / 8) as usize] |= 1 << (i % 8);
    }
    out.extend_from_slice(&bitmap);
}
fn fake_hardware_signature() -> Vec<u8> {
    let mut out = vec![0, 24, 0, 11];
    sized(&mut out, &generate_secret_key_bytes());
    sized(&mut out, &generate_secret_key_bytes());
    out
}

pub(crate) fn public_identity(
    algo: AlgoId,
    key: Vec<u8>,
) -> crate::abi::SessionRegistry::PublicIdentity {
    crate::abi::SessionRegistry::PublicIdentity {
        typeId: algo as u8,
        key: key.into(),
    }
}
