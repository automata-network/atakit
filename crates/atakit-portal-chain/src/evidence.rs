//! Exact ABI builders for the replacement attestation evidence.

use alloy_primitives::{Bytes, B256};
use alloy_sol_types::SolValue;

use crate::{
    AkPubCollateral, AkPubCollateralType, AmdSevSnpZkEvidence, Bytes48, IntelTdxDcapZkEvidence,
    PcrValue256, PcrValue384, ProgramBoundZkProof, PublicIdentity, TeeReport, TpmCertifyEvidence,
    TpmQuoteEvidence, TpmReport, TpmReportType, VerificationBackendType,
};

pub fn fixed_bytes48(value: [u8; 48]) -> Bytes48 {
    let mut first = [0u8; 32];
    let mut second = [0u8; 16];
    first.copy_from_slice(&value[..32]);
    second.copy_from_slice(&value[32..]);
    Bytes48 {
        first: first.into(),
        second: second.into(),
    }
}

pub fn tpm_quote_evidence(
    tpms_attest: Vec<u8>,
    tpm_signature: Vec<u8>,
    pcr0_startup_locality: u8,
    pcr_values256: Vec<PcrValue256>,
    pcr_values384: Vec<PcrValue384>,
) -> TpmQuoteEvidence {
    TpmQuoteEvidence {
        tpmsAttest: tpms_attest.into(),
        tpmSignature: tpm_signature.into(),
        pcr0StartupLocality: pcr0_startup_locality,
        pcrValues256: pcr_values256,
        pcrValues384: pcr_values384,
    }
}

pub fn tpm_certify_evidence(
    tpms_attest: Vec<u8>,
    tpm_signature: Vec<u8>,
    tpmt_public: Vec<u8>,
) -> TpmCertifyEvidence {
    TpmCertifyEvidence {
        tpmsAttest: tpms_attest.into(),
        tpmSignature: tpm_signature.into(),
        tpmtPublic: tpmt_public.into(),
    }
}

pub fn encode_tpm_quote_evidence_data(evidence: &TpmQuoteEvidence) -> Vec<u8> {
    evidence.abi_encode()
}

pub fn encode_tpm_certify_evidence_data(evidence: &TpmCertifyEvidence) -> Vec<u8> {
    evidence.abi_encode()
}

pub fn wrap_tpm_quote_solidity(evidence: &TpmQuoteEvidence) -> TpmReport {
    TpmReport {
        verificationBackendType: VerificationBackendType::Solidity,
        tpmReportType: TpmReportType::TpmQuote,
        data: encode_tpm_quote_evidence_data(evidence).into(),
    }
}

pub fn wrap_tpm_quote_zk(proof: &ProgramBoundZkProof) -> TpmReport {
    TpmReport {
        verificationBackendType: VerificationBackendType::ZkSuccinct,
        tpmReportType: TpmReportType::TpmQuote,
        data: proof.abi_encode().into(),
    }
}

pub fn wrap_tpm_certify(evidence: &TpmCertifyEvidence) -> TpmReport {
    TpmReport {
        verificationBackendType: VerificationBackendType::Solidity,
        tpmReportType: TpmReportType::TpmCertify,
        data: encode_tpm_certify_evidence_data(evidence).into(),
    }
}

pub fn tee_report(tee_type: crate::TEEType, raw_attestation_bytes: Vec<u8>) -> TeeReport {
    TeeReport {
        verificationBackendType: VerificationBackendType::Solidity,
        teeType: tee_type,
        data: raw_attestation_bytes.into(),
    }
}

pub fn program_bound_zk_proof(
    program_identifier: B256,
    output: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> ProgramBoundZkProof {
    ProgramBoundZkProof {
        programIdentifier: program_identifier,
        output: output.into(),
        proofBytes: proof_bytes.into(),
    }
}

pub fn tee_report_tdx_zk(
    backend: VerificationBackendType,
    proof: ProgramBoundZkProof,
    quote_body: Vec<u8>,
) -> TeeReport {
    let evidence = IntelTdxDcapZkEvidence {
        proof,
        quoteBody: quote_body.into(),
    };
    TeeReport {
        verificationBackendType: backend,
        teeType: crate::TEEType::IntelTDX,
        data: evidence.abi_encode().into(),
    }
}

pub fn tee_report_snp_zk(
    backend: VerificationBackendType,
    proof: ProgramBoundZkProof,
    raw_report: Vec<u8>,
) -> TeeReport {
    let evidence = AmdSevSnpZkEvidence {
        proof,
        rawReport: raw_report.into(),
    };
    TeeReport {
        verificationBackendType: backend,
        teeType: crate::TEEType::AmdSevSnp,
        data: evidence.abi_encode().into(),
    }
}

pub fn ak_pub_collateral(
    kind: AkPubCollateralType,
    backend: VerificationBackendType,
    data: Vec<u8>,
) -> AkPubCollateral {
    AkPubCollateral {
        akPubCollateralType: kind,
        verificationBackendType: backend,
        data: data.into(),
    }
}

pub fn encode_azure_maa_jwt_data(jwt: &[u8], hcl_var_data: &[u8]) -> Vec<u8> {
    (jwt.to_vec(), hcl_var_data.to_vec()).abi_encode_params()
}

pub fn encode_session_key_authorization(
    tpm_delegation_signature: &[u8],
    session_key_possession_signature: &[u8],
) -> Vec<u8> {
    (
        tpm_delegation_signature.to_vec(),
        session_key_possession_signature.to_vec(),
    )
        .abi_encode_params()
}

pub fn azure_maa_jwt_collateral(jwt: &[u8], hcl_var_data: &[u8]) -> AkPubCollateral {
    ak_pub_collateral(
        AkPubCollateralType::AzureMaaJwt,
        VerificationBackendType::Solidity,
        encode_azure_maa_jwt_data(jwt, hcl_var_data),
    )
}

pub fn encode_gcp_cert_chain_data(certs: &[Vec<u8>]) -> Vec<u8> {
    (certs.to_vec(),).abi_encode_params()
}

pub fn gcp_cert_chain_collateral(certs: &[Vec<u8>]) -> AkPubCollateral {
    ak_pub_collateral(
        AkPubCollateralType::GcpCertChain,
        VerificationBackendType::Solidity,
        encode_gcp_cert_chain_data(certs),
    )
}

pub fn aws_nitrotpm_collateral(proof: &ProgramBoundZkProof) -> AkPubCollateral {
    ak_pub_collateral(
        AkPubCollateralType::AwsNitroTpmProof,
        VerificationBackendType::ZkSuccinct,
        proof.abi_encode(),
    )
}

pub fn public_identity(algo: crate::AlgoId, key_bytes: Vec<u8>) -> PublicIdentity {
    PublicIdentity {
        typeId: algo.as_u8(),
        key: Bytes::from(key_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bank_aware_tpm_quote_round_trip() {
        let evidence = tpm_quote_evidence(
            vec![1, 2, 3],
            vec![4, 5],
            0xff,
            vec![PcrValue256 {
                pcrIndex: 15,
                value: B256::from([0x15; 32]),
                eventLogHashes: vec![B256::from([0xa1; 32])],
            }],
            vec![PcrValue384 {
                pcrIndex: 15,
                value: fixed_bytes48([0x38; 48]),
                eventLogHashes: vec![fixed_bytes48([0xb1; 48])],
            }],
        );
        let encoded = encode_tpm_quote_evidence_data(&evidence);
        assert_eq!(TpmQuoteEvidence::abi_decode(&encoded).unwrap(), evidence);
    }

    #[test]
    fn program_bound_snp_evidence_round_trip() {
        let proof = program_bound_zk_proof(B256::from([7; 32]), vec![8; 64], vec![9; 128]);
        let report = tee_report_snp_zk(
            VerificationBackendType::ZkSuccinct,
            proof.clone(),
            vec![0xaa; 1184],
        );
        let decoded = AmdSevSnpZkEvidence::abi_decode(&report.data).unwrap();
        assert_eq!(decoded.proof, proof);
        assert_eq!(decoded.rawReport.len(), 1184);
    }

    #[test]
    fn program_bound_tdx_evidence_round_trip() {
        let proof = program_bound_zk_proof(B256::from([7; 32]), vec![8; 277], vec![9; 128]);
        let report = tee_report_tdx_zk(
            VerificationBackendType::ZkSuccinct,
            proof.clone(),
            vec![0xaa; 584],
        );
        let decoded = IntelTdxDcapZkEvidence::abi_decode(&report.data).unwrap();
        assert_eq!(decoded.proof, proof);
        assert_eq!(decoded.quoteBody.len(), 584);
    }

    #[test]
    fn collateral_builders_set_exact_backend() {
        let azure = azure_maa_jwt_collateral(b"a.b.c", b"{}");
        assert!(matches!(
            azure.verificationBackendType,
            VerificationBackendType::Solidity
        ));
        let proof = program_bound_zk_proof(B256::from([1; 32]), vec![2], vec![3]);
        let aws = aws_nitrotpm_collateral(&proof);
        assert!(matches!(
            aws.akPubCollateralType,
            AkPubCollateralType::AwsNitroTpmProof
        ));
        assert!(matches!(
            aws.verificationBackendType,
            VerificationBackendType::ZkSuccinct
        ));
    }
}
