use alloy_primitives::keccak256;
use alloy_sol_types::SolValue;
use atakit_attestation::evidence_abi::*;

const ENCODING_HASHES: [&str; 3] = [
    "0xf61ed1a902fd172784167d054fb395a10b912f70a0b1869ed78208c75f3f9e44",
    "0x5b7d3cec060b54e33ea4549962444ce5cc9c85e221ff2b6d138d5307121fad57",
    "0x28f4dfef3a4e284609badf8db21ac91f2bf1c497ea5aed73dbbf6c11c05b8214",
];

#[test]
fn evidence_encodings_match_fixed_vectors() {
    let certify = tpm_certify_evidence(vec![1; 33], vec![2; 65], vec![3; 67]).abi_encode();
    let authorization = encode_session_key_authorization(&[4; 70], &[5; 65]);
    let certs = vec![vec![6; 33], vec![7; 65]];
    let chain = encode_gcp_cert_chain_data(&certs);
    for (bytes, expected) in [&certify, &authorization, &chain]
        .into_iter()
        .zip(ENCODING_HASHES)
    {
        assert_eq!(keccak256(bytes).to_string(), expected);
    }
    let decoded = TpmCertifyEvidence::abi_decode(&certify).unwrap();
    assert_eq!(decoded.tpmtPublic.as_ref(), &[3; 67]);
    let (delegation, possession) =
        <(alloy_primitives::Bytes, alloy_primitives::Bytes)>::abi_decode_params(&authorization)
            .unwrap();
    assert_eq!(delegation.as_ref(), &[4; 70]);
    assert_eq!(possession.as_ref(), &[5; 65]);
}
