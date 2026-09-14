# AWS key-rotation regression evidence

Public, hardware-signed evidence collected on the controlled hoodi-fork during
the 2026-09-12 release validation. No private keys or credentials are included.
The rotation transaction succeeded, but the old verifier rejected the retained
NitroTPM document against the new rotation nonce.

Tests evaluate the document at 2026-09-12 07:30:00 UTC. They authenticate its
certificate chain and signature using the root in this fixed fixture, then
check the original nonce/PCR commitment and both original/current TPM quote
signatures. Mutated input cannot replace that fixed test root.

These are targeted NitroTPM/TPM tests, not full SNP vendor-certificate or live
chain tests. The separate SNP certificate check is not supplied collateral.
Runtime trust selection and freshness limits are unchanged.

The client crate also has an opt-in `aws_rotation_saved_evidence_chain_replay`
test. It resolves full trust and policy from the caller-selected
`ATAKIT_AWS_ROTATION_RPC_URL` and `ATAKIT_AWS_ROTATION_SESSION_REGISTRY`, fetches
AMD collateral, and verifies the complete saved response at capture time.
It reuses the captured challenge only to replay this historical response;
it does not claim a fresh attestation or a new live rotation.
