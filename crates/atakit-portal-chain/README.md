# atakit-portal-chain

This crate provides Solidity ABI encoding, message hashes, signing helpers,
and local verification of publisher-approved workload and base-image policies.
It is included in this repository so the CLI builds from a self-contained
source checkout.

Publisher signatures authenticate policy bytes. They do not establish current
registration, freshness or non-revocation. Callers must apply those checks
where required by their verification policy.
