# Automata DCAP provenance

- Source: `https://github.com/automata-network/automata-dcap-attestation`
- Commit: `bd3b13408640aa3d645f726a9f5f2f3697ce7f20`
- Upstream pull request: `https://github.com/automata-network/automata-dcap-attestation/pull/158`
- License: MIT, retained in `LICENSE`

The imported components are `dcap-rs`, `pccs-reader-rs`, the generated EVM
bindings, the on-chain deployment registry, the shared utility crate, and the
quote samples used by upstream tests.

The bindings, utility, and network-registry build scripts are disabled.
Checked-in generated bindings, version declarations, and deployment metadata
are authoritative. This keeps normal `atakit-ng` builds offline and
reproducible. The imported crates remain in their own nested Cargo workspace so
generated source does not change `atakit-ng` formatting checks.
