# Automata DCAP provenance

- Source: `https://github.com/automata-network/automata-dcap-attestation`
- Commit: `7ee427e0d4d4ab51861c81fedc0c6338e67c49b6`
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
