# atakit-cvm-encoding

`atakit-cvm-encoding` implements the canonical Solidity ABI encodings defined
by the Atakit specifications. Its public API uses Rust byte arrays and
vectors. Alloy is an implementation dependency and is not part of the public
types.

The crate contains no contract bindings, provider, signer, or network client.
See the [workload specification](../../docs/atakit-workload-toml-spec.md) and
[runtime configuration](../../docs/runtime-configuration.md).
