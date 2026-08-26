# atakit-cvm-encoding

`atakit-cvm-encoding` implements the canonical Solidity ABI encodings defined
by the atakit suite specifications. Its public API uses Rust byte arrays and
vectors. Alloy is an implementation dependency and is not part of the public
types.

The crate contains no contract bindings, provider, signer, or network client.
The canonical specifications live in the `docs/specs/` directory of the
[`atakit-suite`](https://github.com/automata-network/atakit-suite) repository.
