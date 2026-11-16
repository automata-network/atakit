# Atakit Prover Artifact Specification

## Purpose

Prover artifacts bind a semantic attestation program to immutable guest bytes,
the verifier program identity, output/proof encodings, and upstream provenance.
They are release inputs and audit records; they are not workload-manifest data.

## Program Artifact Manifest

Each program has a TOML file under `artifacts/` with these fields:

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | Artifact schema, currently `1`. |
| `protocol_version` | yes | Minimum prover protocol version. |
| `program_id` | yes | Stable semantic program name. |
| `backend_id` | yes | zkVM/backend implementation. |
| `onchain_backend` | yes | Existing contract adapter identifier. |
| `execution_modes` | yes | Modes implemented by this artifact. |
| `artifact_sha256` | yes | SHA-256 of the exact guest ELF/image bytes. |
| `verifier_program_id` | yes for release | Program/vkey identity configured on chain. |
| `output_schema` | yes | Public output schema identifier. |
| `proof_encoding` | yes | Proof byte encoding identifier. |
| `source` | yes | Guest source location or immutable upstream repository revision. |
| `sp1_version` | for SP1 source-built guests | Exact SP1 guest toolchain/library version. |
| `dcap_source` | for DCAP guests | Immutable upstream DCAP verifier source revision. |
| `source_archive_sha256` | when vendored archive used | Hash of fetched source archive. |
| `license` | yes | SPDX license expression. |

An upstream identity may be recorded separately while integration is being
validated, but production release must record the identity computed from the
exact shipped artifact as `verifier_program_id`. Hash or identity drift is a
release failure.

Example:

```toml
schema_version = 1
protocol_version = 2
program_id = "amd_sev_snp.v1"
backend_id = "sp1"
onchain_backend = "zk_succinct"
execution_modes = ["network"]
artifact_sha256 = "..."
verifier_program_id = "0x..."
output_schema = "automata.snp_verifier_journal.v1"
proof_encoding = "sp1_groth16.v1"
source = "owner/repository@commit"
license = "Apache-2.0"
```

## Install Descriptor

The portal discovers a backend using
`/etc/atakit/provers.d/<backend-id>.toml`:

```toml
schema_version = 1
id = "sp1"
protocol_version = 2
binary = "/usr/libexec/atakit/atakit-proverd-sp1"
# signer_scheme = "es256k_digest" # optional delegated signer requirement
```

`id` must equal the filename stem and negotiated `backend_id`. `binary` must be
absolute. An optional `socket` is reserved for an externally supervised daemon;
portal-managed daemons use a runtime-generated socket and ignore it.

`signer_scheme` is optional. When present, the daemon must advertise it and the
portal must provide a compatible delegated signer plus configured credential.
When absent, no signer socket or credential is required. Protocol version 2 of
the portal implements `es256k_digest`; future schemes can be added without
changing daemon transport or proof messages.

In production the descriptor and executable must be regular non-symlink files,
owned by UID 0, with group/other write bits clear. The portal must fail closed
before launching an unsafe artifact.

## Release Manifest

`release/provers.toml` is the production allowlist. Each entry identifies a
backend, installed binary, and descriptor. A backend absent from this file is
not copied into production images. Test/conformance daemons must never appear.

A backend-specific release manifest may list its program artifact manifests.
Image tooling must fail when a selected file is missing, unhashed, or outside
the declared release set.

## Provenance

Vendored sources must include their upstream repository, immutable revision,
archive checksum where applicable, license, local modifications, and the exact
guest artifact checksum. Generated ELFs must either be reproducible from the
pinned tree or accompanied by upstream release provenance. A source-built guest
must have its own checked-in lockfile and an explicit build command that does not
run during ordinary portal or daemon compilation.

## Versioning

Changing guest bytes changes `artifact_sha256` and normally the verifier program
identity. A semantic input/output change requires a new `program_id` version or
`output_schema`; it must not silently replace an existing artifact. Backend-only
changes that preserve program identity may retain `program_id` but still create
a new immutable artifact record.
