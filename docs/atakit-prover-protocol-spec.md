# Atakit Prover Protocol Specification

## Version

The current protocol version is `2`. The protocol uses handwritten Rust data
types serialized with bincode. It has no schema generator or external compiler.
Every encoded payload carries its protocol version. A peer must reject a
different version before decoding the message body.

## Transport

The portal is the client and the prover daemon is the server on a private Unix
domain stream socket. Each frame contains:

1. a four-byte big-endian unsigned payload length;
2. the four ASCII bytes `ATPK`;
3. a four-byte big-endian protocol version; and
4. one bincode-encoded message body.

The maximum payload, including `ATPK` and the version, is 64 MiB. Zero-length,
oversized, wrong-magic, wrong-version, truncated, and trailing-byte frames are
protocol errors.

Bincode uses version 1.3 with fixed-width integer encoding, little-endian
integers, a 64 MiB decode limit, and trailing-byte rejection. Struct fields are
encoded in the order listed below. Enum variants use their listed zero-based
order. Optional values and collection lengths use bincode's version 1.3 format.
All fields are always serialized. `SubmitProofRequest.options` is an ordered map
and is encoded in key order.

One request yields one response with the same `request_id`. Implementations may
reuse a connection or reconnect between calls. Unknown message variants and
request/response ID mismatches are fatal for that call.

The delegated signer is a separate Unix socket using the same framing. It
accepts `SignDigestRequest` and returns `SignDigestResponse`.

The supervisor must provision the daemon runtime directory before privilege
drop as a worker-owned directory with mode `0700`. Daemon and signer sockets
must be Unix sockets with mode `0600`. The delegated signer must authenticate
the connecting peer as the exact portal-spawned daemon process; filesystem
permissions or a shared worker UID alone are not sufficient authorization.

## Version 2 Message Schema

The version 2 structs use this exact field order:

| Type | Fields in encoded order |
|---|---|
| `ProgramCapability` | `program_id`, `artifact_id`, `verifier_program_id`, `onchain_backend`, `output_schema`, `proof_encodings` |
| `CapabilitiesRequest` | no fields |
| `CapabilitiesResponse` | `protocol_version`, `backend_id`, `execution_modes`, `signer_schemes`, `programs` |
| `SubmitProofRequest` | `client_request_id`, `program_id`, `execution_mode`, `endpoint`, `timestamp`, `evidence`, `chain_rpc_url`, `chain_id`, `options` |
| `SubmitProofResponse` | `job_id` |
| `GetJobRequest` | `job_id` |
| `ProofResult` | `program_id`, `backend_id`, `onchain_backend`, `artifact_id`, `verifier_program_id`, `output_schema`, `proof_encoding`, `public_output`, `proof` |
| `Job` | `job_id`, `client_request_id`, `state`, `detail`, `result` |
| `GetJobResponse` | `job` |
| `CancelJobRequest` | `job_id` |
| `CancelJobResponse` | `job` |
| `ErrorResponse` | `code`, `message`, `retryable` |
| `Request` | `request_id`, `body` |
| `Response` | `request_id`, `body` |
| `SignDigestRequest` | `request_id`, `credential_id`, `scheme`, `digest` |
| `SignDigestResponse` | `request_id`, `signature`, `public_identity`, `error` |

`Request.body` variants are `Capabilities`, `SubmitProof`, `GetJob`, and
`CancelJob`, in that order. `Response.body` variants are `Capabilities`,
`SubmitProof`, `GetJob`, `CancelJob`, and `Error`, in that order. `Job.state`
uses signed 32-bit values: `0` unspecified, `1` queued, `2` running, `3`
succeeded, `4` failed, and `5` cancelled.

The SP1 daemon uses the same `ATPK` header and bincode settings for persisted
`SubmitProofRequest` and `Job` files. It decodes current files normally. It removes
headerless files from the prior unshipped Protobuf format, malformed `ATPK`
files, unsupported versions, and unpaired `.request` or `.job` files. It logs each file name and reason,
but never its contents. One incompatible file must not prevent valid current
jobs from loading or prevent daemon startup. The daemon does not decode the
prior Protobuf format.

## Process Invocation

A portal-managed daemon must accept:

```text
--socket <private Unix socket>
--state-dir <private per-boot job directory>
```

When its descriptor declares `signer_scheme`, the portal also supplies
`--signer-socket <path>` and `--signer-address <public identity>`. Daemons that
do not declare delegated signing must not require those arguments. Additional
backend settings belong in `SubmitProofRequest`, not command-line secrets.

## Capabilities

Before submitting work, a client must request `CapabilitiesResponse` and check:

- `protocol_version` equals `2`;
- `backend_id` equals the selected descriptor/config backend;
- the requested execution mode is present;
- the required signer scheme is present when credentials are needed;
- exactly one capability exists for each required program:
  `amd_sev_snp.v1`, `intel_tdx_dcap.v2`, `tpm_quote.v1`, and
  `aws_nitrotpm.v1`.

A program capability binds:

| Field | Meaning |
|---|---|
| `program_id` | Stable semantic program name, such as `amd_sev_snp.v1`. |
| `artifact_id` | Immutable release artifact identity. |
| `verifier_program_id` | Exact on-chain verifier program identity. |
| `onchain_backend` | Contract adapter, such as `zk_succinct`. |
| `output_schema` | Public output encoding understood by the verifier contract. |
| `proof_encodings` | Accepted proof byte encodings. |

Clients must not synthesize any of these values from `backend_id`.

## Jobs

`SubmitProofRequest` contains the evidence, program, execution mode, provider
endpoint, timestamp, chain context, and backend-specific string options. Secret
keys are never included.

`client_request_id` is a mandatory idempotency key scoped to the supplied
`state-dir` lifetime (normally one CVM boot). The daemon persists the request-to-job mapping there so a process restart preserves idempotency.
Submitting the same ID and identical request must return the original `job_id`.
Submitting the same ID with different content must return a non-retryable
conflict error. This rule prevents duplicate hosted-prover charges after a
transport timeout.

`GetJob` returns one of:

```text
QUEUED -> RUNNING -> SUCCEEDED
                  -> FAILED
       -> CANCELLED
```

Terminal states do not change. `CancelJob` is idempotent. Cancelling a terminal
job returns its existing terminal state. A successful job must contain exactly
one `ProofResult`; other states must not be interpreted as proof success.

The client must tolerate transport interruption and daemon-declared retryable
errors while polling by reconnecting and retaining the original `job_id`.
Non-retryable protocol errors terminate polling. When the overall proof
deadline expires, including while a `GetJob` call is blocked, the client must
send `CancelJob` before returning a timeout. Cancellation failure is logged but
must not convert the timed-out job into a successful proof.

A daemon must stop local work and propagate cancellation to its remote backend
when that backend exposes cancellation. If the backend cannot guarantee remote
cancellation, the daemon must still keep the job terminally `CANCELLED` and
must never surface a later proof as successful.

## Proof Result Validation

The client must reject a successful result unless all metadata matches the
capability selected before submission:

- `program_id`
- `backend_id`
- `onchain_backend`
- `artifact_id`
- `verifier_program_id`
- `output_schema`
- `proof_encoding` in the declared set

Both `public_output` and `proof` are opaque to the transport. Their encodings
are defined by the artifact manifest and on-chain adapter.

### Program-bound proof identity

Protocol version `2` adds `verifier_program_id` to both
`ProgramCapability` and `ProofResult`. The portal requires the two values to
match. It passes the exact negotiated identity into `ProgramBoundZkProof`.
The contract then resolves that identity through `ZkVerifierRegistry`.

The four current programs have separate input and output schemas. The Intel
TDX DCAP and AMD SEV-SNP programs verify TEE reports. `tpm_quote.v1` verifies
and evaluates a bank-aware TPM Quote. `aws_nitrotpm.v1` verifies the AWS
NitroTPM Attestation Document and commits to the selected SHA-384 PCR values.

## Delegated Signing

`SignDigestRequest` contains a credential identifier, scheme, and digest. In
version 2 the production SP1 network daemon uses `es256k_digest` with a 32-byte
digest. The signer must reject unknown schemes, credential identifiers, and
digest lengths. It returns only the signature and public identity; private key
material and general transaction signing are outside the protocol.

The signer listener must accept requests only from the PID of the daemon child
for which it was created. A connection from any other peer is closed without
processing a signing request.

## Startup Failure

The portal must not initialize workload containers until daemon capability
negotiation succeeds. Descriptor validation, process spawn, socket readiness,
protocol negotiation, signer negotiation, and required-program validation are
one startup transaction. Failure at any point must abort the signer task, kill
the child, and remove both sockets.

## Errors

`ErrorResponse` includes a stable machine `code`, human-readable `message`, and
`retryable` flag. At minimum implementations distinguish invalid requests,
unsupported capability, idempotency conflict, unknown job, signing failure,
backend failure, cancellation, and internal failure. Retrying is permitted only
when `retryable` is true and must retain the original `client_request_id`.

## Versioning

Version `2` is a strict positional schema. Peers reject every other protocol
version before decoding the message body. They do not decode protocol version
`1`. Adding, removing, reordering, or changing a field or enum variant requires
a new protocol version. A framing, required-semantics, or state-transition
change also requires a new protocol version.
