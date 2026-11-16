# Session Attestation and Lifecycle Specification

This document is the canonical protocol for atakit application sessions. It
defines session creation, evidence transport, request binding, owner-authorized
lifecycle operations, contract encodings, status retention, and offline
verification. Contract ABI details remain mirrored in
[`cvm-registry/session-registry.md`](cvm-registry/session-registry.md).

## Normative conventions

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

- Binary evidence and HTTP challenges use RFC 4648 base64url without padding.
- Ethereum addresses, identifiers, calldata, fingerprints, and signatures use
  lowercase `0x`-prefixed hexadecimal.
- JSON fields defined by this specification are always present. A value that
  does not apply is encoded as `null`; it is not omitted.
- `JCS(value)` means RFC 8785 JSON Canonicalization Scheme bytes.
- `bytes32(x)` denotes exactly 32 bytes. `address(0)` is twenty zero bytes.
- Contract signatures use recoverable ES256K `(r,s,v)` signatures encoded as
  65 bytes with Ethereum `v` 27 or 28 and a low `s` value. TPM signatures
  retain their native TPM encoding where a structure says so.
- Contract owner-message digests use `SHA256(abi.encode(...))`. TPM transition
  commitments and key delegation use `keccak256(abi.encode(...))`.
- `opExpiresAt` / `op_expires_at` is an authorization deadline. It is distinct
  from a stored session's absolute `sessionExpiresAt` and a workload policy's
  relative `sessionTtl`.

## Startup and key ownership

Successful startup does not establish verification for a secret provisioner.
Before releasing secrets, the provisioner MUST authenticate the claimed
workload and measurements against its trusted policy sources, verify freshness,
and bind delivery to the verified recipient. See the
[secret provisioning security notice](secret-provisioning-security-notice.md).

The portal does not expose a workload session at process bootstrap. After it
has validated the manifest, extended PCR23, and launched the workload
containers, it creates a session candidate before enabling workload traffic or
`/sign-message`.

Each candidate owns:

1. a fresh application `k256::SecretKey::random(OsRng)` held only in a
   zeroizing supervisor allocation; and
2. a fresh transient TPM signing key.

Neither private key nor a reloadable TPM-wrapped key is persisted. A supervisor
holds at most one committed secret and one candidate secret. Candidate begin,
evidence/signing, commit, abort, and committed-session query are explicit IPC
operations. Commit is idempotent over `(candidate_id, session_id)`. A worker
that sees an uncertain commit result queries the committed session and either
completes the exact match or aborts the candidate. Only an IPC `Response::Ok`
permits state advancement.

The worker holds its session write lock across supervisor commit and local
context replacement. Commit and abort flush replaced TPM handles and zeroize
the corresponding application secret. Every application-key signature request
includes the expected session ID; a mismatch is rejected.

An authorized lifecycle operation keeps the committed predecessor and one
successor candidate at the same time. The predecessor application key remains
the current `/sign-message` key. Rotate and renew use its committed TPM key for
the transition authorization. The candidate has a separate application key
and TPM handle and supplies the successor evidence and delegation. The worker
commits the candidate only after `isSessionActive(successorSessionId)` is true.
A definite pre-confirmation failure aborts only the candidate and leaves the
predecessor committed. An unknown broadcast outcome remains running and keeps
the candidate until the chain result can be resolved.

The supervisor represents every committed TPM signing key as exactly one of
`Absent`, `Loaded`, or `Suspended`. `Suspended` retains the saved TPM context.
Candidate construction changes a `Loaded` predecessor to `Suspended`, builds
the candidate key, and then restores the predecessor. Restoring a saved TPM
context borrows that context; a failed `context_load` leaves the predecessor in
`Suspended` so a later signing request can retry the same context. If
predecessor restoration fails, the supervisor flushes the candidate key and
fails candidate construction. It does not discard the predecessor context.
Only a successful candidate commit may replace and discard the predecessor's
loaded key or saved context. Terminal candidate failure therefore preserves
the committed predecessor's signing capability.

The post-launch quote selects SHA-256 PCRs 0 through 16 and PCR23. PCR10 and its
IMA launch events are retained. A session MUST NOT use evidence collected
before container launch.

Initial startup therefore uses this order:

1. validate the manifest and extend PCR23;
2. launch the workload containers, which starts their processes;
3. collect the post-launch Quote and construct the session candidate;
4. when `registration = "required"`, submit the registration and enter
   `Registering`; and
5. open the workload manifest-declared inbound ports and enter `Running` only
   after `isSessionActive(sessionId)` is observed true.

For `registration = "required"`, chain confirmation is not a prerequisite for
workload process execution. It gates only the portal-managed inbound firewall
rules for the workload manifest-declared ports. It does not guarantee that a
workload process cannot make outbound connections, write files, run background
jobs, or cause other startup effects before confirmation.

## Session binding

For a chain-bound candidate, the owner nonce is read from the configured
registry and the Quote/Certify qualifying data is:

```text
keccak256(abi.encode(
    keccak256("CVM_SESSION_REG_NONCE_V1"),
    chainId,
    registry,
    ownerFingerprint,
    ownerNonce
))
```

For a local-bound candidate, `chainId = 0`, `registry = address(0)`, and the
nonce is a fresh portal-random 32-byte unsigned integer. A local binding is
never presented as chain-active and cannot be upgraded in place.

Registration modes behave as follows:

| Mode | Binding and startup behavior |
|---|---|
| `off` | Always local-bound. No RPC. |
| `required` | Resolve chain ID and owner nonce through RPC or fail closed. Workload processes start before registration. The workload manifest-declared inbound ports remain closed until the selected submitter sends the prepared registration and `isSessionActive(sessionId)` is observed true. |
| `optional` | Attempt the chain path. On failure, create a local-bound session and retain that binding until reboot. |

In this specification, “observed” means that the configured `chain.rpc_url`
returned the value. The portal uses normal JSON-RPC calls. It does not verify a
consensus proof, block-header chain, state proof, or agreement among independent
RPC endpoints. The portal therefore trusts `chain.rpc_url` for `eth_chainId`,
the owner nonce, transaction and receipt results, and
`isSessionActive(sessionId)`. An actor that controls `chain.rpc_url` can report
a false active result and cause the portal to open the workload
manifest-declared inbound ports and enter `Running`. `registration = "required"`
does not provide independent chain confirmation against such an actor.

For portal-managed optional registration, a permanent submission failure or
retry exhaustion before broadcast MUST replace the chain-bound candidate with
a fresh local-bound session. That replacement uses `chainId = 0`, the zero
registry address, and a fresh random local binding, and commits the new
candidate atomically. If replacement fails, the portal enters `Failed`.

After an unknown broadcast outcome, the portal keeps the original chain-bound
candidate and the exact signed transaction bytes. Until `opExpiresAt`, it polls
both `isSessionActive(sessionId)` and the locally calculated transaction hash,
and retries only those same transaction bytes with bounded backoff. It does not
build a different session or transaction. At expiry it stops sending and makes
one final `isSessionActive` call. A true result verifies the original session.
Any other result is a terminal failure: required registration enters `Failed`,
while optional registration installs a fresh local-bound session or enters
`Failed` if replacement fails. The final chain status retains the known failure
detail after a successful local fallback.

Only a transport failure or malformed success response has unknown delivery.
If `eth_sendRawTransaction` reports that it already knows the exact signed
transaction, the portal observes the locally calculated transaction hash
without unknown-delivery rebroadcasts. Every other valid JSON-RPC error is a
rejected send attempt. The portal may use its bounded submission retry loop,
but it MUST NOT enter submitted-transaction observation for that rejected
attempt.

Each portal-owned submission attempt checks the owner-authorization deadline
before fee estimation, after fee estimation and before `SignWithGasWallet`,
and immediately before `eth_sendRawTransaction`. An expired check is terminal
and prevents every later step. Retry backoff that crosses the deadline prevents
another attempt. These checks use the contract boundary:
`now > opExpiresAt` is expired and `now == opExpiresAt` remains valid.

When the exact prepared transaction carries an Azure MAA JWT, the portal MUST
parse its top-level numeric unsigned 64-bit `iat`, `nbf`, and `exp` claims.
Before `eth_estimateGas`, the portal MUST wait until the latest block timestamp
is at least `max(iat, nbf)`. `MaaJwtNotYetValid` and
`MaaJwtIssuedInFuture` are time-dependent failures: the portal MUST wait for a
newer block and retry the exact prepared JWT and calldata. It MUST NOT fetch a
replacement JWT during this wait because a replacement moves the validity
start forward. The wait ends as a terminal failure at JWT expiry or
owner-authorization expiry. `MaaJwtExpired` is not retryable.

atakit-portal is the only transaction owner. It constructs the transaction
envelope, fills gas and wallet nonce, signs through the supervisor-held gas
wallet, broadcasts, retries, checks receipts, and polls `isSessionActive`.

Binding mode and attestation mode are independent axes. Binding mode is
`local` or `chain`; attestation mode is `hardware` or `emulation` and is
derived from the authoritative detected TEE rather than stored independently.
The permitted combinations are:

| Attestation mode | Local binding | Chain binding |
|---|---|---|
| `hardware` | allowed, with complete hardware/provider verification | allowed |
| `emulation` | allowed only in an explicit `tee-emulation` development build | forbidden |
| unavailable | forbidden; no session is created | forbidden |

An emulation build requires `chain.registration = "off"`. A normal build with
no detected TEE MUST fail session creation and MUST NOT silently substitute an
emulated session. Emulation never produces chain calldata or a
`chain_submission_available` result.

## Session and evidence projections

`GET /session` reads only committed in-memory state and performs no RPC. Its
response contains the session ID; application-key type, bytes, and fingerprint;
workload, base-image, profile, and variant IDs; binding mode; derived
attestation mode; TEE type; chain ID; registry; and
`chain_submission_available`. It makes no active, expired, revoked, or
globally-latest claim. The attestation mode and TEE type are projections of the
single authoritative platform identity, not additional mutable state.

Before the first session is committed, `GET /session` and
`GET /session/evidence-bundle` return `503 Service Unavailable`, include
`Retry-After: 1`, and return:

```json
{
  "code": "session_not_ready",
  "state": "initializing_session",
  "retryable": true
}
```

The workload-facing `POST /sign-message` route uses this same response. A
malformed evidence-bundle challenge remains `400 Bad Request`.

`GET /session/evidence-bundle?challenge=<base64url-bytes32>` returns the current
session only:

```json
{
  "evidence_bundle": {
    "format": 2,
    "binding": {},
    "platform": {
      "cloud": "gcp",
      "cloud_provenance": {
        "source": "dmi" | "metadata" | "user_provided" | "unresolved",
        "detection": {
          "dmi": {
            "sys_vendor": "Google" | null,
            "product_name": "Google Compute Engine" | null,
            "bios_vendor": "Google" | null,
            "detected_cloud": "gcp" | "unknown"
          },
          "metadata": {
            "gcp": {"attempted": true, "matched": true, "http_status": 200, "response_headers": {"metadata-flavor": "Google"}, "response_body": "instance/\nproject/\n", "error": null},
            "azure": {"attempted": false, "matched": false, "http_status": null, "response_headers": {}, "response_body": null, "error": null},
            "aws": {"attempted": false, "matched": false, "http_status": null, "response_headers": {}, "response_body": null, "error": null},
            "detected_cloud": "gcp",
            "conflict": false
          }
        },
        "user_provided": "gcp" | null
      },
      "attestation_mode": "hardware",
      "tee": "tdx",
      "machine_type": "c3-standard-4"
    },
    "tee_evidence": {},
    "ak_evidence": {},
    "tpm_quote": {
      "tpms_attest": "base64url",
      "tpm_signature": "base64url",
      "signature_hash": "0x...",
      "pcr0_startup_locality": 0
    },
    "tpm_certify": {},
    "pcr_values": [],
    "event_log_hashes": [],
    "session_key": {},
    "session_key_delegation": {},
    "session_id": "0x...",
    "policy": {
      "workload_id": "0x...",
      "base_image_id": "0x...",
      "platform_profile_id": "0x...",
      "measurement_variant_id": "0x...",
      "pcr_bank_selection": "sha256-and-sha384",
      "pcr_specs256": [],
      "pcr_specs384": []
    },
    "owner": {},
    "provider_binding": null
  },
  "request_binding": {
    "challenge": "base64url",
    "signature": "0x..."
  }
}
```

The bundle carries the raw TEE report, AK authentication material, Quote,
Certify, PCR values, ordered event hashes, public keys, signatures, and policy
inputs. The verifier calculates the Quote digest, evidence hashes, AK/TPM
bindings, delegation, policy result, and session ID from those source values.
For a resolved hardware session, the portal projects the complete effective
dual-bank PCR policy into `pcr_specs256` and `pcr_specs384`. It also projects
the PCR0 startup locality authenticated by the Quote. The permitted
`pcr_bank_selection` values are `sha256`, `sha384`, and
`sha256-and-sha384`. Each projected PCR rule contains only `pcr_index` and the
exact `comparison` hex bytes resolved from the trusted policy.
The TPM Quote selects one bank, or selects SHA-256 followed by SHA-384. The
portal constructs that order without `PcrSelectionListBuilder`, whose internal
hash map does not preserve insertion order. Before returning a session bundle,
the portal reads both banks before and after the Quote and checks the signed
`pcrDigest` against the captured values. If that check fails after the bounded
retry loop, the persisted failure detail contains an
`atakit.pcr-evidence-capture.v1` JSON object. It preserves the exact
`TPMS_ATTEST`, bank order, selected indexes, before and after PCR values, signed
`pcrDigest`, and recomputed `pcrDigest` as unpadded base64url.
A format 2 bundle requires
`session_key_delegation.session_key_possession_signature`. The certified TPM
signing key and the session key both sign the exact digest in
`session_key_delegation.digest`. The TPM signature is stored in
`session_key_delegation.signature`. The 65-byte recoverable ES256K session-key
signature is stored in
`session_key_delegation.session_key_possession_signature`. The second
signature proves that the producer which claims the session-key fingerprint
also owns the matching private key. Format 1 bundles do not contain this proof
and are not accepted.
A local-bound bundle has
`owner.contract_authorization = null`. It contains no predecessor, lifecycle
operation, history, or request status.

After `rotateKey`, the current Quote follows the contract rule and evaluates
the registered invariant, variant, and workload PCR blocks without a newly
generated provider PCR15 rule. The bundle then carries a non-null
`provider_binding` object. That object is a bounded projection of the last
complete-attestation Quote, Certify, PCR values, event hashes, binding, TPM
signing key, session ID, and PCR policy. The verifier checks this retained
Quote against the current TEE report and AK before it checks the rotation
Quote. A later key rotation reuses the same object; it does not nest another
bundle. Initial registration, renewal, and local-bound sessions omit
`provider_binding`.

`platform.cloud` is the sole resolved cloud value used to collect and verify
the evidence. `platform.cloud_provenance` records how that value was obtained:
the source that authorized it, observed DMI strings, bounded CSP-specific
metadata responses and detector inferences, and the exact accepted operator
declaration. AWS IMDSv2 tokens are excluded. Detector inferences are retained
audit inputs and are not additional operational cloud state.

`event_log_hashes` contains only entries that extended a PCR. TCG
`EV_NO_ACTION` (`event_type_id = 0x00000003`) is excluded. IMA's non-TCG
sentinel `event_type_id = 0` is retained because those entries do extend PCR10.
The lossless kernel firmware and IMA logs, including `EV_NO_ACTION` records,
are separately available from `GET /event-log/raw`.

The request-binding digest is:

```text
SHA256(abi.encode(
    keccak256("ATAKIT_PORTAL_SESSION_REQUEST_BINDING_EVIDENCE_BUNDLE_V1"),
    challengeBytes32,
    SHA256(JCS(evidence_bundle))
))
```

The current application key signs the digest with the same canonical 65-byte
recoverable ES256K form: Ethereum `v` 27 or 28 and a low `s` value.

`owner.contract_authorization` is a projection used to construct or inspect an
on-chain registration operation. It is not an input to offline verification of
the current session. The offline verifier does not verify an owner registration
signature, an owner operation deadline, or an owner nonce against registry
state. It verifies that the owner fingerprint and nonce bytes carried in the
bundle produce the Quote qualifying data. Chain transaction authorization and
registry-state checks belong to the contract or to a separate chain client.

`GET /chain-submission`, `POST /chain-submission`, and
`POST /chain-submission/submitted` do not exist. Prepared calldata remains an
internal atakit-portal value. `/trust-chain` also does not exist.

## Owner-authorized lifecycle API

Preparation endpoints are:

```text
POST /session/new
POST /session/rotate-key
POST /session/renew
POST /session/recover
```

Every body contains `op_expires_at` and a `0x` recoverable
`owner_intent_signature`. Rotate, renew, and recover additionally contain
`old_session_id`; new rejects that field. Unknown fields are rejected.

The preparation request hash is:

```text
new:
SHA256(abi.encode(keccak256(operationDomain), opExpiresAt))

rotate-key, renew, recover:
SHA256(abi.encode(keccak256(operationDomain), opExpiresAt, oldSessionId))
```

The operation domains are, respectively,
`ATAKIT_PORTAL_SESSION_NEW_V1`,
`ATAKIT_PORTAL_SESSION_ROTATE_KEY_V1`,
`ATAKIT_PORTAL_SESSION_RENEW_V1`, and
`ATAKIT_PORTAL_SESSION_RECOVER_V1`.

The owner signs `request_hash` with its provisioned ES256K identity. The
signature is excluded from the hash. Preparation processing MUST do only:

1. enforce `owner_operations.max_request_body_bytes`;
2. parse the fixed schema;
3. compute the request hash;
4. verify the owner intent signature;
5. return the existing waiting/running/recent result for a duplicate, or admit
   the request if the waiting map has capacity; and
6. return `202` with a cryptographically random 32-byte base64url challenge,
   request hash, and challenge expiry.

It MUST NOT perform RPC, session-state, TPM, TEE, policy, or operation-deadline
checks before challenge authorization.

The owner authorizes the challenge by signing:

```text
SHA256(abi.encode(
    keccak256("ATAKIT_PORTAL_CHALLENGE_AUTHORIZE_V1"),
    challengeBytes32,
    requestHash,
    challengeExpiresAt
))
```

`POST /challenge/authorize` accepts exactly `request_hash`, `challenge`, and
`owner_authorization_signature`. It verifies the signature and challenge
expiry, then performs deferred checks. The challenge is consumed immediately
before dispatch. Success returns `202` with state `running`. For a chain-bound
request, the portal MUST also set `/status.chain.status` to `preparing` before
returning. Candidate construction remains asynchronous, so `session_id` stays
null in the lifecycle status until the successor exists.

For a chain-bound successor, `running` covers candidate construction,
submission, chain observation, and local candidate commit. atakit-portal fills
the transaction, signs with the gas wallet, broadcasts, checks the receipt, and
observes `isSessionActive`. A request becomes `completed` only after the
successor is chain-active and the candidate is committed locally.

If the shared owner nonce changes, the portal aborts the candidate and rebuilds
the same lifecycle command with the same predecessor; it MUST NOT replace
lifecycle calldata with plain registration calldata. When its transaction
reverts, the portal first checks `isSessionActive(session_id)`. A true result
commits the successor because an earlier transaction succeeded. A false result
triggers a fresh owner nonce read. An advanced owner nonce rebuilds the
candidate; an unchanged owner nonce fails the request and restores the
predecessor. Temporary `isSessionActive` and owner-nonce RPC failures keep the
request running until a bounded retry succeeds or `op_expires_at` passes. An
advanced owner nonce clears the stale successor from request status, increments
the shared attempt counter, applies bounded backoff, and rebuilds only while an
attempt remains. The request hash, command, predecessor, and `op_expires_at`
remain unchanged. The application session key, TPM signing key and evidence,
owner-nonce binding, successor session ID, and contract calldata are fresh.
Initial registration and lifecycle operations use the same reverted-transaction
classifier. A pending transaction or RPC result that cannot prove success or
failure keeps the request running.

Only `/session/new` accepts a local-bound predecessor. Rotate-key, renew, and
recover require a chain-bound current session and fail after authorization with
`409` and code `chain_bound_session_required`.

When `/session/new` commits a local-bound successor, the portal updates the
current session ID without changing `/status.chain.status` or
`/status.chain.detail`. Registration `off` remains `off`. An optional-
registration fallback remains `failed` and keeps the chain failure detail. A
local session replacement has no chain submission and MUST NOT report `ready`.

## Request status

At most one session-changing operation runs at a time. Initial registration
and every lifecycle operation use the same session-operation lock. While
initial registration or another lifecycle operation holds the lock,
authorization returns `409 session_operation_already_running` and leaves the
request in `waiting` so the caller can retry. Waiting bodies are kept in a
capped in-memory map and are removed with their challenge when execution
starts. Small status records live in a map with an oldest-to-newest completion
queue.

`GET /session/status` returns the current session-changing operation or an
idle projection. It selects a running request first, then a valid latest
request, then the newest retained waiting request, then the newest retained
completed request. Admission sequence numbers provide deterministic ordering
when several requests share the same second-resolution timestamp.
`GET /requests/{request_hash}` returns one request. Every
record has the same fields: request hash, command, state, session ID or error
code, and created, started, and completed timestamps; unavailable values are
`null`. Once the candidate exists, a running record reports its successor
session ID. Reads never extend retention and running records are never evicted.

When no request is retained, `GET /session/status` returns `200` with:

```json
{
  "request_hash": null,
  "command": null,
  "state": "idle",
  "session_id": null,
  "error_code": null,
  "created_at": null,
  "started_at": null,
  "completed_at": null
}
```

The general endpoint returns this projection before the first request, after
all requests expire or are evicted, and after reboot. It never uses `404` to
represent healthy idle state.

Completed records expire after
`owner_operations.request_status_retention_seconds` and are capped by
`owner_operations.max_completed_request_statuses`. Missing, expired, evicted,
and pre-reboot hashes return `404 request_not_found`. All request state is
memory-only and disappears on reboot.

## atakit lifecycle commands

The cloud deployment interface is:

```text
atakit cloud session new <instance>
atakit cloud session rotate-key <instance>
atakit cloud session renew <instance>
atakit cloud session recover <instance> --old-session-id <bytes32>
atakit cloud session status <instance> [--request-hash <bytes32>] [--wait]
```

The four mutation commands MUST perform full TLS attestation and verify the
current challenge-bound session before sending an owner signature. There is no
unsafe TLS bypass. `rotate-key` and `renew` use the verified current session as
`old_session_id`. `recover` requires the operator to supply the older session
ID. Only `new` may start from a local-bound current session.

These commands mutate portal and on-chain session state only. They do not
start, stop, delete, or recreate a cloud virtual machine. Contract expiry
prevents later use of a session but does not terminate the cloud virtual
machine. `rotate-key` preserves the predecessor's absolute
`sessionExpiresAt`. `renew` and `recover` verify complete fresh attestation and
assign a new policy-derived expiry. `recover` recovers an on-chain session; it
does not recover a stopped cloud virtual machine.

atakit signs only the lifecycle preparation hash and returned authorization
challenge. atakit-portal remains the only component that fills, signs,
broadcasts, retries, and observes the chain transaction. The lifecycle command
surface has no gas-wallet, relay-wallet, calldata, or transaction-submission
option.

After authorization, atakit polls the exact request hash. It prints and saves
that hash before waiting, so an interrupted observer can continue with
`atakit cloud session status --request-hash <hash> --wait`. A local timeout
does not change portal state and does not submit another request. A waiting
request still needs the original mutation command to authorize it.

`atakit cloud session status` verifies portal TLS before reading portal request
state. It does not resolve `WorkloadRegistry` policy before displaying
`idle`, `waiting`, `running`, or `failed`. Only a `completed` request triggers
trusted workload-policy resolution, fresh successor-session verification, and
the chain-active check when the verified successor is chain-bound. If that
final policy or registry lookup fails, the command still reports that the
portal returned `completed`, then returns a successor-verification error.
Session mutation commands keep the stricter order: they resolve trusted
workload policy and verify the current session before signing owner
authorization.

By default, atakit sets `op_expires_at` to the current time plus the portal's
900-second proof timeout plus `owner_operations.op_expiry_seconds`. This leaves
the configured owner-operation window available for transaction submission
after a proof consumes its complete supported time. An explicit
`--op-expiry-seconds` replaces this complete calculated window. The default
local wait is the resulting owner-authorization window plus 60 seconds. All
four mutation commands use this same calculation.

Before reporting success, atakit MUST verify a fresh current-session evidence
bundle, require its session ID to match the completed request's successor, and,
for a chain-bound successor, independently require `isSessionActive` to return
true. Reports contain request and result metadata but MUST NOT contain the
owner signatures, challenge authorization signature, or private-key material.

For `atakit cloud session` deployment-management commands, the verification
binding requirement is derived from the deployment's immutable named
`[cloud.targets.<name>]` configuration. These commands intentionally resolve
that same named configuration; they do not store a separate
registration-policy copy in deployment state. Changing the target, its
inherited defaults, or its referenced configuration while the deployment
exists is unsupported. An omitted policy and `required` require a chain-bound
session. `off` requires a local-bound session. `optional` accepts either
verified binding so that a valid optional-registration fallback remains
usable. The final registry check is derived from the verified successor's
binding: a chain-bound successor requires `isSessionActive`; a local-bound
successor does not. Rotate-key, renew, and recover still require a chain-bound
predecessor. Only new accepts a local-bound predecessor. `atakit cloud
verify-session` does not use this deployment binding requirement.

Before any `atakit cloud session` command verifies evidence, atakit resolves
the complete trusted workload policy for the saved deployment. For `required`
and `optional`, it MUST read the exact `WorkloadSpec` from the configured
`WorkloadRegistry`, check its name and version against saved deployment
identity, and check that its base-image access mode allows the TLS-selected
base-image ID. It converts every `WorkloadSpec.pcrs` item and every
`WorkloadSpec.requirements` item into verifier input. Workload PCR rules are
appended to the effective base-image profile and variant rules; a workload rule
never replaces a base-image rule for the same PCR index. Failure to read or
convert the trusted `WorkloadSpec` fails before owner authorization.

For deployment-management verification with `registration = "off"`, atakit
hashes and inspects the saved `.atawl`, requires its archive hash, name, and
version to match deployment state, and supplies its calculated SHA-256 and
SHA-384 PCR23 values and manifest attribute requirements. This applies even
when the base image is verified through a chain or trust pack. It MUST NOT
read `WorkloadRegistry` for this workload, and MUST require a local-bound
session. Missing or modified archives fail verification; manual workload PCR
overrides are rejected in this mode. Base-image verification and platform
collateral trust remain unchanged. Registration `required` and `optional`
retain their existing policy sources. This applies to cloud deployment,
initialization, resume, and deployment-management session operations.
The independent `cloud verify-session` command retains its explicit
verifier-selected policy authority described below.
Offline verification does not add session-expiry or revocation claims.

`atakit cloud verify-session` is an independent verifier command. Its required
subject inputs are the canonical base-image reference, canonical workload
reference, and instance identity containing the portal host and status port.
The verifier MAY supply all subject inputs directly. A matching local
deployment MAY fill missing subject inputs, but MUST NOT supply trusted policy
or collateral.

The verifier selects one measurement and workload policy authority: registry
contracts selected with `--chain`, explicit operator input, or trust packs.
When `--chain` is present, atakit derives `BaseImageRegistry` and
`WorkloadRegistry` from that chain's `SessionRegistry`. The deployment target,
saved registration value, saved chain name, provider image alias, saved
`.atawl`, and automatic local measurement cache MUST NOT choose or replace the
policy authority. When explicit policy is selected, the verifier MUST supply
the signed measurement pack, its trusted publisher key, and the trusted
workload PCR23.

Vendor-authenticated attestation collateral is a separate choice. It MAY come
from files, direct HTTP services, trust packs, or Automata on-chain PCCS in any
policy-authority mode. A read-only Automata on-chain PCCS query MUST NOT read or
replace a base-image measurement policy or workload policy from registry
contracts.

For a chain-bound session, the authenticated `chain_id` and `registry` claims
in the evidence bundle MUST match the chain ID returned by the
verifier-selected RPC endpoint and the `SessionRegistry` address from the
verifier-selected chain configuration. The evidence bundle MUST NOT select or
replace either trusted value. Selecting a chain for trusted collateral does
not by itself require a chain-bound session; a local-bound session remains
valid when the caller's binding policy permits it.

The caller MAY apply an optional `required_binding` policy after normal
session verification. This policy is separate from the trust authority.
`required_binding = None` accepts either verified binding mode; it does not
skip any cryptographic binding check. The current trust-pack and explicit
sources do not provide verifier-selected chain coordinates, so a chain-bound
session fails closed under those sources because its chain claims cannot be
authenticated. This is an input limitation, not a local-binding policy.

`atakit-verifierd` uses `required_binding = None` and reports the actual
binding. A client that relies on chain registration must separately require a
chain-bound session and, when authorization depends on current registration,
check that registry state.

Chain-resolved and explicitly supplied collateral MUST enter the same TLS and
session verification functions. The source does not change evidence,
signature, identity, PCR, attribute, request-binding, or session-binding
checks. `--trusted-workload-pcr23` selects an explicit PCR23-only workload
policy instead of a registry `WorkloadSpec`; this changes the verifier's chosen
policy content, not the verification function. Portal-reported identities are
never trusted to select policy.

The canonical hash vectors shared by atakit and atakit-portal are:

```text
new(op_expires_at = 1700000300):
  0x0786170f67db0f8e294618e4d290daaa2527185674f87d2d50e442dcfb0d86fe

renew(op_expires_at = 1700000300, old_session_id = 0x22 repeated 32 times):
  0x968953c3b83a02886f534869f51f900b6d98fd939e9aae4fd3ee0188e1df1d60

authorize(challenge = bytes 0x00 through 0x1f,
          request_hash = renew vector above,
          challenge_expires_at = 1700000060):
  0xa223e36fdbb9999aebc75e8af0f98a45736a63b9a9f0696f874b5aa2753c7efd
```

## Contract lifecycle

The session registry preserves its existing storage layout. Renaming ABI
parameter/component identifiers does not move storage and existing registered
sessions remain readable.

### Registration and revocation

Registration performs complete TEE, AK, Quote, Certify, delegation, and policy
verification. It assigns `sessionExpiresAt = block.timestamp + sessionTtl`, or
the contract default when `sessionTtl == 0`. Owner authorization is:

```text
SHA256(abi.encode(
    keccak256("CVM_MSG_SESSION_REGISTER_V1"),
    chainId, registry, opExpiresAt, sessionId,
    workloadId, baseImageId, platformProfileId, measurementVariantId,
    sessionKeyFingerprint
))
```

Revocation retains `CVM_MSG_SESSION_REVOKE_V1` and covers chain, registry,
`opExpiresAt`, and session ID.

### `rotateKey`

`rotateKey` requires an active predecessor, the predecessor TPM signing key,
and the same AK fingerprint. It verifies fresh Quote, Certify, delegation, and
policy evidence, retains the caller-supplied `teeReportBytesHash`, inherits the
predecessor's policy tuple and absolute `sessionExpiresAt`, and atomically
revokes the predecessor. The old TPM commitment is:

```text
keccak256(abi.encode(
    keccak256("CVM_SESSION_ROTATE_KEY_V1"),
    chainId, registry, oldSessionId,
    newTpmSigningKeyFingerprint, newSessionKeyFingerprint,
    teeReportBytesHash
))
```

The owner digest is:

```text
SHA256(abi.encode(
    keccak256("CVM_MSG_SESSION_ROTATE_KEY_V1"),
    chainId, registry, opExpiresAt, oldSessionId, newSessionId
))
```

It emits `SessionRevoked`, `SessionKeyRotated`, and
`AttestationKeysRevealed` in that order.

`rotateKey` does not receive or verify a new TEE report. It inherits the TEE
state accepted by the predecessor's complete registration or renewal.

### `renewSession`

Renew requires an active predecessor and its TPM signing key. The successor
undergoes independent complete attestation and may change AK, workload,
base-image, profile, or variant. Its lifetime is freshly policy-derived. The
old TPM key signs:

```text
keccak256(abi.encode(
    keccak256("CVM_SESSION_RENEW_V1"),
    chainId, registry, oldSessionId, newSessionId,
    keccak256(abi.encode(newEvidence))
))
```

The owner signs the lifecycle tuple described below using
`CVM_MSG_SESSION_RENEW_V1`. Renew atomically revokes the predecessor and emits
`SessionRevoked`, `SessionRegistered`, `AttestationKeysRevealed`, and
`SessionRenewed`.

### `recoverSession`

Recover requires an existing, non-revoked predecessor owned by the signer.
The predecessor may be expired and no old TPM key is required. The successor
undergoes complete independent attestation and receives a fresh policy-derived
lifetime. The owner signs the lifecycle tuple using
`CVM_MSG_SESSION_RECOVER_V1`. Recover revokes the predecessor and emits
`SessionRevoked`, `SessionRegistered`, `AttestationKeysRevealed`, and
`SessionRecovered`. A second recovery using that predecessor fails with
`SessionAlreadyRevoked`; recovery is single-use per predecessor.

Renew and recover owner digests are:

```text
SHA256(abi.encode(
    operationDomain,
    chainId, registry, opExpiresAt,
    oldSessionId, newSessionId,
    workloadId, baseImageId, platformProfileId, measurementVariantId,
    newSessionKeyFingerprint
))
```

No owner-global current-session or predecessor mapping is added.

## Offline verification

The `atakit-attestation` verification core is shared by TLS and session
verification. It verifies raw evidence locally and MUST NOT substitute an
on-chain ZK-proof result for raw TEE verification. Its typed session result
includes structured checks and errors, request-binding verification, and
the verified session identifiers. TLS retains its existing public verification
entry point.

Provider authentication, raw TEE verification, TPM Quote parsing/signature
verification, and PCR policy evaluation belong to a provider-neutral core.
TLS and session verification are separate protocol adapters over that core;
neither adapter is the implementation owner of the shared checks.

Both adapters apply the trusted exact-CPUID
`AmdSnpSecurityPolicy.requiredLaunchMitigationVector` and
`requiredCurrentMitigationVector` fields. A nonzero mask requires a signed
AMD SEV-SNP version-5 report. Each signed mitigation vector must contain every
bit in its matching mask.

PCR policy modes are:

- `STATIC`: the replayed/final PCR equals the registered value.
- `DYNAMIC_SUBSET`: every policy hash occurs in the non-empty replay input, in
  any order. The policy list is a set of required unordered landmarks and need
  not be a complete log; additional observed events are permitted.
- `DYNAMIC_SUBSEQUENCE`: registered hashes are ordered landmarks in the replay
  input. Additional events may occur before, between, and after landmarks.
- `DYNAMIC_INDEXED_EVENT_SETS`: the measured event count equals the committed
  count and every listed event index matches one digest in its allowed set.
  Unlisted indexes are skipped.
- `EXTEND_FROM_ZERO`: the authenticated PCR equals one bank-width TPM extend
  from zero. SHA-256 uses `sha256(bytes32(0) || extendValue)`. SHA-384 uses
  `sha384(bytes48(0) || extendValue)`.

The verifier decodes the opaque `comparison` bytes canonically. Every dynamic
mode replays the complete measured event log to the signed PCR value.

The registered and provider-generated PCR rules use the same named block:

```solidity
struct PcrPolicyBlock {
    PcrSpec256[] pcrSpecs256;
    PcrSpec384[] pcrSpecs384;
}
```

Each array is strictly ordered by ascending `pcrIndex`. The SHA-256 bank comes
before the SHA-384 bank. A registry computes and stores this metadata when it
registers a block:

```text
blockHash = keccak256(abi.encode(
    keccak256("CVM_PCR_POLICY_BLOCK_V1"),
    block.pcrSpecs256,
    block.pcrSpecs384
))
```

The metadata also stores the three-byte PCR-selection bitmap for each bank.
`SessionRegistry` combines the stored invariant, variant, and workload block
metadata with the ephemeral provider block metadata. It does not load the
registered comparison blobs to compute these values.

The exact policy proved by `tpm_quote.v1` is:

```text
PolicyCommitment = keccak256(abi.encode(
    keccak256("CVM_TPM_POLICY_COMMITMENT_V1"),
    invariantBlockHash,
    variantBlockHash,
    workloadBlockHash,
    providerBlockHash
))
```

The four block positions define the order. `SessionRegistry` does not merge or
sort rules across blocks. `PolicyCommitment` does not contain the workload,
base-image, platform-profile, or measurement-variant identifiers. Those
identifiers select the stored blocks. `SessionRegistry` independently checks
the selected hierarchy, workload access rule, TEE attributes, and workload
attribute requirements.

The TPM Quote value commitment is:

```solidity
struct PcrCommitment {
    bytes32 pcrSelect;
    bytes32 pcrDigest;
}
```

`pcrDigest` is the exact signed 32-byte TPM Quote `pcrDigest`. `pcrSelect` is a
normalized form of the signed `TPML_PCR_SELECTION`. A valid selection has one
or two unique supported banks, every `sizeofSelect` equals three, the bank
identifiers are strictly ascending, and every selected PCR index is supported.
For each bank, append `uint16 bankId || bytes3 pcrSelectBitmap` in signed Quote
order, then right-pad the result with zero bytes to 32 bytes. The supported
bank identifiers are `TPM_ALG_SHA256 = 0x000b` and
`TPM_ALG_SHA384 = 0x000c`, so the required ascending order is SHA-256 followed
by SHA-384. Within a bank, the three-byte bitmap defines ascending PCR-index
order. The evidence PCR values use that same bank and index order when the
verifier recomputes `pcrDigest`.

`tpm_quote.v1` verifies the TPM Quote signature, `qualifyingData`, signed
selection, signed `pcrDigest`, supplied PCR values, and every rule in the four
blocks. Its journal returns the exact `PolicyCommitment` and
`PcrCommitment`. On-chain `TpmVerifier` computes the expected
`PolicyCommitment` and `pcrSelect` from registry metadata plus the provider
block. It requires exact equality with the journal values. The direct Solidity
path enforces the same `PolicyCommitment`, `pcrSelect`, `pcrDigest`, and rules.

For committed-session verification, the verifier reconstructs the same
provider PCR15 rule that `SessionRegistry` used. GCP Intel TDX uses
`bytes16(0) || UUID`. GCP AMD SEV-SNP uses `REPORT_ID`. AWS AMD SEV-SNP uses
`bytes16(0) || REPORT_ID` for SHA-384 and also uses `REPORT_ID` for SHA-256 in
dual-bank mode. The verifier appends the provider rule after the registered
invariant, variant, and workload rules. It does not replace a published PCR15
rule.

For a fresh AWS AMD SEV-SNP session registration, the portal first creates the
Attestation Key and captures the TPM Quote using the current
`qualifyingData`. It parses the signed Quote selection, enforces the canonical
selection above, constructs `PcrCommitment`, and then requests the AMD SEV-SNP
report with:

```text
REPORT_DATA[0:32] = akPubFingerprint
REPORT_DATA[32:64] = keccak256(abi.encode(
    keccak256("CVM_AWS_REPORT_DATA_PCR_COMMITMENT_V1"),
    pcrCommitment.pcrSelect,
    pcrCommitment.pcrDigest
))
```

The portal places only the domain-separated hash in `REPORT_DATA`; it does not
place the raw 64-byte `PcrCommitment` there. This order is not circular. The
portal does not trust the Quote when it requests the AMD SEV-SNP report. The
later TPM Quote verification authenticates the Quote.

`aws_nitrotpm.v1` verifies the NitroTPM document, certificate chain, signature,
Attestation Key, nonce, document time, exact AMD SEV-SNP report hash, and
NitroTPM PCR15-to-`REPORT_ID` binding. It constructs the NitroTPM
`PcrCommitment` from the normalized selection, supplied selected SHA-256 PCR
values, and signed NitroTPM SHA-384 PCR values. It requires
`REPORT_DATA[0:32]` to equal the verified Attestation Key fingerprint and
`REPORT_DATA[32:64]` to equal the domain-separated hash of that exact
`PcrCommitment`. Its journal returns the complete NitroTPM `PcrCommitment`.

AWS session registration requires exact equality:

```text
verified AMD SEV-SNP REPORT_DATA
    -> hash(NitroTPM PcrCommitment)
    -> NitroTPM PcrCommitment
    == TPM Quote PcrCommitment
    == evidence PcrCommitment
```

This binding applies only to AWS paths that request a fresh AMD SEV-SNP report.
Azure and GCP do not add this binding. A key-rotation path that does not request
a fresh AMD SEV-SNP report cannot create a new AWS `REPORT_DATA` binding.
`PolicyCommitment` remains separate and is never placed in `REPORT_DATA`.

Non-extended events are handled canonically according to their event type and
are not replayed as PCR extensions.

Session verification is synchronous and requires explicit typed trust inputs.
The caller owns all file, snapshot, registry, and RPC retrieval before invoking
the verifier. The verifier does not select sources, fetch missing values, or
record source provenance. Provider trust is supplied in the corresponding
shape: GCP AK roots plus TDX DCAP collateral, GCP AK roots plus AMD ARK roots
for SNP, Azure MAA signing keys, or AWS Nitro roots and document-freshness
limits plus AMD ARK roots and AMD SEV-SNP collateral. Missing, unused,
provider-mismatched, or unsupported trust input is a verification failure.

Production verification samples the system clock once at the top-level
verification entry point. A caller may instead supply a pinned verification
time. Every time-sensitive check uses that single value: Intel TDX DCAP, AMD
SEV-SNP certificates and revocation lists, GCP AK certificates, Azure MAA
signing-key validity, and Azure MAA JWT validity.

The `atakit-attestation-client` crate is the reusable read-only retrieval layer
for callers that select a chain as their trust and collateral source. It
resolves the registry graph, registered base-image and workload policy,
platform root approval, Azure MAA signing keys, and verifier-selected chain
coordinates, then passes the resulting typed values to `atakit-attestation`.
The client does not change the synchronous verifier contract: its RPC endpoint
and `SessionRegistry` are caller inputs, portal evidence cannot select them,
and ordinary JSON-RPC responses are trusted data rather than consensus or
storage proofs.

Azure TLS verification and committed-session verification resolve their MAA
signing keys independently. TLS bootstrap resolves the exact `kid` and `iss`
from the fresh `/tls-attestation` JWT and uses that key only for the fresh TLS
evidence. After `GET /session/evidence-bundle`, atakit parses the MAA JWT from
the committed `SessionContext`, resolves that JWT's exact `kid` through
`SessionRegistry.akCollateralVerifier()`,
`AkCollateralVerifier.maaKeyRegistry()`, and
`MaaKeyRegistry.getMaaSigningKey(keccak256(kid))`, and requires the registry
entry to exist, not be revoked, have an issuer hash matching the exact `iss`,
and satisfy `verification_time <= not_after`. It then verifies the committed
JWT signature with that exact key. The JWT must contain top-level numeric
unsigned 64-bit `iat`, `nbf`, and `exp` claims; nested fields cannot substitute
for them. The claims must satisfy `nbf < exp`, `iat < exp`,
`iat <= verification_time`, and
`nbf <= verification_time < exp`. The fresh TLS MAA key is never a fallback
for the committed session MAA key.

The committed-session MAA failures use these exact codes:

- missing registry entry: `committed_session_maa_key_not_registered`;
- revoked registry entry: `committed_session_maa_key_revoked`;
- expired registry entry: `committed_session_maa_key_expired`;
- issuer mismatch: `committed_session_maa_issuer_mismatch`; and
- invalid JWT signature: `committed_session_maa_signature_invalid`.

When `--azure-maa-key` supplies manual trust, atakit retains every supplied key
through TLS bootstrap and committed-session retrieval. It independently
selects the key that verifies each JWT. A key that verified the fresh TLS JWT
does not authorize a committed-session JWT signed by another key.

Every required cryptographic check is fail-closed. A verifier MUST NOT omit a
check because a required input cannot be parsed or uses an unsupported key
type. In particular, the object certified by TPM Certify MUST parse as an ECC
P-256 `TPMT_PUBLIC`, and its projected SEC1 public key MUST exactly equal
`session_key_delegation.tpm_signing_key.bytes`. A malformed, RSA, non-P-256, or
mismatched certified object is an explicit `tpm-certify-public-key` failure.

The caller also supplies a typed trusted policy containing the workload,
base-image, platform-profile, and measurement-variant IDs, the effective PCR
policy, effective attributes, and attribute requirements. The policy object
inside the evidence bundle is an untrusted projection. Its identifiers must
equal the caller-supplied identifiers. A non-empty PCR-policy projection must
equal the caller-supplied PCR policy; an empty projection supplies no trust and
is permitted because PCR evaluation always uses the caller-supplied policy.
Attribute requirements are likewise evaluated only against caller-supplied
trusted effective attributes.

The offline verifier handles these reserved attributes, then evaluates
ordinary metadata requirements. This changes only the order in which failed
checks appear in the verification report. It uses the same acceptance rules
as the on-chain policy registry, which evaluates ordinary requirements first.

- `atakit.attestation.v1.tee.intel-tdx.debug.enabled`
- `atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed`
- `atakit.attestation.v1.tee.amd-sev-snp.debug.enabled`
- `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled`
- `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum`
- `atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy`

It extracts the applicable states from the cryptographically verified report
and evaluates only the reserved attributes for the selected TEE platform. A
reserved attribute for the other TEE platform is not applied to that session.
Each effective Boolean base-image declaration defaults to `false` when missing
and must equal the verified value. Its matching workload requirement defaults
to `[false]` and must be exactly `[false]` or `[false, true]`.

For Intel TDX, the verifier also converts the raw Intel DCAP TCB status into
the one-hot bit `1 << status`. The effective base-image mask and workload mask
both default to `0x1`, which permits only status `ok`. Each mask must include
`ok`, may contain only bits `0..5`, `8`, and `9`, and must contain the verified
one-hot bit. A measurement-variant mask replaces the matching profile mask.
Raw Intel DCAP statuses 6, 7, and unknown values remain hard failures.

For AMD SEV-SNP, the verifier requires an active registry policy for the exact
signed CPUID. That policy supplies missing values; it is not an independent
mandatory floor. The base-image value is the selected measurement-variant
value, otherwise the platform-profile value, otherwise the registry default.
The workload value is its explicit packed requirement, otherwise the registry
default.

For `tcb.minimum`, the effective value is the component-wise maximum of those
resolved base-image and workload values. For `platform-info.policy`, the
verifier combines the required-set masks and required-clear masks from those
two resolved values and rejects any set-versus-clear conflict. A value below
the registry default takes effect only when both the base-image side and
workload side explicitly replace the default. See
[AMD SEV-SNP Security Policy Specification](amd-sev-snp-security-policy-spec.md).

Custom and hexadecimal attribute requirements keep their existing behavior.

Intel TDX verification permits `DEBUG` at the vendor-verification layer so the
policy can decide it. It still rejects invalid reserved attribute bits,
missing `SEPT_VE_DISABLE`, nonzero Intel TDX 1.5 `MR_SERVICETD`, and TCB
statuses that have no configurable status bit. AMD SEV-SNP verification permits
`POLICY.DEBUG` and `POLICY.MIGRATE_MA` for policy evaluation. It still requires
an exact 1,184-byte report, version 3 through 5, valid signature and key
settings, valid policy-reserved bits, `VMPL=0`, an all-zero or all-`0xff`
`REPORT_ID_MA` no-association sentinel, supported CPUID and `PLATFORM_INFO`,
valid report-version reserved fields, and ordered
reported, committed, and current TCB components.

The effective PCR policy contains both the selected base-image profile and
variant rules and every trusted workload rule. Rules with the same PCR index
remain separate and all are evaluated. The typed workload portion contains
the workload ID, workload PCR rules, and workload attribute requirements.

Binding mode changes only the qualifying-data context and its required shape.
A local-bound hardware session undergoes the same provider, TEE, AK, Quote,
Certify, delegation, and policy checks as a chain-bound session. The production
verification entry point never accepts QEMU or synthetic emulation evidence.
Its successful result explicitly reports `attestation_mode = hardware`.
Emulation is not accepted through an option or flag on the production
verification entry point; any development-only emulation inspection API must
use a separate input and result type and make no hardware-attestation claim.
Neither mode causes the offline verifier to verify owner transaction
authorization.

The current Rust implementation wires these checks for GCP TDX, GCP SNP,
Azure TDX, Azure SNP, and AWS SNP through the shared core. An AWS session uses
`tee_evidence.kind = "configfs_tsm"` and
`ak_evidence.kind = "aws_nitro_doc"`. The verifier authenticates the raw
NitroTPM document, its certificate path and freshness, its Attestation Key and
nonce, its SHA-384 PCR values and PCR15 report binding, the raw AMD SEV-SNP
VLEK report, and the TPM Quote as one chain. It cannot produce a partial
success.

Registration authorization and rotate, renew, and recover authorization are
not properties of a current-session evidence bundle and are not verified or
inferred by this API. The result makes no globally-latest, active, expired, or
revoked claim for either local-bound or chain-bound sessions.

## Domain vectors

These Keccak-256 values are language-independent fixtures:

| Literal | `keccak256(literal)` |
|---|---|
| `ATAKIT_PORTAL_SESSION_NEW_V1` | `0x7168c70277c8a7b699398fd6114474c2b84b71314f9f2cbd7dfbbc9ad17eec47` |
| `ATAKIT_PORTAL_SESSION_ROTATE_KEY_V1` | `0x131c4dde2f0f7d54bd5fb3f1cc3d9300dc1e1aa054b79baabd9a67b99a4ca0f5` |
| `ATAKIT_PORTAL_SESSION_RENEW_V1` | `0x2978650afdb9adc11d86ff3d52adc1fdd5beb8c1541d89c14c781047f0c306bd` |
| `ATAKIT_PORTAL_SESSION_RECOVER_V1` | `0x30fa27810a72ac597fac180cf0923bfe730f1f932849fe48a1bb061d03893258` |
| `CVM_SESSION_ROTATE_KEY_V1` | `0x55997df232b2d66bd3186581c7f2e14645eaab4f3f2639094d98fcec722262bb` |
| `CVM_MSG_SESSION_ROTATE_KEY_V1` | `0x35bc7dbc6065f16ec1a121e394b4def21af016a19a4807eae353231a7b644326` |
| `CVM_SESSION_RENEW_V1` | `0x37c7a989c0f449c8a96b989e27657c5da4e742cd5b0e3dc9d7cb92e21176570e` |
| `CVM_MSG_SESSION_RENEW_V1` | `0xaf6e7c37d438349d2dd85f2d2507703ad2f6893900bae598146eec2dfb6746e8` |
| `CVM_MSG_SESSION_RECOVER_V1` | `0x1382594f92a7140bab1abb4fa585ff7bcd5c3f416a89a7538e819666e0e0d37a` |
| `CVM_MSG_SESSION_REGISTER_V1` | `0xea255740ebc8b92dd501a7abe06ca898a3cafd61398ebb4714aa43e8af8e8aee` |
| `CVM_MSG_SESSION_REVOKE_V1` | `0x66af7e8171a946520ef427c4ee0a0b07ee2ed02f07d45c946717a7982f8c96b5` |
| `ATAKIT_PORTAL_CHALLENGE_AUTHORIZE_V1` | `0x615dcf7f257d94b50571dc2144a8029d0313547676323579115e306670407bec` |
| `ATAKIT_PORTAL_SESSION_REQUEST_BINDING_EVIDENCE_BUNDLE_V1` | `0x334ce29c811caecf694584d7875d7fd2d8d61407750a9064dbc455a846e33a0d` |
| `ATAKIT_PORTAL_SESSION_REQUEST_BINDING_CHAIN_SUBMISSION_V1` | `0xbc939d4f6087dc7de9439f2aaa710264d19507da7ecbcb388b6cbaa10d3cebf8` |

Machine-readable ABI/digest vectors live in
`docs/specs/fixtures/session-attestation-vectors.json` and are consumed by the
Rust and Solidity suites. Changing a literal or tuple shape requires updating
both implementations and this specification in the same change.
