# atakit-verifierd API and Configuration Specification

Status: Implemented

`atakit-verifierd` lets a workload verify the current session of another atakit
portal, or verify a challenge-bound session evidence bundle received through a
caller-owned transport. It uses the same verification code as
`atakit cloud verify-session`. It returns the verified session public key. It
does not exchange application keys, hold workload secrets, submit transactions,
or proxy peer traffic.

## 1. HTTP API

The default listener is `0.0.0.0:9100`. `VERIFIERD_LISTEN` may replace it with another IP address and port.

### 1.1 `POST /v1/verify`

The request body is JSON:

```json
{
  "portal": { "host": "peer.example", "port": 2024 },
  "base_image": "0x1111111111111111111111111111111111111111111111111111111111111111/automata-linux:v0.3.0-debug",
  "workload": "0x2222222222222222222222222222222222222222222222222222222222222222/peer-attestation-demo:v0.0.5"
}
```

All three top-level fields are required. Unknown fields are rejected at both
levels. `portal.host` MUST contain exactly one DNS name or IP address. It MUST
NOT contain a URL scheme, path, query, credentials, port, or surrounding
whitespace. `portal.port` MUST be an integer from 1 through 65535.
`base_image` and `workload` MUST use the canonical
`<publisher>/<name>:<version>` form.

`portal` is untrusted routing input. It selects where verification is
attempted. It does not select the measurement policy, workload policy, trust
anchors, session binding, or accepted identity. Those values come from the
selected trust authority and the verified evidence.

A successful response has HTTP status 200 and this shape:

```json
{
  "verified": true,
  "session_id": "0x...",
  "session_key_fingerprint": "0x...",
  "session_public_key": { "type_id": 3, "key": "0x04..." },
  "workload_id": "0x...",
  "base_image_id": "0x...",
  "binding_mode": "chain",
  "binding_chain_id": 560048,
  "binding_registry": "0x...",
  "attestation_mode": "hardware",
  "sources": { "inputs": {} },
  "checks": []
}
```

The daemon recomputes `workload_id` and `base_image_id` from the requested canonical references. It obtains every other value from the verified portal TLS and session evidence paths.

A malformed request or destination rejected by the destination policy has
HTTP status 400. A failed portal or session verification has HTTP status 422.
When all eight verification slots are occupied, the daemon returns HTTP status
429 without resolving or connecting to the requested portal. A verification
that exceeds 360 seconds returns HTTP status 504. Every failure uses the
`SessionVerificationFailure` shape:

```json
{
  "checks": [],
  "errors": ["reason"]
}
```

When the shared verifier returns a `SessionVerificationFailure`, the daemon MUST return its `checks` and `errors` without translating them into another error format.

Errors produced before portal TLS attestation succeeds MUST NOT return the
remote response body, response headers, certificate bytes, destination DNS
results, or local trust configuration. The daemon returns a fixed error
category instead. This prevents a caller-selected HTTPS service from using an
error response as a read channel.

The maximum `POST /v1/verify` request body is 16 KiB.

### 1.2 `POST /v1/verify-session-bundle`

This endpoint verifies a session evidence bundle already held by the caller. It
does not resolve a portal destination, open a connection to the peer, or perform
portal TLS verification.

The request body is JSON:

```json
{
  "session_evidence": {
    "evidence_bundle": { "format": 2 },
    "request_binding": {
      "challenge": "<32-byte unpadded base64url>",
      "signature": "0x..."
    }
  },
  "expected_challenge": "<32-byte unpadded base64url>",
  "base_image": "0x1111111111111111111111111111111111111111111111111111111111111111/automata-linux:v0.3.0-debug",
  "workload": "0x2222222222222222222222222222222222222222222222222222222222222222/peer-attestation-demo:v0.0.5"
}
```

All four top-level fields are required. Unknown fields are rejected in the
top-level object, `session_evidence`, `request_binding`, and every object inside
`evidence_bundle`. `session_evidence` MUST be the exact JSON shape returned by
`GET /session/evidence-bundle`: one format-2 `evidence_bundle` object and one
`request_binding` object. `evidence_bundle.pcr_values`,
`evidence_bundle.event_log_hashes`, and every PCR policy array are limited to
24 entries. Each `sha256` or `sha384` array inside one event-log entry is
limited to 65,535 hashes, and one bundle is limited to 131,070 event hashes in
total. Every SHA-256 event hash MUST be a `0x`-prefixed 32-byte hexadecimal
value. Every SHA-384 event hash MUST be a `0x`-prefixed 48-byte hexadecimal
value. `expected_challenge` MUST be the canonical unpadded base64url encoding
of exactly 32 bytes. `base_image` and `workload` use the same canonical
reference rules as `POST /v1/verify`.

The daemon resolves the measurement policy, workload policy, and trust anchors
from its configured `chain`, `trust-pack`, or `explicit` authority. Vendor
collateral comes from the existing platform-specific sources. The submitted
`evidence_bundle.policy.platform_profile_id` and
`evidence_bundle.policy.measurement_variant_id` never select trusted policy.
The trusted measurement policy selects exactly one profile by `cloud` and
`tee`, then exactly one variant by `machine_type`; the shared session verifier
compares the submitted identifiers and PCR policy projection with those
independently selected values.

The trust authority does not select a required session binding. The daemon
verifies and reports the session's actual `binding_mode`, `binding_chain_id`,
and `binding_registry`, but does not add a local-versus-chain acceptance
policy. This does not skip binding verification. A chain-bound session still
requires verifier-selected chain coordinates, and its signed chain ID and
`SessionRegistry` address MUST match those coordinates. A caller that relies
on chain registration must separately require a chain-bound session and check
the current registry state when that state matters to its authorization.

The shared session verifier requires `request_binding.challenge` to equal
`expected_challenge`, and verifies that `request_binding.signature` is the
verified session key's signature over the request-binding domain, that
challenge, and the SHA-256 hash of the RFC 8785 canonical `evidence_bundle`.
The response is the same `VerifyResponse` shape returned by
`POST /v1/verify`, including the verified session public key and trust-input
provenance.

Success proves that the submitted session evidence is valid under the selected
authority and that its verified session key signed the exact bundle for the
expected challenge. It does not prove that the session belongs to an IP
address, DNS name, or transport endpoint. A caller that derives
`expected_challenge` from a connection transcript owns the transcript format,
freshness, direction separation, and proof that each participant possesses its
channel private key. A separate portal `/sign-message` signature may bind the
verified session to that channel public key.

A malformed request has HTTP status 400. A failed trust, policy, evidence,
binding, or challenge verification has HTTP status 422. Both verification
endpoints share the same eight verification slots. When all slots are occupied,
the daemon returns HTTP status 429. A request that exceeds the shared 360-second
total limit returns HTTP status 504. Every failure uses the
`SessionVerificationFailure` shape, and a shared-verifier failure is returned
without translation. For `POST /v1/verify-session-bundle`, the daemon acquires
a verification slot and starts the total deadline before collecting or parsing
the request body. It parses the JSON on a blocking worker. If blocking JSON
parsing or synchronous cryptographic verification is still running after an
HTTP 504 response, it continues to occupy its verification slot until the
worker exits. A timed-out worker therefore cannot let the daemon start more
than eight blocking verifications at once.

For `POST /v1/verify`, the portal's successful
`GET /session/evidence-bundle` response is limited to 8 MiB. A non-successful
portal response is limited to 64 KiB. Exceeding either limit fails the request
without buffering the remaining response. The daemon parses a successful
response through the bounded typed bundle before retaining the exact signed
JSON value. It performs that parsing on a blocking worker that keeps its
verification slot until parsing exits, including after an HTTP timeout.

The complete `POST /v1/verify` and `POST /v1/verify-session-bundle`
verification workflows run on permit-owning blocking workers. Those workers
drive asynchronous network requests through the Tokio runtime, but all portal
response parsing, supplied-evidence parsing, base64url, ABI, CBOR, certificate,
quote, policy, and cryptographic processing runs outside Tokio worker threads.
An HTTP timeout detaches a worker instead of stopping it, so the worker keeps
its verification slot until it exits. The portal TLS response and decoded
provider evidence use the structural and size limits in
`tls-attestation-spec.md`.

The maximum `POST /v1/verify-session-bundle` request body is 8 MiB.

### 1.3 `GET /v1/health`

A running process returns HTTP status 200 and `{"status":"ok"}`.

### 1.4 `GET /v1/config`

The response reports:

- `trust_mode`;
- `portal_allowed_ports`;
- `portal_allowed_cidrs`, or `null` when no CIDR restriction is configured;
- loaded trust-pack kind, issuer, revision, validity window, and digest; and
- supported platforms. In `explicit` and `trust-pack` mode this means the loaded coarse trust inputs are complete. In `chain` mode this means the verifier implements the platform; the daemon checks the required registry records for the exact peer during each request.

The response MUST NOT expose the chain RPC URL, Provisioning Certificate Caching Service URL, publisher public keys, or local trust-file paths.

## 2. Dynamic portal destinations

This section applies only to `POST /v1/verify`.

The caller supplies the portal host and port for each request. The daemon
parses the endpoint before it parses the two application references. It then
applies this sequence before opening a portal connection:

1. The port MUST appear in the allowed-port set. The default set is only
   `2024`.
2. A DNS name is resolved once. The daemon selects one permitted socket
   address and retains it for the complete request.
3. Unspecified, multicast, broadcast, and known cloud metadata addresses are
   always rejected.
4. Loopback and link-local addresses are rejected unless an explicit CIDR
   entry permits them.
5. When an allowed-CIDR set is present, the selected address MUST belong to
   that set. When it is absent, public and private unicast addresses are
   accepted.
6. The selected socket address is installed in both the portal TLS bootstrap
   client and the certificate-pinned current-session client. Neither client
   resolves the DNS name again.

Portal HTTP clients MUST NOT follow redirects or use process proxy variables.
Before portal TLS attestation succeeds, the daemon sends only the TLS
handshake and a fixed `GET /tls-attestation?nonce=<fresh-random-nonce>`
request. After portal TLS attestation succeeds, it requests the
challenge-bound current-session evidence through the client pinned to the
attested certificate.

`VERIFIERD_PORTAL_ALLOWED_PORTS` optionally replaces the default port set. Its
value is a nonempty JSON array of nonzero integers. For example:

```text
VERIFIERD_PORTAL_ALLOWED_PORTS=[2024,12024]
```

`VERIFIERD_PORTAL_ALLOWED_CIDRS` optionally restricts resolved addresses. Its
value is a nonempty JSON array of IPv4 or IPv6 CIDR strings. It can also
explicitly permit loopback or link-local verification for a local test. For
example:

```text
VERIFIERD_PORTAL_ALLOWED_CIDRS=["10.0.0.0/8","2001:db8::/32"]
```

These variables restrict network destinations. They are not a trust authority
and MUST NOT alter policy or evidence verification.

This destination policy limits what `atakit-verifierd` can contact. It does
not provide workload-wide exfiltration protection. The CVM portal currently
allows workload containers to make outbound connections. Workload-wide or
per-container outbound restrictions require a separate portal network policy.

The daemon scans the complete environment at startup. Any unknown `VERIFIERD_*` name is an error. This makes a misspelled security setting fail startup instead of being silently ignored.

`VERIFIERD_*` names are reserved in unmeasured env files. Workload archive creation and portal startup MUST reject them there. They may be supplied through measured manifest `environment` or measured `env-file` input.

## 3. One trust authority

`VERIFIERD_TRUST_MODE` is required. It accepts exactly `chain`, `trust-pack`, or `explicit`. It has no default.

The variables for a mode that was not selected are an error. The daemon MUST NOT merge trust inputs from different modes.

`VERIFIERD_TRUST_MODE` selects the trust authority. It does not select the
session binding or a vendor collateral source. The daemon accepts either
binding mode when all normal verification checks succeed. The current
trust-pack and explicit inputs do not contain verifier-selected chain
coordinates. A chain-bound session therefore fails closed under those modes
because its chain claims cannot be authenticated, not because those trust
authorities require local binding.

`VERIFIERD_PCCS_URL` is not a trust authority. It selects a direct HTTP Intel
Provisioning Certificate Caching Service whose vendor-signed collateral is
verified locally. It may be used in every mode. If it is absent, every mode
uses Automata on-chain PCCS through its default collateral RPC endpoint.
Read-only collateral contract calls do not make the registry the measurement
or workload policy authority.

The daemon parses the selected Intel TDX collateral source configuration at
startup. It constructs the source client, queries the source, and constructs
or validates `IntelTdxDcapCollateral` only after a peer presents Intel TDX
evidence. AMD SEV-SNP verification does none of those source operations and
does not reject an otherwise valid Intel TDX source that it never uses.

AMD certificate retrieval remains platform-specific. GCP evidence may carry
VCEK, ASK, and ARK. Azure may retrieve VCEK, ASK, ARK, and certificate
revocation lists from AMD KDS. AWS evidence may carry VLEK and may retrieve
ASVK, ARK, and certificate revocation lists from AMD KDS. Chain mode checks
that SHA-256 of the resolved ARK is approved by `SnpAttestation.rootCerts`.
Trust-pack and explicit modes check the resolved ARK against their configured
roots. There is no AMD on-chain collateral reader.

### 3.1 Chain mode

Chain mode requires:

- `VERIFIERD_RPC_URL`;
- `VERIFIERD_SESSION_REGISTRY`.

`VERIFIERD_CHAIN_ID` is optional. When present, the connected chain ID MUST match it.

Chain mode resolves the base-image measurement policy, workload policy, trust
anchors, and Azure MAA keys from the registry graph rooted at
`VERIFIERD_SESSION_REGISTRY`. It also supplies verifier-selected chain
coordinates for authenticating a chain-bound session. It accepts a valid
local-bound or chain-bound session.

A `.atatp` file in `/atakit-portal/unmeasured-data` is a startup error under
chain mode.

### 3.2 Trust-pack mode

Trust-pack mode requires:

- `VERIFIERD_COLLATERAL_PUBLISHER_PUBKEY`;
- `VERIFIERD_WORKLOAD_PUBLISHER_PUBKEY`;
- at least one `collateral-trust` `.atatp` file; and
- exactly one `workload-trust` `.atatp` file.

The daemon scans regular files ending in `.atatp` directly under `/atakit-portal/unmeasured-data`. It reads every archive through the bounds in the atatp archive specification. It verifies the declared kind with that role's configured key. It then constructs `PackTrustSource` at startup so duplicate or malformed claims fail before the listener starts.

The following optional variables pin the SHA-256 digest of the canonical `trust-pack.json` bytes:

- `VERIFIERD_COLLATERAL_TRUST_PACK_SHA256`;
- `VERIFIERD_WORKLOAD_TRUST_PACK_SHA256`.

A pin applies to every pack of that role. A collateral pin therefore permits only packs with that one digest.

Trust-pack mode rechecks each pack validity window for every verification. It
uses the exact Azure MAA signing certificates in the collateral trust pack.
It does not discover MAA certificates dynamically or fill a missing trusted
root, MAA certificate, policy, or other trust input from registry contracts.
A missing trusted input fails closed. With the current inputs, this mode can
authenticate local-bound sessions but lacks the trusted chain coordinates
needed to authenticate chain-bound claims.

### 3.3 Explicit mode

Explicit mode makes the operator the sole trust authority. It requires:

- `VERIFIERD_MEASUREMENTS`;
- `VERIFIERD_MEASUREMENT_PUBLISHER_PUBKEYS`, a nonempty JSON array of public keys;
- `VERIFIERD_TRUSTED_WORKLOAD_PCR23_SHA256`, exactly 32 bytes as canonical `0x` lowercase hexadecimal; and
- `VERIFIERD_TRUSTED_WORKLOAD_PCR23_SHA384`, exactly 48 bytes in the same form.

The measurement pack signature and its publisher-qualified subject MUST verify. The `base_image` request MUST equal that subject.

Explicit trust files use JSON arrays of paths:

- `VERIFIERD_GCP_AK_ROOT_CERTS`;
- `VERIFIERD_AZURE_MAA_CERTS`;
- `VERIFIERD_AWS_NITRO_ROOT_CERTS`;
- `VERIFIERD_AMD_ARK_ROOT_CERTS`;
- `VERIFIERD_AMD_SNP_CRLS`.

`VERIFIERD_AMD_SNP_SECURITY_POLICY` names one policy file.
`VERIFIERD_TDX_DCAP_COLLATERAL` names one Intel TDX collateral file and cannot
be combined with `VERIFIERD_PCCS_URL`. If neither is present, explicit mode uses
Automata on-chain PCCS when and only when it verifies Intel TDX evidence.

AWS NitroTPM document freshness uses these two variables together:

- `VERIFIERD_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS`;
- `VERIFIERD_AWS_DOCUMENT_ALLOWED_FUTURE_CLOCK_DIFFERENCE_SECONDS`.

Supplying only one is an error.
`VERIFIERD_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS` MUST be greater than zero.
With the current inputs, explicit mode can authenticate local-bound sessions
but lacks the trusted chain coordinates needed to authenticate chain-bound
claims. A `.atatp` file in `/atakit-portal/unmeasured-data` is a startup error
under explicit mode.

## 4. Startup and shutdown

The daemon fully parses its configuration and trust files before binding the HTTP listener. Chain mode also connects to the configured chain before binding. Configuration failure, trust-pack failure, trust-file failure, and chain connection failure stop startup.

The process handles Ctrl-C and, on Unix, SIGTERM by stopping the HTTP listener gracefully.

## 5. Container package

The shipped Linux x86-64 container package MUST contain a static PIE
`atakit-verifierd` executable. The executable MUST have no ELF program
interpreter and no `DT_NEEDED` shared-library entries.

The runtime image MUST be pinned by digest. It MUST run as a non-root user and
provide the certificate bundle named by `SSL_CERT_FILE`, because chain and
off-chain collateral modes make HTTPS requests. The current package uses
`gcr.io/distroless/static-debian12` as user 65532 with
`SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`.
