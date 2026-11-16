# TLS Attestation Specification

This document defines the atakit TLS bootstrap attestation protocol. It is the
cross-repo contract between the in-CVM portal, the `atakit` CLI, and reusable
verification libraries.

The portal serves HTTPS on `:1024` and `:2024` using a self-signed ECDSA P-256
certificate generated inside the CVM. Before this protocol, clients had to use
broad invalid-certificate bypass for first contact. TLS attestation replaces
that with a fail-closed bootstrap:

```
the live TLS certificate is trusted only when a live TPM signs a nonce-bound
quote over that certificate hash, and the quote-signing TPM AK is proven to be
bound to the attested CVM whose PCRs match the expected base-image policy
```

## Status

Version: 2.

The portal emits response format 2. It quotes SHA-256 and SHA-384 PCR0 through
PCR16 and PCR23 in one TPM Quote. It returns the PCR0 `StartupLocality` value
and the ordered SHA-256 and SHA-384 event hashes used for dynamic policy.

The verifier requires measurement-pack version 3 and evaluates the bank or
banks named by `pcrBankSelection`. It supports `STATIC`, `DYNAMIC_SUBSET`,
`DYNAMIC_SUBSEQUENCE`, `DYNAMIC_INDEXED_EVENT_SETS`, and `EXTEND_FROM_ZERO` in
both banks through the canonical opaque `comparison` blob. It verifies the
signed Quote selection and `pcrDigest` before applying policy.

Automatic trust supports GCP Intel TDX, GCP AMD SEV-SNP, Azure Intel TDX,
Azure AMD SEV-SNP, and AWS AMD SEV-SNP with NitroTPM when the caller supplies
the required trusted roots, collateral, revocation data, and measurement
policy. AWS verification authenticates the raw NitroTPM document and AMD
SEV-SNP VLEK report, then checks their shared Attestation Key, nonce, and PCR
bindings. On-chain AWS verification uses `amd_sev_snp.v1`,
`aws_nitrotpm.v1`, and the bank-aware TPM Quote path defined in
[registry reference](https://github.com/automata-network/automata-tee-workload-measurement).

QEMU and unknown platforms are not production trust evidence. Any development
bypass must be explicit and separate from the production verifier result.

## Goals

- Bind the first-contact self-signed TLS certificate to an attested CVM.
- Work before `/init`, including when `chain.registration = "off"`.
- Avoid relying on TEE `report_data` for TLS certificate binding, because Azure
  already uses report data for HCL `var_data`.
- Reuse the existing TEE-to-vTPM binding mechanisms where possible.
- Produce structured diagnostics on failure so operators can inspect PCRs,
  evidence, selected measurements, and the certificate before making a manual
  decision.
- Provide verification logic as a reusable library so other CLIs can consume the
  same protocol.

## Non-goals

- Do not replace session attestation. TLS attestation is a pre-init TLS bootstrap
  protocol; `/session/evidence-bundle` is the post-init session evidence
  surface.
- Do not persist manual TLS overrides in version 2.
- Do not define a measurement-pack archive format in version 2. Measurement packs are
  signed JSON with a detached signature.
- Do not trust the portal-reported `base_image_id` as proof of identity. The
  normal chain-backed path uses it only as an untrusted lookup key for the
  configured `BaseImageRegistry`. The verifier accepts that identity only
  after the returned policy verifies the attested measurements.

## Endpoint

TLS attestation is exposed on the persistent portal HTTPS port:

```text
GET /tls-attestation?nonce=<base64url-32-byte-random>
```

The endpoint is available before `/init` and remains available after `/init`.
It uses the same self-signed TLS certificate as all other portal endpoints.

Request rules:

- `nonce` is mandatory.
- The nonce value is exactly 32 random bytes encoded as base64url without
  padding.
- Missing, malformed, padded, or wrong-length nonce returns `400 Bad Request`.
- The nonce is not secret. It is a freshness challenge and may appear in logs.

The endpoint MUST NOT accept a default nonce. The verifier MUST reject evidence
whose response nonce differs from the request nonce.

## TLS Bootstrap Binding

The portal asks the TPM to quote PCRs with this `qualifying_data`:

```text
qualifying_data = H(ATAKIT_TLS_BOOTSTRAP_V1, nonce, tls_cert_sha256)
```

Where:

- `H` is the protocol hash function used for TPM quote challenge construction.
  Implementations SHOULD use Keccak-256 over ABI-style typed inputs when
  sharing code with existing atakit trust-chain helpers; the exact encoding MUST
  be fixed in code and tests before v1 is finalized.
- `ATAKIT_TLS_BOOTSTRAP_V1` is the domain separator. It prevents evidence for
  TLS bootstrap from being confused with session-registration evidence.
- `nonce` is the decoded 32-byte client challenge.
- `tls_cert_sha256` is SHA-256 over the DER-encoded leaf TLS certificate served
  by the portal on the current connection.

The CVM report does not need to contain the TLS certificate hash. The verifier
gets the binding through this chain:

```
live TLS cert
  -> SHA-256 hash included in TPM quote qualifying_data
TPM quote
  -> signed by vTPM AK
vTPM AK
  -> proven to belong to the CVM by CSP-specific TEE/vTPM binding
CVM report
  -> verified against CSP attestation roots/collateral
PCRs
  -> quoted by the same AK and checked against trusted measurements
```

Verifier invariant:

```text
The verifier MUST NOT trust tls_cert_sha256 unless the TPM quote signs the
expected qualifying_data and the same quote-signing AK is proven to belong to
the attested CVM report.
```

## Response

All binary fields are base64url without padding. Hashes and digests are `0x`
prefixed lowercase hex.

```json
{
  "format": 2,
  "nonce": "<base64url-32-byte-random>",
  "tlsCertDer": "<base64url>",
  "tlsCertSha256": "0x...",
  "qualifyingData": "0x...",
  "platform": {
    "cloud": "gcp",
    "cloudProvenance": {
      "source": "dmi",
      "detection": {
        "dmi": {
          "sys_vendor": "Google",
          "product_name": "Google Compute Engine",
          "bios_vendor": "Google",
          "detected_cloud": "gcp"
        },
        "metadata": {
          "gcp": {"attempted": true, "matched": true, "http_status": 200, "response_headers": {"metadata-flavor": "Google"}, "response_body": "instance/\nproject/\n", "error": null},
          "azure": {"attempted": false, "matched": false, "http_status": null, "response_headers": {}, "response_body": null, "error": null},
          "aws": {"attempted": false, "matched": false, "http_status": null, "response_headers": {}, "response_body": null, "error": null},
          "detected_cloud": "gcp",
          "conflict": false
        }
      },
      "user_provided": null
    },
    "tee": "tdx",
    "machineType": "c3-standard-4"
  },
  "tpm": {
    "akPublic": "<base64url>",
    "quote": "<base64url>",
    "signature": "<base64url>",
    "pcr0StartupLocality": 0,
    "pcrs": [
      {
        "index": 0,
        "sha256": "0x...",
        "sha384": "0x..."
      }
    ],
    "eventLogHashes": [
      {
        "pcrIndex": 0,
        "sha256": ["0x..."],
        "sha384": ["0x..."]
      }
    ]
  },
  "teeEvidence": {
    "kind": "configfs-tsm",
    "report": "<base64url>"
  },
  "akBinding": {
    "kind": "gcp-cert-chain",
    "data": "<base64url>"
  },
  "collateral": {}
}
```

Field semantics:

| Field | Description |
|---|---|
| `format` | Response schema version. Version 2 MUST be `2`. |
| `nonce` | Echo of the request nonce. |
| `tlsCertDer` | DER bytes of the portal TLS leaf certificate. |
| `tlsCertSha256` | SHA-256 over `tlsCertDer`. |
| `qualifyingData` | Digest passed to the TPM quote. Returned for diagnostics; verifier recomputes independently. |
| `platform.cloud` | `gcp`, `azure`, `aws`, `qemu`, or `unknown`. |
| `platform.cloudProvenance` | Source authorizing `platform.cloud`; raw DMI and bounded CSP-specific metadata observations; detector inferences; and the exact accepted operator declaration. AWS IMDSv2 tokens are excluded. Detector inferences are provenance, not independently actionable cloud values. |
| `platform.tee` | `tdx`, `sev-snp`, `none`, or `unknown`. NitroTPM is not a TEE type. |
| `platform.machineType` | Machine type from the same platform detection source used by `/status`; may be `unknown`. |
| `tpm.akPublic` | Public area or public-key bytes for the quote-signing AK, using the same representation the verifier consumes for the CSP binding. |
| `tpm.quote` | TPM attestation structure for PCR quote. |
| `tpm.signature` | TPM signature over the quote. |
| `tpm.pcr0StartupLocality` | `0` through `4` for the single valid PCR0 `StartupLocality` event, or `255` when the event is absent. |
| `tpm.pcrs` | PCR values reported with the quote. The verifier authenticates the exact SHA-256 and SHA-384 bank/index pairs selected by the signed quote. A reported value from an unselected bank is diagnostic only and cannot satisfy PCR policy. |
| `tpm.eventLogHashes` | Ordered per-PCR SHA-256 and SHA-384 extend-event digests. Both arrays are always present. |
| `teeEvidence` | CSP/TEE report bytes and vendor auxiliary material. |
| `akBinding` | CSP-specific material that binds the AK to the CVM report. |
| `collateral` | Additional endpoint-provided verifier inputs that do not fit the stable fields. The portal sends an empty object for Intel TDX. Implementations SHOULD keep this sparse and documented per `kind`. |

Verifier input limits are part of this format. A verifier accepts at most 24
entries in `tpm.pcrs` and 24 entries in `tpm.eventLogHashes`. Each SHA-256 or
SHA-384 event-hash array accepts at most 65,535 hashes, and one response
accepts at most 131,070 event hashes in total. Every SHA-256 event hash is a
`0x`-prefixed 32-byte hexadecimal value. Every SHA-384 event hash is a
`0x`-prefixed 48-byte hexadecimal value. The encoded `collateral` JSON value
is limited to 64 KiB.

Provider evidence is also bounded before secondary parsing. A decoded Intel
TDX quote is limited to 1 MiB. A decoded AMD SEV-SNP report is limited to 64
KiB, while its decoded certificate table remains limited to 1 MiB. A decoded
GCP AK binding is limited to 4 MiB and may contain at most 16 certificates,
each limited to 1 MiB. A decoded Azure MAA binding is limited to 1 MiB; its
decoded JWT header is limited to 16 KiB, its decoded claims are limited to 1
MiB, and Azure HCL data may contain at most 16 keys. A decoded AWS NitroTPM
document is limited to 256 KiB.

For Intel TDX, `teeEvidence.report` is the exact Intel TDQUOTE encoded as
base64url without `=` characters. It is not JSON inside the base64url value.
The decoded TDQUOTE ends immediately after the number of signature-data bytes
declared by its little-endian signature-data length field.

A provider adapter MAY receive a fixed-size buffer with zero bytes after the
declared TDQUOTE. The provider adapter MUST require the complete declared
TDQUOTE, reject any nonzero trailing byte, and remove all trailing zero bytes
before constructing portal evidence. After that acquisition boundary, every
producer and verifier MUST reject any trailing byte and MUST NOT truncate the
evidence it receives.

- GCP and AWS use `teeEvidence.kind = "configfs-tsm"`. `teeEvidence.report`
  contains the exact TDQUOTE extracted from configfs-tsm `outblob`, after the
  provider adapter removes permitted trailing zero bytes.
  `teeEvidence.auxiliary` is absent.
- Azure uses `teeEvidence.kind = "azure-tdx"`. `teeEvidence.report` contains
  the TDQUOTE returned by Azure IMDS `/acc/tdquote`.
  `teeEvidence.auxiliary` contains the HCL `var_data` bytes as unpadded
  base64url.

The verifier accepts Intel DCAP quote version 4 or 5 with
`tee_type = 0x00000081`. Both versions start with a 48-byte quote header.
Version 4 then carries a 584-byte TDREPORT10 body. Version 5 adds a 6-byte
little-endian body header: a 2-byte body type and 4-byte body size. Body type
`2` carries a 584-byte TDREPORT10. Body type `3` carries a 648-byte
TDREPORT15. The body is followed by a 4-byte little-endian signature-data
length and that many Intel DCAP signature-data bytes.

For Intel TDX on GCP or Azure, the portal does not fetch public DCAP
collateral; it returns local evidence only. The verifier resolves the
vendor-verification material before calling the reusable verification library.
Supported source shapes:

- an explicit offline `atakit.intel-tdx-dcap-collateral` version 1 JSON file;
- a direct HTTP PCCS/PCS URL, including Intel PCS, CSP PCCS, or an operator-run
  PCCS;
- Automata on-chain PCCS, accessed through chain RPC and DAO contract calls
  rather than the HTTP PCCS API. Automata is a collateral source only: the
  verifier reads raw Intel collateral from chain, constructs an in-process
  `IntelTdxDcapCollateral`, and runs Automata `dcap-rs` over the endpoint's TDX
  quote. The verifier MUST NOT accept an opaque on-chain "verified" DCAP output
  as a substitute for local quote verification.

The Intel TDX collateral source is independent of the measurement and workload
policy authority. A verifier using explicit policy or trust-pack policy MAY
query Automata on-chain PCCS for vendor-signed Intel collateral. That query
MUST NOT read a base-image measurement policy or workload policy from registry
contracts. The verifier MUST select and validate the Intel TDX collateral
source only after the response declares Intel TDX evidence; AMD SEV-SNP
verification does not touch an unused Intel TDX collateral source.

The default Automata resolver uses Hoodi
`https://ethereum-hoodi-rpc.publicnode.com`. Contract addresses and versioned
DAO mappings come from the `automata-dcap-network-registry` dependency data at
Automata DCAP commit
`b710da2ba804d5ced51798f1aabc0b67537c739d`. `atakit` MUST NOT maintain a
second hard-coded DAO table. `PccsReader` selects the registry entry by the RPC
chain ID and resolves the standard Intel TCB evaluation data number before
reading versioned FMSPC TCB and enclave identity data.

The reusable verifier accepts `IntelTdxDcapCollateral` as a typed input that is
separate from `TlsAttestationResponse`. It parses the collateral once and keeps
the parsed `dcap_rs::types::collateral::Collateral` in an `Arc`. An `Arc` is a
shared, reference-counted pointer. This avoids parsing the same immutable
collateral again when TLS verification passes it to session verification. This
is process-scoped reuse, not a time-based or persistent cache. Every quote
verification still checks the collateral signatures, certificate revocation
lists, validity times, and freshness against the verifier's one sampled
verification time.

The typed value records the quote's FMSPC, PCE ID, PCK CA type, and resolver
selection. The resolver selection is `standard`, `early`, or an explicit TCB
evaluation data number. An explicit number must equal the evaluation data
number in the signed TCB Info. The typed value also records the signed TCB Info
and QE Identity evaluation data numbers. The current implementation does not
keep an index or persistent cache. A caller MUST NOT reuse the parsed value for
a quote whose FMSPC, PCE ID, or PCK CA type differs.

`--tdx-dcap-collateral` accepts only the following version 1 file format:

```json
{
  "schema": "atakit.intel-tdx-dcap-collateral",
  "version": 1,
  "selector": {
    "fmspc": "001122334455",
    "pceId": "0000",
    "pckCa": "processor",
    "tcbEvaluationDataNumber": 17,
    "qeIdentityEvaluationDataNumber": 17
  },
  "payload": {
    "rootCaCrlDer": "<unpadded-base64url>",
    "pckCrlDer": "<unpadded-base64url>",
    "issuerChainDer": [
      "<unpadded-base64url DER certificate>",
      "<unpadded-base64url DER certificate>"
    ],
    "tcbInfoSignedJson": "<unpadded-base64url complete UTF-8 signed response>",
    "qeIdentitySignedJson": "<unpadded-base64url complete UTF-8 signed response>"
  }
}
```

All fields are required. Unknown fields are rejected. `fmspc` and `pceId` use
lowercase hexadecimal with exact lengths of 12 and 4 characters. `pckCa` is
`processor` or `platform`. Payload values use canonical unpadded base64url.
The whole document is limited to 16 MiB. Each decoded payload component is
limited to 4 MiB. `issuerChainDer` must contain between one and eight DER
certificates. The selector must match the quote and the evaluation data
numbers inside the signed JSON responses. The signed inner `tcbInfo` and
`enclaveIdentity` JSON bytes must stay unchanged because each signature covers
those exact bytes. The former
`dcap_qvl::QuoteCollateralV3` JSON form, native Automata
`dcap_rs::types::collateral::Collateral` JSON form, and
`collateral.gcpTdxDcap` wrapper are not accepted.

HTTP PCCS and Automata on-chain PCCS results are not serialized into
`TlsAttestationResponse` or an intermediate `serde_json::Value`; the resolver
constructs `IntelTdxDcapCollateral` directly. A caller can use
`IntelTdxDcapCollateral::to_file_json` to write the version 1 file. The writer
pins the signed evaluation data numbers, uses lowercase selector hexadecimal,
and uses canonical unpadded base64url for every payload field.

For AMD SEV-SNP, the reusable verifier accepts a typed
`AmdSnpVerificationCollateral` input. GCP supplies its certificate table in
`teeEvidence.auxiliary`. For Azure, `atakit-cloud` fetches the VCEK and
ASK/ARK certificate chain from AMD Key Distribution Service during each TLS
bootstrap operation. `atakit-cloud` also fetches the current signer-specific
AMD certificate revocation list unless the operator supplies `--amd-snp-crl`.
It uses `/vcek/v1/{product}/crl` for a VCEK-signed report and
`/vlek/v1/{product}/crl` for a VLEK-signed report. The short-lived verification
context may pass that exact typed value from TLS verification to session
verification in the same command. Session verification checks certificate and
revocation validity again against its current verification time. The portal
does not fetch AMD public collateral. The resolver does not insert AMD
certificates or certificate revocation lists into
`TlsAttestationResponse.collateral`.

The decoded AMD SEV-SNP certificate table is limited to 1 MiB and 64 entries.
It must contain a complete zero terminator. Certificate ranges must start after
the header, must not overlap, and must not repeat ARK, ASK, VCEK, or VLEK
entries. The `SNP_CERT_TABLE_ASK_GUID` entry carries the signer-matching
intermediate CA: ASK for VCEK, or ASVK for VLEK. The verifier accepts the VLEK
specification's `SEV-VLEK` ASVK common name and the current AMD Key
Distribution Service form `SEV-VLEK-{product}`. Unknown certificate types
remain allowed for format extension and are not copied into
`AmdSnpVerificationCollateral`.

The ARK inside `AmdSnpVerificationCollateral` is only the candidate root for
the presented certificate chain. `TrustAnchors.amd_ark_roots` or
`TrustAnchors.amd_ark_root_hashes` must separately approve the exact ARK. The
certificate revocation lists belong to `AmdSnpVerificationCollateral`, not
`TrustAnchors`. The resolver performs no process-wide or persistent AMD
collateral caching.

For Automata on-chain PCCS, `PccsReader` performs read-only `eth_call`
requests to obtain the same collateral a PCCS HTTP server would return:

1. Parse the endpoint TDX quote.
2. Extract the embedded PCK certificate chain, FMSPC, and PCK CA type.
3. Select the Automata deployment from the RPC chain ID.
4. Read the current standard TDX TCB evaluation number from
   `TcbEvalDao.standard(1)`.
5. Select the versioned FMSPC TCB DAO and enclave identity DAO for that TCB
   evaluation number.
6. Read the Intel root CA, TCB signing CA, PCK CA certificate and CRLs, TDX TCB
   info, and TD_QE identity.
7. Construct the typed `IntelTdxDcapCollateral` verifier input.
8. Parse the quote and collateral with Automata `dcap-rs`, then call
   `verify_dcap_quote_with_policy_ref` with
   `DcapVerificationPolicy::production().with_tdx_tcb_revocation_policy(
   TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch)`.

Automata `dcap-rs` keeps
`TdxTcbRevocationPolicy::IntelQvlCompatible` as the default for existing API
callers. That default follows the fully matched SGX/PCE/TDX row in TDX TCB
Info, as Intel QVL does. `atakit` selects
`TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch` so it also rejects a
`Revoked` or `Unspecified` status from the first row whose SGX/PCE fields match
the PCK certificate, before the TDX fields are considered. This stricter check
does not fetch separate SGX TCB Info.

`--tdx-dcap-automata-read-strategy direct-concurrent` is the default.
`PccsReader` starts the three PCS certificate reads and the standard TCB
evaluation lookup together. It starts the TDX TCB and TD_QE reads together
after the evaluation number is known.

`--tdx-dcap-automata-read-strategy multicall3` uses the standard Multicall3
address. `--tdx-dcap-automata-multicall3-address <ADDRESS>` overrides that
address. A failed Multicall3 batch falls back to direct concurrent calls. A
failed call inside a successful batch is retried once as a direct call.

The reusable verifier accepts only typed `IntelTdxDcapCollateral`. Endpoint
response collateral and opaque Automata verification-output wrappers are not
Intel TDX DCAP collateral inputs.

When registration is enabled and a SessionRegistry is configured, the CLI may
also resolve trust anchors from Automata contracts before calling the reusable
verifier:

| Evidence | Endpoint provides | Chain lookup | Local verifier use |
| --- | --- | --- | --- |
| GCP AK cert chain | Leaf-to-root AK X.509 chain in `akBinding` | `SessionRegistry.akCollateralVerifier() -> AkCollateralVerifier.tpmAttestation() -> TpmAttestation.verifiedCA(keccak256(root_der))` | Verify the full AK chain locally and accept the root by hash. |
| Azure MAA JWT | MAA JWT and HCL `varData` in `akBinding` | `SessionRegistry.akCollateralVerifier() -> AkCollateralVerifier.maaKeyRegistry() -> MaaKeyRegistry.getMaaSigningKey(keccak256(kid))` | Verify JWT locally against the registered signing key and issuer hash. |
| AMD SEV-SNP ARK | ARK/intermediate-CA/VEK cert table in `teeEvidence.auxiliary` | `SessionRegistry.teeVerifier() -> TeeVerifier.snpAttestation() -> SnpAttestation.rootCerts(processorModel)` | Verify ARK -> ASK -> VCEK or ARK -> ASVK -> VLEK, then verify the SNP report locally and accept the ARK root by SHA-256 hash. |

If registration is off, these chain lookups are disabled. Operators must then
provide local trust roots/collateral explicitly, or inspect the failure report
and use the manual `--trust-tls-cert-sha256` override.

The wire response SHOULD use the same lower-level evidence encodings as existing
portal endpoints where possible, but TLS attestation has a separate top-level
schema so it can be consumed without first initializing the portal.

## Verification Algorithm

The verifier MUST run all reachable checks and produce a structured
`VerificationReport`. It SHOULD avoid failing at the first error unless a field
is missing in a way that makes later parsing impossible.

Required checks:

1. Capture the live peer TLS certificate from the bootstrap connection.
2. Decode and validate the response schema.
3. Verify `response.nonce == request.nonce`.
4. Hash `tlsCertDer` and verify it equals `tlsCertSha256`.
5. Hash the live peer certificate and verify it equals `tlsCertSha256`.
6. Recompute `qualifyingData`.
7. Verify the TPM quote signature under the returned AK.
8. Verify the TPM quote binds the expected `qualifyingData`.
9. Parse every bank selection in the quote. Accept one bank, or SHA-256 followed
   by SHA-384. Reject SHA-384 followed by SHA-256, unsupported selected banks,
   missing selected values, duplicate bank selections, and PCR indexes other
   than 0 through 16 or 23. Rebuild the quote PCR digest from selected values in
   quote selection order. The current ECDSA/SHA-256 and RSASSA/SHA-256 AK
   schemes produce a 32-byte SHA-256 `pcrDigest`.
10. Verify the CSP-specific AK-to-CVM binding.
11. Verify the CVM report against CSP trust anchors and collateral.
12. Resolve the expected measurement policy.
13. Select the base-image platform profile and variant.
14. Verify only the authenticated bank/index projection from step 9 satisfies
    the selected policy. Static and dynamic rules may match a selected SHA-256
    or SHA-384 value. Each dynamic rule replays the matching bank's ordered
    event hashes to the Quote-authenticated final PCR value.
15. Extract the verified TEE attribute states and require them to match the
    effective base-image declarations.
16. If the caller supplied a workload manifest, apply its measured
    `config.attributes` requirements. If no workload is selected yet, apply
    the resolved base-image policy by itself. Boolean base-image values still
    default to `false`, Intel TDX TCB status still defaults to `ok`, and a
    missing AMD SEV-SNP packed base-image value resolves to the active
    exact-CPUID registry default.
17. Return a pinned TLS identity containing the DER cert and cert hash.

Every later Portal TLS connection, including reconnects, MUST present the exact
DER certificate accepted in step 17. The client MUST reject any other
certificate before sending HTTP requests or secrets. A certificate issued by a
public certificate authority, or a replacement certificate using the same key,
does not satisfy this requirement. Public root certificates MUST NOT provide a
fallback trust path.

The client MUST still verify the TLS handshake signature and certificate
validity. Hostname matching is not required for this connection: attestation
authenticates the exact certificate, and clients may connect to the Portal by IP
address. A new certificate requires a new attestation or the existing explicit
certificate override flow.

If any required check fails, the verifier fails closed unless the caller
supplies a one-shot cert override that exactly matches the live peer cert hash.

## CSP Binding Rules

### GCP

Portal response:

- TEE report from configfs-tsm (`TDQUOTE` for TDX or `SNP_REPORT` for SEV-SNP).
  GCP TDX requests the quote with `report_data[0..16]` set to the UUID from
  `/proc/uuid_tdx`, matching the existing chain-registration path.
- vTPM AK certificate leaf from TPM NV `0x01c10002`.
- AK certificate chain fetched by AIA walk, leaf to root.
- TPM quote signed by the vTPM AK.

Verifier rules:

- Validate the AK certificate chain to trusted Google/GCP roots.
- Verify the TPM quote under the AK public key from the AK certificate.
- Verify the existing TEE-to-vTPM PCR15 binding:
  - TDX: PCR15 commits to the TDX quote UUID/report-data binding value.
  - SEV-SNP: PCR15 commits to `SNP_REPORT.report_id`.
- Verify the TEE report using the appropriate vendor collateral:
  - SEV-SNP: parse the AMD aux cert table, require `ARK + ASK + VCEK` or
    `ARK + ASVK + VLEK`, require the ARK DER to exactly match a trusted
    `--amd-ark-root-cert`, verify the signer-matching
    ARK/intermediate-CA/VEK RSA-PSS/SHA-384 certificate signatures, verify VEK
    TCB extensions against `SNP_REPORT.reported_tcb`, verify the VCEK chip-id
    extension against `SNP_REPORT.chip_id`, and verify the report ECDSA-P384
    signature under the VEK public key.
  - TDX: borrow the parsed Automata
    `dcap_rs::types::collateral::Collateral` from the verifier-resolved
    `IntelTdxDcapCollateral` and verify the parsed quote with
    `DcapVerificationPolicy::production()` configured with
    `TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch`. The production
    policy permits `DEBUG` at this vendor-verification layer so the trusted
    base-image attribute policy can decide it. It rejects non-zero TDX 1.5
    migration service TD measurements, reserved TDX attribute bits, reports
    without `SEPT_VE_DISABLE`, and revoked or unspecified preliminary SGX/PCE
    matches. It returns fully matched Intel DCAP TCB statuses 0 through 5, 8,
    and 9 as one-hot policy bits. Statuses 6, 7, and unknown values fail closed.
    Missing or invalid collateral fails closed at `gcp-tee-vendor-report`.
- Verify measurement PCRs against the selected base-image profile.
- Extract the applicable verified TEE attributes from the signed report.
  Merge trusted profile and variant attributes, with variant values replacing
  profile values. Evaluate only reserved attributes for the selected TEE
  platform. A missing reserved Boolean value means `false`, and the trusted
  declaration must equal the verified state. For Intel TDX, require the
  verified one-hot TCB status bit to appear in the effective base-image mask.
  The mask defaults to `ok` only. A measurement-variant mask replaces the
  matching profile mask. Before
  sending `POST /init`, apply the selected workload manifest's measured
  `config.attributes` requirements. A missing reserved Boolean requirement
  permits only `false`; a missing Intel TDX TCB requirement permits only `ok`.
  For AMD SEV-SNP, resolve the active registry default for the report's exact
  CPUID. Resolve the base-image value from the selected measurement variant,
  then platform profile, then that registry default. When a workload is
  selected, resolve its value from an explicit requirement or the registry
  default and combine the two resolved sides. When no workload is selected,
  apply only the resolved base-image side.
  Apply ordinary custom attribute requirements against the same effective
  attribute set. Compute the requirements and an archive digest from the same
  byte snapshot, then require the bytes loaded for `POST /init` to match that
  digest.

### Azure

Portal response:

- MAA JWT for the CVM report.
- Raw HCL `var_data`.
- HCLAk public material.
- TPM quote signed by HCLAk.

Verifier rules:

- Validate the MAA JWT signature using the expected MAA signing keys.
- Validate MAA claims, including issuer/audience rules chosen by the trust
  anchor configuration.
- Require top-level numeric unsigned 64-bit `iat`, `nbf`, and `exp` claims.
  Nested fields cannot substitute for them. Require
  `nbf < exp`, `iat < exp`, `iat <= verification_time`, and
  `nbf <= verification_time < exp`.
- Verify the MAA report-data prefix equals `sha256(hclVarData)`.
- Require `teeEvidence.auxiliary` to equal the same `hclVarData`.
- Require the signed TDX or SEV-SNP report's `report_data` to equal
  `sha256(hclVarData) || zeros_32`.
- Verify the raw report with the selected vendor:
  - TDX: parse the quote and verify it with resolved DCAP collateral under the
    same production policy and TCB acceptance rules as GCP TDX.
  - SEV-SNP: resolve the AMD ARK/ASK/VCEK certificate chain, verify the
    certificate chain and VCEK revocation list, and verify the report
    signature.
- Parse HCLAkPub from `hclVarData`.

Production verification samples the system clock once at the top-level
verification entry point. Callers that need pinned-time verification supply
that time explicitly. Intel TDX DCAP, AMD SEV-SNP certificates and revocation
lists, GCP AK certificates, Azure MAA signing-key validity, and Azure MAA JWT
validity all use that same verification time.
- Verify the TPM quote under HCLAkPub.
- Verify measurement PCRs against the selected base-image profile.
- Extract verified TEE attribute states from the signed report. Merge trusted
  profile and variant declarations, evaluate only reserved attributes for the
  selected TEE platform, require each applicable declaration to match the
  verified state or status, and apply the selected workload manifest's
  measured `config.attributes` requirements before sending `POST /init`.
  Missing reserved requirements use the same safe defaults as GCP. Compute the
  requirements and an archive digest from the same byte snapshot, then require
  the bytes loaded for `POST /init` to match that digest.

AMD SEV-SNP policy resolution uses the active
`AmdSnpSecurityPolicyRegistry` record for the report's exact CPUID. The
offline verifier obtains it from
`SessionRegistry.teeSecurityPolicyVerifier()`,
`TeeSecurityPolicyVerifier.amdSnpSecurityPolicyRegistry()`, and
`AmdSnpSecurityPolicyRegistry.getActivePolicy(cpuid)`, or receives the same
record from the explicit `--amd-snp-security-policy` version 1 JSON file.
These are the chain and explicit authorities, never both at once, so there is
no precedence between them. Evidence cannot choose this policy. The file is read for the current command and is not
cached or persisted.
Missing, inactive, duplicate, unsupported, or mismatched CPUID policy fails
closed.

The offline verifier always applies the registry record's
`requiredLaunchMitigationVector` and `requiredCurrentMitigationVector`. If
either mask is nonzero, the signed report must be version 5. Each signed
vector must contain every bit in its matching required mask. Base-image and
workload policy cannot replace these masks.

The registry record supplies missing values; it is not an independent
mandatory floor. The effective base-image value comes from the selected
measurement variant, then the platform profile, then the registry default. If
a workload is present, its explicit value replaces its registry default, and
the verifier applies both resolved sides. When no workload is present, TLS
verification applies the resolved base-image value by itself. For
`tcb.minimum`, combining two sides means a component-wise maximum. For
`platform-info.policy`, it means combining required-set and required-clear
masks and rejecting conflicts. See
[AMD SEV-SNP Security Policy Specification](amd-sev-snp-security-policy-spec.md).
Intel TDX `TD_ATTRIBUTES.PERFMON` remains a future policy candidate.

Azure HCLAk TPM operations use the persistent HCLAk with empty-password USER
auth. They do not require EK-derived `PolicySecret`.

### AWS

The offline verifier requires `platform.cloud = "aws"`,
`platform.tee = "sev-snp"`, and `teeEvidence.kind = "configfs-tsm"`. It:

1. parses the raw untagged COSE_Sign1 NitroTPM document and requires its
   protected ES384 header, `SHA384` digest declaration, and complete PCR0
   through PCR23 map;
2. verifies the NitroTPM certificate path, trusted root, COSE signature, and
   signed-document freshness at one verifier-selected time;
3. requires `doc.nonce` to equal the TLS `qualifyingData`;
4. requires the P-256 SubjectPublicKeyInfo in `doc.public_key` to equal the
   quoted TPM Attestation Key;
5. requires AMD SEV-SNP `REPORT_DATA[0..32]` to equal the canonical ES256
   Attestation Key fingerprint and `REPORT_DATA[32..64]` to equal 32 zero
   bytes;
6. requires NitroTPM SHA-384 PCR15 to equal
   `SHA384(bytes64(0) || REPORT_ID)`;
7. constructs the normalized NitroTPM `PcrCommitment`, requires it to equal
   both the authenticated TPM Quote `PcrCommitment` and evidence
   `PcrCommitment`, and requires SHA-384 PCR15; and
8. verifies the raw AMD SEV-SNP report and VLEK certificate chain under the
   caller-supplied AMD ARK trust and revocation data.

Fresh AWS session registration uses the stronger `REPORT_DATA[32..64]`
`PcrCommitment` hash defined by
[Session Attestation Specification](session-attestation-spec.md). The TLS
bootstrap endpoint keeps its separate Attestation-Key-only `REPORT_DATA`
format.

The caller may resolve the trusted Nitro root hash and signed-document
freshness limits from its selected `SessionRegistry`. Portal evidence cannot
select those values.

### QEMU and Unknown Platforms

Version 2 production verifier behavior:

- Return unsupported or untrusted.
- A development bypass, if added later, MUST require an explicit flag and MUST
  not share the same success type as production TLS attestation.

## Measurement Policy

TLS attestation needs a trusted base-image measurement policy even when chain
registration is disabled.

Naming conventions:

- CLI/config: `base-image`.
- JSON: `baseImage`.
- Rust: `base_image` / `BaseImage`.

Every command that verifies a portal selects **one authority** first, and takes
both its trust anchors and its base-image measurement policy from that authority.
There is no precedence between sources, because two sources are never configured
at once: supplying operator-pinned inputs alongside a chain is a configuration
error, refused before the portal is contacted.

For `atakit cloud verify-session`:

1. **Explicit** — `--measurements <path>` pins the selected local file or
   directory, and the operator is the authority. `--chain` must not be present.
2. **Chain** — `--chain` makes the registry the authority. The command derives
   `BaseImageRegistry` from that chain's `SessionRegistry`, fetches the full
   base-image hierarchy for the identifier `--base-image` derives, and converts
   it into the in-memory measurement policy. Profile names must map
   unambiguously to cloud/TEE, using names such as `gcp-tdx`, `gcp-sev-snp`,
   `azure-tdx`, `azure-sev-snp`, or `aws-sev-snp`; unknown profile names fail
   closed instead of guessing. `--measurements` and pinned trust files must not
   be present.
3. Neither selected — fail closed. The command does not automatically read the
   deployment operator's local measurement cache.

For `atakit cloud deploy`, `atakit cloud init`, `atakit workload init`, and the
commands that open verified portal sessions, the same rule applies with one
difference: these reach a portal before a base-image reference is necessarily
known, so chain mode selects the registry record by the identifier from the
unauthenticated `GET /status`.

1. **Explicit** — `--measurements <path>` supplies the policy and the operator
   is the authority.
2. **Chain** — read `base_image_id` from `GET /status` and treat it **only** as
   a lookup key. Use the configured `BaseImageRegistry`, or derive it from the
   configured `SessionRegistry`, fetch that exact hierarchy, convert it into the
   in-memory measurement policy, and verify the TPM measurements against it. The
   identifier selects which record is read; it never decides what that record
   says.
3. If `--base-image <publisher>/<name>:<version>` is present, derive its
   identifier and require it to equal the `GET /status` lookup key. The flag is
   an optional assertion in chain mode, not a second policy source.
4. Accept the base-image identity only after the measurement policy passes.

These commands do not automatically read the local base-image measurement
cache. A cached measurement pack is not part of the normal chain-backed path.

For `chain.registration = "off"`:

- Chain data may not exist, but it may still be configured as a verifier
  collateral service.
- The verifier still needs a base-image measurement source. It comes from an
  explicit `--measurements <path>` or the configured on-chain
  `BaseImageRegistry`.
- Registration policy controls only whether the portal submits a session to
  chain. It MUST NOT disable verifier-side reads from a configured Automata
  chain RPC. The chain can be used like any other collateral endpoint to fetch
  base-image measurement policy, GCP AK trust roots, Azure MAA signing keys,
  AMD ARK root hashes, or TDX DCAP collateral.
- `atakit cloud init` and `atakit cloud deploy` MUST NOT treat the provider
  selector in deployment-state `image_ref` as a trust source. In the normal
  path, `GET /status.base_image_id` selects the `BaseImageRegistry` entry but
  remains untrusted until the returned measurement policy passes.
- `atakit cloud verify-session` MUST obtain its chain only from the verifier's
  `--chain`. A local deployment MAY fill the portal address, canonical
  base-image reference, canonical workload reference, and report path. It MUST
  NOT supply measurement policy, registry addresses, platform roots, or any
  other collateral.
- Direct `atakit workload init <host>` uses the same default
  `GET /status.base_image_id` to `BaseImageRegistry` lookup and does not require
  `--base-image`.
- The verifier MUST NOT use portal-reported `base_image_ref` as a policy source.
  It may use `base_image_id` only as the exact `BaseImageRegistry` lookup key.

Measurement pack format is defined in
[`measurement-pack-spec.md`](measurement-pack-spec.md).

The reserved profile attribute names and Boolean encodings are defined in that
specification. AMD SEV-SNP cryptographic verification does not reject
`POLICY.DEBUG` or `POLICY.MIGRATE_MA` before policy evaluation. It still
accepts only the all-zero or all-`0xff` `REPORT_ID_MA` no-association
sentinel, rejects every other `REPORT_ID_MA`, and rejects nonzero `VMPL`,
invalid policy-reserved bits, unsupported report versions, and a report length
other than 1,184 bytes.

## CLI Flags

New or extended CLI inputs:

```text
--base-image <name:version>
--measurements <path>
--measurement-publisher-key <hex-sec1-es256k-pubkey>
--gcp-ak-root-cert <hex-x509-der>
--azure-maa-key <hex-pkcs1-rsa-pubkey-or-hex-jwk-json>
--amd-ark-root-cert <hex-x509-der>
--amd-snp-crl <hex-der>
--amd-snp-security-policy <path>
--trust-tls-cert-sha256 <0xsha256>
--unsafe-skip-tls-attestation
```

`--measurements` accepts:

- a JSON measurement-pack path, with `.sig` discovered next to it;
- a directory containing `measurement-pack.json` and `measurement-pack.sig`.

`--measurement-publisher-key` is repeatable. Values are SEC1-encoded ES256K
public keys in hex, compressed or uncompressed. At least one trusted publisher
key is required when `--measurements` is supplied.

`--gcp-ak-root-cert` is repeatable. Values are hex-encoded trusted GCP vTPM AK
root certificates in X.509 DER. GCP verification fails closed when the portal
returns `akBinding.kind = "gcp-cert-chain"` and no trusted GCP root certificate
is configured.

`--azure-maa-key` is repeatable. Values are hex-encoded trusted Azure MAA RSA
public keys, either PKCS#1 DER or JWK JSON bytes. Azure verification fails
closed when the portal returns `akBinding.kind = "azure-maa-jwt"` and no trusted
MAA key is configured.

`--amd-ark-root-cert` is repeatable. Values are hex-encoded trusted AMD SEV-SNP
ARK root certificates in X.509 DER. GCP SEV-SNP verification fails closed when
the portal returns `teeEvidence.kind = "configfs-tsm"` for `platform.tee =
"sev-snp"` and no trusted AMD ARK root certificate is configured.

`--amd-snp-security-policy` reads the version 1 file defined by the
[AMD SEV-SNP Security Policy Specification](amd-sev-snp-security-policy-spec.md).
It supplies explicit trusted policy for every CPUID listed in that file.

`--trust-tls-cert-sha256` is a one-shot override. It does not persist trust.

`--unsafe-skip-tls-attestation` is a break-glass compatibility flag. It skips
`GET /tls-attestation`, does not write a verification report, does not evaluate
measurement policy or CSP collateral, and builds a client that accepts the
portal self-signed TLS certificate without validation. It restores the legacy
unsafe TLS behavior for the current command only.

## Failure Report

Verification failure MUST produce a structured report. The report is both a
human audit artifact and a machine-readable record for support/debugging.

The concise terminal output SHOULD include a check matrix:

```text
TLS attestation failed

check                         result
live cert captured            pass
response cert hash            pass
nonce                         pass
tpm quote structure           pass
tpm quote challenge           pass
tpm quote pcr digest          fail
cvm report                    pass
ak/cvm binding                pass
measurement policy            fail

full report: /path/to/report.json
```

The full JSON report SHOULD include:

- live peer TLS cert SHA-256;
- returned TLS cert SHA-256;
- nonce;
- qualifying data;
- CSP and TEE type;
- machine type;
- AK fingerprint;
- quote signature status;
- quote challenge status;
- CVM report status;
- TEE/vTPM binding status;
- actual PCR values;
- expected PCR policy;
- measurement source and selected pack revision;
- selected base image, platform profile, and variant;
- passed, failed, and skipped checks;
- raw evidence blobs or file references.

Report storage:

- `atakit cloud deploy` / `atakit cloud init`: next to deployment state as
  `<instance>.tls-attestation-report.json`.
- direct `atakit workload init <host>`: under
  `$ATAKIT_CACHE_DIR/tls-attestation/`.

## Manual Override

Default behavior is fail-closed. A user may override only by pinning the exact
live peer certificate hash:

```text
--trust-tls-cert-sha256 <0xsha256>
```

Rules:

- The override hash MUST exactly match the live peer TLS certificate SHA-256.
- The command MUST still write the failure report.
- No persistent trust entry is written.
- The command may continue only with a TLS client pinned to that exact cert.
- Override is refused if the bootstrap client cannot capture the live peer cert.

The override is intended for manual inspection workflows, not automated
production use.

For development or emergency recovery, operators may pass
`--unsafe-skip-tls-attestation`. This is not a manual override of a failed
verification result; it bypasses verification entirely and accepts the portal
self-signed certificate without pinning. The command MUST emit an explicit
warning when this flag is used.

## Reusable Library

`atakit` provides the reusable verifier crate:

```text
crates/atakit-attestation
```

Public API shape:

```rust
pub struct VerificationInputs {
    pub nonce: [u8; 32],
    pub live_peer_cert_der: Vec<u8>,
    pub response: TlsAttestationResponse,
    pub measurement_policy: Option<MeasurementPolicy>,
    pub trust_anchors: TrustAnchors,
}

pub struct VerifiedTlsIdentity {
    pub cert_der: Vec<u8>,
    pub cert_sha256: [u8; 32],
    pub base_image_id: Option<[u8; 32]>,
    pub platform_profile_id: Option<[u8; 32]>,
    pub variant_id: Option<[u8; 32]>,
}

pub struct VerificationReport {
    pub checks: Vec<VerificationCheck>,
    pub evidence: EvidenceSummary,
}

pub struct VerificationFailure {
    pub report: VerificationReport,
    pub errors: Vec<VerificationError>,
}

pub fn parse_measurement_pack(bytes: &[u8]) -> Result<MeasurementPack>;

pub fn verify_measurement_pack(
    bytes: &[u8],
    sig: &[u8],
    trusted_publisher_keys: &[Vec<u8>],
) -> Result<MeasurementPack>;

pub fn verify_tls_attestation(
    inputs: VerificationInputs,
) -> Result<VerifiedTlsIdentity, VerificationFailure>;

pub fn verify_tls_attestation_with_workload_attributes(
    inputs: VerificationInputs,
    workload_attributes: &AttributeRequirements,
) -> Result<VerifiedTlsIdentity, VerificationFailure>;
```

`verify_tls_attestation` applies the effective base-image declarations without
adding workload requirements. Use
`verify_tls_attestation_with_workload_attributes` when a workload has already
been selected. That function also applies the selected workload's measured
requirements. The caller must derive `workload_attributes` from the same
verified archive bytes that it later sends to `POST /init`.

Library responsibilities:

- parse and validate measurement packs;
- verify measurement-pack signatures;
- verify TPM quote structure/signature/challenge;
- verify CSP evidence and AK-to-CVM binding;
- evaluate PCR policy;
- evaluate report-bound TEE states against the trusted base-image declarations
  and, when supplied, the selected workload requirements;
- produce `VerificationReport`.

CLI responsibilities:

- generate nonce;
- fetch `/tls-attestation`;
- capture live peer cert;
- select one trust authority and resolve the measurement policy from it;
- print/write reports;
- apply one-shot override;
- construct the pinned TLS client for later portal requests.

## Relationship to Existing Endpoints

`GET /tls-attestation` is not a replacement for existing evidence endpoints.

| Endpoint | Time | Purpose |
|---|---|---|
| `GET /tls-attestation?nonce=...` | pre-init and post-init | Bootstrap trust in the self-signed TLS cert. |
| `GET /tee-evidence` | always | Raw TEE report and AK collateral surface. |
| `GET /platform-measurements` | always | TPM PCRs and verifier-shaped event log. |
| `GET /session/evidence-bundle?challenge=<base64url-32>` | post-init | Complete current-session evidence with request binding. |

Nonce difference:

- `/tls-attestation` uses a 32-byte random binary nonce encoded as base64url.
- `/session/evidence-bundle` also uses a 32-byte base64url challenge at the GET boundary. The
  decoded bytes are interpreted as the big-endian ABI `uint256` owner nonce for
  session-registration qualifying data.

## Security Notes

- A self-signed cert is trusted only after successful attestation or exact
  one-shot override.
- The nonce prevents replay of old evidence.
- The TLS cert hash inside `qualifying_data` prevents a valid CVM TPM quote from
  being reused to endorse a different TLS cert.
- The domain separator prevents cross-protocol evidence confusion.
- The CSP binding check is mandatory. A TPM quote without proof that its AK
  belongs to the CVM report is not sufficient.
- Measurement selection is controlled by local/chain trusted inputs, not by the
  remote portal's unverified status fields.
