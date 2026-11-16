# Measurement Pack Specification

Version 4. there is no
migration from version 3 and no dual read path, so version 3 packs do not parse.

It depends on publisher-qualified identifiers, which are implemented in
`automata-tee-workload-measurement` and in `atakit`.

A measurement pack is a signed statement by a publisher about what a named
artifact measures to. Two kinds exist:

| Kind | `schema` | Subject | Measurements |
|---|---|---|---|
| Base image | `atakit.base_image_measurement_pack.v4` | a registered base image | platform profiles and variants |
| Workload | `atakit.workload_measurement_pack.v1` | a registered workload | the PCR23 binding |

They share one **envelope** — identity, validity, canonical encoding, and
signature — and nothing else. The envelope is one implementation because two
copies of signature verification are two chances to differ. The bodies are
separate types with independent `schema` versions, because a base image
describes per-platform PCR policy and a workload describes a single measured
manifest, and a consumer of one must not silently accept the other.

Measurement packs are separate from `.atabi` and `.atawl` archives so
measurements can be revised, signed, mirrored, and consumed independently of the
artifacts they describe.

## What version 4 changes

- **Subjects are publisher-qualified.** `subject.publisher` carries the owner
  fingerprint, and it is an input to the derived id. Without it a name and
  version named an identity anyone could claim to speak for, and an offline
  verifier had nothing to check that claim against.
- **`base_image` becomes `subject`**, shared by both kinds.
- **Keys are `snake_case`**, matching `trust-pack.json` and the Rust field
  names.
- **`published_at` is Unix seconds**, not an RFC 3339 string. RFC 8785
  canonicalizes JSON structure, not string semantics:
  `"2026-07-07T00:00:00Z"`, `"2026-07-07T00:00:00.000Z"`, and
  `"2026-07-06T20:00:00-04:00"` are three distinct byte strings for one
  instant, all canonical JSON. An integer admits exactly one encoding, which is
  what a signed format requires, and it matches every other time field a
  verifier compares.
- **Local lookup is keyed by id**, so no path encoding is involved.
- **Workload measurement packs exist.** Previously a workload's PCR23 was bound
  to its publisher only by on-chain registration, so offline verification had
  nothing to check.

This portable measurement-pack format is separate from the local saved
platform-profile file. The local file is defined in
[platform-profile-json-spec.md](platform-profile-json-spec.md). Each portable
PCR rule carries the exact opaque `comparison` bytes used on chain.

## Artifact Format

This specification defines no archive format. The canonical artifact is:

```text
<base-image>-<version>.measurements.json
<base-image>-<version>.measurements.sig
```

For directory-based distribution:

```text
measurement-pack.json
measurement-pack.sig
measurement-pack.pubkey
```

`measurement-pack.pubkey` is a transport sidecar for workload trust-pack
assembly. It contains the publisher's 65-byte uncompressed SEC1 secp256k1
public key as lowercase `0x04...` hexadecimal. It is not a new trust input:
the workload trust-pack reader recomputes its owner fingerprint and compares
that value with the signed `subject.publisher` before it uses the key.

`--measurements <path>` accepts either the JSON file path or the directory path.
When a JSON path is supplied, the verifier discovers the detached signature by
replacing `.json` with `.sig` or by appending `.sig` if the path does not end in
`.json`.

For local automatic lookup, atakit searches by derived id:

```text
<atakit-data-dir>/baseimage/measurements/<base_image_id>/
  measurement-pack.json
  measurement-pack.sig
  measurement-pack.pubkey
```

A workload pack is filed beside the store entry it describes, which is already
keyed on the identifier:

```text
<atakit-data-dir>/workloads/<workload_id>/
  measurement-pack.json
  measurement-pack.sig
```

The id is `0x` followed by 64 lowercase hexadecimal characters, so it is
path-safe by construction: there is no separator, `.`, or `..` to neutralise and
no encoding to keep reversible. It is also publisher-qualified, so two
publishers holding the same name and version get separate directories instead of
overwriting one another.

Version 3 encoded the name and version into path segments with a `ref~` escape
scheme. That scheme has no remaining users and is removed.

The supported producers are:

```bash
atakit-imgbuild measurement-pack <name>:<version> \
  --signing-key <named-provisioned-es256k-key> \
  [--revision <n>] [--uri <image-uri>]

atakit workload build --signing-key <named-provisioned-es256k-key> [...]
```

Both take a provisioned ES256K key from `[keys]`, so there is one key
convention. `atakit workload build` requires one because the signing key's
fingerprint **is** the publisher component of the workload id: without it the
identifier is not computable at build time, and the pack it emits would have
nothing to bind the measurement to.

It reads every saved profile for the image, recomputes the base-image, profile,
and variant ids, writes canonical JSON to the automatic lookup directory, and
creates the detached signature and uncompressed public-key sidecar beside it.
It rejects unknown platform profile names instead of guessing their cloud or
TEE type.

For chain-derived measurement policy, no JSON artifact is required. The CLI
fetches the `BaseImageRegistry` hierarchy and constructs the same in-memory
shape. Since the on-chain profile does not store `cloud` and `tee` as
first-class fields, chain-derived conversion requires the platform profile name
to encode them unambiguously. Supported names include `gcp-tdx`, `gcp-sev-snp`,
`azure-tdx`, `azure-sev-snp`, and `aws-sev-snp`. Unknown names fail closed.

**There is no source precedence.** A verification selects one authority and
takes its base-image measurement policy from that authority alone:
`--measurements` and the local pack for `--base-image` belong to the operator,
and chain-derived policy belongs to the registry. Supplying an operator source
alongside a chain is a configuration error, refused before verification begins,
not an input that outranks the other.

Earlier revisions defined "explicit, then local pack, then chain-derived"
precedence. That is withdrawn, for the reason recorded in
[atatp-archive-spec.md](atatp-archive-spec.md): with precedence, an operator who
believed they had pinned a value could not tell from the result whether the
pinned value was used or whether another source had quietly supplied it, and
"who is the trust authority for this verification" had no single answer.

A present but invalid operator-supplied pack MUST fail closed. It never falls
back to the chain — under an exclusive rule there is nothing to fall back to.

## Signature

The `.sig` file is a detached ES256K signature over the canonical JSON bytes.
Trusted publisher keys are configured by the caller. The verifier MUST reject a
pack if:

- the signature is missing;
- the publisher key is not trusted;
- the signature does not verify over the exact canonical JSON bytes;
- the JSON is not canonical according to the implementation's canonicalization
  rules.

The implementation enforces RFC 8785-style canonical JSON by parsing the pack,
canonicalizing it, and requiring the canonical bytes to match the signed input
bytes exactly. Producers MUST sign the canonical bytes.

Verifiers accept trusted publisher public keys as SEC1 ES256K points in hex
form. The detached signature MAY be raw 64-byte `r || s`, 65-byte `r || s || v`
(the recovery byte is ignored for verification), or DER-encoded ECDSA.

## Schema

### Envelope

Every pack, of either kind, has this shape:

```json
{
  "schema": "atakit.base_image_measurement_pack.v4",
  "revision": 1,
  "published_at": 1786000000,
  "subject": {
    "publisher": "0x9f2c...e07d",
    "name": "automata-linux",
    "version": "v0.2.6-debug",
    "id": "0x...",
    "uri": "https://example.invalid/automata-linux-v0.2.6-debug.atabi",
    "archive_sha256": "0x..."
  },
  "measurements": { }
}
```

`measurements` is the kind-specific body, selected by `schema`. A verifier
checks the envelope first — canonical bytes, signature, and the `subject.id`
recomputation — and only then interprets `measurements`. A pack whose `schema`
is not the kind the caller asked for MUST be rejected before its body is read.

### Base-image body

`schema` is `atakit.base_image_measurement_pack.v4`. `measurements` is:

```json
{
  "profiles": [
    {
      "name": "gcp-tdx",
      "id": "0x...",
      "cloud": "gcp",
      "tee": "tdx",
      "pcr_bank_selection": "sha256-and-sha384",
      "invariant_pcrs256": [
        { "pcr_index": 4, "comparison": "0x..." }
      ],
      "invariant_pcrs384": [],
      "attributes": [
        {
          "name": "atakit.attestation.v1.tee.intel-tdx.debug.enabled",
          "value": false
        },
        {
          "name": "atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed",
          "value": ["ok", "sw-hardening-needed"]
        },
        { "name": "example.environment", "value": "production" }
      ],
      "variants": [
        {
          "name": "c3-standard-4",
          "id": "0x...",
          "machine_types": ["c3-standard-4"],
          "variant_pcrs256": [],
          "variant_pcrs384": [],
          "attributes": []
        }
      ]
    }
  ]
}
```

### Workload body

`schema` is `atakit.workload_measurement_pack.v1`. `measurements` is:

```json
{
  "pcr23_sha256": "0x...",
  "pcr23_sha384": "0x..."
}
```

PCR23 is the hash of the compiled `manifest.json`, so these two values are the
workload's complete measured identity. Both banks are required: a pack that
carried only one would silently constrain nothing on a target attesting in the
other.

The workload body deliberately carries no platform profiles. A workload measures
the same way on every platform; what varies by platform is the base image
underneath it, which its own pack describes.

**`publisher` is not part of PCR23.** The same source builds to the same PCR23
regardless of who signs it. The pack binds publisher to measurement externally,
which is what makes the binding checkable offline without making an artifact's
measurement depend on who published it.

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | yes | Selects the kind and the body version. |
| `revision` | integer | yes | Monotonic pack revision for the same subject. Higher valid revision wins for automatic local lookup. |
| `published_at` | integer | yes | Publication time, Unix seconds. |
| `subject` | object | yes | What this pack makes a statement about. |
| `measurements` | object | yes | Kind-specific body, selected by `schema`. |

### `subject`

| Field | Type | Required | Description |
|---|---|---|---|
| `publisher` | bytes32 hex | yes | Owner fingerprint of the publisher. An input to `id`. |
| `name` | string | yes | Repository or workload name. |
| `version` | string | yes | Version tag. |
| `id` | bytes32 hex | yes | Expected derived id. The verifier recomputes it from `publisher`, `name`, and `version` and rejects a mismatch. |
| `uri` | string | no | Optional source URI for the related archive or release. Diagnostic only. |
| `archive_sha256` | bytes32 hex | no | SHA-256 of the related `.atabi` or `.atawl`. Diagnostic unless the caller explicitly requires it, but because it sits inside the signed canonical bytes it is how a publisher vouches for archive content: a substituted archive no longer matches any pack that publisher signed. `atakit workload build` always records it; `atakit-imgbuild measurement-pack` records it when given `--archive`. |

The recomputation of `id` is what makes the publisher binding enforceable rather
than advisory. A pack claiming one publisher while carrying another's
measurements produces an id that does not match the one the caller expects, and
fails before any measurement is read.

### `profiles[]`

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Platform profile name, for example `gcp-tdx`. |
| `id` | bytes32 hex | yes | Expected platform profile id. Verifier recomputes and rejects mismatch. |
| `cloud` | string | yes | `gcp`, `azure`, or `aws`. |
| `tee` | string | yes | `tdx` or `sev-snp`. AWS NitroTPM profiles use `sev-snp`. |
| `pcr_bank_selection` | string | yes | `sha256`, `sha384`, or `sha256-and-sha384`. |
| `invariant_pcrs256` | array | yes | SHA-256 PCR specs that always hold. |
| `invariant_pcrs384` | array | yes | SHA-384 PCR specs that always hold. |
| `variants` | array | yes | Machine/profile variants. |
| `attributes` | array | no | Platform attributes. Readable attributes use `{ "name": "...", "value": ... }` objects. Custom values are strings, reserved Boolean values are Booleans, Intel TDX TCB status values are status-name arrays, and AMD SEV-SNP packed values are `0x`-prefixed bytes32 strings. The hexadecimal `{ "key": "0x...", "value": "0x..." }` form is valid for ordinary attributes. |

### `variants[]`

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Variant name. |
| `id` | bytes32 hex | yes | Expected variant id. Verifier recomputes and rejects mismatch. |
| `machine_types` | array | no | Cloud machine types that select this variant. |
| `variant_pcrs256` | array | yes | SHA-256 PCR specs for indexes the profile leaves unpinned. Must be disjoint from `invariant_pcrs256`. |
| `variant_pcrs384` | array | yes | SHA-384 PCR specs for indexes the profile leaves unpinned. Must be disjoint from `invariant_pcrs384`. |
| `attributes` | array | no | Variant overrides using the same readable or hexadecimal forms as the profile. Custom attributes and all six reserved TEE attributes are allowed. |

### PCR specs

| Field | Type | Required | Description |
|---|---|---|---|
| `pcr_index` | integer | yes | TPM PCR index, limited to 0 through 16 or 23. |
| `comparison` | hexadecimal bytes | yes | Exact canonical ABI bytes described below. The value MUST start with `0x` and MUST not be empty. |

`comparison` is one opaque blob. Its canonical encoding is
`abi.encode(uint16 comparisonType, comparison-specific fields...)`.
Decoders MUST decode the complete blob, re-encode it, and require exact byte
equality. Trailing bytes, alternate offsets, and alternate padding are invalid.

| `comparisonType` | Name | SHA-256 fields after the type | SHA-384 fields after the type |
|---|---|---|---|
| `0` | `STATIC` | `bytes32 expectedValue` | `Bytes48 expectedValue` |
| `1` | `DYNAMIC_SUBSET` | `bytes32[] landmarks` | `Bytes48[] landmarks` |
| `2` | `DYNAMIC_SUBSEQUENCE` | `bytes32[] landmarks` | `Bytes48[] landmarks` |
| `3` | `DYNAMIC_INDEXED_EVENT_SETS` | `IndexedEventSets256 rule` | `IndexedEventSets384 rule` |
| `4` | `EXTEND_FROM_ZERO` | `bytes32 extendValue` | `Bytes48 extendValue` |

`Bytes48` is `(bytes32 first, bytes16 second)`. An indexed rule contains an
exact `uint16 expectedEventCount` and a sorted array of checked events. Each
checked event contains a `uint16 eventIndex` and a sorted, unique, non-empty
array of allowed digest values. Unlisted event indexes are unconstrained. The
verifier still replays the complete measured event log to the quoted PCR value.

`EXTEND_FROM_ZERO` requires the authenticated PCR value to equal one TPM
extend from the all-zero bank value. SHA-256 evaluates
`sha256(bytes32(0) || extendValue)`. SHA-384 evaluates
`sha384(bytes48(0) || extendValue)` and therefore requires the ZK TPM Quote
backend on chain.

### Invariant precedence

A platform profile invariant always holds. Each bank has its own union:
`invariant_pcrs256 + variant_pcrs256` and `invariant_pcrs384 + variant_pcrs384`.

An index present in both registered platform and variant arrays MUST fail
closed before publication. `atakit-imgbuild` rejects the profile at read time,
and `BaseImageRegistry` rejects the variant at registration with
`VariantOverridesInvariantPcr`. This does not ban duplicate indexes in a
complete in-memory TPM verification request. A published rule and a generated
provider rule may target the same index; the verifier evaluates both against
the one authenticated PCR value. Resolving a registered overlap in the
variant's favour would let an offline verifier accept a session
that on-chain registration refuses, so implementations MUST NOT do so.

To make a PCR machine-type dependent, publish a base image whose profile does
not list that index as an invariant. An existing profile's invariants cannot be
narrowed after publication.

The current TLS attestation verifier implements all three PCR policies. `dynamicSubset` requires
every policy landmark to occur in the measured event log. `dynamicSubsequence`
also requires the landmarks to occur in policy order. Both dynamic policies
replay the complete measured event log and require its result to equal the
quoted PCR value. An unknown policy name MUST fail closed.

## ID Derivation

The verifier recomputes all ids from names and rejects mismatches.

```text
subject.id        = keccak256(abi.encode(DOMAIN, publisher, name, version))
platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, subject.id, profile.name))
variantId         = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variant.name))
```

`DOMAIN` is `BASEIMAGE_DOMAIN` for a base-image pack and `WORKLOAD_DOMAIN` for a
workload pack. `publisher` is the owner fingerprint,
`keccak256(abi.encode(KEY_DOMAIN, identity.type_id, identity.key))`.

The domain constants MUST match the on-chain `BaseImageRegistry` and
`WorkloadRegistry` definitions. Profile and variant ids apply to base-image
packs only.

## Effective PCR Policy

For a selected profile and variant:

1. Select the bank or banks named by `profile.pcr_bank_selection`.
2. For each selected bank, combine the profile invariant and matching variant
   arrays.
3. Reject overlap between the profile and variant arrays.
4. Reject duplicate or unsorted PCR indexes within any array.

The merged list is the policy used for TLS attestation.

Each selected bank must satisfy the current provider and verification rules.

The producer MUST preserve the invariant and variant classification from the
saved platform-profile JSON. In particular, the built-in GCP and Azure policy
keeps PCRs 4, 9, and 11 profile-wide and writes reproducible
machine-configuration PCRs to the selected variant. It excludes PCR 1 on both
clouds because boot-device enumeration changes with disk topology. The exact
GCP and Azure PCR sets are defined in
[platform-profile-json-spec.md](platform-profile-json-spec.md#built-in-gcp-and-azure-classification).

## Effective Attribute Policy

Readable names are converted to `keccak256(bytes(name))`. Custom readable
values are converted to `keccak256(bytes(value))`. A generated Intel TDX
profile includes explicit safe values for Intel TDX debug and TCB status. A
generated AMD SEV-SNP profile includes explicit `false` values for AMD SEV-SNP
debug and `MIGRATE_MA`. It does not add packed AMD SEV-SNP values: their
absence selects the active exact-CPUID registry default. Regeneration keeps
existing explicit values.

Variant attributes replace profile attributes with the same key. The verifier
uses the merged value as the trusted base-image declaration. This rule applies
to custom attributes and all six reserved TEE attributes.

The exact lookup order is:

1. the selected measurement variant;
2. the selected platform profile;
3. the attribute-specific missing default.

The missing defaults are `false` for the three Boolean attributes, `ok` only
for the Intel TDX TCB status mask, and the active exact-CPUID
`AmdSnpSecurityPolicyRegistry` value for both AMD SEV-SNP packed policies.

The reserved names are:

- `atakit.attestation.v1.tee.intel-tdx.debug.enabled`
- `atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed`
- `atakit.attestation.v1.tee.amd-sev-snp.debug.enabled`
- `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled`
- `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum`
- `atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy`

The Boolean declarations default to `false` when absent and must equal the
state extracted from the verified report. The Intel TDX TCB declaration is a
mask and defaults to `ok` only. The verified one-hot Intel DCAP TCB status bit
must appear in the mask. Verification evaluates only the reserved attributes
for the selected TEE platform. Reserved attributes for the other TEE platform
are not applied to that session. Unknown names under
`atakit.attestation.v1.tee.` fail closed. Custom and hexadecimal attributes keep
the ordinary metadata behavior. The AMD SEV-SNP packed layouts and default
resolution are defined in
[AMD SEV-SNP Security Policy Specification](amd-sev-snp-security-policy-spec.md).

## Variant Selection

The verifier selects a profile by matching:

- attested cloud type;
- attested TEE type;
- expected base-image id.

The verifier filters variants by matching `machineType` to
`variant.machine_types`. An empty machine-type list does not match.

When several variants match the machine type, the verifier evaluates each
complete effective PCR policy, including the profile invariants and every
selected bank. Exactly one policy must match. It never combines a PCR value
from one variant with a value from another. Zero matches or multiple complete
matches fail closed. Attribute checks follow selection; an attribute failure
does not cause fallback to another variant.

TLS selection uses PCR values authenticated by the TPM quote. Verification of
a supplied session bundle may use its PCR values to select a candidate, but
must then authenticate the exact values, all session signatures, and the
derived profile/variant identifiers before returning success. Submitted policy
identifiers cannot select a trusted variant.

Azure SEV-SNP firmware variant names use the canonical suffix described in
[platform-profile-json-spec.md](platform-profile-json-spec.md#azure-sev-snp-firmware-variants).
Both measurement-pack production and registry conversion recover the original
machine type from this suffix. Legacy names remain literal machine types.

## Relationship to `.atabi` and `.atawl`

`.atabi` packages disk images and secure boot certificates; `.atawl` packages a
compiled workload. Measurement packs package verification policy. They are
intentionally separate:

- a measurement pack can be updated after a base-image archive ships;
- offline verifiers can consume measurements without downloading disk images;
- multiple publishers or mirrors can distribute policy for the same image;
- signatures and trust policy are simpler for small JSON artifacts.

A future `.atabi` MAY embed a measurement snapshot for convenience, but the
standalone signed measurement pack remains the canonical policy artifact for
TLS attestation v1.

**Archives are not signed, and signing them is not planned.** A verifier never
sees archive bytes; it sees PCRs from a TEE. Provenance on bytes nobody checks
would need a second key convention and would invite the belief that a valid
archive signature says something about what the artifact measures to. Where
archive integrity is wanted, `subject.archive_sha256` already carries it under
the pack signature.

## Relationship to `.atatp`

A `workload-trust` trust pack carries a workload spec and the base-image
measurement packs its `base_image_ids` name. Version 4 removes the archive-wide
`payload/measurement-publisher-pubkey.pem`: each measurement pack states its own
publisher inside the signed bytes, and `subject.id` binds that publisher to the
identifier the workload spec names. A substituted publisher yields a different
id and fails the match.

The signing key still travels with the pack, as a per-entry `<stem>.pubkey`,
because a fingerprint is a hash and an ES256K signature cannot be checked
against one. It is an addressing input, not a trust input: the reader requires
`keccak256(abi.encode(KEY_DOMAIN, type_id, key))` to equal `subject.publisher`
before it verifies anything with that key, so the key is no longer a choice the
party it constrains gets to make freely.
