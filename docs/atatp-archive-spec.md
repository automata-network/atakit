# `.atatp` Trust Pack Specification

A `.atatp` file distributes signed verification trust inputs to an offline
verifier. It packages trust roots, registry-published policy values, and
base-image and workload policy into a single signed artifact, so a verifier can
resolve them without reading a chain. The file is a tar.zst (tar +
zstandard) with a custom extension — inspectable with standard tools
(`tar --zstd -tf`).

A trust pack supplies **inputs**. It never contains evidence, never changes a
verification check, and never selects the endpoint or registry a verifier uses.
Its contents are converted into the same typed values a chain-resolved verifier
would produce, and the conversion must not weaken any evidence, signature,
identity, PCR, attribute, request-binding, session-binding, or registry-state
check.

**Trust packs are one of two mutually exclusive verification modes.** A
verification resolves every trust input from the chain, or from trust packs,
never from both. See [Verification Modes](#verification-modes).

## Design Principles

1. **One signature over a canonical index.** The index hashes every payload
   entry, so one signature covers the whole pack.
2. **Authority is bound to role, twice.** `kind` fixes both which payload paths
   may appear and which publisher key must have signed the pack. This binds
   authority *between* kinds. Authority *within* a kind is bound separately, by
   deriving every identifier from its publisher's owner fingerprint, so a pack
   signer cannot speak for a publisher whose fingerprint they do not hold.
3. **Content selects, filenames address.** Every entry that is keyed by
   platform, CPU, or base image is chosen by a field inside its own signed
   bytes, never by its path.
4. **Expiry is derived, not declared.** A pack cannot advertise a longer life
   than the shortest-lived thing inside it.
5. **One trust source per verification.** Packs and the chain are alternatives,
   never layers. There is no precedence rule because there is nothing to order.

---

## Archive Layout

```text
collateral-trust.atatp
  trust-pack.json
  trust-pack.sig
  payload/
    ...
```

| Entry | Description |
|---|---|
| `trust-pack.json` | Canonical JSON (RFC 8785). Identity, validity, and the SHA-256 of every payload entry. |
| `trust-pack.sig` | Detached signature over the exact bytes of `trust-pack.json`. |
| `payload/` | The trust inputs. Every entry must appear in `hashes`. |

Only zstd compression is defined. There is no legacy gzip read path.

**The index is not named `manifest.json`.** That name is the compiled workload
definition inside a `.atawl`, whose hash *is* PCR23, and every container image
tar under `images/` carries its own OCI `manifest.json`. Reusing it would make
"the manifest" ambiguous. `trust-pack.json` parallels the existing
`measurement-pack.json`.

---

## `trust-pack.json`

```json
{
  "format": 1,
  "kind": "collateral-trust",
  "issuer": "example-publisher",
  "revision": 7,
  "not_before": 1785000000,
  "not_after": 1790000000,
  "hashes": {
    "payload/roots/gcp-ak-root.pem": "sha256:9f2c...",
    "payload/amd-snp-security-policy/0x00190100.json": "sha256:41ab..."
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | integer | yes | Schema version. Current: `1`. |
| `kind` | string | yes | `collateral-trust` or `workload-trust`. Selects the payload namespace and the required publisher key. |
| `issuer` | string | yes | Human label identifying the publisher. **Never** used in a trust decision. |
| `revision` | integer | yes | Monotonic per issuer and kind. **Informational only** — see below. |
| `not_before` | integer | yes | Unix seconds. |
| `not_after` | integer | yes | Unix seconds. Derived, see [Validity](#validity). |
| `hashes` | object | yes | Payload path to `sha256:<lowercase hex>`. Every payload entry appears exactly once. |

Unknown fields are rejected. The JSON is RFC 8785 canonical form, matching how
`manifest.json` is canonicalized for PCR23.

### `revision` is informational

A reader **must not** reject a pack on the basis of `revision`, and no verifier
is required to remember the highest value it has seen. The field exists so a
human comparing two packs, or an operator reading `GET /v1/config`, can tell
which is newer. It is not a rollback control.

Stating this explicitly because a monotonic counter reads like protection.
Enforcing it would require a verifier to persist the highest revision per
issuer and kind across restarts, and nothing in this design has such state —
the daemon is stateless by construction. A verifier that does not remember
cannot detect a replayed older pack, so an unenforced counter would be a
security property that exists only in the field's name.

**Rollback protection is digest pinning, bounded by `not_after`.** Pinned, an
operator can serve exactly one artifact. Unpinned, they may serve any pack the
role's publisher signed that has not yet expired, and `revision` does not
narrow that window.

### Signature

`trust-pack.sig` is an ES256K signature over `sha256(trust-pack.json bytes)`.

**The key that verifies the pack signature comes only from the verifier's
configuration.** `kind` selects which configured publisher key applies. A pack
cannot influence which key verifies *the pack itself* — a pack that supplied
its own pack-verification key would verify under any key its author held.

This property covers the pack signature and nothing else. Key material carried
in the payload is never a trust input: the per-pack signing key under
`payload/measurement-packs/` is validated by recomputing its owner fingerprint
and requiring the derived identifier to match, so a substituted key produces a
different base-image identifier and is rejected. See
[Measurement packs](#measurement-packs--payloadmeasurement-packs).

The configured key is an uncompressed SEC1 secp256k1 public key in hex,
matching the existing `--measurement-publisher-key` convention, so the command
line and any offline verifier share one format.

**For `kind: "workload-trust"`, the configured key's owner fingerprint must
equal the publisher segment of the workload reference in
`payload/workload-spec.json`.** Without that check a verifier configured with
publisher A's key would accept a pack in which A names publisher B's workload
reference, deriving B's `workload_id` while applying policy A chose — the same
substitution the identifier change closes one level down. The fingerprint is
`keccak256(abi.encode(KEY_DOMAIN, type_id, key))`, computed over the configured
key exactly as `LibKey.computeKeyFingerprint` computes it on chain.

The signature covers the **index**, not the archive bytes. Tar is not
canonical — entry ordering, padding, and metadata vary between producers — so a
signature over archive bytes would not be reproducible. Hashing payload entries
into a canonical index and signing that index is how `.atawl` already
establishes integrity.

---

## Kinds and Payload Namespaces

`kind` defines the **only** paths that may appear. A pack containing any path
outside its namespace is rejected whole, before any entry is used.

This is what makes authority structural rather than conventional: without it, a
workload publisher's key could sign a pack containing `payload/roots/` and
silently become a trust root authority.

The namespace rule bounds authority **between** kinds. It creates no authority
boundary **within** a kind — everything a `workload-trust` pack contains is
authorized by the workload publisher's signature alone — which is why the
boundary that matters inside `workload-trust`, between the workload publisher
and the base-image publisher, is enforced by identifier derivation instead. See
[Base-image publisher authority](#base-image-publisher-authority).

### `kind: "collateral-trust"`

```text
payload/roots/gcp-ak-root.pem
payload/roots/amd-ark-<product-line>.pem
payload/roots/aws-nitro-root.pem
payload/azure-maa/*.pem
payload/amd-snp-security-policy/*.json
payload/aws-document-limits.json
payload/amd-snp-crl/*.der          optional
payload/tdx-dcap/*.json            optional
```

### `kind: "workload-trust"`

```text
payload/workload-spec.json
payload/measurement-packs/*.json
payload/measurement-packs/*.sig
payload/measurement-packs/*.pubkey
```

Every `*.json` under `payload/measurement-packs/` must have a `*.sig` and a
`*.pubkey` on the same stem, and no `*.sig` or `*.pubkey` may appear without
its `*.json`. `payload/measurement-publisher-pubkey.pem` — one archive-wide key
that decided what every base image measured — is **not** in this namespace and
must be rejected if present.

---

## Payload Entry Formats

### Trust roots — `payload/roots/*.pem`

PEM X.509 certificates. These are candidate roots; a verifier converts them
into the corresponding `TrustAnchors` field. Each vendor's approval hash uses
the algorithm its verifier compares — SHA-256 for the AMD ARK, Keccak-256 for
the GCP vTPM AK root and the AWS Nitro root.

**The Intel SGX Root CA is not carried here and must be rejected if present.**
It is a compile-time constant in two independent places:
`dcap_rs::INTEL_ROOT_CA_PEM`, and `PcsDao.ROOT_CA_PUBKEY_HASH` in
`automata-on-chain-pccs`, which compares `keccak256(pubKey)` directly. There is
no runtime governance for that root anywhere in the stack, and a pack must not
appear to provide one.

### Azure MAA — `payload/azure-maa/*.pem`

The MAA **signing certificate**, as published in the `x5c` field of the
attestation instance's OpenID metadata endpoint. Not a bare public key.

- The public key is taken from the certificate's `SubjectPublicKeyInfo`.
- `not_after` is taken from the certificate's validity period.

A bare public key carries no expiry, and accepting one would produce a
never-expiring trust key. There is no `revoked` field: a pack revokes a key by
omitting it, and both revocation and rotation require a reissued pack in any
case.

`kid` and `issuer` are not stored. They are taken from the MAA JWT header and
claims at verification time, and the signature check is what binds the key to
the token.

### AMD SEV-SNP security policy — `payload/amd-snp-security-policy/*.json`

An `atakit.amd-sev-snp-security-policy` version 1 document, exactly as
[amd-sev-snp-security-policy-spec.md](amd-sev-snp-security-policy-spec.md)
defines it: `schema`, `version`, and a `policies` array whose entries carry
`cpuid`, `minimumTcb`, `platformInfoPolicy`, and the required launch and
current mitigation vectors.

The complete document rather than one bare `AmdSnpSecurityPolicy` per file, for
two reasons. It has one parser, which already rejects unsupported processors,
malformed TCB fields, an invalid platform-info policy, and duplicate CPUIDs; a
bare-policy form would need a second implementation of those rules, and a
divergence between them would be a policy a pack accepts and the chain path
does not. It is also the artifact an operator already holds — the reviewed
policy loaded into `AmdSnpSecurityPolicyRegistry` — so a pack carries the file
that was reviewed rather than a re-derived transcription of it.

**A CPUID may be claimed once across the whole pack.** The single-document
parser already rejects duplicates within one file; a reader must extend that
across files, and across packs per
[Failure Rules](#failure-rules). Two files claiming one CPUID is fatal, because
silently choosing one would make the winner invisible.

Selection is still by `cpuid` inside the signed bytes, so a file holding several
policies contributes each of them independently and the filename addresses
nothing.

### AWS document limits — `payload/aws-document-limits.json`

```json
{
  "maximum_age_seconds": 300,
  "allowed_future_clock_difference_seconds": 60
}
```

### Vendor collateral — `payload/tdx-dcap/*.json`, `payload/amd-snp-crl/*.der`

Optional. Intel TDX DCAP collateral in `atakit.intel-tdx-dcap-collateral`
version 1 form, one entry per `(fmspc, pceId, pckCa)`, and AMD SEV-SNP
certificate revocation lists in DER.

`payload/tdx-dcap/` **is a Provisioning Certificate Caching Service snapshot.**
A publisher produces it by reading a caching service — the Automata on-chain
Provisioning Certificate Caching Service, or an HTTP one — and serializing each
identity's collateral into an entry. The pack carries the cached data itself,
not a pointer to where it came from, so nothing in a pack selects a verifier's
network dependency.

Where a verifier fetches collateral it does **not** have is its own
configuration, never the pack's. A pack that has no entry for a presented
quote simply does not cover that hardware.

#### Vendor collateral is not a trust source

This material is vendor-signed and therefore self-authenticating, which makes
it the one thing a `trust-pack` mode verifier may still fetch. Its presence in
a pack is an **availability** choice, not a trust one.

**In every policy-authority mode, collateral the configured inputs do not
contain may be fetched from a configured collateral source** — an HTTP
Provisioning Certificate Caching Service, Automata on-chain PCCS, or AMD Key
Distribution Service. A read-only Automata on-chain PCCS query is not a policy
fallback: no measurement policy, workload policy, trust anchor, or identity is
resolved from registry contracts. Only vendor-signed Intel material is read
and verified locally.

Four rules bound it:

- **Fetched collateral is validated against trust anchors selected from the
  active mode's source.** That source still decides what is trusted; the fetch
  decides only where bytes came from.
- **The collateral source does not select the policy authority.** Automata
  on-chain PCCS is permitted under `chain`, `trust-pack`, and `explicit` policy
  authority. Those read-only collateral calls MUST NOT read a base-image
  measurement policy or workload policy from registry contracts.
- **A configured entry that exists but is invalid, expired, or does not match
  the presented quote fails the verification.** It must not trigger a fetch.
  Fetching past a broken pinned entry would make pinning advisory.
- **A miss with no configured collateral source fails closed**, naming the
  missing collateral identity.

Two further consequences follow from what this material is:

- It is keyed to hardware the publisher cannot fully predict, so a snapshot
  cannot guarantee coverage — a peer redeployed onto a different stepping
  produces an identity the pack has no entry for.
- It expires quickly and therefore shortens `not_after` sharply. A pack of
  roots and policy lives for months; add DCAP collateral and it lives for days.

### Workload spec — `payload/workload-spec.json`

A serialized `WorkloadSpec` — `publisher`, `name`, `version`,
`base_image_mode`, `base_image_ids`, `requirements`, `workload_pcrs256`,
`workload_pcrs384` — which converts through the same path a chain-fetched spec
does.

Keys are `snake_case`, matching `trust-pack.json` and measurement pack version
4, rather than mirroring the contract's Solidity field names.
`base_image_mode` is spelled `any`, `blacklist`, or `whitelist` rather than
carried as the contract's `uint8` `AccessMode`: a JSON file has no ABI to make
`2` self-describing, and an off-by-one between `blacklist` and `whitelist`
inverts an access rule silently.

`publisher` is new with publisher-qualified identifiers and has no on-chain
counterpart: `WorkloadRegistry` stores the spec under a `workloadId` that
already includes the publisher, so the chain path recovers it from the key it
looked the spec up by. A file has no such key, so the reference carries it, and
the verifier derives `workload_id` from the complete
`<publisher>/<name>:<version>` reference exactly as the chain path derives it.

Two checks bind that reference:

- the derived `workload_id` must equal the one the caller asked to verify,
  which is what stops a pack answering for a workload nobody requested;
- the configured `workload-trust` key's owner fingerprint must equal
  `publisher`, per [Signature](#signature).

### Measurement packs — `payload/measurement-packs/*`

Base-image measurement packs in the format defined by
[measurement-pack-spec.md](measurement-pack-spec.md), each as a triple sharing
one stem:

| Entry | Contents |
|---|---|
| `<stem>.json` | The measurement pack, version 4, canonical JSON. |
| `<stem>.sig` | Its detached ES256K signature over those exact bytes. |
| `<stem>.pubkey` | The signing publisher's uncompressed SEC1 secp256k1 public key, `0x` and lowercase hex. |

A directory rather than a single file, because `WorkloadSpec.baseImageIds` is a
list.

**`<stem>.pubkey` is an addressing input, not a trust input.** It is supplied by
the party it constrains, so nothing may be believed on its account. A reader
validates it by recomputation, in this order, and stops at the first failure:

1. `keccak256(abi.encode(KEY_DOMAIN, type_id, key))` over the supplied key must
   equal `subject.publisher` inside the pack;
2. `keccak256(abi.encode(BASEIMAGE_DOMAIN, subject.publisher, subject.name,
   subject.version))` must equal `subject.id`;
3. the `<stem>.sig` signature must verify over the `<stem>.json` bytes under
   that key;
4. `subject.id` must appear in `WorkloadSpec.baseImageIds`.

Step 1 is what makes the key safe to accept from the pack. Forging a pack for a
base image the signer does not publish requires a key whose owner fingerprint
collides with the real publisher's, which is a keccak-256 preimage. Step 3 is
what binds the measurements themselves to that publisher rather than merely
naming them, and step 4 is what binds them to the base image the *workload*
publisher chose.

Pairing the triple by filename stem is safe precisely because every member is
validated by content: a substituted `.pubkey` fails step 1, a substituted `.sig`
fails step 3, and a substituted `.json` fails step 4. The stem is addressing, as
[Content-Indexed Selection](#content-indexed-selection) requires.

**What the inner signature now provides.** The outer pack signature covers
*which* base-image policies ship, which is the workload publisher's decision on
both the chain and the pack path. The inner signature covers *what those
policies say*, which is the base-image publisher's, and the identifier
recomputation is what makes that second authority checkable offline rather than
merely asserted. Earlier revisions of this document claimed the separation
without the identifier change that establishes it; see
[Base-image publisher authority](#base-image-publisher-authority).

What the inner signature does provide as specified: the pack producer cannot
alter a measurement pack it obtained from a base-image publisher without
invalidating that pack's own `.sig`, and a verifier that has independently
pinned the base-image publisher's key by some other means can use it. Neither
property is enforced by anything in this specification.

`atakit-imgbuild measurement-pack` emits the `.json`, `.sig`, and `.pubkey`
triple together. `atakit trust-pack build workload <workload.atawl>` accepts
one or more explicit measurement-pack JSON paths, reads the other two files
beside each JSON file, derives `payload/workload-spec.json` from the measured
workload manifest, and validates the completed archive before writing it. The
same workload policy constructor feeds both this command and
`atakit workload publish`, so the packed and contract forms cannot encode PCR,
attribute, or base-image rules independently.

---

## Content-Indexed Selection

Entries keyed by platform, CPU, or base image are selected by a field inside
their own signed bytes. The filename is addressing only.

| Entry | Selected by |
|---|---|
| `payload/tdx-dcap/*.json` | `selector.fmspc`, `selector.pceId`, `selector.pckCa` |
| `payload/amd-snp-security-policy/*.json` | `cpuid` |
| `payload/measurement-packs/*.json` | `subject.publisher`, `subject.name`, `subject.version` |

Selection matches all three subject fields, and they are exactly the three
inputs `subject.id` derives from, so selecting an entry and deriving the
`base_image_id` the workload spec names are the same operation. Matching on
`(name, version)` alone would not identify a base image uniquely — that pair
does not bind the publisher identity.

Selecting by filename would let an entry be presented as something it is not. A
pack producer could ship a genuine, correctly signed measurement pack for one
base image under the filename of another; every signature would verify, and the
verifier would apply the wrong PCR policy while believing it verified the right
image. The filename is covered only by the pack signature, so only the entry's
own signed content can decide what that entry describes.

This rule is independent of the identifier change recorded under
[Base-image publisher authority](#base-image-publisher-authority) and holds
either way.

`measurement-pack-spec.md` files its own local lookup directory under the
derived id for the same reason, and that id is `0x` followed by 64 lowercase
hexadecimal characters, so no path encoding is involved and nothing in a path
can disagree with the signed data.

## Validity

`not_after` is **derived by the writer**, not chosen: the minimum of the
publisher's intended value and the earliest expiry of every artifact the pack
contains — Azure MAA certificate validity, certificate revocation list
`nextUpdate`, and the validity windows of signed TCB Info and QE Identity.

A pack therefore cannot advertise a longer life than its shortest-lived
content. A reader must reject a pack whose current time falls outside
`[not_before, not_after)`.

## Verification Procedure

A reader performs these steps in order and stops at the first failure.

1. Decompress within the [limits](#archive-limits) below.
2. Reject any entry that is not a regular file, and any absolute path, path
   traversal, symbolic link, hard link, device, FIFO, socket, or duplicate
   path.
3. Parse `trust-pack.json`. Reject unknown fields and any `format` other than
   `1`.
4. Re-serialize the parsed value in RFC 8785 canonical form and reject unless
   it is byte-identical to the `trust-pack.json` bytes read from the archive.
5. Verify `trust-pack.sig` over `sha256(trust-pack.json bytes)` using the
   verifier's configured public key **for the role named by `kind`**.
6. Reject unless the current time is within `[not_before, not_after)`.
7. Reject any payload path outside the namespace for `kind`.
8. Reject unless the set of payload entries and the key set of `hashes` are
   identical, and every entry's SHA-256 matches.
9. Parse each entry in its declared format. For `kind: "workload-trust"`,
   reject unless every `payload/measurement-packs/*.json` has a `.sig` and a
   `.pubkey` on the same stem and no `.sig` or `.pubkey` stands without its
   `.json`.

Steps 1 through 9 establish that the archive is intact and was signed by the
role's publisher. They do **not** establish what a `workload-trust` pack's
base-image measurements are authorized to say; that is the recomputation
sequence under
[Measurement packs](#measurement-packs--payloadmeasurement-packs), which runs
when an entry is selected, because it needs the `base_image_id` the workload
spec names.

Step 4 must precede step 5. The signature covers the bytes as they appear in
the archive, so without it a producer could ship non-canonical bytes that still
verify, and two byte-different archives carrying identical parsed content would
pin to two different digests. Rejecting before the signature check also keeps
the canonical-form requirement from being something only a well-behaved
producer honours.

A pack that fails any step is rejected **whole**. Partial acceptance is not
defined.

## Verification Modes

A verification runs in exactly one of three modes, selected explicitly by
configuration. There is no default and no precedence rule.

### `chain`

Trust anchors, base-image measurement policy, workload policy, AMD SEV-SNP
security policy, Azure MAA signing keys, AWS document limits, and every other
registry-published policy value resolve from the configured chain.

**Configured `.atatp` trust packs are rejected.** Presenting a pack in `chain`
mode is a configuration error, not an input that is ignored.

### `trust-pack`

Every trust anchor and policy input resolves from the configured trust packs.

- **No registry-policy fallback for any missing entry.**
- The verifier does not query `SessionRegistry` or any registry policy
  contract. It may query Automata on-chain PCCS only for vendor-signed Intel
  collateral, under the independent collateral rule above.
- A missing required input **fails closed and names the input**.
- Registry policy-authority configuration is rejected. A configuration
  carrying both that authority and a pack is refused before any verification
  begins. A collateral-only Automata on-chain PCCS RPC endpoint is not registry
  policy-authority configuration.

### `explicit`

The operator supplies the trust inputs directly, as files and flags. This is a
distinct trust model, not a compatibility path: the operator is the authority,
which is what makes it the right mode for offline verification, tests, and
measurement campaigns.

- **`.atatp` inputs are rejected.**
- **Missing trust inputs are never filled from the chain.**
- `--measurements` and its publisher identity supply the base-image policy.
- The supplied root certificates, Azure MAA certificates, AMD SEV-SNP security
  policy, AWS document limits, and workload policy must between them cover
  everything the presented platform requires.
- A missing required input **fails closed and names the input**.

The mode is complete or it fails. There is no partial `explicit` verification
topped up from elsewhere.

### Why exclusive rather than layered

An earlier revision of this design let packs supply what they had and the chain
fill the rest. That is withdrawn. Layering means every input has a silent
precedence rule, and an operator who believes they pinned a value cannot tell
from the result whether the pinned value was used or a chain value quietly
replaced a pack entry that was missing, malformed, or shadowed. Two sources
also means two answers to "who is the trust authority for this verification",
which is the question the mode now answers outright.

**Represent this as one mutually exclusive configuration type**, not as
independent optional fields validated after the fact. A configuration that
cannot express two sources cannot be misconfigured into two. The top-level
verification API selects one complete source before resolution begins; there is
no operation that merges one source's inputs into another's.

### The trust authority follows the mode

Each mode names a different authority, and that is the point of having three:
the registry in `chain`, the pack publisher in `trust-pack`, the operator in
`explicit`.

In `trust-pack` and `explicit` modes the verifier does not additionally enforce
chain whitelist membership, registration, activation, or revocation state — it
has no chain to ask, by construction. An operator choosing either is choosing
that authority in place of the registry's, and the mode makes the choice
explicit rather than emergent.

**Session binding is separate from the policy authority.** It is a signed
property of the session evidence. A local-bound session needs no selected
chain coordinates and may be verified under any policy authority. A
chain-bound session requires verifier-selected chain ID and `SessionRegistry`
coordinates so its claims can be authenticated. The current `trust-pack` and
`explicit` sources do not contain those coordinates, so chain-bound sessions
fail closed under those modes. Missing coordinates must not be filled from a
registry client. A caller's optional local-versus-chain acceptance policy is
also separate from the policy authority.

## Failure Rules

**A pack that exists but cannot be used is fatal, never a fallback.** An
invalid signature, an expired validity window, a namespace violation, or a hash
mismatch means the verifier refuses to start. Falling back to another source
would mean an operator believes they pinned something and silently did not.

**Duplicate claims across packs are fatal.** If two packs supply the same
logical input — the same CPUID policy, the same root, the same base image
measurement pack — the verifier refuses to start. Silently choosing one would
make the winner invisible.

**A missing required input is fatal and names the input.** In `trust-pack` mode
a pack set must be complete for the platform being verified. Which inputs are
required depends on the peer's `platform.cloud` and `platform.tee` and is
therefore known only after the attestation response arrives, so completeness is
a per-verification property, not something startup can fully check.

**A packed entry that is present but unusable never triggers a fetch.** An
entry that is invalid, expired, or does not match the presented evidence fails
the verification. It does not fall through to a vendor endpoint. The only
permitted fetch is for collateral the pack does not contain at all — see
[Vendor collateral is not a trust source](#vendor-collateral-is-not-a-trust-source).

## Digest Pinning

A verifier may pin a pack by the SHA-256 of `trust-pack.json` bytes — the same
bytes the signature covers. Because that file is canonical and hashes every
payload entry, pinning it pins the complete contents deterministically,
independent of how the archive was produced.

Unpinned, a verifier accepts any pack that role's publisher signs, and the
publisher may reissue freely. Pinned, the verifier accepts exactly one
artifact, and a reissue requires the verifier's configuration to change.

Pinning is the **only** rollback control. Unpinned, an operator may serve any
older pack the publisher legitimately signed until it expires, bounded by
`not_after` alone. `revision` does not bound it — the field is informational
and no reader enforces it.

## Archive Limits

A conforming reader must bound decompression before parsing anything, and must
reject when a bound is exceeded rather than continuing:

| Limit | Value |
|---|---|
| Single entry size | 4 MiB |
| Entry count | 1024 |
| Total decompressed size | 64 MiB |
| Compression ratio | 100:1 |

The single-entry limit is fixed, not provisional: it is
`MAX_COLLATERAL_COMPONENT_BYTES` in `atakit-attestation`
(`crates/atakit-attestation/src/tdx_dcap.rs:17`, `4 * 1024 * 1024`). An
embedded Intel TDX DCAP collateral component that a reader accepts here but
`atakit-attestation` later rejects would be a wasted parse, so the two must
agree. Changing one requires changing the other.

The other three values are **provisional**. They were chosen to sit well above
the largest pack this design anticipates — PEM roots, Azure MAA signing
certificates, and `AmdSnpSecurityPolicy` JSON are all single-digit kibibytes,
and only `payload/tdx-dcap/` grows with hardware coverage — but no pack has
been produced yet, so none of them has been measured against a real artifact.
Confirm them against a produced `collateral-trust` pack carrying a full
Provisioning Certificate Caching Service snapshot before this specification is
treated as settled. Raise a bound only with a recorded measurement showing a
legitimate pack exceeds it; do not raise one in response to an untrusted
archive.

## Base-image publisher authority

An image or workload identifier includes its publisher fingerprint:

```text
id = keccak256(abi.encode(keccak256(domain), ownerFingerprint, name, version))
```

The verifier recomputes this identifier from the signed subject and checks it
against the expected identity. Each measurement pack supplies a public key,
but that key must hash to the expected publisher fingerprint. The workload
publisher cannot substitute another base-image publisher merely by placing a
different public key in a trust pack.

## Relationship to `TrustAnchors`

A `collateral-trust` pack converts into `TrustAnchors` fields and
`TlsVerificationTrust.amd_snp_crls`. A `workload-trust` pack converts into
`MeasurementPolicy` and `TrustedWorkloadSessionPolicy`. Two kinds, two
destinations, no overlap.

The chain, trust packs, and operator-supplied files produce the same typed
values, and the source must never change what is checked. They are
**alternatives**, selected by [mode](#verification-modes), not layers to be
merged. A `TrustAnchors` value is built from one selected source; it is never
assembled by overlaying one source's values onto another's.

A verifier still records which source supplied each field. Under exclusive
modes that record is largely uniform within a run — which is the point. It
remains worth reporting because vendor collateral may still arrive from a
configured HTTP or Automata on-chain PCCS endpoint in `trust-pack` and
`explicit` modes, and a reader should be able to see that without inferring it.

Operator-supplied files are the `explicit` mode. They are
neither folded into `trust-pack` nor removed: they carry a distinct trust
model — the operator as authority — which is what offline verification, tests,
and measurement campaigns need.
