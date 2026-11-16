# Saved Platform-Profile JSON Specification

`atakit-imgbuild generate-platform-profile` writes one saved platform-profile
JSON file for each measured cloud and TEE profile. The file is the source used
by `atakit-imgbuild publish` and by measurement-pack generation.

This document specifies the local saved file. It is not the measurement-pack
wire format. See [measurement-pack-spec.md](measurement-pack-spec.md) for the
portable offline-verification format.

## Location and File Name

The file is stored under:

```text
<image-store>/<repository>/<tag>/platform_profiles/<profile-name>.json
```

`<profile-name>.json` must match `platformProfile.name`. The profile name and
every variant name must be valid path components. Profile names must be unique
within the directory. Variant names must be unique within the file.

## Top-Level Shape

```json
{
  "platformProfile": {
    "name": "gcp-tdx",
    "cloudType": "gcp",
    "teeType": "tdx",
    "pcrBankSelection": "sha256",
    "invariantPcrPolicy": {
      "pcrSpecs256": [],
      "pcrSpecs384": []
    },
    "attributes": [
      {
        "name": "atakit.attestation.v1.tee.intel-tdx.debug.enabled",
        "value": false
      },
      {
        "name": "atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed",
        "value": ["ok"]
      },
      {
        "name": "example.environment",
        "value": "production"
      }
    ]
  },
  "variants": [
    {
      "name": "c3-standard-4",
      "variantPcrPolicy": {
        "pcrSpecs256": [],
        "pcrSpecs384": []
      },
      "attributes": []
    }
  ]
}
```

All top-level fields are required.

### `platformProfile`

| Field | Type | Required | Rule |
|---|---|---|---|
| `name` | string | yes | Must match the JSON file name without `.json`. |
| `cloudType` | string | yes | Non-empty value measured from `/status.platform`, not inferred from the profile name. |
| `teeType` | string | yes | Non-empty value measured from `/status.platform`. Reserved attribute filtering recognizes `tdx` and `sev-snp`. |
| `pcrBankSelection` | string | yes | `sha256`, `sha384`, or `sha256-and-sha384`. |
| `invariantPcrPolicy` | PCR policy block | yes | Contains `pcrSpecs256` and `pcrSpecs384`. Each array must have unique, sorted indexes limited to 0 through 16 or 23. |
| `attributes` | array of attributes | no | Defaults to `[]`. Duplicate readable or recognized reserved keys are rejected. The on-chain registry also rejects every duplicate encoded key during publication. |

### `variants[]`

| Field | Type | Required | Rule |
|---|---|---|---|
| `name` | string | yes | Non-empty, unique within the file, and free of NUL bytes. |
| `variantPcrPolicy` | PCR policy block | yes | Contains `pcrSpecs256` and `pcrSpecs384`. Each array must be disjoint from the same-bank array in `invariantPcrPolicy`. |
| `attributes` | array of attributes | no | Defaults to `[]`. Duplicate readable or recognized reserved keys are rejected. Custom attributes and all six reserved TEE attributes are allowed. The on-chain registry also rejects every duplicate encoded key during publication. |

## Azure SEV-SNP firmware variants

`atakit-imgbuild generate-platform-profile IMAGE --platform azure-sev-snp
--strict` automatically groups Azure SEV-SNP samples by their complete SHA-256
PCR 0/PCR 2 pair, even when only one pair is present. Other platforms keep
machine-type variant names. Grouping does not establish provider provenance
or replace the operator's baseline trust review.

Each group requires at least three saved samples. The operator must include a
normal reboot and a separate VM of the same image and machine type. The tool
counts files; it cannot establish independent VM placement from file names.
Azure firmware generation rejects other unstable selected PCRs within a group,
even when `--strict` is omitted.
Both PCR 0 and PCR 2 must remain exact static rules. Exclusions or dynamic
rules for either PCR are rejected in this mode.

The variant name is `<machine-type>@firmware-<digest>`, where `digest` is the
64-character lowercase Keccak-256 digest of:

```text
ASCII("atakit.azure-sev-snp.firmware.v1") || 0x00 || PCR0_SHA256 || PCR2_SHA256
```

The PCR values are raw 32-byte values in that order. The machine type remains
unchanged in saved measurement input; the generator changes only its in-memory
grouping key. This suffix gives each complete pair a distinct registry ID.
The name is not a certificate or proof that the firmware is trusted.

Machine-type attributes apply to every firmware variant of that machine.
Attributes configured for the full firmware variant name override those
machine-type entries. Profile and base-image attributes retain their normal
precedence. Existing saved machine-type attributes are preserved when creating
the corresponding firmware variants.

The measurement pack and registry reader map canonical firmware names back to
the original machine type. The verifier selects exactly one matching complete
PCR policy. Existing clients that reject multiple variants for one machine
type must be updated before using these profiles. The contract ABI and PCR
comparison encoding do not change.

For Azure SEV-SNP, the portal reads SHA-256 PCR 0 and PCR 2 from its supervisor
and computes the same firmware variant name and ID. It does not read a variant
ID from initialization `pcr_policy`. Other platforms retain the machine-type
derivation. The contract verifies the evidence against the exact claimed ID's
registered policy; it does not search other variants.

`pcr_policy` retains its existing role as fallback measurement-collection rules
when the portal cannot resolve the registry policy. Its IDs must match the
session independently selected by the portal.

The updated Azure portal requires firmware-named profiles generated by the
updated builder. It does not fall back to an old machine-type ID if its firmware
ID is absent from the registry. New image contents still require fresh image
measurements. At a new boot, the portal derives its claim from that boot's PCRs;
an unknown firmware pair yields an unregistered ID and cannot register.

## PCR Spec Shape

```json
{
  "pcrIndex": 4,
  "verifyType": 0,
  "matchData": [
    "0x0000000000000000000000000000000000000000000000000000000000000000"
  ],
  "indexedAllowedValues": [],
  "eventIndices": [1, 3],
  "totalEvents": 4
}
```

| Field | Type | Required | Rule |
|---|---|---|---|
| `pcrIndex` | integer | yes | 0 through 16 or 23. |
| `verifyType` | integer | yes | `0` is `STATIC`, `1` is `DYNAMIC_SUBSET`, `2` is `DYNAMIC_SUBSEQUENCE`, and `3` is `DYNAMIC_INDEXED_EVENT_SETS`. |
| `matchData` | array of hexadecimal strings | yes | `STATIC` requires exactly one entry. Landmark modes require at least one entry. Type `3` requires this array to be empty. Values are 32 bytes in SHA-256 rules and 48 bytes in SHA-384 rules. |

Comparison type `4` (`EXTEND_FROM_ZERO`) is reserved for provider PCR15 rules
that `SessionRegistry` creates in memory after it verifies the TEE report. A
platform profile does not store or generate this provider rule.
| `indexedAllowedValues` | array of arrays of hexadecimal strings | no | Type `3` requires one sorted, unique, non-empty allowed set for each `eventIndices` entry. Other types omit it. |
| `eventIndices` | array of integers | no | Type `3` publishes these checked indexes inside `comparison`. For landmark modes this remains display metadata. |
| `totalEvents` | integer | no | Type `3` publishes this exact event count inside `comparison`. For landmark modes this remains display metadata. |

This saved profile is producer input. Publication converts every rule to the
single opaque `comparison` blob used by the registry and measurement-pack v3.

## Built-In GCP and Azure Classification

When no operator file replaces the platform defaults,
`atakit-imgbuild generate-platform-profile` uses the following classification
for both supported TEE types on each cloud:

| Cloud | Excluded PCRs | Profile-wide invariants | Measurement-variant PCRs |
|---|---|---|---|
| GCP | 1, 2, 10, 15, 23 | 4, 9, 11 | 0, 3, 5, 6, 7 |
| Azure | 1, 5, 6, 10, 15, 23 | 4, 9, 11 | 0, 2, 3, 7 |

PCR 1 is excluded on both clouds because boot order, boot-device paths, and
device enumeration change when disk topology changes. GCP PCR 2 and Azure PCR
5 contain deployed disk-topology measurements. Azure PCR 6 contains
per-instance measurements. PCR 10 changes across boots. PCR 15 binds one CVM,
and PCR 23 is the runtime workload measurement.

The profile-wide PCRs measure the base image. The measurement-variant PCRs
describe the selected hardware configuration and remain in
the matching `variants[].variantPcrPolicy.pcrSpecs256` and
`variants[].variantPcrPolicy.pcrSpecs384` arrays even when currently collected machine types happen
to produce equal values. PCRs 8, 12, 13, 14, and 16 through 22 use the same
variant classification when the measured platform supplies usable values.

These defaults do not replace measurement validation. Profile generation
still requires samples from each accepted cloud, TEE type, and machine type,
including a reboot and a fresh instance before publication. An operator file
under `<config-dir>/platforms/<profile-name>.toml` may replace the exclusion
set or a classification for evidence-backed platform behavior. The
`--exclude-pcr` command option adds to the configured exclusion set.

## Attribute Shapes

Each attribute must use exactly one of these two shapes.

### Readable Shape

The readable shape contains only `name` and `value`:

```json
{
  "name": "example.environment",
  "value": "production"
}
```

Custom names require a string value. Publication encodes them as:

```text
key   = keccak256(bytes(name))
value = keccak256(bytes(value))
```

The following names have reserved value types:

| Name | Required JSON value | Applies to |
|---|---|---|
| `atakit.attestation.v1.tee.intel-tdx.debug.enabled` | Boolean | `teeType = "tdx"` |
| `atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed` | array of supported status-name strings | `teeType = "tdx"` |
| `atakit.attestation.v1.tee.amd-sev-snp.debug.enabled` | Boolean | `teeType = "sev-snp"` |
| `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled` | Boolean | `teeType = "sev-snp"` |
| `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum` | `0x`-prefixed bytes32 string | `teeType = "sev-snp"` |
| `atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy` | `0x`-prefixed bytes32 string | `teeType = "sev-snp"` |

Unknown names beginning with `atakit.attestation.v1.tee.` are rejected.

The Intel TDX TCB status array must be non-empty, contain unique supported
names, and include `ok`. The supported names and mask bits are defined in
[baseimage-toml-spec.md](baseimage-toml-spec.md).
The reader normalizes this array into canonical bit order.

### Hexadecimal Shape

The hexadecimal shape contains only `key` and `value`:

```json
{
  "key": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
```

Both fields must be `0x`-prefixed bytes32 values. This shape is valid for
ordinary attributes. If `key` equals a reserved hash,
the reader validates the reserved encoding and normalizes it to the readable
shape. Invalid Boolean values, invalid Intel TDX TCB masks, and invalid packed
AMD SEV-SNP policies are rejected. The packed layouts are defined in
[AMD SEV-SNP Security Policy Specification](amd-sev-snp-security-policy-spec.md).
An ordinary hexadecimal key is opaque to the saved-file reader. The
BaseImageRegistry performs the final duplicate-key check when the profile is
published.

## TEE Filtering

The saved profile reader rejects a reserved attribute that does not apply to
`platformProfile.teeType`. For example, an AMD SEV-SNP debug attribute is not
valid in a saved `tdx` profile. Custom attributes apply to every TEE type.

This authoring rule is stricter than the on-chain ABI. `PlatformProfile` does
not contain a TEE type. On chain, SessionRegistry obtains `teeType` from the
successful type-specific TeeVerifier result and evaluates only the reserved
attributes for that TEE platform.

## Generation and Regeneration

`atakit-imgbuild generate-platform-profile` applies
`baseimage.toml` declarations in this order:

1. Start with `[attributes.all]`.
2. Replace matching keys from
   `[attributes.profiles."<profile-name>"]`.
3. Keep custom attributes.
4. Keep only reserved entries from `[attributes.all]` that apply to the
   measured `teeType`. Reject a named profile entry for another TEE type.
5. Preserve existing saved profile attributes that were not replaced by the current
   configuration.
6. Add missing safe defaults to the platform profile:
   - Intel TDX debug: `false`
   - Intel TDX TCB status: `["ok"]`
   - AMD SEV-SNP debug: `false`
   - AMD SEV-SNP `MIGRATE_MA`: `false`
   Do not add an AMD SEV-SNP packed TCB or `PLATFORM_INFO` value. Absence is
   meaningful: it selects the active exact-CPUID registry default.
7. For each variant, preserve existing attributes that are not replaced by
   `[attributes.variants."<profile-name>"."<variant-name>"]`.
8. Add the exact configured variant entries. Reject an unknown profile or
   variant target and reject a reserved entry for another TEE type. Do not
   copy inherited `[attributes.all]` or profile entries into the variant
   array.

An explicit current configuration value replaces the existing value for the
same key. Otherwise, regeneration preserves an existing explicit `true`,
`false`, TCB array, packed bytes32 policy, or custom value. Packed AMD SEV-SNP
policies and the Intel TDX TCB status mask use the same rule as every other
attribute.

## Publication

`atakit-imgbuild publish` converts every saved attribute into the existing
on-chain `Attribute { key, value }` shape. It does not publish `cloudType`,
`teeType`, `eventIndices`, or `totalEvents`. `cloudType` and `teeType` remain
trusted local metadata for profile selection and filtering; the TEE type used
during session registration comes from the successful type-specific verifier
result. Publication preserves and displays every profile and variant
attribute. The verifier resolves an effective value by key in this order:
selected measurement variant, selected platform profile, then the
attribute-specific missing default. `[attributes.all]` is an authoring input
that is materialized into each generated platform profile.
