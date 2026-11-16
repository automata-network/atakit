# AMD SEV-SNP Security Policy Specification

This specification defines the AMD SEV-SNP security state that atakit reads
from a signed attestation report. It also defines the default policy registry,
base-image declarations, workload requirements, and offline verification.

## Scope

This version supports AMD family `0x19` with model `0x00` through `0x1f`.
This covers the supported Milan and Genoa processor models. The exact
processor key is:

```text
cpuid = (family << 16) | (model << 8) | stepping
```

The registry therefore separates different family, model, and stepping
values. Turin is not supported. The FMC TCB component used by Turin must be
zero.

## Reserved attributes

The two Boolean attributes keep their existing encoding:

| Name | Meaning | Value |
|---|---|---|
| `atakit.attestation.v1.tee.amd-sev-snp.debug.enabled` | `POLICY.DEBUG` | `false = bytes32(0)`, `true = bytes32(uint256(1))` |
| `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled` | `POLICY.MIGRATE_MA` | `false = bytes32(0)`, `true = bytes32(uint256(1))` |

The two packed attributes use these exact keys:

| Name | `keccak256(bytes(name))` |
|---|---|
| `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum` | `0x15647616165618c3cfed2ab7f083f2f7eef7f57519e43d97ab220ff7860157d2` |
| `atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy` | `0x279fd9a317a2dc8dfeea12391ea795ac6c21ff52977c499f910f07a27afbed7d` |

Authoring tools reject any other name under
`atakit.attestation.v1.tee.`. On-chain contracts recognize the exact hashes.

### `tcb.minimum`

The value is one `bytes32`. It contains four 64-bit lanes:

```text
bits 255..192  CURRENT_TCB minimum
bits 191..128  REPORTED_TCB minimum
bits 127..64   COMMITTED_TCB minimum
bits 63..0     LAUNCH_TCB minimum
```

Each lane uses the normalized AMD TCB component layout:

```text
bits 7..0    bootloader
bits 15..8   TEE
bits 23..16  SNP
bits 31..24  microcode
bits 63..32  zero
```

For example, a lane with bootloader `4`, TEE `0`, SNP `29`, and microcode
`222` is `0x00000000de1d0004`. A policy that applies this minimum to all four
report fields is:

```text
0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004
```

Comparison is component by component. Each actual component must be greater
than or equal to its matching minimum. Numeric comparison of the complete
`bytes32` is not valid.

### `platform-info.policy`

The value is one `bytes32`:

```text
bits 63..0    bits that PLATFORM_INFO must set
bits 127..64  bits that PLATFORM_INFO must clear
bits 255..128 zero
```

The required-set and required-clear masks must not overlap. This version
supports these `PLATFORM_INFO` bits:

| Bit | AMD field |
|---:|---|
| 0 | `SMT_EN` |
| 1 | `TSME_EN` |
| 2 | `ECC_EN` |
| 3 | `RAPL_DIS` |
| 4 | `CIPHERTEXT_HIDING_DRAM_EN` |
| 5 | `ALIAS_CHECK_COMPLETE` |

Every other bit is unsupported. In particular, `TIO_EN` at bit 7 is not
supported in this version.

For example, require `ALIAS_CHECK_COMPLETE` to be set and `SMT_EN` to be
clear:

```text
0x0000000000000000000000000000000000000000000000010000000000000020
```

## Signed report validation

The verifier first checks the proof-bound raw report hash. It then requires
the raw report to be exactly 1,184 bytes and applies all checks below before it
returns security state.

- Report version must be 3, 4, or 5.
- Signature algorithm must be ECDSA P-384 with SHA-384.
- Signing-key selection and mask-chip settings must be valid.
- Required policy bits must be present and policy-reserved bits must be zero.
- `VMPL` must be zero.
- `REPORT_ID_MA` must be either all zero or all `0xff`. Both values mean that
  no migration agent is associated. Every other value is rejected because
  active migration-agent association is not supported, even when
  `POLICY.MIGRATE_MA` is permitted.
- Every raw TCB field must have zero reserved and FMC bytes.
- `reported_tcb <= committed_tcb <= current_tcb` and
  `launch_tcb <= committed_tcb` must hold component by component.
- CPUID reserved bytes must be zero and the exact CPUID must be supported.
- `PLATFORM_INFO` may contain only the six supported bits.
- Current-version and committed-version reserved bytes must be zero.
- For report versions before 5, bytes `0x1f8..0x29f` must be zero.
- For report version 5, launch and current mitigation vectors at `0x1f8` and
  `0x200` are permitted; bytes `0x208..0x29f` must be zero.

The successful `TeeVerificationResult` contains:

```solidity
bytes32 amdSevSnpTcbValues;
uint64 amdSevSnpPlatformInfo;
uint24 amdSevSnpCpuid;
uint32 amdSevSnpReportVersion;
uint64 amdSevSnpLaunchMitigationVector;
uint64 amdSevSnpCurrentMitigationVector;
```

`amdSevSnpTcbValues` uses the same four-lane layout as `tcb.minimum`.
`enabledTeeAttributes` contains the verified Boolean debug and `MIGRATE_MA`
states. Reports before version 5 return zero for both mitigation vectors.

## Default registry

`AmdSnpSecurityPolicyRegistry` is an upgradeable registry with one record for
each exact CPUID:

```solidity
struct AmdSnpSecurityPolicy {
    bytes32 minimumTcb;
    bytes32 platformInfoPolicy;
    bytes32 sourceDigest;
    uint64 revision;
    bool active;
    uint64 requiredLaunchMitigationVector;
    uint64 requiredCurrentMitigationVector;
}
```

The two mitigation-vector fields are required bit masks. For each field, the
registry checks `(actual & required) == required`. Extra report bits are
allowed. If either required mask is nonzero, the report must be version 5.
Zero for both masks means that report versions 3 through 5 remain allowed and
the registry does not require any mitigation-vector bit.

The mitigation-vector masks are exact-CPUID registry requirements. Base-image
and workload authors cannot replace or relax them.

The owner submits a CPUID-sorted array of updates. A nonzero `sourceDigest`
identifies the reviewed source file. Revisions may only move forward. Reusing
a revision is allowed only when the update is identical. A policy can be
deactivated, but a session cannot use a missing or inactive policy.

The deployment creates an empty registry. An operator must load an active
policy for every allowed CPUID before enabling session registration. The
checked update script reads a JSON file:

```json
{
  "policies": [
    {
      "cpuid": 1638657,
      "expectedRevision": 0,
      "revision": 1,
      "active": true,
      "minimumTcb": "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
      "platformInfoPolicy": "0x0000000000000000000000000000000000000000000000000000000000000020",
      "requiredCurrentMitigationVector": 22,
      "requiredLaunchMitigationVector": 22
    }
  ]
}
```

The example decimal CPUID is Milan B1 `0x190101`. The mitigation-vector value
22 is `0x16`, which requires bits 1, 2, and 4 in both signed version-5 report
fields. The mask follows AMD-SB-3020 bit 1, AMD-SB-3016 bit 2, and AMD-SB-3030
and AMD-SB-3034 bit 4 for Milan. The update script hashes the exact JSON text
and passes the hash as `sourceDigest`.

## Explicit verifier policy file

`atakit workload init`, `atakit cloud deploy`, `atakit cloud init`,
`atakit cloud verify-session`, and `atakit cloud session` accept
`--amd-snp-security-policy <path>`. The path must contain an
`atakit.amd-sev-snp-security-policy` version 1 JSON document:

```json
{
  "schema": "atakit.amd-sev-snp-security-policy",
  "version": 1,
  "policies": [
    {
      "cpuid": "0x190101",
      "minimumTcb": "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
      "platformInfoPolicy": "0x0000000000000000000000000000000000000000000000000000000000000020",
      "requiredLaunchMitigationVector": "0x0000000000000016",
      "requiredCurrentMitigationVector": "0x0000000000000016"
    }
  ]
}
```

Every hexadecimal field uses a lowercase `0x` prefix and a fixed width.
`cpuid` contains exactly three bytes. Each packed policy contains exactly 32
bytes. Each mitigation vector contains exactly eight bytes. Every field is
required. Unknown fields, an empty policy list, duplicate CPUID values,
unsupported CPUID values, and invalid packed policies fail closed.

The file is an explicit verifier trust input. Evidence cannot select it. When
the file contains the report's exact CPUID, that entry takes precedence over
`AmdSnpSecurityPolicyRegistry`. When it does not contain the report's CPUID, a
configured chain may still supply the active registry record. Without either
source, AMD SEV-SNP verification fails. atakit reads the file for the current
command and does not cache or persist it.

## Base-image and workload policy

A base image declares packed values through `[attributes.all]`, a named
`[attributes.profiles."<profile-name>"]` table, or a named
`[attributes.variants."<profile-name>"."<variant-name>"]` table:

```toml
[attributes.all]
"atakit.attestation.v1.tee.amd-sev-snp.debug.enabled" = false
"atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled" = false
"atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum" = "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004"
"atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy" = "0x0000000000000000000000000000000000000000000000000000000000000020"

[attributes.variants."gcp-sev-snp"."n2d-standard-4"]
"atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum" = "0x00000000df1e000500000000de1d000400000000de1d000400000000de1d0004"
"atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy" = "0x0000000000000000000000000000000000000000000000010000000000000020"
```

A workload uses exactly one packed string value:

```toml
[workload.attributes]
"atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum" = [
  "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
]
"atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy" = [
  "0x0000000000000000000000000000000000000000000000000000000000000020",
]
```

These values are already packed `bytes32` values. Authoring tools do not hash
the value string. They decode the hex and publish the exact 32 bytes.

Custom attributes and all six reserved TEE attributes use the same lookup.
The selected measurement-variant value replaces the matching platform-profile
value. If the variant omits a key, the profile value applies. Missing AMD
SEV-SNP packed values are zero.

One base image or workload may contain both Intel TDX and AMD SEV-SNP
reserved attributes. Authoring tools retain the complete declared list and
apply the entries that match each generated profile. Session verification
evaluates only the reserved attributes for `TeeVerificationResult.teeType`.
Custom attributes are not filtered.

## Effective policy

The active exact-CPUID registry policy supplies defaults. It is not an
independent mandatory floor.

For `tcb.minimum`, resolve the two policy sides independently:

```text
B = measurement-variant value, otherwise platform-profile value,
    otherwise the active exact-CPUID registry default

W = explicit workload value, otherwise the active exact-CPUID registry default
```

The effective TCB minimum is the component-wise maximum of `B` and `W`. The
signed current, reported, committed, and launch TCB values must satisfy that
effective minimum component by component.

This rule permits a deliberate two-party relaxation:

- If only the base image declares a value below the registry default, the
  missing workload value resolves to the registry default.
- If only the workload declares a value below the registry default, the
  missing base-image value resolves to the registry default.
- If both sides explicitly declare lower values, those lower values take
  effect.

For `platform-info.policy`, resolve `B` and `W` in the same way. Combine
`B.requiredSet` with `W.requiredSet`, and combine `B.requiredClear` with
`W.requiredClear`. Reject any bit that the combined policy requires both set
and clear. The registry policy participates only when the corresponding side
has no explicit value. It is not merged again after resolution.

The Boolean attributes keep their safe defaults. A missing base-image
declaration means `false`. A missing workload requirement permits only
`false`.

The registry always applies `requiredLaunchMitigationVector` and
`requiredCurrentMitigationVector` before the authorable TCB,
`PLATFORM_INFO`, and Boolean policies. These two masks have no base-image or
workload override path.

Full registration, `renewSession`, and session recovery verify a new report
and resolve against the current active exact-CPUID registry defaults.
`rotateKey` does not carry a new TEE report. It only changes the session key
and inherits the security state accepted by the preceding registration or
renewal.

## Offline verification

The offline verifier performs the same report parsing and policy resolution as
the contracts. It accepts the active CPUID default through one of two trust
paths:

1. Resolve `SessionRegistry.teeSecurityPolicyVerifier()`, resolve
   `TeeSecurityPolicyVerifier.amdSnpSecurityPolicyRegistry()`, then call
   `getActivePolicy(cpuid)` on that registry.
2. Receive an explicit `AmdSnpSecurityPolicy` in the verifier's trusted input.

The evidence bundle cannot supply its own trusted registry default. A missing,
inactive, duplicate, unsupported, or mismatched CPUID policy fails closed.
TLS bootstrap applies the policy before sending workload data to `POST /init`.
Committed-session verification applies the same mitigation-vector checks.
When TLS verification has no workload, it applies only resolved base-image
policy `B`. An explicit base-image value therefore replaces the registry
default for that verification. Hard report validation remains unchanged and
cannot be relaxed through attributes.

Until a real signed version-5 report has passed both offline and contract
verification for the exact CPUID, operators must publish zero for both
mitigation-vector masks. A later nonzero update needs a new policy revision
and the normal `sourceDigest` review.
