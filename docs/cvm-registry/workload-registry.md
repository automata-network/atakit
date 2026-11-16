# WorkloadRegistry -- Detailed Analysis

**File**: `src/WorkloadRegistry.sol`
**Interface**: `src/interfaces/registries/IWorkloadRegistry.sol`
**Role**: Manages native SHA-256 and SHA-384 workload measurement policies for PCR0 through PCR16 and PCR23

## Inheritance

```
IWorkloadRegistry
OwnableUpgradeable
PausableUpgradeable
UUPSUpgradeable
```

## Immutables

| Variable | Type | Purpose |
|---|---|---|
| `signatureVerifier` | `ISignatureVerifier` | Signature verification dependency |

## Storage

| Variable | Type | Purpose |
|---|---|---|
| `_workloads` | `mapping(bytes32 => WorkloadSpecStorage)` | Workload specifications |
| `_baseImageSet` | `mapping(bytes32 => mapping(bytes32 => bool))` | Base image allowlist/blocklist lookup |
| `_whitelist` | `mapping(bytes32 => bool)` | Owner fingerprint whitelist |
| `__gap` | `uint256[47]` | Storage gap for upgrades |

## Storage Struct

```solidity
struct WorkloadSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;              // owner fingerprint
    WorkloadSpec workloadSpec;  // full specification
}
```

## Data Model

```solidity
struct WorkloadSpec {
    string name;
    string version;
    uint64 sessionTtl;                          // session TTL in seconds (0 => SessionRegistry default of 30 days)
    AccessMode baseImageMode;            // ANY | WHITELIST | BLACKLIST
    bytes32[] baseImageIds;              // list for whitelist/blacklist
    AttributeRequirement[] requirements; // constraints on platform attributes
    PcrPolicyBlock workloadPcrPolicy;
}

struct AttributeRequirement {
    bytes32 key;
    bytes32[] allowedValues;  // empty = any value accepted (just require key exists)
}

enum AccessMode {
    ANY,        // all base images allowed
    BLACKLIST,  // listed base images blocked
    WHITELIST   // only listed base images allowed
}
```

## ID Derivation

`ownerFingerprint` is the fingerprint of the `ownerIdentity` that authorizes
registration.
```
workloadId = keccak256(abi.encode(WORKLOAD_DOMAIN, ownerFingerprint, name, version))
```

## Public Functions

### `registerWorkload`
```solidity
function registerWorkload(
    WorkloadSpec calldata spec,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 workloadId)
```

- Registers workload with full policy specification
- `spec.sessionTtl` is consumed later by `SessionRegistry`; `sessionTtl == 0` means "use DEFAULT_CVM_TTL (30 days)"
- Computes owner fingerprint, verifies signature over `sha256(abi.encode(WORKLOAD_REGISTER_MSG, chainid, address(this), opExpiresAt, spec))`
- Registration allowed when: unpaused OR owner is whitelisted (uses `_checkRegistrationAllowed`, NOT `whenNotPaused`)
- Populates `_baseImageSet` mapping for efficient `isBaseImageAllowed` lookups
- Validates: signature expiry, PCR order, requirement key uniqueness
- Emits: `WorkloadRegistered`

### `deactivateWorkload`
```solidity
function deactivateWorkload(
    bytes32 workloadId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external
```

- Sets `isRevoked = true` (soft delete)
- Requires owner signature over `sha256(abi.encode(WORKLOAD_DEACTIVATE_MSG, chainid, address(this), opExpiresAt, workloadId))`
- Emits: `WorkloadDeactivated`

### `isBaseImageAllowed`
```solidity
function isBaseImageAllowed(
    bytes32 workloadId,
    bytes32 baseImageId
) external view returns (bool)
```

Logic:
- `AccessMode.ANY` -> always `true`
- `AccessMode.WHITELIST` -> `true` only if `_baseImageSet[workloadId][baseImageId] == true`
- `AccessMode.BLACKLIST` -> `true` only if `_baseImageSet[workloadId][baseImageId] == false`

`registerWorkload` does not query `BaseImageRegistry`. A workload may list a
deterministic base-image ID before that base image is registered. An empty
`WHITELIST` is valid and denies every base image. An empty `BLACKLIST` allows
every base image.

### View Functions

| Function | Returns | Notes |
|---|---|---|
| `getWorkload(workloadId)` | `WorkloadSpec` | Reverts if not found |
| `getWorkloadOwner(workloadId)` | `bytes32` | Owner fingerprint |
| `isWorkloadRevoked(workloadId)` | `bool` | Revocation status |

### Admin Functions (owner-only)

| Function | Purpose |
|---|---|
| `addToWhitelist(bytes32[])` | Add fingerprints to registration whitelist |
| `removeFromWhitelist(bytes32)` | Remove fingerprint from whitelist |
| `isWhitelisted(bytes32)` | Check whitelist status |
| `pause()` | Pause registration |
| `unpause()` | Unpause registration |

## Errors

| Error | Condition |
|---|---|
| `WorkloadAlreadyExists(bytes32 workloadId)` | Duplicate registration |
| `WorkloadNotFound(bytes32 workloadId)` | ID doesn't exist |
| `WorkloadNotActive(bytes32 workloadId)` | Workload is revoked |
| `InvalidSignature(bytes32 messageHash, bytes32 signerFingerprint)` | Signature verification failed |
| `Unauthorized(bytes32 actualOwner, bytes32 expectedOwner)` | Signer does not own the workload |
| `SignatureExpired(uint64 opExpiresAt, uint64 nowTs)` | `block.timestamp > opExpiresAt` |
| `InvalidPcrOrder(uint8 prevIndex, uint8 thisIndex)` | PCR specs are not strictly ascending |
| `PcrIndexOutOfRange(uint8 pcrIndex)` | PCR index is not 0 through 16 or 23 |
| `InvalidStaticMatchDataLength(uint8 pcrIndex, uint256 actualLength)` | A `STATIC` PCR rule does not contain exactly one expected value |
| `EmptyPcrComparison(uint8 pcrIndex)` | A PCR rule has an empty opaque `comparison` blob |
| `DuplicateRequirementKey(bytes32 key)` | Repeated key in requirements array |
| `InvalidTeeAttributeRequirementLength(bytes32 key, uint256 actualLength)` | A reserved Boolean does not contain one or two values, or an Intel TDX or AMD SEV-SNP packed requirement does not contain exactly one value |
| `InvalidTeeAttributeRequirementValue(bytes32 key, bytes32 actualValue)` | A reserved Boolean is not exactly `[false]` or `[false, true]`, the Intel TDX TCB mask is invalid, or an AMD SEV-SNP packed value has an invalid layout |
| `NotWhitelisted(bytes32 ownerFingerprint)` | Owner fingerprint not whitelisted |

## Events

| Event | Fields |
|---|---|
| `WorkloadRegistered` | `workloadId, owner, name, version` |
| `WorkloadDeactivated` | `workloadId, owner` |
| `WhitelistAdded` | `fingerprint` |
| `WhitelistRemoved` | `fingerprint` |

## Validation Rules

1. **PCR rules**: Each SHA-256 and SHA-384 array must be sorted ascending by `pcrIndex`. Every index must be 0 through 16 or 23. Each `STATIC` rule contains exactly one expected value. Each dynamic rule contains at least one landmark.
2. **Requirement key uniqueness**: No duplicate keys in `requirements` array (hash-table check via `_validateRequirements`)
3. **Reserved Boolean TEE requirements**: The Intel TDX debug, AMD SEV-SNP debug, and AMD SEV-SNP `MIGRATE_MA` keys accept only `[bytes32(0)]` or `[bytes32(0), bytes32(uint256(1))]`. A missing requirement means `[false]`.
4. **Intel TDX TCB requirement**: `atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed` accepts exactly one mask value. The mask must include `ok` and may contain only bits in `0x33f`. A missing requirement means `ok` only.
5. **AMD SEV-SNP packed requirements**: `tcb.minimum` and `platform-info.policy` each accept exactly one valid packed value. A missing requirement resolves to the active exact-CPUID `AmdSnpSecurityPolicyRegistry` default during verification. An explicit requirement replaces that workload-side default.
6. **Base-image set**: `baseImageIds` are stored without a `BaseImageRegistry` lookup. An empty `WHITELIST` denies every base image; an empty `BLACKLIST` allows every base image.
7. **Signature expiry**: `block.timestamp <= opExpiresAt`
8. **Registration gating**: If `registrationRestricted()` and owner not in `_whitelist`, revert `NotWhitelisted`. False = open registration.

The contract attaches reserved behavior only to the six exact known hashes.
It cannot reconstruct or validate a textual namespace from an arbitrary
`bytes32` key. The workload authoring tools reject unknown names under
`atakit.attestation.v1.tee.` before hashing them. Other names remain ordinary
attribute requirements.

A single workload may contain both Intel TDX and AMD SEV-SNP reserved
requirements. SessionRegistry evaluates only the requirements for the
verified report's `teeType`. Requirements for the other TEE platform do not
constrain that session.

## Initialization

Contract starts **paused** (`_pause()` called in `initialize`).

## Comparison with BaseImageRegistry

| Aspect | BaseImageRegistry | WorkloadRegistry |
|---|---|---|
| PCR range | Typically platform PCRs | Typically workload PCRs |
| Hierarchy | BaseImage -> Profile -> Variant | Flat (single WorkloadSpec) |
| Access control | N/A | Base image allow/blocklist |
| Attributes | Key-value pairs (provided) | Requirements (demanded) |
| TTL | N/A | Defined per workload |
| Complexity | Higher (3-level hierarchy) | Simpler (flat) |
