# CVM Registry Interfaces -- Complete Reference

**Path**: `src/interfaces/` with sub-directories `registries/` and `external/`

## Directory Layout

```
src/interfaces/
├── IAkCollateralVerifier.sol
├── ISignatureVerifier.sol
├── ITeeSecurityPolicyVerifier.sol
├── ITeeVerifier.sol
├── registries/
│   ├── IAmdSnpSecurityPolicyRegistry.sol
│   ├── IBaseImageRegistry.sol
│   ├── IWorkloadRegistry.sol
│   ├── ISessionRegistry.sol
│   ├── IZkVerifierRegistry.sol
│   ├── IKeyResolver.sol
│   └── IMaaKeyRegistry.sol
├── zk/
│   └── IZkVerifierAdapters.sol
└── external/
    ├── IDcapAttestation.sol
    ├── ISnpAttestation.sol
    └── INitroEnclaveVerifier.sol
```

Note: Registry interfaces are under `interfaces/registries/`, NOT directly under `interfaces/`.

---

## IBaseImageRegistry

**File**: `src/interfaces/registries/IBaseImageRegistry.sol`

### Storage Structs (defined at file scope, outside interface)

```solidity
struct BaseImageSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    BaseImageSpec spec;
    bytes32[] platformProfileIds;
}

struct PlatformProfileStorage {
    bool exists;
    PlatformProfile platformProfile;
    bytes32[] variantIds;
}

struct MeasurementVariantStorage {
    bool exists;
    MeasurementVariant measurementVariant;
}
```

### Events

```solidity
event BaseImageRegistered(bytes32 indexed baseImageId, bytes32 indexed owner, string name, string version);
event BaseImageDeactivated(bytes32 indexed baseImageId, bytes32 indexed owner);
event PlatformProfileRegistered(bytes32 indexed baseImageId, bytes32 indexed platformProfileId, string name);
event MeasurementVariantRegistered(bytes32 indexed platformProfileId, bytes32 indexed variantId, string name);
event BaseImageUpdated(bytes32 indexed baseImageId, bytes32 indexed owner);
```

### Function Signatures

```solidity
function registerBaseImage(
    BaseImageSpec calldata spec,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 opExpiresAt,                                      // NOTE: uint64, not uint256
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 baseImageId);

function deactivateBaseImage(
    bytes32 baseImageId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function addPlatformVariants(
    bytes32 baseImageId,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function getBaseImage(bytes32 baseImageId) external view returns (BaseImageSpec memory spec);
function getPlatformProfileIds(bytes32 baseImageId) external view returns (bytes32[] memory);
function getPlatformProfile(bytes32 platformProfileId) external view returns (PlatformProfile memory);
function getMeasurementVariant(bytes32 variantId) external view returns (MeasurementVariant memory);
function getMeasurementVariantIds(bytes32 platformProfileId) external view returns (bytes32[] memory);
/// @dev Enforces parent-child binding: reverts HierarchyMismatch unless the
///      supplied platformProfileId was registered under `baseImageId` and the
///      supplied variantId was registered under `platformProfileId`. Implementation
///      recomputes each child ID from the caller-provided parent + stored child
///      name. See base-image-registry.md "Implementation Nuance".
function getVariant(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
    external view returns (BaseImageSpec memory, PlatformProfile memory, MeasurementVariant memory);
function getBaseImageOwner(bytes32 baseImageId) external view returns (bytes32);
function isBaseImageRevoked(bytes32 baseImageId) external view returns (bool);
function hasVariant(bytes32 variantId) external view returns (bool);
```

---

## IWorkloadRegistry

**File**: `src/interfaces/registries/IWorkloadRegistry.sol`

### Storage Struct (file scope)

```solidity
struct WorkloadSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    WorkloadSpec workloadSpec;
}
```

### Events

```solidity
event WorkloadRegistered(bytes32 indexed workloadId, bytes32 indexed owner, string name, string version);
event WorkloadDeactivated(bytes32 indexed workloadId, bytes32 indexed owner);
```

### Function Signatures

```solidity
function registerWorkload(
    WorkloadSpec calldata spec,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 workloadId);

function deactivateWorkload(
    bytes32 workloadId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function getWorkload(bytes32 workloadId) external view returns (WorkloadSpec memory spec);
function getWorkloadOwner(bytes32 workloadId) external view returns (bytes32);
function isWorkloadRevoked(bytes32 workloadId) external view returns (bool);
function isBaseImageAllowed(bytes32 workloadId, bytes32 baseImageId) external view returns (bool);
```

---

## ISessionRegistry

**File**: `src/interfaces/registries/ISessionRegistry.sol`

### Storage Struct (file scope)

```solidity
struct CVMSessionStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    CVMSession session;
}
```

### Events

```solidity
event SessionRegistered(
    bytes32 indexed sessionId,
    bytes32 indexed owner,
    bytes32 indexed workloadId,
    bytes32 baseImageId,
    bytes32 akPubKeyFingerprint,
    bytes32 tpmSigningKeyFingerprint,
    bytes32 sessionKeyFingerprint
);

event AttestationKeysRevealed(
    bytes32 indexed sessionId,
    PublicIdentity akPub,
    PublicIdentity tpmSigningKey,
    PublicIdentity sessionKey
);

event SessionRevoked(bytes32 indexed sessionId, bytes32 indexed revoker);

event SessionKeyRotated(
    bytes32 indexed oldSessionId,
    bytes32 indexed newSessionId,
    bytes32 indexed owner,
    bytes32 newTpmSigningKeyFingerprint,
    bytes32 newSessionKeyFingerprint
);

event SessionRenewed(
    bytes32 indexed oldSessionId,
    bytes32 indexed newSessionId,
    bytes32 indexed owner
);

event SessionRecovered(
    bytes32 indexed oldSessionId,
    bytes32 indexed newSessionId,
    bytes32 indexed owner
);
```

### Function Signatures

```solidity
function teeSecurityPolicyVerifier()
    external view returns (ITeeSecurityPolicyVerifier);

function registerSession(
    AttestationEvidence calldata evidence,
    bytes32 workloadId,
    bytes32 baseImageId,
    bytes32 platformProfileId,
    bytes32 variantId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 sessionId);

function getSession(bytes32 sessionId) external view returns (CVMSession memory session);
function getSessionId(bytes32 sessionFingerprint) external view returns (bytes32 sessionId);
function getSessionOwner(bytes32 sessionId) external view returns (bytes32 ownerFingerprint);

function revokeSession(
    bytes32 sessionId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function isSessionActive(bytes32 sessionId) external view returns (bool);
function isSessionExpired(bytes32 sessionId) external view returns (bool);
function getNonce(bytes32 ownerFingerprint) external view returns (uint256 nonce);

function getPcrPolicy(
    bytes32 workloadId,
    bytes32 baseImageId,
    bytes32 platformProfileId,
    bytes32 measurementVariantId
) external view returns (ResolvedPcrPolicy memory policy);

function rotateKey(
    bytes32 oldSessionId,
    bytes32 teeReportBytesHash,
    SessionKeyRotationEvidence calldata rotationEvidence,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId);

function renewSession(
    bytes32 oldSessionId,
    AttestationEvidence calldata newEvidence,
    bytes32 workloadId,
    bytes32 baseImageId,
    bytes32 platformProfileId,
    bytes32 measurementVariantId,
    SessionRenewalAuthorization calldata renewalAuthorization,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId);

function recoverSession(
    bytes32 oldSessionId,
    AttestationEvidence calldata newEvidence,
    bytes32 workloadId,
    bytes32 baseImageId,
    bytes32 platformProfileId,
    bytes32 measurementVariantId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId);

function verifySessionSignature(
    bytes32 sessionId,
    PublicIdentity calldata sessionKey,
    bytes32 message,                      // NOTE: bytes32, not bytes calldata
    bytes calldata signature
) external view returns (bool valid);
```

---

## ITeeSecurityPolicyVerifier

**File**: `src/interfaces/ITeeSecurityPolicyVerifier.sol`

```solidity
struct VerifiedTeePolicyInputs {
    TEEType teeType;
    uint256 enabledTeeAttributes;
    uint256 intelTdxTcbStatusBit;
    bytes32 amdSevSnpTcbValues;
    uint64 amdSevSnpPlatformInfo;
    uint24 amdSevSnpCpuid;
    uint32 amdSevSnpReportVersion;
    uint64 amdSevSnpLaunchMitigationVector;
    uint64 amdSevSnpCurrentMitigationVector;
}

function amdSnpSecurityPolicyRegistry()
    external view returns (IAmdSnpSecurityPolicyRegistry);

function verifyTeePolicy(
    VerifiedTeePolicyInputs calldata inputs,
    Attribute[] calldata profileAttributes,
    Attribute[] calldata variantAttributes,
    AttributeRequirement[] calldata requirements
) external view;
```

---

## IAmdSnpSecurityPolicyRegistry

**File**:
`src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol`

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

struct AmdSnpSecurityPolicyUpdate {
    uint24 cpuid;
    uint64 expectedRevision;
    uint64 revision;
    bool active;
    bytes32 minimumTcb;
    bytes32 platformInfoPolicy;
    uint64 requiredLaunchMitigationVector;
    uint64 requiredCurrentMitigationVector;
}

function updatePolicies(
    AmdSnpSecurityPolicyUpdate[] calldata updates,
    bytes32 sourceDigest
) external;

function getPolicy(uint24 cpuid)
    external view returns (AmdSnpSecurityPolicy memory policy);

function getActivePolicy(uint24 cpuid)
    external view returns (AmdSnpSecurityPolicy memory policy);
```

---

## IAkCollateralVerifier

**File**: `src/interfaces/IAkCollateralVerifier.sol`

```solidity
struct AkCollateralVerificationResult {
    bytes32 akPubFingerprint;
    TEEType teeType;
    bytes32 bindingHash;
    bytes32 amdSevSnpReportHash;
    bytes32 awsNitroRootCertHash;
    bytes32 qualifyingData;
    uint64 documentTimestampSeconds;
    PcrCommitment pcrCommitment;
}

function validateAkPub(AkPubCollateralType collateralType, PublicIdentity calldata akPub)
    external pure returns (bytes32 fingerprint);

function verifyAkCollateral(AkPubCollateral calldata collateral)
    external returns (AkCollateralVerificationResult memory result);
```

For Azure, `teeType` is authenticated by the MAA JWT's
`x-ms-attestation-type` claim and `bindingHash` is the MAA-verified
`sha256(hclVarData)`. For GCP, `teeType` is ignored and `bindingHash` is zero
because `SessionRegistry` applies the TEE-to-vTPM PCR15 binding.
For AWS, `amdSevSnpReportHash`, `awsNitroRootCertHash`, `qualifyingData`,
`documentTimestampSeconds`, and `pcrCommitment` come from the verified
`aws_nitrotpm.v1` journal. `SessionRegistry` requires the returned
`PcrCommitment` to equal the value returned by TPM Quote verification.

---

## IZkVerifierRegistry and typed adapters

`IZkVerifierRegistry` maps one exact
`(ZkProofType, VerificationBackendType, programIdentifier)` tuple to an enabled
verifier adapter. The owner can set or disable a route. A proof route never
falls back to another program identifier.

`IZkVerifierAdapters.sol` defines four typed adapters:

- `IIntelTdxDcapZkVerifierAdapter` returns `IntelTdxDcapJournalV1`;
- `IAmdSevSnpZkVerifierAdapter` returns `AmdSevSnpVerifierJournal`;
- `ITpmQuoteZkVerifierAdapter` returns `TpmQuoteJournalV1`; and
- `IAwsNitroTpmZkVerifierAdapter` returns `AwsNitroTpmJournalV1`.

Each adapter accepts `ProgramBoundZkProof` and checks its exact program
identifier before invoking the backend verifier.

---

## IKeyResolver

**File**: `src/interfaces/registries/IKeyResolver.sol`

### Events

```solidity
event IdentityRegistered(bytes32 indexed fingerprint, uint8 typeId);
```

### Function Signatures

```solidity
function registerIdentity(PublicIdentity calldata identity) external returns (bytes32 fingerprint);
function getIdentity(bytes32 fingerprint) external view returns (PublicIdentity memory identity);
function hasIdentity(bytes32 fingerprint) external view returns (bool);
function computeFingerprint(PublicIdentity calldata identity) external pure returns (bytes32 fingerprint);
```

---

## IMaaKeyRegistry

**File**: `src/interfaces/registries/IMaaKeyRegistry.sol`

Admin-managed directory of Microsoft Azure Attestation signing keys consumed by `AkCollateralVerifier` when verifying `AzureMaaJwt` collateral (the registry reference.3.1 + §10.3). Distinct from `IKeyResolver` because the stored value shape (PKCS#1 RSA pubkey + issuer + validity + revocation) and lifecycle (rotation, expiry, admin revocation) differ from a `PublicIdentity` directory.

### Storage Struct (file scope)

```solidity
struct MaaSigningKey {
    bytes pkcs1Pubkey;   // DER PKCS#1 RSAPublicKey, ~270 B for RSA-2048
    bytes32 issuerHash;  // keccak256(bytes("https://<region>.attest.azure.net"))
    uint64 notAfter;     // Unix seconds; from leaf cert NotAfter
    bool revoked;        // overrides notAfter; set by revokeMaaSigningKey
}
```

Lookup key is `kidHash = keccak256(bytes(jwt.header.kid))`. An unregistered kid surfaces as the empty struct (`pkcs1Pubkey.length == 0 && !revoked`); `_verifyAzureAkCollateral` rejects with `MaaKidNotRegistered` on both the unregistered and revoked cases, and additionally enforces `block.timestamp <= notAfter`.

### Events

```solidity
event MaaSigningKeyUpserted(bytes32 indexed kidHash, bytes32 issuerHash, uint64 notAfter);
event MaaSigningKeyRevoked(bytes32 indexed kidHash);
```

### Function Signatures

```solidity
function upsertMaaSigningKey(
    bytes32 kidHash,
    bytes calldata pkcs1Pubkey,
    bytes32 issuerHash,
    uint64 notAfter
) external;

function revokeMaaSigningKey(bytes32 kidHash) external;

function getMaaSigningKey(bytes32 kidHash) external view returns (MaaSigningKey memory);
function hasMaaSigningKey(bytes32 kidHash) external view returns (bool);
```

Admin authentication is the contract's EVM owner via `OwnableUpgradeable.onlyOwner` — no off-chain-signed envelope, no `opExpiresAt` (EVM tx nonce supplies replay protection). The MaaKeyRegistry trust anchor is global state shared across every Azure CVM that registers against the SessionRegistry deployment, so the owner key is the root of trust for the entire Azure path; treat it accordingly (multisig / time-locked rotation).

Upsert validation: `pkcs1Pubkey.length > 0`, `issuerHash != bytes32(0)`,
`notAfter >= block.timestamp` (boundary inclusive, matching the verifier's
`block.timestamp <= notAfter` acceptance). Upserting an existing active kid
replaces the whole record. Upserting a previously revoked kid reverts
`KidRevoked(kidHash)`. Revoke validation: the kid must have been registered
(reverts `KidNotRegistered` for an empty record); the call flips the `revoked`
flag in-place without touching the other fields. Revocation is permanent for
each `kidHash`; there is no restore or un-revoke operation.

`hasMaaSigningKey` deliberately omits the `notAfter` check — the registry has no opinion on the caller's clock; `block.timestamp` enforcement lives in `_verifyAzureAkCollateral`. Use `hasMaaSigningKey` for "is this kid configured?" checks (e.g. operator-side smoke tests) and `getMaaSigningKey().notAfter` when you need to make a freshness decision.

---

## ISignatureVerifier

**File**: `src/interfaces/ISignatureVerifier.sol`

```solidity
interface ISignatureVerifier {
    function verify(
        PublicIdentity calldata identity,
        bytes32 message,
        bytes calldata signature
    ) external view returns (bool valid);
}
```

NatDoc: "Foundation of the owner-auth model - allows TEE-managed keys (RSA, ECDSA-P256, etc.) to own registry entries directly without relying on msg.sender addresses"

---

## ITeeVerifier

**File**: `src/interfaces/ITeeVerifier.sol`

```solidity
interface ITeeVerifier {
    function verifyTeeReport(TeeReport memory teeReport) external returns (TeeVerificationResult memory result);
    function extractDcapReportData(bytes memory quoteBody) external pure returns (bytes memory reportData);
    function extractSnpReportData(bytes memory rawReport) external pure returns (bytes memory reportData);
}
```

---

## IAmdSnpSecurityPolicyRegistry

**File**: `src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol`

```solidity
interface IAmdSnpSecurityPolicyRegistry {
    function updatePolicies(
        AmdSnpSecurityPolicyUpdate[] calldata updates,
        bytes32 sourceDigest
    ) external;

    function getPolicy(uint24 cpuid)
        external view returns (AmdSnpSecurityPolicy memory policy);

    function getActivePolicy(uint24 cpuid)
        external view returns (AmdSnpSecurityPolicy memory policy);
}
```

The data types, revision rules, and packed values are documented in
[AmdSnpSecurityPolicyRegistry](amd-snp-security-policy-registry.md).

---

## IDcapAttestation (External)

**File**: `src/interfaces/external/IDcapAttestation.sol`

```solidity
enum ZkCoProcessorType { None, RiscZero, Succinct }

interface IDcapAttestation {
    function getBp() external view returns (uint16);

    function verifyAndAttestOnChain(bytes calldata input)
        external payable returns (bool success, bytes memory output);

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external payable returns (bool success, bytes memory verifiedOutput);
}
```

Note: `verifyAndAttestOnChain` and `verifyAndAttestWithZKProof` are both `payable` (fee-based verification). `getBp()` returns the base price in basis points.

---

## ISnpAttestation (External)

**File**: `src/interfaces/external/ISnpAttestation.sol`

### Types (file scope)

```solidity
enum VerificationResult { Success, RootCertNotTrusted, IntermediateCertsNotTrusted, InvalidTimestamp }

struct VerifierJournal {
    VerificationResult result;
    uint64 timestamp;
    uint8 processorModel;
    bytes rawReport;
    bytes32[] certs;
    uint160[] certSerials;
    uint8 trustedCertsPrefixLen;
}
```

### Interface

```solidity
interface ISnpAttestation {
    enum ZkCoProcessorType { None, RiscZero, Succinct }

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal memory verifiedOutput);
}
```

Note: SNP only supports ZK proof verification (no on-chain equivalent of `verifyAndAttestOnChain`).

---

## INitroEnclaveVerifier (External)

**File**: `src/interfaces/external/INitroEnclaveVerifier.sol`

### Types (file scope)

```solidity
struct VerifierInput {
    uint8 trustedCertsPrefixLen;
    bytes attestationReport;            // COSE_Sign1 format
}

struct VerifierJournal {
    VerificationResult result;
    uint8 trustedCertsPrefixLen;
    uint64 timestamp;                   // Unix milliseconds
    bytes32[] certs;
    bytes userData;
    bytes nonce;
    bytes publicKey;
    Pcr[] pcrs;
    string moduleId;
}

struct BatchVerifierJournal {
    bytes32 verifierVk;
    VerifierJournal[] outputs;
}

struct Bytes48 {
    bytes32 first;
    bytes16 second;
}

struct Pcr {
    uint64 index;
    Bytes48 value;                       // SHA-384 measurement
}

enum VerificationResult { Success, RootCertNotTrusted, IntermediateCertsNotTrusted, InvalidTimestamp }
```

### Interface

```solidity
interface INitroEnclaveVerifier {
    enum ZkCoProcessorType { Unknown, RiscZero, Succinct }

    function verify(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal memory);

    function batchVerify(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal[] memory);
}
```

Note: Nitro Enclave verifier is **not yet integrated** into `TeeVerifier` -- the interface exists but `TeeVerifier` only dispatches to DCAP (TDX) and SNP. Also supports batch verification via `batchVerify`. Uses `Unknown` instead of `None` for the no-ZK case (unlike DCAP/SNP).

---

## Key Observations Across Interfaces

1. **All `opExpiresAt` parameters are `uint64`** -- not `uint256`. Consistent across all registry interfaces.

2. **Storage structs are defined at file scope** (outside the interface block) in IBaseImageRegistry, IWorkloadRegistry, and ISessionRegistry.

3. **`verifySessionSignature` takes `bytes32 message`** -- the message is passed directly to `signatureVerifier.verify()` without any domain wrapping. Caller is responsible for pre-hashing.

4. **DCAP is `payable`** -- verification calls to Intel DCAP can charge fees (basis points via `getBp()`).

5. **SNP is ZK-only** -- no on-chain verification method, only `verifyAndAttestWithZKProof`.

6. **AWS NitroTPM is separate from `TeeVerifier`** -- `amd_sev_snp.v1`
   verifies the TEE report. `aws_nitrotpm.v1` verifies the NitroTPM
   Attestation Document through `IAkCollateralVerifier`.

7. **IKeyResolver has `IdentityRegistered` event** -- emits `(fingerprint, typeId)` on new registrations.

8. **Whitelist events/functions are NOT in interfaces** -- `addToWhitelist`, `removeFromWhitelist`, `isWhitelisted`, `WhitelistAdded`, `WhitelistRemoved` are implementation-only (in BaseImageRegistry and WorkloadRegistry contracts, not their interfaces). Same for `pause()`/`unpause()`.
