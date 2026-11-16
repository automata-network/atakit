# CVM Registry Contracts -- Architecture Overview

**Source**: [public registry contracts](https://github.com/automata-network/automata-tee-workload-measurement)
**Framework**: Foundry

## High-Level Architecture

Three-tier on-chain registry establishing cryptographic chains of trust from TEE hardware to verifiable CVM session identities.

```
┌─────────────────────────────────────────────────────────────┐
│                    SessionRegistry                          │
│       (orchestrator: attestation and policy pipeline)       │
│   Merges policies from both registries below, verifies     │
│   TEE + TPM evidence, creates time-bounded sessions        │
├──────────────────────────┬──────────────────────────────────┤
│   BaseImageRegistry      │      WorkloadRegistry            │
│   (OS/platform layer)    │      (application layer)         │
│   Platform PCR policies  │      Workload PCR policies       │
│   Platform profiles +    │      Base image access control   │
│   machine variants       │      Attribute requirements      │
└──────────┬───────────────┴──────────────┬───────────────────┘
           │                              │
     ┌─────┴──────┐              ┌────────┴────────┐
     │ TeeVerifier │              │SignatureVerifier│
     │ (DCAP/SNP)  │              │(RS256/ES256/K)  │
     └─────────────┘              └─────────────────┘
           │                              │
     ┌─────┴──────────────┐      ┌────────┴────────┐
     │ TpmVerifier         │      │  KeyResolver    │
     │ (external TPM       │      │ (fingerprint    │
     │  quote/certify)     │      │  directory)     │
     └─────────┬───────────┘      └─────────────────┘
               │ external
        AkCollateralVerifier ── MaaKeyRegistry
```

## Core Design Principles

1. **Fingerprint-based ownership** -- All ownership via `keccak256(abi.encode(KEY_DOMAIN, typeId, key))`, NOT EVM addresses. Enables TEE-managed keys to own registry entries directly.

2. **Signature-verified operations** -- No `msg.sender` checks. Owner operations require off-chain signatures. Anyone can submit a valid signature on behalf of the owner. Prevents address-based front-running; enables intent-based access control.

3. **Policy hierarchy** -- Platform invariants + machine-specific variant overrides are merged at session registration time. By convention, BaseImage carries platform PCR policy and Workload carries workload PCR policy.

4. **Verified TEE attribute policy** -- `TeeVerifier` extracts report-bound
   states. `TeeSecurityPolicyVerifier` first evaluates ordinary metadata, then
   requires the applicable reserved states to match the effective base-image
   declaration and workload policy. `AmdSnpSecurityPolicyRegistry` supplies the
   default TCB and `PLATFORM_INFO` policy for each exact AMD CPUID. An explicit
   value replaces that default on its policy side.

5. **Stateless verifiers** -- `TeeVerifier`, `TeeSecurityPolicyVerifier`,
   `TpmVerifier`, `AkCollateralVerifier`, and `SignatureVerifier` are immutable contracts.
   `SessionRegistry` holds their addresses as immutable constructor
   dependencies.

6. **UUPS upgradeable registries** -- `BaseImageRegistry` (gap=46), `WorkloadRegistry` (gap=47), `SessionRegistry` (gap=45), `AmdSnpSecurityPolicyRegistry` (gap=49), and `KeyResolver` (gap=49) use the UUPS proxy pattern with storage gaps.

7. **Nonce-based replay protection** -- Per-owner nonce in SessionRegistry, bound into TPM quote `extraData`.

8. **Exact ZK program routes** -- `ZkVerifierRegistry` binds one
   `(ZkProofType, VerificationBackendType, programIdentifier)` tuple to one
   enabled typed adapter. Every ZK proof carries its exact program identity.

## Directory Structure

```
src/
├── BaseImageRegistry.sol
├── WorkloadRegistry.sol
├── SessionRegistry.sol
├── AmdSnpSecurityPolicyRegistry.sol
├── TeeSecurityPolicyVerifier.sol
├── KeyResolver.sol
├── MaaKeyRegistry.sol
├── ZkVerifierRegistry.sol
├── TeeVerifier.sol
├── SignatureVerifier.sol
├── bases/
│   ├── TpmBase.sol
│   ├── TpmVerifier.sol
│   └── AkCollateralVerifier.sol
├── interfaces/
│   ├── IAkCollateralVerifier.sol
│   ├── ISignatureVerifier.sol
│   ├── ITeeVerifier.sol
│   ├── registries/
│   │   ├── IBaseImageRegistry.sol
│   │   ├── IWorkloadRegistry.sol
│   │   ├── ISessionRegistry.sol
│   │   ├── IZkVerifierRegistry.sol
│   │   ├── IKeyResolver.sol
│   │   └── IMaaKeyRegistry.sol
│   ├── zk/
│   │   └── IZkVerifierAdapters.sol
│   └── external/
│       ├── IDcapAttestation.sol   (Intel DCAP)
│       ├── ISnpAttestation.sol    (AMD SNP)
│       └── INitroEnclaveVerifier.sol (AWS Nitro, not yet integrated)
├── types/
│   ├── Common.sol                 (core data structures)
│   ├── Evidence.sol               (attestation evidence types)
│   ├── Zk.sol                     (program-bound proofs and journals)
│   └── Constants.sol              (domain separators, algo IDs)
├── lib/
│   ├── LibKey.sol                 (key fingerprinting & conversion)
│   ├── LibBytes.sol               (Bytes48/64 utilities)
│   ├── Sha2Ext.sol                (SHA-384/512)
│   ├── Asn1Decode.sol             (ASN.1 DER parsing)
│   └── BytesUtils.sol             (byte string utilities)
└── mock/
    ├── MockTpmAttestation.sol
    ├── MockSignatureVerifier.sol
    ├── MockAutomataDcapAttestation.sol
    └── MockAutomataSnpAttestation.sol
```

## Contract Dependency Graph

```
SessionRegistry
  ├── inherits: ISessionRegistry, OwnableUpgradeable, UUPSUpgradeable
  ├── immutable refs: ITeeVerifier, TpmVerifier, IAkCollateralVerifier,
  │                   ISignatureVerifier, IBaseImageRegistry, IWorkloadRegistry,
  │                   ITeeSecurityPolicyVerifier
  └── uses: LibKey, LibBytes

BaseImageRegistry
  ├── inherits: IBaseImageRegistry, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable
  ├── immutable ref: ISignatureVerifier
  └── uses: LibKey

WorkloadRegistry
  ├── inherits: IWorkloadRegistry, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable
  ├── immutable ref: ISignatureVerifier
  └── uses: LibKey

TeeVerifier
  ├── inherits: ITeeVerifier
  ├── immutable refs: IDcapAttestation, IZkVerifierRegistry
  └── uses: AmdSnpPolicy, LibBytes, Sha2Ext

SignatureVerifier
  ├── inherits: ISignatureVerifier
  └── uses: OZ RSA, OZ ECDSA, P256Verifier (external), Asn1Decode

KeyResolver
  ├── inherits: IKeyResolver, OwnableUpgradeable, UUPSUpgradeable
  └── uses: LibKey

TpmVerifier
  ├── inherits: TpmBase
  ├── immutable ref: IZkVerifierRegistry
  └── uses: LibKey, LibBytes, Sha2Ext

AkCollateralVerifier
  ├── implements: IAkCollateralVerifier; inherits: TpmBase
  ├── immutable refs: IMaaKeyRegistry, ISignatureVerifier, IZkVerifierRegistry
  └── uses: LibString, Base64 (Solady), LibKey, LibX509

TpmBase (abstract)
  └── holds: ITpmAttestation immutable
```

## Important Implementation Notes

1. **Supported PCR indexes are exact** -- Both registries accept only PCR0
   through PCR16 and PCR23. SHA-256 and SHA-384 arrays are validated
   independently. The platform-vs-workload split remains a convention.

2. **`getVariant()` enforces parent-child binding** -- `BaseImageRegistry.getVariant(baseImageId, platformProfileId, variantId)` verifies each ID exists AND that `platformProfileId` was registered under the supplied `baseImageId` and `variantId` was registered under the supplied `platformProfileId`. Implementation recomputes each child ID from the caller-provided parent and the stored child name; mismatch reverts `HierarchyMismatch(baseImageId, platformProfileId, variantId)`. SessionRegistry's `_lookupPolicy` depends on this guarantee.

3. **The verified report path selects the TEE policy** -- `PlatformProfile`
   has no TEE-type field. `TeeReport.teeType` selects a type-specific
   verification path, which returns success only for evidence with that TEE's
   signed format and valid cryptography. SessionRegistry then evaluates only
   the reserved attributes assigned to `teeResult.teeType`. A base image and a
   workload may contain policy for both Intel TDX and AMD SEV-SNP.

4. **Only exact hashes are reserved on chain** -- The contracts recognize six
   exact attribute hashes. They cannot recover a textual namespace from any
   other hash. Text-based tools reject unknown names under
   `atakit.attestation.v1.tee.` before publication.

5. **Rotation has no new provider evidence** -- `rotateKey` has no new TEE
   report. It evaluates the current registered PCR policy without a generated
   provider rule and inherits the launch state accepted by the predecessor's
   complete registration or renewal.

## PCR Evaluation Modes

| Mode | Semantics |
|---|---|
| `STATIC` | Exact match: `actual == expected` |
| `DYNAMIC_SUBSET` | Every landmark in `comparison` must appear in the PCR events; order does not matter and extra events are permitted |
| `DYNAMIC_SUBSEQUENCE` | The landmarks in `comparison` must appear as an ordered subsequence of the PCR events |
| `DYNAMIC_INDEXED_EVENT_SETS` | The event count must match exactly; every listed event index must match one allowed digest; unlisted indexes are skipped |
| `EXTEND_FROM_ZERO` | The authenticated PCR must equal one bank-width TPM extend from the all-zero value |

Each PCR rule contains only `pcrIndex` and one opaque `comparison` byte blob.
`TpmVerifier` decodes `comparison`; the registries and `SessionRegistry` pass it
unchanged.

## ID Derivation Scheme

All registry IDs are deterministic keccak256 hashes with domain separation.
NOTE: All use `abi.encode` (not `encodePacked`).

| Entity | Formula |
|---|---|
| Key fingerprint | `keccak256(abi.encode(KEY_DOMAIN, typeId, key))` |
| Base image ID | `keccak256(abi.encode(BASEIMAGE_DOMAIN, ownerFingerprint, name, version))` |
| Platform profile ID | `keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profileName))` |
| Variant ID | `keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variantName))` |
| Workload ID | `keccak256(abi.encode(WORKLOAD_DOMAIN, ownerFingerprint, name, version))` |
| Session ID | `keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))` |

## Message Signing Convention

All owner-signed messages use **sha256** (NOT keccak256) and include **chainid + address(this)** for replay protection:
```
message = sha256(abi.encode(MSG_SEPARATOR, block.chainid, address(this), opExpiresAt, ...params))
```

## Deployment

Read the target chain configuration and verify each proxy implementation and
immutable dependency against that chain. Contract bindings must match the
selected network.

## TEE Platform Support

| TEE | Cloud | AK Binding | PCR15 Binding |
|---|---|---|---|
| Intel TDX | Azure | MAA-signed JWT (RS256); `tdx_report_data` claim commits to `sha256(hclVarData)`; JWT signature verified against per-region MAA RSA-2048 key from MaaKeyRegistry | N/A |
| AMD SEV-SNP | Azure | MAA-signed JWT (RS256); `x-ms-sevsnpvm-reportdata` claim commits to `sha256(hclVarData)`; same per-region MAA RSA-2048 key as the TDX path | N/A |
| Intel TDX | GCP | Certificate chain via `ITpmAttestation.verifyCertChain` | `sha256(bytes32(0) \|\| (bytes16(0) \|\| UUID))`; UUID also bound in RTMR3 via `sha384(bytes48(0) \|\| (bytes32(0) \|\| UUID))` |
| AMD SEV-SNP | GCP | Certificate chain | `sha256(bytes32(0) \|\| report_id)` |
| AMD SEV-SNP | AWS | `aws_nitrotpm.v1` verifies the NitroTPM Attestation Document, P-256 Attestation Key, qualifying data, trusted root, exact report hash, and `REPORT_DATA` binding to the complete `PcrCommitment` | Generated SHA-384 PCR15 `EXTEND_FROM_ZERO` binds the Quote to `REPORT_ID`; dual-bank policy adds the same SHA-256 rule; NitroTPM, TPM Quote, and evidence `PcrCommitment` values must be equal |

For Azure TDX and Azure SEV-SNP, `_verifyAzureAkCollateral` returns the
MAA-signed `sha256(hclVarData)` as `bindingHash`. `_verifyProviderEvidence` then
requires the independently verified raw TEE report's `REPORT_DATA` to equal
`bindingHash || bytes32(0)`. Azure does not use PCR15 for this binding.

## Signature Algorithm Support

| ID | Name | Key Format | Signature Format |
|---|---|---|---|
| 0 | NULL | -- | -- |
| 1 | RS256 | DER PKCS#1 RSA public key | Raw RSA signature |
| 2 | ES256 | 65-byte SEC1 uncompressed P-256 | DER-encoded (r, s) |
| 3 | ES256K | 65-byte SEC1 uncompressed secp256k1 | 65-byte Ethereum (r, s, v) |
