# CVM Registry Contracts -- Architecture Overview

**Source**: `~/work/automata-tee-workload-measurement/`
**Total**: ~5,487 lines of Solidity across 30 source files
**Framework**: Foundry

## High-Level Architecture

Three-tier on-chain registry establishing cryptographic chains of trust from TEE hardware to verifiable CVM session identities.

```
┌─────────────────────────────────────────────────────────────┐
│                    SessionRegistry                          │
│         (orchestrator: 9-step attestation pipeline)         │
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
     │ AkCollateralVerifier│      │ (fingerprint    │
     │ (TPM quote/certify) │      │  directory)     │
     └─────────────────────┘      └─────────────────┘
```

## Core Design Principles

1. **Fingerprint-based ownership** -- All ownership via `keccak256(abi.encode(KEY_DOMAIN, typeId, key))`, NOT EVM addresses. Enables TEE-managed keys to own registry entries directly.

2. **Signature-verified operations** -- No `msg.sender` checks. Owner operations require off-chain signatures. Anyone can submit a valid signature on behalf of the owner. Prevents address-based front-running; enables intent-based access control.

3. **Policy hierarchy** -- Platform invariants + machine-specific variant overrides are merged at session registration time. By convention, BaseImage carries platform PCR policy and Workload carries workload PCR policy.

4. **Stateless verifiers** -- `TeeVerifier` and `SignatureVerifier` are immutable, stateless, shared across registries. No storage, no upgrades needed.

5. **UUPS upgradeable registries** -- `BaseImageRegistry` (gap=46), `WorkloadRegistry` (gap=47), `SessionRegistry` (gap=47), `KeyResolver` (gap=49) all use UUPS proxy pattern with storage gaps.

6. **Nonce-based replay protection** -- Per-owner nonce in SessionRegistry, bound into TPM quote `extraData`.

7. **Polymorphic verification backends** -- Solidity (on-chain), ZK RiscZero, ZK Succinct. TEE verification can be offloaded to ZK proofs.

## Directory Structure

```
src/
├── BaseImageRegistry.sol          (524 lines)
├── WorkloadRegistry.sol           (304 lines)
├── SessionRegistry.sol            (1,312 lines)
├── KeyResolver.sol                (101 lines)
├── TeeVerifier.sol                (298 lines)
├── SignatureVerifier.sol          (172 lines)
├── bases/
│   ├── TpmBase.sol                (29 lines)
│   ├── TpmVerifier.sol            (196 lines)
│   └── AkCollateralVerifier.sol   (190 lines)
├── interfaces/
│   ├── ISignatureVerifier.sol
│   ├── ITeeVerifier.sol
│   ├── registries/
│   │   ├── IBaseImageRegistry.sol
│   │   ├── IWorkloadRegistry.sol
│   │   ├── ISessionRegistry.sol
│   │   └── IKeyResolver.sol
│   └── external/
│       ├── IDcapAttestation.sol   (Intel DCAP)
│       ├── ISnpAttestation.sol    (AMD SNP)
│       └── INitroEnclaveVerifier.sol (AWS Nitro, not yet integrated)
├── types/
│   ├── Common.sol                 (core data structures)
│   ├── Evidence.sol               (attestation evidence types)
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
  ├── inherits: ISessionRegistry, TpmVerifier, AkCollateralVerifier, OwnableUpgradeable, UUPSUpgradeable
  ├── immutable refs: ITeeVerifier, ISignatureVerifier, IBaseImageRegistry, IWorkloadRegistry
  └── uses: LibKey, LibBytes, Sha2Ext

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
  ├── immutable refs: IDcapAttestation, ISnpAttestation
  └── uses: (inline assembly for byte manipulation -- no library imports)

SignatureVerifier
  ├── inherits: ISignatureVerifier
  └── uses: OZ RSA, OZ ECDSA, P256Verifier (external), Asn1Decode

KeyResolver
  ├── inherits: IKeyResolver, OwnableUpgradeable, UUPSUpgradeable
  └── uses: LibKey

TpmVerifier (abstract)
  ├── inherits: TpmBase
  └── uses: LibKey

AkCollateralVerifier (abstract)
  ├── inherits: TpmBase
  └── uses: LibString, Base64 (Solady), LibKey, LibX509

TpmBase (abstract)
  └── holds: ITpmAttestation immutable
```

## Important Implementation Notes

1. **PCR index split is not hard-enforced** -- `BaseImageRegistry` and `WorkloadRegistry` only validate sorted `pcrIndex < 24`. The usual platform-vs-workload split is a convention, not a contract-level guardrail.

2. **`getVariant()` does existence checks only** -- `BaseImageRegistry.getVariant(baseImageId, platformProfileId, variantId)` verifies each ID exists, but does not verify that `platformProfileId` belongs to `baseImageId` or that `variantId` belongs to `platformProfileId`.

## PCR Evaluation Modes

| Mode | Semantics |
|---|---|
| `STATIC` | Exact match: `actual == expected` |
| `DYNAMIC_SUBSET` | Each PCR event hash must appear in `matchData` (order irrelevant) |
| `DYNAMIC_SUBSEQUENCE` | `matchData` values must appear as subsequence in PCR events (order matters) |

## ID Derivation Scheme

All registry IDs are deterministic keccak256 hashes with domain separation.
NOTE: All use `abi.encode` (not `encodePacked`).

| Entity | Formula |
|---|---|
| Key fingerprint | `keccak256(abi.encode(KEY_DOMAIN, typeId, key))` |
| Base image ID | `keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))` -- NO ownerFingerprint |
| Platform profile ID | `keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profileName))` |
| Variant ID | `keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variantName))` |
| Workload ID | `keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))` -- NO ownerFingerprint |
| Session ID | `keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))` |

## Message Signing Convention

All owner-signed messages use **sha256** (NOT keccak256) and include **chainid + address(this)** for replay protection:
```
message = sha256(abi.encode(MSG_SEPARATOR, block.chainid, address(this), expireAt, ...params))
```

## Deployment (Hoodi Testnet)

| Contract | Address |
|---|---|
| SessionRegistry | `0xD1860020870ffEd23a644d0CD4CA9E7b3Ff53D6c` |
| BaseImageRegistry | `0x15A8F7A012b2dBad3fAD6020a0dF1F81E86F6171` |
| WorkloadRegistry | `0xFA8Eb822594d7aA7221aBE3Cd7f3F17c3F16bA9E` |
| TeeVerifier | `0x80c17Fb23a7f747174DCD29Ec94B8D5a7227F266` |
| SignatureVerifier | `0x996eB4a6E1FEbF1788B027FA990643B2328A5E72` |
| KeyResolver | `0x74Ee5a4c6e9207cFDa2Bb28E79bf97CcA42F18E4` |

## TEE Platform Support

| TEE | Cloud | AK Binding | PCR15 Binding |
|---|---|---|---|
| Intel TDX | Azure | `reportData[0:32] == sha256(akJsonBytes)` | N/A |
| Intel TDX | GCP | Certificate chain via `ITpmAttestation.verifyCertChain` | `sha256(bytes32(0) \|\| sha256(UUID))` from RTMR3 |
| AMD SEV-SNP | GCP | Certificate chain | `sha256(bytes32(0) \|\| report_id)` |

NOTE: Azure binding path in `_verifyTeeAkBinding` uses `extractDcapReportData` (TDX-specific). Azure SNP binding is not currently implemented -- the code dispatches on collateral type (`AzureAkPubJson`), not TEE type, and only handles DCAP report data extraction.

## Signature Algorithm Support

| ID | Name | Key Format | Signature Format |
|---|---|---|---|
| 0 | NULL | -- | -- |
| 1 | RS256 | DER PKCS#1 RSA public key | Raw RSA signature |
| 2 | ES256 | 65-byte SEC1 uncompressed P-256 | DER-encoded (r, s) |
| 3 | ES256K | 65-byte SEC1 uncompressed secp256k1 | 65-byte Ethereum (r, s, v) |
