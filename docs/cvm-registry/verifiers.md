# Verifier Contracts -- Detailed Analysis

## TeeVerifier

**File**: `src/TeeVerifier.sol`
**Interface**: `src/interfaces/ITeeVerifier.sol`
**Role**: Stateless dispatcher for TEE attestation verification (Intel TDX via DCAP, AMD SEV-SNP)

### Immutables

| Variable | Type | Purpose |
|---|---|---|
| `dcapAttestation` | `IDcapAttestation` | Intel DCAP verification backend |
| `zkVerifierRegistry` | `IZkVerifierRegistry` | Exact program-identifier and adapter routes |

### Constants

```solidity
// Quote body type identifiers
uint16 constant QUOTE_BODY_TYPE_TD10 = 2;
uint16 constant QUOTE_BODY_TYPE_TD15 = 3;

// Quote body sizes
uint256 constant TD10_QUOTE_BODY_SIZE = 584;
uint256 constant TD15_QUOTE_BODY_SIZE = 648;

// DCAP output parsing
uint256 constant DCAP_QUOTE_BODY_OFFSET = 11;  // header: 2+2+1+6 bytes
uint256 constant DCAP_MIN_OUTPUT_LEN = 584;     // TD10_QUOTE_BODY_SIZE (520 + 64)

// Report data extraction
uint256 constant REPORT_DATA_SIZE = 64;
uint256 constant DCAP_REPORT_DATA_START = 520;  // offset within quote body

// SNP
uint256 constant SNP_REPORT_DATA_OFFSET = 0x50;  // 80 decimal
uint256 constant SNP_REPORT_SIZE = 1184;
```

### Version

```solidity
string public constant TEE_VERIFIER_VERSION = "2.0.0";
```

### Functions

#### `verifyTeeReport`
```solidity
function verifyTeeReport(TeeReport memory teeReport) external returns (TeeVerificationResult memory)
```

**TDX (Intel) flow**:
1. Dispatch based on `VerificationBackendType`:
   - Solidity: require `teeReport.data` to end exactly after its declared DCAP
     signature data, then call
     `dcapAttestation.verifyAndAttestOnChain(teeReport.data)`
   - ZK RiscZero/Succinct: decode `IntelTdxDcapZkEvidence`, resolve the exact
     adapter through `ZkVerifierRegistry`, and verify the program-bound proof.
2. Read the raw DCAP TCB status. Accept configurable values 0 through 5, 8, and
   9; reject 6, 7, and unknown values.
3. Convert the status to `intelTdxTcbStatusBit = 1 << rawStatus`.
4. For Solidity, extract the quote body from verified DCAP output. For ZK,
   require the supplied quote body to have the verified TD10 or TD15 length and
   require `keccak256(quoteBody) == journal.quoteBodyHash`.
5. Require valid reserved attribute bits and `SEPT_VE_DISABLE`.
6. Reject a nonzero Intel TDX 1.5 `MR_SERVICETD`.
7. Extract `DEBUG` into `enabledTeeAttributes`; debug is permitted here and
   decided by SessionRegistry policy
8. Return the quote body as `reportData` with `valid=true`. Return
   `keccak256(teeReport.data)` for Solidity and `journal.fullQuoteHash` for ZK
   as `teeReportBytesHash`. Both values are the hash of the same exact Intel
   TDX DCAP quote. A verifier rejects every trailing byte, including zero, and
   never truncates verifier input.

**SNP (AMD) flow**:
1. ZK only. Decode `AmdSevSnpZkEvidence`, resolve the exact adapter through
   `ZkVerifierRegistry`, and verify its `ProgramBoundZkProof`.
2. Validate `journal.result == VerificationResult.Success`
3. Require the proof-bound raw report to be exactly 1,184 bytes before reading fields
4. Require report version 3 through 5, valid ECDSA P-384 signature selection,
   valid key settings, valid policy-reserved bits, and `VMPL=0`
5. Accept only an all-zero or all-`0xff` `REPORT_ID_MA` as no active
   migration-agent association. Reject every other value.
6. Validate raw TCB reserved fields and require
   `reported_tcb <= committed_tcb <= current_tcb` component by component
7. Require a supported exact CPUID and supported `PLATFORM_INFO` bits
8. Validate every version-specific reserved field
9. Extract `POLICY.DEBUG` and `POLICY.MIGRATE_MA` into `enabledTeeAttributes`
10. For version 5, extract `LAUNCH_MIT_VECTOR` at `0x1f8` and
    `CURRENT_MIT_VECTOR` at `0x200`. For earlier versions, return zero for
    both vectors.
11. Return the raw report, report version, normalized TCB, `PLATFORM_INFO`,
    CPUID, and mitigation-vector fields with `valid=true`.

The normalized AMD SEV-SNP state is checked by
`TeeSecurityPolicyVerifier`, which reads the active exact-CPUID
`AmdSnpSecurityPolicyRegistry` record. The complete report checks, packed
formats, supported processor range, and merge rules are defined in
[AMD SEV-SNP Security Policy Specification](../amd-sev-snp-security-policy-spec.md).
Intel TDX `TD_ATTRIBUTES.PERFMON` remains a future policy candidate.

### Modular prover mapping

The portal maps each validated daemon result to `ProgramBoundZkProof`. A
validated protocol result maps `onchain_backend` as follows:

| Protocol value | `VerificationBackendType` | zk coprocessor |
|---|---|---|
| `zk_succinct` | ZK Succinct | program/vkey from the selected SP1 artifact manifest |
| `zk_risc_zero` | ZK Risc Zero | image ID from the selected RISC Zero artifact manifest |

The daemon also returns `program_id`, `artifact_id`, `verifier_program_id`,
`output_schema`, and `proof_encoding`. The portal accepts them only when they
exactly match a capability negotiated before submission. The contract resolves
`verifier_program_id` through `ZkVerifierRegistry` and does not infer a route
from the backend name.

`amd_sev_snp.v1` must use a ZK backend because the contract has no SNP Solidity
path. `intel_tdx_dcap.v1` may use the existing Solidity DCAP path or a ZK path.
With init `chain.tee_backend = "auto"`, SNP selects ZK and TDX selects Solidity.
Forcing `"zk"` on TDX requires the artifact's verifier program identity to be
registered in the corresponding on-chain coprocessor configuration.

#### Helper Functions

| Function | Visibility | Purpose |
|---|---|---|
| `extractDcapQuoteBody(output)` | private | Parse DCAP output -> TD10/TD15 quote body bytes |
| `extractDcapReportData(quoteBody)` | external | Extract 64 bytes at offset 520 from quote body |
| `extractSnpAttestationReport(rawReport)` | private | Require the exact 1,184-byte report and validate policy fields |
| `extractSnpReportData(rawReport)` | external | Extract 64 bytes at offset 0x50 from SNP report |
| `deriveGcpPcr15ExtendValue(result)` | external | Extract the exact SHA-256 bank-width value extended into GCP PCR15 from a verified TDX UUID/RTMR3 pair or AMD SEV-SNP `REPORT_ID` |

`extractDcapQuoteBody` uses inline assembly for byte extraction.
`deriveGcpPcr15ExtendValue` uses `LibBytes` and `Sha2Ext` for exact
verified-report parsing and SHA-384 RTMR3 reconstruction. It returns
`bytes16(0) || UUID` for TDX and `REPORT_ID` for AMD SEV-SNP. It does not
calculate the final PCR value.

### Errors

| Error | Condition |
|---|---|
| `UnsupportedTeeType(TEEType actual)` | Not TDX or SNP |
| `UnsupportedBackendType(TEEType teeType, VerificationBackendType backend)` | Invalid verification backend (for example, Solidity for SNP) |
| `TeeReportTooShort(uint256 length, uint256 minRequired)` | Generic report is too short |
| `UnsupportedDcapBodyType(uint16 bodyType)` | DCAP output is neither TD10 nor TD15 |
| `DcapReportDataOob(uint256 length, uint256 minRequired)` | DCAP report-data slice is out of bounds |
| `DcapVerificationFailed(bytes output)` | Upstream DCAP verification failed |
| `DcapTcbStatusNotAccepted(uint8 actual)` | DCAP trusted computing base status is 6, 7, or an unknown non-configurable value |
| `InvalidDcapQuoteBodyLength(uint256 actual, uint256 expected)` | Intel TDX quote body length does not match its body type |
| `DcapQuoteBodyHashMismatch(bytes32 expected, bytes32 actual)` | Supplied Intel TDX quote body does not match the proof journal |
| `UnsupportedDcapQuoteVersion(uint16 actual)` | Raw Intel TDX quote version is not 4 or 5 |
| `InvalidDcapTeeType(uint32 actual)` | Raw Intel TDX quote does not declare Intel TDX TEE type `0x81` |
| `InvalidDcapQuoteLength(uint256 actual, uint256 expected)` | Raw Intel TDX quote is truncated or has trailing bytes |
| `InvalidTdxAttributes(bytes8 actual)` | Intel TDX reserved attribute bits are invalid |
| `TdxSeptVeDisableRequired()` | Intel TDX `SEPT_VE_DISABLE` is absent |
| `TdxMigrationServiceTdNotSupported()` | Intel TDX 1.5 `MR_SERVICETD` is nonzero |
| `SnpVerificationFailed(VerificationResult result)` | SNP proof journal reports failure |
| `SnpReportHashMismatch(bytes32 expected, bytes32 actual)` | Supplied raw SNP report is not the proof-committed report |
| `InvalidSnpReportLength(uint256 actual, uint256 expected)` | Raw report is not exactly 1,184 bytes |
| `UnsupportedSnpReportVersion(uint32 actual)` | AMD SEV-SNP report version is unsupported |
| `InvalidSnpPolicy(uint64 actual)` | Required or reserved AMD SEV-SNP policy bits are invalid |
| `UnsupportedSnpVmpl(uint32 actual)` | AMD SEV-SNP `VMPL` is nonzero |
| `SnpMigrationAgentNotSupported()` | AMD SEV-SNP `REPORT_ID_MA` is neither the all-zero nor the all-`0xff` no-association sentinel |
| `InvalidSnpSignatureAlgorithm(uint32 actual)` | AMD SEV-SNP report signature algorithm is not ECDSA P-384 with SHA-384 |
| `InvalidSnpKeySettings(uint32 actual)` | AMD SEV-SNP signing-key selection or masking-chip settings are unsupported |
| `InvalidSnpReservedField(uint256 offset)` | A reserved AMD SEV-SNP report field is nonzero |
| `InvalidSnpTcb(uint256 offset, uint64 actual)` | An AMD SEV-SNP TCB field has nonzero reserved bytes |
| `InvalidSnpPlatformInfo(uint64 actual)` | AMD SEV-SNP `PLATFORM_INFO` contains an unsupported bit |
| `UnsupportedSnpCpuid(uint24 actual)` | AMD SEV-SNP CPUID is outside AMD family `0x19`, model `0x00` through `0x1f` |
| `InvalidSnpTcbOrder(bytes32 lower, bytes32 upper)` | The AMD SEV-SNP TCB fields do not satisfy reported ≤ committed ≤ current; launch TCB has no ordering rule |

---

## SignatureVerifier

**File**: `src/SignatureVerifier.sol`
**Interface**: `src/interfaces/ISignatureVerifier.sol`
**Role**: Stateless multi-algorithm signature verification

### Version & Immutables

```solidity
string public constant SIGNATURE_VERIFIER_VERSION = "1.0.0";
address public immutable P256_VERIFIER_ADDRESS;
```

### Dependencies

- OpenZeppelin `RSA` library (PKCS#1 v1.5 SHA-256)
- OpenZeppelin `ECDSA` library (secp256k1 recovery)
- External `P256Verifier` contract (for P-256/secp256r1) at `P256_VERIFIER_ADDRESS`
- Custom `Asn1Decode` library (DER parsing for RSA keys and P-256 signatures)

### Errors

```solidity
error UnsupportedAlgorithm(uint8 typeId);
error InputTooLong(uint256 length);
```

### Constructor

```solidity
constructor(address p256VerifierAddress)
```

### Function

```solidity
function verify(
    PublicIdentity calldata identity,
    bytes32 message,
    bytes calldata signature
) external view returns (bool)
```

**Algorithm dispatch based on `identity.typeId`**:

#### RS256 (typeId = 1)
1. Parse DER-encoded PKCS#1 RSA public key from `identity.key`
2. Extract modulus (n) and exponent (e) via ASN.1 decoding
3. Call `RSA.pkcs1Sha256(message, signature, e, n)`

#### ES256 (typeId = 2)
1. Validate key is 65 bytes starting with `0x04`
2. Extract x, y coordinates from SEC1 uncompressed point
   - `x = bytes32(key[1:33])`, `y = bytes32(key[33:65])`
3. Parse DER-encoded signature to extract r, s via ASN.1 decoding
4. Call external P256Verifier: `staticcall(p256Verifier, abi.encode(message, r, s, x, y))`
5. Result: first 32 bytes of return value == 1

#### ES256K (typeId = 3)
1. Validate key is 65 bytes starting with `0x04`
2. Derive expected address from public key: `address(uint160(uint256(keccak256(key[1:65]))))`
3. Call `ECDSA.tryRecoverCalldata(message, signature)` to recover signer address
4. Compare recovered address with expected address and check no error

---

## TpmVerifier

**File**: `src/bases/TpmVerifier.sol`
**Inheritance**: `TpmBase`, `OwnableUpgradeable`, `UUPSUpgradeable`
**Role**: TPM quote and certify verification

`TpmVerifier` is deployed behind an `ERC1967Proxy`. `SessionRegistry` stores
the proxy address as its immutable `tpmVerifier` dependency. The owner may
upgrade the `TpmVerifier` implementation without upgrading `SessionRegistry`.
The implementation constructor keeps the immutable TPM-attestation library and
ZK-verifier-registry addresses. The proxy initializer sets the owner.

### Constants

```solidity
// Required TPMA_OBJECT attribute bits
uint32 constant TPMA_OBJECT_REQUIRED_SET = 0x40072;
// fixedTPM (0x2) | fixedParent (0x10) | sensitiveDataOrigin (0x20) | userWithAuth (0x40) | sign (0x40000)

// Forbidden TPMA_OBJECT bits (must be clear)
// Allowed bits (may be 0 or 1): {1,4,5,6,10,18} = 0x00040472
// stClear (bit 2) and adminWithPolicy (bit 7) are explicitly forbidden.
uint32 constant TPMA_OBJECT_REQUIRED_CLEAR = 0xFFFBFB8D;
```

### Functions

#### `verifyTpmQuote`
```solidity
function verifyTpmQuote(
    TpmReport memory tpmReport,
    PublicIdentity memory akPub,
    bytes32 expectedQualifyingData,
    TpmVerificationRequest memory request
) public returns (TpmQuoteVerificationResult memory)
```

1. Validate `tpmReportType == TpmQuote`
2. For `Solidity`, decode `TpmQuoteEvidence`, verify the Attestation Key
   signature, require the exact 32-byte `expectedQualifyingData`, parse the
   signed bank selection, verify the signed `pcrDigest`, evaluate every rule
   in the four policy blocks, and return the exact `PcrCommitment` and
   `PolicyCommitment`.
3. For `ZkSuccinct`, decode `ProgramBoundZkProof`, resolve the exact
   `TpmQuote` adapter, verify the proof, and decode `TpmQuoteJournalV1` into the
   same five result fields.
4. Require the exact Attestation Key fingerprint, qualifying data,
   normalized signed selection, and `PolicyCommitment`.
5. Reject every unconfigured backend.

The raw path accepts SHA-256, SHA-384, or both in that order. Each bank must
select at least one supported index. Supported indexes are 0 through 16 and
23. `TpmVerifier` alone decodes each opaque PCR `comparison`. It requires a
complete canonical ABI decoding and rejects trailing bytes or alternate ABI
encodings. Every non-`STATIC` SHA-384 comparison, including
`EXTEND_FROM_ZERO`, requires `tpm_quote.v1`; the Solidity path accepts
SHA-384 only for `STATIC` rules.

`EXTEND_FROM_ZERO` has comparison type `4`. SHA-256 uses
`abi.encode(uint16(4), bytes32 extendValue)` and requires the authenticated
PCR value to equal `sha256(bytes32(0) || extendValue)`. SHA-384 uses
`abi.encode(uint16(4), Bytes48 extendValue)` and requires the authenticated
PCR value to equal `sha384(bytes48(0) || extendValue)`.

Each policy block hash is:

```solidity
keccak256(abi.encode(
    PCR_POLICY_BLOCK_DOMAIN,
    block.pcrSpecs256,
    block.pcrSpecs384
))
```

The complete policy commitment is:

```solidity
keccak256(abi.encode(
    TPM_POLICY_COMMITMENT_DOMAIN,
    invariantBlockHash,
    variantBlockHash,
    workloadBlockHash,
    providerBlockHash
))
```

`PcrCommitment.pcrSelect` packs each signed Quote selection entry as
`uint16 bankId || bytes3 pcrSelectBitmap`. The one or two entries use ascending
bank identifiers and the result is right-padded to 32 bytes.
`PcrCommitment.pcrDigest` is the exact signed 32-byte Quote digest.
```

The array encoding binds every length, `pcrIndex`, complete `comparison` blob,
and rule order.

#### `verifyTpmCertify`
```solidity
function verifyTpmCertify(
    TpmReport memory tpmReport,
    PublicIdentity memory akPub
) public view returns (TpmCertifyVerificationResult memory)
```

1. Validate `tpmReportType == TpmCertify`
2. Validate `verificationBackendType == Solidity`
3. Decode `TpmCertifyEvidence` from `tpmReport.data`
4. Validate CLEAR bits on `tpmtPublic[4:8]` via `_validateClearBits` -- checks `TPMA_OBJECT_REQUIRED_CLEAR` BEFORE the library call
5. Convert `PublicIdentity` -> `CertPubkey`
6. Call `tpmAttestation.verifyTpmKeyCertification(tpmsAttest, tpmSignature, tpmtPublic, akCertPubkey, TPMA_OBJECT_REQUIRED_SET)` -- the library validates SET bits
7. Convert certified key (`CertPubkey`) back to `PublicIdentity`
8. Compute fingerprint of certified key
9. Return: `{ valid: true, certifiedKey, certifiedKeyFingerprint }`

### Errors

| Error | Condition |
|---|---|
| `UnexpectedTpmReportType(TpmReportType actual, TpmReportType expected)` | Wrong report type for operation |
| `TpmReportBackendNotConfigured(TpmReportType, VerificationBackendType)` | No configured backend for the report type |
| `TpmQuoteExtraDataMismatch(bytes32 measured, bytes32 expected)` | Nonce binding check failed |
| `TpmQuoteLibraryFailed()` | TPM attestation library returned error |
| `InvalidPcrBankOrder()` | SHA-384 precedes SHA-256 or a bank repeats |
| `UnsupportedPcrSelection(uint16 algorithm, uint32 mask)` | Quote selected an unsupported PCR index |
| `InvalidPcrComparisonType(uint16 algorithm, uint8 pcrIndex, uint256 encodedType)` | The first ABI word does not fit `uint16` |
| `UnsupportedPcrComparison(uint16 algorithm, uint8 pcrIndex, uint16 comparisonType)` | The implementation does not support the comparison type |
| `NonCanonicalPcrComparison(uint16 algorithm, uint8 pcrIndex)` | Decoding and re-encoding changed the comparison bytes |
| `DynamicSha384PolicyRequiresZk(uint8 pcrIndex, uint16 comparisonType)` | Raw Solidity path received a dynamic SHA-384 rule |
| `PcrIndexedEventSetMismatch(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex)` | A checked event digest is not in its allowed set |
| `TpmaObjectForbiddenBitsSet(uint32 actualAttrs, uint32 forbiddenBitsSet)` | Certified key has forbidden attributes |
| `TpmtPublicTooShort(uint256 length)` | `tpmtPublic` is too short to extract attributes |

---

## AkCollateralVerifier

**File**: `src/bases/AkCollateralVerifier.sol`
**Interface**: `src/interfaces/IAkCollateralVerifier.sol`
**Inheritance**: `IAkCollateralVerifier`, `TpmBase`
**Role**: Separately deployed Azure MAA, GCP certificate-chain, AWS
NitroTPM-proof, and Attestation Key validator

### Function

```solidity
function validateAkPub(
    AkPubCollateralType collateralType,
    PublicIdentity calldata akPub
) external pure returns (bytes32 fingerprint)

function verifyAkCollateral(
    AkPubCollateral calldata collateral
) external returns (AkCollateralVerificationResult memory)
// Returns the exact AkCollateralVerificationResult fields.
```

`validateAkPub` requires RS256 with a non-empty key for Azure. It requires
ES256 with a valid uncompressed P-256 curve point for GCP and AWS. It returns
the exact `KEY_RESOLVER_V1` fingerprint.

Dispatches based on `collateral.akPubCollateralType`:

#### AzureMaaJwt
Azure delivers the AK public key inside an HCL `var_data` JWK document, anchored to the platform via a Microsoft Azure Attestation (MAA) signed JWT. Wire format is an ABI tuple:

```
abi.encode((bytes jwt, bytes hclVarData))
```

- `jwt` is a Microsoft Azure Attestation-signed JSON Web Token (RS256 / RSA-2048 / SHA-256) issued for `/attest/TdxVm` (TDX) or `/attest/SevSnpVm` (SNP).
- `hclVarData` is the JSON document from vTPM NV `0x01400001`, containing the `HCLAkPub` JWK.

Verification steps:
1. `abi.decode` `collateral.data` into `(bytes jwt, bytes hclVarData)`.
2. Split `jwt` on `.` into header / claims / signature parts (all base64url).
3. Base64url-decode the header; parse JSON; extract `kid` and `alg` (require `"RS256"`).
4. Look up MAA signing key by `keccak256(bytes(kid))` in the MAA Signing Key Registry; require `!revoked` and `block.timestamp <= notAfter`.
5. Verify the RS256 signature on `header || "." || claims` against the registered PKCS#1 RSA-2048 pubkey using `SignatureVerifier._verifyRsa`.
6. Base64url-decode the claims; parse JSON; assert:
   - `iss` matches the issuer hash registered for the kid
   - `x-ms-attestation-type` in `{"tdxvm", "sevsnpvm"}`
   - `x-ms-compliance-status == "azure-compliant-cvm"`
7. Extract the report-data claim (`tdx_report_data` for TDX, `x-ms-sevsnpvm-reportdata` for SNP); hex-decode first 32 bytes as `bindingHash`; assert next 32 bytes decode to zero.
8. Assert `sha256(hclVarData) == bindingHash`.
9. Parse `HCLAkPub` from `hclVarData` using the scoped JWK parser and return
   its exact `KEY_RESOLVER_V1` fingerprint.

The verifier maps `x-ms-attestation-type` to the returned `teeType`
(`tdxvm` → `IntelTDX`, `sevsnpvm` → `AmdSevSnp`). `SessionRegistry` requires
this value to equal `TeeVerificationResult.teeType`.

Binding: `sha256(hclVarData)` is returned as `bindingHash`. `SessionRegistry`
requires the verified Intel TDX or AMD SEV-SNP report's 64-byte `REPORT_DATA`
to equal `bindingHash || bytes32(0)`. This joins the independently verified raw
TEE report to the MAA-signed HCL data and prevents report splicing.

#### GcpCertChain
GCP provides X.509 certificate chain:
1. ABI-decode `bytes[]` array of DER certificates from collateral data
2. Call `tpmAttestation.verifyCertChain(certs)` -> returns `CertPubkey`
3. Require `certs[0]` to satisfy the non-CA attestation constraints; generic chain verification also accepts CA targets
4. Convert `CertPubkey` -> `PublicIdentity`

Binding: `bindingHash = bytes32(0)`. AK is bound to TEE via PCR15 computation (verified in SessionRegistry step 7).

#### AwsNitroTpmProof

`AwsNitroTpmProof` requires `VerificationBackendType.ZkSuccinct`. The verifier
decodes `ProgramBoundZkProof`, resolves the exact `AwsNitroTpm` adapter through
`ZkVerifierRegistry`, and returns `AwsNitroTpmJournalV1`. The journal binds the
AMD SEV-SNP report hash, trusted Nitro root hash, Attestation Key fingerprint,
qualifying data, document timestamp, and the complete `PcrCommitment`.

### Errors

| Error | Condition |
|---|---|
| `UnsupportedAkCollateralType(AkPubCollateralType actual)` | Unknown collateral type |
| `AzureJwkParsingFailed()` | `HCLAkPub` JWK field extraction from `hclVarData` failed |
| `MaaJwtStructureInvalid(uint8 segmentCount)` | JWT does not contain three non-empty segments |
| `MaaJwtBase64DecodeFailed(uint8 segment)` | A JWT segment decodes to empty bytes |
| `MaaJwtAlgUnsupported(bytes32 algHash)` | JWT header `alg` is not `"RS256"` |
| `MaaJwtHeaderClaimMissing(bytes32 fieldNameHash)` | Required `kid` or `alg` header is absent |
| `MaaJwtClaimMissing(bytes32 fieldNameHash)` | A required JWT claim is absent |
| `MaaKidNotRegistered(bytes32 kidHash)` | Key is empty, revoked, or expired |
| `MaaJwtIssuerMismatch(bytes32 actual, bytes32 expected)` | `iss` does not match the registered issuer |
| `MaaJwtAttestationTypeUnsupported(bytes32 attestationTypeHash)` | Attestation type is neither TDX nor SNP |
| `MaaJwtComplianceFailed(bytes32 complianceStatusHash)` | Compliance claim is not `"azure-compliant-cvm"` |
| `MaaJwtReportDataMalformed(uint256 length, uint256 badCharOffset)` | Report-data claim has invalid length, hex, or padding |
| `MaaJwtSignatureInvalid(bytes32 kidHash)` | `SignatureVerifier.verify` rejected the RS256 signature |
| `MaaJwtBindingMismatch(bytes32 measured, bytes32 expected)` | `sha256(hclVarData)` did not equal the report-data claim prefix |

---

## TpmBase

**File**: `src/bases/TpmBase.sol`
**Role**: Shared abstract base holding `ITpmAttestation` immutable

```solidity
abstract contract TpmBase {
    ITpmAttestation public immutable tpmAttestation;
    constructor(ITpmAttestation _tpmAttestation) {
        tpmAttestation = _tpmAttestation;
    }
}
```

`SessionRegistry` and the separately deployed `AkCollateralVerifier` each
receive an immutable `ITpmAttestation` reference through `TpmBase`.
