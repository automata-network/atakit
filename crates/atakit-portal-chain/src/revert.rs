//! Best-effort decoder for on-chain revert data into human-readable strings.
//!
//! When an `eth_call` / `eth_estimateGas` / `eth_sendRawTransaction` reverts,
//! nodes return the ABI-encoded custom error in the JSON-RPC error `data` field
//! as `0x<4-byte-selector><args>`. The portal otherwise surfaces that hex
//! verbatim, leaving operators to look the selector up by hand. [`decode_revert`]
//! recognizes the errors on the AMD SEV-SNP ZK registration path and renders
//! them with their arguments, so `chain.detail` says *why* a registration
//! failed.
//!
//! Scope is the full SNP ZK `registerSession` path plus the two universal
//! Solidity errors (`Error(string)` / `Panic(uint256)`): the `TeeVerifier`
//! SNP backend, the `SessionRegistry` PCR/attribute/session checks, and the
//! `BaseImageRegistry` / `WorkloadRegistry` lookups it drives. Unknown
//! selectors return `None` — the caller keeps showing the raw hex.
//!
//! Enum parameters canonicalize to `uint8` in the 4-byte selector signature, so
//! every enum arg below is declared `uint8` (the selector still matches the
//! on-chain `keccak256(signature)[..4]`); the discriminant is rendered back to
//! its name. Selectors are pinned against the live contract signatures in
//! `tests::selectors_match_onchain`.

use alloy_primitives::U256;
use alloy_sol_types::{sol, SolError};

sol! {
    // ── Universal Solidity reverts ────────────────────────────────
    /// `require(cond, "msg")` / `revert("msg")`.
    error Error(string message);
    /// Solidity `panic` (assert, overflow, etc.); arg is the panic code.
    error Panic(uint256 code);

    // ── TeeVerifier (automata-tee-workload-measurement/src/TeeVerifier.sol) ──
    /// TEE type with no verifier wired (e.g. an unknown discriminant).
    error UnsupportedTeeType(uint8 actual);
    /// No verification backend wired for this (tee, backend) pair. The SNP path
    /// hit this as `(AmdSevSnp, Solidity)` before the ZK backend was selected.
    error UnsupportedBackendType(uint8 teeType, uint8 backend);
    /// Raw SNP report shorter than the 1184-byte minimum.
    error SnpReportTooShort(uint256 length, uint256 minRequired);
    error TeeReportTooShort(uint256 length, uint256 minRequired);
    error UnsupportedDcapQuoteVersion(uint16 actual);
    error InvalidDcapTeeType(uint32 actual);
    error InvalidDcapQuoteLength(uint256 actual, uint256 expected);
    error UnsupportedDcapBodyType(uint16 bodyType);
    error DcapReportDataOob(uint256 length, uint256 minRequired);
    error DcapVerificationFailed(bytes output);
    error DcapTcbStatusNotAccepted(uint8 actual);
    error InvalidDcapQuoteBodyLength(uint256 actual, uint256 expected);
    error DcapQuoteBodyHashMismatch(bytes32 expected, bytes32 actual);
    error DcapProofVerificationFailed(bytes output);
    error InvalidDcapJournalOutputLength(uint256 actual, uint256 expected);
    error InvalidTdxAttributes(bytes8 actual);
    error TdxSeptVeDisableRequired();
    error TdxMigrationServiceTdNotSupported();
    /// `ISnpAttestation.VerificationResult` (uint8) when SNP verification failed.
    error SnpVerificationFailed(uint8 result);
    /// `keccak256(rawReport)` did not match the proof journal's report hash.
    error SnpReportHashMismatch(bytes32 expected, bytes32 actual);
    error InvalidSnpReportLength(uint256 actual, uint256 expected);
    error UnsupportedSnpReportVersion(uint32 actual);
    error InvalidSnpPolicy(uint64 actual);
    error UnsupportedSnpVmpl(uint32 actual);
    error SnpMigrationAgentNotSupported();
    error InvalidSnpSignatureAlgorithm(uint32 actual);
    error InvalidSnpKeySettings(uint32 actual);
    error InvalidSnpReservedField(uint256 offset);
    error InvalidSnpTcb(uint256 offset, uint64 actual);
    error InvalidSnpPlatformInfo(uint64 actual);
    error UnsupportedSnpCpuid(uint24 actual);
    error InvalidSnpTcbOrder(bytes32 lower, bytes32 upper);

    // ── TpmVerifier (src/bases/TpmVerifier.sol) ───────────────────
    struct PcrBytes48 {
        bytes32 first;
        bytes16 second;
    }
    error PcrValueNotFound(uint16 algorithm, uint8 pcrIndex);
    error InvalidPcrRule(uint16 algorithm, uint8 pcrIndex);
    error InvalidPcrComparisonType(uint16 algorithm, uint8 pcrIndex, uint256 encodedType);
    error UnsupportedPcrComparison(uint16 algorithm, uint8 pcrIndex, uint16 comparisonType);
    error NonCanonicalPcrComparison(uint16 algorithm, uint8 pcrIndex);
    error DynamicSha384PolicyRequiresZk(uint8 pcrIndex, uint16 comparisonType);
    error PcrReplayMismatch256(uint8 pcrIndex, bytes32 measured, bytes32 replayed);
    error PcrStaticMismatch256(uint8 pcrIndex, bytes32 measured, bytes32 expected);
    error PcrStaticMismatch384(uint8 pcrIndex, PcrBytes48 measured, PcrBytes48 expected);
    error PcrEventLogEmpty(uint16 algorithm, uint8 pcrIndex, uint16 comparisonType);
    error PcrSubsetLandmarkMissing(uint16 algorithm, uint8 pcrIndex, uint256 landmarkIndex);
    error PcrSubsequenceLandmarkMissing(
        uint16 algorithm,
        uint8 pcrIndex,
        uint256 matched,
        uint256 required
    );
    error PcrEventCountMismatch(uint16 algorithm, uint8 pcrIndex, uint256 actual, uint16 expected);
    error PcrCheckedEventsEmpty(uint16 algorithm, uint8 pcrIndex);
    error PcrCheckedEventIndexOutOfRange(
        uint16 algorithm,
        uint8 pcrIndex,
        uint16 eventIndex,
        uint16 eventCount
    );
    error PcrCheckedEventIndexesNotSorted(
        uint16 algorithm,
        uint8 pcrIndex,
        uint16 previous,
        uint16 current
    );
    error PcrAllowedValuesEmpty(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex);
    error PcrAllowedValuesNotSorted(
        uint16 algorithm,
        uint8 pcrIndex,
        uint16 eventIndex,
        uint256 position
    );
    error PcrIndexedEventSetMismatch(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex);
    error EmptyPcrComparison(uint8 pcrIndex);
    /// A required workload attribute `key` was not present.
    error AttributeNotFound(bytes32 key);
    /// Attribute `key` carried a value outside the workload's allowed set.
    error AttributeValueNotAllowed(bytes32 key, bytes32 actualValue);
    error TeeVerificationFailed();
    error AkCollateralVerificationFailed();
    error SessionNotFound();
    error SessionKeyPossessionFailed(bytes32 messageHash, bytes32 sessionKeyFingerprint);
    error SessionFingerprintInUse(bytes32 sessionKeyFingerprint, bytes32 activeSessionId);
    error UnsupportedAzureTeeType(uint8 teeType);
    error AzureMaaTeeTypeMismatch(uint8 teeReportType, uint8 maaTeeType);
    error AzureTeeReportDataMismatch(
        bytes32 actualBindingHash,
        bytes32 expectedBindingHash,
        bytes32 actualPadding
    );
    error AzureTeeReportDataTooShort(uint256 actualLength, uint256 minRequired);
    error TeeAttributeBaseImageMismatch(
        bytes32 key,
        bytes32 declaredValue,
        bytes32 verifiedValue
    );
    error EmptyTeeAttributeRequirement(bytes32 key);
    error InvalidPackedTeeAttributeRequirementLength(bytes32 key, uint256 actualLength);
    error TeeAttributeValueNotAllowed(bytes32 key, bytes32 actualValue);
    error TeeAttributePolicyConflict(bytes32 key, bytes32 baseValue, bytes32 workloadValue);
    error PolicyNotFound(uint24 cpuid);
    error PolicyNotActive(uint24 cpuid);
    error PolicyRevisionMismatch(uint24 cpuid, uint64 actual, uint64 expected);
    error SnpMitigationPolicyRequiresReportVersion(uint32 actualVersion, uint32 requiredVersion);
    error SnpLaunchMitigationVectorMissing(uint64 requiredMask, uint64 actual);
    error SnpCurrentMitigationVectorMissing(uint64 requiredMask, uint64 actual);

    // ── AkCollateralVerifier (src/bases/AkCollateralVerifier.sol) ─
    error MaaJwtClaimMissing(bytes32 fieldNameHash);
    error MaaJwtNumericClaimMalformed(bytes32 fieldNameHash);
    error MaaJwtValidityWindowInvalid(uint64 issuedAt, uint64 notBefore, uint64 expiresAt);
    error MaaJwtNotYetValid(uint64 notBefore, uint256 verificationTime);
    error MaaJwtExpired(uint64 expiresAt, uint256 verificationTime);
    error MaaJwtIssuedInFuture(uint64 issuedAt, uint256 verificationTime);

    // ── TpmVerifier (src/bases/TpmVerifier.sol) ───────────────────
    /// Quote extraData did not match the current owner nonce binding.
    error TpmQuoteExtraDataMismatch(bytes32 measured, bytes32 expected);
    /// ZK evidence did not match the current owner nonce binding.
    error QualifyingDataMismatch(bytes32 measured, bytes32 expected);

    // ── Registry lookups (BaseImageRegistry / WorkloadRegistry) ───
    /// Caller fingerprint does not match the registered owner. Shared signature
    /// across SessionRegistry / BaseImageRegistry / WorkloadRegistry (one selector).
    error Unauthorized(bytes32 actualOwner, bytes32 expectedOwner);
    error BaseImageNotFound(bytes32 baseImageId);
    error BaseImageNotActive(bytes32 baseImageId);
    error BaseImageNotAllowed(bytes32 baseImageId);
    error PlatformProfileNotFound(bytes32 platformProfileId);
    error WorkloadNotFound(bytes32 workloadId);
    error WorkloadNotActive(bytes32 workloadId);
    error InvalidTeeAttributeValue(bytes32 key, bytes32 actualValue);
    /// A submitted measurement variant pins `pcrIndex`, which platform profile
    /// `platformProfileId` already declares invariant. Remove the index from the profile's
    /// invariants (in a new base image) if it is genuinely machine-type dependent.
    error VariantOverridesInvariantPcr(bytes32 platformProfileId, uint8 pcrIndex);
    error InvalidTeeAttributeRequirementLength(bytes32 key, uint256 actualLength);
    error InvalidTeeAttributeRequirementValue(bytes32 key, bytes32 actualValue);

    // ── SP1 Groth16 zkVerifier ────────────────────────────────────
    /// Raised when the proof doesn't match the verifier's pinned program id
    /// (vkey) — the most likely SNP-path revert when program-id pinning (R7) is
    /// misconfigured. No args (selector 0x7fcdd1f4).
    error ProofInvalid();
}

/// Map an `ISnpAttestation.VerificationResult` discriminant to its name.
/// `Success` (0) should never accompany a `SnpVerificationFailed` revert, but
/// it's handled for completeness; unknown discriminants render numerically.
fn verification_result_name(v: u8) -> String {
    match v {
        0 => "Success".to_string(),
        1 => "RootCertNotTrusted".to_string(),
        2 => "InvalidTimestamp".to_string(),
        other => format!("Unknown({other})"),
    }
}

/// `TEEType` discriminant → name (`src/types/Evidence.sol`).
fn tee_type_name(v: u8) -> String {
    match v {
        0 => "IntelTDX".to_string(),
        1 => "AmdSevSnp".to_string(),
        other => format!("Unknown({other})"),
    }
}

/// `VerificationBackendType` discriminant → name (`src/types/Evidence.sol`).
fn backend_type_name(v: u8) -> String {
    match v {
        0 => "Solidity".to_string(),
        1 => "ZkRiscZero".to_string(),
        2 => "ZkSuccinct".to_string(),
        other => format!("Unknown({other})"),
    }
}

fn pcr_algorithm_name(value: u16) -> String {
    match value {
        0x000b => "SHA-256".to_string(),
        0x000c => "SHA-384".to_string(),
        other => format!("Unknown(0x{other:04x})"),
    }
}

fn pcr_comparison_type_name(value: u16) -> String {
    match value {
        0 => "STATIC".to_string(),
        1 => "DYNAMIC_SUBSET".to_string(),
        2 => "DYNAMIC_SUBSEQUENCE".to_string(),
        3 => "DYNAMIC_INDEXED_EVENT_SETS".to_string(),
        other => format!("Unknown({other})"),
    }
}

fn pcr_bytes48_hex(value: &PcrBytes48) -> String {
    format!("{}{}", hex::encode(value.first), hex::encode(value.second))
}

/// A time-dependent Microsoft Azure Attestation JWT revert. The first two
/// variants can become valid when the chain mines a newer block. `Expired`
/// cannot become valid and must not be retried with the same JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaaJwtTimeRevert {
    NotYetValid {
        not_before: u64,
        verification_time: U256,
    },
    IssuedInFuture {
        issued_at: u64,
        verification_time: U256,
    },
    Expired {
        expires_at: u64,
        verification_time: U256,
    },
}

/// Decode only the Microsoft Azure Attestation JWT time errors that need
/// special submission handling.
pub fn decode_maa_jwt_time_revert(data: &[u8]) -> Option<MaaJwtTimeRevert> {
    if data.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = data[..4].try_into().ok()?;
    if selector == MaaJwtNotYetValid::SELECTOR {
        let error = MaaJwtNotYetValid::abi_decode(data).ok()?;
        return Some(MaaJwtTimeRevert::NotYetValid {
            not_before: error.notBefore,
            verification_time: error.verificationTime,
        });
    }
    if selector == MaaJwtIssuedInFuture::SELECTOR {
        let error = MaaJwtIssuedInFuture::abi_decode(data).ok()?;
        return Some(MaaJwtTimeRevert::IssuedInFuture {
            issued_at: error.issuedAt,
            verification_time: error.verificationTime,
        });
    }
    if selector == MaaJwtExpired::SELECTOR {
        let error = MaaJwtExpired::abi_decode(data).ok()?;
        return Some(MaaJwtTimeRevert::Expired {
            expires_at: error.expiresAt,
            verification_time: error.verificationTime,
        });
    }
    None
}

/// Decode revert `data` (the raw `0x`-stripped bytes: 4-byte selector followed
/// by ABI-encoded args) into a human-readable description, or `None` if the
/// selector isn't one this decoder knows.
pub fn decode_revert(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = data[..4].try_into().ok()?;

    // ── Universal Solidity reverts ────────────────────────────────
    if selector == Error::SELECTOR {
        let e = Error::abi_decode(data).ok()?;
        return Some(format!("Error({:?})", e.message));
    }
    if selector == Panic::SELECTOR {
        let e = Panic::abi_decode(data).ok()?;
        return Some(format!("Panic(0x{:x})", e.code));
    }

    // ── TeeVerifier ───────────────────────────────────────────────
    if selector == UnsupportedTeeType::SELECTOR {
        let e = UnsupportedTeeType::abi_decode(data).ok()?;
        return Some(format!(
            "UnsupportedTeeType(actual={})",
            tee_type_name(e.actual)
        ));
    }
    if selector == UnsupportedBackendType::SELECTOR {
        let e = UnsupportedBackendType::abi_decode(data).ok()?;
        return Some(format!(
            "UnsupportedBackendType(teeType={}, backend={}) — no verifier wired \
             for this pair; the SNP ZK path needs backend=ZkSuccinct or ZkRiscZero",
            tee_type_name(e.teeType),
            backend_type_name(e.backend)
        ));
    }
    if selector == SnpReportTooShort::SELECTOR {
        let e = SnpReportTooShort::abi_decode(data).ok()?;
        return Some(format!(
            "SnpReportTooShort(length={}, minRequired={})",
            e.length, e.minRequired
        ));
    }
    if selector == TeeReportTooShort::SELECTOR {
        let e = TeeReportTooShort::abi_decode(data).ok()?;
        return Some(format!(
            "TeeReportTooShort(length={}, minRequired={})",
            e.length, e.minRequired
        ));
    }
    if selector == UnsupportedDcapQuoteVersion::SELECTOR {
        let e = UnsupportedDcapQuoteVersion::abi_decode(data).ok()?;
        return Some(format!("UnsupportedDcapQuoteVersion(actual={})", e.actual));
    }
    if selector == InvalidDcapTeeType::SELECTOR {
        let e = InvalidDcapTeeType::abi_decode(data).ok()?;
        return Some(format!("InvalidDcapTeeType(actual={})", e.actual));
    }
    if selector == InvalidDcapQuoteLength::SELECTOR {
        let e = InvalidDcapQuoteLength::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidDcapQuoteLength(actual={}, expected={})",
            e.actual, e.expected
        ));
    }
    if selector == UnsupportedDcapBodyType::SELECTOR {
        let e = UnsupportedDcapBodyType::abi_decode(data).ok()?;
        return Some(format!("UnsupportedDcapBodyType(bodyType={})", e.bodyType));
    }
    if selector == DcapReportDataOob::SELECTOR {
        let e = DcapReportDataOob::abi_decode(data).ok()?;
        return Some(format!(
            "DcapReportDataOob(length={}, minRequired={})",
            e.length, e.minRequired
        ));
    }
    if selector == DcapVerificationFailed::SELECTOR {
        let e = DcapVerificationFailed::abi_decode(data).ok()?;
        return Some(format!(
            "DcapVerificationFailed(output=0x{})",
            hex::encode(e.output)
        ));
    }
    if selector == DcapTcbStatusNotAccepted::SELECTOR {
        let e = DcapTcbStatusNotAccepted::abi_decode(data).ok()?;
        return Some(format!("DcapTcbStatusNotAccepted(actual={})", e.actual));
    }
    if selector == InvalidDcapQuoteBodyLength::SELECTOR {
        let e = InvalidDcapQuoteBodyLength::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidDcapQuoteBodyLength(actual={}, expected={})",
            e.actual, e.expected
        ));
    }
    if selector == DcapQuoteBodyHashMismatch::SELECTOR {
        let e = DcapQuoteBodyHashMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "DcapQuoteBodyHashMismatch(expected=0x{}, actual=0x{})",
            hex::encode(e.expected),
            hex::encode(e.actual)
        ));
    }
    if selector == DcapProofVerificationFailed::SELECTOR {
        let e = DcapProofVerificationFailed::abi_decode(data).ok()?;
        return Some(format!(
            "DcapProofVerificationFailed(output=0x{})",
            hex::encode(e.output)
        ));
    }
    if selector == InvalidDcapJournalOutputLength::SELECTOR {
        let e = InvalidDcapJournalOutputLength::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidDcapJournalOutputLength(actual={}, expected={})",
            e.actual, e.expected
        ));
    }
    if selector == InvalidTdxAttributes::SELECTOR {
        let e = InvalidTdxAttributes::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidTdxAttributes(actual=0x{})",
            hex::encode(e.actual)
        ));
    }
    if selector == TdxSeptVeDisableRequired::SELECTOR {
        return Some("TdxSeptVeDisableRequired()".to_string());
    }
    if selector == TdxMigrationServiceTdNotSupported::SELECTOR {
        return Some("TdxMigrationServiceTdNotSupported()".to_string());
    }
    if selector == SnpVerificationFailed::SELECTOR {
        let e = SnpVerificationFailed::abi_decode(data).ok()?;
        return Some(format!(
            "SnpVerificationFailed({})",
            verification_result_name(e.result)
        ));
    }
    if selector == SnpReportHashMismatch::SELECTOR {
        let e = SnpReportHashMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "SnpReportHashMismatch(expected=0x{}, actual=0x{})",
            hex::encode(e.expected),
            hex::encode(e.actual)
        ));
    }
    if selector == InvalidSnpReportLength::SELECTOR {
        let e = InvalidSnpReportLength::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidSnpReportLength(actual={}, expected={})",
            e.actual, e.expected
        ));
    }
    if selector == UnsupportedSnpReportVersion::SELECTOR {
        let e = UnsupportedSnpReportVersion::abi_decode(data).ok()?;
        return Some(format!("UnsupportedSnpReportVersion(actual={})", e.actual));
    }
    if selector == InvalidSnpPolicy::SELECTOR {
        let e = InvalidSnpPolicy::abi_decode(data).ok()?;
        return Some(format!("InvalidSnpPolicy(actual={})", e.actual));
    }
    if selector == UnsupportedSnpVmpl::SELECTOR {
        let e = UnsupportedSnpVmpl::abi_decode(data).ok()?;
        return Some(format!("UnsupportedSnpVmpl(actual={})", e.actual));
    }
    if selector == SnpMigrationAgentNotSupported::SELECTOR {
        return Some("SnpMigrationAgentNotSupported()".to_string());
    }
    if selector == InvalidSnpSignatureAlgorithm::SELECTOR {
        let e = InvalidSnpSignatureAlgorithm::abi_decode(data).ok()?;
        return Some(format!("InvalidSnpSignatureAlgorithm(actual={})", e.actual));
    }
    if selector == InvalidSnpKeySettings::SELECTOR {
        let e = InvalidSnpKeySettings::abi_decode(data).ok()?;
        return Some(format!("InvalidSnpKeySettings(actual={})", e.actual));
    }
    if selector == InvalidSnpReservedField::SELECTOR {
        let e = InvalidSnpReservedField::abi_decode(data).ok()?;
        return Some(format!("InvalidSnpReservedField(offset={})", e.offset));
    }
    if selector == InvalidSnpTcb::SELECTOR {
        let e = InvalidSnpTcb::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidSnpTcb(offset={}, actual={})",
            e.offset, e.actual
        ));
    }
    if selector == InvalidSnpPlatformInfo::SELECTOR {
        let e = InvalidSnpPlatformInfo::abi_decode(data).ok()?;
        return Some(format!("InvalidSnpPlatformInfo(actual={})", e.actual));
    }
    if selector == UnsupportedSnpCpuid::SELECTOR {
        let e = UnsupportedSnpCpuid::abi_decode(data).ok()?;
        return Some(format!("UnsupportedSnpCpuid(actual=0x{:06x})", e.actual));
    }
    if selector == InvalidSnpTcbOrder::SELECTOR {
        let e = InvalidSnpTcbOrder::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidSnpTcbOrder(lower=0x{}, upper=0x{})",
            hex::encode(e.lower),
            hex::encode(e.upper)
        ));
    }

    // ── TpmVerifier and PCR-registry checks ───────────────────────
    if selector == PcrValueNotFound::SELECTOR {
        let e = PcrValueNotFound::abi_decode(data).ok()?;
        return Some(format!(
            "PcrValueNotFound(algorithm={}, pcr={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex
        ));
    }
    if selector == InvalidPcrRule::SELECTOR {
        let e = InvalidPcrRule::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidPcrRule(algorithm={}, pcr={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex
        ));
    }
    if selector == InvalidPcrComparisonType::SELECTOR {
        let e = InvalidPcrComparisonType::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidPcrComparisonType(algorithm={}, pcr={}, encodedType={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.encodedType
        ));
    }
    if selector == UnsupportedPcrComparison::SELECTOR {
        let e = UnsupportedPcrComparison::abi_decode(data).ok()?;
        return Some(format!(
            "UnsupportedPcrComparison(algorithm={}, pcr={}, comparisonType={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            pcr_comparison_type_name(e.comparisonType)
        ));
    }
    if selector == NonCanonicalPcrComparison::SELECTOR {
        let e = NonCanonicalPcrComparison::abi_decode(data).ok()?;
        return Some(format!(
            "NonCanonicalPcrComparison(algorithm={}, pcr={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex
        ));
    }
    if selector == DynamicSha384PolicyRequiresZk::SELECTOR {
        let e = DynamicSha384PolicyRequiresZk::abi_decode(data).ok()?;
        return Some(format!(
            "DynamicSha384PolicyRequiresZk(pcr={}, comparisonType={})",
            e.pcrIndex,
            pcr_comparison_type_name(e.comparisonType)
        ));
    }
    if selector == PcrReplayMismatch256::SELECTOR {
        let e = PcrReplayMismatch256::abi_decode(data).ok()?;
        return Some(format!(
            "PcrReplayMismatch256(pcr={}, measured=0x{}, replayed=0x{})",
            e.pcrIndex,
            hex::encode(e.measured),
            hex::encode(e.replayed)
        ));
    }
    if selector == PcrStaticMismatch256::SELECTOR {
        let e = PcrStaticMismatch256::abi_decode(data).ok()?;
        return Some(format!(
            "PcrStaticMismatch256(pcr={}, measured=0x{}, expected=0x{})",
            e.pcrIndex,
            hex::encode(e.measured),
            hex::encode(e.expected)
        ));
    }
    if selector == PcrStaticMismatch384::SELECTOR {
        let e = PcrStaticMismatch384::abi_decode(data).ok()?;
        return Some(format!(
            "PcrStaticMismatch384(pcr={}, measured=0x{}, expected=0x{})",
            e.pcrIndex,
            pcr_bytes48_hex(&e.measured),
            pcr_bytes48_hex(&e.expected)
        ));
    }
    if selector == PcrEventLogEmpty::SELECTOR {
        let e = PcrEventLogEmpty::abi_decode(data).ok()?;
        return Some(format!(
            "PcrEventLogEmpty(algorithm={}, pcr={}, comparisonType={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            pcr_comparison_type_name(e.comparisonType)
        ));
    }
    if selector == PcrSubsetLandmarkMissing::SELECTOR {
        let e = PcrSubsetLandmarkMissing::abi_decode(data).ok()?;
        return Some(format!(
            "PcrSubsetLandmarkMissing(algorithm={}, pcr={}, landmarkIndex={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.landmarkIndex
        ));
    }
    if selector == PcrSubsequenceLandmarkMissing::SELECTOR {
        let e = PcrSubsequenceLandmarkMissing::abi_decode(data).ok()?;
        return Some(format!(
            "PcrSubsequenceLandmarkMissing(algorithm={}, pcr={}, matched={}, required={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.matched,
            e.required
        ));
    }
    if selector == PcrEventCountMismatch::SELECTOR {
        let e = PcrEventCountMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "PcrEventCountMismatch(algorithm={}, pcr={}, actual={}, expected={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.actual,
            e.expected
        ));
    }
    if selector == PcrCheckedEventsEmpty::SELECTOR {
        let e = PcrCheckedEventsEmpty::abi_decode(data).ok()?;
        return Some(format!(
            "PcrCheckedEventsEmpty(algorithm={}, pcr={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex
        ));
    }
    if selector == PcrCheckedEventIndexOutOfRange::SELECTOR {
        let e = PcrCheckedEventIndexOutOfRange::abi_decode(data).ok()?;
        return Some(format!(
            "PcrCheckedEventIndexOutOfRange(algorithm={}, pcr={}, eventIndex={}, eventCount={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.eventIndex,
            e.eventCount
        ));
    }
    if selector == PcrCheckedEventIndexesNotSorted::SELECTOR {
        let e = PcrCheckedEventIndexesNotSorted::abi_decode(data).ok()?;
        return Some(format!(
            "PcrCheckedEventIndexesNotSorted(algorithm={}, pcr={}, previous={}, current={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.previous,
            e.current
        ));
    }
    if selector == PcrAllowedValuesEmpty::SELECTOR {
        let e = PcrAllowedValuesEmpty::abi_decode(data).ok()?;
        return Some(format!(
            "PcrAllowedValuesEmpty(algorithm={}, pcr={}, eventIndex={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.eventIndex
        ));
    }
    if selector == PcrAllowedValuesNotSorted::SELECTOR {
        let e = PcrAllowedValuesNotSorted::abi_decode(data).ok()?;
        return Some(format!(
            "PcrAllowedValuesNotSorted(algorithm={}, pcr={}, eventIndex={}, position={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.eventIndex,
            e.position
        ));
    }
    if selector == PcrIndexedEventSetMismatch::SELECTOR {
        let e = PcrIndexedEventSetMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "PcrIndexedEventSetMismatch(algorithm={}, pcr={}, eventIndex={})",
            pcr_algorithm_name(e.algorithm),
            e.pcrIndex,
            e.eventIndex
        ));
    }
    if selector == EmptyPcrComparison::SELECTOR {
        let e = EmptyPcrComparison::abi_decode(data).ok()?;
        return Some(format!("EmptyPcrComparison(pcr={})", e.pcrIndex));
    }
    if selector == VariantOverridesInvariantPcr::SELECTOR {
        let e = VariantOverridesInvariantPcr::abi_decode(data).ok()?;
        return Some(format!(
            "VariantOverridesInvariantPcr(platformProfileId=0x{}, pcr={}) — a variant may only \
             pin PCR indices the profile leaves unpinned",
            hex::encode(e.platformProfileId),
            e.pcrIndex
        ));
    }
    if selector == AttributeNotFound::SELECTOR {
        let e = AttributeNotFound::abi_decode(data).ok()?;
        return Some(format!("AttributeNotFound(key=0x{})", hex::encode(e.key)));
    }
    if selector == AttributeValueNotAllowed::SELECTOR {
        let e = AttributeValueNotAllowed::abi_decode(data).ok()?;
        return Some(format!(
            "AttributeValueNotAllowed(key=0x{}, actualValue=0x{})",
            hex::encode(e.key),
            hex::encode(e.actualValue)
        ));
    }
    if selector == TeeVerificationFailed::SELECTOR {
        return Some("TeeVerificationFailed()".to_string());
    }
    if selector == AkCollateralVerificationFailed::SELECTOR {
        return Some("AkCollateralVerificationFailed()".to_string());
    }
    if selector == SessionNotFound::SELECTOR {
        return Some("SessionNotFound()".to_string());
    }
    if selector == SessionKeyPossessionFailed::SELECTOR {
        let error = SessionKeyPossessionFailed::abi_decode(data).ok()?;
        return Some(format!(
            "SessionKeyPossessionFailed(messageHash=0x{}, sessionKeyFingerprint=0x{}) — the session private key did not sign the TPM delegation message",
            hex::encode(error.messageHash),
            hex::encode(error.sessionKeyFingerprint)
        ));
    }
    if selector == SessionFingerprintInUse::SELECTOR {
        let error = SessionFingerprintInUse::abi_decode(data).ok()?;
        return Some(format!(
            "SessionFingerprintInUse(sessionKeyFingerprint=0x{}, activeSessionId=0x{}) — revoke or replace the active session before reusing this session key",
            hex::encode(error.sessionKeyFingerprint),
            hex::encode(error.activeSessionId)
        ));
    }
    if selector == UnsupportedAzureTeeType::SELECTOR {
        let e = UnsupportedAzureTeeType::abi_decode(data).ok()?;
        return Some(format!(
            "UnsupportedAzureTeeType(teeType={})",
            tee_type_name(e.teeType)
        ));
    }
    if selector == AzureMaaTeeTypeMismatch::SELECTOR {
        let e = AzureMaaTeeTypeMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "AzureMaaTeeTypeMismatch(teeReportType={}, maaTeeType={})",
            tee_type_name(e.teeReportType),
            tee_type_name(e.maaTeeType)
        ));
    }
    if selector == AzureTeeReportDataMismatch::SELECTOR {
        let e = AzureTeeReportDataMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "AzureTeeReportDataMismatch(actualBindingHash=0x{}, expectedBindingHash=0x{}, actualPadding=0x{})",
            hex::encode(e.actualBindingHash),
            hex::encode(e.expectedBindingHash),
            hex::encode(e.actualPadding)
        ));
    }
    if selector == AzureTeeReportDataTooShort::SELECTOR {
        let e = AzureTeeReportDataTooShort::abi_decode(data).ok()?;
        return Some(format!(
            "AzureTeeReportDataTooShort(actualLength={}, minRequired={})",
            e.actualLength, e.minRequired
        ));
    }
    if selector == TeeAttributeBaseImageMismatch::SELECTOR {
        let e = TeeAttributeBaseImageMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "TeeAttributeBaseImageMismatch(key=0x{}, declaredValue=0x{}, verifiedValue=0x{})",
            hex::encode(e.key),
            hex::encode(e.declaredValue),
            hex::encode(e.verifiedValue)
        ));
    }
    if selector == EmptyTeeAttributeRequirement::SELECTOR {
        let e = EmptyTeeAttributeRequirement::abi_decode(data).ok()?;
        return Some(format!(
            "EmptyTeeAttributeRequirement(key=0x{})",
            hex::encode(e.key)
        ));
    }
    if selector == InvalidPackedTeeAttributeRequirementLength::SELECTOR {
        let e = InvalidPackedTeeAttributeRequirementLength::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidPackedTeeAttributeRequirementLength(key=0x{}, actualLength={})",
            hex::encode(e.key),
            e.actualLength
        ));
    }
    if selector == TeeAttributeValueNotAllowed::SELECTOR {
        let e = TeeAttributeValueNotAllowed::abi_decode(data).ok()?;
        return Some(format!(
            "TeeAttributeValueNotAllowed(key=0x{}, actualValue=0x{})",
            hex::encode(e.key),
            hex::encode(e.actualValue)
        ));
    }
    if selector == TeeAttributePolicyConflict::SELECTOR {
        let e = TeeAttributePolicyConflict::abi_decode(data).ok()?;
        return Some(format!(
            "TeeAttributePolicyConflict(key=0x{}, baseValue=0x{}, workloadValue=0x{})",
            hex::encode(e.key),
            hex::encode(e.baseValue),
            hex::encode(e.workloadValue)
        ));
    }
    if selector == PolicyNotFound::SELECTOR {
        let e = PolicyNotFound::abi_decode(data).ok()?;
        return Some(format!("PolicyNotFound(cpuid=0x{:06x})", e.cpuid));
    }
    if selector == PolicyNotActive::SELECTOR {
        let e = PolicyNotActive::abi_decode(data).ok()?;
        return Some(format!("PolicyNotActive(cpuid=0x{:06x})", e.cpuid));
    }
    if selector == PolicyRevisionMismatch::SELECTOR {
        let error = PolicyRevisionMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "PolicyRevisionMismatch(cpuid=0x{:06x}, actual={}, expected={}) — reload the current AMD SEV-SNP policy before preparing the update",
            error.cpuid, error.actual, error.expected
        ));
    }
    if selector == SnpMitigationPolicyRequiresReportVersion::SELECTOR {
        let error = SnpMitigationPolicyRequiresReportVersion::abi_decode(data).ok()?;
        return Some(format!(
            "SnpMitigationPolicyRequiresReportVersion(actualVersion={}, requiredVersion={}) — a nonzero AMD SEV-SNP mitigation-vector mask requires a version-5 report",
            error.actualVersion, error.requiredVersion
        ));
    }
    if selector == SnpLaunchMitigationVectorMissing::SELECTOR {
        let error = SnpLaunchMitigationVectorMissing::abi_decode(data).ok()?;
        return Some(format!(
            "SnpLaunchMitigationVectorMissing(requiredMask=0x{:016x}, actual=0x{:016x}) — LAUNCH_MIT_VECTOR is missing a required bit",
            error.requiredMask, error.actual
        ));
    }
    if selector == SnpCurrentMitigationVectorMissing::SELECTOR {
        let error = SnpCurrentMitigationVectorMissing::abi_decode(data).ok()?;
        return Some(format!(
            "SnpCurrentMitigationVectorMissing(requiredMask=0x{:016x}, actual=0x{:016x}) — CURRENT_MIT_VECTOR is missing a required bit",
            error.requiredMask, error.actual
        ));
    }
    if selector == MaaJwtClaimMissing::SELECTOR {
        let e = MaaJwtClaimMissing::abi_decode(data).ok()?;
        return Some(format!(
            "MaaJwtClaimMissing(fieldNameHash=0x{})",
            hex::encode(e.fieldNameHash)
        ));
    }
    if selector == MaaJwtNumericClaimMalformed::SELECTOR {
        let e = MaaJwtNumericClaimMalformed::abi_decode(data).ok()?;
        return Some(format!(
            "MaaJwtNumericClaimMalformed(fieldNameHash=0x{})",
            hex::encode(e.fieldNameHash)
        ));
    }
    if selector == MaaJwtValidityWindowInvalid::SELECTOR {
        let e = MaaJwtValidityWindowInvalid::abi_decode(data).ok()?;
        return Some(format!(
            "MaaJwtValidityWindowInvalid(iat={}, nbf={}, exp={})",
            e.issuedAt, e.notBefore, e.expiresAt
        ));
    }
    if selector == MaaJwtNotYetValid::SELECTOR {
        let e = MaaJwtNotYetValid::abi_decode(data).ok()?;
        return Some(format!(
            "MaaJwtNotYetValid(nbf={}, verificationTime={})",
            e.notBefore, e.verificationTime
        ));
    }
    if selector == MaaJwtExpired::SELECTOR {
        let e = MaaJwtExpired::abi_decode(data).ok()?;
        return Some(format!(
            "MaaJwtExpired(exp={}, verificationTime={})",
            e.expiresAt, e.verificationTime
        ));
    }
    if selector == MaaJwtIssuedInFuture::SELECTOR {
        let e = MaaJwtIssuedInFuture::abi_decode(data).ok()?;
        return Some(format!(
            "MaaJwtIssuedInFuture(iat={}, verificationTime={})",
            e.issuedAt, e.verificationTime
        ));
    }
    if selector == QualifyingDataMismatch::SELECTOR {
        let e = QualifyingDataMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "QualifyingDataMismatch(measured=0x{}, expected=0x{})",
            hex::encode(e.measured),
            hex::encode(e.expected)
        ));
    }
    if selector == TpmQuoteExtraDataMismatch::SELECTOR {
        let e = TpmQuoteExtraDataMismatch::abi_decode(data).ok()?;
        return Some(format!(
            "TpmQuoteExtraDataMismatch(measured=0x{}, expected=0x{})",
            hex::encode(e.measured),
            hex::encode(e.expected)
        ));
    }

    // ── Registry lookups + authorization ──────────────────────────
    if selector == Unauthorized::SELECTOR {
        let e = Unauthorized::abi_decode(data).ok()?;
        return Some(format!(
            "Unauthorized(actual=0x{}, expected=0x{}) — caller fingerprint does \
             not match the registered owner",
            hex::encode(e.actualOwner),
            hex::encode(e.expectedOwner)
        ));
    }
    if selector == BaseImageNotFound::SELECTOR {
        let e = BaseImageNotFound::abi_decode(data).ok()?;
        return Some(format!(
            "BaseImageNotFound(baseImageId=0x{})",
            hex::encode(e.baseImageId)
        ));
    }
    if selector == BaseImageNotActive::SELECTOR {
        let e = BaseImageNotActive::abi_decode(data).ok()?;
        return Some(format!(
            "BaseImageNotActive(baseImageId=0x{})",
            hex::encode(e.baseImageId)
        ));
    }
    if selector == BaseImageNotAllowed::SELECTOR {
        let e = BaseImageNotAllowed::abi_decode(data).ok()?;
        return Some(format!(
            "BaseImageNotAllowed(baseImageId=0x{})",
            hex::encode(e.baseImageId)
        ));
    }
    if selector == PlatformProfileNotFound::SELECTOR {
        let e = PlatformProfileNotFound::abi_decode(data).ok()?;
        return Some(format!(
            "PlatformProfileNotFound(platformProfileId=0x{})",
            hex::encode(e.platformProfileId)
        ));
    }
    if selector == WorkloadNotFound::SELECTOR {
        let e = WorkloadNotFound::abi_decode(data).ok()?;
        return Some(format!(
            "WorkloadNotFound(workloadId=0x{})",
            hex::encode(e.workloadId)
        ));
    }
    if selector == WorkloadNotActive::SELECTOR {
        let e = WorkloadNotActive::abi_decode(data).ok()?;
        return Some(format!(
            "WorkloadNotActive(workloadId=0x{})",
            hex::encode(e.workloadId)
        ));
    }
    if selector == InvalidTeeAttributeValue::SELECTOR {
        let e = InvalidTeeAttributeValue::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidTeeAttributeValue(key=0x{}, actualValue=0x{})",
            hex::encode(e.key),
            hex::encode(e.actualValue)
        ));
    }
    if selector == InvalidTeeAttributeRequirementLength::SELECTOR {
        let e = InvalidTeeAttributeRequirementLength::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidTeeAttributeRequirementLength(key=0x{}, actualLength={})",
            hex::encode(e.key),
            e.actualLength
        ));
    }
    if selector == InvalidTeeAttributeRequirementValue::SELECTOR {
        let e = InvalidTeeAttributeRequirementValue::abi_decode(data).ok()?;
        return Some(format!(
            "InvalidTeeAttributeRequirementValue(key=0x{}, actualValue=0x{})",
            hex::encode(e.key),
            hex::encode(e.actualValue)
        ));
    }

    // ── SP1 Groth16 zkVerifier ────────────────────────────────────
    if selector == ProofInvalid::SELECTOR {
        return Some(
            "ProofInvalid() — SP1 zkVerifier rejected the proof; likely a \
             program-id (vkey) mismatch against the verifier's pinned value (R7)"
                .to_string(),
        );
    }
    None
}

pub fn is_tpm_quote_extra_data_mismatch_revert(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == TpmQuoteExtraDataMismatch::SELECTOR
}

/// A nonce-binding mismatch needs a live nonce check before rebuilding evidence.
pub fn is_owner_nonce_binding_mismatch_revert(data: &[u8]) -> bool {
    TpmQuoteExtraDataMismatch::abi_decode(data).is_ok()
        || QualifyingDataMismatch::abi_decode(data).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};

    #[test]
    fn decodes_snp_report_hash_mismatch() {
        let expected = B256::repeat_byte(0xab);
        let actual = B256::repeat_byte(0xcd);
        let data = SnpReportHashMismatch { expected, actual }.abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert!(s.contains("SnpReportHashMismatch"));
        assert!(s.contains(&hex::encode(expected)));
        assert!(s.contains(&hex::encode(actual)));
    }

    #[test]
    fn decodes_intel_tdx_quote_body_hash_mismatch() {
        let expected = B256::repeat_byte(0x12);
        let actual = B256::repeat_byte(0x34);
        let data = DcapQuoteBodyHashMismatch { expected, actual }.abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert!(decoded.contains("DcapQuoteBodyHashMismatch"));
        assert!(decoded.contains(&hex::encode(expected)));
        assert!(decoded.contains(&hex::encode(actual)));
    }

    #[test]
    fn decodes_intel_tdx_exact_quote_errors() {
        assert_eq!(
            decode_revert(&UnsupportedDcapQuoteVersion { actual: 3 }.abi_encode()).as_deref(),
            Some("UnsupportedDcapQuoteVersion(actual=3)")
        );
        assert_eq!(
            decode_revert(&InvalidDcapTeeType { actual: 0 }.abi_encode()).as_deref(),
            Some("InvalidDcapTeeType(actual=0)")
        );
        assert_eq!(
            decode_revert(
                &InvalidDcapQuoteLength {
                    actual: U256::from(8_000),
                    expected: U256::from(4_935),
                }
                .abi_encode()
            )
            .as_deref(),
            Some("InvalidDcapQuoteLength(actual=8000, expected=4935)")
        );
    }

    #[test]
    fn decodes_snp_verification_failed_named_result() {
        // result = 2 → InvalidTimestamp
        let data = SnpVerificationFailed { result: 2 }.abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert_eq!(s, "SnpVerificationFailed(InvalidTimestamp)");
    }

    #[test]
    fn decodes_snp_report_too_short() {
        let data = SnpReportTooShort {
            length: U256::from(100u64),
            minRequired: U256::from(1184u64),
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert_eq!(s, "SnpReportTooShort(length=100, minRequired=1184)");
    }

    #[test]
    fn decodes_verified_tee_attribute_errors() {
        let data = AkCollateralVerificationFailed {}.abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some("AkCollateralVerificationFailed()")
        );

        let key = B256::repeat_byte(0x11);
        let declared = B256::ZERO;
        let verified = B256::with_last_byte(1);
        let data = TeeAttributeBaseImageMismatch {
            key,
            declaredValue: declared,
            verifiedValue: verified,
        }
        .abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert!(decoded.starts_with("TeeAttributeBaseImageMismatch("));
        assert!(decoded.contains(&hex::encode(key)));

        let data = SnpMigrationAgentNotSupported {}.abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some("SnpMigrationAgentNotSupported()")
        );

        let data = TeeAttributePolicyConflict {
            key,
            baseValue: B256::ZERO,
            workloadValue: B256::with_last_byte(1),
        }
        .abi_encode();
        assert!(decode_revert(&data)
            .expect("decoded")
            .starts_with("TeeAttributePolicyConflict("));
    }

    #[test]
    fn decodes_maa_jwt_time_errors() {
        let field_name_hash = B256::repeat_byte(0x11);
        let data = MaaJwtClaimMissing {
            fieldNameHash: field_name_hash,
        }
        .abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some(
                "MaaJwtClaimMissing(fieldNameHash=0x1111111111111111111111111111111111111111111111111111111111111111)"
            )
        );

        let data = MaaJwtExpired {
            expiresAt: 200,
            verificationTime: U256::from(200),
        }
        .abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some("MaaJwtExpired(exp=200, verificationTime=200)")
        );
        assert_eq!(
            decode_maa_jwt_time_revert(&data),
            Some(MaaJwtTimeRevert::Expired {
                expires_at: 200,
                verification_time: U256::from(200),
            })
        );

        let data = MaaJwtNotYetValid {
            notBefore: 105,
            verificationTime: U256::from(100),
        }
        .abi_encode();
        assert_eq!(
            decode_maa_jwt_time_revert(&data),
            Some(MaaJwtTimeRevert::NotYetValid {
                not_before: 105,
                verification_time: U256::from(100),
            })
        );

        let data = MaaJwtIssuedInFuture {
            issuedAt: 106,
            verificationTime: U256::from(100),
        }
        .abi_encode();
        assert_eq!(
            decode_maa_jwt_time_revert(&data),
            Some(MaaJwtTimeRevert::IssuedInFuture {
                issued_at: 106,
                verification_time: U256::from(100),
            })
        );

        let data = MaaJwtValidityWindowInvalid {
            issuedAt: 100,
            notBefore: 200,
            expiresAt: 200,
        }
        .abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some("MaaJwtValidityWindowInvalid(iat=100, nbf=200, exp=200)")
        );
    }

    #[test]
    fn decodes_amd_snp_security_policy_errors() {
        let data = UnsupportedSnpCpuid {
            actual: 0x191101u32.try_into().unwrap(),
        }
        .abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some("UnsupportedSnpCpuid(actual=0x191101)")
        );

        let data = PolicyNotActive {
            cpuid: 0x190100u32.try_into().unwrap(),
        }
        .abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some("PolicyNotActive(cpuid=0x190100)")
        );

        let data = InvalidSnpTcb {
            offset: U256::from(0x38),
            actual: 0x0000_0001_0000_0000,
        }
        .abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert!(decoded.starts_with("InvalidSnpTcb("), "{decoded}");

        let data = SnpMitigationPolicyRequiresReportVersion {
            actualVersion: 3,
            requiredVersion: 5,
        }
        .abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert!(decoded.contains("actualVersion=3"), "{decoded}");
        assert!(decoded.contains("version-5 report"), "{decoded}");

        let data = SnpLaunchMitigationVectorMissing {
            requiredMask: 0x12,
            actual: 0x10,
        }
        .abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert!(
            decoded.contains("requiredMask=0x0000000000000012"),
            "{decoded}"
        );
        assert!(decoded.contains("LAUNCH_MIT_VECTOR"), "{decoded}");

        let data = SnpCurrentMitigationVectorMissing {
            requiredMask: 0x24,
            actual: 0x20,
        }
        .abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert!(
            decoded.contains("requiredMask=0x0000000000000024"),
            "{decoded}"
        );
        assert!(decoded.contains("CURRENT_MIT_VECTOR"), "{decoded}");
    }

    #[test]
    fn decodes_azure_tee_report_data_mismatch() {
        let actual_binding_hash = B256::repeat_byte(0x11);
        let expected_binding_hash = B256::repeat_byte(0x22);
        let actual_padding = B256::with_last_byte(1);
        let data = AzureTeeReportDataMismatch {
            actualBindingHash: actual_binding_hash,
            expectedBindingHash: expected_binding_hash,
            actualPadding: actual_padding,
        }
        .abi_encode();

        let decoded = decode_revert(&data).expect("decoded");
        assert!(decoded.starts_with("AzureTeeReportDataMismatch("));
        assert!(decoded.contains(&hex::encode(actual_binding_hash)));
        assert!(decoded.contains(&hex::encode(expected_binding_hash)));
        assert!(decoded.contains(&hex::encode(actual_padding)));
    }

    #[test]
    fn decodes_standard_error_string() {
        let data = Error {
            message: "boom".to_string(),
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert!(s.contains("boom"));
    }

    #[test]
    fn decodes_proof_invalid_no_args() {
        let data = ProofInvalid {}.abi_encode();
        // Pin the known SP1 Groth16 selector while we're here.
        assert_eq!(data, [0x7f, 0xcd, 0xd1, 0xf4]);
        let s = decode_revert(&data).expect("decoded");
        assert!(s.starts_with("ProofInvalid()"));
    }

    #[test]
    fn decodes_unsupported_backend_type_named_enums() {
        // The pair we hit live: (AmdSevSnp, Solidity) — the SNP report routed to
        // the Solidity backend before the ZK backend was wired.
        let data = UnsupportedBackendType {
            teeType: 1,
            backend: 0,
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert!(s.contains("teeType=AmdSevSnp"), "{s}");
        assert!(s.contains("backend=Solidity"), "{s}");
        assert!(s.contains("ZkSuccinct"), "{s}");
        assert!(s.contains("ZkRiscZero"), "{s}");
    }

    #[test]
    fn decodes_pcr_static_mismatch() {
        let measured = B256::repeat_byte(0x11);
        let expected = B256::repeat_byte(0x22);
        let data = PcrStaticMismatch256 {
            pcrIndex: 4,
            measured,
            expected,
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert!(s.starts_with("PcrStaticMismatch256(pcr=4,"), "{s}");
        assert!(s.contains(&hex::encode(measured)));
        assert!(s.contains(&hex::encode(expected)));
    }

    #[test]
    fn decodes_noncanonical_pcr_comparison() {
        let data = NonCanonicalPcrComparison {
            algorithm: 0x000b,
            pcrIndex: 4,
        }
        .abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert_eq!(
            decoded,
            "NonCanonicalPcrComparison(algorithm=SHA-256, pcr=4)"
        );
    }

    #[test]
    fn decodes_azure_maa_tee_type_mismatch() {
        let data = AzureMaaTeeTypeMismatch {
            teeReportType: 0,
            maaTeeType: 1,
        }
        .abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some("AzureMaaTeeTypeMismatch(teeReportType=IntelTDX, maaTeeType=AmdSevSnp)")
        );
    }

    #[test]
    fn decodes_session_not_found() {
        let data = SessionNotFound {}.abi_encode();
        assert_eq!(decode_revert(&data).as_deref(), Some("SessionNotFound()"));
    }

    #[test]
    fn decodes_session_key_possession_failed() {
        let message_hash = B256::repeat_byte(0x11);
        let fingerprint = B256::repeat_byte(0x22);
        let data = SessionKeyPossessionFailed {
            messageHash: message_hash,
            sessionKeyFingerprint: fingerprint,
        }
        .abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert!(decoded.contains(&hex::encode(message_hash)));
        assert!(decoded.contains(&hex::encode(fingerprint)));
        assert!(decoded.contains("session private key"));
    }

    #[test]
    fn decodes_session_fingerprint_in_use() {
        let fingerprint = B256::repeat_byte(0x33);
        let session_id = B256::repeat_byte(0x44);
        let data = SessionFingerprintInUse {
            sessionKeyFingerprint: fingerprint,
            activeSessionId: session_id,
        }
        .abi_encode();
        let decoded = decode_revert(&data).expect("decoded");
        assert!(decoded.contains(&hex::encode(fingerprint)));
        assert!(decoded.contains(&hex::encode(session_id)));
        assert!(decoded.contains("revoke or replace"));
    }

    #[test]
    fn decodes_policy_revision_mismatch() {
        let data = PolicyRevisionMismatch {
            cpuid: 0x191101u32.try_into().unwrap(),
            actual: 4,
            expected: 3,
        }
        .abi_encode();
        assert_eq!(
            decode_revert(&data).as_deref(),
            Some(
                "PolicyRevisionMismatch(cpuid=0x191101, actual=4, expected=3) — reload the current AMD SEV-SNP policy before preparing the update"
            )
        );
    }

    #[test]
    fn decodes_variant_overrides_invariant_pcr() {
        let profile_id = B256::repeat_byte(0x5a);
        let data = VariantOverridesInvariantPcr {
            platformProfileId: profile_id,
            pcrIndex: 4,
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert!(s.starts_with("VariantOverridesInvariantPcr("), "{s}");
        assert!(s.contains(&hex::encode(profile_id)), "{s}");
        assert!(s.contains("pcr=4"), "{s}");
    }

    #[test]
    fn decodes_pcr_subsequence_landmark_missing_neutral() {
        let data = PcrSubsequenceLandmarkMissing {
            algorithm: 0x000b,
            pcrIndex: 9,
            matched: U256::from(3u64),
            required: U256::from(5u64),
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert_eq!(
            s,
            "PcrSubsequenceLandmarkMissing(algorithm=SHA-256, pcr=9, matched=3, required=5)"
        );
    }

    #[test]
    fn decodes_pcr_event_log_empty_named_comparison_type() {
        let data = PcrEventLogEmpty {
            algorithm: 0x000c,
            pcrIndex: 11,
            comparisonType: 3,
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert_eq!(
            s,
            "PcrEventLogEmpty(algorithm=SHA-384, pcr=11, comparisonType=DYNAMIC_INDEXED_EVENT_SETS)"
        );
    }

    #[test]
    fn decodes_pcr_subset_missing_landmark() {
        let data = PcrSubsetLandmarkMissing {
            algorithm: 0x000b,
            pcrIndex: 10,
            landmarkIndex: U256::from(1u64),
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert_eq!(
            s,
            "PcrSubsetLandmarkMissing(algorithm=SHA-256, pcr=10, landmarkIndex=1)"
        );
    }

    #[test]
    fn decodes_tpm_quote_extra_data_mismatch() {
        let measured = B256::repeat_byte(0x11);
        let expected = B256::repeat_byte(0x22);
        let data = TpmQuoteExtraDataMismatch { measured, expected }.abi_encode();
        assert!(is_tpm_quote_extra_data_mismatch_revert(&data));
        assert!(is_owner_nonce_binding_mismatch_revert(&data));
        let s = decode_revert(&data).expect("decoded");
        assert!(s.starts_with("TpmQuoteExtraDataMismatch("), "{s}");
        assert!(s.contains(&hex::encode(measured)));
        assert!(s.contains(&hex::encode(expected)));
    }

    #[test]
    fn decodes_qualifying_data_mismatch() {
        let measured = B256::repeat_byte(0x11);
        let expected = B256::repeat_byte(0x22);
        let data = QualifyingDataMismatch { measured, expected }.abi_encode();
        assert_eq!(&data[..4], &[0xff, 0x4f, 0x34, 0xc3]);
        assert!(is_owner_nonce_binding_mismatch_revert(&data));
        assert!(!is_owner_nonce_binding_mismatch_revert(&data[..4]));
        assert!(!is_owner_nonce_binding_mismatch_revert(
            &ProofInvalid {}.abi_encode()
        ));
        assert_eq!(
            decode_revert(&data).unwrap(),
            format!(
                "QualifyingDataMismatch(measured=0x{}, expected=0x{})",
                hex::encode(measured),
                hex::encode(expected)
            )
        );
    }

    #[test]
    fn decodes_unauthorized() {
        let actual = B256::repeat_byte(0xaa);
        let expected = B256::repeat_byte(0xbb);
        let data = Unauthorized {
            actualOwner: actual,
            expectedOwner: expected,
        }
        .abi_encode();
        let s = decode_revert(&data).expect("decoded");
        assert!(s.contains("Unauthorized(actual="), "{s}");
        assert!(s.contains(&hex::encode(actual)));
        assert!(s.contains(&hex::encode(expected)));
    }

    #[test]
    fn decodes_registry_lookup_ids() {
        let id = B256::repeat_byte(0x5a);
        for s in [
            decode_revert(
                &PlatformProfileNotFound {
                    platformProfileId: id,
                }
                .abi_encode(),
            ),
            decode_revert(&BaseImageNotFound { baseImageId: id }.abi_encode()),
            decode_revert(&WorkloadNotFound { workloadId: id }.abi_encode()),
        ] {
            let s = s.expect("decoded");
            assert!(s.contains(&hex::encode(id)), "{s}");
        }
    }

    /// Pin every selector against the live on-chain signatures
    /// (`cast sig`), so a signature drift fails here instead of silently
    /// mis-decoding a revert in production.
    #[test]
    fn selectors_match_onchain() {
        assert_eq!(UnsupportedTeeType::SELECTOR, [0xdf, 0x84, 0x03, 0x5d]);
        assert_eq!(UnsupportedBackendType::SELECTOR, [0x19, 0x4d, 0x13, 0x7a]);
        assert_eq!(SnpReportTooShort::SELECTOR, [0x6d, 0xd6, 0x3d, 0x17]);
        assert_eq!(TeeReportTooShort::SELECTOR, [0x99, 0x47, 0x58, 0xab]);
        assert_eq!(
            UnsupportedDcapQuoteVersion::SELECTOR,
            [0xf4, 0x0d, 0xa8, 0xd3]
        );
        assert_eq!(InvalidDcapTeeType::SELECTOR, [0xd8, 0xa5, 0xf4, 0x58]);
        assert_eq!(InvalidDcapQuoteLength::SELECTOR, [0x8f, 0x15, 0xbd, 0x68]);
        assert_eq!(UnsupportedDcapBodyType::SELECTOR, [0xcb, 0x2a, 0xe7, 0x2c]);
        assert_eq!(DcapReportDataOob::SELECTOR, [0xe8, 0x2a, 0x73, 0xe1]);
        assert_eq!(DcapVerificationFailed::SELECTOR, [0x2d, 0xaf, 0xc5, 0x71]);
        assert_eq!(DcapTcbStatusNotAccepted::SELECTOR, [0xe9, 0x2f, 0x92, 0x80]);
        assert_eq!(
            InvalidDcapQuoteBodyLength::SELECTOR,
            [0xd0, 0x1f, 0x3f, 0xd9]
        );
        assert_eq!(
            DcapQuoteBodyHashMismatch::SELECTOR,
            [0xca, 0x9a, 0x45, 0xf6]
        );
        assert_eq!(
            DcapProofVerificationFailed::SELECTOR,
            [0x22, 0xa9, 0x94, 0x63]
        );
        assert_eq!(
            InvalidDcapJournalOutputLength::SELECTOR,
            [0x60, 0xad, 0xc1, 0xf8]
        );
        assert_eq!(InvalidTdxAttributes::SELECTOR, [0xe2, 0xe6, 0x6a, 0xe9]);
        assert_eq!(TdxSeptVeDisableRequired::SELECTOR, [0x36, 0xc6, 0x38, 0x62]);
        assert_eq!(
            TdxMigrationServiceTdNotSupported::SELECTOR,
            [0x36, 0x1a, 0xce, 0xee]
        );
        assert_eq!(InvalidSnpReportLength::SELECTOR, [0x68, 0x24, 0x34, 0x7a]);
        assert_eq!(
            UnsupportedSnpReportVersion::SELECTOR,
            [0x3e, 0x0b, 0x86, 0x93]
        );
        assert_eq!(InvalidSnpPolicy::SELECTOR, [0xcc, 0xb3, 0xf9, 0x69]);
        assert_eq!(UnsupportedSnpVmpl::SELECTOR, [0x15, 0x99, 0x9b, 0x2a]);
        assert_eq!(
            SnpMigrationAgentNotSupported::SELECTOR,
            [0x29, 0x02, 0x3f, 0xec]
        );
        assert_eq!(
            InvalidSnpSignatureAlgorithm::SELECTOR,
            [0xaf, 0xc7, 0x71, 0x67]
        );
        assert_eq!(InvalidSnpKeySettings::SELECTOR, [0x7c, 0x1c, 0xcb, 0x77]);
        assert_eq!(InvalidSnpReservedField::SELECTOR, [0xdd, 0x8f, 0x72, 0x66]);
        assert_eq!(InvalidSnpTcb::SELECTOR, [0xfb, 0x91, 0xf5, 0xb7]);
        assert_eq!(InvalidSnpPlatformInfo::SELECTOR, [0x1a, 0xf7, 0xea, 0x80]);
        assert_eq!(UnsupportedSnpCpuid::SELECTOR, [0xfa, 0x0c, 0x56, 0x2c]);
        assert_eq!(InvalidSnpTcbOrder::SELECTOR, [0x22, 0x06, 0x5b, 0x82]);
        assert_eq!(PcrStaticMismatch256::SELECTOR, [0x6f, 0xac, 0x2d, 0xf7]);
        assert_eq!(
            NonCanonicalPcrComparison::SELECTOR,
            [0x8a, 0x13, 0xd5, 0x09]
        );
        assert_eq!(PcrEventLogEmpty::SELECTOR, [0x5d, 0x6e, 0xdb, 0xd1]);
        assert_eq!(PcrSubsetLandmarkMissing::SELECTOR, [0x16, 0xb0, 0x48, 0x1c]);
        assert_eq!(
            PcrSubsequenceLandmarkMissing::SELECTOR,
            [0x52, 0x9a, 0x6d, 0xd4]
        );
        assert_eq!(
            PcrIndexedEventSetMismatch::SELECTOR,
            [0x88, 0x2e, 0xd1, 0xa1]
        );
        assert_eq!(EmptyPcrComparison::SELECTOR, [0x61, 0x9f, 0xe4, 0xfe]);
        assert_eq!(
            VariantOverridesInvariantPcr::SELECTOR,
            [0x95, 0x85, 0x91, 0x54]
        );
        assert_eq!(AttributeNotFound::SELECTOR, [0x15, 0x77, 0x64, 0xb8]);
        assert_eq!(AttributeValueNotAllowed::SELECTOR, [0x76, 0x5b, 0x91, 0xbc]);
        assert_eq!(TeeVerificationFailed::SELECTOR, [0x6f, 0xb4, 0xbe, 0xc8]);
        assert_eq!(
            AkCollateralVerificationFailed::SELECTOR,
            [0x48, 0xdc, 0xbb, 0xde]
        );
        assert_eq!(SessionNotFound::SELECTOR, [0x96, 0xc9, 0x5f, 0x81]);
        assert_eq!(
            SessionKeyPossessionFailed::SELECTOR,
            [0x72, 0xa3, 0xdf, 0x6b]
        );
        assert_eq!(SessionFingerprintInUse::SELECTOR, [0x00, 0x81, 0x58, 0x1c]);
        assert_eq!(UnsupportedAzureTeeType::SELECTOR, [0xf0, 0x82, 0x52, 0x58]);
        assert_eq!(AzureMaaTeeTypeMismatch::SELECTOR, [0xab, 0xe2, 0xd6, 0x04]);
        assert_eq!(
            AzureTeeReportDataMismatch::SELECTOR,
            [0xa2, 0x81, 0x0f, 0x47]
        );
        assert_eq!(
            AzureTeeReportDataTooShort::SELECTOR,
            [0x18, 0x15, 0xf5, 0x10]
        );
        assert_eq!(
            TeeAttributeBaseImageMismatch::SELECTOR,
            [0x3f, 0xf5, 0x71, 0x10]
        );
        assert_eq!(
            EmptyTeeAttributeRequirement::SELECTOR,
            [0xc5, 0xb9, 0x36, 0x76]
        );
        assert_eq!(
            InvalidPackedTeeAttributeRequirementLength::SELECTOR,
            [0x30, 0x2e, 0xb6, 0x0e]
        );
        assert_eq!(
            TeeAttributeValueNotAllowed::SELECTOR,
            [0x48, 0x4c, 0xbd, 0xf6]
        );
        assert_eq!(
            TeeAttributePolicyConflict::SELECTOR,
            [0xcf, 0x6f, 0x96, 0xce]
        );
        assert_eq!(PolicyNotFound::SELECTOR, [0xb9, 0x10, 0x86, 0xda]);
        assert_eq!(PolicyNotActive::SELECTOR, [0x9d, 0x02, 0xde, 0x56]);
        assert_eq!(PolicyRevisionMismatch::SELECTOR, [0xa6, 0x8c, 0x39, 0x9a]);
        assert_eq!(
            SnpMitigationPolicyRequiresReportVersion::SELECTOR,
            [0xac, 0x85, 0xa3, 0xf3]
        );
        assert_eq!(
            SnpLaunchMitigationVectorMissing::SELECTOR,
            [0x83, 0x13, 0xbd, 0x69]
        );
        assert_eq!(
            SnpCurrentMitigationVectorMissing::SELECTOR,
            [0xc1, 0x5c, 0x21, 0xf7]
        );
        assert_eq!(MaaJwtClaimMissing::SELECTOR, [0xd5, 0x8d, 0x7d, 0xb1]);
        assert_eq!(
            MaaJwtNumericClaimMalformed::SELECTOR,
            [0x42, 0x4a, 0xde, 0xe5]
        );
        assert_eq!(
            MaaJwtValidityWindowInvalid::SELECTOR,
            [0xf1, 0x0d, 0x08, 0x2c]
        );
        assert_eq!(MaaJwtNotYetValid::SELECTOR, [0xaf, 0x70, 0x37, 0xba]);
        assert_eq!(MaaJwtExpired::SELECTOR, [0xc5, 0xe5, 0x00, 0xc0]);
        assert_eq!(MaaJwtIssuedInFuture::SELECTOR, [0x17, 0xda, 0x65, 0x59]);
        assert_eq!(InvalidTeeAttributeValue::SELECTOR, [0x8c, 0x18, 0x59, 0x72]);
        assert_eq!(
            InvalidTeeAttributeRequirementLength::SELECTOR,
            [0x5f, 0xc2, 0xaf, 0x33]
        );
        assert_eq!(
            InvalidTeeAttributeRequirementValue::SELECTOR,
            [0xf7, 0x9f, 0x1a, 0x33]
        );
        assert_eq!(
            TpmQuoteExtraDataMismatch::SELECTOR,
            [0xb3, 0xb0, 0xe3, 0xf1]
        );
        assert_eq!(Unauthorized::SELECTOR, [0xea, 0x65, 0x8d, 0xc0]);
        assert_eq!(BaseImageNotFound::SELECTOR, [0xa5, 0x86, 0x24, 0x43]);
        assert_eq!(BaseImageNotActive::SELECTOR, [0x1c, 0x2e, 0xf4, 0x98]);
        assert_eq!(BaseImageNotAllowed::SELECTOR, [0x07, 0x9f, 0xe0, 0x44]);
        assert_eq!(PlatformProfileNotFound::SELECTOR, [0xbd, 0xa3, 0x68, 0xc0]);
        assert_eq!(WorkloadNotFound::SELECTOR, [0x84, 0xe8, 0x5c, 0x83]);
        assert_eq!(WorkloadNotActive::SELECTOR, [0x07, 0xbf, 0x25, 0x4c]);
    }

    #[test]
    fn unknown_selector_and_short_data_return_none() {
        assert!(decode_revert(&[0x00, 0x01, 0x02, 0x03]).is_none());
        assert!(decode_revert(&[0xde, 0xad]).is_none());
    }
}
