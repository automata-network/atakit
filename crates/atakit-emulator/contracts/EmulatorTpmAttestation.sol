// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;
import {MockTpmAttestation} from "./MockTpmAttestation.sol";

/// @notice Stateless hardware-only TPM runtime. Real TpmVerifier still validates quote nonce, PCR digest, selection and policy.
/// @dev Inherits the repository's licensed parsing mock; never substitute this for TpmVerifier or SignatureVerifier.
contract EmulatorTpmAttestation is MockTpmAttestation {}
