// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;
import {IDcapAttestation} from "@contracts/src/interfaces/external/IDcapAttestation.sol";

/// @notice Hardware-only local emulator: skips Intel cryptography, retains strict TDX framing.
/// @dev Stateless runtime is safe to etch over a hardware backend with arbitrary existing storage.
contract EmulatorDcapAttestation is IDcapAttestation {
    error InvalidQuoteFraming();
    error UnsupportedZkProof();

    function getBp() external pure returns (uint16) {
        return 0;
    }

    function le(bytes calldata input, uint256 offset, uint256 size) private pure returns (uint256 value) {
        if (input.length < offset + size) revert InvalidQuoteFraming();
        for (uint256 i; i < size; ++i) {
            value |= uint256(uint8(input[offset + i])) << (8 * i);
        }
    }

    function verifyAndAttestOnChain(bytes calldata input) external payable returns (bool, bytes memory) {
        (uint16 version, uint16 bodyType, bytes memory body) = quoteBody(input);
        return (true, abi.encodePacked(version, bodyType, uint8(0), bytes6(0), body));
    }

    function verifyAndAttestOnChainV2(bytes calldata input) external payable returns (bool, bytes memory, bytes memory) {
        return outputV2(input);
    }

    function verifyAndAttestOnChainV2(bytes calldata input, uint32, bool)
        external payable returns (bool, bytes memory, bytes memory)
    {
        return outputV2(input);
    }

    // Hardware collateral is synthetic; quote framing and commitments remain exact.
    function outputV2(bytes calldata input) private view returns (bool, bytes memory, bytes memory) {
        (uint16 version, uint16 bodyType, bytes memory body) = quoteBody(input);
        bytes32[6] memory collateralHashes;
        bytes memory output = abi.encodePacked(
            uint16(2), uint16(1), uint8(6), version, bodyType, uint8(0),
            bytes6(0), bytes16(0), bytes16(0), false, uint16(0), uint16(0),
            uint64(block.timestamp), collateralHashes, keccak256(input), keccak256(body)
        );
        return (true, output, body);
    }

    function quoteBody(bytes calldata input) private pure returns (uint16 version, uint16 bodyType, bytes memory body) {
        version = uint16(le(input, 0, 2));

        if (le(input, 4, 4) != 0x81) revert InvalidQuoteFraming();
        bodyType = 2;
        uint256 bodyOffset = 48;
        uint256 bodySize = 584;
        if (version == 5) {
            bodyType = uint16(le(input, 48, 2));
            if (bodyType == 3) bodySize = 648;
            else if (bodyType != 2) revert InvalidQuoteFraming();
            if (le(input, 50, 4) != bodySize) revert InvalidQuoteFraming();
            bodyOffset = 54;
        } else if (version != 4) {
            revert InvalidQuoteFraming();
        }
        uint256 end = bodyOffset + bodySize;
        uint256 signatureLength = le(input, end, 4);
        if (input.length != end + 4 + signatureLength) revert InvalidQuoteFraming();
        body = input[bodyOffset:end];
    }

    function verifyAndAttestWithZKProof(bytes calldata, ZkCoProcessorType, bytes calldata, bytes32, uint32)
        external
        payable
        returns (bool, bytes memory)
    {
        revert UnsupportedZkProof();
    }
}
