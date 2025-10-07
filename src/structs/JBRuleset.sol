// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Ruleset configuration for a Juicebox project
/// @dev Minimal struct containing only the fields needed by the hook
struct JBRuleset {
    uint256 cycleNumber;
    uint256 id;
    uint256 basedOnId;
    uint256 start;
    uint256 duration;
    uint256 weight;
    uint256 decayPercent;
    address approvalHook;
    uint256 metadata;
}

