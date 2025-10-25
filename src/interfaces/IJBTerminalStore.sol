// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IJBTerminalStore
/// @notice Interface for the Juicebox Terminal Store contract
interface IJBTerminalStore {
    /// @notice Get the current reclaimable surplus for a project
    /// @param projectId The project ID
    /// @param token The token address
    /// @param currency The currency ID
    /// @param decimals The number of decimals
    /// @return surplus The current reclaimable surplus
    function currentReclaimableSurplusOf(
        uint256 projectId,
        address token,
        uint256 currency,
        uint256 decimals
    ) external view returns (uint256 surplus);
}
