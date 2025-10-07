// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IJBToken} from "./IJBToken.sol";

/// @notice Interface for the JBTokens contract
interface IJBTokens {
    /// @notice Get the project ID for a given token
    /// @param token The token address to look up
    /// @return projectId The project ID that owns the token
    function projectIdOf(IJBToken token) external view returns (uint256 projectId);
}

