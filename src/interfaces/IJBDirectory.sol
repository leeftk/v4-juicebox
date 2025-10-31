// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IJBDirectory {
    /// @notice Get the primary terminal for a project
    /// @param projectId The ID of the project
    /// @param token The token being paid (address(0) for ETH)
    /// @return terminal The primary terminal for the project
    function primaryTerminalOf(uint256 projectId, address token) external view returns (address terminal);
}

