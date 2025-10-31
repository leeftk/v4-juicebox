// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Interface for the JBMultiTerminal contract
interface IJBMultiTerminal {
    /// @notice Pay a Juicebox project
    /// @param projectId The ID of the project being paid
    /// @param token The token being paid (address(0) for ETH)
    /// @param amount The amount of tokens to pay
    /// @param beneficiary The address that will receive project tokens
    /// @param minReturnedTokens The minimum number of project tokens expected
    /// @param memo A memo to attach to the payment
    /// @param metadata Additional metadata for the payment
    /// @return beneficiaryTokenCount The number of project tokens received
    function pay(
        uint256 projectId,
        address token,
        uint256 amount,
        address beneficiary,
        uint256 minReturnedTokens,
        string calldata memo,
        bytes calldata metadata
    ) external payable returns (uint256 beneficiaryTokenCount);

    /// @notice Redeem tokens from a Juicebox project
    /// @param projectId The ID of the project
    /// @param token The token being redeemed
    /// @param amount The amount of tokens to redeem
    /// @param beneficiary The address that will receive the redemption proceeds
    /// @param minReturnedTokens The minimum number of tokens expected
    /// @param memo A memo to attach to the redemption
    /// @param metadata Additional metadata for the redemption
    /// @return The number of tokens received from redemption
    function redeemTokensOf(
        uint256 projectId,
        address token,
        uint256 amount,
        address beneficiary,
        uint256 minReturnedTokens,
        string calldata memo,
        bytes calldata metadata
    ) external returns (uint256);
}

