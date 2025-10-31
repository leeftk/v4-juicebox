// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IUniswapV3Factory
/// @notice Interface for Uniswap v3 factory contract
interface IUniswapV3Factory {
    /// @notice Get the pool address for a given token pair and fee tier
    /// @param tokenA First token in the pair
    /// @param tokenB Second token in the pair
    /// @param fee The fee tier
    /// @return pool The pool address
    function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address pool);

    /// @notice Create a new pool for a given token pair and fee tier
    /// @param tokenA First token in the pair
    /// @param tokenB Second token in the pair
    /// @param fee The fee tier
    /// @return pool The new pool address
    function createPool(address tokenA, address tokenB, uint24 fee) external returns (address pool);

    /// @notice Enable a fee amount for pool creation
    /// @param fee The fee amount to enable
    /// @param tickSpacing The tick spacing for the fee tier
    function enableFeeAmount(uint24 fee, int24 tickSpacing) external;
}
