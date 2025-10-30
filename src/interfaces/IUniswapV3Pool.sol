// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IUniswapV3Pool
/// @notice Interface for Uniswap v3 pool contract
interface IUniswapV3Pool {
    /// @notice Get the current pool state
    /// @return sqrtPriceX96 The current price as a sqrt(price) * 2^96
    /// @return tick The current tick
    /// @return observationIndex The index of the last oracle observation
    /// @return observationCardinality The current maximum number of observations stored
    /// @return observationCardinalityNext The next maximum number of observations to store
    /// @return feeProtocol The protocol fee for both tokens of the pool
    /// @return unlocked Whether the pool is currently unlocked
    function slot0() external view returns (
        uint160 sqrtPriceX96,
        int24 tick,
        uint16 observationIndex,
        uint16 observationCardinality,
        uint16 observationCardinalityNext,
        uint8 feeProtocol,
        bool unlocked
    );

    /// @notice Initialize the pool with a starting price
    /// @param sqrtPriceX96 The starting price as a sqrt(price) * 2^96
    function initialize(uint160 sqrtPriceX96) external;

    /// @notice Add liquidity to a position
    /// @param recipient The address to receive the minted tokens
    /// @param tickLower The lower tick of the position
    /// @param tickUpper The upper tick of the position
    /// @param amount The amount of liquidity to mint
    /// @param data Any data to pass to the callback
    /// @return amount0 The amount of token0 minted
    /// @return amount1 The amount of token1 minted
    function mint(address recipient, int24 tickLower, int24 tickUpper, uint128 amount, bytes calldata data)
        external
        returns (uint256 amount0, uint256 amount1);

    /// @notice Remove liquidity from a position
    /// @param tickLower The lower tick of the position
    /// @param tickUpper The upper tick of the position
    /// @param amount The amount of liquidity to burn
    /// @return amount0 The amount of token0 burned
    /// @return amount1 The amount of token1 burned
    function burn(int24 tickLower, int24 tickUpper, uint128 amount)
        external
        returns (uint256 amount0, uint256 amount1);

    /// @notice Execute a swap
    /// @param recipient The address to receive the output tokens
    /// @param zeroForOne Whether swapping token0 for token1
    /// @param amountSpecified The amount of the swap
    /// @param sqrtPriceLimitX96 The price limit for the swap
    /// @param data Any data to pass to the callback
    /// @return amount0 The amount of token0 swapped
    /// @return amount1 The amount of token1 swapped
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
}
