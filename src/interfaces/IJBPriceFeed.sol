// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Interface for a price feed
interface IJBPriceFeed {
    /// @notice Gets the current price of 1 unit of the unit currency in terms of the pricing currency
    /// @param decimals The number of decimals the returned fixed point price should include
    /// @return The price of 1 unit of the unit currency in terms of the pricing currency
    function currentUnitPrice(uint256 decimals) external view returns (uint256);
}

