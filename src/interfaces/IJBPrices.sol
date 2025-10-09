// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IJBPriceFeed} from "./IJBPriceFeed.sol";

/// @notice Interface for the JBPrices contract which manages price feeds
interface IJBPrices {
    event AddPriceFeed(
        uint256 indexed projectId,
        uint256 indexed pricingCurrency,
        uint256 indexed unitCurrency,
        IJBPriceFeed feed,
        address caller
    );

    function DEFAULT_PROJECT_ID() external view returns (uint256);

    function priceFeedFor(uint256 projectId, uint256 pricingCurrency, uint256 unitCurrency)
        external
        view
        returns (IJBPriceFeed);

    function pricePerUnitOf(uint256 projectId, uint256 pricingCurrency, uint256 unitCurrency, uint256 decimals)
        external
        view
        returns (uint256);

    function addPriceFeedFor(uint256 projectId, uint256 pricingCurrency, uint256 unitCurrency, IJBPriceFeed feed)
        external;
}

