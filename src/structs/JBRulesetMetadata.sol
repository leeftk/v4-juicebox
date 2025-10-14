// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Metadata for a Juicebox ruleset
/// @dev Minimal struct containing common metadata fields
struct JBRulesetMetadata {
    uint256 reservedPercent;
    uint256 redemptionRate;
    uint256 baseCurrency;
    bool pausePay;
    bool pauseCreditTransfers;
    bool allowOwnerMinting;
    bool allowSetCustomToken;
    bool allowTerminalMigration;
    bool allowSetTerminals;
    bool allowSetController;
    bool allowAddAccountingContext;
    bool allowAddPriceFeed;
    bool allowCrosschainSuckerExtension;
    bool holdFees;
    bool useTotalSurplusForRedemptions;
    bool useDataHookForPay;
    bool useDataHookForRedeem;
    address dataHook;
    uint256 metadata;
}

