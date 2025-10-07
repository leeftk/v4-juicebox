// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {JBRuleset} from "../structs/JBRuleset.sol";
import {JBRulesetMetadata} from "../structs/JBRulesetMetadata.sol";

/// @notice Interface for the JBController contract
interface IJBController {
    /// @notice Get the current ruleset for a project
    /// @param projectId The ID of the project
    /// @return ruleset The current ruleset
    /// @return metadata The current ruleset metadata
    function currentRulesetOf(uint256 projectId)
        external
        view
        returns (JBRuleset memory ruleset, JBRulesetMetadata memory metadata);
}

