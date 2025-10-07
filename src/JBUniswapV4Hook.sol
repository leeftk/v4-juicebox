// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BaseHook} from "@uniswap/v4-periphery/src/utils/BaseHook.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Import Juicebox protocol interfaces
import {IJBTokens} from "./interfaces/IJBTokens.sol";
import {IJBToken} from "./interfaces/IJBToken.sol";
import {IJBMultiTerminal} from "./interfaces/IJBMultiTerminal.sol";
import {IJBController} from "./interfaces/IJBController.sol";

import {JBRuleset} from "./structs/JBRuleset.sol";
import {JBRulesetMetadata} from "./structs/JBRulesetMetadata.sol";

/// @title JBUniswapV4Hook
/// @notice Official Juicebox integration for Uniswap v4 that provides price comparison and optimal routing
/// @dev This hook compares prices between Uniswap pools and Juicebox projects, then routes to the cheaper option
/// @custom:security-contact security@juicebox.money
contract JBUniswapV4Hook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using SafeERC20 for IERC20;

    //*********************************************************************//
    // --------------------------- custom errors ------------------------- //
    //*********************************************************************//

    error JBUniswapV4Hook_InvalidJuiceboxToken();
    error JBUniswapV4Hook_PaymentFailed();

    //*********************************************************************//
    // --------------------- immutable properties  ----------------------- //
    //*********************************************************************//

    /// @notice The Juicebox tokens contract for project token lookup
    IJBTokens public immutable TOKENS;

    /// @notice The Juicebox multi-terminal for processing payments
    IJBMultiTerminal public immutable TERMINAL;

    /// @notice The Juicebox controller for ruleset information
    IJBController public immutable CONTROLLER;

    //*********************************************************************//
    // --------------------- public stored properties -------------------- //
    //*********************************************************************//

    /// @notice Mapping from Uniswap pool ID to Juicebox project ID
    mapping(PoolId => uint256) public projectIdOf;

    /// @notice Mapping from Uniswap pool ID to Juicebox project token address
    mapping(PoolId => address) public juiceboxTokenOf;

    //*********************************************************************//
    // ---------------------------- events ------------------------------- //
    //*********************************************************************//

    /// @notice Emitted when a Juicebox project is detected in a pool
    event JuiceboxProjectDetected(PoolId indexed poolId, address indexed token, uint256 indexed projectId);

    /// @notice Emitted when a payment is processed to a Juicebox project
    event JuiceboxPaymentProcessed(
        PoolId indexed poolId,
        address indexed token,
        uint256 indexed projectId,
        uint256 amount,
        uint256 tokensReceived
    );

    /// @notice Emitted when token weight is calculated for a project
    event TokenWeightCalculated(uint256 indexed projectId, uint256 weight, uint256 tokensPerEth);

    /// @notice Emitted when prices are compared between Uniswap and Juicebox
    event PriceComparison(
        PoolId indexed poolId,
        uint256 uniswapPrice,
        uint256 juiceboxPrice,
        bool juiceboxCheaper,
        uint256 priceDifference
    );

    /// @notice Emitted when a routing decision is made
    event RouteSelected(
        PoolId indexed poolId, bool useJuicebox, uint256 expectedTokens, uint256 savings
    );

    //*********************************************************************//
    // -------------------------- constructor ---------------------------- //
    //*********************************************************************//

    /// @param poolManager The Uniswap v4 pool manager
    /// @param tokens The Juicebox tokens contract
    /// @param terminal The Juicebox multi-terminal
    /// @param controller The Juicebox controller
    constructor(
        IPoolManager poolManager,
        IJBTokens tokens,
        IJBMultiTerminal terminal,
        IJBController controller
    )
        BaseHook(poolManager)
    {
        TOKENS = tokens;
        TERMINAL = terminal;
        CONTROLLER = controller;
    }

    //*********************************************************************//
    // ---------------------- external transactions ---------------------- //
    //*********************************************************************//

    /// @notice Manually register a Juicebox project for a pool
    /// @param poolId The pool ID
    /// @param token The Juicebox project token address
    /// @return projectId The project ID if successfully registered
    function registerJuiceboxProject(PoolId poolId, address token) external returns (uint256 projectId) {
        projectId = _checkAndRegisterJuiceboxToken(token, poolId);
        if (projectId == 0) revert JBUniswapV4Hook_InvalidJuiceboxToken();
        return projectId;
    }

    //*********************************************************************//
    // ------------------------- public views ---------------------------- //
    //*********************************************************************//

    /// @notice Get the hook permissions for Uniswap v4
    /// @return permissions The hook permissions struct
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    /// @notice Calculate expected tokens for a given payment amount
    /// @param projectId The Juicebox project ID
    /// @param ethAmount The amount of ETH being paid
    /// @return expectedTokens The expected number of tokens to be received
    function calculateExpectedTokens(uint256 projectId, uint256 ethAmount)
        external
        view
        returns (uint256 expectedTokens)
    {
        try CONTROLLER.currentRulesetOf(projectId) returns (JBRuleset memory ruleset, JBRulesetMetadata memory)
        {
            // Weight represents tokens issued per ETH paid
            expectedTokens = (ruleset.weight * ethAmount) / 1e18;
        } catch {
            expectedTokens = 0;
        }
    }

    /// @notice Calculate the price per token in the Uniswap pool
    /// @dev This is a simplified implementation - production version should query actual pool price
    /// @param poolId The pool ID
    /// @param amountIn The input amount
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return pricePerToken The price per token (in wei)
    function calculateUniswapPrice(PoolId poolId, uint256 amountIn, bool zeroForOne)
        external
        pure
        returns (uint256 pricePerToken)
    {
        // Simplified implementation - returns 1 ETH per token
        // TODO: Implement actual pool price query using sqrtPriceX96
        pricePerToken = 1e18;
    }

    /// @notice Compare prices between Uniswap pool and Juicebox project
    /// @param poolId The pool ID
    /// @param amountIn The input amount
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return juiceboxCheaper Whether Juicebox is cheaper
    /// @return priceDifference The price difference (positive if Juicebox is cheaper)
    /// @return uniswapPrice The Uniswap price per token
    /// @return juiceboxPrice The Juicebox price per token
    function comparePrices(PoolId poolId, uint256 amountIn, bool zeroForOne)
        external
        view
        returns (bool juiceboxCheaper, uint256 priceDifference, uint256 uniswapPrice, uint256 juiceboxPrice)
    {
        uint256 projectId = projectIdOf[poolId];
        if (projectId == 0) {
            return (false, 0, 0, 0);
        }

        // Calculate Uniswap price
        uniswapPrice = this.calculateUniswapPrice(poolId, amountIn, zeroForOne);

        // Calculate Juicebox price
        uint256 expectedTokens = this.calculateExpectedTokens(projectId, amountIn);
        if (expectedTokens == 0) {
            juiceboxPrice = type(uint256).max;
        } else {
            juiceboxPrice = (amountIn * 1e18) / expectedTokens;
        }

        // Compare prices
        if (juiceboxPrice < uniswapPrice) {
            juiceboxCheaper = true;
            priceDifference = uniswapPrice - juiceboxPrice;
        } else {
            juiceboxCheaper = false;
            priceDifference = juiceboxPrice - uniswapPrice;
        }

        return (juiceboxCheaper, priceDifference, uniswapPrice, juiceboxPrice);
    }

    /// @notice Get project information for a pool
    /// @param poolId The pool ID
    /// @return projectId The Juicebox project ID (0 if not a Juicebox project)
    /// @return token The Juicebox project token address
    /// @return weight The current project weight
    function getProjectInfo(PoolId poolId) external view returns (uint256 projectId, address token, uint256 weight) {
        projectId = projectIdOf[poolId];
        token = juiceboxTokenOf[poolId];

        if (projectId != 0) {
            try CONTROLLER.currentRulesetOf(projectId) returns (JBRuleset memory ruleset, JBRulesetMetadata memory)
            {
                weight = ruleset.weight;
            } catch {
                weight = 0;
            }
        }
    }

    /// @notice Check if a token is a Juicebox project token
    /// @param token The token address to check
    /// @return projectId The project ID if found, 0 otherwise
    function isJuiceboxToken(address token) external view returns (uint256 projectId) {
        try TOKENS.projectIdOf(IJBToken(token)) returns (uint256 _projectId) {
            return _projectId;
        } catch {
            return 0;
        }
    }

    /// @notice Get optimal routing recommendation for a swap
    /// @param poolId The pool ID
    /// @param amountIn The input amount
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return useJuicebox Whether to use Juicebox instead of Uniswap
    /// @return expectedTokens Expected tokens from Juicebox (if applicable)
    /// @return savings Amount saved by using the optimal route
    function getOptimalRoute(PoolId poolId, uint256 amountIn, bool zeroForOne)
        external
        view
        returns (bool useJuicebox, uint256 expectedTokens, uint256 savings)
    {
        uint256 projectId = projectIdOf[poolId];
        if (projectId == 0) {
            return (false, 0, 0);
        }

        (bool juiceboxCheaper, uint256 priceDifference,,) = this.comparePrices(poolId, amountIn, zeroForOne);

        if (juiceboxCheaper) {
            useJuicebox = true;
            expectedTokens = this.calculateExpectedTokens(projectId, amountIn);
            savings = priceDifference;
        } else {
            useJuicebox = false;
            expectedTokens = 0;
            savings = 0;
        }

        return (useJuicebox, expectedTokens, savings);
    }

    /// @notice Get current price comparison for a pool
    /// @param poolId The pool ID
    /// @param amountIn The input amount
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return projectId The Juicebox project ID
    /// @return uniswapPrice The Uniswap price per token
    /// @return juiceboxPrice The Juicebox price per token
    /// @return juiceboxTokensPerEth The Juicebox tokens per ETH (weight)
    /// @return juiceboxCheaper Whether Juicebox is cheaper
    /// @return priceDifference The price difference
    /// @return savingsPercentage The savings percentage in basis points
    function getPriceComparison(PoolId poolId, uint256 amountIn, bool zeroForOne)
        external
        view
        returns (
            uint256 projectId,
            uint256 uniswapPrice,
            uint256 juiceboxPrice,
            uint256 juiceboxTokensPerEth,
            bool juiceboxCheaper,
            uint256 priceDifference,
            uint256 savingsPercentage
        )
    {
        projectId = projectIdOf[poolId];
        if (projectId == 0) {
            return (0, 0, 0, 0, false, 0, 0);
        }

        (juiceboxCheaper, priceDifference, uniswapPrice, juiceboxPrice) =
            this.comparePrices(poolId, amountIn, zeroForOne);

        // Get Juicebox tokens per ETH (weight)
        try CONTROLLER.currentRulesetOf(projectId) returns (JBRuleset memory ruleset, JBRulesetMetadata memory) {
            juiceboxTokensPerEth = ruleset.weight;
        } catch {
            juiceboxTokensPerEth = 0;
        }

        // Calculate savings percentage
        if (uniswapPrice > 0) {
            savingsPercentage = (priceDifference * 10_000) / uniswapPrice; // In basis points
        }

        return (
            projectId,
            uniswapPrice,
            juiceboxPrice,
            juiceboxTokensPerEth,
            juiceboxCheaper,
            priceDifference,
            savingsPercentage
        );
    }

    //*********************************************************************//
    // ---------------------- internal transactions ---------------------- //
    //*********************************************************************//

    /// @notice Hook called before a swap
    /// @dev Checks if either token in the swap is a Juicebox project token
    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata, bytes calldata)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        PoolId poolId = key.toId();

        // Check if either token is a Juicebox project token
        _checkAndRegisterJuiceboxToken(Currency.unwrap(key.currency0), poolId);
        _checkAndRegisterJuiceboxToken(Currency.unwrap(key.currency1), poolId);

        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    /// @notice Hook called after a swap
    /// @dev Compares prices and routes to cheaper option (Uniswap or Juicebox)
    function _afterSwap(
        address swapper,
        PoolKey calldata key,
        SwapParams calldata params,
        BalanceDelta,
        bytes calldata
    )
        internal
        override
        returns (bytes4, int128)
    {
        PoolId poolId = key.toId();
        uint256 projectId = projectIdOf[poolId];

        // If this pool has a Juicebox project, compare prices and route optimally
        if (projectId != 0) {
            address juiceboxToken = juiceboxTokenOf[poolId];
            uint256 amountIn =
                params.amountSpecified > 0 ? uint256(params.amountSpecified) : uint256(-params.amountSpecified);

            // Determine which token is the Juicebox token and the swap direction
            bool isToken0Juicebox = juiceboxToken == Currency.unwrap(key.currency0);
            bool zeroForOne = params.zeroForOne;

            // Compare prices between Uniswap and Juicebox
            (bool juiceboxCheaper, uint256 priceDifference, uint256 uniswapPrice, uint256 juiceboxPrice) =
                this.comparePrices(poolId, amountIn, zeroForOne);

            emit PriceComparison(poolId, uniswapPrice, juiceboxPrice, juiceboxCheaper, priceDifference);

            // Route to the cheaper option
            if (juiceboxCheaper && isToken0Juicebox == zeroForOne) {
                // Juicebox is cheaper and we're buying the Juicebox token
                uint256 expectedTokens = this.calculateExpectedTokens(projectId, amountIn);

                emit RouteSelected(poolId, true, expectedTokens, priceDifference);

                // Process Juicebox payment instead of Uniswap swap
                uint256 tokensReceived = _processJuiceboxPayment(projectId, juiceboxToken, amountIn, swapper);

                emit JuiceboxPaymentProcessed(poolId, juiceboxToken, projectId, amountIn, tokensReceived);
            } else {
                // Uniswap is cheaper, proceed with normal swap
                emit RouteSelected(poolId, false, 0, 0);
            }
        }

        return (BaseHook.afterSwap.selector, 0);
    }

    //*********************************************************************//
    // ----------------------- private helpers --------------------------- //
    //*********************************************************************//

    /// @notice Check if a token is a Juicebox project token and register it
    /// @param token The token address to check
    /// @param poolId The pool ID to associate with this token
    /// @return projectId The project ID if found, 0 otherwise
    function _checkAndRegisterJuiceboxToken(address token, PoolId poolId) private returns (uint256 projectId) {
        // Check if this token is already registered for this pool
        if (projectIdOf[poolId] != 0) {
            return projectIdOf[poolId];
        }

        // Check if the token is a Juicebox project token
        try TOKENS.projectIdOf(IJBToken(token)) returns (uint256 _projectId) {
            if (_projectId != 0) {
                projectId = _projectId;
                projectIdOf[poolId] = projectId;
                juiceboxTokenOf[poolId] = token;

                emit JuiceboxProjectDetected(poolId, token, projectId);

                // Log the current weight for this project
                _logProjectWeight(projectId);
            }
        } catch {
            // Token is not a Juicebox project token
            return 0;
        }
    }

    /// @notice Log the current project weight and calculate tokens per ETH
    /// @param projectId The Juicebox project ID
    function _logProjectWeight(uint256 projectId) private {
        try CONTROLLER.currentRulesetOf(projectId) returns (JBRuleset memory ruleset, JBRulesetMetadata memory) {
            emit TokenWeightCalculated(projectId, ruleset.weight, ruleset.weight);
        } catch {
            // Project ruleset not found or error
        }
    }

    /// @notice Process a payment to a Juicebox project
    /// @param projectId The Juicebox project ID
    /// @param token The token being paid
    /// @param amount The amount to pay
    /// @param beneficiary The address to receive the project tokens
    /// @return tokensReceived The number of project tokens received
    function _processJuiceboxPayment(uint256 projectId, address token, uint256 amount, address beneficiary)
        private
        returns (uint256 tokensReceived)
    {
        try TERMINAL.pay{value: token == address(0) ? amount : 0}(
            projectId, token, amount, beneficiary, 0, "Uniswap v4 Hook Payment", bytes("")
        ) returns (uint256 _tokensReceived) {
            tokensReceived = _tokensReceived;
        } catch {
            revert JBUniswapV4Hook_PaymentFailed();
        }
    }
}

