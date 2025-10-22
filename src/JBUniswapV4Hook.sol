// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHook} from "@uniswap/v4-periphery/src/utils/BaseHook.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {
    BeforeSwapDelta,
    BeforeSwapDeltaLibrary,
    toBeforeSwapDelta
} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {FullMath} from "@uniswap/v4-core/src/libraries/FullMath.sol";
import {FixedPoint96} from "@uniswap/v4-core/src/libraries/FixedPoint96.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Import Juicebox protocol interfaces
import {IJBTokens} from "./interfaces/IJBTokens.sol";
import {IJBToken} from "./interfaces/IJBToken.sol";
import {IJBDirectory} from "./interfaces/IJBDirectory.sol";
import {IJBMultiTerminal} from "./interfaces/IJBMultiTerminal.sol";
import {IJBController} from "./interfaces/IJBController.sol";
import {IJBPrices} from "./interfaces/IJBPrices.sol";

import {JBRuleset} from "./structs/JBRuleset.sol";
import {JBRulesetMetadata} from "./structs/JBRulesetMetadata.sol";

/// @title JBUniswapV4Hook
/// @notice Official Juicebox integration for Uniswap v4 that provides price comparison and optimal routing
/// @dev This hook compares prices between Uniswap pools and Juicebox projects, then routes to the cheaper option
/// @custom:security-contact security@juicebox.money
contract JBUniswapV4Hook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using StateLibrary for IPoolManager;
    using SafeERC20 for IERC20;

    //*********************************************************************//
    // --------------------------- custom errors ------------------------- //
    //*********************************************************************//

    error JBUniswapV4Hook_InvalidCurrencyId();

    //*********************************************************************//
    // --------------------- immutable properties  ----------------------- //
    //*********************************************************************//

    /// @notice The Juicebox tokens contract for project token lookup
    IJBTokens public immutable TOKENS;

    /// @notice The Juicebox directory for terminal lookup
    IJBDirectory public immutable DIRECTORY;

    /// @notice The Juicebox controller for ruleset information
    IJBController public immutable CONTROLLER;

    /// @notice The Juicebox prices contract for currency conversion
    IJBPrices public immutable PRICES;

    /// @notice Native ETH address representation
    address public constant UNISWAP_NATIVE_ETH = address(0);

    /// @notice Juicebox native token address
    address public constant JB_NATIVE_TOKEN = address(0x000000000000000000000000000000000000EEEe);

    //*********************************************************************//
    // --------------------- public stored properties -------------------- //
    //*********************************************************************//

    /// @notice Mapping from Uniswap pool ID to Juicebox project ID
    mapping(PoolId => uint256) public projectIdOf;

    //*********************************************************************//
    // ---------------------------- events ------------------------------- //
    //*********************************************************************//

    /// @notice Emitted when a payment is processed to a Juicebox project
    event JuiceboxPaymentProcessed(
        PoolId indexed poolId, address indexed token, uint256 indexed projectId, uint256 amount, uint256 tokensReceived
    );

    /// @notice Emitted when prices are compared between Uniswap and Juicebox
    event PriceComparison(
        PoolId indexed poolId,
        uint256 uniswapPrice,
        uint256 juiceboxPrice,
        bool juiceboxCheaper,
        uint256 priceDifference
    );

    /// @notice Emitted when a routing decision is made
    event RouteSelected(PoolId indexed poolId, bool useJuicebox, uint256 expectedTokens, uint256 savings);

    //*********************************************************************//
    // -------------------------- constructor ---------------------------- //
    //*********************************************************************//

    /// @param poolManager The Uniswap v4 pool manager
    /// @param tokens The Juicebox tokens contract
    /// @param directory The Juicebox directory
    /// @param controller The Juicebox controller
    /// @param prices The Juicebox prices contract for currency conversion
    constructor(
        IPoolManager poolManager,
        IJBTokens tokens,
        IJBDirectory directory,
        IJBController controller,
        IJBPrices prices
    ) BaseHook(poolManager) {
        TOKENS = tokens;
        DIRECTORY = directory;
        CONTROLLER = controller;
        PRICES = prices;
    }

    /// @notice Receive function to accept ETH
    receive() external payable {}

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
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: true, // Enable to override swap behavior
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    /// @notice Calculate expected tokens for a given payment amount in any currency
    /// @param projectId The Juicebox project ID
    /// @param paymentToken The token being used for payment
    /// @param paymentAmount The amount being paid (in the token's native decimals)
    /// @return expectedTokens The expected number of tokens to be received
    function calculateExpectedTokensWithCurrency(uint256 projectId, address paymentToken, uint256 paymentAmount)
        public
        view
        returns (uint256 expectedTokens)
    {
        // Get the project's weight (tokens per ETH)
        uint256 tokensPerBaseCurrency;
        // Get the currency Id for the `weight`. 
        uint256 baseCurrency;
        try CONTROLLER.currentRulesetOf(projectId) returns (JBRuleset memory ruleset, JBRulesetMetadata memory metadata) {
            tokensPerBaseCurrency = ruleset.weight;
            baseCurrency = metadata.baseCurrency;
        } catch {
            return 0;
        }

        // Use Juicebox's address for native token if the payment token is uniswap's native token.
        if (paymentToken == UNISWAP_NATIVE_ETH) paymentToken = JB_NATIVE_TOKEN;

        // Get the currency ID for the payment token
        uint32 paymentCurrencyId = uint32(uint160(paymentToken));

        // Get the decimals of the payment token
        uint8 paymentTokenDecimals;
        try IERC20Metadata(paymentToken).decimals() returns (uint8 decimals) {
            paymentTokenDecimals = decimals;
        } catch {
            // If we can't get decimals, assume 18
            paymentTokenDecimals = 18;
        }

        // Get the price: how much ETH per 1 unit of payment token
        // pricePerUnitOf returns the price of unitCurrency (paymentToken) in terms of pricingCurrency (ETH)
        // The result is scaled by 10^decimals (18 in this case)
        uint256 baseCurrencyPerPaymentToken;
        try PRICES.pricePerUnitOf(projectId, paymentCurrencyId, baseCurrency, 18) returns (uint256 price) {
            baseCurrencyPerPaymentToken = price;
        } catch {
            return 0;
        }

        // Calculate tokens based on ETH equivalent
        // baseCurrencyPerPaymentToken is in 18 decimals, and paymentAmount is in the payment token's decimals. We want 18.
        expectedTokens = (baseCurrencyPerPaymentToken * paymentAmount) / paymentTokenDecimals;
    }

    /// @notice Estimate expected output tokens from a Uniswap swap
    /// @dev This is a simplified estimation that doesn't account for multi-tick swaps or complex price impact
    /// @param poolId The pool ID
    /// @param amountIn The input amount
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return estimatedOut The estimated output amount
    function estimateUniswapOutput(
        PoolId poolId,
        PoolKey memory,
        /* key */
        uint256 amountIn,
        bool zeroForOne
    )
        public
        view
        returns (uint256 estimatedOut)
    {
        // Get current pool state
        (uint160 sqrtPriceX96,,,) = poolManager.getSlot0(poolId);

        // Get pool liquidity - simplified: we use a basic estimation
        // In production, this should account for liquidity distribution across ticks
        // For now, return 0 to indicate we need proper implementation
        // TODO: This should be using TWAP style price calucation or fork

        // For a basic estimate using current spot price:
        // Calculate Q192 = 2^192
        uint256 Q192 = uint256(FixedPoint96.Q96) * FixedPoint96.Q96;
        uint256 priceSquared = uint256(sqrtPriceX96) * sqrtPriceX96;

        if (zeroForOne) {
            // Selling token0 for token1
            // price = token1/token0 = priceSquared / Q192
            // estimatedOut = amountIn * price
            estimatedOut = FullMath.mulDiv(amountIn, priceSquared, Q192);
        } else {
            // Selling token1 for token0
            // price = token0/token1 = Q192 / priceSquared
            // estimatedOut = amountIn * price
            estimatedOut = FullMath.mulDiv(amountIn, Q192, priceSquared);
        }

        // Apply a simple fee estimate (subtract ~0.3% for 3000 fee tier)
        // In reality, fee should be read from the pool
        // Assuming 3000 = 0.3%
        estimatedOut = (estimatedOut * 997) / 1000; // 0.3% fee

        return estimatedOut;
    }

    //*********************************************************************//
    // ---------------------- internal transactions ---------------------- //
    //*********************************************************************//

    /// @notice Check if a token is a Juicebox project token and register it
    /// @param token The token address to check
    /// @param poolId The pool ID to register the project for
    /// @return projectId The project ID if found, 0 otherwise
    function _checkAndRegisterJuiceboxToken(address token, PoolId poolId) internal returns (uint256 projectId) {
        // Check if this token is already registered for this pool
        if (projectIdOf[poolId] != 0) {
            return projectIdOf[poolId];
        }

        // Check if the token is a Juicebox project token
        try TOKENS.projectIdOf(IJBToken(token)) returns (uint256 _projectId) {
            if (_projectId != 0) {
                projectId = _projectId;
                projectIdOf[poolId] = projectId;
                return projectId;
            }
        } catch {
            // Token is not a Juicebox project token
            return 0;
        }

        return 0;
    }

    /// @notice Hook called before a swap
    /// @dev Compares prices between Uniswap and Juicebox, routes to cheaper option
    function _beforeSwap(address swapper, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        PoolId poolId = key.toId();

        // Determine input and output currencies based on swap direction
        Currency inputCurrency = params.zeroForOne ? key.currency0 : key.currency1;
        Currency outputCurrency = params.zeroForOne ? key.currency1 : key.currency0;

        address tokenIn = Currency.unwrap(inputCurrency);
        address tokenOut = Currency.unwrap(outputCurrency);

        // Get absolute amount (params.amountSpecified is negative for exact input)
        uint256 amountIn =
            params.amountSpecified > 0 ? uint256(params.amountSpecified) : uint256(-params.amountSpecified);

        // Check if there's a Juicebox project for this pool (auto-detect or use cached)
        uint256 projectId = projectIdOf[poolId];

        // If not cached, try to detect Juicebox project token
        if (projectId == 0) {
            projectId = _checkAndRegisterJuiceboxToken(tokenOut, poolId);
            if (projectId == 0) {
                // No Juicebox project, proceed with normal Uniswap swap
                return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
            }
        }

        // Calculate how many tokens we'd get from Juicebox
        uint256 juiceboxExpectedTokens = calculateExpectedTokensWithCurrency(projectId, tokenIn, amountIn);

        // Calculate how many tokens we'd get from Uniswap
        uint256 uniswapExpectedTokens = estimateUniswapOutput(poolId, key, amountIn, params.zeroForOne);

        // Compare the outputs - Juicebox is better if it gives more tokens
        bool juiceboxBetter = juiceboxExpectedTokens > uniswapExpectedTokens;

        emit PriceComparison(
            poolId,
            uniswapExpectedTokens,
            juiceboxExpectedTokens,
            juiceboxBetter,
            juiceboxBetter
                ? juiceboxExpectedTokens - uniswapExpectedTokens
                : uniswapExpectedTokens - juiceboxExpectedTokens
        );

        // If Juicebox gives more tokens, route through Juicebox
        if (juiceboxBetter && juiceboxExpectedTokens > 0) {
            // Route the swap through Juicebox instead of Uniswap
            uint256 tokensReceived = _routeToJuicebox(projectId, inputCurrency, outputCurrency, amountIn, swapper);

            emit JuiceboxPaymentProcessed(poolId, tokenOut, projectId, amountIn, tokensReceived);

            // Return a delta that prevents the Uniswap swap from executing
            // deltaSpecified = -amountSpecified makes amountToSwap = 0
            // deltaUnspecified = amountSpecified to account for the output we're providing
            BeforeSwapDelta hookDelta =
                toBeforeSwapDelta(int128(-params.amountSpecified), int128(params.amountSpecified));

            return (BaseHook.beforeSwap.selector, hookDelta, 0);
        }

        // Uniswap gives more tokens, proceed with normal swap
        emit RouteSelected(poolId, false, 0, 0);
        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    /// @notice Routes a swap through Juicebox instead of Uniswap
    /// @dev Takes input tokens from PoolManager, processes Juicebox payment, settles output tokens back
    /// @param projectId The Juicebox project ID
    /// @param inputCurrency The input currency (what the swapper is paying)
    /// @param outputCurrency The output currency (what the swapper receives - Juicebox token)
    /// @param amountIn The amount of input tokens
    /// @return tokensReceived The amount of Juicebox tokens received
    function _routeToJuicebox(
        uint256 projectId,
        Currency inputCurrency,
        Currency outputCurrency,
        uint256 amountIn,
        address /* beneficiary */
    ) internal returns (uint256 tokensReceived) {
        // Step 1: Take input tokens from PoolManager to this hook contract
        // This debits the swapper's account and gives tokens to the hook
        poolManager.take(inputCurrency, address(this), amountIn);

        //router ----> poolManager +++++++ ----> take tokens from poolManager to this contract ==== neutral delta 

        address tokenIn = Currency.unwrap(inputCurrency);
        address tokenOut = Currency.unwrap(outputCurrency);

        // Get the primary terminal for the project.
        address terminal = DIRECTORY.primaryTerminalOf(projectId, tokenIn);

        // Step 2: Process payment through Juicebox
        // Approve the terminal to spend the tokens if needed
        if (!inputCurrency.isAddressZero()) {
            IERC20(tokenIn).safeIncreaseAllowance(address(terminal), amountIn);
        }

        // Pay to Juicebox - tokens are minted to THIS contract, not the swapper
        // We'll settle them to the PoolManager which will credit the swapper
        uint256 payValue = inputCurrency.isAddressZero() ? amountIn : 0;

        tokensReceived = IJBMultiTerminal(terminal).pay{
            value: payValue
        }(
            projectId,
            tokenIn,
            amountIn,
            address(this), // Tokens come to the hook first
            0, // No minimum tokens required
            "", // Empty memo
            bytes("") // Empty metadata
        );

        // Step 3: Settle output tokens to PoolManager
        // This credits the swapper's account with the output tokens
        if (!outputCurrency.isAddressZero()) {
            // Sync then transfer tokens to PoolManager and settle
            poolManager.sync(outputCurrency);
            IERC20(tokenOut).safeTransfer(address(poolManager), tokensReceived);
            poolManager.settle();
        } else {
            // Output is native ETH - settle with value
            poolManager.settle{value: tokensReceived}();
        }

        return tokensReceived;
    }
}

