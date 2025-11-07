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
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {FullMath} from "@uniswap/v4-core/src/libraries/FullMath.sol";
import {FixedPoint96} from "@uniswap/v4-core/src/libraries/FixedPoint96.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
// Uniswap v3 interfaces
import {IUniswapV3Factory} from "./interfaces/IUniswapV3Factory.sol";
import {IUniswapV3Pool} from "./interfaces/IUniswapV3Pool.sol";
import {IUniswapV3SwapCallback} from "../lib/v3-core/contracts/interfaces/callback/IUniswapV3SwapCallback.sol";

// v3 oracle data is read via interface calls, no library imports needed

// Import Oracle library for TWAP
import {Oracle} from "./libraries/Oracle.sol";

// Import Juicebox protocol interfaces
import {IJBTokens} from "@bananapus/core-v5/interfaces/IJBTokens.sol";
import {IJBToken} from "@bananapus/core-v5/interfaces/IJBToken.sol";
import {IJBDirectory} from "@bananapus/core-v5/interfaces/IJBDirectory.sol";
import {IJBMultiTerminal} from "@bananapus/core-v5/interfaces/IJBMultiTerminal.sol";
import {IJBController} from "@bananapus/core-v5/interfaces/IJBController.sol";
import {IJBTerminal} from "@bananapus/core-v5/interfaces/IJBTerminal.sol";

import {IJBPrices} from "@bananapus/core-v5/interfaces/IJBPrices.sol";
import {IJBTerminalStore} from "@bananapus/core-v5/interfaces/IJBTerminalStore.sol";

import {JBRuleset} from "@bananapus/core-v5/structs/JBRuleset.sol";
import {JBRulesetMetadata} from "@bananapus/core-v5/structs/JBRulesetMetadata.sol";

// Import PRB Math for logarithmic functions
import {UD60x18} from "../lib/prb-math/src/ud60x18/ValueType.sol";
import {log2} from "../lib/prb-math/src/ud60x18/Math.sol";

interface IMsgSender {
    function msgSender() external view returns (address);
}

/// @title JBUniswapV4Hook
/// @notice Official Juicebox integration for Uniswap v4 that provides price comparison and optimal routing
/// @dev This hook compares prices between Uniswap pools and Juicebox projects, then routes to the cheaper option
/// @custom:security-contact security@juicebox.money
contract JBUniswapV4Hook is BaseHook, IUniswapV3SwapCallback {
    using PoolIdLibrary for PoolKey;
    using StateLibrary for IPoolManager;
    using SafeERC20 for IERC20;
    using Oracle for Oracle.Observation[65535];

    //*********************************************************************//
    // --------------------------- custom errors ------------------------- //
    //*********************************************************************//

    error JBUniswapV4Hook_InvalidCurrencyId();

    //*********************************************************************//
    // ---------------------------- structs ------------------------------ //
    //*********************************************************************//

    /// @notice Tracks the oracle observation state for a pool
    /// @member index The index of the last written observation for the pool
    /// @member cardinality The cardinality of the observations array for the pool
    /// @member cardinalityNext The cardinality target of the observations array for the pool
    struct ObservationState {
        uint16 index;
        uint16 cardinality;
        uint16 cardinalityNext;
    }

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

    /// @notice The Juicebox terminal store for getting reclaimable surplus
    IJBTerminalStore public immutable TERMINAL_STORE;

    /// @notice The Uniswap v3 factory for v3 pool lookups
    IUniswapV3Factory public immutable V3_FACTORY;

    /// @notice Native ETH address representation
    address public constant UNISWAP_NATIVE_ETH = address(0);

    /// @notice Juicebox native token address
    address public constant JB_NATIVE_TOKEN = address(0x000000000000000000000000000000000000EEEe);

    /// @notice TWAP period in seconds (30 minutes by default)
    uint32 public constant TWAP_PERIOD = 1800;

    /// @notice Standard TWAP window in seconds (1 hour by default)
    uint256 public constant STANDARD_TWAP_WINDOW = 1 hours;

    /// @notice The denominator used when calculating TWAP slippage percent values.
    uint256 public constant TWAP_SLIPPAGE_DENOMINATOR = 10_000;

    /// @notice The uncertain slippage tolerance allowed.
    uint256 public constant UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE = 1050;

    //*********************************************************************//
    // --------------------- public stored properties -------------------- //
    //*********************************************************************//

    /// @notice Mapping from Uniswap pool ID to Juicebox project ID
    mapping(PoolId => uint256) public projectIdOf;

    /// @notice The list of observations for a given pool ID
    mapping(PoolId => Oracle.Observation[65535]) public observations;

    /// @notice The current observation array state for the given pool ID
    mapping(PoolId => ObservationState) public states;

    //*********************************************************************//
    // ---------------------------- events ------------------------------- //
    //*********************************************************************//

    /// @notice Emitted when a routing decision is made
    event RouteSelected(PoolId indexed poolId, bool useJuicebox, uint256 expectedTokens, uint256 savings);

    /// @notice Emitted when v3 pool prices are compared
    event V3PriceComparison(
        address indexed token0,
        address indexed token1,
        uint256 v3Price,
        uint256 v4Price,
        bool v3Cheaper,
        uint256 priceDifference
    );

    /// @notice Emitted when the best route is selected among v3, v4, and Juicebox
    event BestRouteSelected(
        PoolId indexed poolId,
        string routeType, // "v3", "v4", or "juicebox"
        uint256 expectedTokens,
        uint256 savings
    );

    //*********************************************************************//
    // -------------------------- constructor ---------------------------- //
    //*********************************************************************//

    /// @param poolManager The Uniswap v4 pool manager
    /// @param tokens The Juicebox tokens contract
    /// @param directory The Juicebox directory
    /// @param controller The Juicebox controller
    /// @param prices The Juicebox prices contract for currency conversion
    /// @param terminalStore The Juicebox terminal store for getting reclaimable surplus
    /// @param v3Factory The Uniswap v3 factory for v3 pool lookups
    constructor(
        IPoolManager poolManager,
        IJBTokens tokens,
        IJBDirectory directory,
        IJBController controller,
        IJBPrices prices,
        IJBTerminalStore terminalStore,
        IUniswapV3Factory v3Factory
    ) BaseHook(poolManager) {
        TOKENS = tokens;
        DIRECTORY = directory;
        CONTROLLER = controller;
        PRICES = prices;
        TERMINAL_STORE = terminalStore;
        V3_FACTORY = v3Factory;
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
            afterInitialize: true, // Initialize oracle observations
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true, // Record oracle observations
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
        try CONTROLLER.currentRulesetOf(
            projectId
        ) returns (JBRuleset memory ruleset, JBRulesetMetadata memory metadata) {
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

        if (paymentToken == JB_NATIVE_TOKEN) {
            // For native ETH, use Juicebox's native token address for currency ID
            paymentTokenDecimals = 18; // ETH has 18 decimals
        } else {
            // Get the decimals of the payment token
            try IERC20Metadata(paymentToken).decimals() returns (uint8 decimals) {
                paymentTokenDecimals = decimals;
            } catch {
                // If we can't get decimals, assume 18
                paymentTokenDecimals = 18;
            }
        }

        // Get the price: how much baseCurrency per 1 unit of payment token
        // pricePerUnitOf returns the pricingCurrency cost for one unit of unitCurrency
        // So: pricePerUnitOf(projectId, baseCurrency, paymentCurrencyId, 18) returns baseCurrency cost for 1 unit of paymentCurrencyId
        // The result is scaled by 10^decimals (18 in this case)
        uint256 baseCurrencyPerPaymentToken;
        // If payment currency is the same as base currency, use 1:1 conversion
        // Special case: JB_NATIVE_TOKEN (0xEEEe) represents ETH, same as baseCurrency = 1
        // Since paymentToken is already converted to JB_NATIVE_TOKEN if it was address(0),
        // we need to check if both represent ETH (paymentToken == JB_NATIVE_TOKEN && baseCurrency == 1)
        // OR if the currency IDs match (paymentCurrencyId == baseCurrency)
        if (paymentCurrencyId == baseCurrency) {
            // Same currency IDs - direct match
            baseCurrencyPerPaymentToken = 1e18;
        } else if (paymentToken == JB_NATIVE_TOKEN && baseCurrency == 1) {
            // Both represent ETH but have different IDs (0xeeee vs 1)
            baseCurrencyPerPaymentToken = 1e18;
        } else {
            // Different currencies - need price conversion
            try PRICES.pricePerUnitOf(projectId, baseCurrency, paymentCurrencyId, 18) returns (uint256 price) {
                baseCurrencyPerPaymentToken = price;
            } catch {
                return 0;
            }
        }

        // Calculate tokens based on the payment amount and weight
        // Formula: expectedTokens = (tokensPerBaseCurrency * paymentAmount * baseCurrencyPerPaymentToken) / (1e18 * paymentTokenDecimals)
        // This converts paymentAmount to baseCurrency, then multiplies by tokensPerBaseCurrency
        // Use FullMath for safe multiplication to prevent overflow

        if (paymentTokenDecimals == 18) {
            // If baseCurrencyPerPaymentToken is 1e18 (1:1 conversion), simplify the calculation
            if (baseCurrencyPerPaymentToken == 1e18) {
                // Direct calculation: (weight * paymentAmount) / 1e18
                expectedTokens = FullMath.mulDiv(tokensPerBaseCurrency, paymentAmount, 1e18);
            } else {
                // First multiply tokensPerBaseCurrency and paymentAmount
                uint256 intermediate = FullMath.mulDiv(tokensPerBaseCurrency, paymentAmount, 1e18);
                // Then multiply by baseCurrencyPerPaymentToken and divide by 1e18
                expectedTokens = FullMath.mulDiv(intermediate, baseCurrencyPerPaymentToken, 1e18);
            }
        } else {
            // Convert paymentAmount to 18 decimals first
            uint256 paymentAmount18 = (paymentAmount * 1e18) / (10 ** paymentTokenDecimals);
            // Use FullMath for safe multiplication
            if (baseCurrencyPerPaymentToken == 1e18) {
                // Direct calculation when conversion is 1:1
                expectedTokens = FullMath.mulDiv(tokensPerBaseCurrency, paymentAmount18, 1e18);
            } else {
                uint256 intermediate = FullMath.mulDiv(tokensPerBaseCurrency, paymentAmount18, 1e18);
                expectedTokens = FullMath.mulDiv(intermediate, baseCurrencyPerPaymentToken, 1e18);
            }
        }
    }

    /// @notice Calculate expected output from selling JB tokens
    /// @param projectId The Juicebox project ID
    /// @param tokenAmountIn The amount of JB tokens being sold
    /// @param outputToken The token to receive (e.g., ETH, USDC)
    /// @return expectedOutput The expected amount of output tokens received
    function calculateExpectedOutputFromSelling(uint256 projectId, uint256 tokenAmountIn, address outputToken)
        public
        view
        returns (uint256 expectedOutput)
    {
        uint256 decimals;
        try IERC20Metadata(outputToken).decimals() returns (uint8 tokenDecimals) {
            decimals = tokenDecimals;
        } catch {
            decimals = 18;
        }

        // Get the current reclaimable surplus for the project
        // This represents how much value can be reclaimed for the given token amount
        return TERMINAL_STORE.currentReclaimableSurplusOf(
            projectId,
            tokenAmountIn,
            uint32(uint160(outputToken)), // the currency id of the output token
            decimals
        );
    }

    /// @notice Estimate expected output tokens from a Uniswap swap using TWAP
    /// @dev Uses time-weighted average price to prevent manipulation
    /// @param poolId The pool ID
    /// @param key The pool key
    /// @param amountIn The input amount
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return estimatedOut The estimated output amount
    function estimateUniswapOutput(PoolId poolId, PoolKey memory key, uint256 amountIn, bool zeroForOne)
        public
        view
        returns (uint256 estimatedOut)
    {
        // Get TWAP price instead of spot price to prevent manipulation
        uint160 sqrtPriceX96TWAP = _getTWAPSqrtPrice(poolId);

        // If TWAP is not available (not enough observations), fallback to spot price
        if (sqrtPriceX96TWAP == 0) {
            (sqrtPriceX96TWAP,,,) = poolManager.getSlot0(poolId);
        }

        // Calculate Q192 = 2^192
        uint256 Q192 = uint256(FixedPoint96.Q96) * FixedPoint96.Q96;
        uint256 priceSquared = uint256(sqrtPriceX96TWAP) * sqrtPriceX96TWAP;

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

        // Apply fee from pool key
        // fee is in hundredths of a bip, so 3000 = 0.3%
        if (key.fee > 0) {
            estimatedOut = estimatedOut - FullMath.mulDiv(estimatedOut, key.fee, 1000000);
        }

        return estimatedOut;
    }

    /// @notice Get the TWAP sqrt price for a pool
    /// @param poolId The pool ID
    /// @return sqrtPriceX96 The TWAP sqrt price, or 0 if not enough observations
    function _getTWAPSqrtPrice(PoolId poolId) internal view returns (uint160) {
        ObservationState memory state = states[poolId];

        // Need at least 2 observations for TWAP
        if (state.cardinality < 2) {
            return 0;
        }

        // Get current pool state for observation
        (, int24 tick,, uint128 liquidity) = poolManager.getSlot0(poolId);

        uint32 currentTime = uint32(block.timestamp);

        // Calculate the target time (TWAP_PERIOD seconds ago)
        uint32 oldestAllowedTime = currentTime > TWAP_PERIOD ? currentTime - TWAP_PERIOD : 0;

        // Get oldest observation timestamp
        Oracle.Observation memory oldestObs = observations[poolId][(state.index + 1) % state.cardinality];
        if (!oldestObs.initialized) {
            oldestObs = observations[poolId][0];
        }

        // If we don't have observations old enough, return 0
        if (oldestObs.blockTimestamp > oldestAllowedTime) {
            return 0;
        }

        // Observe the TWAP
        int24 arithmeticMeanTick =
            this.observeTWAP(poolId, TWAP_PERIOD, tick, state.index, liquidity, state.cardinality);

        // Convert tick to sqrtPriceX96
        return TickMath.getSqrtPriceAtTick(arithmeticMeanTick);
    }

    /// @notice Observe TWAP tick
    /// @param poolId The pool ID
    /// @param secondsAgo Seconds in the past to calculate TWAP from
    /// @param tick Current tick
    /// @param index Current observation index
    /// @param liquidity Current liquidity
    /// @param cardinality Current cardinality
    /// @return arithmeticMeanTick The time-weighted average tick
    function observeTWAP(
        PoolId poolId,
        uint32 secondsAgo,
        int24 tick,
        uint16 index,
        uint128 liquidity,
        uint16 cardinality
    ) external view returns (int24 arithmeticMeanTick) {
        uint32 currentTime = uint32(block.timestamp);

        // Get tick cumulative for current time
        (int48 tickCumulativeCurrent,) =
            observations[poolId].observeSingle(currentTime, 0, tick, index, liquidity, cardinality);

        // Get tick cumulative for secondsAgo
        (int48 tickCumulativePast,) =
            observations[poolId].observeSingle(currentTime, secondsAgo, tick, index, liquidity, cardinality);

        // Calculate arithmetic mean tick
        arithmeticMeanTick = int24((tickCumulativeCurrent - tickCumulativePast) / int48(uint48(secondsAgo)));
    }

    /// @notice Estimate expected output tokens from a Uniswap v3 swap using TWAP
    /// @dev Uses sophisticated TWAP calculation with slippage protection
    /// @param token0 First token in the pair
    /// @param token1 Second token in the pair
    /// @param amountIn The input amount
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return estimatedOut The estimated output amount
    function estimateUniswapV3Output(address token0, address token1, uint256 amountIn, bool zeroForOne)
        external
        view
        returns (uint256 estimatedOut)
    {
        // Use _getQuote which handles the factory call internally
        // For _getQuote: (projectToken, amountIn, terminalToken) -> amountOut
        // When zeroForOne=true: swapping token0->token1, so token0 is input, token1 is output
        //   We want: how many token1 do we get for token0? So projectToken=token1, terminalToken=token0
        // When zeroForOne=false: swapping token1->token0, so token1 is input, token0 is output
        //   We want: how many token0 do we get for token1? So projectToken=token0, terminalToken=token1
        address inputToken = zeroForOne ? token0 : token1;
        address outputToken = zeroForOne ? token1 : token0;
        estimatedOut = _getQuote(0, outputToken, amountIn, inputToken);
        return estimatedOut;
    }

    /// @notice Get a quote based on the TWAP, using the TWAP window and slippage tolerance for the specified project.
    /// @param projectId The ID of the project which the swap is associated with.
    /// @param projectToken The project token being swapped for.
    /// @param amountIn The number of terminal tokens being used to swap.
    /// @param terminalToken The terminal token being paid in and used to swap.
    /// @return amountOut The minimum number of tokens to receive based on the TWAP and its params.
    function _getQuote(uint256 projectId, address projectToken, uint256 amountIn, address terminalToken)
        internal
        view
        returns (uint256 amountOut)
    {
        // Get a reference to the pool that'll be used to make the swap.
        address v3Pool;
        try V3_FACTORY.getPool(projectToken, terminalToken, 10000) returns (address poolAddr) {
            v3Pool = poolAddr;
        } catch {
            return 0;
        }

        // Make sure the pool exists, if not, return an empty quote.
        if (v3Pool == address(0)) return 0;

        IUniswapV3Pool pool = IUniswapV3Pool(v3Pool);

        // If there is a contract at the address, try to get the pool's slot 0.
        try pool.slot0() returns (uint160, int24, uint16, uint16, uint16, uint8, bool unlocked) {
            // If the pool hasn't been initialized, return an empty quote.
            if (!unlocked) return 0;
        } catch {
            // If the address is invalid, return an empty quote.
            return 0;
        }

        // Use the standard TWAP window
        uint256 twapWindow = STANDARD_TWAP_WINDOW;

        // If the oldest observation is younger than the TWAP window, use the oldest observation.
        uint32 oldestObservation;
        try this._getOldestObservationSecondsAgo(pool) returns (uint32 oo) {
            oldestObservation = oo;
        } catch {
            oldestObservation = 0;
        }
        if (oldestObservation < twapWindow && oldestObservation > 0) twapWindow = oldestObservation;

        // Keep a reference to the TWAP tick.
        int24 arithmeticMeanTick;

        // Keep a reference to the liquidity.
        uint128 liquidity;

        // Resolve mean tick and liquidity source
        if (oldestObservation == 0) {
            // fallback: use spot tick and current in-range liquidity
            try pool.slot0() returns (uint160, int24 tick, uint16, uint16, uint16, uint8, bool) {
                arithmeticMeanTick = tick;
                liquidity = pool.liquidity();
            } catch {
                return 0;
            }
        } else {
            try this._consult(pool, uint32(twapWindow)) returns (int24 tick, uint128 liq) {
                arithmeticMeanTick = tick;
                liquidity = liq;
            } catch {
                return 0;
            }
        }

        // If there's no liquidity, return an empty quote.
        if (liquidity == 0) return 0;

        // Calculate the slippage tolerance.
        uint256 slippageTolerance = _getSlippageTolerance({
            amountIn: amountIn,
            liquidity: liquidity,
            projectToken: projectToken,
            terminalToken: terminalToken,
            arithmeticMeanTick: arithmeticMeanTick
        });

        // If the slippage tolerance is the maximum, return an empty quote.
        if (slippageTolerance == TWAP_SLIPPAGE_DENOMINATOR) return 0;

        // Get a quote based on this TWAP tick.
        amountOut = _getQuoteAtTick({
            tick: arithmeticMeanTick, baseAmount: uint128(amountIn), baseToken: terminalToken, quoteToken: projectToken
        });

        // return the lowest acceptable return based on the TWAP and its parameters.
        amountOut -= (amountOut * slippageTolerance) / TWAP_SLIPPAGE_DENOMINATOR;
    }


    /// @notice Get the slippage tolerance for a given amount in and liquidity.
    /// @param amountIn The amount in to get the slippage tolerance for.
    /// @param liquidity The liquidity to get the slippage tolerance for.
    /// @param projectToken The project token to get the slippage tolerance for.
    /// @param terminalToken The terminal token to get the slippage tolerance for.
    /// @param arithmeticMeanTick The arithmetic mean tick to get the slippage tolerance for.
    /// @return slippageTolerance The slippage tolerance for the given amount in and liquidity.
    function _getSlippageTolerance(
        uint256 amountIn,
        uint128 liquidity,
        address projectToken,
        address terminalToken,
        int24 arithmeticMeanTick
    ) internal pure returns (uint256) {
        // Direction: is terminalToken token0?
        (address token0,) = projectToken < terminalToken ? (projectToken, terminalToken) : (terminalToken, projectToken);
        bool zeroForOne = terminalToken == token0;

        // sqrtP in Q96 from the TWAP tick
        uint160 sqrtP = TickMath.getSqrtPriceAtTick(arithmeticMeanTick);

        // If the sqrtP is 0, there's no valid price so we'll return the maximum slippage tolerance.
        if (sqrtP == 0) return TWAP_SLIPPAGE_DENOMINATOR;

        // Approximate % of range liquidity consumed by the swap (in bps)
        // Multiply by 10 to to amplify the results and prevent results on the low end from rounding to zero.
        uint256 base = FullMath.mulDiv(amountIn, 10 * TWAP_SLIPPAGE_DENOMINATOR, uint256(liquidity));

        // Stage 1 — raw estimate (bps), normalized by √P
        uint256 rawSlippageBps = zeroForOne
            ? FullMath.mulDiv(base, uint256(sqrtP), uint256(1) << 96)
            : FullMath.mulDiv(base, uint256(1) << 96, uint256(sqrtP));

        // Stage 2 — policy adjustment: map raw → adjusted using log scaling and caps
        // Higher rawSlippageBps (lower liquidity) = MORE protection. Lower rawSlippageBps = LESS protection.
        if (rawSlippageBps == 0) return UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE;
        
        // Cap very large values at reasonable maximum
        uint256 maxAllowed = rawSlippageBps > 15 * TWAP_SLIPPAGE_DENOMINATOR
            ? TWAP_SLIPPAGE_DENOMINATOR * 88 / 100
            : (rawSlippageBps > 10 * TWAP_SLIPPAGE_DENOMINATOR
                ? TWAP_SLIPPAGE_DENOMINATOR * 67 / 100
                : rawSlippageBps / 5); // Default max: 20% of input
        
        // Logarithmic scaling: Use log2 to create smooth growth with diminishing returns
        // Formula: adjusted grows logarithmically with rawSlippageBps
        // Scale rawSlippageBps to UD60x18 format (multiply by 1e18 to satisfy log2 requirement of x >= UNIT)
        uint256 scaledValue = rawSlippageBps * 1e18;
        if (scaledValue < 1e18) scaledValue = 1e18; // Ensure >= UNIT for log2
        
        UD60x18 logValue = log2(UD60x18.wrap(scaledValue));
        
        // Unwrap logValue - it's in UD60x18 format where 1 = 1e18
        // Divide by 1e18 to get the actual log2 value
        uint256 logApprox = UD60x18.unwrap(logValue) / 1e18;
        
        // Base value: minimum slippage protection (for very small raw/high liquidity)
        uint256 baseValue = UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE;
        
        // Scale factor: how much the log value contributes to the result
        // Higher scaleFactor = steeper curve (more sensitive to liquidity changes)
        uint256 scaleFactor = 800; // Adjusts the steepness of the logarithmic curve
        
        // Calculate adjusted: base + logarithmic growth
        // Higher raw (low liquidity) → larger logApprox → larger adjusted (more protection)
        // Lower raw (high liquidity) → smaller logApprox → smaller adjusted (less protection)
        uint256 adjustedSlippageBps = baseValue + (scaleFactor * logApprox) / 2;
        
        // Cap at reasonable maximum to prevent excessive slippage protection
        if (adjustedSlippageBps > maxAllowed) adjustedSlippageBps = maxAllowed;
        
        // For very small raw (high liquidity), ensure minimum sensible protection
        if (rawSlippageBps < 500 && adjustedSlippageBps < baseValue + 100) {
            adjustedSlippageBps = baseValue + (rawSlippageBps / 5);
        }
        
        return adjustedSlippageBps;
    }

    /// @notice Calculates time-weighted means of tick and liquidity for a given Uniswap V3 pool
    /// @param pool The pool that we want to observe
    /// @param secondsAgo Number of seconds in the past from which to calculate the time-weighted means
    /// @return arithmeticMeanTick The arithmetic mean tick from (block.timestamp - secondsAgo) to block.timestamp
    /// @return harmonicMeanLiquidity The harmonic mean liquidity from (block.timestamp - secondsAgo) to block.timestamp
    function _consult(IUniswapV3Pool pool, uint32 secondsAgo)
        external
        view
        returns (int24 arithmeticMeanTick, uint128 harmonicMeanLiquidity)
    {
        require(secondsAgo != 0);

        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = secondsAgo;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s) =
            pool.observe(secondsAgos);

        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        uint160 secondsPerLiquidityCumulativesDelta =
            secondsPerLiquidityCumulativeX128s[1] - secondsPerLiquidityCumulativeX128s[0];

        arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(secondsAgo)));
        // Always round to negative infinity
        if (tickCumulativesDelta < 0 && (tickCumulativesDelta % int56(uint56(secondsAgo)) != 0)) arithmeticMeanTick--;

        // We are multiplying here instead of shifting to ensure that harmonicMeanLiquidity doesn't overflow uint128
        uint192 secondsAgoX160 = uint192(secondsAgo) * type(uint160).max;
        harmonicMeanLiquidity = uint128(secondsAgoX160 / (uint192(secondsPerLiquidityCumulativesDelta) << 32));
    }

    /// @notice Given a pool, it returns the number of seconds ago of the oldest stored observation
    /// @param pool Address of Uniswap V3 pool that we want to observe
    /// @return secondsAgo The number of seconds ago of the oldest observation stored for the pool
    function _getOldestObservationSecondsAgo(IUniswapV3Pool pool) external view returns (uint32 secondsAgo) {
        (, , uint16 observationIndex, uint16 observationCardinality, , , ) = pool.slot0();
        require(observationCardinality > 0);

        (uint32 observationTimestamp, , , bool initialized) =
            pool.observations((observationIndex + 1) % observationCardinality);

        // The next index might not be initialized if the cardinality is in the process of increasing
        // In this case the oldest observation is always in index 0
        if (!initialized) {
            (observationTimestamp, , , ) = pool.observations(0);
        }

        secondsAgo = uint32(block.timestamp) - observationTimestamp;
    }

    /// @notice Given a tick and a token amount, calculates the amount of token received in exchange
    /// @param tick Tick value used to calculate the quote
    /// @param baseAmount Amount of token to be converted
    /// @param baseToken Address of an ERC20 token contract used as the baseAmount denomination
    /// @param quoteToken Address of an ERC20 token contract used as the quoteAmount denomination
    /// @return quoteAmount Amount of quoteToken received for baseAmount of baseToken
    function _getQuoteAtTick(int24 tick, uint128 baseAmount, address baseToken, address quoteToken)
        internal
        pure
        returns (uint256 quoteAmount)
    {
        uint160 sqrtRatioX96 = TickMath.getSqrtPriceAtTick(tick);

        // Calculate quoteAmount with better precision if it doesn't overflow when multiplied by itself
        if (sqrtRatioX96 <= type(uint128).max) {
            uint256 ratioX192 = uint256(sqrtRatioX96) * sqrtRatioX96;
            quoteAmount = baseToken < quoteToken
                ? FullMath.mulDiv(ratioX192, baseAmount, 1 << 192)
                : FullMath.mulDiv(1 << 192, baseAmount, ratioX192);
        } else {
            uint256 ratioX128 = FullMath.mulDiv(sqrtRatioX96, sqrtRatioX96, 1 << 64);
            quoteAmount = baseToken < quoteToken
                ? FullMath.mulDiv(ratioX128, baseAmount, 1 << 128)
                : FullMath.mulDiv(1 << 128, baseAmount, ratioX128);
        }
    }

    //*********************************************************************//
    // ---------------------- internal transactions ---------------------- //
    //*********************************************************************//

    /// @notice Hook called after pool initialization to set up oracle
    /// @param key The pool key
    /// @param tick The initial tick
    /// @return selector The function selector
    function _afterInitialize(address, PoolKey calldata key, uint160, int24 tick) internal override returns (bytes4) {
        PoolId poolId = key.toId();

        // Initialize oracle with first observation
        (uint16 cardinality, uint16 cardinalityNext) = observations[poolId].initialize(uint32(block.timestamp), tick);

        states[poolId] = ObservationState({index: 0, cardinality: cardinality, cardinalityNext: cardinalityNext});

        return BaseHook.afterInitialize.selector;
    }

    /// @notice Hook called after swap to record price observations
    /// @param key The pool key
    /// @return selector The function selector
    /// @return delta The delta to return (zero in our case)
    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, BalanceDelta, bytes calldata)
        internal
        override
        returns (bytes4, int128)
    {
        PoolId poolId = key.toId();

        // Get current pool state
        (, int24 tick,, uint128 liquidity) = poolManager.getSlot0(poolId);

        ObservationState memory state = states[poolId];

        // Write new observation
        (uint16 indexUpdated, uint16 cardinalityUpdated) = observations[poolId]
        .write(state.index, uint32(block.timestamp), tick, liquidity, state.cardinality, state.cardinalityNext);

        // Update state
        states[poolId] = ObservationState({
            index: indexUpdated, cardinality: cardinalityUpdated, cardinalityNext: state.cardinalityNext
        });

        return (BaseHook.afterSwap.selector, 0);
    }

    /// @notice Check if a token is a Juicebox project token and register it
    /// @param token The token address to check
    /// @param poolId The pool ID to register the project for
    /// @return projectId The project ID if found, 0 otherwise
    function _checkAndRegisterJuiceboxToken(address token, PoolId poolId) internal returns (uint256 projectId) {
        // Check if the token is a Juicebox project token
        try TOKENS.projectIdOf(IJBToken(token)) returns (uint256 _projectId) {
            if (_projectId != 0) {
                projectId = _projectId;
                // Cache the project ID for this pool if not already cached
                if (projectIdOf[poolId] == 0) {
                    projectIdOf[poolId] = projectId;
                }
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
    function _beforeSwap(address swapper, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        PoolId poolId = key.toId();

        // Decode the actual user address from hookData (if provided)
        // If empty hookData, no custom routing (standard Uniswap swap)
        address actualUser = address(0);
        if (hookData.length >= 32) {
            // HookData contains the router address - call msgSender() on it to get actual user
            address routerAddress = abi.decode(hookData, (address));
            try IMsgSender(routerAddress).msgSender() returns (address user) {
                actualUser = user;
            } catch {
                // Router doesn't support msgSender(), can't route to JB
                actualUser = address(0);
            }
        }

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
            // Check both input and output tokens for Juicebox projects
            projectId = _checkAndRegisterJuiceboxToken(tokenOut, poolId);
            if (projectId == 0) {
                projectId = _checkAndRegisterJuiceboxToken(tokenIn, poolId);
            }
            if (projectId == 0) {
                // No Juicebox project, proceed with normal Uniswap swap
                return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
            }
        }

        // Determine if we're buying or selling JB tokens
        bool isSellingJBToken = _checkAndRegisterJuiceboxToken(tokenIn, poolId) == projectId;
        bool isBuyingJBToken = _checkAndRegisterJuiceboxToken(tokenOut, poolId) == projectId;

        uint256 juiceboxExpectedOutput;
        uint256 uniswapExpectedOutput;
        bool juiceboxBetter = false;

        if (isBuyingJBToken) {
            // Buying JB tokens: compare Juicebox vs Uniswap for getting JB tokens
            juiceboxExpectedOutput = calculateExpectedTokensWithCurrency(projectId, tokenIn, amountIn);
            uniswapExpectedOutput = estimateUniswapOutput(poolId, key, amountIn, params.zeroForOne);
            juiceboxBetter = juiceboxExpectedOutput > uniswapExpectedOutput;
        } else if (isSellingJBToken) {
            // Selling JB tokens: compare Juicebox vs Uniswap for getting output tokens
            juiceboxExpectedOutput = calculateExpectedOutputFromSelling(projectId, amountIn, tokenOut);
            uniswapExpectedOutput = estimateUniswapOutput(poolId, key, amountIn, params.zeroForOne);
            juiceboxBetter = juiceboxExpectedOutput > uniswapExpectedOutput;
        } else {
            // No JB token involved, proceed with normal Uniswap swap
            emit RouteSelected(poolId, false, 0, 0);
            return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        // Calculate how many tokens we'd get from Uniswap v4
        uint256 uniswapV4ExpectedTokens = estimateUniswapOutput(poolId, key, amountIn, params.zeroForOne);

        // Calculate how many tokens we'd get from Uniswap v3 (10000 fee tier only)
        // Determine v3 swap direction based on token ordering (v3 uses token0 < token1)
        // For estimateUniswapV3Output, we need to pass tokens in sorted order (token0 < token1)
        address v3Token0 = tokenIn < tokenOut ? tokenIn : tokenOut;
        address v3Token1 = tokenIn < tokenOut ? tokenOut : tokenIn;
        bool v3ZeroForOne = tokenIn < tokenOut;
        uint256 uniswapV3ExpectedTokens;
        try this.estimateUniswapV3Output(v3Token0, v3Token1, amountIn, v3ZeroForOne) returns (uint256 tokens) {
            uniswapV3ExpectedTokens = tokens;
        } catch {
            uniswapV3ExpectedTokens = 0;
        }

        // Compare v3 vs v4 prices
        bool v3BetterThanV4 = uniswapV3ExpectedTokens > uniswapV4ExpectedTokens;
        emit V3PriceComparison(
            tokenIn,
            tokenOut,
            uniswapV3ExpectedTokens,
            uniswapV4ExpectedTokens,
            v3BetterThanV4,
            v3BetterThanV4
                ? uniswapV3ExpectedTokens - uniswapV4ExpectedTokens
                : uniswapV4ExpectedTokens - uniswapV3ExpectedTokens
        );

        // Determine the best option among v3, v4, and Juicebox
        uint256 bestExpectedTokens = uniswapV4ExpectedTokens;
        string memory bestRoute = "v4";
        uint256 bestSavings = 0;

        // Check if v3 is better than v4
        if (v3BetterThanV4 && uniswapV3ExpectedTokens > 0) {
            bestExpectedTokens = uniswapV3ExpectedTokens;
            bestRoute = "v3";
            bestSavings = uniswapV3ExpectedTokens - uniswapV4ExpectedTokens;
        }

        // Check if Juicebox is better than the best Uniswap option
        bool juiceboxBetterThanUniswap = juiceboxExpectedOutput > bestExpectedTokens;
        if (juiceboxBetterThanUniswap && juiceboxExpectedOutput > 0) {
            bestExpectedTokens = juiceboxExpectedOutput;
            bestRoute = "juicebox";
            bestSavings = juiceboxExpectedOutput - (v3BetterThanV4 ? uniswapV3ExpectedTokens : uniswapV4ExpectedTokens);
        }

        emit BestRouteSelected(poolId, bestRoute, bestExpectedTokens, bestSavings);

        // If Juicebox gives better output AND we have actualUser, route through Juicebox
        if (juiceboxBetterThanUniswap && juiceboxExpectedOutput > 0 && actualUser != address(0)) {
            // Execute Juicebox routing (works for both buying and selling)
            // Pass the correct isBuying flag based on which branch we came from
            bool isBuying = isBuyingJBToken; // true when buying JB tokens, false when selling
            uint256 outputReceived =
                _routeThroughJuicebox(projectId, inputCurrency, outputCurrency, amountIn, actualUser, isBuying);

            emit RouteSelected(poolId, true, outputReceived, outputReceived - bestExpectedTokens);

            // Return delta that reflects what hook did
            // The hook takes the input amount and settles the output amount
            // For both buying and selling: take inputCurrency, settle outputCurrency
            BeforeSwapDelta hookDelta = toBeforeSwapDelta(int128(uint128(amountIn)), -int128(uint128(outputReceived)));

            return (BaseHook.beforeSwap.selector, hookDelta, 0);
        }

        // If v3 is better than v4, execute the v3 swap
        if (v3BetterThanV4 && uniswapV3ExpectedTokens > 0) {
            // Execute v3 swap
            uint256 outputReceived = _routeThroughV3(tokenIn, tokenOut, amountIn, params.zeroForOne);
            
            emit RouteSelected(poolId, false, outputReceived, outputReceived - uniswapV4ExpectedTokens);
            
            // Return delta that reflects what hook did
            // The hook takes the input amount and settles the output amount
            BeforeSwapDelta hookDelta = toBeforeSwapDelta(int128(uint128(amountIn)), -int128(uint128(outputReceived)));
            
            return (BaseHook.beforeSwap.selector, hookDelta, 0);
        }

        // Proceed with normal v4 swap
        emit RouteSelected(poolId, false, uniswapV4ExpectedTokens, 0);
        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    /// @notice Routes a swap through Juicebox instead of Uniswap
    /// @dev Handles both buying and selling JB tokens through Juicebox
    /// @param projectId The Juicebox project ID
    /// @param inputCurrency The input currency (what the swapper is paying)
    /// @param outputCurrency The output currency (what the swapper receives)
    /// @param amountIn The amount of input tokens
    /// @param swapper The address of the swapper
    /// @param isBuying Whether we're buying JB tokens (true) or selling them (false)
    /// @return outputReceived The amount of output tokens received
    function _routeThroughJuicebox(
        uint256 projectId,
        Currency inputCurrency,
        Currency outputCurrency,
        uint256 amountIn,
        address swapper,
        bool isBuying
    ) internal returns (uint256 outputReceived) {
        address tokenIn = Currency.unwrap(inputCurrency);
        address tokenOut = Currency.unwrap(outputCurrency);

        // Get the primary terminal for the project
        // For buying: terminal handles tokenIn (payment token)
        // For selling: terminal handles tokenIn (JB token being redeemed)
        IJBTerminal terminal = IJBTerminal(DIRECTORY.primaryTerminalOf(projectId, tokenIn));

        // Take input from PoolManager (pre-deposited by JuiceboxSwapRouter)
        poolManager.take(inputCurrency, address(this), amountIn);

        // Approve the terminal to spend the tokens if needed
        if (!inputCurrency.isAddressZero()) {
            IERC20(tokenIn).safeIncreaseAllowance(address(terminal), amountIn);
        }

        if (isBuying) {
            // Buying JB tokens: Pay to Juicebox and receive JB tokens
            uint256 payValue = inputCurrency.isAddressZero() ? amountIn : 0;
            outputReceived = IJBMultiTerminal(address(terminal))
            .pay{
                value: payValue
            }(
                projectId,
                tokenIn,
                amountIn,
                address(this), // Tokens come to hook
                0, // No minimum tokens required
                "", // Empty memo
                bytes("") // Empty metadata
            );
        } else {
            // Selling JB tokens: Cash out JB tokens and receive output currency
            // Call the terminal's cash out function to get the output tokens
            outputReceived = IJBMultiTerminal(address(terminal))
                .cashOutTokensOf(
                    address(this), // holder (hook owns the JB tokens)
                    projectId,
                    amountIn, // cashOutCount: Amount of JB tokens to cash out
                    tokenOut, // tokenToReclaim: The output token we want to receive
                    0, // minTokensReclaimed: No minimum tokens required
                    payable(address(this)), // beneficiary (hook)
                    bytes("") // Empty metadata
                );
        }

        // Settle output back to PoolManager
        if (!outputCurrency.isAddressZero()) {
            poolManager.sync(outputCurrency);
            IERC20(tokenOut).safeTransfer(address(poolManager), outputReceived);
            poolManager.settle();
        } else {
            poolManager.settle{value: outputReceived}();
        }

        return outputReceived;
    }

    /// @notice Routes a swap through Uniswap v3 instead of v4
    /// @dev Takes input tokens from PoolManager, executes v3 swap, settles output tokens back
    /// @param tokenIn The input token address
    /// @param tokenOut The output token address
    /// @param amountIn The amount of input tokens
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return outputReceived The amount of output tokens received
    function _routeThroughV3(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        bool zeroForOne
    ) internal returns (uint256 outputReceived) {
        // Convert Uniswap native ETH to address(0) for v3 pool lookup
        address token0 = tokenIn < tokenOut ? tokenIn : tokenOut;
        address token1 = tokenIn < tokenOut ? tokenOut : tokenIn;
        
        // Get the v3 pool (10000 fee tier)
        address v3Pool = V3_FACTORY.getPool(token0, token1, 10000);
        require(v3Pool != address(0), "V3 pool not found");

        // Check pool is unlocked
        (,,,,,, bool unlocked) = IUniswapV3Pool(v3Pool).slot0();
        require(unlocked, "V3 pool locked");

        // Take input from PoolManager
        Currency inputCurrency = Currency.wrap(tokenIn);
        Currency outputCurrency = Currency.wrap(tokenOut);
        poolManager.take(inputCurrency, address(this), amountIn);

        // Determine swap direction based on token ordering
        bool swapZeroForOne = tokenIn < tokenOut;
        
        // Execute v3 swap
        // v3 swap parameters: recipient, zeroForOne, amountSpecified, sqrtPriceLimitX96, data
        // The swap will call uniswapV3SwapCallback during execution
        (int256 amount0Delta, int256 amount1Delta) = IUniswapV3Pool(v3Pool).swap(
            address(this), // recipient
            swapZeroForOne,
            int256(amountIn), // amountSpecified (positive for exact input)
            0, // sqrtPriceLimitX96 (0 = no limit)
            abi.encode(token0, token1, uint24(10000)) // data for callback validation
        );

        // Calculate output received (one of the deltas will be negative, the other positive)
        if (swapZeroForOne) {
            // Swapping token0 for token1: amount0Delta is positive (input), amount1Delta is negative (output)
            outputReceived = uint256(-amount1Delta);
        } else {
            // Swapping token1 for token0: amount1Delta is positive (input), amount0Delta is negative (output)
            outputReceived = uint256(-amount0Delta);
        }

        // Settle output back to PoolManager
        if (!outputCurrency.isAddressZero()) {
            poolManager.sync(outputCurrency);
            IERC20(tokenOut).safeTransfer(address(poolManager), outputReceived);
            poolManager.settle();
        } else {
            // Output is native ETH - settle with value
            poolManager.settle{value: outputReceived}();
        }

        return outputReceived;
    }

    /// @notice Compute the deterministic address of a Uniswap v3 pool
    /// @dev Uses CREATE2 address computation (same as Uniswap v3 factory)
    /// @param factory The v3 factory address
    /// @param token0 First token (must be < token1)
    /// @param token1 Second token (must be > token0)
    /// @param fee The fee tier
    /// @return pool The computed pool address
    function _computeV3PoolAddress(address factory, address token0, address token1, uint24 fee)
        internal
        pure
        returns (address pool)
    {
        require(token0 < token1, "Invalid token order");
        
        // Uniswap v3 pool init code hash
        bytes32 POOL_INIT_CODE_HASH = 0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54;
        
        bytes32 salt = keccak256(abi.encode(token0, token1, fee));
        bytes32 hash = keccak256(abi.encodePacked(hex"ff", factory, salt, POOL_INIT_CODE_HASH));
        
        // Convert to address (uint160 is the size of an address)
        pool = address(uint160(uint256(hash)));
    }

    /// @notice Callback for Uniswap v3 swaps
    /// @dev Called by the v3 pool during swap execution to request payment
    /// @param amount0Delta The amount of token0 that must be paid (positive) or received (negative)
    /// @param amount1Delta The amount of token1 that must be paid (positive) or received (negative)
    /// @param data Additional data containing pool info for validation
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external override {
        require(amount0Delta > 0 || amount1Delta > 0, "No swap");
        
        // Decode pool info from data
        (address token0, address token1, uint24 fee) = abi.decode(data, (address, address, uint24));
        
        // Validate callback - ensure msg.sender is a valid v3 pool from the factory
        // Check via factory's getPool method (works for both real and mock factories)
        address expectedPool = V3_FACTORY.getPool(token0, token1, fee);
        require(msg.sender == expectedPool && expectedPool != address(0), "Invalid callback");

        // Determine which token to pay (one delta will be positive)
        uint256 amountToPay;
        address tokenToPay;
        
        if (amount0Delta > 0) {
            amountToPay = uint256(amount0Delta);
            tokenToPay = token0;
        } else {
            amountToPay = uint256(amount1Delta);
            tokenToPay = token1;
        }

        // Transfer the required amount to the pool
        // The tokens should already be in this contract from the take() call
        IERC20(tokenToPay).safeTransfer(msg.sender, amountToPay);
    }
}

