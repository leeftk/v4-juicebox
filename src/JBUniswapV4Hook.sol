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

// v3 oracle data is read via interface calls, no library imports needed

// Import Oracle library for TWAP
import {Oracle} from "./libraries/Oracle.sol";

// Import Juicebox protocol interfaces
import {IJBTokens} from "./interfaces/IJBTokens.sol";
import {IJBToken} from "./interfaces/IJBToken.sol";
import {IJBDirectory} from "./interfaces/IJBDirectory.sol";
import {IJBMultiTerminal} from "./interfaces/IJBMultiTerminal.sol";
import {IJBController} from "./interfaces/IJBController.sol";

import {IJBPrices} from "./interfaces/IJBPrices.sol";
import {IJBTerminalStore} from "./interfaces/IJBTerminalStore.sol";

import {JBRuleset} from "./structs/JBRuleset.sol";
import {JBRulesetMetadata} from "./structs/JBRulesetMetadata.sol";

interface IMsgSender {
    function msgSender() external view returns (address);
}

/// @title JBUniswapV4Hook
/// @notice Official Juicebox integration for Uniswap v4 that provides price comparison and optimal routing
/// @dev This hook compares prices between Uniswap pools and Juicebox projects, then routes to the cheaper option
/// @custom:security-contact security@juicebox.money
contract JBUniswapV4Hook is BaseHook {
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
        // pricePerUnitOf returns the price of unitCurrency (paymentToken) in terms of pricingCurrency (baseCurrency)
        // The result is scaled by 10^decimals (18 in this case)
        uint256 baseCurrencyPerPaymentToken;
        try PRICES.pricePerUnitOf(projectId, paymentCurrencyId, baseCurrency, 18) returns (uint256 price) {
            baseCurrencyPerPaymentToken = price;
        } catch {
            return 0;
        }

        // Calculate tokens based on the payment amount and weight
        // Formula: expectedTokens = (tokensPerBaseCurrency * paymentAmount * baseCurrencyPerPaymentToken) / (1e18 * paymentTokenDecimals)
        // This converts paymentAmount to baseCurrency, then multiplies by tokensPerBaseCurrency
        // Use FullMath for safe multiplication to prevent overflow

        if (paymentTokenDecimals == 18) {
            // For 18-decimal tokens, use FullMath to safely multiply three numbers
            // First multiply tokensPerBaseCurrency and paymentAmount
            uint256 intermediate = FullMath.mulDiv(tokensPerBaseCurrency, paymentAmount, 1e18);
            // Then multiply by baseCurrencyPerPaymentToken and divide by 1e18
            expectedTokens = FullMath.mulDiv(intermediate, baseCurrencyPerPaymentToken, 1e18);
        } else {
            // Convert paymentAmount to 18 decimals first
            uint256 paymentAmount18 = (paymentAmount * 1e18) / (10 ** paymentTokenDecimals);
            // Use FullMath for safe multiplication
            uint256 intermediate = FullMath.mulDiv(tokensPerBaseCurrency, paymentAmount18, 1e18);
            expectedTokens = FullMath.mulDiv(intermediate, baseCurrencyPerPaymentToken, 1e18);
        }
    }

    /// @notice Calculate expected output from selling JB tokens
    /// @param projectId The Juicebox project ID
    /// @param tokenAmount The amount of JB tokens being sold
    /// @param outputToken The token to receive (e.g., ETH, USDC)
    /// @return expectedOutput The expected amount of output tokens received
    function calculateExpectedOutputFromSelling(uint256 projectId, uint256 tokenAmount, address outputToken)
        public
        view
        returns (uint256 expectedOutput)
    {
        // Get the current reclaimable surplus for the project
        // This represents how much value can be reclaimed per token
        uint256 surplus = TERMINAL_STORE.currentReclaimableSurplusOf(
            projectId,
            outputToken,
            1, // ETH currency
            18 // 18 decimals
        );

        // Calculate expected output based on surplus per token
        // surplus is the total reclaimable value, we need to calculate per token
        // This is a simplified calculation - in practice, you'd need to get the total token supply
        // and calculate the per-token value
        expectedOutput = (surplus * tokenAmount) / 1e18;
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
        // Pass the tokens in the correct order for the quote
        estimatedOut = _getQuote(0, zeroForOne ? token1 : token0, amountIn, zeroForOne ? token0 : token1);
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

        // Compute final slippage tolerance (bps), normalized by √P
        uint256 slippageTolerance = zeroForOne
            ? FullMath.mulDiv(base, uint256(sqrtP), uint256(1) << 96)
            : FullMath.mulDiv(base, uint256(1) << 96, uint256(sqrtP));

        // Adjust the slippage tolerance to be reasonable given the ranges.
        if (slippageTolerance > 15 * TWAP_SLIPPAGE_DENOMINATOR) return TWAP_SLIPPAGE_DENOMINATOR * 88 / 100;
        else if (slippageTolerance > 10 * TWAP_SLIPPAGE_DENOMINATOR) return TWAP_SLIPPAGE_DENOMINATOR * 67 / 100;
        else if (slippageTolerance > 30_000) return slippageTolerance / 12;
        else if (slippageTolerance > 15_000) return slippageTolerance / 10;
        else if (slippageTolerance > 10_000) return slippageTolerance * 2 / 15;
        else if (slippageTolerance > 5000) return slippageTolerance * 3 / 20;
        else if (slippageTolerance > 1500) return slippageTolerance / 5;
        else if (slippageTolerance > 500) return (slippageTolerance / 5) + 200;
        else if (slippageTolerance > 0) return (slippageTolerance / 5) + 100;
        else return UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE;
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
        uint256 uniswapV3ExpectedTokens;
        try this.estimateUniswapV3Output(tokenIn, tokenOut, amountIn, params.zeroForOne) returns (uint256 tokens) {
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

        // If v3 is better than v4, we can't route through v3 from a v4 hook
        // So we proceed with v4, but emit the comparison for transparency
        if (v3BetterThanV4) {
            emit RouteSelected(
                poolId, false, uniswapV4ExpectedTokens, uniswapV3ExpectedTokens - uniswapV4ExpectedTokens
            );
        } else {
            emit RouteSelected(poolId, false, uniswapV4ExpectedTokens, 0);
        }

        // Proceed with normal v4 swap
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
        address terminal = DIRECTORY.primaryTerminalOf(projectId, tokenIn);

        // Take input from PoolManager (pre-deposited by JuiceboxSwapRouter)
        poolManager.take(inputCurrency, address(this), amountIn);

        // Approve the terminal to spend the tokens if needed
        if (!inputCurrency.isAddressZero()) {
            IERC20(tokenIn).safeIncreaseAllowance(address(terminal), amountIn);
        }

        if (isBuying) {
            // Buying JB tokens: Pay to Juicebox and receive JB tokens
            uint256 payValue = inputCurrency.isAddressZero() ? amountIn : 0;
            outputReceived = IJBMultiTerminal(terminal)
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
            // Selling JB tokens: Redeem JB tokens and receive output currency
            // Calculate expected output based on surplus
            outputReceived = calculateExpectedOutputFromSelling(projectId, amountIn, tokenOut);

            // For testing purposes, we'll simulate the redemption by calling the terminal
            // In practice, you'd need to call the appropriate Juicebox redemption function
            if (outputReceived > 0) {
                // Call the terminal's redemption function to get the output tokens
                // This simulates the redemption process
                outputReceived = IJBMultiTerminal(terminal)
                    .redeemTokensOf(
                        projectId,
                        tokenOut, // The output token we want to receive
                        amountIn, // Amount of JB tokens to redeem
                        address(this), // Beneficiary (hook)
                        0, // No minimum tokens required
                        "", // Empty memo
                        bytes("") // Empty metadata
                    );
            }
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
}

