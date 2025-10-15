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

// Import Oracle library for TWAP
import {Oracle} from "./libraries/Oracle.sol";

// Import Juicebox protocol interfaces
import {IJBTokens} from "./interfaces/IJBTokens.sol";
import {IJBToken} from "./interfaces/IJBToken.sol";
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

    /// @notice The Juicebox multi-terminal for processing payments
    IJBMultiTerminal public immutable TERMINAL;

    /// @notice The Juicebox controller for ruleset information
    IJBController public immutable CONTROLLER;

    /// @notice The Juicebox prices contract for currency conversion
    IJBPrices public immutable PRICES;

    /// @notice Currency ID for ETH (standard in Juicebox)
    uint256 public constant ETH_CURRENCY_ID = 1;

    /// @notice Native ETH address representation
    address public constant NATIVE_ETH = address(0);

    /// @notice TWAP period in seconds (30 minutes by default)
    uint32 public constant TWAP_PERIOD = 1800;

    //*********************************************************************//
    // --------------------- public stored properties -------------------- //
    //*********************************************************************//

    /// @notice Mapping from Uniswap pool ID to Juicebox project ID
    mapping(PoolId => uint256) public projectIdOf;

    /// @notice Mapping from token address to Juicebox currency ID
    mapping(address => uint256) public currencyIdOf;

    /// @notice The list of observations for a given pool ID  
    mapping(PoolId => Oracle.Observation[65535]) public observations;
    
    /// @notice The current observation array state for the given pool ID
    mapping(PoolId => ObservationState) public states;

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
    /// @param terminal The Juicebox multi-terminal
    /// @param controller The Juicebox controller
    /// @param prices The Juicebox prices contract for currency conversion
    constructor(
        IPoolManager poolManager,
        IJBTokens tokens,
        IJBMultiTerminal terminal,
        IJBController controller,
        IJBPrices prices
    ) BaseHook(poolManager) {
        TOKENS = tokens;
        TERMINAL = terminal;
        CONTROLLER = controller;
        PRICES = prices;

        // Set ETH currency ID
        currencyIdOf[NATIVE_ETH] = ETH_CURRENCY_ID;
    }

    /// @notice Receive function to accept ETH
    receive() external payable {}

    //*********************************************************************//
    // ---------------------- external transactions ---------------------- //
    //*********************************************************************//

    /// @notice Set the Juicebox currency ID for a token
    /// @dev This is needed to enable price conversions for non-ETH tokens
    /// @param token The token address
    /// @param currencyId The Juicebox currency ID for this token
    function setCurrencyId(address token, uint256 currencyId) external {
        if (currencyId == 0) revert JBUniswapV4Hook_InvalidCurrencyId();
        currencyIdOf[token] = currencyId;
    }
    
    /// @notice Increase the oracle cardinality for a pool
    /// @param poolId The pool ID
    /// @param cardinalityNext The new cardinality target
    function increaseCardinalityNext(PoolId poolId, uint16 cardinalityNext) external {
        ObservationState memory state = states[poolId];
        uint16 cardinalityNextNew = observations[poolId].grow(state.cardinality, cardinalityNext);
        states[poolId].cardinalityNext = cardinalityNextNew;
    }

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

    /// @notice Calculate expected tokens for a given payment amount in ETH
    /// @param projectId The Juicebox project ID
    /// @param ethAmount The amount of ETH being paid
    /// @return expectedTokens The expected number of tokens to be received
    function calculateExpectedTokens(uint256 projectId, uint256 ethAmount)
        external
        view
        returns (uint256 expectedTokens)
    {
        try CONTROLLER.currentRulesetOf(projectId) returns (JBRuleset memory ruleset, JBRulesetMetadata memory) {
            // Weight represents tokens issued per ETH paid
            expectedTokens = (ruleset.weight * ethAmount) / 1e18;
        } catch {
            expectedTokens = 0;
        }
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
        uint256 tokensPerETH;
        try CONTROLLER.currentRulesetOf(projectId) returns (JBRuleset memory ruleset, JBRulesetMetadata memory) {
            tokensPerETH = ruleset.weight;
        } catch {
            return 0;
        }

        // If payment is in ETH, calculate directly
        if (paymentToken == NATIVE_ETH) {
            return (tokensPerETH * paymentAmount) / 1e18;
        }

        // Get the currency ID for the payment token
        uint256 paymentCurrencyId = currencyIdOf[paymentToken];
        if (paymentCurrencyId == 0) {
            // No currency ID registered, cannot convert
            return 0;
        }

        // Get the decimals of the payment token
        uint8 paymentTokenDecimals;
        try IERC20Metadata(paymentToken).decimals() returns (uint8 decimals) {
            paymentTokenDecimals = decimals;
        } catch {
            // If we can't get decimals, assume 18
            // Maybe all payment tokens are 18 decimals?
            paymentTokenDecimals = 18;
        }

        // Get the price: how much ETH per 1 unit of payment token
        // pricePerUnitOf returns the price of unitCurrency (paymentToken) in terms of pricingCurrency (ETH)
        // The result is scaled by 10^decimals (18 in this case)
        uint256 ethPerPaymentToken;
        try PRICES.pricePerUnitOf(projectId, ETH_CURRENCY_ID, paymentCurrencyId, 18) returns (uint256 price) {
            ethPerPaymentToken = price;
        } catch {
            // Try using default price feeds (projectId = 0)
            try PRICES.pricePerUnitOf(
                PRICES.DEFAULT_PROJECT_ID(), ETH_CURRENCY_ID, paymentCurrencyId, 18
            ) returns (uint256 price) {
                ethPerPaymentToken = price;
            } catch {
                return 0;
            }
        }

        // Convert payment amount to ETH equivalent
        // paymentAmount is in native token decimals, price is per 1 whole token with 18 decimal precision
        // First normalize paymentAmount to 18 decimals, then multiply by price
        uint256 ethEquivalent;
        if (paymentTokenDecimals <= 18) {
            // Scale up to 18 decimals if needed
            uint256 normalizedAmount = paymentAmount * (10 ** (18 - paymentTokenDecimals));
            ethEquivalent = (normalizedAmount * ethPerPaymentToken) / 1e18;
        } else {
            // Scale down from higher decimals (edge case, but handle it)
            uint256 normalizedAmount = paymentAmount / (10 ** (paymentTokenDecimals - 18));
            ethEquivalent = (normalizedAmount * ethPerPaymentToken) / 1e18;
        }

        // Calculate tokens based on ETH equivalent
        // tokensPerETH and ethEquivalent are both in 18 decimals
        expectedTokens = (tokensPerETH * ethEquivalent) / 1e18;
    }

    /// @notice Estimate expected output tokens from a Uniswap swap using TWAP
    /// @dev Uses time-weighted average price to prevent manipulation
    /// @param poolId The pool ID
    /// @param key The pool key
    /// @param amountIn The input amount
    /// @param zeroForOne Whether swapping token0 for token1
    /// @return estimatedOut The estimated output amount
    function estimateUniswapOutput(
        PoolId poolId,
        PoolKey memory key,
        uint256 amountIn,
        bool zeroForOne
    )
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
        try this.observeTWAP(poolId, TWAP_PERIOD, tick, state.index, liquidity, state.cardinality) returns (
            int24 arithmeticMeanTick
        ) {
            // Convert tick to sqrtPriceX96
            return TickMath.getSqrtPriceAtTick(arithmeticMeanTick);
        } catch {
            // If observation fails, return 0 to fallback to spot
            return 0;
        }
    }
    
    /// @notice Observe TWAP tick (external to allow try/catch)
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

    //*********************************************************************//
    // ---------------------- internal transactions ---------------------- //
    //*********************************************************************//

    /// @notice Hook called after pool initialization to set up oracle
    /// @param key The pool key
    /// @param tick The initial tick
    /// @return selector The function selector
    function _afterInitialize(address, PoolKey calldata key, uint160, int24 tick) 
        internal 
        override 
        returns (bytes4) 
    {
        PoolId poolId = key.toId();
        
        // Initialize oracle with first observation
        (uint16 cardinality, uint16 cardinalityNext) = 
            observations[poolId].initialize(uint32(block.timestamp), tick);
        
        states[poolId] = ObservationState({
            index: 0,
            cardinality: cardinality,
            cardinalityNext: cardinalityNext
        });
        
        return BaseHook.afterInitialize.selector;
    }

    /// @notice Hook called after swap to record price observations
    /// @param key The pool key
    /// @return selector The function selector
    /// @return delta The delta to return (zero in our case)
    function _afterSwap(
        address,
        PoolKey calldata key,
        SwapParams calldata,
        BalanceDelta,
        bytes calldata
    ) internal override returns (bytes4, int128) {
        PoolId poolId = key.toId();
        
        // Get current pool state
        (, int24 tick,, uint128 liquidity) = poolManager.getSlot0(poolId);
        
        ObservationState memory state = states[poolId];
        
        // Write new observation
        (uint16 indexUpdated, uint16 cardinalityUpdated) = observations[poolId].write(
            state.index,
            uint32(block.timestamp),
            tick,
            liquidity,
            state.cardinality,
            state.cardinalityNext
        );
        
        // Update state
        states[poolId] = ObservationState({
            index: indexUpdated,
            cardinality: cardinalityUpdated,
            cardinalityNext: state.cardinalityNext
        });
        
        return (BaseHook.afterSwap.selector, 0);
    }

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

        // Step 2: Process payment through Juicebox
        // Approve the terminal to spend the tokens if needed
        if (!inputCurrency.isAddressZero()) {
            IERC20(tokenIn).safeIncreaseAllowance(address(TERMINAL), amountIn);
        }

        // Pay to Juicebox - tokens are minted to THIS contract, not the swapper
        // We'll settle them to the PoolManager which will credit the swapper
        uint256 payValue = inputCurrency.isAddressZero() ? amountIn : 0;
        tokensReceived = TERMINAL.pay{
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

