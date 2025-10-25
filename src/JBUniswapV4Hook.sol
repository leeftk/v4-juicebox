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

    /// @notice Native ETH address representation
    address public constant UNISWAP_NATIVE_ETH = address(0);

    /// @notice Juicebox native token address
    address public constant JB_NATIVE_TOKEN = address(0x000000000000000000000000000000000000EEEe);

    /// @notice TWAP period in seconds (30 minutes by default)
    uint32 public constant TWAP_PERIOD = 1800;

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

    //*********************************************************************//
    // -------------------------- constructor ---------------------------- //
    //*********************************************************************//

    /// @param poolManager The Uniswap v4 pool manager
    /// @param tokens The Juicebox tokens contract
    /// @param directory The Juicebox directory
    /// @param controller The Juicebox controller
    /// @param prices The Juicebox prices contract for currency conversion
    /// @param terminalStore The Juicebox terminal store for getting reclaimable surplus
    constructor(
        IPoolManager poolManager,
        IJBTokens tokens,
        IJBDirectory directory,
        IJBController controller,
        IJBPrices prices,
        IJBTerminalStore terminalStore
    ) BaseHook(poolManager) {
        TOKENS = tokens;
        DIRECTORY = directory;
        CONTROLLER = controller;
        PRICES = prices;
        TERMINAL_STORE = terminalStore;
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
        
        if (paymentToken == UNISWAP_NATIVE_ETH) {
            // For native ETH, use Juicebox's native token address for currency ID
            paymentCurrencyId = uint32(uint160(JB_NATIVE_TOKEN));
            paymentTokenDecimals = 18; // ETH has 18 decimals
        } else {
            // For ERC20 tokens, use the token address directly
            paymentCurrencyId = uint32(uint160(paymentToken));
            
            // Get the decimals of the payment token
            try IERC20Metadata(paymentToken).decimals() returns (uint8 decimals) {
                paymentTokenDecimals = decimals;
            } catch {
                // If we can't get decimals, assume 18
                paymentTokenDecimals = 18;
            }
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

    /// @notice Calculate expected output from selling JB tokens
    /// @param projectId The Juicebox project ID
    /// @param tokenAmount The amount of JB tokens being sold
    /// @param outputToken The token to receive (e.g., ETH, USDC)
    /// @return expectedOutput The expected amount of output tokens received
    function calculateExpectedOutputFromSelling(
        uint256 projectId,
        uint256 tokenAmount,
        address outputToken
    ) public view returns (uint256 expectedOutput) {
        // Get the current reclaimable surplus for the project
        // This represents how much value can be reclaimed per token
        uint256 surplus = TERMINAL_STORE.currentReclaimableSurplusOf(
            projectId,
            outputToken,
            1, // ETH currency
            18  // 18 decimals
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

        // If Juicebox gives better output AND we have actualUser, route through Juicebox
        if (juiceboxBetter && juiceboxExpectedOutput > 0 && actualUser != address(0)) {
            // Execute Juicebox routing (works for both buying and selling)
            // Pass the correct isBuying flag based on which branch we came from
            bool isBuying = isBuyingJBToken; // true when buying JB tokens, false when selling
            uint256 outputReceived = _routeThroughJuicebox(projectId, inputCurrency, outputCurrency, amountIn, actualUser, isBuying);
            
            emit RouteSelected(poolId, true, outputReceived, outputReceived - uniswapExpectedOutput);
            
            // Return delta that reflects what hook did
            // The hook takes the input amount and settles the output amount
            // For both buying and selling: take inputCurrency, settle outputCurrency
            BeforeSwapDelta hookDelta = toBeforeSwapDelta(int128(uint128(amountIn)), -int128(uint128(outputReceived)));
            
            return (BaseHook.beforeSwap.selector, hookDelta, 0);
        }

        // Uniswap gives better output, proceed with normal swap
        emit RouteSelected(poolId, false, 0, 0);
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
            outputReceived = IJBMultiTerminal(terminal).pay{
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
                outputReceived = IJBMultiTerminal(terminal).redeemTokensOf(
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

