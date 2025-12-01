# Untested Areas in JBUniswapV4Hook

This document identifies areas of the codebase that are currently untested or have insufficient test coverage.

## 1. Error Conditions & Reverts

### 1.1 Exact Output Swaps Not Supported
- **Location**: `_beforeSwap()` line 965
- **Error**: `JBUniswapV4Hook_ExactOutputSwapsNotSupported()`
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify that exact-output swaps (amountSpecified > 0) revert with this error

### 1.2 V3 Pool Not Found
- **Location**: `_routeThroughV3()` line 1165
- **Error**: `require(v3Pool != address(0), "V3 pool not found")`
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: When v3 pool doesn't exist, routing should revert

### 1.3 V3 Pool Locked
- **Location**: `_routeThroughV3()` line 1169
- **Error**: `require(unlocked, "V3 pool locked")`
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: When v3 pool is locked, routing should revert

### 1.4 UniswapV3SwapCallback Errors
- **Location**: `uniswapV3SwapCallback()` lines 1228, 1236
- **Errors**: 
  - `require(amount0Delta > 0 || amount1Delta > 0, "No swap")` - when both deltas are <= 0
  - `require(msg.sender == expectedPool && expectedPool != address(0), "Invalid callback")` - invalid callback sender
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: 
  - Test callback with both deltas <= 0
  - Test callback from invalid sender (not a valid v3 pool)
  - Test callback with expectedPool == address(0)

### 1.5 _consult() Error
- **Location**: `_consult()` line 620
- **Error**: `require(secondsAgo != 0)`
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Calling `_consult()` with `secondsAgo == 0` should revert

### 1.6 _getOldestObservationSecondsAgo() Error
- **Location**: `_getOldestObservationSecondsAgo()` line 647
- **Error**: `require(observationCardinality > 0)`
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Calling with pool that has cardinality == 0 should revert

## 2. Slippage Tolerance Edge Cases

### 2.1 Zero sqrtP
- **Location**: `_getSlippageTolerance()` line 546
- **Behavior**: Returns `TWAP_SLIPPAGE_DENOMINATOR` (100%) when sqrtP == 0
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify maximum slippage tolerance is returned when sqrtP is 0

### 2.2 Zero rawSlippageBps
- **Location**: `_getSlippageTolerance()` line 559
- **Behavior**: Returns `UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE` when rawSlippageBps == 0
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify base tolerance is returned when rawSlippageBps is 0

### 2.3 Very Large rawSlippageBps (> 15 * TWAP_SLIPPAGE_DENOMINATOR)
- **Location**: `_getSlippageTolerance()` lines 563-567
- **Behavior**: Caps at 88% of TWAP_SLIPPAGE_DENOMINATOR
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify capping behavior for very large raw values

### 2.4 Large rawSlippageBps (> 10 * TWAP_SLIPPAGE_DENOMINATOR)
- **Location**: `_getSlippageTolerance()` lines 565-566
- **Behavior**: Caps at 67% of TWAP_SLIPPAGE_DENOMINATOR
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify capping behavior for large raw values

### 2.5 maxAllowed Exceeds TWAP_SLIPPAGE_DENOMINATOR
- **Location**: `_getSlippageTolerance()` lines 571-573
- **Behavior**: Safety cap to prevent exceeding 100%
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify maxAllowed is capped at TWAP_SLIPPAGE_DENOMINATOR

### 2.6 adjustedSlippageBps > maxAllowed
- **Location**: `_getSlippageTolerance()` line 600
- **Behavior**: Caps adjustedSlippageBps at maxAllowed
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify adjusted value is capped when it exceeds maxAllowed

### 2.7 Very Small rawSlippageBps (< 500)
- **Location**: `_getSlippageTolerance()` lines 603-605
- **Behavior**: Ensures minimum sensible protection for high liquidity scenarios
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify minimum protection is applied for very small raw values

### 2.8 Slippage Tolerance at Maximum
- **Location**: `_getQuote()` line 507
- **Behavior**: Returns 0 when slippageTolerance >= TWAP_SLIPPAGE_DENOMINATOR
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify empty quote is returned when slippage tolerance is at maximum

### 2.9 Slippage Amount > amountOut
- **Location**: `_getQuote()` lines 518-520
- **Behavior**: Returns 0 to prevent underflow
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify safety check prevents underflow when slippage exceeds output

## 3. Token Normalization Edge Cases

### 3.1 WETH Normalization for Pricing
- **Location**: `_normalizeToken()` line 760
- **Behavior**: Normalizes both address(0) and WETH to JB_NATIVE_TOKEN
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More comprehensive tests for:
  - WETH normalization in price calculations
  - Edge cases where WETH is used in different contexts

### 3.2 Native ETH vs WETH in Terminal Interactions
- **Location**: `_normalizeTokenForTerminal()` line 769
- **Behavior**: Only normalizes address(0) to JB_NATIVE_TOKEN, not WETH
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: Verify WETH is NOT normalized for terminal interactions (only used in v3 routing)

### 3.3 V3 Token Conversion Edge Cases
- **Location**: `_convertToV3Token()` line 777
- **Behavior**: Converts address(0) to WETH for v3 operations
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More edge cases:
  - What happens when WETH itself is passed?
  - What happens with other tokens?

## 4. Price Calculation Edge Cases

### 4.1 currentRulesetOf() Fails
- **Location**: `calculateExpectedTokensWithCurrency()` lines 238-247
- **Behavior**: Returns 0 when ruleset lookup fails
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More comprehensive error scenarios:
  - Invalid project ID
  - Contract call failures
  - Reentrancy scenarios

### 4.2 pricePerUnitOf() Fails
- **Location**: `calculateExpectedTokensWithCurrency()` lines 274-278
- **Behavior**: Returns 0 when price lookup fails
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More edge cases:
  - Missing price feed
  - Invalid currency IDs
  - Price feed returns 0

### 4.3 Same Currency ID Matching
- **Location**: `calculateExpectedTokensWithCurrency()` lines 266-272
- **Behavior**: Handles both direct currency ID match and JB_NATIVE_TOKEN + baseCurrency == 1
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More edge cases for currency matching logic

### 4.4 Reserved Percent Edge Cases
- **Location**: `calculateExpectedTokensWithCurrency()` lines 292-300
- **Behavior**: Applies reserved percent when > 0
- **Status**: ✅ **TESTED** (testCalculateExpectedTokensWithReservedPercent)
- **Test Needed**: Edge cases:
  - Reserved percent == MAX_RESERVED_PERCENT (should return 0)
  - Reserved percent > MAX_RESERVED_PERCENT (should handle gracefully)

## 5. Oracle Observation Edge Cases

### 5.1 Cardinality Growth Edge Cases
- **Location**: `_recordObservation()` lines 884-893
- **Behavior**: Auto-grows cardinality when at capacity
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Cardinality growth at different thresholds (128, 256)
  - Cardinality already at maximum
  - Multiple rapid observations triggering growth

### 5.2 Observation Wrapping
- **Location**: `_recordObservation()` line 715
- **Behavior**: Handles observation index wrapping
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More comprehensive wrapping scenarios

### 5.3 TWAP Not Available (Not Enough Observations)
- **Location**: `_getTWAPSqrtPrice()` lines 699-700, 721-723
- **Behavior**: Returns 0 when cardinality < 2 or observations not old enough
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More edge cases:
  - Exactly 1 observation
  - Observations exist but too recent
  - Oldest observation not initialized

### 5.4 TWAP Fallback to Spot Price
- **Location**: `estimateUniswapOutput()` lines 342-344
- **Behavior**: Falls back to spot price when TWAP unavailable
- **Status**: ✅ **TESTED** (testTWAPFallbackToSpot)
- **Test Needed**: Edge cases where spot price is also unavailable

## 6. Routing Logic Edge Cases

### 6.1 Terminal Not Available
- **Location**: `_beforeSwap()` lines 1037-1039
- **Behavior**: Checks if terminal exists and has code
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Terminal address exists but has no code
  - Terminal lookup fails
  - Terminal exists but returns address(0)

### 6.2 Juicebox Output == 0
- **Location**: `_beforeSwap()` lines 1041-1044
- **Behavior**: Only routes to Juicebox if output > 0
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: Verify routing doesn't happen when output is 0

### 6.3 V3 Output == 0
- **Location**: `_beforeSwap()` lines 1013-1017, 1027-1030
- **Behavior**: Handles v3 estimation failures gracefully
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More edge cases when v3 estimation returns 0

### 6.4 Equal Prices (V3 == V4)
- **Location**: `_beforeSwap()` lines 1019-1020
- **Behavior**: Prefers v4 when prices are equal
- **Status**: ✅ **TESTED** (testV3RoutingWhenPricesEqual)
- **Test Needed**: Edge case where all three routes have equal prices

## 7. V3 Routing Edge Cases

### 7.1 ETH Wrapping/Unwrapping Failures
- **Location**: `_routeThroughV3()` lines 1181-1183, 1210-1212
- **Behavior**: Wraps ETH to WETH for v3, unwraps for output
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - WETH deposit fails
  - WETH withdraw fails
  - Insufficient balance scenarios

### 7.2 V3 Swap Callback Edge Cases
- **Location**: `uniswapV3SwapCallback()` lines 1242-1248
- **Behavior**: Determines which token to pay based on deltas
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Both deltas positive (shouldn't happen, but test anyway)
  - Token transfer failures
  - Insufficient balance in hook contract

## 8. Juicebox Routing Edge Cases

### 8.1 Terminal.pay() Failures
- **Location**: `_routeThroughJuicebox()` lines 1113-1121
- **Behavior**: Calls terminal.pay() for buying JB tokens
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Terminal.pay() reverts
  - Terminal.pay() returns 0
  - Approval failures

### 8.2 Terminal.cashOutTokensOf() Failures
- **Location**: `_routeThroughJuicebox()` lines 1127-1136
- **Behavior**: Calls terminal.cashOutTokensOf() for selling JB tokens
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Terminal.cashOutTokensOf() reverts
  - Terminal.cashOutTokensOf() returns 0
  - Insufficient JB token balance in hook

### 8.3 Native ETH Payment Handling
- **Location**: `_routeThroughJuicebox()` line 1112
- **Behavior**: Handles native ETH payments with value
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Incorrect value sent
  - Value sent when not needed
  - Value not sent when needed

## 9. Token Decimal Edge Cases

### 9.1 _getTokenDecimals() Failures
- **Location**: `_getTokenDecimals()` lines 787-790
- **Behavior**: Defaults to 18 decimals on failure
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Token contract doesn't exist
  - Token contract doesn't implement decimals()
  - Token contract reverts on decimals() call

### 9.2 Non-18 Decimal Tokens
- **Location**: `_calculateTokensWithCurrency()` lines 808-809
- **Behavior**: Normalizes payment amount to 18 decimals
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Tokens with 6 decimals (USDC)
  - Tokens with 8 decimals (WBTC)
  - Tokens with 0 decimals
  - Tokens with > 18 decimals (shouldn't exist, but test)

## 10. Quote Calculation Edge Cases

### 10.1 _getQuote() Pool Not Found
- **Location**: `_getQuote()` lines 438-442, 445
- **Behavior**: Returns 0 when pool doesn't exist
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More edge cases for pool lookup failures

### 10.2 _getQuote() Pool Not Initialized
- **Location**: `_getQuote()` lines 450-456
- **Behavior**: Returns 0 when pool not initialized or invalid
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More edge cases for uninitialized pools

### 10.3 _getQuote() No Liquidity
- **Location**: `_getQuote()` line 495
- **Behavior**: Returns 0 when liquidity is 0
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: Verify behavior when pool exists but has no liquidity

### 10.4 _getQuote() Oldest Observation Edge Cases
- **Location**: `_getQuote()` lines 462-468
- **Behavior**: Adjusts TWAP window based on oldest observation
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: 
  - Oldest observation == 0 (fallback to spot)
  - Oldest observation < TWAP window
  - _getOldestObservationSecondsAgo() fails

### 10.5 _getQuote() _consult() Failures
- **Location**: `_getQuote()` lines 486-491
- **Behavior**: Falls back to spot price when _consult() fails
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: More edge cases for _consult() failures

## 11. Integration Edge Cases

### 11.1 Multiple Rapid Swaps
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify hook handles multiple rapid swaps correctly:
  - Oracle observations update correctly
  - Routing decisions remain consistent
  - No state corruption

### 11.2 Reentrancy Scenarios
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify hook is safe from reentrancy:
  - During terminal.pay() calls
  - During terminal.cashOutTokensOf() calls
  - During v3 swap callbacks

### 11.3 Gas Optimization Edge Cases
- **Status**: ❌ **NOT TESTED**
- **Test Needed**: Verify gas usage is reasonable:
  - Large cardinality observations
  - Complex routing decisions
  - Multiple route comparisons

## 12. Constants & Configuration

### 12.1 TWAP_PERIOD Constant
- **Location**: Line 125
- **Value**: 1800 seconds (30 minutes)
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: Verify TWAP calculations use this constant correctly

### 12.2 STANDARD_TWAP_WINDOW Constant
- **Location**: Line 128
- **Value**: 1 hours
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: Verify v3 quote calculations use this window

### 12.3 UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE Constant
- **Location**: Line 138
- **Value**: 1050 (10.5%)
- **Status**: ⚠️ **PARTIALLY TESTED**
- **Test Needed**: Verify this is used correctly in edge cases

## Summary

- **Critical Missing Tests**: 6 (error conditions that should revert)
- **Important Missing Tests**: ~30+ (edge cases in core functionality)
- **Nice-to-Have Tests**: ~15 (integration and optimization scenarios)

**Priority Areas:**
1. Error conditions and reverts (critical for security)
2. Slippage tolerance edge cases (critical for correct routing)
3. V3 callback validation (critical for security)
4. Oracle observation edge cases (important for correctness)
5. Token normalization edge cases (important for correctness)

