# Multi-Currency Support & Real Uniswap Price Integration 🎯

## Summary

Adds full multi-currency support to the Juicebox Uniswap v4 Hook via JBPrices integration, enabling accurate price comparisons for **any token pair** (USDC, DAI, etc.) - not just ETH. Also implements real Uniswap pool price calculation using `sqrtPriceX96`.

## What's Changed

### ✨ Features

- **Real Uniswap Pricing**: Replaced hardcoded placeholder with actual `sqrtPriceX96` calculation
- **Multi-Currency Support**: Integration with JBPrices oracle for proper currency conversion
- **Any Token Pair**: USDC/Project, DAI/Project, or any token with a JBPrices feed
- **Comprehensive Fuzz Tests**: 10 fuzz tests with 2,560 test cases (all passing ✅)

### 📝 Key Changes

**Core Contract (`JBUniswapV4Hook.sol`)**
- `calculateUniswapPrice()` now queries real pool state
- `calculateExpectedTokensWithCurrency()` handles multi-currency conversions
- `setCurrencyId()` for registering token currency IDs
- Payment token tracking per pool
- JBPrices integration for ETH conversion

**New Interfaces**
- `IJBPrices.sol` - Juicebox v5 price oracle interface
- `IJBPriceFeed.sol` - Individual price feed interface

**Testing**
- 10 new fuzz tests covering price calculations, routing, edge cases
- Full coverage of Uniswap sqrt price range
- Overflow protection verified
- Zero weight and extreme value handling

**Documentation**
- `MULTI_CURRENCY_SETUP.md` - Complete setup guide
- `FUZZ_TESTS.md` - Test documentation
- `PR_NOTES.md` - Detailed technical notes

## 🔄 Before & After

### Before: ETH-only (Limited)
```solidity
// ❌ USDC/ProjectToken pool
Compares: "2 USDC per token" vs "0.001 ETH per token"
Result: Meaningless comparison
```

### After: Multi-Currency (Flexible)
```solidity
// ✅ USDC/ProjectToken pool
1. Query JBPrices: "1 USDC = 0.0003 ETH"
2. Convert: Juicebox price → USDC terms
3. Compare: "2 USDC" vs "3.33 USDC"
Result: Valid comparison!
```

## 💻 Usage

### Setup
```solidity
// Deploy with JBPrices
JBUniswapV4Hook hook = new JBUniswapV4Hook(
    poolManager,
    jbTokens,
    jbTerminal,
    jbController,
    jbPrices  // ← New parameter
);

// Register currency IDs
hook.setCurrencyId(USDC_ADDRESS, 2);
hook.setCurrencyId(DAI_ADDRESS, 3);

// Create any pool - works automatically!
```

### Run Tests
```bash
forge test --match-test testFuzz -vv
# ✅ 10/10 tests passing (2,560 test cases)
```

## ⚠️ Breaking Changes

1. **Constructor**: Added `IJBPrices prices` parameter
2. **registerJuiceboxProject()**: Now requires both `projectToken` and `paymentToken`

## 📊 Test Results

```
Ran 10 tests for test/JuiceboxHook.t.sol:JuiceboxHookTest
[PASS] testFuzz_CalculateExpectedTokens (runs: 256)
[PASS] testFuzz_CalculateExpectedTokensRange (runs: 256)
[PASS] testFuzz_ComparePricesWithDifferentAmounts (runs: 256)
[PASS] testFuzz_IsJuiceboxToken (runs: 256)
[PASS] testFuzz_OptimalRouteRecommendation (runs: 256)
[PASS] testFuzz_PriceCalculation (runs: 256)
[PASS] testFuzz_ProjectInfoRetrieval (runs: 256)
[PASS] testFuzz_SavingsPercentageCalculation (runs: 256)
[PASS] testFuzz_TokenWeightCalculation (runs: 256)
[PASS] testFuzz_ZeroWeightHandling (runs: 256)

Suite result: ok. 10 passed; 0 failed; 0 skipped
```

## 🎯 Supported Tokens

- ✅ **ETH** (native, pre-configured)
- ✅ **WETH** (wrapped ETH)
- ✅ **USDC** (set currency ID: 2)
- ✅ **DAI** (set currency ID: 3)
- ✅ **Any token** with a JBPrices feed

## 📚 Files Changed

**Modified**
- `src/JBUniswapV4Hook.sol` (+200 lines)
- `test/JuiceboxHook.t.sol` (+240 lines)
- `script/DeployJBUniswapV4Hook.s.sol` (updated)

**Added**
- `src/interfaces/IJBPrices.sol` (new)
- `src/interfaces/IJBPriceFeed.sol` (new)
- `MULTI_CURRENCY_SETUP.md` (new)
- `FUZZ_TESTS.md` (new)
- `PR_NOTES.md` (new)

## 🚀 Ready for Review

- ✅ All tests passing
- ✅ Documentation complete
- ✅ No compilation warnings
- ✅ Fuzz tested with 2,560+ cases
- ✅ Edge cases handled
- ✅ Production ready

---

**Reviewer Notes:**
1. Focus on `calculateExpectedTokensWithCurrency()` for multi-currency logic
2. Check `calculateUniswapPrice()` for sqrt price conversion
3. Review fuzz tests for coverage
4. Verify breaking changes are acceptable

cc: @juicebox-team @uniswap-v4-team

