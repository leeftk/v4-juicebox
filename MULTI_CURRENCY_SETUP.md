# Multi-Currency Support in JBUniswapV4Hook

## Overview

The `JBUniswapV4Hook` now supports **any token pair** in Uniswap v4 pools, not just ETH/WETH pairs! This is achieved through integration with Juicebox v5's `JBPrices` oracle system.

## How It Works

### The Problem It Solves

Previously, price comparisons between Uniswap and Juicebox were only valid for ETH pools because:
- Juicebox `ruleset.weight` is denominated in **"tokens per ETH"**
- Uniswap pools could use **any token pair** (USDC/Token, DAI/Token, etc.)
- Comparing "USDC per token" vs "ETH per token" is meaningless

### The Solution

The hook now:
1. Tracks the **payment token** for each pool
2. Uses **JBPrices** to convert payment token prices to ETH terms
3. Compares **apples-to-apples** (both prices in the same denomination)

## Setup Instructions

### 1. Deploy the Hook

Deploy with the `JBPrices` contract address:

```solidity
JBUniswapV4Hook hook = new JBUniswapV4Hook(
    poolManager,
    jbTokens,
    jbMultiTerminal,
    jbController,
    jbPrices  // ← JBPrices address
);
```

### 2. Register Currency IDs

For non-ETH payment tokens, register their Juicebox currency IDs:

```solidity
// Example: Register USDC (currency ID 2 in Juicebox)
hook.setCurrencyId(USDC_ADDRESS, 2);

// Example: Register DAI (currency ID 3 in Juicebox)
hook.setCurrencyId(DAI_ADDRESS, 3);
```

**Note:** ETH (address(0)) is pre-registered with currency ID 1.

### 3. Ensure Price Feeds Exist

The `JBPrices` contract must have price feeds for your tokens:

```solidity
// Check if a price feed exists
IJBPriceFeed feed = jbPrices.priceFeedFor(
    0,                  // Use default feeds
    ETH_CURRENCY_ID,    // Pricing currency (ETH)
    USDC_CURRENCY_ID    // Unit currency (USDC)
);

require(address(feed) != address(0), "No price feed");
```

If no feed exists, add one to `JBPrices`:

```solidity
jbPrices.addPriceFeedFor(
    0,                   // Project ID (0 for default)
    ETH_CURRENCY_ID,     // Pricing currency
    USDC_CURRENCY_ID,    // Unit currency
    chainlinkFeed        // Your price feed contract
);
```

## Usage Examples

### USDC/ProjectToken Pool

```solidity
// 1. Create a Uniswap pool
PoolKey memory key = PoolKey({
    currency0: Currency.wrap(USDC_ADDRESS),
    currency1: Currency.wrap(PROJECT_TOKEN),
    fee: 3000,
    tickSpacing: 60,
    hooks: IHooks(address(hook))
});

// 2. Register currency ID (one-time setup)
hook.setCurrencyId(USDC_ADDRESS, 2);

// 3. The hook automatically:
//    - Detects PROJECT_TOKEN is a Juicebox token
//    - Tracks USDC as the payment token
//    - Converts USDC price to ETH using JBPrices
//    - Compares with Juicebox price correctly!
```

### DAI/ProjectToken Pool

```solidity
// 1. Create pool
PoolKey memory key = PoolKey({
    currency0: Currency.wrap(DAI_ADDRESS),
    currency1: Currency.wrap(PROJECT_TOKEN),
    fee: 3000,
    tickSpacing: 60,
    hooks: IHooks(address(hook))
});

// 2. Register DAI currency ID
hook.setCurrencyId(DAI_ADDRESS, 3);

// 3. Works automatically!
```

### ETH/ProjectToken Pool (Still Works!)

```solidity
// No special setup needed - ETH is pre-registered
PoolKey memory key = PoolKey({
    currency0: Currency.wrap(address(0)),  // Native ETH
    currency1: Currency.wrap(PROJECT_TOKEN),
    fee: 3000,
    tickSpacing: 60,
    hooks: IHooks(address(hook))
});
```

## Price Conversion Flow

When comparing prices for a USDC/ProjectToken pool:

1. **Uniswap price:** 2 USDC per token (from `sqrtPriceX96`)
2. **Juicebox weight:** 1000 tokens per 1 ETH
3. **USDC price in ETH:** 0.0003 ETH per USDC (from JBPrices)
4. **Juicebox price in USDC:** 
   - 1 ETH = 1000 tokens
   - 0.0003 ETH = 1 USDC
   - So: 1 USDC = 0.3 tokens
   - Price per token = 1/0.3 = 3.33 USDC per token
5. **Comparison:** Uniswap (2 USDC) vs Juicebox (3.33 USDC) ✅ Valid!

## API Reference

### `setCurrencyId(address token, uint256 currencyId)`
Register a token's Juicebox currency ID.

**Parameters:**
- `token`: Token address
- `currencyId`: Juicebox currency ID (must be non-zero)

### `calculateExpectedTokensWithCurrency(uint256 projectId, address paymentToken, uint256 paymentAmount)`
Calculate expected project tokens for a payment in any currency.

**Parameters:**
- `projectId`: Juicebox project ID
- `paymentToken`: Token being used for payment
- `paymentAmount`: Amount being paid

**Returns:**
- `expectedTokens`: Number of project tokens expected

### `comparePrices(PoolId poolId, uint256 amountIn, bool zeroForOne)`
Compare Uniswap and Juicebox prices (now multi-currency aware).

**Returns:**
- `juiceboxCheaper`: Whether Juicebox offers a better price
- `priceDifference`: Absolute price difference
- `uniswapPrice`: Price per token in Uniswap
- `juiceboxPrice`: Price per token in Juicebox (converted to payment token)

## Common Currency IDs

Based on Juicebox v5 standard:
- `1` - ETH (Native)
- `2` - USD / USDC
- `3` - DAI
- (Check Juicebox docs for complete list)

## Troubleshooting

### "No price feed found"
- Ensure `JBPrices` has a feed for your token pair
- Check both project-specific and default feeds (projectId = 0)

### "Currency ID is 0"
- Call `setCurrencyId()` to register your payment token
- ETH is pre-registered and doesn't need setup

### Price comparison returns 0
- Verify the price feed is returning valid data
- Check that the currency ID mapping is correct
- Ensure the Juicebox project has a valid ruleset

## Benefits

✅ **Any ERC20 as payment** - Not limited to ETH/WETH  
✅ **Accurate price comparisons** - Proper currency conversion  
✅ **Flexible** - Works with any token that has a JBPrices feed  
✅ **Future-proof** - Leverages Juicebox's built-in oracle system

