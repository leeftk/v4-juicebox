# nana-uni-v4-util-v5

Uniswap V4 hook that intelligently routes swaps between V4 pools, V3 pools, and Juicebox project minting/cash-out to give users the best price, with TWAP oracle protection against manipulation.

## Overview

When a Juicebox project token is traded on Uniswap V4, the `JBUniswapV4Hook` intercepts the swap and compares prices from three sources: the V4 pool itself, any existing V3 pool for the same pair, and Juicebox's native minting/cash-out mechanism. It routes to whichever gives the user the most tokens. This ensures Juicebox project tokens always trade at or above their intrinsic treasury-backed value.

The hook maintains its own TWAP (Time-Weighted Average Price) oracle to protect against price manipulation. For V4 it uses a 30-minute lookback; for V3 routing it uses a 1-hour lookback. When insufficient historical data is available, it falls back to spot price.

The contract is immutable after deployment — no admin functions, no upgradeability. All parameters are constants or immutable constructor arguments.

## Architecture

| Contract | Description |
|----------|-------------|
| `JBUniswapV4Hook` | Uniswap V4 `BaseHook` that compares prices across V4, V3, and Juicebox for every swap involving a project token, then routes to the best option. Maintains its own TWAP oracle via observation recording on every swap, liquidity change, and pool initialization. Implements `IUniswapV3SwapCallback` for V3 routing. |
| `Oracle` (library) | Ring-buffer observation array (up to 65535 slots) storing tick cumulatives and seconds-per-liquidity. Supports `observe`, `observeSingle`, `write`, `grow`, and binary search over the circular buffer. Modified from Uniswap V3's oracle to add a `prevTick` field and `MIN_ABS_TICK_MOVE` / `LIMIT_ABS_TICK_MOVE` constants. |
| `IUniswapV3Factory` | Minimal interface for V3 factory (`getPool`, `createPool`). |
| `IUniswapV3Pool` | Minimal interface for V3 pool (`slot0`, `observe`, `swap`, `mint`, `burn`, `liquidity`, `token0`, `token1`). |
| `IWETH` | Minimal WETH interface (`deposit`, `withdraw`). |

## Routing Flow

```
User initiates swap in V4 pool
  |
beforeSwap() fires
  |
  +-- Is a Juicebox project token involved?
  |     NO --> proceed with normal V4 swap
  |     YES --> compare all three routes:
  |
  +-- V4 estimate (TWAP-based, 30-min window)
  +-- V3 estimate (TWAP-based, 1-hour window, 10000 fee tier)
  +-- Juicebox estimate (weight * price conversion, or cashOut surplus)
  |
  +-- Pick highest output
  |     Juicebox --> take from PoolManager, pay/cashOut via terminal, settle back
  |     V3       --> take from PoolManager, wrap ETH if needed, swap via V3, settle back
  |     V4       --> return ZERO_DELTA, let V4 AMM execute normally
  |
afterSwap() records oracle observation
```

## Hook Permissions

```
afterInitialize:          true   -- initialize oracle
beforeSwap:               true   -- price comparison and routing
beforeSwapReturnDelta:    true   -- override swap when routing elsewhere
afterSwap:                true   -- record observation, enforce slippage
afterAddLiquidity:        true   -- record observation
afterRemoveLiquidity:     true   -- record observation
```

## Install

```bash
forge install
```

## Develop

| Command | Description |
|---------|-------------|
| `forge build` | Compile contracts (requires solc ^0.8.24, evm_version cancun) |
| `forge test` | Run all tests |
| `forge test --match-contract JBUniswapV4HookTest` | Run unit tests only |
| `forge test --match-contract JBUniswapV4HookForkTest` | Run fork tests (needs `MAINNET_RPC_URL`) |
| `forge test -vvv` | Run tests with full trace |
| `forge test --gas-report` | Gas profiling |

## Key Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `TWAP_PERIOD` | 1800 (30 min) | V4 TWAP lookback window |
| `STANDARD_TWAP_WINDOW` | 3600 (1 hour) | V3 TWAP lookback window |
| `JB_NATIVE_TOKEN` | `0x...EEEe` | Juicebox native ETH sentinel |
| `UNISWAP_NATIVE_ETH` | `address(0)` | Uniswap native ETH sentinel |

## Constructor

```solidity
constructor(
    IPoolManager poolManager,      // Uniswap V4 singleton PoolManager
    IJBTokens tokens,              // Juicebox tokens registry
    IJBDirectory directory,        // Juicebox directory
    IJBPrices prices,              // Juicebox price feeds
    IUniswapV3Factory v3Factory,   // Uniswap V3 factory for V3 routing
    address wrappedNativeEth       // WETH address (chain-specific)
)
```

## License

MIT
