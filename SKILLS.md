# nana-uni-v4-util-v5

## Purpose

Uniswap V4 hook that automatically routes swaps involving Juicebox project tokens to the best price among V4, V3, and Juicebox protocol, with built-in TWAP oracle protection.

## Contracts

| Contract | Role |
|----------|------|
| `JBUniswapV4Hook` | V4 BaseHook: `beforeSwap` compares three routes and overrides the swap when V3 or Juicebox is cheaper; `afterSwap`/`afterAddLiquidity`/`afterRemoveLiquidity` record TWAP observations; `afterInitialize` bootstraps the oracle. Also implements `IUniswapV3SwapCallback` for V3 routing. |
| `Oracle` (library) | Circular observation buffer storing `(blockTimestamp, prevTick, tickCumulative, secondsPerLiquidityCumulativeX128)`. Supports `observe`, `observeSingle`, `write`, `grow`, and binary search. |
| `IUniswapV3Factory` | V3 factory interface for pool lookups. |
| `IUniswapV3Pool` | V3 pool interface for `slot0`, `observe`, `swap`, `liquidity`, `token0/token1`. |
| `IWETH` | Minimal WETH `deposit`/`withdraw` interface. |

## Key Functions

| Function | Contract | What it does |
|----------|----------|--------------|
| `_beforeSwap` | `JBUniswapV4Hook` | Core routing: detects if swap involves JB token, estimates V4/V3/Juicebox outputs, picks best, executes via `_routeThroughJuicebox` or `_routeThroughV3` or returns `ZERO_DELTA` for V4. Requires `hookData` to contain `uint256 amountOutMin`. Only supports exact-input swaps. |
| `_afterSwap` | `JBUniswapV4Hook` | Records oracle observation; validates `amountOutMin` slippage for V4 swaps that were not rerouted. |
| `_afterInitialize` | `JBUniswapV4Hook` | Initializes oracle ring buffer for new pool. |
| `calculateExpectedTokensWithCurrency` | `JBUniswapV4Hook` | View: estimates project tokens from paying `paymentAmount` of `paymentToken`, accounting for weight, currency conversion, reserved rate. |
| `calculateExpectedOutputFromSelling` | `JBUniswapV4Hook` | View: estimates terminal tokens from cashing out `tokenAmountIn` project tokens via `currentReclaimableSurplusOf`. |
| `estimateUniswapOutput` | `JBUniswapV4Hook` | View: estimates V4 swap output using TWAP sqrt price, with fee deduction. Falls back to spot price if TWAP unavailable. |
| `estimateUniswapV3Output` | `JBUniswapV4Hook` | View: estimates V3 swap output via `_getQuote` which uses V3 TWAP (1-hour window). |
| `observeTWAP` | `JBUniswapV4Hook` | View: returns arithmetic mean tick over `secondsAgo` for a V4 pool's oracle. |
| `_consult` | `JBUniswapV4Hook` | External-self-call: computes V3 TWAP tick and harmonic mean liquidity via `pool.observe()`. Declared `external` so it can be try/caught. |
| `_getOldestObservationSecondsAgo` | `JBUniswapV4Hook` | External-self-call: returns age of oldest V3 observation. Declared `external` for try/catch. |
| `_routeThroughJuicebox` | `JBUniswapV4Hook` | Takes input from PoolManager, calls `terminal.pay()` (buying) or `terminal.cashOutTokensOf()` (selling), settles output back. |
| `_routeThroughV3` | `JBUniswapV4Hook` | Takes input from PoolManager, wraps ETH to WETH if needed, executes V3 `swap()`, unwraps WETH if needed, settles output back. |
| `uniswapV3SwapCallback` | `JBUniswapV4Hook` | V3 callback: validates caller is the expected V3 pool, transfers owed tokens. |
| `_getTWAPSqrtPrice` | `JBUniswapV4Hook` | Returns TWAP sqrt price for V4 pool (30-min window), or 0 if insufficient data. Auto-converts mean tick to sqrtPriceX96 via `TickMath`. |
| `_recordObservation` | `JBUniswapV4Hook` | Writes new observation to ring buffer; auto-grows cardinality (doubles up to 256) when buffer is full. |
| `observe` | `Oracle` | Returns tick cumulatives and seconds-per-liquidity for an array of `secondsAgos`. |
| `write` | `Oracle` | Appends a new observation; bumps cardinality if `cardinalityNext > cardinality`. |
| `grow` | `Oracle` | Pre-pays SSTOREs to expand the observation buffer. |

## Integration Points

| Dependency | Import | Used For |
|------------|--------|----------|
| `@uniswap/v4-core` | `IPoolManager`, `PoolKey`, `PoolId`, `StateLibrary`, `TickMath`, `FullMath`, `Currency`, `SwapParams`, `BeforeSwapDelta`, `BalanceDelta`, `Hooks` | V4 pool interaction, price math, hook framework |
| `@uniswap/v4-periphery` | `BaseHook` | Hook base class with permission flags |
| `@openzeppelin/uniswap-hooks` | `CurrencySettler` | Safe `settle()` / `take()` wrappers for V4 flash accounting |
| `@bananapus/core-v6` | `IJBTokens`, `IJBDirectory`, `IJBController`, `IJBPrices`, `IJBTerminalStore`, `IJBMultiTerminal`, `IJBTerminal`, `JBRuleset`, `JBRulesetMetadataResolver`, `JBConstants` | Juicebox protocol: project token lookup, terminal routing, weight/price queries, pay/cashOut |
| `@openzeppelin/contracts` | `IERC20`, `IERC20Metadata`, `SafeERC20` | Token transfers and decimal queries |

## Key Types

| Struct/Enum | Key Fields | Used In |
|-------------|------------|---------|
| `Oracle.Observation` | `uint32 blockTimestamp`, `int24 prevTick`, `int48 tickCumulative`, `uint144 secondsPerLiquidityCumulativeX128`, `bool initialized` | `observations` mapping (per PoolId, ring buffer of 65535) |
| `ObservationState` | `uint16 index`, `uint16 cardinality`, `uint16 cardinalityNext` | `states` mapping (per PoolId), tracks write position and buffer capacity |

## Gotchas

- **Exact-output swaps are not supported.** `_beforeSwap` reverts with `JBUniswapV4Hook_ExactOutputSwapsNotSupported` if `params.amountSpecified > 0`. Only exact-input (negative `amountSpecified`) is handled.
- **`hookData` must encode `uint256 amountOutMin`.** Exactly 32 bytes required; otherwise `_beforeSwap` reverts with `JBUniswapV4Hook_AmountOutMinRequired`.
- **`_consult` and `_getOldestObservationSecondsAgo` are declared `external`, not `internal`.** They are called via `this._consult()` / `this._getOldestObservationSecondsAgo()` so they can be wrapped in try/catch. Test mocks cannot call them as internal helpers.
- **TWAP falls back to spot price silently.** If fewer than 2 observations or less than `TWAP_PERIOD` seconds of data exist, `_getTWAPSqrtPrice` returns 0 and the estimator uses `getSlot0` spot price instead. No revert, no event.
- **V3 routing uses a hardcoded 10000 fee tier (1%).** Only pools with this fee tier are considered. If the best V3 liquidity is in a different fee tier, it will be missed.
- **Native ETH vs WETH normalization has distinct paths.** For Juicebox terminal calls, `address(0)` maps to `JB_NATIVE_TOKEN` (0x...EEEe). For V3 calls, `address(0)` maps to `WETH`. These are NOT interchangeable.
- **Pragma must be `^0.8.24`** because V4 core dependencies require it. The `foundry.toml` uses `evm_version = "cancun"`.
- **Oracle auto-grows cardinality** up to a max of 256. Each grow doubles the buffer size. This is paid for in gas by whoever triggers the observation write that fills the buffer.

## Example Integration

```solidity
// Deploying a V4 pool with the JBUniswapV4Hook
import {JBUniswapV4Hook} from "nana-uni-v4-util-v6/src/JBUniswapV4Hook.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

// Deploy hook (address must match permission flags via HookMiner)
JBUniswapV4Hook hook = new JBUniswapV4Hook(
    poolManager,
    jbTokens,
    jbDirectory,
    jbPrices,
    v3Factory,
    weth
);

// Initialize a pool with the hook
PoolKey memory key = PoolKey({
    currency0: Currency.wrap(address(projectToken)),
    currency1: Currency.wrap(address(0)), // native ETH
    fee: 3000,
    tickSpacing: 60,
    hooks: hook
});

poolManager.initialize(key, sqrtPriceX96);

// Swap through the pool -- hook will auto-route to best price
// hookData must contain amountOutMin as uint256
bytes memory hookData = abi.encode(uint256(minTokensOut));
```
