# JBUniswapV4Hook - Juicebox × Uniswap V4 Integration

**Official Juicebox integration for Uniswap v4 that provides intelligent price comparison and optimal routing with TWAP oracle protection**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-^0.8.24-lightgrey)](https://soliditylang.org/)

## Overview

The `JBUniswapV4Hook` is a Uniswap V4 hook that intelligently routes swaps between Uniswap V4 pools, Uniswap V3 pools, and Juicebox project token minting. It compares prices in real-time across all three routes and automatically routes to the option that gives users the most tokens, while using TWAP (Time-Weighted Average Price) oracle protection against manipulation.

### Key Features

- ✅ **Multi-Route Price Comparison** - Compares Uniswap V4, Uniswap V3, and Juicebox prices on every swap
- ✅ **Optimal Routing** - Automatically routes to the cheapest option (most tokens for user)
- ✅ **TWAP Oracle Protection** - Protects against price manipulation and front-running using time-weighted averages
- ✅ **Uniswap V3 Integration** - Routes through V3 pools when they offer better prices than V4
- ✅ **Multi-Currency Support** - Works with native ETH and ERC20 tokens (including non-18 decimal tokens)
- ✅ **Event Transparency** - Emits detailed price comparison and routing decision events
- ✅ **Slippage Protection** - Dynamic slippage tolerance based on liquidity and TWAP calculations

## Architecture

### Core Components

**`JBUniswapV4Hook.sol`** - Main hook contract implementing:
- `beforeSwap()` - Price comparison and routing logic across V4, V3, and Juicebox
- `afterSwap()` - Oracle observation recording for TWAP calculations
- `afterInitialize()` - Oracle initialization for new pools
- `afterAddLiquidity()` / `afterRemoveLiquidity()` - Oracle observation updates

**`Oracle.sol`** - Library for managing price observations and TWAP calculations

### Hook Permissions

The hook requires the following Uniswap V4 permissions:

```solidity
afterInitialize: true              // Initialize oracle observations
afterAddLiquidity: true            // Record oracle observations
afterRemoveLiquidity: true         // Record oracle observations
beforeSwap: true                   // Compare prices and route
afterSwap: true                    // Record oracle observations
beforeSwapReturnDelta: true        // Override swap behavior for routing
```

### Integration Points

#### Juicebox Protocol Contracts
- **`IJBTokens`** - Identifies Juicebox project tokens and maps them to project IDs
- **`IJBDirectory`** - Retrieves primary terminals for project payments
- **`IJBController`** - Retrieves project rulesets and weight (tokens per payment unit)
- **`IJBPrices`** - Converts between different currencies using price feeds
- **`IJBTerminalStore`** - Gets reclaimable surplus for selling tokens
- **`IJBMultiTerminal`** - Processes payments (`pay()`) and token redemptions (`cashOutTokensOf()`)

#### Uniswap Contracts
- **`IPoolManager`** - Uniswap V4 pool manager for V4 pool operations
- **`IUniswapV3Factory`** - Uniswap V3 factory for V3 pool lookups (10000 fee tier)
- **`IUniswapV3Pool`** - Uniswap V3 pool interface for routing through V3 pools

## How It Works

### Routing Flow

```
User initiates swap in V4 pool
    ↓
Hook's beforeSwap() is called
    ↓
1. Detect if swap involves Juicebox project token
    ↓
2. Calculate expected outputs from all routes:
   ├─ Uniswap V4: Uses TWAP oracle (30-min window)
   ├─ Uniswap V3: Uses TWAP oracle (1-hour window) with slippage tolerance
   └─ Juicebox: Calculates based on project weight & currency rates
    ↓
3. Compare all three outputs
    ↓
4. Route to best option:
   ├─ If Juicebox best → Route through Juicebox terminal
   ├─ If V3 best → Route through V3 pool (with WETH wrapping if needed)
   └─ If V4 best → Proceed with normal V4 swap
    ↓
5. Record oracle observation (afterSwap)
```

### Price Comparison Logic

The hook compares three routes:

1. **Uniswap V4 Route**: Uses the pool's own TWAP oracle (30-minute window)
2. **Uniswap V3 Route**: Uses V3 pool TWAP oracle (1-hour window) with dynamic slippage tolerance
3. **Juicebox Route**: Calculates tokens based on:
   - Project weight (tokens per payment unit)
   - Currency conversion rates (via `IJBPrices`)
   - Token decimals (supports non-18 decimal tokens)

The route with the highest expected output is selected.

### TWAP Oracle Protection

The hook implements a Time-Weighted Average Price oracle that:

- **Records observations** after each swap, liquidity change, and pool initialization
- **Uses 30-minute lookback** for V4 pools and 1-hour for V3 pools
- **Falls back to spot price** if insufficient historical data (< 2 observations or < TWAP_PERIOD seconds)
- **Protects against manipulation** by requiring attackers to maintain price manipulation for extended periods

**Without TWAP**: Attacker can manipulate spot price → Victim pays inflated price  
**With TWAP**: Attacker's manipulation has limited impact → Victim protected by historical average

### Slippage Tolerance Calculation

For V3 routing, the hook calculates dynamic slippage tolerance based on:

1. **Liquidity**: Lower liquidity = higher slippage tolerance
2. **Swap Size**: Larger swaps relative to liquidity = higher tolerance
3. **TWAP Price**: Uses TWAP tick to normalize calculations
4. **Logarithmic Scaling**: Smooth growth with diminishing returns

The formula:
- Base calculation: `(amountIn * 10 * 10000) / liquidity`
- Normalized by sqrt price: `base * sqrtP / 2^96` (or inverse)
- Logarithmic adjustment: `baseValue + (scaleFactor * log2(rawSlippageBps)) / 2`
- Capped at 88% for very large values, 67% for large values, or 20% of raw for normal values

### Uniswap V3 Integration

The hook can route swaps through Uniswap V3 pools when they offer better prices:

1. **Pool Lookup**: Uses V3 factory to find pool with 10000 fee tier (1%)
2. **Token Conversion**: Converts native ETH (`address(0)`) to WETH for V3 operations
3. **Swap Execution**: Executes swap via V3 pool's `swap()` function
4. **Callback Handling**: Implements `uniswapV3SwapCallback()` to pay for swaps
5. **WETH Unwrapping**: Converts WETH back to native ETH if output is native ETH

### Token Decimal Handling

The hook properly handles tokens with different decimal counts:

- **18 decimals** (default): Standard ERC20 tokens
- **6 decimals** (e.g., USDC): Properly normalized in calculations
- **8 decimals** (e.g., WBTC): Properly normalized in calculations
- **0 decimals**: Handled gracefully with fallback to 18

The `_getTokenDecimals()` function attempts to read decimals from the token contract, falling back to 18 if not available.

## Contract Functions

### Public View Functions

#### `calculateExpectedTokensWithCurrency(uint256 projectId, address paymentToken, uint256 paymentAmount)`
Calculates expected tokens for buying a Juicebox project token with any payment currency.

**Parameters:**
- `projectId`: The Juicebox project ID
- `paymentToken`: The token being used for payment (address(0) for native ETH)
- `paymentAmount`: The amount being paid (in the token's native decimals)

**Returns:** Expected number of tokens to be received

#### `calculateExpectedOutputFromSelling(uint256 projectId, uint256 tokenAmountIn, address outputToken)`
Calculates expected output when selling Juicebox project tokens.

**Parameters:**
- `projectId`: The Juicebox project ID
- `tokenAmountIn`: The number of project tokens being sold
- `outputToken`: The token to receive (address(0) for native ETH)

**Returns:** Expected amount of output tokens

#### `estimateUniswapOutput(PoolId poolId, PoolKey memory key, uint256 amountIn, bool zeroForOne)`
Estimates output from a Uniswap V4 swap using TWAP oracle.

**Parameters:**
- `poolId`: The V4 pool ID
- `key`: The pool key
- `amountIn`: Input amount
- `zeroForOne`: Swap direction

**Returns:** Estimated output amount

#### `estimateUniswapV3Output(address token0, address token1, uint256 amountIn, bool zeroForOne)`
Estimates output from a Uniswap V3 swap using TWAP oracle with slippage tolerance.

**Parameters:**
- `token0`: First token in pair (must be < token1)
- `token1`: Second token in pair
- `amountIn`: Input amount
- `zeroForOne`: Swap direction (true = token0 → token1)

**Returns:** Estimated output amount

#### `observeTWAP(PoolId poolId, uint32 secondsAgo, int24 tick, uint16 index, uint128 liquidity, uint16 cardinality)`
Observes TWAP tick for a given pool and time window.

**Parameters:**
- `poolId`: The V4 pool ID
- `secondsAgo`: Seconds in the past to calculate TWAP from
- `tick`: Current tick
- `index`: Current observation index
- `liquidity`: Current liquidity
- `cardinality`: Current cardinality

**Returns:** Arithmetic mean tick over the time window

#### `_consult(IUniswapV3Pool pool, uint32 secondsAgo)`
Calculates time-weighted means of tick and liquidity for a V3 pool.

**Parameters:**
- `pool`: The V3 pool to observe
- `secondsAgo`: Number of seconds in the past

**Returns:**
- `arithmeticMeanTick`: Arithmetic mean tick
- `harmonicMeanLiquidity`: Harmonic mean liquidity

#### `_getOldestObservationSecondsAgo(IUniswapV3Pool pool)`
Returns the number of seconds ago of the oldest stored observation for a V3 pool.

**Parameters:**
- `pool`: The V3 pool to query

**Returns:** Number of seconds ago of the oldest observation

### Hook Functions

#### `beforeSwap(address, PoolKey calldata key, SwapParams calldata params, bytes calldata)`
Main routing logic that compares prices and routes to the best option.

**Flow:**
1. Validates exact-input swap (reverts on exact-output)
2. Detects if swap involves Juicebox project token
3. Calculates expected outputs from V4, V3, and Juicebox
4. Compares outputs and routes to best option
5. Returns swap delta to override V4 swap if routing elsewhere

#### `afterSwap(address, PoolKey calldata key, SwapParams calldata, BalanceDelta, bytes calldata)`
Records oracle observation after swap completes.

#### `afterInitialize(address, PoolKey calldata key, uint160, int24 tick)`
Initializes oracle observations when a new pool is created.

#### `afterAddLiquidity(address, PoolKey calldata key, ModifyLiquidityParams calldata, BalanceDelta, bytes calldata)`
Records oracle observation after liquidity is added.

#### `afterRemoveLiquidity(address, PoolKey calldata key, ModifyLiquidityParams calldata, BalanceDelta, bytes calldata)`
Records oracle observation after liquidity is removed.

### Internal Functions

#### `_routeThroughJuicebox(...)`
Routes a swap through Juicebox terminal instead of Uniswap.

**Handles:**
- Buying JB tokens via `terminal.pay()`
- Selling JB tokens via `terminal.cashOutTokensOf()`
- Token normalization (native ETH → JB_NATIVE_TOKEN)
- Currency conversion via `IJBPrices`

#### `_routeThroughV3(...)`
Routes a swap through Uniswap V3 pool.

**Handles:**
- Pool lookup via V3 factory
- Pool lock check
- WETH wrapping for native ETH input
- V3 swap execution
- WETH unwrapping for native ETH output
- Callback payment via `uniswapV3SwapCallback()`

#### `uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data)`
Callback function called by V3 pool during swap execution.

**Validates:**
- At least one delta is positive (actual swap occurred)
- Caller is a valid V3 pool from factory
- Pool exists (not address(0))

**Pays:** Required token amount to the V3 pool

#### `_getQuote(uint256 projectId, address projectToken, uint256 amountIn, address terminalToken)`
Gets a quote based on V3 TWAP with slippage tolerance.

**Flow:**
1. Looks up V3 pool (10000 fee tier)
2. Validates pool exists and is unlocked
3. Determines TWAP window (uses oldest observation if < 1 hour)
4. Calculates TWAP tick and liquidity
5. Applies slippage tolerance
6. Returns quote amount

#### `_getSlippageTolerance(...)`
Calculates dynamic slippage tolerance based on liquidity and swap size.

**Formula:**
- Base: `(amountIn * 10 * 10000) / liquidity`
- Normalized by sqrt price
- Logarithmic scaling with caps
- Returns value in basis points (0-10000)

#### `_getTWAPSqrtPrice(PoolId poolId)`
Gets the TWAP sqrt price for a V4 pool.

**Returns:** TWAP sqrt price, or 0 if insufficient observations

#### `_recordObservation(PoolId poolId)`
Records a new oracle observation for a pool.

**Features:**
- Auto-grows cardinality when at capacity
- Doubles cardinality up to 256 maximum
- Writes observation to ring buffer

## Custom Errors

```solidity
error JBUniswapV4Hook_ExactOutputSwapsNotSupported();
// Reverts when exact-output swap is attempted (only exact-input supported)

error JBUniswapV4Hook_SecondsAgoCannotBeZero();
// Reverts when secondsAgo is zero in _consult()

error JBUniswapV4Hook_ObservationCardinalityZero();
// Reverts when observation cardinality is zero

error JBUniswapV4Hook_V3PoolNotFound();
// Reverts when V3 pool is not found for token pair

error JBUniswapV4Hook_V3PoolLocked();
// Reverts when V3 pool is locked (cannot swap)

error JBUniswapV4Hook_NoSwap();
// Reverts when swap callback has no valid swap (both deltas <= 0)

error JBUniswapV4Hook_InvalidCallback();
// Reverts when swap callback is called from invalid sender or pool doesn't exist
```

## Events

```solidity
event RouteSelected(
    PoolId indexed poolId,
    bool useJuicebox,
    uint256 expectedTokens
);
// Emitted when routing decision is made

event BestRouteSelected(
    PoolId indexed poolId,
    string routeType,  // "v3", "v4", or "juicebox"
    uint256 expectedTokens
);
// Emitted when best route is selected among all three options
```

## Security Considerations

### TWAP Oracle Protection

- **30-minute lookback** for V4 pools, 1-hour for V3 pools
- **Falls back to spot price** if insufficient data
- **Manipulation resistance**: Attacker must maintain manipulation for extended periods
- **Front-running protection**: Single-block manipulation has minimal TWAP impact
- **Economic disincentive**: Arbitrageurs would exploit sustained manipulation

### Slippage Protection

- **Dynamic tolerance**: Adjusts based on liquidity and swap size
- **Logarithmic scaling**: Prevents excessive tolerance for small swaps
- **Caps**: Maximum 88% tolerance for extreme cases, typically much lower
- **TWAP-based**: Uses time-weighted prices, not spot prices

### Access Control

- **No admin functions**: Contract is immutable after deployment
- **No upgradeability**: All parameters are constants or immutable
- **Read-only external calls**: Only reads from Juicebox and Uniswap contracts
- **Callback validation**: V3 callback validates caller is legitimate pool

### Reentrancy Protection

- **No external calls before state changes**: State is updated before external calls
- **Uniswap V4 protection**: PoolManager handles reentrancy protection
- **V3 callback**: Only transfers tokens, no state changes

### Input Validation

- **Exact-output swaps**: Reverted (only exact-input supported)
- **Zero amounts**: Handled gracefully (returns 0 or reverts appropriately)
- **Invalid pools**: Returns 0 or reverts with custom error
- **Token decimals**: Falls back to 18 if not available

### Edge Cases

- **No V3 pool**: Falls back to V4 or Juicebox
- **No Juicebox terminal**: Falls back to V4 or V3
- **Insufficient TWAP data**: Falls back to spot price
- **Locked V3 pool**: Reverts with clear error
- **Zero liquidity**: Slippage tolerance handles gracefully

## Testing

### Test Coverage

The codebase includes comprehensive test coverage:

- **Unit Tests**: Token calculations, hook permissions, project detection, oracle operations
- **Fork Tests**: Integration with real mainnet contracts (Juicebox, Uniswap V3)
- **Edge Case Tests**: Error conditions, slippage tolerance, non-18 decimal tokens
- **Fuzz Tests**: TWAP oracle, security scenarios, routing logic

### Running Tests

```bash
# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test suite
forge test --match-contract JBUniswapV4HookTest
forge test --match-contract JBUniswapV4HookForkTest
forge test --match-contract SlippageToleranceTest

# Run fork tests (requires mainnet RPC)
forge test --match-contract JBUniswapV4HookForkTest

# Generate gas report
forge test --gas-report
```

### Fork Tests

Fork tests use real mainnet contracts and require a mainnet RPC endpoint:

```bash
# Optionally set your RPC URL (recommended for reliable testing)
export MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

# Or use a public RPC (may have rate limits)
# Defaults to https://ethereum-rpc.publicnode.com if MAINNET_RPC_URL is not set

# Run fork tests
forge test --match-contract JBUniswapV4HookForkTest
```

**Note:** Public RPC endpoints may rate limit. For reliable fork testing, use your own RPC endpoint from providers like:
- [Alchemy](https://www.alchemy.com/)
- [Infura](https://www.infura.io/)
- [QuickNode](https://www.quicknode.com/)
- [Ankr](https://www.ankr.com/)

## Deployment

### Prerequisites

```bash
# Install dependencies
forge install

# Compile contracts
forge build
```

### Constructor Parameters

The hook requires the following constructor parameters:

```solidity
constructor(
    IPoolManager poolManager,           // Uniswap V4 pool manager
    IJBTokens tokens,                   // Juicebox tokens contract
    IJBDirectory directory,              // Juicebox directory
    IJBController controller,            // Juicebox controller
    IJBPrices prices,                   // Juicebox prices contract
    IJBTerminalStore terminalStore,     // Juicebox terminal store
    IUniswapV3Factory v3Factory,        // Uniswap V3 factory
    address wrappedNativeEth            // WETH address (chain-specific)
)
```

### Mainnet Addresses

**Juicebox Protocol (Mainnet):**
- `IJBTokens`: `0x4d0Edd347FB1fA21589C1E109B3474924BE87636`
- `IJBDirectory`: `0x0061E516886A0540F63157f112C0588eE0651dCF`
- `IJBController`: `0x27da30646502e2f642bE5281322Ae8C394F7668a`
- `IJBPrices`: `0x9b90E507cF6B7eB681A506b111f6f50245e614c4`
- `IJBTerminalStore`: `0xfE33B439Ec53748C87DcEDACb83f05aDd5014744`

**Uniswap V3 (Mainnet):**
- `IUniswapV3Factory`: `0x1F98431c8aD98523631AE4a59f267346ea31F984`
- `WETH`: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`

### Local Development

```bash
# Start Anvil
anvil

# Deploy the hook
forge script script/DeployJBUniswapV4Hook.s.sol \
    --rpc-url http://localhost:8545 \
    --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
    --broadcast
```

### Network Deployment

```bash
# Store private key
cast wallet import <KEY_NAME> --interactive

# Deploy
forge script script/DeployJBUniswapV4Hook.s.sol \
    --rpc-url <YOUR_RPC_URL> \
    --account <KEY_NAME> \
    --sender <YOUR_ADDRESS> \
    --broadcast
```

### Hook Address Calculation

Uniswap V4 hooks must be deployed at specific addresses determined by their permissions. Use the `HookMiner` utility to find a valid address:

```solidity
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

uint160 flags = uint160(
    Hooks.AFTER_INITIALIZE_FLAG |
    Hooks.BEFORE_SWAP_FLAG |
    Hooks.AFTER_SWAP_FLAG |
    Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG |
    Hooks.AFTER_ADD_LIQUIDITY_FLAG |
    Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
);

address hookAddress = HookMiner.find(
    flags,
    type(JBUniswapV4Hook).creationCode,
    abi.encode(...constructorArgs)
);
```

## Configuration

### Constants

The contract uses the following constants:

```solidity
uint32 constant TWAP_PERIOD = 1800;                    // 30 minutes
uint256 constant STANDARD_TWAP_WINDOW = 1 hours;       // 1 hour for V3
uint256 constant TWAP_SLIPPAGE_DENOMINATOR = 10_000;    // 100% in bps
uint256 constant UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE = 1050; // 10.5% default
address constant UNISWAP_NATIVE_ETH = address(0);       // Native ETH
address constant JB_NATIVE_TOKEN = 0x000...EEEe;       // JB native token
```

### Immutable Parameters

- `TOKENS`: Juicebox tokens contract (immutable)
- `DIRECTORY`: Juicebox directory (immutable)
- `CONTROLLER`: Juicebox controller (immutable)
- `PRICES`: Juicebox prices contract (immutable)
- `TERMINAL_STORE`: Juicebox terminal store (immutable)
- `V3_FACTORY`: Uniswap V3 factory (immutable)
- `WETH`: Wrapped native ETH address (immutable, chain-specific)

## Gas Optimization

- **Project IDs cached**: After first detection, project IDs are cached
- **TWAP calculations**: Uses efficient Uniswap V4 library functions
- **Minimal storage writes**: Observations use ring buffer (overwrites old data)
- **Selective routing**: Only calculates routes when JB token detected
- **Custom errors**: Gas-efficient error handling (no string storage)

## Troubleshooting

### Hook Deployment Failures

Ensure hook permissions match flags:
```solidity
Hooks.AFTER_INITIALIZE_FLAG | 
Hooks.BEFORE_SWAP_FLAG | 
Hooks.AFTER_SWAP_FLAG |
Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG |
Hooks.AFTER_ADD_LIQUIDITY_FLAG |
Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
```

### TWAP Returns Zero

Possible causes:
- Pool too new (< 2 observations)
- Insufficient time elapsed (< TWAP_PERIOD)
- No swaps in lookback window

**Solution**: System automatically falls back to spot price

### Price Comparison Issues

Check:
- Currency IDs set correctly for all tokens in Juicebox
- Juicebox project has non-zero weight
- Price feed exists for currency conversions
- V3 pool exists for token pair (if routing through V3)

### V3 Routing Failures

Possible causes:
- No V3 pool exists for token pair (10000 fee tier)
- V3 pool is locked
- Insufficient liquidity in V3 pool

**Solution**: Hook falls back to V4 or Juicebox route

## Resources

### Juicebox Protocol
- [Documentation](https://docs.juicebox.money)
- [Protocol Repository](https://github.com/jbx-protocol)
- [Core V5 Contracts](https://github.com/jbx-protocol/juice-contracts-v3)

### Uniswap V4
- [Documentation](https://docs.uniswap.org/contracts/v4/overview)
- [v4-periphery](https://github.com/uniswap/v4-periphery)
- [v4-core](https://github.com/uniswap/v4-core)
- [v4-by-example](https://v4-by-example.org)

### Uniswap V3
- [Documentation](https://docs.uniswap.org/contracts/v3/overview)
- [Oracle Guide](https://docs.uniswap.org/concepts/protocol/oracle)
- [TWAP Best Practices](https://blog.uniswap.org/uniswap-v3-oracles)

## License

MIT

## Security

For security concerns or to report vulnerabilities, please contact: **security@juicebox.money**

**Audit Status**: Not yet audited - use at your own risk in production

**Bug Bounty**: Not currently active

---

**Built with ❤️ by the Juicebox community**
