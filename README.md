# JBUniswapV4Hook - Juicebox × Uniswap V4 Integration

**Official Juicebox integration for Uniswap v4 that provides price comparison and optimal routing with TWAP oracle protection 🦄🧃**

## Overview

The JBUniswapV4Hook is a Uniswap V4 hook that intelligently routes swaps between Uniswap pools and Juicebox project token minting. It compares prices in real-time and automatically routes to the option that gives users the most tokens, while using TWAP (Time-Weighted Average Price) oracle protection against manipulation.

### Key Features

- ✅ **Automatic Price Comparison** - Compares Uniswap vs Juicebox prices on every swap
- ✅ **Optimal Routing** - Routes to the cheaper option (more tokens for user)
- ✅ **TWAP Oracle Protection** - Protects against price manipulation and front-running
- ✅ **Multi-Currency Support** - Works with ETH and ERC20 tokens
- ✅ **Event Transparency** - Emits price comparison and routing decision events

## How It Works

```
User initiates swap → Hook checks both routes:
├─ Uniswap Route: Uses TWAP oracle for manipulation-resistant pricing
└─ Juicebox Route: Calculates tokens based on project weight & currency rates

→ Compare outputs → Route to option giving MORE tokens → User receives optimal amount
```

### TWAP Oracle Protection

The hook implements a Time-Weighted Average Price oracle that:
- Records price observations after each swap
- Uses historical data to calculate average prices over 30-minute windows
- Protects users from front-running by using stable average prices

**Without TWAP**: Attacker can manipulate spot price → Victim pays inflated price  
**With TWAP**: Attacker's manipulation has limited impact → Victim protected by historical average

## Architecture

### Core Components

**`JBUniswapV4Hook.sol`** - Main hook contract implementing:
- `beforeSwap()` - Price comparison and routing logic
- `afterSwap()` - Oracle observation recording
- `afterInitialize()` - Oracle initialization for new pools

**Hook Permissions:**
```solidity
afterInitialize: true    // Initialize oracle observations
beforeSwap: true         // Compare prices and route
afterSwap: true          // Record oracle observations
beforeSwapReturnDelta: true  // Override swap behavior for Juicebox routing
```

### Juicebox Integration

Integrates with Juicebox protocol contracts:
- **IJBTokens** - Identifies Juicebox project tokens
- **IJBMultiTerminal** - Processes payments to mint tokens
- **IJBController** - Retrieves project weight (tokens per ETH)
- **IJBPrices** - Converts between currencies

## Testing

**36 tests with 100% pass rate** including:
- Unit tests: Token calculation, hook permissions, project detection, oracle initialization
- Fuzz tests (256+ runs): TWAP oracle, security (manipulation/front-running), routing, price comparison

### Running Tests

```bash
# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test suite
forge test --match-contract JuiceboxHookTest

# Run TWAP oracle tests
forge test --match-test testFuzz_TWAP

# Run security tests
forge test --match-test "testFuzz_PriceManipulation|testFuzz_FrontRunning"

# Generate gas report
forge test --gas-report
```

## Deployment

### Prerequisites

```bash
forge install
```

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

## Configuration

### Setting Currency IDs

For non-ETH tokens, set the Juicebox currency ID:

```solidity
hook.setCurrencyId(tokenAddress, currencyId);
```

### Increasing Oracle Cardinality

For better TWAP precision:

```solidity
hook.increaseCardinalityNext(poolId, 100); // Store 100 observations
```

## Security

### TWAP Oracle Protection

- **30-minute lookback period** - Falls back to spot price if insufficient data
- **Manipulation resistance** - Attacker must maintain manipulation for 30+ minutes with massive capital
- **Front-running protection** - Single-block manipulation has minimal TWAP impact
- **Economic disincentive** - Arbitrageurs and other traders would exploit the attacker

## Gas Optimization

- Project IDs cached after first detection
- TWAP calculations use efficient Uniswap V4 library
- Only active hooks executed when needed
- Minimal storage writes (observations ring buffer)

## Events

```solidity
event JuiceboxPaymentProcessed(
    PoolId indexed poolId,
    address indexed token,
    uint256 indexed projectId,
    uint256 amount,
    uint256 tokensReceived
);

event PriceComparison(
    PoolId indexed poolId,
    uint256 uniswapPrice,
    uint256 juiceboxPrice,
    bool juiceboxCheaper,
    uint256 priceDifference
);

event RouteSelected(
    PoolId indexed poolId,
    bool useJuicebox,
    uint256 expectedTokens,
    uint256 savings
);
```

## Example Usage

```solidity
// For Juicebox project token pools:
// Hook auto-detects project, compares prices, routes optimally, emits events

// For non-Juicebox pools:
// Normal Uniswap swap behavior
```

## Troubleshooting

### Hook Deployment Failures

Ensure hook permissions match flags:
```solidity
Hooks.AFTER_INITIALIZE_FLAG | 
Hooks.BEFORE_SWAP_FLAG | 
Hooks.AFTER_SWAP_FLAG |
Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG
```

### TWAP Returns Zero

Possible causes:
- Pool too new (< 2 observations)
- Insufficient time elapsed (< TWAP_PERIOD)
- No swaps in lookback window

Solution: System automatically falls back to spot price

### Price Comparison Issues

Check:
- Currency IDs set correctly for all tokens
- Juicebox project has non-zero weight
- Price feed exists for currency conversions

## Resources

### Juicebox
- [Docs](https://docs.juicebox.money)
- [Protocol](https://github.com/jbx-protocol)

### Uniswap V4
- [Docs](https://docs.uniswap.org/contracts/v4/overview)
- [v4-periphery](https://github.com/uniswap/v4-periphery)
- [v4-core](https://github.com/uniswap/v4-core)
- [v4-by-example](https://v4-by-example.org)

### Oracle
- [Uniswap V3 Oracle Guide](https://docs.uniswap.org/concepts/protocol/oracle)
- [TWAP Best Practices](https://blog.uniswap.org/uniswap-v3-oracles)

## License

MIT

## Security

For security concerns: security@juicebox.money

**Audits**: Not yet audited - use at your own risk in production
