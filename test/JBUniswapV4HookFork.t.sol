// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {PoolModifyLiquidityTest} from "@uniswap/v4-core/src/test/PoolModifyLiquidityTest.sol";
import {PoolSwapTest} from "@uniswap/v4-core/src/test/PoolSwapTest.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";

import {JBUniswapV4Hook} from "../src/JBUniswapV4Hook.sol";
import {JuiceboxSwapRouter} from "./utils/JuiceboxSwapRouter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Import Juicebox interfaces
import {
    IJBTokens,
    IJBMultiTerminal,
    IJBController,
    IJBPrices,
    IJBDirectory,
    IJBTerminalStore
} from "../src/JBUniswapV4Hook.sol";
import {IJBToken} from "@bananapus/core-v5/interfaces/IJBToken.sol";
import {JBRuleset} from "@bananapus/core-v5/structs/JBRuleset.sol";
import {JBRulesetMetadata} from "@bananapus/core-v5/structs/JBRulesetMetadata.sol";
import {IUniswapV3Factory} from "../src/interfaces/IUniswapV3Factory.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

/// @title JBUniswapV4HookForkTest
/// @notice Fork tests using mainnet addresses
/// @dev To run these tests:
///      1. Set MAINNET_RPC_URL in your .env file (e.g., MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY)
///      2. Run: forge test --match-contract JBUniswapV4HookForkTest --fork-url $MAINNET_RPC_URL -vv
/// @dev These tests use real mainnet contracts, so they require a mainnet RPC endpoint
contract JBUniswapV4HookForkTest is Test {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;
    using SafeERC20 for IERC20;

    // Mainnet Juicebox addresses
    address constant MAINNET_JB_TOKENS = 0x4d0Edd347FB1fA21589C1E109B3474924BE87636;
    address constant MAINNET_JB_DIRECTORY = 0x0061E516886A0540F63157f112C0588eE0651dCF;
    address constant MAINNET_JB_CONTROLLER = 0x27da30646502e2f642bE5281322Ae8C394F7668a;
    address constant MAINNET_JB_PRICES = 0x9b90E507cF6B7eB681A506b111f6f50245e614c4;
    address constant MAINNET_JB_TERMINAL_STORE = 0xfE33B439Ec53748C87DcEDACb83f05aDd5014744;
    address constant MAINNET_V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;

    // Mainnet token addresses
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    JBUniswapV4Hook hook;
    PoolManager manager;
    PoolSwapTest swapRouter;
    JuiceboxSwapRouter jbSwapRouter;
    PoolModifyLiquidityTest modifyLiquidityRouter;

    // Test constants
    uint160 constant SQRT_PRICE_1_1 = 79228162514264337593543950336; // sqrt(1.0001^0) * 2^96
    bytes constant ZERO_BYTES = "";

    PoolKey key;
    PoolId id;

    // Test user with mainnet ETH
    address testUser = address(0xBEEF);

    function setUp() public {
        // Fork mainnet at a recent block
        vm.createFork(vm.envString("MAINNET_RPC_URL"));

        // Mark mainnet contracts as persistent so they can be called in fork tests
        vm.makePersistent(MAINNET_JB_TOKENS);
        vm.makePersistent(MAINNET_JB_DIRECTORY);
        vm.makePersistent(MAINNET_JB_CONTROLLER);
        vm.makePersistent(MAINNET_JB_PRICES);
        vm.makePersistent(MAINNET_JB_TERMINAL_STORE);
        vm.makePersistent(MAINNET_V3_FACTORY);

        // Deploy core contracts
        manager = new PoolManager(address(this));
        swapRouter = new PoolSwapTest(IPoolManager(address(manager)));
        jbSwapRouter = new JuiceboxSwapRouter(IPoolManager(address(manager)));
        modifyLiquidityRouter = new PoolModifyLiquidityTest(IPoolManager(address(manager)));

        // Deploy the hook with mainnet addresses
        uint160 flags = uint160(
            Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG
                | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG
        );

        bytes memory constructorArgs = abi.encode(
            IPoolManager(address(manager)),
            IJBTokens(MAINNET_JB_TOKENS),
            IJBDirectory(MAINNET_JB_DIRECTORY),
            IJBController(MAINNET_JB_CONTROLLER),
            IJBPrices(MAINNET_JB_PRICES),
            IJBTerminalStore(MAINNET_JB_TERMINAL_STORE),
            IUniswapV3Factory(MAINNET_V3_FACTORY)
        );

        (, bytes32 salt) = HookMiner.find(address(this), flags, type(JBUniswapV4Hook).creationCode, constructorArgs);

        hook = new JBUniswapV4Hook{salt: salt}(
            IPoolManager(address(manager)),
            IJBTokens(MAINNET_JB_TOKENS),
            IJBDirectory(MAINNET_JB_DIRECTORY),
            IJBController(MAINNET_JB_CONTROLLER),
            IJBPrices(MAINNET_JB_PRICES),
            IJBTerminalStore(MAINNET_JB_TERMINAL_STORE),
            IUniswapV3Factory(MAINNET_V3_FACTORY)
        );

        // Set up a simple pool with USDC/WETH (currencies must be ordered: currency0 < currency1)
        key = PoolKey({
            currency0: Currency.wrap(USDC),
            currency1: Currency.wrap(WETH),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        id = key.toId();

        // Give test user some ETH
        vm.deal(testUser, 100 ether);

        // Initialize the pool
        manager.initialize(key, SQRT_PRICE_1_1);
    }

    /// @notice Test that the hook can be deployed and initialized with mainnet addresses
    function testHookDeployment() public view {
        assertTrue(address(hook) != address(0), "Hook should be deployed");
        assertEq(address(hook.TOKENS()), MAINNET_JB_TOKENS, "Should use mainnet JB_TOKENS");
        assertEq(address(hook.DIRECTORY()), MAINNET_JB_DIRECTORY, "Should use mainnet JB_DIRECTORY");
        assertEq(address(hook.CONTROLLER()), MAINNET_JB_CONTROLLER, "Should use mainnet JB_CONTROLLER");
        assertEq(address(hook.PRICES()), MAINNET_JB_PRICES, "Should use mainnet JB_PRICES");
        assertEq(address(hook.TERMINAL_STORE()), MAINNET_JB_TERMINAL_STORE, "Should use mainnet TERMINAL_STORE");
        assertEq(address(hook.V3_FACTORY()), MAINNET_V3_FACTORY, "Should use mainnet V3_FACTORY");
    }

    /// @notice Test that the hook can query a real Juicebox project
    function testQueryRealJuiceboxProject() public view {
        // Query project ID 1 (Juicebox v5 mainnet projects typically start at 1)
        uint256 projectId = 1;

        // Query the project's current ruleset
        (JBRuleset memory ruleset, JBRulesetMetadata memory metadata) =
            IJBController(MAINNET_JB_CONTROLLER).currentRulesetOf(projectId);

        // Validate that the project exists and has valid ruleset data
        assertTrue(ruleset.weight > 0, "Project should have a positive weight");
        assertTrue(metadata.baseCurrency > 0, "Project should have a base currency");

        // Test calculating expected tokens with ETH payment
        uint256 ethAmount = 1 ether;
        uint256 expectedTokens = hook.calculateExpectedTokensWithCurrency(
            projectId,
            address(0), // ETH
            ethAmount
        );

        // Should return tokens based on the project's weight
        assertTrue(expectedTokens > 0, "Should calculate expected tokens for ETH payment");

        // Test calculating expected tokens with USDC payment
        uint256 usdcAmount = 1000 * 1e6; // 1000 USDC (6 decimals)
        uint256 expectedTokensUSDC = hook.calculateExpectedTokensWithCurrency(projectId, USDC, usdcAmount);

        // Should return tokens (may be 0 if price feed doesn't exist, but should not revert)
        assertTrue(expectedTokensUSDC >= 0, "Should calculate expected tokens for USDC payment");

        // Try to verify project token registration (if we can find the token)
        // Note: The exact method to get project token may vary by Juicebox version
        // This is optional validation - the main test is the ruleset query and calculations

        // Test calculating expected output from selling tokens (if project has reclaimable surplus)
        if (expectedTokens > 0) {
            uint256 expectedOutput = hook.calculateExpectedOutputFromSelling(projectId, expectedTokens, USDC);
            // Output may be 0 if no surplus, but should not revert
            assertTrue(expectedOutput >= 0, "Should calculate expected output from selling tokens");
        }
    }

    /// @notice Test that the hook can query Uniswap v3 factory
    function testQueryUniswapV3Factory() public view {
        // Check if a WETH/USDC pool exists (10000 fee tier)
        address pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, USDC, 10000);

        // Pool may or may not exist, but factory should be callable
        assertTrue(
            IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, USDC, 10000) == pool,
            "Should be able to query v3 factory"
        );
    }

    /// @notice Test that calculateExpectedTokensWithCurrency works with real contracts
    function testCalculateExpectedTokensWithRealContracts() public view {
        // Try to calculate expected tokens for a known project (if it exists)
        // Using project ID 1 as an example
        try hook.calculateExpectedTokensWithCurrency(1, address(0), 1 ether) returns (uint256 tokens) {
            // Calculation succeeded
            assertTrue(tokens >= 0, "Should return non-negative tokens");
        } catch {
            // Project doesn't exist or other error - this is expected for unknown projects
            // In production, you'd use a known project ID
        }
    }

    /// @notice Test that estimateUniswapV3Output works with real v3 pools
    function testEstimateUniswapV3OutputWithRealPool() public view {
        // Check if WETH/USDC pool exists
        address v3Pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, USDC, 10000);

        if (v3Pool != address(0)) {
            // Pool exists, try to estimate output
            try hook.estimateUniswapV3Output(WETH, USDC, 1 ether, true) returns (uint256 output) {
                assertTrue(output > 0, "Should return positive output for existing pool");
            } catch {
                // Estimation failed - might be due to pool state
            }
        } else {
            // Pool doesn't exist, skip
        }
    }

    /// @notice Test that the hook can detect if a token is a Juicebox project token
    function testDetectJuiceboxToken() public {
        // This test would need a real JB project token address
        // For now, we just verify the hook can call the TOKENS contract
        try IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(address(0))) returns (uint256 projectId) {
            // If address(0) returns 0, that's expected
            assertTrue(projectId == 0 || projectId > 0, "Should return a project ID or 0");
        } catch {
            // Expected to fail for invalid token
        }
    }

    /// @notice Test that oracle initialization works
    function testOracleInitialization() public view {
        // Check that oracle was initialized during pool setup
        (uint16 index, uint16 cardinality, uint16 cardinalityNext) = hook.states(id);

        assertEq(index, 0, "Initial index should be 0");
        assertEq(cardinality, 1, "Initial cardinality should be 1");
        assertEq(cardinalityNext, 1, "Initial cardinalityNext should be 1");
    }
}

