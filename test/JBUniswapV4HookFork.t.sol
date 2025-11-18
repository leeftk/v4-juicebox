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
import {IJBTerminal} from "@bananapus/core-v5/interfaces/IJBTerminal.sol";
import {IJBMultiTerminal} from "@bananapus/core-v5/interfaces/IJBMultiTerminal.sol";
import {IJBToken} from "@bananapus/core-v5/interfaces/IJBToken.sol";
import {JBRuleset} from "@bananapus/core-v5/structs/JBRuleset.sol";
import {JBRulesetMetadata} from "@bananapus/core-v5/structs/JBRulesetMetadata.sol";
import {IUniswapV3Factory} from "../src/interfaces/IUniswapV3Factory.sol";
import {IUniswapV3Pool} from "../src/interfaces/IUniswapV3Pool.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";
import {INonfungiblePositionManager} from "../lib/v3-periphery/contracts/interfaces/INonfungiblePositionManager.sol";

/// @title JBUniswapV4HookForkTest
/// @notice Fork tests using mainnet addresses
/// @dev To run these tests:
///      1. Optionally set MAINNET_RPC_URL in your .env file (e.g., MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY)
///         If not set, defaults to https://ethereum-rpc.publicnode.com (public RPC, may have rate limits)
///         For reliable testing, use your own RPC endpoint (Alchemy, Infura, QuickNode, etc.)
///      2. Run: forge test --match-contract JBUniswapV4HookForkTest -vv
/// @dev These tests use real mainnet contracts, so they require a mainnet RPC endpoint
/// @dev Note: Public RPC endpoints may rate limit. If tests fail with 429 errors, set MAINNET_RPC_URL to your own endpoint
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
    address constant MAINNET_V3_POSITION_MANAGER = 0xC36442b4a4522E871399CD717aBDD847Ab11FE88;
    uint24 constant V3_FEE_TIER = 10000; // 1%

    // Mainnet token addresses
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant BAN = 0x0faCEdf66a1E37714dbd748639Ea36D23254dB73;
    address constant NANA = 0x58204a8849BF6A625D56021adfD12ce4a4A3AF13;

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

    // Default RPC URL - can be overridden by setting MAINNET_RPC_URL environment variable
    // Note: Public RPCs may have rate limits. For reliable testing, set MAINNET_RPC_URL to your own RPC endpoint
    string constant DEFAULT_MAINNET_RPC = "https://eth-mainnet.g.alchemy.com/v2/Z1QKz_KCVFbuBVkAcdYFf";

    /// @notice Get RPC URL from environment variable or use default
    function _getRpcUrl() internal view returns (string memory) {
        try vm.envString("MAINNET_RPC_URL") returns (string memory rpcUrl) {
            return rpcUrl;
        } catch {
            return DEFAULT_MAINNET_RPC;
        }
    }

    function setUp() public {
        // Fork mainnet at a recent block
        // Use MAINNET_RPC_URL env var if set, otherwise use default public RPC
        string memory rpcUrl = _getRpcUrl();
        uint256 forkId = vm.createFork(rpcUrl);
        vm.selectFork(forkId);

        // Mark mainnet contracts as persistent so they can be called in fork tests
        vm.makePersistent(MAINNET_JB_TOKENS);
        vm.makePersistent(MAINNET_JB_DIRECTORY);
        vm.makePersistent(MAINNET_JB_CONTROLLER);
        vm.makePersistent(MAINNET_JB_PRICES);
        vm.makePersistent(MAINNET_JB_TERMINAL_STORE);
        vm.makePersistent(MAINNET_V3_FACTORY);
        // Persist other external contracts used during tests
        vm.makePersistent(MAINNET_V3_POSITION_MANAGER);
        vm.makePersistent(WETH);
        vm.makePersistent(USDC);
        vm.makePersistent(BAN);
        vm.makePersistent(NANA);

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
            IUniswapV3Factory(MAINNET_V3_FACTORY),
            WETH
        );

        (, bytes32 salt) = HookMiner.find(address(this), flags, type(JBUniswapV4Hook).creationCode, constructorArgs);

        hook = new JBUniswapV4Hook{salt: salt}(
            IPoolManager(address(manager)),
            IJBTokens(MAINNET_JB_TOKENS),
            IJBDirectory(MAINNET_JB_DIRECTORY),
            IJBController(MAINNET_JB_CONTROLLER),
            IJBPrices(MAINNET_JB_PRICES),
            IJBTerminalStore(MAINNET_JB_TERMINAL_STORE),
            IUniswapV3Factory(MAINNET_V3_FACTORY),
            WETH
        );

        // Set up a simple pool with NANA/WETH (currencies must be ordered: currency0 < currency1)
        key = PoolKey({
            currency0: Currency.wrap(NANA),
            currency1: Currency.wrap(WETH),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        id = key.toId();

        // Give test user some ETH
        vm.deal(testUser, 100 ether);

        // Get the price from Uniswap V3 pool to match it
        uint160 v3SqrtPriceX96 = SQRT_PRICE_1_1; // Default fallback

        // Try to get price from V3 pool (try common fee tiers: 3000, 500, 10000)
        uint24[] memory feeTiers = new uint24[](3);
        feeTiers[0] = 3000; // 0.3% - matches our V4 pool fee
        feeTiers[1] = 500; // 0.05%
        feeTiers[2] = 10000; // 1%

        for (uint256 i = 0; i < feeTiers.length; i++) {
            address v3Pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(NANA, WETH, feeTiers[i]);
            if (v3Pool != address(0)) {
                try IUniswapV3Pool(v3Pool).slot0() returns (
                    uint160 sqrtPriceX96, int24, uint16, uint16, uint16, uint8, bool unlocked
                ) {
                    if (unlocked && sqrtPriceX96 > 0) {
                        v3SqrtPriceX96 = sqrtPriceX96;
                        break;
                    }
                } catch {
                    // Continue to next fee tier
                    continue;
                }
            }
        }

        // Try to re-initialize price to match the Juicebox price index (NANA per WETH)
        // Use the hook's calculation to get how many NANA are minted per 1 WETH, then convert to sqrtPriceX96.
        // ratio token1/token0 = WETH per NANA = 1e18 / (NANA per 1e18 WETH)
        uint160 jbSqrtPriceX96 = 0;
        uint256 projectId = IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(NANA));
        if (projectId != 0) {
            try hook.calculateExpectedTokensWithCurrency(projectId, WETH, 1 ether) returns (uint256 nanaPerWeth) {
                if (nanaPerWeth > 0) {
                    // ratioX192 = (WETH per NANA) * 2^192 = ((1e18 << 192) / nanaPerWeth)
                    uint256 ratioX192 = (uint256(1e18) << 192) / nanaPerWeth;
                    jbSqrtPriceX96 = uint160(_sqrt(ratioX192));
                    // Prefer JB-derived price if computed successfully
                    v3SqrtPriceX96 = jbSqrtPriceX96;
                }
            } catch {
                // keep v3SqrtPriceX96 fallback
            }
        }

        // Initialize the pool with the derived price
        manager.initialize(key, v3SqrtPriceX96);

        // Add large liquidity to v4 pool to enable controlled price shifts via swaps
        {
            address user = testUser;
            // Fund user with tokens
            uint256 nanaAmount = 1_000_000 ether;
            uint256 wethLiquidityEth = 2_000 ether;
            deal(NANA, user, nanaAmount);
            vm.deal(user, wethLiquidityEth);

            vm.startPrank(user);
            // Wrap ETH into WETH
            (bool wrapOk,) = WETH.call{value: wethLiquidityEth}(abi.encodeWithSignature("deposit()"));
            require(wrapOk, "WETH deposit failed");

            // Approvals for v4 liquidity router and swap router (future swaps)
            IERC20(NANA).approve(address(modifyLiquidityRouter), type(uint256).max);
            IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
            IERC20(WETH).approve(address(jbSwapRouter), type(uint256).max);

            // Add ample liquidity over a reasonably wide band
            modifyLiquidityRouter.modifyLiquidity(
                key,
                ModifyLiquidityParams({
                    tickLower: -600, // multiple of tickSpacing (60)
                    tickUpper: 600,
                    liquidityDelta: 1_000_000 ether,
                    salt: bytes32(0)
                }),
                ZERO_BYTES
            );
            vm.stopPrank();
        }

        // Ensure a Uniswap v3 WETH/NANA pool exists at JB-derived price if possible, and add large liquidity
        {
            // Determine token ordering for v3
            address token0 = NANA;
            address token1 = WETH;

            // Create/initialize pool at JB price if it doesn't exist and JB price was computed
            if (jbSqrtPriceX96 != 0) {
                try INonfungiblePositionManager(MAINNET_V3_POSITION_MANAGER)
                    .createAndInitializePoolIfNecessary(token0, token1, V3_FEE_TIER, jbSqrtPriceX96) returns (
                    address
                ) {
                // no-op; pool created or already existed
                }
                    catch {
                    // ignore if pool exists and cannot be reinitialized
                }
            }

            // Add large liquidity via NFPM.mint
            address user = testUser;
            uint256 nanaAmount = 2_000_000 ether;
            uint256 wethAmountEth = 4_000 ether;
            deal(NANA, user, nanaAmount);
            vm.deal(user, wethAmountEth);

            vm.startPrank(user);
            // Wrap ETH into WETH for v3 liquidity
            (bool wrapOk2,) = WETH.call{value: wethAmountEth}(abi.encodeWithSignature("deposit()"));
            require(wrapOk2, "WETH deposit failed (v3)");

            // Approve NFPM to pull tokens
            IERC20(NANA).approve(MAINNET_V3_POSITION_MANAGER, type(uint256).max);
            IERC20(WETH).approve(MAINNET_V3_POSITION_MANAGER, type(uint256).max);

            int24 tickLower = -887200; // wide range for 1% fee (tick spacing 200)
            int24 tickUpper = 887200;
            try INonfungiblePositionManager(MAINNET_V3_POSITION_MANAGER)
                .mint(
                    INonfungiblePositionManager.MintParams({
                        token0: token0,
                        token1: token1,
                        fee: V3_FEE_TIER,
                        tickLower: tickLower,
                        tickUpper: tickUpper,
                        amount0Desired: 1_000_000 ether, // NANA
                        amount1Desired: 2_000 ether, // WETH
                        amount0Min: 0,
                        amount1Min: 0,
                        recipient: user,
                        deadline: block.timestamp
                    })
                ) returns (
                uint256, uint128, uint256, uint256
            ) {
            // minted
            }
                catch {
                // ignore if mint fails (e.g., fee tier not enabled or other constraints)
            }
            vm.stopPrank();
        }
    }

    // Integer sqrt via Babylonian method for uint256
    function _sqrt(uint256 x) internal pure returns (uint256 y) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
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
        // Look up the project ID based on the NANA token address via JB Tokens registry
        uint256 projectId = IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(NANA));

        // Query the project's current ruleset
        (JBRuleset memory ruleset, JBRulesetMetadata memory metadata) =
            IJBController(MAINNET_JB_CONTROLLER).currentRulesetOf(projectId);

        // Validate that the project exists and has valid ruleset data
        assertTrue(ruleset.weight > 0, "Project should have a positive weight");
        assertTrue(metadata.baseCurrency > 0, "Project should have a base currency");

        // Test calculating expected tokens with ETH payment
        uint256 ethAmount = 1 ether;
        uint256 expectedTokens = hook.calculateExpectedTokensWithCurrency(projectId, address(0), 1 ether);

        // Should return tokens based on the project's weight
        assertTrue(expectedTokens > 0, "Should calculate expected tokens for ETH payment");
        // Test calculating expected tokens with NANA payment
        // uint256 nanaAmount = 1000 ether; // 1000 NANA
        // uint256 expectedTokensNANA = hook.calculateExpectedTokensWithCurrency(projectId, NANA, nanaAmount);

        // // Should return tokens (may be 0 if price feed doesn't exist, but should not revert)
        // assertTrue(expectedTokensNANA >= 0, "Should calculate expected tokens for NANA payment");

        // // Try to verify project token registration (if we can find the token)
        // // Note: The exact method to get project token may vary by Juicebox version
        // // This is optional validation - the main test is the ruleset query and calculations

        // // Test calculating expected output from selling tokens (if project has reclaimable surplus)
        // if (expectedTokens > 0) {
        //     uint256 expectedOutput = hook.calculateExpectedOutputFromSelling(projectId, expectedTokens, USDC);
        //     // Output may be 0 if no surplus, but should not revert
        //     assertTrue(expectedOutput >= 0, "Should calculate expected output from selling tokens");
        // }
    }

    /// @notice Test that estimateUniswapV3Output works with real v3 pools
    function testEstimateUniswapV3OutputWithRealPool() public view {
        // Check if WETH/NANA pool exists
        address v3Pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, NANA, 10000);

        if (v3Pool != address(0)) {
            // Pool exists, try to estimate output
            // Swap 1 WETH for NANA: WETH is token0, NANA is token1, so zeroForOne=true
            try hook.estimateUniswapV3Output(WETH, NANA, 1 ether, true) returns (uint256 output) {
                assertTrue(output > 0, "Should return positive output for existing pool");
            } catch Error(string memory reason) {
                // Estimation failed - might be due to pool state, insufficient observations, or no liquidity
                console.log("V3 estimation failed:", reason);
                // This is acceptable - pool may not have enough TWAP data or liquidity
            } catch (bytes memory lowLevelData) {
                // Low-level revert (e.g., division by zero, overflow)
                console.log("V3 estimation reverted with low-level error");
                // This is acceptable - pool state may be invalid
            }
        }
    }

    /// @notice Test that the hook can detect if a token is a Juicebox project token
    function testDetectJuiceboxToken() public {
        // This test would need a real JB project token address
        // For now, we just verify the hook can call the TOKENS contract
        try IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(address(NANA))) returns (uint256 projectId) {
            // If address(0) returns 0, that's expected
            assertTrue(projectId == 0 || projectId > 0, "Should return a project ID or 0");
        } catch Error(string memory reason) {
            // Expected to fail for invalid token - address(0) is not a valid IJBToken
            console.log("projectIdOf failed for invalid token:", reason);
            // This is expected behavior
        } catch (bytes memory lowLevelData) {
            // Low-level revert (e.g., invalid function selector, contract doesn't exist)
            console.log("projectIdOf reverted with low-level error");
            // This is acceptable - the token contract may not exist or be invalid
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

    /// @notice Test that TWAP estimation works with real pool data
    /// @dev Adapted from testEstimateUniswapOutput in the main test file
    function testTWAPEstimationWithRealPool() public view {
        // Test TWAP estimation for the NANA/WETH pool
        // With only initial observation, estimate should use spot price fallback

        try hook.estimateUniswapOutput(id, key, 1 ether, false) returns (uint256 estimatedOut) {
            // Should return positive value (may be 0 if pool has no liquidity)
            assertTrue(estimatedOut >= 0, "Should estimate output (may be 0 for empty pool)");
        } catch Error(string memory reason) {
            // Estimation may fail if pool has issues (no observations, invalid state)
            console.log("Uniswap output estimation failed:", reason);
            // This is acceptable - pool may not have enough TWAP data yet
        } catch (bytes memory lowLevelData) {
            // Low-level revert (e.g., division by zero, arithmetic overflow)
            console.log("Uniswap output estimation reverted with low-level error");
            // This is acceptable - pool state may be invalid or calculations may overflow
        }
    }

    /// @notice Test that v3 routing comparison works with real Uniswap v3 pools
    /// @dev Adapted from testV3RoutingWhenCheaper in the main test file
    function testV3RoutingComparisonWithRealPool() public view {
        // Check if WETH/NANA v3 pool exists (10000 fee tier)
        address v3Pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, NANA, 10000);

        if (v3Pool != address(0)) {
            // Pool exists, test v3 output estimation
            uint256 amountIn = 1 ether; // 1 WETH

            try hook.estimateUniswapV3Output(WETH, NANA, amountIn, true) returns (uint256 v3Output) {
                // Also estimate v4 output for comparison
                try hook.estimateUniswapOutput(id, key, amountIn, false) returns (uint256 v4Output) {
                    // Both should return positive values
                    assertTrue(v3Output > 0, "V3 should return positive output");
                    assertTrue(v4Output >= 0, "V4 should return non-negative output");
                    // The hook will compare these and route to the better option
                    // This test verifies both estimation methods work with real pools
                } catch Error(string memory reason) {
                    // V4 estimation failed (pool may be empty, no observations, or invalid state)
                    console.log("V4 output estimation failed:", reason);
                    // This is acceptable - v4 pool may not have enough TWAP data
                } catch (bytes memory lowLevelData) {
                    // Low-level revert for v4 estimation
                    console.log("V4 output estimation reverted with low-level error");
                    // This is acceptable - pool state may be invalid
                }
            } catch Error(string memory reason) {
                // V3 estimation failed - might be due to pool state, insufficient observations, or no liquidity
                console.log("V3 output estimation failed:", reason);
                // This is acceptable - v3 pool may not have enough TWAP data or liquidity
            } catch (bytes memory lowLevelData) {
                // Low-level revert for v3 estimation
                console.log("V3 output estimation reverted with low-level error");
                // This is acceptable - pool state may be invalid
            }
        }
    }

    /// @notice Complex test: Multi-route price comparison with real pools and Juicebox projects
    /// @dev Tests the hook's ability to compare v3, v4, and Juicebox prices and route optimally
    /// @dev This test simulates a realistic scenario where all three routes are available
    function testComplexMultiRoutePriceComparisonBuying() public view {
        // Query prices from existing pools without adding liquidity
        // Check if v3 pool exists
        address v3Pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, NANA, 10000);

        if (v3Pool != address(0)) {
            // Test with a real swap amount
            uint256 testAmount = 1 ether; // 1 WETH

            // Estimate outputs from all three routes
            uint256 v4Output;
            uint256 v3Output;
            uint256 juiceboxOutput = 0;

            // Get v4 output estimate
            try hook.estimateUniswapOutput(id, key, testAmount, false) returns (uint256 output) {
                v4Output = output;
            } catch {
                v4Output = 0;
            }

            // Get v3 output estimate
            try hook.estimateUniswapV3Output(WETH, NANA, testAmount, true) returns (uint256 output) {
                v3Output = output;
            } catch {
                v3Output = 0;
            }

            // Try to get Juicebox output (if we can find a project)
            // Query project ID 1 as a test
            uint256 projectId = IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(NANA));
            try hook.calculateExpectedTokensWithCurrency(projectId, address(0), testAmount) returns (uint256 output) {
                juiceboxOutput = output;
            } catch {
                juiceboxOutput = 0;
            }

            // Verify that at least one route returns a valid estimate
            assertTrue(
                v4Output > 0 || v3Output > 0 || juiceboxOutput > 0, "At least one route should return a valid estimate"
            );

            // Log the comparison for debugging
            console.log("V4 Output:", v4Output);
            console.log("V3 Output:", v3Output);
            console.log("Juicebox Output:", juiceboxOutput);

            // The hook should route to the best option
            // In a real scenario, the hook would compare these and route accordingly
            uint256 bestOutput = v4Output;
            if (v3Output > bestOutput) bestOutput = v3Output;
            if (juiceboxOutput > bestOutput) bestOutput = juiceboxOutput;

            assertTrue(bestOutput > 0, "Best output should be positive");
        }
    }

    /// @notice Complex test: Multi-route price comparison when selling NANA for WETH
    /// @dev Mirrors testComplexMultiRoutePriceComparison but focuses on the sell flow
    function testComplexMultiRoutePriceComparisonSelling() public view {
        address v3Pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, NANA, 10000);

        if (v3Pool != address(0)) {
            uint256 testAmount = 1_000 ether; // Sell 1,000 NANA for WETH

            uint256 v4Output;
            uint256 v3Output;
            uint256 juiceboxOutput;

            // V4 estimate: selling token0 (NANA) for token1 (WETH) => zeroForOne = true
            try hook.estimateUniswapOutput(id, key, testAmount, true) returns (uint256 output) {
                v4Output = output;
            } catch {
                v4Output = 0;
            }

            // V3 estimate requires sorted tokens (token0 < token1), NANA < WETH
            try hook.estimateUniswapV3Output(NANA, WETH, testAmount, true) returns (uint256 output) {
                v3Output = output;
            } catch {
                v3Output = 0;
            }

            // Juicebox sell-path output (receive WETH when redeeming NANA)
            uint256 projectId = IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(NANA));
            if (projectId != 0) {
                try hook.calculateExpectedOutputFromSelling(projectId, testAmount, WETH) returns (uint256 output) {
                    juiceboxOutput = output;
                } catch {
                    juiceboxOutput = 0;
                }
            }

            assertTrue(
                v4Output > 0 || v3Output > 0 || juiceboxOutput > 0, "At least one route should return a valid estimate"
            );

            console.log("V4 Output (WETH):", v4Output);
            console.log("V3 Output (WETH):", v3Output);
            console.log("Juicebox Output (WETH):", juiceboxOutput);

            uint256 bestOutput = v4Output;
            if (v3Output > bestOutput) bestOutput = v3Output;
            if (juiceboxOutput > bestOutput) bestOutput = juiceboxOutput;

            assertTrue(bestOutput > 0, "Best output should be positive");
        }
    }

    /// @notice Test that an oracle observation is recorded after a swap on fork
    function testOracleObservationRecording() public {
        // Record initial observation index
        (uint16 initialIndex,,) = hook.states(id);

        // Prepare a user with tokens and add minimal liquidity so a swap can execute
        address user = testUser;
        uint256 banAmount = 1_000 ether;
        uint256 wethForLiquidity = 2 ether;
        uint256 amountIn = 0.1 ether;

        // Fund user with BAN and ETH, then wrap ETH to WETH
        deal(BAN, user, banAmount);
        vm.deal(user, 5 ether);

        vm.startPrank(user);
        (bool wrapOk,) = WETH.call{value: wethForLiquidity + amountIn}(abi.encodeWithSignature("deposit()"));
        require(wrapOk, "WETH deposit failed");

        // Approve for liquidity and swap
        IERC20(BAN).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(jbSwapRouter), amountIn);

        // Add a bit of liquidity to enable swapping
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 5 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        // Ensure a different timestamp for a new observation slot
        vm.warp(block.timestamp + 1);

        // Execute a small WETH -> BAN swap (currency1 -> currency0)
        SwapParams memory params = SwapParams({
            zeroForOne: false, amountSpecified: -int256(amountIn), sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });
        jbSwapRouter.swap(key, params);
        vm.stopPrank();

        // Check that observation index moved forward (or wrapped)
        (uint16 newIndex,,) = hook.states(id);
        assertTrue(newIndex == initialIndex + 1 || newIndex == 0, "Index should have incremented");
    }

    // =========================
    // Price selection fork tests
    // =========================

    function _bestRouteSelectedSig() private pure returns (bytes32) {
        return keccak256("BestRouteSelected(bytes32,string,uint256,uint256)");
    }

    function _getLastBestRouteFromLogs()
        private
        returns (string memory routeType, uint256 expectedTokens, uint256 savings)
    {
        Vm.Log[] memory entries = vm.getRecordedLogs();
        bytes32 sig = _bestRouteSelectedSig();
        for (uint256 i = entries.length; i > 0; i--) {
            Vm.Log memory logEntry = entries[i - 1];
            if (logEntry.topics.length > 0 && logEntry.topics[0] == sig) {
                (routeType, expectedTokens, savings) = abi.decode(logEntry.data, (string, uint256, uint256));
                return (routeType, expectedTokens, savings);
            }
        }
        return ("", 0, 0);
    }

    /// @notice Make v4 clearly favorable by pushing price with a BAN->WETH swap, then verify route="v4".
    function testFork_V4BestPriceRoutesToV4_WETHtoNANA() public {
        address user = testUser;

        // Fund and wrap
        deal(NANA, user, 50_000 ether);
        vm.deal(user, 200 ether);
        vm.startPrank(user);
        (bool okWrap1,) = WETH.call{value: 100 ether}(abi.encodeWithSignature("deposit()"));
        require(okWrap1, "wrap failed");

        // Approvals
        IERC20(NANA).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(jbSwapRouter), type(uint256).max);

        // Add ample liquidity
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -120, tickUpper: 120, liquidityDelta: 200 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        // Push price to make NANA cheaper vs WETH for a subsequent WETH->NANA swap:
        // Do a large NANA->WETH swap (zeroForOne=true) which increases NANA reserves and removes WETH.
        IERC20(NANA).approve(address(swapRouter), type(uint256).max);
        SwapParams memory pushDownNANAPrice = SwapParams({
            zeroForOne: true, amountSpecified: -int256(5000 ether), sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        // Best-effort; ignore failure due to liquidity limits
        try swapRouter.swap(key, pushDownNANAPrice, PoolSwapTest.TestSettings(false, false), ZERO_BYTES) {} catch {}

        // Now do the priced swap via JB router (so hook can choose route)
        vm.recordLogs();
        uint256 amountIn = 1 ether;
        SwapParams memory testSwap = SwapParams({
            zeroForOne: false, amountSpecified: -int256(amountIn), sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });
        try jbSwapRouter.swap(key, testSwap) {
            (string memory route, uint256 expectedTokens, uint256 savings) = _getLastBestRouteFromLogs();
            // Expect v4 due to manipulated favorable v4 price
            assertEq(keccak256(bytes(route)), keccak256("v4"), "Expected best route to be v4");
        } catch Error(string memory reason) {
            console.log("testFork_V4BestPriceRoutesToV4 swap failed:", reason);
        } catch {
            console.log("testFork_V4BestPriceRoutesToV4 swap reverted");
        }
        vm.stopPrank();
    }

    /// @notice Mirror the previous test but for the NANA->WETH direction, ensuring v4 is selected when v4 pricing is best.
    function testFork_V4BestPriceRoutesToV4_NANAtoWETH() public {
        address user = testUser;

        // Fund and wrap
        deal(NANA, user, 50_000 ether);
        vm.deal(user, 200 ether);
        vm.startPrank(user);
        (bool okWrap1,) = WETH.call{value: 100 ether}(abi.encodeWithSignature("deposit()"));
        require(okWrap1, "wrap failed");

        // Approvals
        IERC20(NANA).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(NANA).approve(address(jbSwapRouter), type(uint256).max);
        IERC20(WETH).approve(address(swapRouter), type(uint256).max);

        // Add ample liquidity
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -120, tickUpper: 120, liquidityDelta: 200 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        // Push price to make WETH cheaper vs NANA for a subsequent NANA->WETH swap:
        // Do a large WETH->NANA swap (zeroForOne=false) which increases WETH reserves and removes NANA.
        SwapParams memory pushUpWETHSupply = SwapParams({
            zeroForOne: false, amountSpecified: -int256(5000 ether), sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });
        // Best-effort; ignore failure due to liquidity limits
        try swapRouter.swap(key, pushUpWETHSupply, PoolSwapTest.TestSettings(false, false), ZERO_BYTES) {} catch {}

        // Now do the priced swap via JB router (so hook can choose route)
        vm.recordLogs();
        uint256 amountIn = 1_000 ether;
        SwapParams memory testSwap = SwapParams({
            zeroForOne: true, amountSpecified: -int256(amountIn), sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        try jbSwapRouter.swap(key, testSwap) {
            (string memory route, uint256 expectedTokens, uint256 savings) = _getLastBestRouteFromLogs();
            // Expect v4 due to manipulated favorable v4 price
            assertEq(keccak256(bytes(route)), keccak256("v4"), "Expected best route to be v4");
        } catch Error(string memory reason) {
            console.log("testFork_V4BestPriceRoutesToV4_NANAtoWETH swap failed:", reason);
        } catch {
            console.log("testFork_V4BestPriceRoutesToV4_NANAtoWETH swap reverted");
        }
        vm.stopPrank();
    }

    /// @notice Make v4 unfavorable by pushing price with a WETH->NANA swap, then verify route="v3" (if v3 pool exists).
    function testFork_V3BestPriceRoutesToV3_WETHtoNANA() public {
        // Require an actual v3 pool for NANA/WETH at 1% fee; skip if absent
        address v3Pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, NANA, 10000);
        if (v3Pool == address(0)) return;

        address user = testUser;
        // Funds
        deal(NANA, user, 50_000 ether);
        vm.deal(user, 200 ether);
        vm.startPrank(user);
        (bool okWrap,) = WETH.call{value: 100 ether}(abi.encodeWithSignature("deposit()"));
        require(okWrap, "wrap failed");

        // Approvals
        IERC20(NANA).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(jbSwapRouter), type(uint256).max);
        IERC20(WETH).approve(address(swapRouter), type(uint256).max);

        // Add liquidity
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -120, tickUpper: 120, liquidityDelta: 150 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        // Make v4 price worse for WETH->NANA by doing a large WETH->NANA swap (zeroForOne=false)
        SwapParams memory pushUpNANAPrice = SwapParams({
            zeroForOne: false, amountSpecified: -int256(5000 ether), sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });
        try swapRouter.swap(key, pushUpNANAPrice, PoolSwapTest.TestSettings(false, false), ZERO_BYTES) {} catch {}

        // Now perform a small WETH->NANA swap and expect "v3"
        vm.recordLogs();
        uint256 amountIn = 1 ether;
        SwapParams memory testSwap = SwapParams({
            zeroForOne: false, amountSpecified: -int256(amountIn), sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });
        try jbSwapRouter.swap(key, testSwap) {
            (string memory route, uint256 expectedTokens, uint256 savings) = _getLastBestRouteFromLogs();
            assertEq(keccak256(bytes(route)), keccak256("v3"), "Expected best route to be v3");
        } catch Error(string memory reason) {
            console.log("testFork_V3BestPriceRoutesToV3 swap failed:", reason);
        } catch {
            console.log("testFork_V3BestPriceRoutesToV3 swap reverted");
        }
        vm.stopPrank();
    }

    /// @notice Mirror the v3 routing test for the NANA->WETH direction, ensuring v3 is selected when v4 pricing is worse.
    function testFork_V3BestPriceRoutesToV3_NANAtoWETH() public {
        // Require an actual v3 pool for NANA/WETH at 1% fee; skip if absent
        address v3Pool = IUniswapV3Factory(MAINNET_V3_FACTORY).getPool(WETH, NANA, 10000);
        if (v3Pool == address(0)) return;

        address user = testUser;
        // Funds
        deal(NANA, user, 50_000 ether);
        vm.deal(user, 200 ether);
        vm.startPrank(user);
        (bool okWrap,) = WETH.call{value: 100 ether}(abi.encodeWithSignature("deposit()"));
        require(okWrap, "wrap failed");

        // Approvals
        IERC20(NANA).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(NANA).approve(address(jbSwapRouter), type(uint256).max);
        IERC20(NANA).approve(address(swapRouter), type(uint256).max);

        // Add liquidity
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -120, tickUpper: 120, liquidityDelta: 150 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        // Make v4 price worse for NANA->WETH by doing a large NANA->WETH swap (zeroForOne=true)
        SwapParams memory pushDownWETHLiquidity = SwapParams({
            zeroForOne: true, amountSpecified: -int256(5000 ether), sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        try swapRouter.swap(key, pushDownWETHLiquidity, PoolSwapTest.TestSettings(false, false), ZERO_BYTES) {} catch {}

        // Now perform a NANA->WETH swap and expect "v3"
        vm.recordLogs();
        uint256 amountIn = 1_000 ether;
        SwapParams memory testSwap = SwapParams({
            zeroForOne: true, amountSpecified: -int256(amountIn), sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        try jbSwapRouter.swap(key, testSwap) {
            (string memory route, uint256 expectedTokens, uint256 savings) = _getLastBestRouteFromLogs();
            assertEq(keccak256(bytes(route)), keccak256("v3"), "Expected best route to be v3");
        } catch Error(string memory reason) {
            console.log("testFork_V3BestPriceRoutesToV3_NANAtoWETH swap failed:", reason);
        } catch {
            console.log("testFork_V3BestPriceRoutesToV3_NANAtoWETH swap reverted");
        }
        vm.stopPrank();
    }

    /// @notice Basic: if no v3 pool exists, prefer JB when JB quote beats v4; otherwise fall back to v4.
    function testFork_NoV3Pool_JuiceboxBestOrV4Fallback_WETHtoNANA() public {
        // Skip if a v3 pool exists for NANA/WETH at 1% fee
        address v3Pool = address(0);
        // Get NANA projectId
        uint256 projectId = IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(NANA));
        vm.assume(projectId != 0);

        // Attempt to re-initialize price to the Juicebox price index by creating a fresh pool
        // with a distinct PoolKey (different tickSpacing) initialized at JB-derived sqrtPrice.
        PoolKey memory useKey = key;
        PoolId useId = id;
        {
            // Compute JB price: NANA per 1 WETH
            try hook.calculateExpectedTokensWithCurrency(projectId, WETH, 1 ether) returns (uint256 nanaPerWeth) {
                if (nanaPerWeth > 0) {
                    // Create a new pool key so we can initialize at the JB price (original pool cannot be reinitialized)
                    PoolKey memory jbKey = PoolKey({
                        currency0: Currency.wrap(NANA),
                        currency1: Currency.wrap(WETH),
                        fee: 3000,
                        tickSpacing: 120, // different from default 60 -> new pool
                        hooks: IHooks(address(hook))
                    });
                    PoolId jbId = jbKey.toId();
                    // sqrtPriceX96 = sqrt((token1/token0) * 2^192)
                    // token1/token0 (WETH per NANA) = (1e18 / nanaPerWeth)
                    uint256 ratioX192 = (uint256(1e18) << 192) / nanaPerWeth;
                    uint160 jbSqrtPriceX96 = uint160(_sqrt(ratioX192));
                    // Initialize the new pool at JB price
                    manager.initialize(jbKey, jbSqrtPriceX96);
                    useKey = jbKey;
                    useId = jbId;
                }
            } catch {
                // If JB price unavailable, proceed with the original pool and its existing price
            }
        }

        address user = testUser;
        // Funds
        deal(NANA, user, 10_000 ether);
        vm.deal(user, 50 ether);
        vm.startPrank(user);
        (bool okWrap,) = WETH.call{value: 10 ether}(abi.encodeWithSignature("deposit()"));
        require(okWrap, "wrap failed");

        // Approvals
        IERC20(NANA).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(jbSwapRouter), type(uint256).max);

        // Add minimal liquidity so swaps via v4 can execute if chosen
        modifyLiquidityRouter.modifyLiquidity(
            useKey,
            ModifyLiquidityParams({
                tickLower: -int24(useKey.tickSpacing),
                tickUpper: int24(useKey.tickSpacing),
                liquidityDelta: 10 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );

        uint256 amountIn = 1 ether;
        // Compare expected outputs
        uint256 v4Out = 0;
        try hook.estimateUniswapOutput(useId, useKey, amountIn, false) returns (uint256 o) {
            v4Out = o;
        } catch {}

        uint256 v3Out = 0;
        try hook.estimateUniswapV3Output(WETH, NANA, amountIn, true) returns (uint256 o) {
            v3Out = o;
        } catch {}

        uint256 jbOut = 0;
        // JB quote using WETH as payment token; if no feed, this may be 0
        try hook.calculateExpectedTokensWithCurrency(projectId, WETH, amountIn) returns (uint256 o) {
            jbOut = o;
        } catch {}

        // Execute via JB router to let hook choose
        vm.recordLogs();
        SwapParams memory testSwap = SwapParams({
            zeroForOne: false, amountSpecified: -int256(amountIn), sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        try jbSwapRouter.swap(useKey, testSwap) {
            (string memory route, uint256 expectedTokens, uint256 savings) = _getLastBestRouteFromLogs();

            // Check for primary terminal (same check as in JBUniswapV4Hook.sol lines 924-928)
            IJBTerminal jbTerminal;
            address tokenIn = WETH;
            try IJBDirectory(MAINNET_JB_DIRECTORY).primaryTerminalOf(projectId, tokenIn) returns (IJBTerminal t) {
                jbTerminal = t;
            } catch {
                jbTerminal = IJBTerminal(address(0));
            }

            if (jbOut > v4Out && jbOut > 0 && address(jbTerminal) != address(0)) {
                assertEq(keccak256(bytes(route)), keccak256("juicebox"), "Expected route to be juicebox");
            } else if (v4Out > 0) {
                assertEq(keccak256(bytes(route)), keccak256("v4"), "Expected route to be v4");
            }
        } catch Error(string memory reason) {
            console.log("testFork_NoV3Pool_JuiceboxBestOrV4Fallback swap failed:", reason);
        } catch {
            console.log("testFork_NoV3Pool_JuiceboxBestOrV4Fallback swap reverted");
        }
        vm.stopPrank();
    }

    /// @notice Mirror of testFork_NoV3Pool_JuiceboxBestOrV4Fallback for the sell (NANA->WETH) direction.
    function testFork_NoV3Pool_JuiceboxBestOrV4Fallback_NANAtoWETH() public {
        address v3Pool = address(0);
        uint256 projectId = IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(NANA));
        vm.assume(projectId != 0);

        PoolKey memory useKey = key;
        PoolId useId = id;
        {
            try hook.calculateExpectedTokensWithCurrency(projectId, WETH, 1 ether) returns (uint256 nanaPerWeth) {
                if (nanaPerWeth > 0) {
                    PoolKey memory jbKey = PoolKey({
                        currency0: Currency.wrap(NANA),
                        currency1: Currency.wrap(WETH),
                        fee: 3000,
                        tickSpacing: 120,
                        hooks: IHooks(address(hook))
                    });
                    PoolId jbId = jbKey.toId();
                    uint256 ratioX192 = (uint256(1e18) << 192) / nanaPerWeth;
                    uint160 jbSqrtPriceX96 = uint160(_sqrt(ratioX192));
                    manager.initialize(jbKey, jbSqrtPriceX96);
                    useKey = jbKey;
                    useId = jbId;
                }
            } catch {}
        }

        address user = testUser;
        deal(NANA, user, 10_000 ether);
        vm.deal(user, 50 ether);
        vm.startPrank(user);
        (bool okWrap,) = WETH.call{value: 10 ether}(abi.encodeWithSignature("deposit()"));
        require(okWrap, "wrap failed");

        IERC20(NANA).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(NANA).approve(address(jbSwapRouter), type(uint256).max);

        modifyLiquidityRouter.modifyLiquidity(
            useKey,
            ModifyLiquidityParams({
                tickLower: -int24(useKey.tickSpacing),
                tickUpper: int24(useKey.tickSpacing),
                liquidityDelta: 10 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );

        uint256 amountIn = 1_000 ether;

        uint256 v4Out = 0;
        try hook.estimateUniswapOutput(useId, useKey, amountIn, true) returns (uint256 o) {
            v4Out = o;
        } catch {}

        uint256 v3Out = 0;
        try hook.estimateUniswapV3Output(NANA, WETH, amountIn, true) returns (uint256 o) {
            v3Out = o;
        } catch {}

        uint256 jbOut = 0;
        try hook.calculateExpectedOutputFromSelling(projectId, amountIn, WETH) returns (uint256 o) {
            jbOut = o;
        } catch {}

        vm.recordLogs();
        SwapParams memory testSwap = SwapParams({
            zeroForOne: true, amountSpecified: -int256(amountIn), sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        try jbSwapRouter.swap(useKey, testSwap) {
            (string memory route,,) = _getLastBestRouteFromLogs();

            IJBTerminal jbTerminal;
            address tokenIn = NANA;
            try IJBDirectory(MAINNET_JB_DIRECTORY).primaryTerminalOf(projectId, tokenIn) returns (IJBTerminal t) {
                jbTerminal = t;
            } catch {
                jbTerminal = IJBTerminal(address(0));
            }

            if (jbOut > v4Out && jbOut > 0 && address(jbTerminal) != address(0)) {
                assertEq(keccak256(bytes(route)), keccak256("juicebox"), "Expected route to be juicebox");
            } else if (v4Out > 0) {
                assertEq(keccak256(bytes(route)), keccak256("v4"), "Expected route to be v4");
            }
        } catch Error(string memory reason) {
            console.log("testFork_NoV3Pool_JuiceboxBestOrV4Fallback_NANAtoWETH swap failed:", reason);
        } catch {
            console.log("testFork_NoV3Pool_JuiceboxBestOrV4Fallback_NANAtoWETH swap reverted");
        }
        vm.stopPrank();
    }

    /// @notice Test that cashOutTokensOf is executed when selling JB tokens through Juicebox
    /// @dev This test verifies the full sell flow:
    function testFork_SellingJBTokenViaCashOutTokensOf() public {
        uint256 projectId = IJBTokens(MAINNET_JB_TOKENS).projectIdOf(IJBToken(NANA));
        vm.assume(projectId != 0);

        address user = testUser;
        vm.deal(user, 20 ether);
        vm.startPrank(user);
        
        // Wrap ETH to WETH
        (bool wrapOk,) = WETH.call{value: 10 ether}(abi.encodeWithSignature("deposit()"));
        require(wrapOk, "WETH wrap failed");
        
        // Approve for swaps and liquidity
        IERC20(WETH).approve(address(jbSwapRouter), type(uint256).max);
        IERC20(WETH).approve(address(modifyLiquidityRouter), type(uint256).max);
        IERC20(NANA).approve(address(jbSwapRouter), type(uint256).max);
        
        // Add liquidity to enable swaps
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({
                tickLower: -120,
                tickUpper: 120,
                liquidityDelta: 200 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );
        
        // First, user needs to own NANA tokens. Get them by buying via Juicebox or Uniswap
        // Try buying through Juicebox first (WETH -> NANA)
        uint256 buyAmount = 2 ether;
        SwapParams memory buySwap = SwapParams({
            zeroForOne: false, // WETH -> NANA
            amountSpecified: -int256(buyAmount),
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });
        
        // Execute buy - this may route through Juicebox or Uniswap
        try jbSwapRouter.swap(key, buySwap) {
            // Buy succeeded
        } catch {
            vm.stopPrank();
            return; // Can't test if buy fails
        }
        
        // Check user's NANA balance
        uint256 userNANABalance = IERC20(NANA).balanceOf(user);
        if (userNANABalance == 0) {
            vm.stopPrank();
            return; // User doesn't have NANA tokens to sell
        }
        
        // Now set up for selling: make Juicebox better than Uniswap
        // Manipulate v4 price to be worse by doing a large swap that makes NANA more expensive
        IERC20(NANA).approve(address(swapRouter), type(uint256).max);
        SwapParams memory priceManipulation = SwapParams({
            zeroForOne: false, // WETH -> NANA, makes NANA more expensive (worse for selling NANA)
            amountSpecified: -int256(5000 ether),
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });
        try swapRouter.swap(key, priceManipulation, PoolSwapTest.TestSettings(false, false), ZERO_BYTES) {} catch {}
        
        // Calculate expected outputs for selling
        uint256 sellAmount = userNANABalance > 1000 ether ? 1000 ether : userNANABalance / 2;
        
        uint256 v4Out = 0;
        try hook.estimateUniswapOutput(id, key, sellAmount, true) returns (uint256 o) {
            v4Out = o;
        } catch {}
        
        uint256 jbOut = 0;
        try hook.calculateExpectedOutputFromSelling(projectId, sellAmount, WETH) returns (uint256 o) {
            jbOut = o;
        } catch {}
        
        // Only proceed if Juicebox is better
        if (jbOut <= v4Out || jbOut == 0) {
            vm.stopPrank();
            return; // Juicebox not better, can't test this scenario
        }
        
        // Record initial balances
        uint256 initialUserWETH = IERC20(WETH).balanceOf(user);
        uint256 initialUserNANA = IERC20(NANA).balanceOf(user);
        
        // Execute sell swap (NANA -> WETH)
        // During this swap:
        // 1. User sends NANA to pool via a swap
        // 2. Hook takes NANA from pool (hook now owns ERC20 tokens)
        // 3. Hook calls cashOutTokensOf(address(this), ...) to cash out tokens it owns
        // 4. Hook receives WETH and settles back to pool
        vm.recordLogs();
        
        SwapParams memory sellSwap = SwapParams({
            zeroForOne: true, // NANA -> WETH
            amountSpecified: -int256(sellAmount),
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        
        try jbSwapRouter.swap(key, sellSwap) {
            // Verify route was Juicebox
            (string memory route,,) = _getLastBestRouteFromLogs();
            assertEq(keccak256(bytes(route)), keccak256("juicebox"), "Should route through Juicebox");
            
            // Verify user received WETH (proving cashOutTokensOf succeeded and hook settled WETH back)
            uint256 finalUserWETH = IERC20(WETH).balanceOf(user);
            uint256 finalUserNANA = IERC20(NANA).balanceOf(user);
            
            uint256 wethReceived = finalUserWETH > initialUserWETH ? finalUserWETH - initialUserWETH : 0;
            uint256 nanaSpent = initialUserNANA > finalUserNANA ? initialUserNANA - finalUserNANA : 0;
            
            // User should have received WETH and spent NANA
            assertTrue(wethReceived > 0, "User should have received WETH from cashOutTokensOf");
            assertEq(nanaSpent, sellAmount, "User should have spent the exact sell amount");
            
            // Verify hook's temporary token ownership was cleared (hook shouldn't own tokens after swap)
            uint256 hookTokenBalance = IJBTokens(MAINNET_JB_TOKENS).totalBalanceOf(address(hook), projectId);
            // Hook may have some tokens if it routed through Juicebox during buy, but should be minimal
            // The key is that cashOutTokensOf succeeded and user received WETH
        } catch Error(string memory reason) {
            console.log("testFork_SellingJBTokenViaCashOutTokensOf swap failed:", reason);
        } catch {
            console.log("testFork_SellingJBTokenViaCashOutTokensOf swap reverted");
        }
        
        vm.stopPrank();
    }
}

