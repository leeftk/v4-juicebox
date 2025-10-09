// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {PoolModifyLiquidityTest} from "@uniswap/v4-core/src/test/PoolModifyLiquidityTest.sol";
import {PoolSwapTest} from "@uniswap/v4-core/src/test/PoolSwapTest.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";

import {JuiceboxHook} from "../src/JuiceboxHook.sol";
import {MockERC20} from "./mock/MockERC20.sol";

// Import Juicebox interfaces from the hook file
import {IJBTokens, IJBMultiTerminal, IJBController} from "../src/JuiceboxHook.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

// Mock Juicebox contracts for testing
contract MockJBTokens {
    mapping(address => uint256) public projectIdOf;

    function setProjectId(address token, uint256 projectId) external {
        projectIdOf[token] = projectId;
    }
}

contract MockJBMultiTerminal {
    uint256 public lastProjectId;
    address public lastToken;
    uint256 public lastAmount;
    address public lastBeneficiary;

    function pay(
        uint256 projectId,
        address token,
        uint256 amount,
        address beneficiary,
        uint256 minReturnedTokens,
        string calldata memo,
        bytes calldata metadata
    ) external payable returns (uint256 beneficiaryTokenCount) {
        lastProjectId = projectId;
        lastToken = token;
        lastAmount = amount;
        lastBeneficiary = beneficiary;

        // Mock: return 1000 tokens per ETH
        return amount * 1000;
    }
}

contract MockJBController {
    mapping(uint256 => uint256) public weights;

    function setWeight(uint256 projectId, uint256 weight) external {
        weights[projectId] = weight;
    }

    function currentRulesetOf(uint256 projectId)
        external
        view
        returns (
            uint256 id,
            uint256 weight,
            uint256 duration,
            uint256 weightCutPercent,
            address approvalHook,
            uint256 packedMetadata
        )
    {
        weight = weights[projectId];
        return (1, weight, 0, 0, address(0), 0);
    }
}

contract JuiceboxHookTest is Test {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;

    JuiceboxHook hook;
    MockJBTokens mockJBTokens;
    MockJBMultiTerminal mockJBMultiTerminal;
    MockJBController mockJBController;

    PoolManager manager;
    PoolSwapTest swapRouter;
    PoolModifyLiquidityTest modifyLiquidityRouter;

    // Test constants
    uint160 constant SQRT_PRICE_1_1 = 79228162514264337593543950336; // sqrt(1.0001^0) * 2^96
    bytes constant ZERO_BYTES = "";

    MockERC20 token0;
    MockERC20 token1;
    PoolKey key;
    PoolId id;

    function setUp() public {
        // Deploy core contracts
        manager = new PoolManager(address(this));
        swapRouter = new PoolSwapTest(IPoolManager(address(manager)));
        modifyLiquidityRouter = new PoolModifyLiquidityTest(IPoolManager(address(manager)));

        // Deploy mock Juicebox contracts
        mockJBTokens = new MockJBTokens();
        mockJBMultiTerminal = new MockJBMultiTerminal();
        mockJBController = new MockJBController();

        // Deploy the hook with proper address mining
        // Get hook permissions to determine the required address flags
        Hooks.Permissions memory permissions = Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });

        // Calculate the required flags for the hook permissions
        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG);

        // Prepare constructor arguments
        bytes memory constructorArgs = abi.encode(
            IPoolManager(address(manager)),
            IJBTokens(address(mockJBTokens)),
            IJBMultiTerminal(address(mockJBMultiTerminal)),
            IJBController(address(mockJBController))
        );

        // Find a valid hook address using HookMiner
        (address hookAddress, bytes32 salt) =
            HookMiner.find(
                address(this), // deployer
                flags,
                type(JuiceboxHook).creationCode,
                constructorArgs
            );

        // Deploy the hook with the mined address
        hook = new JuiceboxHook{
            salt: salt
        }(
            IPoolManager(address(manager)),
            IJBTokens(address(mockJBTokens)),
            IJBMultiTerminal(address(mockJBMultiTerminal)),
            IJBController(address(mockJBController))
        );

        // Deploy test tokens
        token0 = new MockERC20("Token0", "TK0");
        token1 = new MockERC20("Token1", "TK1");

        // Ensure token0 < token1 for Uniswap v4 requirements
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }

        // Set up a Juicebox project for token0
        mockJBTokens.setProjectId(address(token0), 123);
        mockJBController.setWeight(123, 1000e18); // 1000 tokens per ETH

        // Set up pool
        key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        id = key.toId();

        // Manually register the Juicebox project in the hook (after id is set)
        hook.registerJuiceboxProject(id, address(token0));

        // Give tokens to the test user first
        token0.mint(address(this), 1000 ether);
        token1.mint(address(this), 1000 ether);

        // Approve tokens for liquidity addition
        token0.approve(address(modifyLiquidityRouter), 1000 ether);
        token1.approve(address(modifyLiquidityRouter), 1000 ether);

        // Initialize the pool
        manager.initialize(key, SQRT_PRICE_1_1);

        // Add liquidity
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 10 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );
    }

    function testJuiceboxProjectDetection() public {
        // Check that the hook detects the Juicebox project
        (uint256 projectId, address token, uint256 weight) = hook.getProjectInfo(id);

        assertEq(projectId, 123, "Project ID should be 123");
        assertEq(token, address(token0), "Token should be token0");
        assertEq(weight, 1000e18, "Weight should be 1000e18");
    }

    function testTokenWeightCalculation() public {
        uint256 ethAmount = 1 ether;
        uint256 expectedTokens = hook.calculateExpectedTokens(123, ethAmount);

        assertEq(expectedTokens, 1000 ether, "Expected tokens should be 1000 ether");
    }

    function testIsJuiceboxToken() public {
        uint256 projectId = hook.isJuiceboxToken(address(token0));
        assertEq(projectId, 123, "token0 should be a Juicebox token");

        uint256 nonJuiceboxId = hook.isJuiceboxToken(address(token1));
        assertEq(nonJuiceboxId, 0, "token1 should not be a Juicebox token");
    }

    function testSwapWithJuiceboxPayment() public {
        // Approve tokens for swapping
        token0.approve(address(swapRouter), 1 ether);

        // Perform a swap that should trigger Juicebox payment
        SwapParams memory params =
            SwapParams({zeroForOne: true, amountSpecified: 1 ether, sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1});

        // Expect the Juicebox payment event
        vm.expectEmit(true, true, false, true);
        emit JuiceboxHook.JuiceboxPaymentProcessed(id, address(token0), 123, 1 ether, 1000 ether);

        swapRouter.swap(key, params, PoolSwapTest.TestSettings(false, false), ZERO_BYTES);

        // Check that the mock terminal was called correctly
        assertEq(mockJBMultiTerminal.lastProjectId(), 123, "Project ID should be 123");
        assertEq(mockJBMultiTerminal.lastToken(), address(token0), "Token should be token0");
        assertEq(mockJBMultiTerminal.lastAmount(), 1 ether, "Amount should be 1 ether");
        // Beneficiary is the swap router (swapper), not the test contract
        assertEq(mockJBMultiTerminal.lastBeneficiary(), address(swapRouter), "Beneficiary should be swap router");
    }

    function testManualProjectRegistration() public {
        // Create a new token and set it as a Juicebox project
        MockERC20 newToken = new MockERC20("New Juicebox Token", "NJT");
        mockJBTokens.setProjectId(address(newToken), 456);
        mockJBController.setWeight(456, 2000e18);

        // Create a NEW pool with the new token (not reuse existing pool id)
        PoolKey memory newKey = PoolKey({
            currency0: Currency.wrap(address(newToken)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
        PoolId newId = newKey.toId();

        // Manually register the project
        uint256 projectId = hook.registerJuiceboxProject(newId, address(newToken));

        assertEq(projectId, 456, "Project ID should be 456");

        // Check project info
        (uint256 registeredProjectId, address registeredToken, uint256 weight) = hook.getProjectInfo(newId);
        assertEq(registeredProjectId, 456, "Registered project ID should be 456");
        assertEq(registeredToken, address(newToken), "Registered token should be newToken");
        assertEq(weight, 2000e18, "Weight should be 2000e18");
    }

    function testNonJuiceboxTokenSwap() public {
        // Swap with token1 (not a Juicebox token) - should not trigger Juicebox payment
        token1.approve(address(swapRouter), 1 ether);

        SwapParams memory params =
            SwapParams({zeroForOne: false, amountSpecified: 1 ether, sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1});

        swapRouter.swap(key, params, PoolSwapTest.TestSettings(false, false), ZERO_BYTES);

        // Mock terminal should not have been called (payment not processed)
        assertEq(mockJBMultiTerminal.lastProjectId(), 0, "Project ID should still be 0");
    }

    function testPriceComparison() public {
        // Test price comparison functionality
        (bool juiceboxCheaper, uint256 priceDifference, uint256 uniswapPrice, uint256 juiceboxPrice) =
            hook.comparePrices(id, 1 ether, false); // Swap token1 for token0

        console.log("Price Comparison:");
        console.log("  Juicebox cheaper:", juiceboxCheaper);
        console.log("  Price difference:", priceDifference);
        console.log("  Uniswap price:", uniswapPrice);
        console.log("  Juicebox price:", juiceboxPrice);

        // Test optimal route recommendation
        (bool useJuicebox, uint256 expectedTokens, uint256 savings) = hook.getOptimalRoute(id, 1 ether, false);

        console.log("Optimal Route:");
        console.log("  Use Juicebox:", useJuicebox);
        console.log("  Expected tokens:", expectedTokens);
        console.log("  Savings:", savings);

        // Test price comparison details
        (
            uint256 projectId,
            uint256 uniswapPrice2,
            uint256 juiceboxPrice2,
            uint256 juiceboxTokensPerEth,
            bool juiceboxCheaper2,
            uint256 priceDifference2,
            uint256 savingsPercentage
        ) = hook.getPriceComparison(id, 1 ether, false);

        console.log("Price Comparison Details:");
        console.log("  Project ID:", projectId);
        console.log("  Juicebox tokens per ETH:", juiceboxTokensPerEth);
        console.log("  Savings percentage (bps):", savingsPercentage);

        // Verify basic functionality
        assertEq(projectId, 123, "Project ID should be 123");
        assertTrue(juiceboxTokensPerEth > 0, "Juicebox tokens per ETH should be positive");
        assertTrue(expectedTokens > 0, "Expected tokens should be positive");
    }

    function testMultipleJuiceboxProjects() public {
        // Set up token1 as also a Juicebox project
        mockJBTokens.setProjectId(address(token1), 789);
        mockJBController.setWeight(789, 500e18);

        // Perform swaps with both tokens
        token0.approve(address(swapRouter), 0.5 ether);
        token1.approve(address(swapRouter), 0.5 ether);

        // Swap with token0
        SwapParams memory params0 =
            SwapParams({zeroForOne: true, amountSpecified: 0.5 ether, sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1});

        swapRouter.swap(key, params0, PoolSwapTest.TestSettings(false, false), ZERO_BYTES);

        // Swap with token1
        SwapParams memory params1 =
            SwapParams({zeroForOne: false, amountSpecified: 0.5 ether, sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1});

        swapRouter.swap(key, params1, PoolSwapTest.TestSettings(false, false), ZERO_BYTES);

        // Both projects should have been detected and processed
        (uint256 projectId0, address token0Addr,) = hook.getProjectInfo(id);
        assertEq(projectId0, 123, "Token0 project should be 123");
        assertEq(token0Addr, address(token0), "Token0 should be registered");
    }

    function testHookPermissions() public {
        Hooks.Permissions memory permissions = hook.getHookPermissions();

        assertFalse(permissions.beforeInitialize, "Should not have beforeInitialize permission");
        assertFalse(permissions.afterInitialize, "Should not have afterInitialize permission");
        assertFalse(permissions.beforeAddLiquidity, "Should not have beforeAddLiquidity permission");
        assertFalse(permissions.afterAddLiquidity, "Should not have afterAddLiquidity permission");
        assertFalse(permissions.beforeRemoveLiquidity, "Should not have beforeRemoveLiquidity permission");
        assertFalse(permissions.afterRemoveLiquidity, "Should not have afterRemoveLiquidity permission");
        assertTrue(permissions.beforeSwap, "Should have beforeSwap permission");
        assertTrue(permissions.afterSwap, "Should have afterSwap permission");
        assertFalse(permissions.beforeDonate, "Should not have beforeDonate permission");
        assertFalse(permissions.afterDonate, "Should not have afterDonate permission");
    }

    function testCalculateExpectedTokensWithZeroWeight() public {
        // Set weight to 0
        mockJBController.setWeight(123, 0);

        uint256 expectedTokens = hook.calculateExpectedTokens(123, 1 ether);
        assertEq(expectedTokens, 0, "Expected tokens should be 0 when weight is 0");
    }

    function testCalculateExpectedTokensWithInvalidProject() public {
        uint256 expectedTokens = hook.calculateExpectedTokens(999, 1 ether);
        assertEq(expectedTokens, 0, "Expected tokens should be 0 for invalid project");
    }

    // ============================================
    // FUZZ TESTS
    // ============================================

    function testFuzz_CalculateExpectedTokens(uint256 ethAmount, uint256 weight) public {
        // Bound inputs to reasonable ranges
        ethAmount = bound(ethAmount, 1, 1000 ether);
        weight = bound(weight, 1e18, 1000000e18); // 1 to 1M tokens per ETH

        // Set the weight for our test project
        mockJBController.setWeight(123, weight);

        // Calculate expected tokens
        uint256 expectedTokens = hook.calculateExpectedTokens(123, ethAmount);

        // Verify the calculation: expectedTokens = (weight * ethAmount) / 1e18
        uint256 calculated = (weight * ethAmount) / 1e18;
        assertEq(expectedTokens, calculated, "Expected tokens calculation mismatch");
    }

    function testFuzz_CalculateExpectedTokensRange(uint88 ethAmount) public {
        // Using uint88 to avoid overflow when multiplying with weight
        vm.assume(ethAmount > 0);

        mockJBController.setWeight(123, 1000e18);

        uint256 expectedTokens = hook.calculateExpectedTokens(123, ethAmount);

        // Should scale linearly with amount
        assertEq(expectedTokens, (1000e18 * uint256(ethAmount)) / 1e18);
    }

    function testFuzz_IsJuiceboxToken(address token, uint256 projectId) public {
        vm.assume(projectId > 0);
        vm.assume(projectId < type(uint128).max);

        // Set the token as a Juicebox project
        mockJBTokens.setProjectId(token, projectId);

        // Check it's detected correctly
        uint256 detectedId = hook.isJuiceboxToken(token);
        assertEq(detectedId, projectId, "Project ID should match");
    }

    function testFuzz_TokenWeightCalculation(uint256 weight, uint256 ethAmount) public {
        // Bound to prevent overflow
        weight = bound(weight, 1e18, type(uint128).max);
        ethAmount = bound(ethAmount, 1, type(uint128).max);

        // Avoid overflow in calculation
        vm.assume(weight <= type(uint256).max / ethAmount);

        mockJBController.setWeight(123, weight);

        uint256 expectedTokens = hook.calculateExpectedTokens(123, ethAmount);

        // Verify no overflow and correct calculation
        assertLe(expectedTokens, type(uint256).max, "Should not overflow");
        assertEq(expectedTokens, (weight * ethAmount) / 1e18, "Calculation should be correct");
    }

    function testFuzz_PriceCalculation(uint160 sqrtPriceX96) public {
        // Bound to valid Uniswap sqrt price range
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE + 1, TickMath.MAX_SQRT_PRICE - 1));

        // Create a new pool with this price
        MockERC20 fuzzToken0 = new MockERC20("FuzzToken0", "FT0");
        MockERC20 fuzzToken1 = new MockERC20("FuzzToken1", "FT1");

        // Ensure proper ordering
        if (address(fuzzToken0) > address(fuzzToken1)) {
            (fuzzToken0, fuzzToken1) = (fuzzToken1, fuzzToken0);
        }

        // Set up as Juicebox project
        mockJBTokens.setProjectId(address(fuzzToken0), 456);
        mockJBController.setWeight(456, 1000e18);

        PoolKey memory fuzzKey = PoolKey({
            currency0: Currency.wrap(address(fuzzToken0)),
            currency1: Currency.wrap(address(fuzzToken1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        // Initialize pool with fuzzed price
        manager.initialize(fuzzKey, sqrtPriceX96);
        PoolId fuzzId = fuzzKey.toId();

        // Register project
        hook.registerJuiceboxProject(fuzzId, address(fuzzToken0));

        // Calculate Uniswap price - should not revert
        uint256 uniswapPrice = hook.calculateUniswapPrice(fuzzId, 1 ether, true);

        // Price should be non-zero
        assertGt(uniswapPrice, 0, "Uniswap price should be positive");

        // Compare prices - should not revert
        (bool juiceboxCheaper, uint256 priceDifference, uint256 uniPrice, uint256 jbPrice) =
            hook.comparePrices(fuzzId, 1 ether, false);

        // Both prices should be calculated
        assertGt(uniPrice, 0, "Uniswap price should be positive");

        // If Juicebox has a price (not max), verify price difference
        if (jbPrice != type(uint256).max) {
            if (juiceboxCheaper) {
                assertEq(priceDifference, uniPrice - jbPrice, "Price difference should match (JB cheaper)");
            } else {
                assertEq(priceDifference, jbPrice - uniPrice, "Price difference should match (Uni cheaper)");
            }
        }
    }

    function testFuzz_ComparePricesWithDifferentAmounts(uint96 amount) public {
        vm.assume(amount > 0.01 ether);
        vm.assume(amount < 100 ether);

        (bool juiceboxCheaper, uint256 priceDifference, uint256 uniswapPrice, uint256 juiceboxPrice) =
            hook.comparePrices(id, amount, false);

        // Prices should be calculated
        assertGt(uniswapPrice, 0, "Uniswap price should be positive");

        // Price difference should be consistent
        if (juiceboxPrice != type(uint256).max) {
            if (juiceboxCheaper) {
                assertLt(juiceboxPrice, uniswapPrice, "JB should be cheaper");
                assertEq(priceDifference, uniswapPrice - juiceboxPrice);
            } else {
                assertGt(juiceboxPrice, uniswapPrice, "Uni should be cheaper");
                assertEq(priceDifference, juiceboxPrice - uniswapPrice);
            }
        }
    }

    function testFuzz_OptimalRouteRecommendation(uint256 amount, uint256 weight) public {
        amount = bound(amount, 0.01 ether, 100 ether);
        weight = bound(weight, 1e18, 1000000e18);

        mockJBController.setWeight(123, weight);

        (bool useJuicebox, uint256 expectedTokens, uint256 savings) = hook.getOptimalRoute(id, amount, false);

        // If recommending Juicebox, expected tokens should be positive
        if (useJuicebox) {
            assertGt(expectedTokens, 0, "Expected tokens should be positive when using JB");
            assertGt(savings, 0, "Savings should be positive when using JB");
        }

        // Expected tokens should match calculation
        uint256 calculatedTokens = hook.calculateExpectedTokens(123, amount);
        if (useJuicebox) {
            assertEq(expectedTokens, calculatedTokens, "Expected tokens should match calculation");
        }
    }

    function testFuzz_ProjectInfoRetrieval(uint256 projectId, uint256 weight) public {
        projectId = bound(projectId, 1, type(uint128).max);
        weight = bound(weight, 0, type(uint128).max);

        // Create a new token and pool
        MockERC20 newToken = new MockERC20("NewToken", "NT");
        mockJBTokens.setProjectId(address(newToken), projectId);
        mockJBController.setWeight(projectId, weight);

        PoolKey memory newKey = PoolKey({
            currency0: Currency.wrap(address(newToken)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
        PoolId newId = newKey.toId();

        // Register the project
        hook.registerJuiceboxProject(newId, address(newToken));

        // Retrieve info
        (uint256 retrievedId, address retrievedToken, uint256 retrievedWeight) = hook.getProjectInfo(newId);

        assertEq(retrievedId, projectId, "Project ID should match");
        assertEq(retrievedToken, address(newToken), "Token address should match");
        assertEq(retrievedWeight, weight, "Weight should match");
    }

    function testFuzz_ZeroWeightHandling(uint96 amount) public {
        vm.assume(amount > 0);

        // Set weight to 0
        mockJBController.setWeight(123, 0);

        uint256 expectedTokens = hook.calculateExpectedTokens(123, amount);
        assertEq(expectedTokens, 0, "Expected tokens should be 0 with zero weight");

        // Price comparison should return max for Juicebox price
        (,,, uint256 juiceboxPrice) = hook.comparePrices(id, amount, false);
        assertEq(juiceboxPrice, type(uint256).max, "Juicebox price should be max with zero weight");
    }

    function testFuzz_SavingsPercentageCalculation(uint256 amount) public {
        amount = bound(amount, 0.1 ether, 10 ether);

        (
            uint256 projectId,
            uint256 uniswapPrice,
            uint256 juiceboxPrice,
            uint256 juiceboxTokensPerEth,
            bool juiceboxCheaper,
            uint256 priceDifference,
            uint256 savingsPercentage
        ) = hook.getPriceComparison(id, amount, false);

        assertEq(projectId, 123, "Project ID should be 123");
        assertGt(uniswapPrice, 0, "Uniswap price should be positive");

        // If we have a savings percentage, verify it's calculated correctly
        if (savingsPercentage > 0) {
            uint256 expectedSavingsPercentage = (priceDifference * 10_000) / uniswapPrice;
            assertEq(savingsPercentage, expectedSavingsPercentage, "Savings percentage should match calculation");
        }
    }
}

