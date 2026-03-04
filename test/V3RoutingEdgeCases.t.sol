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
import {FullMath} from "@uniswap/v4-core/src/libraries/FullMath.sol";

import {JBUniswapV4Hook} from "../src/JBUniswapV4Hook.sol";
import {MockERC20, MockERC20WithDecimals} from "./mock/MockERC20.sol";
import {MockWETH} from "./mock/MockWETH.sol";
import {JuiceboxSwapRouter} from "./utils/JuiceboxSwapRouter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IUniswapV3SwapCallback} from "../lib/v3-core/contracts/interfaces/callback/IUniswapV3SwapCallback.sol";

// Import Juicebox interfaces and structs from the hook file
import {
    IJBTokens,
    IJBMultiTerminal,
    IJBController,
    IJBPrices,
    IJBDirectory,
    IJBTerminalStore
} from "../src/JBUniswapV4Hook.sol";
import {IJBTerminal} from "@bananapus/core-v6/interfaces/IJBTerminal.sol";
import {IUniswapV3Factory} from "../src/interfaces/IUniswapV3Factory.sol";
import {JBRuleset} from "@bananapus/core-v6/structs/JBRuleset.sol";
import {JBRulesetMetadata} from "@bananapus/core-v6/structs/JBRulesetMetadata.sol";
import {JBRulesetMetadataResolver} from "@bananapus/core-v6/libraries/JBRulesetMetadataResolver.sol";
import {IJBRulesetApprovalHook} from "@bananapus/core-v6/interfaces/IJBRulesetApprovalHook.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

// =====================================================================
// Mock Juicebox contracts (copied from JBUniswapV4Hook.t.sol)
// =====================================================================

contract MockJBTokensV3 {
    mapping(address => uint256) public projectIdOf;

    function setProjectId(address token, uint256 projectId) external {
        projectIdOf[token] = projectId;
    }
}

contract MockJBDirectoryV3 {
    address public mockTerminal;
    address public mockController;

    function setMockTerminal(address terminal) external {
        mockTerminal = terminal;
    }

    function setMockController(address controller) external {
        mockController = controller;
    }

    function controllerOf(uint256 /* projectId */ ) external view returns (address) {
        return mockController;
    }

    function primaryTerminalOf(uint256, /* projectId */ address /* token */ ) external view returns (address) {
        return mockTerminal;
    }
}

contract MockJBPricesV3 {
    mapping(uint256 => mapping(uint256 => mapping(uint256 => uint256))) public prices;

    function DEFAULT_PROJECT_ID() external pure returns (uint256) {
        return 0;
    }

    function setPricePerUnitOf(uint256 projectId, uint256 pricingCurrency, uint256 unitCurrency, uint256 price)
        external
    {
        prices[projectId][pricingCurrency][unitCurrency] = price;
    }

    function pricePerUnitOf(uint256 projectId, uint256 pricingCurrency, uint256 unitCurrency, uint256 /* decimals */ )
        external
        view
        returns (uint256)
    {
        uint256 price = prices[projectId][pricingCurrency][unitCurrency];
        return price > 0 ? price : 1e18;
    }
}

contract MockJBMultiTerminalV3 {
    uint256 public lastProjectId;
    address public lastToken;
    uint256 public lastAmount;
    address public lastBeneficiary;

    mapping(uint256 => address) public projectTokens;

    MockJBTerminalStoreV3 public TERMINAL_STORE;

    uint256 public overridePayReturnAmount;
    uint256 public overrideCashOutReturnAmount;
    bool public useOverridePayReturn;
    bool public useOverrideCashOutReturn;

    function setProjectToken(uint256 projectId, address projectToken) external {
        projectTokens[projectId] = projectToken;
    }

    function setTerminalStore(address terminalStore) external {
        TERMINAL_STORE = MockJBTerminalStoreV3(terminalStore);
    }

    function STORE() external view returns (IJBTerminalStore) {
        return IJBTerminalStore(address(TERMINAL_STORE));
    }

    function setPayReturnAmount(uint256 amount) external {
        overridePayReturnAmount = amount;
        useOverridePayReturn = true;
    }

    function setCashOutReturnAmount(uint256 amount) external {
        overrideCashOutReturnAmount = amount;
        useOverrideCashOutReturn = true;
    }

    function resetOverrides() external {
        useOverridePayReturn = false;
        useOverrideCashOutReturn = false;
    }

    function pay(
        uint256 projectId,
        address token,
        uint256 amount,
        address beneficiary,
        uint256 minReturnedTokens,
        string calldata,
        bytes calldata
    ) external payable returns (uint256 beneficiaryTokenCount) {
        lastProjectId = projectId;
        lastToken = token;
        lastAmount = amount;
        lastBeneficiary = beneficiary;

        if (useOverridePayReturn) {
            beneficiaryTokenCount = overridePayReturnAmount;
        } else {
            beneficiaryTokenCount = amount * 1000;
        }

        require(beneficiaryTokenCount >= minReturnedTokens, "Insufficient tokens returned");

        address projectToken = projectTokens[projectId];
        if (projectToken != address(0)) {
            MockERC20(projectToken).mint(beneficiary, beneficiaryTokenCount);
        }

        return beneficiaryTokenCount;
    }

    function cashOutTokensOf(
        address,
        uint256 projectId,
        uint256 cashOutCount,
        address tokenToReclaim,
        uint256 minTokensReclaimed,
        address payable beneficiary,
        bytes calldata
    ) external returns (uint256) {
        lastProjectId = projectId;
        lastToken = tokenToReclaim;
        lastAmount = cashOutCount;
        lastBeneficiary = beneficiary;

        uint256 outputAmount;

        if (useOverrideCashOutReturn) {
            outputAmount = overrideCashOutReturnAmount;
        } else {
            uint256 surplusAmount =
                TERMINAL_STORE.currentReclaimableSurplusOf(projectId, 1 ether, uint32(uint160(tokenToReclaim)), 18);
            outputAmount = (surplusAmount * cashOutCount) / 1e18;
        }

        require(outputAmount >= minTokensReclaimed, "Insufficient tokens reclaimed");

        if (outputAmount > 0) {
            MockERC20(tokenToReclaim).mint(beneficiary, outputAmount);
        }

        return outputAmount;
    }
}

contract MockJBControllerV3 {
    mapping(uint256 => uint256) public weights;
    mapping(uint256 => uint16) public reservedPercents;

    function setWeight(uint256 projectId, uint256 weight) external {
        weights[projectId] = weight;
    }

    function setReservedPercent(uint256 projectId, uint16 reservedPercent) external {
        reservedPercents[projectId] = reservedPercent;
    }

    function currentRulesetOf(uint256 projectId)
        external
        view
        returns (JBRuleset memory ruleset, JBRulesetMetadata memory metadata)
    {
        metadata = JBRulesetMetadata({
            reservedPercent: reservedPercents[projectId],
            cashOutTaxRate: 0,
            baseCurrency: 1,
            pausePay: false,
            pauseCreditTransfers: false,
            allowOwnerMinting: false,
            allowSetCustomToken: false,
            allowTerminalMigration: false,
            allowSetTerminals: false,
            allowSetController: false,
            allowAddAccountingContext: false,
            allowAddPriceFeed: false,
            ownerMustSendPayouts: false,
            holdFees: false,
            useTotalSurplusForCashOuts: false,
            useDataHookForPay: false,
            useDataHookForCashOut: false,
            dataHook: address(0),
            metadata: 0
        });

        ruleset = JBRuleset({
            cycleNumber: 1,
            id: 1,
            basedOnId: 0,
            start: uint48(block.timestamp),
            duration: 0,
            weight: uint112(weights[projectId]),
            weightCutPercent: 0,
            approvalHook: IJBRulesetApprovalHook(address(0)),
            metadata: JBRulesetMetadataResolver.packRulesetMetadata(metadata)
        });
    }
}

contract MockJBTerminalStoreV3 {
    mapping(uint256 => mapping(uint256 => uint256)) public surplusPerToken;

    function setSurplus(uint256 projectId, address token, uint256 surplusAmount) external {
        uint256 currency = uint32(uint160(token));
        surplusPerToken[projectId][currency] = surplusAmount;
    }

    function currentReclaimableSurplusOf(uint256 projectId, uint256 cashOutCount, uint256 currency, uint256)
        external
        view
        returns (uint256)
    {
        uint256 surplusPerTokenValue = surplusPerToken[projectId][currency];
        if (surplusPerTokenValue == 0) return 0;

        return (surplusPerTokenValue * cashOutCount) / 1e18;
    }
}

contract MockUniswapV3PoolV3Edge {
    using SafeERC20 for IERC20;

    address public immutable token0;
    address public immutable token1;
    uint24 public immutable fee;

    bool public unlocked = true;
    uint160 public sqrtPriceX96;
    int24 public tick;
    uint128 public liquidity;

    uint256 public priceMultiplier;

    bool public swapCalled;
    address public lastSwapRecipient;

    function resetSwapTracking() external {
        swapCalled = false;
        lastSwapRecipient = address(0);
    }

    constructor(address _token0, address _token1, uint24 _fee) {
        token0 = _token0;
        token1 = _token1;
        fee = _fee;
        sqrtPriceX96 = 79228162514264337593543950336; // sqrt(1.0) * 2^96
        tick = 0;
        priceMultiplier = 1e18;
    }

    /// @notice Added for edge case testing: allow toggling the unlocked flag
    function setUnlocked(bool _unlocked) external {
        unlocked = _unlocked;
    }

    function setPriceMultiplier(uint256 multiplier) external {
        priceMultiplier = multiplier;
        if (multiplier >= 1e18) {
            uint256 priceRatio = multiplier * (2 ** 96) ** 2 / 1e18;
            sqrtPriceX96 = uint160(sqrt(priceRatio));
        } else {
            uint256 priceRatio = (2 ** 96) ** 2 * 1e18 / multiplier;
            sqrtPriceX96 = uint160(sqrt(priceRatio));
        }

        if (multiplier >= 0.9e18 && multiplier <= 1.1e18) {
            int256 priceRatio = int256(multiplier) - int256(1e18);
            tick = int24((priceRatio * 10000) / int256(1e18));
        } else if (multiplier > 1.1e18) {
            if (multiplier >= 2e18) {
                tick = 6931;
            } else if (multiplier >= 1.5e18) {
                tick = 4050;
            } else if (multiplier >= 1.2e18) {
                tick = 2630;
            } else {
                tick = 1315 + int24((int256(multiplier) - int256(1.1e18)) * 1315 / int256(0.1e18));
            }
        } else {
            if (multiplier <= 0.5e18) {
                tick = -6931;
            } else if (multiplier <= 0.667e18) {
                tick = -4050;
            } else if (multiplier <= 0.833e18) {
                tick = -2630;
            } else {
                tick = -1315 + int24((int256(multiplier) - int256(0.833e18)) * 1315 / int256(0.067e18));
            }
        }
        if (tick > 887272) tick = 887272;
        if (tick < -887272) tick = -887272;
    }

    function setLiquidity(uint128 _liquidity) external {
        liquidity = _liquidity;
    }

    function slot0()
        external
        view
        returns (
            uint160 _sqrtPriceX96,
            int24 _tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool _unlocked
        )
    {
        return (sqrtPriceX96, tick, 0, 2, 2, 0, unlocked);
    }

    function initialize(uint160 _sqrtPriceX96) external {
        sqrtPriceX96 = _sqrtPriceX96;
        unlocked = true;
    }

    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160, bytes calldata data)
        external
        returns (int256 amount0, int256 amount1)
    {
        require(unlocked, "Pool locked");
        require(amountSpecified > 0, "Exact input required");

        swapCalled = true;
        lastSwapRecipient = recipient;

        uint256 amountIn = uint256(amountSpecified);
        uint256 amountOut;

        if (zeroForOne) {
            uint256 amountAfterFee = amountIn * (1000000 - fee) / 1000000;
            amountOut = (amountAfterFee * priceMultiplier) / 1e18;

            amount0 = int256(amountIn);
            amount1 = -int256(amountOut);
        } else {
            uint256 amountAfterFee = amountIn * (1000000 - fee) / 1000000;
            amountOut = (amountAfterFee * 1e18) / priceMultiplier;

            amount0 = -int256(amountOut);
            amount1 = int256(amountIn);
        }

        IUniswapV3SwapCallback(msg.sender).uniswapV3SwapCallback(amount0, amount1, data);

        if (zeroForOne) {
            require(IERC20(token1).balanceOf(address(this)) >= amountOut, "Insufficient token1 in pool");
            IERC20(token1).safeTransfer(recipient, amountOut);
        } else {
            require(IERC20(token0).balanceOf(address(this)) >= amountOut, "Insufficient token0 in pool");
            IERC20(token0).safeTransfer(recipient, amountOut);
        }

        return (amount0, amount1);
    }

    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s)
    {
        uint256 length = secondsAgos.length;
        tickCumulatives = new int56[](length);
        secondsPerLiquidityCumulativeX128s = new uint160[](length);

        uint32 currentTime = uint32(block.timestamp);
        for (uint256 i = 0; i < length; i++) {
            uint32 timeAgo = secondsAgos[i];
            uint32 observationTime = currentTime > timeAgo ? currentTime - timeAgo : 0;
            int56 tickValue = int56(int24(tick));
            tickCumulatives[i] = tickValue * int56(uint56(observationTime));
            if (liquidity > 0 && timeAgo > 0) {
                uint256 pastTime = observationTime;
                secondsPerLiquidityCumulativeX128s[i] = uint160((pastTime << 128) / uint256(liquidity));
            } else if (liquidity > 0) {
                secondsPerLiquidityCumulativeX128s[i] = uint160((uint256(currentTime) << 128) / uint256(liquidity));
            } else {
                secondsPerLiquidityCumulativeX128s[i] = 0;
            }
        }
    }

    function observations(uint256 index)
        external
        view
        returns (uint32 blockTimestamp, int56 tickCumulative, uint160 secondsPerLiquidityCumulativeX128, bool initialized)
    {
        if (index == 0) {
            uint32 currentTimestamp = uint32(block.timestamp);
            int56 currentCumulative = int56(tick) * int56(uint56(currentTimestamp));
            return (currentTimestamp, currentCumulative, 0, true);
        } else {
            uint32 currentTime = uint32(block.timestamp);
            uint32 oldTimestamp;
            if (currentTime >= 7200) {
                oldTimestamp = currentTime - 7200;
            } else if (currentTime >= 3600) {
                oldTimestamp = currentTime - 3600;
            } else {
                oldTimestamp = currentTime > 3600 ? currentTime - 3600 : 1;
            }
            int56 oldCumulative = int56(tick) * int56(uint56(oldTimestamp));
            return (oldTimestamp, oldCumulative, 0, true);
        }
    }

    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }
}

contract MockUniswapV3FactoryV3Edge is IUniswapV3Factory {
    mapping(address => mapping(address => mapping(uint24 => address))) public pools;

    function getPool(address tokenA, address tokenB, uint24 _fee) external view returns (address pool) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return pools[t0][t1][_fee];
    }

    function createPool(address tokenA, address tokenB, uint24 _fee) external returns (address pool) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(pools[t0][t1][_fee] == address(0), "Pool exists");

        pool = address(new MockUniswapV3PoolV3Edge(t0, t1, _fee));
        pools[t0][t1][_fee] = pool;

        return pool;
    }

    function enableFeeAmount(uint24, int24) external {
        // No-op for mock
    }

    function setPool(address tokenA, address tokenB, uint24 _fee, address pool) external {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        pools[t0][t1][_fee] = pool;
    }
}

// =====================================================================
// Test contract
// =====================================================================

contract V3RoutingEdgeCasesTest is Test {
    receive() external payable {}

    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    JBUniswapV4Hook hook;
    MockJBTokensV3 mockJBTokens;
    MockJBDirectoryV3 mockJBDirectory;
    MockJBMultiTerminalV3 mockJBMultiTerminal;
    MockJBControllerV3 mockJBController;
    MockJBPricesV3 mockJBPrices;
    MockJBTerminalStoreV3 mockJBTerminalStore;
    MockUniswapV3FactoryV3Edge mockV3Factory;
    MockUniswapV3PoolV3Edge mockV3Pool;
    MockWETH mockWETH;

    PoolManager manager;
    PoolSwapTest swapRouter;
    JuiceboxSwapRouter jbSwapRouter;
    PoolModifyLiquidityTest modifyLiquidityRouter;

    uint160 constant SQRT_PRICE_1_1 = 79228162514264337593543950336;
    bytes constant ZERO_BYTES = "";

    MockERC20 token0;
    MockERC20 token1;
    PoolKey key;
    PoolId id;

    function setUp() public {
        // Warp to a reasonable timestamp so that TWAP observations work properly
        vm.warp(10_000);

        // Deploy core contracts
        manager = new PoolManager(address(this));
        swapRouter = new PoolSwapTest(IPoolManager(address(manager)));
        jbSwapRouter = new JuiceboxSwapRouter(IPoolManager(address(manager)));
        modifyLiquidityRouter = new PoolModifyLiquidityTest(IPoolManager(address(manager)));

        // Deploy mock Juicebox contracts
        mockJBTokens = new MockJBTokensV3();
        mockJBDirectory = new MockJBDirectoryV3();
        mockJBMultiTerminal = new MockJBMultiTerminalV3();
        mockJBController = new MockJBControllerV3();
        mockJBPrices = new MockJBPricesV3();
        mockJBTerminalStore = new MockJBTerminalStoreV3();

        // Set up the directory to point to the terminal and controller
        mockJBDirectory.setMockTerminal(address(mockJBMultiTerminal));
        mockJBDirectory.setMockController(address(mockJBController));

        // Set up the terminal store reference in the terminal
        mockJBMultiTerminal.setTerminalStore(address(mockJBTerminalStore));

        // Deploy mock V3 factory
        mockV3Factory = new MockUniswapV3FactoryV3Edge();

        // Deploy mock WETH
        mockWETH = new MockWETH();

        // Calculate the required hook flags
        uint160 flags = uint160(
            Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG
                | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_ADD_LIQUIDITY_FLAG
                | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
        );

        bytes memory constructorArgs = abi.encode(
            IPoolManager(address(manager)),
            IJBTokens(address(mockJBTokens)),
            IJBDirectory(address(mockJBDirectory)),
            IJBPrices(address(mockJBPrices)),
            IUniswapV3Factory(address(mockV3Factory)),
            address(mockWETH)
        );

        // Find a valid hook address using HookMiner
        (, bytes32 salt) = HookMiner.find(address(this), flags, type(JBUniswapV4Hook).creationCode, constructorArgs);

        // Deploy the hook with the mined address
        hook = new JBUniswapV4Hook{salt: salt}(
            IPoolManager(address(manager)),
            IJBTokens(address(mockJBTokens)),
            IJBDirectory(address(mockJBDirectory)),
            IJBPrices(address(mockJBPrices)),
            IUniswapV3Factory(address(mockV3Factory)),
            address(mockWETH)
        );

        // Deploy test tokens
        token0 = new MockERC20("Token0", "TK0");
        token1 = new MockERC20("Token1", "TK1");

        // Ensure token0 < token1 for Uniswap v4 requirements
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }

        // Create v3 pool for token0/token1 pair (10000 fee tier)
        mockV3Pool = MockUniswapV3PoolV3Edge(mockV3Factory.createPool(address(token0), address(token1), 10000));

        // Set up high liquidity for v3 pool
        mockV3Pool.setLiquidity(1000e18);

        // Mint tokens to the v3 pool so it can handle swaps
        token0.mint(address(mockV3Pool), 10000 ether);
        token1.mint(address(mockV3Pool), 10000 ether);

        // Set up a Juicebox project for token0
        mockJBTokens.setProjectId(address(token0), 123);
        mockJBController.setWeight(123, 1000e18);
        mockJBMultiTerminal.setProjectToken(123, address(token0));

        // Set a 1:1 ETH price for token1
        uint32 token1CurrencyId = uint32(uint160(address(token1)));
        uint256 baseCurrency = 1;
        mockJBPrices.setPricePerUnitOf(123, token1CurrencyId, baseCurrency, 1e18);

        // Set up V4 pool
        key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        id = key.toId();

        // Give tokens to the test user
        token0.mint(address(this), 1000 ether);
        token1.mint(address(this), 1000 ether);

        // Approve tokens for liquidity addition
        token0.approve(address(modifyLiquidityRouter), 1000 ether);
        token1.approve(address(modifyLiquidityRouter), 1000 ether);

        // Approve tokens for the hook
        token0.approve(address(hook), type(uint256).max);
        token1.approve(address(hook), type(uint256).max);

        // Initialize the pool
        manager.initialize(key, SQRT_PRICE_1_1);

        // Add liquidity
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 10 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );
    }

    // =====================================================================
    // Test 1: V3 pool does not exist -> estimateUniswapV3Output returns 0
    // =====================================================================
    function test_V3Pool_DoesNotExist_ReturnsZeroEstimate() public view {
        // Create two fresh token addresses that have no V3 pool registered
        address fakeTokenA = address(0xAAAA);
        address fakeTokenB = address(0xBBBB);

        // Ensure proper ordering
        (address t0, address t1) = fakeTokenA < fakeTokenB ? (fakeTokenA, fakeTokenB) : (fakeTokenB, fakeTokenA);

        // Call estimateUniswapV3Output — _getQuote should find no pool from the factory and return 0
        uint256 estimate = hook.estimateUniswapV3Output(t0, t1, 1 ether, true);
        assertEq(estimate, 0, "Estimate should be 0 when V3 pool does not exist");
    }

    // =====================================================================
    // Test 2: V3 pool is locked -> estimateUniswapV3Output returns 0
    // =====================================================================
    function test_V3Pool_Locked_ReturnsZeroEstimate() public {
        // Lock the pool using our setUnlocked function
        mockV3Pool.setUnlocked(false);

        // Call estimateUniswapV3Output — _getQuote checks slot0().unlocked and returns 0 if false
        uint256 estimate =
            hook.estimateUniswapV3Output(address(token0), address(token1), 1 ether, true);
        assertEq(estimate, 0, "Estimate should be 0 when V3 pool is locked");

        // Restore
        mockV3Pool.setUnlocked(true);
    }

    // =====================================================================
    // Test 3: uniswapV3SwapCallback from non-pool address -> reverts
    // =====================================================================
    function test_V3Callback_InvalidSender_Reverts() public {
        // Call uniswapV3SwapCallback from this test contract (not a valid V3 pool)
        // The callback validates msg.sender against V3_FACTORY.getPool()
        bytes memory data = abi.encode(address(token0), address(token1), uint24(10000));

        vm.expectRevert(JBUniswapV4Hook.JBUniswapV4Hook_InvalidCallback.selector);
        hook.uniswapV3SwapCallback(1, -1, data);
    }

    // =====================================================================
    // Test 4: uniswapV3SwapCallback with both deltas <= 0 -> reverts
    // =====================================================================
    function test_V3Callback_BothDeltasNegative_Reverts() public {
        // Even if called from the correct pool address, both deltas <= 0 should revert first
        // The check `amount0Delta <= 0 && amount1Delta <= 0` is before the sender validation
        bytes memory data = abi.encode(address(token0), address(token1), uint24(10000));

        // Prank as the mock V3 pool to pass the sender check
        vm.prank(address(mockV3Pool));
        vm.expectRevert(JBUniswapV4Hook.JBUniswapV4Hook_NoSwap.selector);
        hook.uniswapV3SwapCallback(-1, -1, data);
    }

    // =====================================================================
    // Test 5: Native ETH converts to WETH for V3 routing
    // =====================================================================
    function test_V3Routing_NativeETH_ConvertsToWETH() public {
        // The hook's _convertToV3Token replaces address(0) with WETH for V3 operations.
        // We verify by creating a V3 pool with WETH as one side and checking that
        // estimateUniswapV3Output resolves correctly.

        // Create a new token to pair with WETH
        MockERC20 otherToken = new MockERC20("Other", "OTH");

        // Order tokens
        address wethAddr = address(mockWETH);
        address otherAddr = address(otherToken);
        (address t0, address t1) = wethAddr < otherAddr ? (wethAddr, otherAddr) : (otherAddr, wethAddr);

        // Create a V3 pool for WETH/otherToken
        MockUniswapV3PoolV3Edge wethPool =
            MockUniswapV3PoolV3Edge(mockV3Factory.createPool(t0, t1, 10000));
        wethPool.setLiquidity(100e18);

        // Now call estimateUniswapV3Output with the native ETH address(0) pair
        // The hook internally converts address(0) -> WETH via _convertToV3Token in _beforeSwap
        // but estimateUniswapV3Output takes token addresses directly.
        // We verify the pool resolution works with WETH addresses.
        bool zeroForOne = wethAddr < otherAddr;
        uint256 estimate = hook.estimateUniswapV3Output(t0, t1, 1 ether, zeroForOne);

        // With liquidity > 0 and a valid pool, we should get a non-zero estimate
        assertGt(estimate, 0, "WETH pool should return non-zero estimate");
    }

    // =====================================================================
    // Test 6: V3 pool with zero liquidity -> _getQuote returns 0
    // =====================================================================
    function test_V3Quote_ZeroLiquidity_ReturnsZero() public {
        // Set V3 pool liquidity to 0
        mockV3Pool.setLiquidity(0);

        // The _getQuote path checks `if (liquidity == 0) return 0` after resolving TWAP/spot
        uint256 estimate =
            hook.estimateUniswapV3Output(address(token0), address(token1), 1 ether, true);
        assertEq(estimate, 0, "Estimate should be 0 when V3 pool has zero liquidity");

        // Restore liquidity
        mockV3Pool.setLiquidity(1000e18);
    }

    // =====================================================================
    // Test 7: Oldest observation age is 0 -> falls back to spot tick
    // =====================================================================
    function test_V3Quote_OldestObservation_SpotFallback() public {
        // Create a fresh pool where the oldest observation has the same timestamp as now
        // This makes _getOldestObservationSecondsAgo return 0, triggering the spot fallback path
        MockERC20 freshToken0 = new MockERC20("Fresh0", "FR0");
        MockERC20 freshToken1 = new MockERC20("Fresh1", "FR1");
        if (address(freshToken0) > address(freshToken1)) {
            (freshToken0, freshToken1) = (freshToken1, freshToken0);
        }

        // Deploy a custom mock pool that returns observation timestamp == block.timestamp
        // causing _getOldestObservationSecondsAgo to return 0
        MockUniswapV3PoolSpotFallback spotPool =
            new MockUniswapV3PoolSpotFallback(address(freshToken0), address(freshToken1), 10000);
        spotPool.setLiquidity(100e18);

        // Register the pool in the factory
        mockV3Factory.setPool(address(freshToken0), address(freshToken1), 10000, address(spotPool));

        // Call estimateUniswapV3Output -> should use spot tick fallback path and return non-zero
        uint256 estimate = hook.estimateUniswapV3Output(
            address(freshToken0), address(freshToken1), 1 ether, true
        );

        // With tick=0 (1:1 price) and liquidity > 0, the spot fallback should yield a non-zero quote
        assertGt(estimate, 0, "Spot fallback should produce a non-zero estimate");
    }

    // =====================================================================
    // Test 8: Positive amountSpecified -> reverts (exact output not supported)
    // =====================================================================
    function test_V3Routing_PositiveAmountSpecified_Reverts() public {
        // The hook's _beforeSwap reverts with JBUniswapV4Hook_ExactOutputSwapsNotSupported
        // when params.amountSpecified > 0
        token1.mint(address(this), 1 ether);
        token1.approve(address(jbSwapRouter), 1 ether);

        // Positive amountSpecified = exact output swap
        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: 1 ether, // positive = exact output, which is not supported
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        vm.expectRevert();
        jbSwapRouter.swap(key, params, 0);
    }

    // =====================================================================
    // Test 9: Valid TWAP observations -> returns positive estimate
    // =====================================================================
    function test_V3Quote_ValidTWAP_ReturnsNonZero() public {
        // The default setUp already has a pool with liquidity=1000e18 and tick=0 (1:1 price)
        // The mock observations() returns an old observation 2 hours ago, enabling TWAP

        // Warp forward so TWAP window is well-established
        vm.warp(block.timestamp + 7200);

        uint256 estimate =
            hook.estimateUniswapV3Output(address(token0), address(token1), 1 ether, true);

        // With a valid TWAP at tick=0 (1:1 price), 1 ether input should produce close to 1 ether output
        assertGt(estimate, 0, "Valid TWAP should return a positive estimate");
        // At 1:1 price, output should be in a reasonable range (no fee applied by _getQuote)
        assertGt(estimate, 0.5 ether, "Output should be within a reasonable range of input for 1:1 price");
    }

    // =====================================================================
    // Test 10: Valid pool callback succeeds (simulated via mock pool swap)
    // =====================================================================
    function test_V3Callback_ValidPool_Succeeds() public {
        // Give the hook tokens so it can pay the callback
        token0.mint(address(hook), 10 ether);

        // Encode the callback data the same way the hook does
        bytes memory callbackData = abi.encode(address(token0), address(token1), uint24(10000));

        // Record pool balance before the callback
        uint256 poolBalBefore = token0.balanceOf(address(mockV3Pool));

        // Prank as the V3 pool (the valid sender) — use startPrank so the callback call is from the pool
        vm.startPrank(address(mockV3Pool));

        // amount0Delta > 0 means pool demands token0 payment. amount1Delta < 0 means output.
        // The hook should transfer token0 to msg.sender (the pool).
        hook.uniswapV3SwapCallback(int256(1 ether), -int256(0.99 ether), callbackData);

        vm.stopPrank();

        uint256 poolBalAfter = token0.balanceOf(address(mockV3Pool));

        // Verify the hook transferred 1 ether of token0 to the pool
        assertEq(poolBalAfter - poolBalBefore, 1 ether, "Hook should have transferred 1 ether of token0 to pool");
    }
}

// =====================================================================
// Helper mock: V3 pool where oldest observation == current timestamp
// This makes _getOldestObservationSecondsAgo() return 0, triggering spot fallback
// =====================================================================
contract MockUniswapV3PoolSpotFallback {
    address public immutable token0;
    address public immutable token1;
    uint24 public immutable fee;

    bool public unlocked = true;
    uint160 public sqrtPriceX96;
    int24 public tick;
    uint128 public liquidity;

    constructor(address _token0, address _token1, uint24 _fee) {
        token0 = _token0;
        token1 = _token1;
        fee = _fee;
        sqrtPriceX96 = 79228162514264337593543950336; // 1:1 price
        tick = 0;
    }

    function setLiquidity(uint128 _liquidity) external {
        liquidity = _liquidity;
    }

    function slot0()
        external
        view
        returns (
            uint160 _sqrtPriceX96,
            int24 _tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool _unlocked
        )
    {
        return (sqrtPriceX96, tick, 0, 2, 2, 0, unlocked);
    }

    /// @notice Both observations return the current block.timestamp so
    /// _getOldestObservationSecondsAgo computes block.timestamp - block.timestamp = 0
    function observations(uint256)
        external
        view
        returns (uint32 blockTimestamp, int56 tickCumulative, uint160 secondsPerLiquidityCumulativeX128, bool initialized)
    {
        // Always return current timestamp — makes oldest observation age == 0
        uint32 ts = uint32(block.timestamp);
        return (ts, int56(tick) * int56(uint56(ts)), 0, true);
    }

    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s)
    {
        uint256 length = secondsAgos.length;
        tickCumulatives = new int56[](length);
        secondsPerLiquidityCumulativeX128s = new uint160[](length);

        uint32 currentTime = uint32(block.timestamp);
        for (uint256 i = 0; i < length; i++) {
            uint32 timeAgo = secondsAgos[i];
            uint32 observationTime = currentTime > timeAgo ? currentTime - timeAgo : 0;
            tickCumulatives[i] = int56(tick) * int56(uint56(observationTime));
            if (liquidity > 0) {
                secondsPerLiquidityCumulativeX128s[i] = uint160((uint256(observationTime) << 128) / uint256(liquidity));
            }
        }
    }
}
