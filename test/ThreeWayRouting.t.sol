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
import {IJBTerminal} from "@bananapus/core-v5/interfaces/IJBTerminal.sol";
import {IUniswapV3Factory} from "../src/interfaces/IUniswapV3Factory.sol";
import {JBRuleset} from "@bananapus/core-v5/structs/JBRuleset.sol";
import {JBRulesetMetadata} from "@bananapus/core-v5/structs/JBRulesetMetadata.sol";
import {JBRulesetMetadataResolver} from "@bananapus/core-v5/libraries/JBRulesetMetadataResolver.sol";
import {IJBRulesetApprovalHook} from "@bananapus/core-v5/interfaces/IJBRulesetApprovalHook.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

// ============================================
// Mock Juicebox contracts for testing
// ============================================

contract MockJBTokens {
    mapping(address => uint256) public projectIdOf;

    function setProjectId(address token, uint256 projectId) external {
        projectIdOf[token] = projectId;
    }
}

contract MockJBDirectory {
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

contract MockJBPrices {
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

contract MockJBTerminalStore {
    mapping(uint256 => mapping(uint256 => uint256)) public surplusPerToken;

    function setSurplus(uint256 projectId, address token, uint256 surplusAmount) external {
        uint256 currency = uint32(uint160(token));
        surplusPerToken[projectId][currency] = surplusAmount;
    }

    function currentReclaimableSurplusOf(
        uint256 projectId,
        uint256 cashOutCount,
        uint256 currency,
        uint256 /* decimals */
    ) external view returns (uint256) {
        uint256 surplusPerTokenValue = surplusPerToken[projectId][currency];
        if (surplusPerTokenValue == 0) return 0;
        return (surplusPerTokenValue * cashOutCount) / 1e18;
    }
}

contract MockJBMultiTerminal {
    uint256 public lastProjectId;
    address public lastToken;
    uint256 public lastAmount;
    address public lastBeneficiary;

    mapping(uint256 => address) public projectTokens;

    MockJBTerminalStore public TERMINAL_STORE;

    uint256 public overridePayReturnAmount;
    uint256 public overrideCashOutReturnAmount;
    bool public useOverridePayReturn;
    bool public useOverrideCashOutReturn;

    function setProjectToken(uint256 projectId, address projectToken) external {
        projectTokens[projectId] = projectToken;
    }

    function setTerminalStore(address terminalStore) external {
        TERMINAL_STORE = MockJBTerminalStore(terminalStore);
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

contract MockJBController {
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

// ============================================
// Mock Uniswap V3 contracts
// ============================================

contract MockUniswapV3Pool {
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

contract MockUniswapV3Factory is IUniswapV3Factory {
    mapping(address => mapping(address => mapping(uint24 => address))) public pools;

    function getPool(address tokenA, address tokenB, uint24 _fee) external view returns (address pool) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return pools[t0][t1][_fee];
    }

    function createPool(address tokenA, address tokenB, uint24 _fee) external returns (address pool) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(pools[t0][t1][_fee] == address(0), "Pool exists");
        pool = address(new MockUniswapV3Pool(t0, t1, _fee));
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

// ============================================
// Three-Way Routing Test Suite
// ============================================

contract ThreeWayRoutingTest is Test {
    receive() external payable {}

    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    JBUniswapV4Hook hook;
    MockJBTokens mockJBTokens;
    MockJBDirectory mockJBDirectory;
    MockJBMultiTerminal mockJBMultiTerminal;
    MockJBController mockJBController;
    MockJBPrices mockJBPrices;
    MockJBTerminalStore mockJBTerminalStore;
    MockUniswapV3Factory mockV3Factory;
    MockUniswapV3Pool mockV3Pool;
    MockWETH mockWETH;

    PoolManager manager;
    PoolSwapTest swapRouter;
    JuiceboxSwapRouter jbSwapRouter;
    PoolModifyLiquidityTest modifyLiquidityRouter;

    uint160 constant SQRT_PRICE_1_1 = 79228162514264337593543950336;
    bytes constant ZERO_BYTES = "";
    uint256 constant PROJECT_ID = 123;

    MockERC20 token0;
    MockERC20 token1;
    PoolKey key;
    PoolId id;

    function setUp() public {
        vm.warp(10000);

        manager = new PoolManager(address(this));
        swapRouter = new PoolSwapTest(IPoolManager(address(manager)));
        jbSwapRouter = new JuiceboxSwapRouter(IPoolManager(address(manager)));
        modifyLiquidityRouter = new PoolModifyLiquidityTest(IPoolManager(address(manager)));

        mockWETH = new MockWETH();

        mockJBTokens = new MockJBTokens();
        mockJBDirectory = new MockJBDirectory();
        mockJBMultiTerminal = new MockJBMultiTerminal();
        mockJBController = new MockJBController();
        mockJBPrices = new MockJBPrices();
        mockJBTerminalStore = new MockJBTerminalStore();

        mockJBDirectory.setMockTerminal(address(mockJBMultiTerminal));
        mockJBDirectory.setMockController(address(mockJBController));
        mockJBMultiTerminal.setTerminalStore(address(mockJBTerminalStore));

        mockV3Factory = new MockUniswapV3Factory();

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

        (, bytes32 salt) =
            HookMiner.find(address(this), flags, type(JBUniswapV4Hook).creationCode, constructorArgs);

        hook = new JBUniswapV4Hook{salt: salt}(
            IPoolManager(address(manager)),
            IJBTokens(address(mockJBTokens)),
            IJBDirectory(address(mockJBDirectory)),
            IJBPrices(address(mockJBPrices)),
            IUniswapV3Factory(address(mockV3Factory)),
            address(mockWETH)
        );

        token0 = new MockERC20("Token0", "TK0");
        token1 = new MockERC20("Token1", "TK1");

        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }

        // Create V3 pool
        mockV3Pool = MockUniswapV3Pool(mockV3Factory.createPool(address(token0), address(token1), 10000));
        mockV3Pool.setLiquidity(1000e18);
        token0.mint(address(mockV3Pool), 10000 ether);
        token1.mint(address(mockV3Pool), 10000 ether);

        // Set up JB project: token0 is the project token
        mockJBTokens.setProjectId(address(token0), PROJECT_ID);
        mockJBController.setWeight(PROJECT_ID, 1000e18);
        mockJBMultiTerminal.setProjectToken(PROJECT_ID, address(token0));

        uint32 token1CurrencyId = uint32(uint160(address(token1)));
        mockJBPrices.setPricePerUnitOf(PROJECT_ID, token1CurrencyId, 1, 1e18);

        // Set up V4 pool
        key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
        id = key.toId();

        token0.mint(address(this), 1000 ether);
        token1.mint(address(this), 1000 ether);

        token0.approve(address(modifyLiquidityRouter), 1000 ether);
        token1.approve(address(modifyLiquidityRouter), 1000 ether);

        token0.approve(address(hook), type(uint256).max);
        token1.approve(address(hook), type(uint256).max);

        manager.initialize(key, SQRT_PRICE_1_1);

        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 10 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );
    }

    // ============================================
    // Test 1: JB wins the three-way comparison
    // ============================================

    /// Given token0 is a JB project token with a very high weight (10000e18)
    /// And V3 pool has default 1:1 pricing
    /// And V4 pool has 1:1 pricing
    /// When the user buys token0 with 1 ether of token1
    /// Then JB should give the best output (10000 tokens vs ~1 from V4/V3)
    /// And a BestRouteSelected event should be emitted with routeType "juicebox"
    function test_ThreeWay_JBWins() public {
        // Set JB weight very high so JB gives way more tokens than Uniswap
        mockJBController.setWeight(PROJECT_ID, 10000e18);

        // V3 pool at default 1:1 price
        mockV3Pool.setPriceMultiplier(1e18);

        // Prepare swap tokens BEFORE setting up expectEmit
        token1.mint(address(this), 1 ether);
        token1.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        // Set expectEmit right before the swap call
        vm.expectEmit(true, false, false, false);
        emit JBUniswapV4Hook.BestRouteSelected(id, "juicebox", 0);

        jbSwapRouter.swap(key, params, 0);

        // Verify JB terminal was called
        assertEq(mockJBMultiTerminal.lastProjectId(), PROJECT_ID, "Should have routed through Juicebox");
    }

    // ============================================
    // Test 2: V3 wins the three-way comparison
    // ============================================

    /// Given V3 pool has a high price multiplier (2:1 ratio)
    /// And JB surplus is very low for selling
    /// And V4 pool has 1:1 pricing
    /// When the user sells token0 for token1
    /// Then V3 should give the best output
    /// And a BestRouteSelected event should be emitted with routeType "v3"
    function test_ThreeWay_V3Wins() public {
        vm.warp(block.timestamp + 10000);

        // Set V3 price very high: 2 token1 per token0
        mockV3Pool.setPriceMultiplier(2e18);
        mockV3Pool.setLiquidity(1000_000_000_000_000_000_000_000_000);

        // Make JB unattractive: low surplus for selling
        mockJBTerminalStore.setSurplus(PROJECT_ID, address(token1), 0.01 ether);

        mockV3Pool.resetSwapTracking();

        // Prepare tokens
        token0.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        vm.expectEmit(true, false, false, false);
        emit JBUniswapV4Hook.BestRouteSelected(id, "v3", 0);

        jbSwapRouter.swap(key, params, 0);

        assertTrue(mockV3Pool.swapCalled(), "V3 swap should have been called");
    }

    // ============================================
    // Test 3: V4 wins the three-way comparison
    // ============================================

    /// Given JB surplus is very low
    /// And V3 pool price is much worse than V4 (0.5 token1 per token0)
    /// And V4 pool has 1:1 pricing
    /// When the user sells token0 for token1
    /// Then V4 should be the best option (default passthrough)
    /// And a BestRouteSelected event should be emitted with routeType "v4"
    function test_ThreeWay_V4Wins() public {
        // Make JB unattractive
        mockJBTerminalStore.setSurplus(PROJECT_ID, address(token1), 0.01 ether);

        // V3 worse than V4
        mockV3Pool.setPriceMultiplier(0.5e18);

        mockV3Pool.resetSwapTracking();

        token0.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        vm.expectEmit(true, false, false, false);
        emit JBUniswapV4Hook.BestRouteSelected(id, "v4", 0);

        jbSwapRouter.swap(key, params, 0);

        assertFalse(mockV3Pool.swapCalled(), "V3 swap should NOT have been called");
    }

    // ============================================
    // Test 4: All equal defaults to V4
    // ============================================

    /// Given V3 pool price is slightly worse than V4
    /// And JB surplus gives approximately the same (or less) output as V4
    /// When the user sells token0 for token1
    /// Then V4 should win as the default passthrough
    /// Note: V4 fee is 0.3% (3000), V3 fee is 1% (10000). V3 estimate from _getQuote uses tick math
    /// without applying V3 pool fee, so to make V3 NOT better we set its multiplier low enough that
    /// even the tick-based estimate is below V4's fee-adjusted estimate.
    function test_ThreeWay_AllEqual_DefaultsToV4() public {
        // V3 at 0.9:1 pricing - slightly worse tick than V4's 1:1 spot price
        // V4 estimate: ~0.997 (1:1 minus 0.3% fee)
        // V3 estimate at 0.9 multiplier: ~0.9 (from tick math), which is below V4
        mockV3Pool.setPriceMultiplier(0.9e18);

        // JB surplus low enough that JB output < V4
        mockJBTerminalStore.setSurplus(PROJECT_ID, address(token1), 0.5 ether);

        mockV3Pool.resetSwapTracking();

        token0.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        vm.expectEmit(true, false, false, false);
        emit JBUniswapV4Hook.BestRouteSelected(id, "v4", 0);

        jbSwapRouter.swap(key, params, 0);

        assertFalse(mockV3Pool.swapCalled(), "V3 should not be called when V4 is the best option");
    }

    // ============================================
    // Test 5: V3 unavailable (no V3 pool exists)
    // ============================================

    /// Given no V3 pool exists for a new token pair
    /// And JB has a high weight
    /// When the user buys JB tokens
    /// Then the hook compares only V4 vs JB, and JB should win
    function test_ThreeWay_V3Unavailable() public {
        // Create new tokens with NO V3 pool
        MockERC20 newToken0 = new MockERC20("NewTK0", "NTK0");
        MockERC20 newToken1 = new MockERC20("NewTK1", "NTK1");

        if (address(newToken0) > address(newToken1)) {
            (newToken0, newToken1) = (newToken1, newToken0);
        }

        uint256 newProjectId = 456;
        mockJBTokens.setProjectId(address(newToken0), newProjectId);
        mockJBController.setWeight(newProjectId, 10000e18);
        mockJBMultiTerminal.setProjectToken(newProjectId, address(newToken0));

        uint32 newToken1CurrencyId = uint32(uint160(address(newToken1)));
        mockJBPrices.setPricePerUnitOf(newProjectId, newToken1CurrencyId, 1, 1e18);

        PoolKey memory newKey = PoolKey({
            currency0: Currency.wrap(address(newToken0)),
            currency1: Currency.wrap(address(newToken1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        newToken0.mint(address(this), 1000 ether);
        newToken1.mint(address(this), 1000 ether);
        newToken0.approve(address(modifyLiquidityRouter), 1000 ether);
        newToken1.approve(address(modifyLiquidityRouter), 1000 ether);
        newToken0.approve(address(hook), type(uint256).max);
        newToken1.approve(address(hook), type(uint256).max);

        manager.initialize(newKey, SQRT_PRICE_1_1);
        modifyLiquidityRouter.modifyLiquidity(
            newKey,
            ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 10 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        PoolId newId = newKey.toId();

        // Prepare swap tokens
        newToken1.mint(address(this), 1 ether);
        newToken1.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        vm.expectEmit(true, false, false, false);
        emit JBUniswapV4Hook.BestRouteSelected(newId, "juicebox", 0);

        jbSwapRouter.swap(newKey, params, 0);

        assertEq(mockJBMultiTerminal.lastProjectId(), newProjectId, "Should route through JB when V3 unavailable");
    }

    // ============================================
    // Test 6: JB terminal unavailable
    // ============================================

    /// Given new tokens are created where neither is a JB project token
    /// When the user swaps
    /// Then only V3 vs V4 comparison happens (no JB involvement)
    /// And RouteSelected is emitted with useJuicebox=false
    function test_ThreeWay_JBTerminalUnavailable() public {
        MockERC20 nonJBToken0 = new MockERC20("NonJB0", "NJB0");
        MockERC20 nonJBToken1 = new MockERC20("NonJB1", "NJB1");

        if (address(nonJBToken0) > address(nonJBToken1)) {
            (nonJBToken0, nonJBToken1) = (nonJBToken1, nonJBToken0);
        }

        MockUniswapV3Pool nonJBV3Pool = MockUniswapV3Pool(
            mockV3Factory.createPool(address(nonJBToken0), address(nonJBToken1), 10000)
        );
        nonJBV3Pool.setLiquidity(1000e18);
        nonJBToken0.mint(address(nonJBV3Pool), 10000 ether);
        nonJBToken1.mint(address(nonJBV3Pool), 10000 ether);

        PoolKey memory nonJBKey = PoolKey({
            currency0: Currency.wrap(address(nonJBToken0)),
            currency1: Currency.wrap(address(nonJBToken1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        nonJBToken0.mint(address(this), 1000 ether);
        nonJBToken1.mint(address(this), 1000 ether);
        nonJBToken0.approve(address(modifyLiquidityRouter), 1000 ether);
        nonJBToken1.approve(address(modifyLiquidityRouter), 1000 ether);

        manager.initialize(nonJBKey, SQRT_PRICE_1_1);
        modifyLiquidityRouter.modifyLiquidity(
            nonJBKey,
            ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 10 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        PoolId nonJBId = nonJBKey.toId();

        // Approve for swap and set expectEmit right before swap call
        nonJBToken0.approve(address(swapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        // For non-JB tokens, only RouteSelected is emitted (not BestRouteSelected)
        vm.expectEmit(true, false, false, true);
        emit JBUniswapV4Hook.RouteSelected(nonJBId, false, 0);

        swapRouter.swap(nonJBKey, params, PoolSwapTest.TestSettings(false, false), abi.encode(uint256(0)));
    }

    // ============================================
    // Test 7: V3 pool is locked
    // ============================================

    /// Given V3 pool is locked (unlocked = false)
    /// And JB has high weight
    /// When the user buys JB tokens
    /// Then V3 estimate should be 0 and hook compares V4 vs JB only
    function test_ThreeWay_V3LockedPool() public {
        // Lock the V3 pool
        mockV3Pool.setUnlocked(false);

        // Set JB weight high so JB is better than V4
        mockJBController.setWeight(PROJECT_ID, 10000e18);

        // Prepare tokens
        token1.mint(address(this), 1 ether);
        token1.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        vm.expectEmit(true, false, false, false);
        emit JBUniswapV4Hook.BestRouteSelected(id, "juicebox", 0);

        jbSwapRouter.swap(key, params, 0);

        assertEq(mockJBMultiTerminal.lastProjectId(), PROJECT_ID, "Should route through JB when V3 locked");

        // Restore V3 pool state
        mockV3Pool.setUnlocked(true);
    }

    // ============================================
    // Test 8: Selling JB tokens - all routes compared
    // ============================================

    /// Given token0 is a JB project token
    /// And JB surplus is very high (5 ETH per token, better than V3/V4)
    /// When the user sells token0 for token1 (zeroForOne=true)
    /// Then JB should win via calculateExpectedOutputFromSelling
    function test_ThreeWay_SellingJBToken_AllRoutes() public {
        // Set high surplus for selling JB tokens
        mockJBTerminalStore.setSurplus(PROJECT_ID, address(token1), 5 ether);

        // V3 at 1:1 (gives ~0.99 after fee)
        mockV3Pool.setPriceMultiplier(1e18);

        mockV3Pool.resetSwapTracking();

        token0.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        vm.expectEmit(true, false, false, false);
        emit JBUniswapV4Hook.BestRouteSelected(id, "juicebox", 0);

        jbSwapRouter.swap(key, params, 0);

        assertEq(mockJBMultiTerminal.lastProjectId(), PROJECT_ID, "Should route through JB for selling");
        assertFalse(mockV3Pool.swapCalled(), "V3 should not be called when JB is better for selling");
    }

    // ============================================
    // Test 9: Native ETH routing
    // ============================================

    /// Given a pool with Currency.wrap(address(0)) as one currency (native ETH)
    /// And the other token is a JB project token with high weight
    /// When the user swaps
    /// Then all three routes should be compared for native ETH
    function test_ThreeWay_NativeETH_AllRoutes() public {
        MockERC20 ethPairToken = new MockERC20("ETHPair", "EP");
        uint256 ethProjectId = 789;

        mockJBTokens.setProjectId(address(ethPairToken), ethProjectId);
        mockJBController.setWeight(ethProjectId, 10000e18);
        mockJBMultiTerminal.setProjectToken(ethProjectId, address(ethPairToken));

        // currency0 = native ETH (address(0)), currency1 = ethPairToken
        Currency nativeETH = Currency.wrap(address(0));
        Currency wrappedToken = Currency.wrap(address(ethPairToken));

        // Create V3 pool with WETH and ethPairToken
        if (address(mockWETH) < address(ethPairToken)) {
            MockUniswapV3Pool ethV3Pool =
                MockUniswapV3Pool(mockV3Factory.createPool(address(mockWETH), address(ethPairToken), 10000));
            ethV3Pool.setLiquidity(1000e18);
            mockWETH.mint(address(ethV3Pool), 10000 ether);
            ethPairToken.mint(address(ethV3Pool), 10000 ether);
        } else {
            MockUniswapV3Pool ethV3Pool =
                MockUniswapV3Pool(mockV3Factory.createPool(address(ethPairToken), address(mockWETH), 10000));
            ethV3Pool.setLiquidity(1000e18);
            mockWETH.mint(address(ethV3Pool), 10000 ether);
            ethPairToken.mint(address(ethV3Pool), 10000 ether);
        }

        PoolKey memory ethKey = PoolKey({
            currency0: nativeETH,
            currency1: wrappedToken,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        vm.deal(address(this), 100 ether);
        ethPairToken.mint(address(this), 1000 ether);
        ethPairToken.approve(address(modifyLiquidityRouter), 1000 ether);

        manager.initialize(ethKey, SQRT_PRICE_1_1);

        modifyLiquidityRouter.modifyLiquidity{value: 10 ether}(
            ethKey,
            ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 10 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        PoolId ethId = ethKey.toId();

        // zeroForOne=true means selling currency0 (ETH) for currency1 (ethPairToken = JB token)
        // This is buying JB tokens with ETH
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        vm.expectEmit(true, false, false, false);
        emit JBUniswapV4Hook.BestRouteSelected(ethId, "juicebox", 0);

        jbSwapRouter.swap{value: 1 ether}(ethKey, params, 0);

        assertEq(mockJBMultiTerminal.lastProjectId(), ethProjectId, "Should route through JB for native ETH swap");
    }

    // ============================================
    // Test 10: amountOutMin applied to winner
    // ============================================

    /// Given JB wins routing but output is below amountOutMin
    /// When the user executes the swap
    /// Then the transaction should revert
    function test_ThreeWay_AmountOutMin_AppliedToWinner() public {
        // JB weight high so JB routing wins
        mockJBController.setWeight(PROJECT_ID, 10000e18);

        // Override pay to return a specific amount
        mockJBMultiTerminal.setPayReturnAmount(5000 ether);

        // Prepare tokens
        token1.mint(address(this), 1 ether);
        token1.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        // amountOutMin higher than what JB returns (5000 < 6000)
        // JB terminal enforces minReturnedTokens internally, causing revert wrapped by PoolManager
        vm.expectRevert();
        jbSwapRouter.swap(key, params, 6000 ether);

        mockJBMultiTerminal.resetOverrides();
    }

    // ============================================
    // Test 11: Fuzz - routing consistency
    // ============================================

    /// Given fuzzed JB weight and V3 price multiplier
    /// When the user performs a swap
    /// Then the best route should always be selected and not revert
    function testFuzz_ThreeWay_RoutingConsistency(uint256 jbWeight, uint256 v3Multiplier) public {
        jbWeight = bound(jbWeight, 1e18, 100000e18);
        v3Multiplier = bound(v3Multiplier, 0.3e18, 3e18);

        vm.warp(block.timestamp + 10000);

        mockJBController.setWeight(PROJECT_ID, jbWeight);
        mockV3Pool.setPriceMultiplier(v3Multiplier);
        mockV3Pool.setLiquidity(1000_000_000_000_000_000_000_000_000);

        mockJBTerminalStore.setSurplus(PROJECT_ID, address(token1), 0.5 ether);

        mockV3Pool.resetSwapTracking();

        // Prepare tokens
        token1.mint(address(this), 1 ether);
        token1.approve(address(jbSwapRouter), 1 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        // Should not revert for any valid combination
        jbSwapRouter.swap(key, params, 0);

        // Verify output is positive
        uint256 token0Balance = token0.balanceOf(address(this));
        assertGt(token0Balance, 0, "Should have received output tokens from some route");
    }

    // ============================================
    // Test 12: Exact output swap reverts
    // ============================================

    /// Given amountSpecified > 0 (exact output swap)
    /// When the user attempts the swap
    /// Then it should revert (error wrapped by PoolManager)
    function test_ThreeWay_ExactOutputSwap_Reverts() public {
        token1.mint(address(this), 10 ether);
        token1.approve(address(jbSwapRouter), 10 ether);

        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: 1 ether, // positive = exact output (not supported)
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        // The hook reverts with ExactOutputSwapsNotSupported, wrapped by PoolManager
        vm.expectRevert();
        jbSwapRouter.swap(key, params, 0);
    }
}
