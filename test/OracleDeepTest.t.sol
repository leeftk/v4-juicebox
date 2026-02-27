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

// ============================================================
// Mock contracts (copied from JBUniswapV4Hook.t.sol since
// Forge compiles test files independently)
// ============================================================

contract MockJBTokens_Oracle {
    mapping(address => uint256) public projectIdOf;

    function setProjectId(address token, uint256 projectId) external {
        projectIdOf[token] = projectId;
    }
}

contract MockJBDirectory_Oracle {
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

contract MockJBPrices_Oracle {
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

contract MockJBTerminalStore_Oracle {
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

contract MockJBMultiTerminal_Oracle {
    uint256 public lastProjectId;
    address public lastToken;
    uint256 public lastAmount;
    address public lastBeneficiary;
    mapping(uint256 => address) public projectTokens;
    MockJBTerminalStore_Oracle public TERMINAL_STORE;
    uint256 public overridePayReturnAmount;
    bool public useOverridePayReturn;

    function setProjectToken(uint256 projectId, address projectToken) external {
        projectTokens[projectId] = projectToken;
    }

    function setTerminalStore(address terminalStore) external {
        TERMINAL_STORE = MockJBTerminalStore_Oracle(terminalStore);
    }

    function STORE() external view returns (IJBTerminalStore) {
        return IJBTerminalStore(address(TERMINAL_STORE));
    }

    function setPayReturnAmount(uint256 amount) external {
        overridePayReturnAmount = amount;
        useOverridePayReturn = true;
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
        uint256 surplusAmount =
            TERMINAL_STORE.currentReclaimableSurplusOf(projectId, 1 ether, uint32(uint160(tokenToReclaim)), 18);
        outputAmount = (surplusAmount * cashOutCount) / 1e18;

        require(outputAmount >= minTokensReclaimed, "Insufficient tokens reclaimed");

        if (outputAmount > 0) {
            MockERC20(tokenToReclaim).mint(beneficiary, outputAmount);
        }

        return outputAmount;
    }
}

contract MockJBController_Oracle {
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

contract MockUniswapV3Pool_Oracle {
    using SafeERC20 for IERC20;

    address public immutable token0;
    address public immutable token1;
    uint24 public immutable fee;

    bool public unlocked = true;
    uint160 public sqrtPriceX96;
    int24 public tick;
    uint128 public liquidity;
    uint256 public priceMultiplier;

    constructor(address _token0, address _token1, uint24 _fee) {
        token0 = _token0;
        token1 = _token1;
        fee = _fee;
        sqrtPriceX96 = 79228162514264337593543950336;
        tick = 0;
        priceMultiplier = 1e18;
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

    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160, bytes calldata data)
        external
        returns (int256 amount0, int256 amount1)
    {
        require(unlocked, "Pool locked");
        require(amountSpecified > 0, "Exact input required");

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
}

contract MockUniswapV3Factory_Oracle is IUniswapV3Factory {
    mapping(address => mapping(address => mapping(uint24 => address))) public pools;

    function getPool(address tokenA, address tokenB, uint24 _fee) external view returns (address pool) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return pools[t0][t1][_fee];
    }

    function createPool(address tokenA, address tokenB, uint24 _fee) external returns (address pool) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(pools[t0][t1][_fee] == address(0), "Pool exists");
        pool = address(new MockUniswapV3Pool_Oracle(t0, t1, _fee));
        pools[t0][t1][_fee] = pool;
        return pool;
    }

    function enableFeeAmount(uint24, int24) external {}

    function setPool(address tokenA, address tokenB, uint24 _fee, address pool) external {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        pools[t0][t1][_fee] = pool;
    }
}

// ============================================================
// Oracle Deep Test
// ============================================================

contract OracleDeepTest is Test {
    receive() external payable {}

    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    JBUniswapV4Hook hook;
    MockJBTokens_Oracle mockJBTokens;
    MockJBDirectory_Oracle mockJBDirectory;
    MockJBMultiTerminal_Oracle mockJBMultiTerminal;
    MockJBController_Oracle mockJBController;
    MockJBPrices_Oracle mockJBPrices;
    MockJBTerminalStore_Oracle mockJBTerminalStore;
    MockUniswapV3Factory_Oracle mockV3Factory;
    MockUniswapV3Pool_Oracle mockV3Pool;

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
        // Start at a reasonable timestamp so TWAP calculations work
        vm.warp(10_000);

        // Deploy core contracts
        manager = new PoolManager(address(this));
        swapRouter = new PoolSwapTest(IPoolManager(address(manager)));
        jbSwapRouter = new JuiceboxSwapRouter(IPoolManager(address(manager)));
        modifyLiquidityRouter = new PoolModifyLiquidityTest(IPoolManager(address(manager)));

        // Deploy mock Juicebox contracts
        mockJBTokens = new MockJBTokens_Oracle();
        mockJBDirectory = new MockJBDirectory_Oracle();
        mockJBMultiTerminal = new MockJBMultiTerminal_Oracle();
        mockJBController = new MockJBController_Oracle();
        mockJBPrices = new MockJBPrices_Oracle();
        mockJBTerminalStore = new MockJBTerminalStore_Oracle();

        mockJBDirectory.setMockTerminal(address(mockJBMultiTerminal));
        mockJBDirectory.setMockController(address(mockJBController));
        mockJBMultiTerminal.setTerminalStore(address(mockJBTerminalStore));

        // Deploy mock v3 factory
        mockV3Factory = new MockUniswapV3Factory_Oracle();

        // Calculate the required hook flags
        uint160 flags = uint160(
            Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG
                | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_ADD_LIQUIDITY_FLAG
                | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
        );

        address testWETH = address(0x1234567890123456789012345678901234567890);

        bytes memory constructorArgs = abi.encode(
            IPoolManager(address(manager)),
            IJBTokens(address(mockJBTokens)),
            IJBDirectory(address(mockJBDirectory)),
            IJBPrices(address(mockJBPrices)),
            IUniswapV3Factory(address(mockV3Factory)),
            testWETH
        );

        (, bytes32 salt) = HookMiner.find(address(this), flags, type(JBUniswapV4Hook).creationCode, constructorArgs);

        hook = new JBUniswapV4Hook{salt: salt}(
            IPoolManager(address(manager)),
            IJBTokens(address(mockJBTokens)),
            IJBDirectory(address(mockJBDirectory)),
            IJBPrices(address(mockJBPrices)),
            IUniswapV3Factory(address(mockV3Factory)),
            testWETH
        );

        // Deploy test tokens
        token0 = new MockERC20("Token0", "TK0");
        token1 = new MockERC20("Token1", "TK1");

        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }

        // Create v3 pool for token0/token1 pair
        mockV3Pool = MockUniswapV3Pool_Oracle(mockV3Factory.createPool(address(token0), address(token1), 10000));
        mockV3Pool.setLiquidity(1000e18);
        token0.mint(address(mockV3Pool), 10000 ether);
        token1.mint(address(mockV3Pool), 10000 ether);

        // Set up a Juicebox project for token0
        mockJBTokens.setProjectId(address(token0), 123);
        mockJBController.setWeight(123, 1000e18);
        mockJBMultiTerminal.setProjectToken(123, address(token0));

        // Set up pool key
        key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        id = key.toId();

        // Mint tokens for this test contract
        token0.mint(address(this), 100_000 ether);
        token1.mint(address(this), 100_000 ether);

        // Approve tokens for liquidity router
        token0.approve(address(modifyLiquidityRouter), type(uint256).max);
        token1.approve(address(modifyLiquidityRouter), type(uint256).max);

        // Approve tokens for swap router
        token0.approve(address(swapRouter), type(uint256).max);
        token1.approve(address(swapRouter), type(uint256).max);

        // Approve tokens for jbSwapRouter
        token0.approve(address(jbSwapRouter), type(uint256).max);
        token1.approve(address(jbSwapRouter), type(uint256).max);

        // Approve tokens for the hook (needed for Juicebox routing)
        token0.approve(address(hook), type(uint256).max);
        token1.approve(address(hook), type(uint256).max);

        // Initialize the pool (triggers afterInitialize -> oracle init)
        manager.initialize(key, SQRT_PRICE_1_1);

        // Add liquidity with wider range so swaps succeed at non-zero ticks
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -600, tickUpper: 600, liquidityDelta: 100 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );
    }

    // ---------------------------------------------------------------
    // Helper: perform a swap using the standard PoolSwapTest router
    // ---------------------------------------------------------------

    function _doSwap(bool zeroForOne, int256 amountSpecified) internal {
        uint160 sqrtLimit =
            zeroForOne ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1;

        SwapParams memory params = SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: amountSpecified,
            sqrtPriceLimitX96: sqrtLimit
        });

        swapRouter.swap(key, params, PoolSwapTest.TestSettings(false, false), abi.encode(uint256(0)));
    }

    // ---------------------------------------------------------------
    // 1. OracleInitialization_SetsCardinalityOne
    // ---------------------------------------------------------------

    /// @notice After pool initialization + the setUp's addLiquidity (same block),
    ///         the oracle should have cardinality=1 (write was a no-op since same timestamp),
    ///         but cardinalityNext=2 (auto-grow triggered because card==cardNext==1 at index 0).
    function test_OracleInitialization_SetsCardinalityOne() public view {
        (uint16 index, uint16 cardinality, uint16 cardinalityNext) = hook.states(id);
        assertEq(cardinality, 1, "Cardinality should be 1 after initialization (same-block addLiq is no-op)");
        // cardinalityNext is 2 because addLiquidity triggered auto-grow before the no-op write
        assertEq(cardinalityNext, 2, "CardinalityNext should be 2 (auto-grow from addLiquidity in setUp)");
        assertEq(index, 0, "Index should be 0 after initialization");
    }

    // ---------------------------------------------------------------
    // 2. OracleWrite_SameBlock_NoOp
    // ---------------------------------------------------------------

    /// @notice Two swaps in the same block should not advance the observation index,
    ///         because Oracle.write() returns early when the timestamp is unchanged.
    function test_OracleWrite_SameBlock_NoOp() public {
        // Record state before swaps
        (uint16 indexBefore,,) = hook.states(id);

        // Advance to a new block so the swap writes one observation past init
        vm.warp(10_100);

        // First swap writes a new observation
        _doSwap(true, -0.001 ether);
        (uint16 indexAfterFirst,,) = hook.states(id);

        // Second swap in the SAME block should be a no-op for the oracle
        _doSwap(false, -0.001 ether);
        (uint16 indexAfterSecond,,) = hook.states(id);

        // The index should not have advanced between the two same-block swaps
        assertEq(indexAfterSecond, indexAfterFirst, "Index should not advance for same-block swap");
        // But it should have advanced once from the initial state
        assertGt(indexAfterFirst, indexBefore, "Index should have advanced from the initial state");
    }

    // ---------------------------------------------------------------
    // 3. OracleWrite_DifferentBlocks_AdvancesIndex
    // ---------------------------------------------------------------

    /// @notice Swaps in different blocks should advance the observation index.
    function test_OracleWrite_DifferentBlocks_AdvancesIndex() public {
        (uint16 indexBefore,,) = hook.states(id);

        // Use explicit absolute timestamps to avoid any ambiguity
        uint256 t1 = 10_100;
        uint256 t2 = 10_200;

        // Move to a new block and swap
        vm.warp(t1);
        _doSwap(true, -0.001 ether);
        (uint16 indexAfterFirst,,) = hook.states(id);

        // Move to another new block and swap again
        vm.warp(t2);
        _doSwap(false, -0.001 ether);
        (uint16 indexAfterSecond,,) = hook.states(id);

        // Each swap in a new block should advance the index
        assertGt(indexAfterFirst, indexBefore, "First swap should advance index");
        assertGt(indexAfterSecond, indexAfterFirst, "Second swap should advance index");
    }

    // ---------------------------------------------------------------
    // 4. OracleCardinality_AutoGrows_AtCapacity
    // ---------------------------------------------------------------

    /// @notice When cardinality == cardinalityNext and index == cardinality - 1,
    ///         the next observation should trigger _recordObservation to double cardinalityNext.
    function test_OracleCardinality_AutoGrows_AtCapacity() public {
        // After setUp: cardinality=1, cardinalityNext=2, index=0
        // (addLiquidity in setUp triggered auto-grow from 1->2, but write was no-op)
        (uint16 indexInit, uint16 cardInit, uint16 cardNextInit) = hook.states(id);
        assertEq(cardInit, 1, "Initial cardinality should be 1");
        assertEq(cardNextInit, 2, "Initial cardinalityNext should be 2 (auto-grow from setUp addLiq)");
        assertEq(indexInit, 0, "Initial index should be 0");

        // First swap in a new block: write advances index, bumps cardinality to cardinalityNext=2
        vm.warp(10_100);
        _doSwap(true, -0.001 ether);

        (uint16 indexMid, uint16 cardMid, uint16 cardNextMid) = hook.states(id);
        assertEq(cardMid, 2, "Cardinality should be 2 after first swap (bumped by write)");
        assertEq(indexMid, 1, "Index should be 1 after first swap");
        // Now cardinality==cardinalityNext==2 and index==1==cardinality-1, so next swap triggers auto-grow

        // Second swap in a new block triggers auto-grow: doubles cardinalityNext to 4
        vm.warp(10_200);
        _doSwap(false, -0.001 ether);

        (, uint16 cardAfter, uint16 cardNextAfter) = hook.states(id);
        assertEq(cardNextAfter, 4, "CardinalityNext should have doubled to 4");
        // cardinality should also be bumped to 4 (since write sees cardNext > card at the boundary)
        assertEq(cardAfter, 4, "Cardinality should have grown to 4");
    }

    // ---------------------------------------------------------------
    // 5. OracleCardinality_CapsAt256
    // ---------------------------------------------------------------

    /// @notice After enough growth cycles, cardinalityNext should cap at 256.
    function test_OracleCardinality_CapsAt256() public {
        // We need to trigger auto-grow repeatedly.
        // Growth pattern: 1 -> 2 -> 4 -> 8 -> 16 -> 32 -> 64 -> 128 -> 256 (8 doublings)
        // Each growth cycle requires filling up to cardinality slots.
        // Total swaps needed: 1 + 2 + 4 + 8 + 16 + 32 + 64 + 128 = 255 + some margin.

        uint256 maxSwaps = 600;
        uint256 ts = 10_100; // start from an explicit timestamp

        for (uint256 swapCount = 0; swapCount < maxSwaps; swapCount++) {
            (, uint16 card, uint16 cardNext) = hook.states(id);

            // Stop once we've reached the cap
            if (cardNext >= 256) break;

            ts += 12;
            vm.warp(ts);

            // Alternate swap directions to stay within the liquidity range
            if (swapCount % 2 == 0) {
                _doSwap(true, -0.0001 ether);
            } else {
                _doSwap(false, -0.0001 ether);
            }
        }

        (, uint16 finalCard, uint16 finalCardNext) = hook.states(id);
        assertEq(finalCardNext, 256, "CardinalityNext should cap at 256");
        assertLe(finalCard, 256, "Cardinality should not exceed 256");
    }

    // ---------------------------------------------------------------
    // 6. OracleObservation_Wraparound
    // ---------------------------------------------------------------

    /// @notice Fill all observation slots to verify wraparound behavior.
    ///         After wrapping, the oldest observations should be overwritten
    ///         but TWAP queries should still function.
    function test_OracleObservation_Wraparound() public {
        uint256 ts = 10_100;

        // Grow to cardinality=2
        vm.warp(ts);
        _doSwap(true, -0.001 ether);
        ts += 12;

        // Grow to cardinality=4 by filling the 2 slots
        vm.warp(ts);
        _doSwap(false, -0.001 ether);
        ts += 12;

        vm.warp(ts);
        _doSwap(true, -0.001 ether);
        ts += 12;

        (, uint16 card,) = hook.states(id);
        assertGe(card, 2, "Cardinality should be at least 2 for wraparound test");

        uint16 currentCard = card;

        // Fill all remaining slots and wrap around by doing currentCard + 2 more swaps
        for (uint256 i = 0; i < currentCard + 2; i++) {
            vm.warp(ts);
            ts += 12;
            if (i % 2 == 0) {
                _doSwap(true, -0.0001 ether);
            } else {
                _doSwap(false, -0.0001 ether);
            }
        }

        // The oracle should still be usable after wraparound
        (uint16 newIndex, uint16 newCard,) = hook.states(id);
        assertGe(newCard, currentCard, "Cardinality should not shrink after wraparound");

        // Verify we can still read the TWAP estimate without reverting
        uint256 estimate = hook.estimateUniswapOutput(id, key, 1 ether, true);
        assertGt(estimate, 0, "TWAP estimate should be positive after wraparound");
    }

    // ---------------------------------------------------------------
    // 7. TWAPSqrtPrice_InsufficientObservations_ReturnsZero
    // ---------------------------------------------------------------

    /// @notice With fewer than 2 observations, _getTWAPSqrtPrice should return 0,
    ///         which causes estimateUniswapOutput to fall back to spot price.
    function test_TWAPSqrtPrice_InsufficientObservations_ReturnsZero() public view {
        // Right after initialization we have exactly 1 observation.
        // The hook's _getTWAPSqrtPrice checks if cardinality < 2 and returns 0.
        (,uint16 cardinality,) = hook.states(id);
        assertEq(cardinality, 1, "Should have exactly 1 observation");

        // estimateUniswapOutput falls back to spot price when _getTWAPSqrtPrice returns 0.
        // Just verify the output is positive (spot price based) and does not revert.
        uint256 estimate = hook.estimateUniswapOutput(id, key, 1 ether, true);
        assertGt(estimate, 0, "Should use spot price fallback when cardinality < 2");
    }

    // ---------------------------------------------------------------
    // 8. TWAPSqrtPrice_SufficientAge_ReturnsNonZero
    // ---------------------------------------------------------------

    /// @notice With observations old enough (>= TWAP_PERIOD), _getTWAPSqrtPrice
    ///         should return a nonzero value, and the TWAP estimate should work.
    function test_TWAPSqrtPrice_SufficientAge_ReturnsNonZero() public {
        // Build up enough cardinality and age.
        // First, write a second observation to get cardinality >= 2.
        vm.warp(10_100);
        _doSwap(true, -0.001 ether);

        (, uint16 card,) = hook.states(id);
        assertGe(card, 2, "Should have at least 2 observations");

        // Now warp far enough into the future that the oldest observation is older
        // than TWAP_PERIOD (1800 seconds).
        vm.warp(12_200);
        // Do one more swap so the latest observation is at the current timestamp.
        _doSwap(false, -0.001 ether);

        // Now the estimateUniswapOutput should use the TWAP price (not spot).
        uint256 estimate = hook.estimateUniswapOutput(id, key, 1 ether, true);
        assertGt(estimate, 0, "TWAP-based estimate should be nonzero with sufficient age");
    }

    // ---------------------------------------------------------------
    // 9. ObserveTWAP_ValidWindow_ReturnsMeanTick
    // ---------------------------------------------------------------

    /// @notice observeTWAP should return a valid arithmetic mean tick for a valid window.
    function test_ObserveTWAP_ValidWindow_ReturnsMeanTick() public {
        // Build observations: at least 2 observations, first at time T, second at T + dt.
        vm.warp(10_100);
        _doSwap(true, -0.001 ether);

        (uint16 obsIndex, uint16 card,) = hook.states(id);
        assertGe(card, 2, "Need at least 2 observations for observeTWAP");

        // Warp a reasonable window into the future
        uint32 secondsAgo = 100; // The window between our two observations
        vm.warp(10_101); // Ensure we are past the last observation

        // Get current pool state for the call
        IPoolManager pm = IPoolManager(address(manager));
        (, int24 currentTick,,) = pm.getSlot0(id);
        uint128 currentLiquidity = pm.getLiquidity(id);

        // observeTWAP should not revert and should return a valid tick
        int24 meanTick = hook.observeTWAP(id, secondsAgo, currentTick, obsIndex, currentLiquidity, card);

        // The mean tick should be within a reasonable range of the current tick.
        // With a 1:1 price pool and tiny swaps, the tick should be near zero.
        assertGe(meanTick, -1000, "Mean tick should be within reasonable range");
        assertLe(meanTick, 1000, "Mean tick should be within reasonable range");
    }

    // ---------------------------------------------------------------
    // 10. RecordObservation_AfterAddLiquidity_Updates
    // ---------------------------------------------------------------

    /// @notice Adding liquidity should trigger _recordObservation and update the oracle.
    function test_RecordObservation_AfterAddLiquidity_Updates() public {
        // Advance to a new block
        vm.warp(10_100);

        (uint16 indexBefore,,) = hook.states(id);

        // Add more liquidity (triggers afterAddLiquidity -> _recordObservation)
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -600, tickUpper: 600, liquidityDelta: 1 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        (uint16 indexAfter,,) = hook.states(id);
        assertGt(indexAfter, indexBefore, "Adding liquidity should advance observation index");
    }

    // ---------------------------------------------------------------
    // 11. RecordObservation_AfterRemoveLiquidity_Updates
    // ---------------------------------------------------------------

    /// @notice Removing liquidity should trigger _recordObservation and update the oracle.
    function test_RecordObservation_AfterRemoveLiquidity_Updates() public {
        // Advance to a new block
        vm.warp(10_100);

        (uint16 indexBefore,,) = hook.states(id);

        // Remove some liquidity (triggers afterRemoveLiquidity -> _recordObservation)
        modifyLiquidityRouter.modifyLiquidity(
            key,
            ModifyLiquidityParams({tickLower: -600, tickUpper: 600, liquidityDelta: -1 ether, salt: bytes32(0)}),
            ZERO_BYTES
        );

        (uint16 indexAfter,,) = hook.states(id);
        assertGt(indexAfter, indexBefore, "Removing liquidity should advance observation index");
    }

    // ---------------------------------------------------------------
    // 12. ObserveTWAP_SecondsAgoZero_Reverts
    // ---------------------------------------------------------------

    /// @notice observeTWAP with secondsAgo=0 should revert with SecondsAgoCannotBeZero.
    function test_ObserveTWAP_SecondsAgoZero_Reverts() public {
        // Build at least 2 observations so cardinality >= 2
        vm.warp(10_100);
        _doSwap(true, -0.001 ether);

        (uint16 obsIndex, uint16 card,) = hook.states(id);
        IPoolManager pm = IPoolManager(address(manager));
        (, int24 currentTick,,) = pm.getSlot0(id);
        uint128 currentLiquidity = pm.getLiquidity(id);

        vm.expectRevert(JBUniswapV4Hook.JBUniswapV4Hook_SecondsAgoCannotBeZero.selector);
        hook.observeTWAP(id, 0, currentTick, obsIndex, currentLiquidity, card);
    }

    // ---------------------------------------------------------------
    // 13. Fuzz: OracleTimestampProgression
    // ---------------------------------------------------------------

    /// @notice Fuzz test: as time advances, observations should always be recorded.
    function testFuzz_OracleTimestampProgression(uint32 delta) public {
        // Bound the time delta to a reasonable range: at least 1 second, at most 1 day
        delta = uint32(bound(uint256(delta), 1, 86400));

        (uint16 indexBefore,,) = hook.states(id);

        // Advance time by the fuzzed delta from a known base
        vm.warp(10_000 + uint256(delta));

        // Do a swap to record an observation
        _doSwap(true, -0.0001 ether);

        (uint16 indexAfter,,) = hook.states(id);

        // Index should have advanced because time progressed
        assertGt(indexAfter, indexBefore, "Observation index should advance when time progresses");
    }

    // ---------------------------------------------------------------
    // 14. TWAPSqrtPrice_OldestObsTooRecent_ReturnsZero
    // ---------------------------------------------------------------

    /// @notice If the oldest observation is newer than TWAP_PERIOD (1800s),
    ///         _getTWAPSqrtPrice should return 0 and estimation falls back to spot.
    function test_TWAPSqrtPrice_OldestObsTooRecent_ReturnsZero() public {
        // Write a second observation (so cardinality >= 2)
        vm.warp(10_100);
        _doSwap(true, -0.001 ether);

        (, uint16 card,) = hook.states(id);
        assertGe(card, 2, "Should have at least 2 observations");

        // Do NOT warp past TWAP_PERIOD. The oldest observation was written at 10000 (init)
        // and current time is 10100. oldestAllowedTime = 10100 - 1800 = 8300.
        // oldest obs timestamp (10000) > 8300 => _getTWAPSqrtPrice returns 0 (uses spot).

        uint256 spotEstimate = hook.estimateUniswapOutput(id, key, 1 ether, true);
        assertGt(spotEstimate, 0, "Should produce positive spot-price estimate when TWAP unavailable");

        // Now warp far enough so TWAP is available (oldest obs at 10000, need current > 10000 + 1800)
        vm.warp(12_100);
        _doSwap(false, -0.001 ether);

        uint256 twapEstimate = hook.estimateUniswapOutput(id, key, 1 ether, true);
        assertGt(twapEstimate, 0, "Should produce positive TWAP estimate when history is sufficient");

        // Both should be positive (the exact values may differ, confirming different code paths)
        // The key assertion is that the first call didn't revert despite insufficient TWAP history.
    }
}
