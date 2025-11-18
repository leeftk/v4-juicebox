// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {FullMath} from "@uniswap/v4-core/src/libraries/FullMath.sol";
import {UD60x18} from "../lib/prb-math/src/ud60x18/ValueType.sol";
import {log2} from "../lib/prb-math/src/ud60x18/Math.sol";

contract SlippageCalcHarness {
    uint256 public constant TWAP_SLIPPAGE_DENOMINATOR = 10_000;
    uint256 public constant UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE = 1050;

    function getSlippageTolerance(
        uint256 amountIn,
        uint128 liquidity,
        address projectToken,
        address terminalToken,
        int24 arithmeticMeanTick
    ) external pure returns (uint256) {
        (address token0,) = projectToken < terminalToken ? (projectToken, terminalToken) : (terminalToken, projectToken);
        bool zeroForOne = terminalToken == token0;

        uint160 sqrtP = TickMath.getSqrtPriceAtTick(arithmeticMeanTick);
        if (sqrtP == 0) return TWAP_SLIPPAGE_DENOMINATOR;

        uint256 base = FullMath.mulDiv(amountIn, 10 * TWAP_SLIPPAGE_DENOMINATOR, uint256(liquidity));

        uint256 rawSlippageBps = zeroForOne
            ? FullMath.mulDiv(base, uint256(sqrtP), uint256(1) << 96)
            : FullMath.mulDiv(base, uint256(1) << 96, uint256(sqrtP));

        if (rawSlippageBps == 0) return UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE;

        uint256 maxAllowed = rawSlippageBps > 15 * TWAP_SLIPPAGE_DENOMINATOR
            ? TWAP_SLIPPAGE_DENOMINATOR * 88 / 100
            : (rawSlippageBps > 10 * TWAP_SLIPPAGE_DENOMINATOR
                    ? TWAP_SLIPPAGE_DENOMINATOR * 67 / 100
                    : rawSlippageBps / 5);

        uint256 scaledValue = rawSlippageBps * 1e18;
        if (scaledValue < 1e18) scaledValue = 1e18;
        UD60x18 logValue = log2(UD60x18.wrap(scaledValue));
        uint256 logApprox = UD60x18.unwrap(logValue) / 1e18;

        uint256 baseValue = UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE;
        uint256 scaleFactor = 800;
        uint256 adjustedSlippageBps = baseValue + (scaleFactor * logApprox) / 2;

        if (adjustedSlippageBps > maxAllowed) adjustedSlippageBps = maxAllowed;
        if (rawSlippageBps < 500 && adjustedSlippageBps < baseValue + 100) {
            adjustedSlippageBps = baseValue + (rawSlippageBps / 5);
        }
        return adjustedSlippageBps;
    }
}

contract SlippageToleranceTest is Test {
    SlippageCalcHarness internal hook;

    address internal tokenA = address(0xA);
    address internal tokenB = address(0xB);

    function setUp() public {
        hook = new SlippageCalcHarness();
    }

    // Helper: tick=0 implies sqrtP == 2^96 (price ~ 1), simplifies normalization to 1
    int24 constant TICK_ONE_TO_ONE = 0;

    function test_OneOutOfTwoHundred_IsOnePercentCap() public {
        // amountIn = 1e18, liquidity ~= 200e18 → raw ≈ 500 bps
        uint256 amountIn = 1e18;
        uint128 liquidity = uint128(200e18);
        // Arrange ordering so zeroForOne path multiplies by sqrtP and divides by 2^96 (equals 1 at tick=0)
        // terminalToken == token0 → make terminalToken < projectToken
        address projectToken = tokenB; // 0xB
        address terminalToken = tokenA; // 0xA

        uint256 adjusted = hook.getSlippageTolerance(amountIn, liquidity, projectToken, terminalToken, TICK_ONE_TO_ONE);

        // Expect ~ raw/5 = 100 bps (1%) since raw = 500
        assertEq(adjusted, 100, "adjusted should cap at 1% for 1/200");
    }

    function test_TinyRaw_AppliesFloor() public {
        // amountIn = 1e18, liquidity = 5e21 → raw ≈ 20 bps
        uint256 amountIn = 1e18;
        uint128 liquidity = uint128(5e21);
        address projectToken = tokenB;
        address terminalToken = tokenA;

        uint256 adjusted = hook.getSlippageTolerance(amountIn, liquidity, projectToken, terminalToken, TICK_ONE_TO_ONE);

        // Tiny-raw floor: base(1050) + raw/5 (=4) = 1054 bps
        assertEq(adjusted, 1054, "tiny raw should floor to ~1054 bps");
    }

    function test_LargeRaw_CapsAtTwentyPercent() public {
        // Choose amount/liquidity so raw ~ 10,000 bps → cap at raw/5 = 2000 bps
        uint256 amountIn = 5e20; // 500 tokens
        uint128 liquidity = uint128(5e21); // choose ratio = 10,000 bps
        address projectToken = tokenB;
        address terminalToken = tokenA;

        uint256 adjusted = hook.getSlippageTolerance(amountIn, liquidity, projectToken, terminalToken, TICK_ONE_TO_ONE);

        assertEq(adjusted, 2000, "should cap at 20% of raw (2000 bps)");
    }

    function testFuzz_RespectsCapsAndFloors(uint128 amountIn, uint128 liquidity) public {
        vm.assume(amountIn > 0);
        vm.assume(liquidity > 0);

        address projectToken = tokenB;
        address terminalToken = tokenA;

        uint256 adjusted = hook.getSlippageTolerance(amountIn, liquidity, projectToken, terminalToken, TICK_ONE_TO_ONE);

        // Recompute raw for bounds
        (address token0,) = projectToken < terminalToken ? (projectToken, terminalToken) : (terminalToken, projectToken);
        bool zeroForOne = terminalToken == token0;
        uint256 base = FullMath.mulDiv(uint256(amountIn), 10 * hook.TWAP_SLIPPAGE_DENOMINATOR(), uint256(liquidity));
        uint256 sqrtP = uint256(TickMath.getSqrtPriceAtTick(TICK_ONE_TO_ONE));
        uint256 raw = zeroForOne
            ? FullMath.mulDiv(base, sqrtP, uint256(1) << 96)
            : FullMath.mulDiv(base, uint256(1) << 96, sqrtP);

        if (raw == 0) {
            // When raw is zero, implementation returns the UNCERTAIN floor directly
            assertEq(adjusted, hook.UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE(), "raw=0 should return base floor");
            return;
        }

        uint256 maxAllowed = raw > 15 * hook.TWAP_SLIPPAGE_DENOMINATOR()
            ? hook.TWAP_SLIPPAGE_DENOMINATOR() * 88 / 100
            : (raw > 10 * hook.TWAP_SLIPPAGE_DENOMINATOR() ? hook.TWAP_SLIPPAGE_DENOMINATOR() * 67 / 100 : raw / 5);

        if (raw < 500) {
            uint256 minFloor = hook.UNCERTAIN_TWAP_SLIPPAGE_TOLERANCE() + (raw / 5);
            // For tiny raw, implementation prefers the floor even if it exceeds the cap
            assertGe(adjusted, minFloor, "must respect tiny-raw floor");
        } else {
            // Otherwise cap must hold
            assertLe(adjusted, maxAllowed, "must respect cap");
        }
    }
}

