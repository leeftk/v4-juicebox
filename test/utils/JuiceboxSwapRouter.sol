// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {CurrencySettler} from "@uniswap/v4-core/test/utils/CurrencySettler.sol";

/// @title JuiceboxSwapRouter
/// @notice Custom router that pre-deposits tokens to enable Juicebox routing in the hook
contract JuiceboxSwapRouter {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;
    using CurrencySettler for Currency;

    IPoolManager public immutable poolManager;

    struct CallbackData {
        address sender;
        PoolKey key;
        SwapParams params;
        bytes hookData;
    }

    constructor(IPoolManager _poolManager) {
        poolManager = _poolManager;
    }

    /// @notice Execute a swap that allows Juicebox routing
    /// @param key The pool key
    /// @param params The swap parameters
    /// @return delta The balance delta from the swap
    function swap(PoolKey memory key, SwapParams memory params) external payable returns (BalanceDelta delta) {
        // Encode sender address in hookData so hook knows who the real user is
        bytes memory hookData = abi.encode(msg.sender);
        
        delta = abi.decode(
            poolManager.unlock(abi.encode(CallbackData(msg.sender, key, params, hookData))), (BalanceDelta)
        );
    }

    function unlockCallback(bytes calldata rawData) external returns (bytes memory) {
        require(msg.sender == address(poolManager), "Only PoolManager can call");

        CallbackData memory data = abi.decode(rawData, (CallbackData));

        // Determine input currency based on swap direction
        Currency inputCurrency = data.params.zeroForOne ? data.key.currency0 : data.key.currency1;
        Currency outputCurrency = data.params.zeroForOne ? data.key.currency1 : data.key.currency0;
        
        // Get input amount (absolute value)
        uint256 inputAmount = data.params.amountSpecified < 0 
            ? uint256(-data.params.amountSpecified) 
            : uint256(data.params.amountSpecified);

        // PRE-DEPOSIT: Transfer input tokens from user to this router, then to PoolManager
        // This creates a balance in PoolManager that the hook can take() from
        if (!inputCurrency.isAddressZero()) {
            IERC20 inputToken = IERC20(Currency.unwrap(inputCurrency));
            // Transfer from user to router
            inputToken.safeTransferFrom(data.sender, address(this), inputAmount);
            
            // Now settle from router to PoolManager (payer = address(this))
            inputCurrency.settle(poolManager, address(this), inputAmount, false);
        } else {
            // For native ETH
            poolManager.settle{value: inputAmount}();
        }

        // Execute the swap - hook can now take() the pre-deposited tokens
        BalanceDelta delta = poolManager.swap(data.key, data.params, data.hookData);

        // The delta reflects what the user owes/receives MINUS what the hook did
        // Since we pre-deposited inputAmount, we need to account for it
        int256 delta0 = delta.amount0();
        int256 delta1 = delta.amount1();

        // Adjust deltas by the pre-deposited amount
        if (data.params.zeroForOne) {
            // We pre-deposited currency0
            delta0 += int256(inputAmount);
        } else {
            // We pre-deposited currency1
            delta1 += int256(inputAmount);
        }

        // Now settle only the remaining delta
        if (delta0 < 0) {
            data.key.currency0.settle(poolManager, data.sender, uint256(-delta0), false);
        }
        if (delta1 < 0) {
            data.key.currency1.settle(poolManager, data.sender, uint256(-delta1), false);
        }
        
        // Take any credits from PoolManager
        if (delta0 > 0) {
            data.key.currency0.take(poolManager, data.sender, uint256(delta0), false);
        }
        if (delta1 > 0) {
            data.key.currency1.take(poolManager, data.sender, uint256(delta1), false);
        }

        return abi.encode(delta);
    }

    receive() external payable {}
}

