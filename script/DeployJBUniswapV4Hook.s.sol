// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

import {JBUniswapV4Hook} from "../src/JBUniswapV4Hook.sol";
import {IJBTokens} from "../src/interfaces/IJBTokens.sol";
import {IJBDirectory} from "../src/interfaces/IJBDirectory.sol";
import {IJBController} from "../src/interfaces/IJBController.sol";
import {IJBPrices} from "../src/interfaces/IJBPrices.sol";
import {IJBTerminalStore} from "../src/interfaces/IJBTerminalStore.sol";

/// @title DeployJBUniswapV4Hook
/// @notice Script to deploy the JBUniswapV4Hook with multi-currency support
contract DeployJBUniswapV4Hook is Script {
    // Default test addresses (override with environment variables)
    address constant DEFAULT_JB_TOKENS = 0x1234567890123456789012345678901234567890;
    address constant DEFAULT_JB_DIRECTORY = 0x2345678901234567890123456789012345678901;
    address constant DEFAULT_JB_CONTROLLER = 0x3456789012345678901234567890123456789012;
    address constant DEFAULT_JB_PRICES = 0x4567890123456789012345678901234567890123;
    address constant DEFAULT_JB_TERMINAL_STORE = 0x5678901234567890123456789012345678901234;

    function run() external {
        // Get the pool manager address from environment or use a default
        address poolManager = vm.envOr("POOL_MANAGER", address(0));
        require(poolManager != address(0), "POOL_MANAGER environment variable not set");

        // Get Juicebox addresses from environment or use defaults
        address jbTokens = vm.envOr("JB_TOKENS", DEFAULT_JB_TOKENS);
        address jbDirectory = vm.envOr("JB_DIRECTORY", DEFAULT_JB_DIRECTORY);
        address jbController = vm.envOr("JB_CONTROLLER", DEFAULT_JB_CONTROLLER);
        address jbPrices = vm.envOr("JB_PRICES", DEFAULT_JB_PRICES);
        address jbTerminalStore = vm.envOr("JB_TERMINAL_STORE", DEFAULT_JB_TERMINAL_STORE);

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console2.log("Deploying JBUniswapV4Hook with:");
        console2.log("  Deployer:", deployer);
        console2.log("  Pool Manager:", poolManager);
        console2.log("  JB Tokens:", jbTokens);
        console2.log("  JB Directory:", jbDirectory);
        console2.log("  JB Controller:", jbController);
        console2.log("  JB Prices:", jbPrices);
        console2.log("  JB Terminal Store:", jbTerminalStore);

        vm.startBroadcast(deployerPrivateKey);

        // Get hook permissions to determine the required address flags
        Hooks.Permissions memory permissions = Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: true,
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
        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_INITIALIZE_FLAG);

        // Prepare constructor arguments
        bytes memory constructorArgs = abi.encode(
            IPoolManager(poolManager),
            IJBTokens(jbTokens),
            IJBDirectory(jbDirectory),
            IJBController(jbController),
            IJBPrices(jbPrices),
            IJBTerminalStore(jbTerminalStore)
        );

        // Find a valid hook address using HookMiner
        (address hookAddress, bytes32 salt) =
            HookMiner.find(deployer, flags, type(JBUniswapV4Hook).creationCode, constructorArgs);

        console2.log("Found hook address:", hookAddress);
        console2.log("Salt:", vm.toString(salt));

        // Deploy the hook with the mined address
        JBUniswapV4Hook hook = new JBUniswapV4Hook{
            salt: salt
        }(
            IPoolManager(poolManager),
            IJBTokens(jbTokens),
            IJBDirectory(jbDirectory),
            IJBController(jbController),
            IJBPrices(jbPrices),
            IJBTerminalStore(jbTerminalStore)
        );

        console2.log("JBUniswapV4Hook deployed at:", address(hook));

        // Verify the hook permissions
        Hooks.Permissions memory deployedPermissions = hook.getHookPermissions();
        console2.log("Hook permissions:");
        console2.log("  beforeSwap:", deployedPermissions.beforeSwap);
        console2.log("  afterSwap:", deployedPermissions.afterSwap);

        vm.stopBroadcast();

        // Save deployment info
        string memory deploymentInfo = string(
            abi.encodePacked(
                "JBUniswapV4Hook deployed at: ",
                vm.toString(address(hook)),
                "\nDeployer: ",
                vm.toString(deployer),
                "\nJBPrices: ",
                vm.toString(jbPrices)
            )
        );

        vm.writeFile("deployments/JBUniswapV4Hook.txt", deploymentInfo);
        console2.log("Deployment info saved to deployments/JBUniswapV4Hook.txt");
    }
}

