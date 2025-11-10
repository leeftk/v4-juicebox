// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

import {JBUniswapV4Hook} from "../src/JBUniswapV4Hook.sol";
import {IJBTokens} from "@bananapus/core-v5/interfaces/IJBTokens.sol";
import {IJBDirectory} from "@bananapus/core-v5/interfaces/IJBDirectory.sol";
import {IJBController} from "@bananapus/core-v5/interfaces/IJBController.sol";
import {IJBPrices} from "@bananapus/core-v5/interfaces/IJBPrices.sol";
import {IJBTerminalStore} from "@bananapus/core-v5/interfaces/IJBTerminalStore.sol";
import {IUniswapV3Factory} from "../src/interfaces/IUniswapV3Factory.sol";

/// @title DeployJBUniswapV4Hook
/// @notice Script to deploy the JBUniswapV4Hook with multi-currency support
contract DeployJBUniswapV4Hook is Script {
    // Default test addresses (override with environment variables)
    address constant DEFAULT_JB_TOKENS = 0x4d0Edd347FB1fA21589C1E109B3474924BE87636;
    address constant DEFAULT_JB_DIRECTORY = 0x0061E516886A0540F63157f112C0588eE0651dCF;
    address constant DEFAULT_JB_CONTROLLER = 0x84dCD186F4c67798ed84e07dD01D1e7af8Ce4c43;
    address constant DEFAULT_JB_PRICES = 0x9b90E507cF6B7eB681A506b111f6f50245e614c4;
    address constant DEFAULT_JB_TERMINAL_STORE = 0xfE33B439Ec53748C87DcEDACb83f05aDd5014744;
    
    function getFactory() internal view returns (address) {
        if (block.chainid == 1) {
            return 0x1F98431c8aD98523631AE4a59f267346ea31F984;
            // Ethereum Mainnet
        } else if (block.chainid == 11_155_111) {
            return 0x0227628f3F023bb0B980b67D528571c95c6DaC1c;
            // Optimism Mainnet
        } else if (block.chainid == 10) {
            return 0x1F98431c8aD98523631AE4a59f267346ea31F984;
            // Optimism Mainnet
        } else if (block.chainid == 8453) {
            return 0x33128a8fC17869897dcE68Ed026d694621f6FDfD;
            // Base Mainnet
        } else if (block.chainid == 11_155_420) {
            return 0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24;
            // Optimism Sepolia
        } else if (block.chainid == 84_532) {
            return 0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24;
            // BASE Sepolia
        } else if (block.chainid == 42_161) {
            return 0x1F98431c8aD98523631AE4a59f267346ea31F984;
            // Arbitrum Mainnet
        } else if (block.chainid == 421_614) {
            return 0x248AB79Bbb9bC29bB72f7Cd42F17e054Fc40188e;
        } else {
            revert("Invalid RPC / no juice contracts deployed on this network");
        }
    }

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
        address v3Factory = vm.envOr("V3_FACTORY", getFactory());

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
            IJBTerminalStore(jbTerminalStore),
            IUniswapV3Factory(v3Factory)
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
            IJBTerminalStore(jbTerminalStore),
            IUniswapV3Factory(v3Factory)
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

