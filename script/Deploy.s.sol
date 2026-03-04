// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

import {JBUniswapV4Hook} from "src/JBUniswapV4Hook.sol";
import {IJBTokens} from "@bananapus/core-v6/interfaces/IJBTokens.sol";
import {IJBDirectory} from "@bananapus/core-v6/interfaces/IJBDirectory.sol";
import {IJBPrices} from "@bananapus/core-v6/interfaces/IJBPrices.sol";
import {IUniswapV3Factory} from "src/interfaces/IUniswapV3Factory.sol";

contract DeployScript is Script {
    /// @notice the salts that are used to deploy the contracts.
    bytes32 UNISWAP_V4_HOOK = "JBUniswapV4HookV6";

    /// @notice tracks the addresses that are required for the chain we are deploying to.
    address poolManager;
    address weth;
    address v3Factory;

    // Core deployment addresses (read from deployment JSON).
    address jbDirectory;
    address jbTokens;
    address jbPrices;

    function run() public {
        // Get the core deployment addresses.
        // NOTE: CoreDeploymentLib can't be used directly (pragma 0.8.23 vs ^0.8.24).
        // We inline the same JSON-reading pattern here.
        string memory basePath =
            vm.envOr("NANA_CORE_DEPLOYMENT_PATH", string("node_modules/@bananapus/core-v6/deployments/"));
        string memory networkName = _getNetworkName();

        jbDirectory = _getCoreAddress(basePath, networkName, "JBDirectory");
        jbTokens = _getCoreAddress(basePath, networkName, "JBTokens");
        jbPrices = _getCoreAddress(basePath, networkName, "JBPrices");

        // Pool manager must be provided (V4 is still rolling out).
        poolManager = vm.envOr("POOL_MANAGER", address(0));
        require(poolManager != address(0), "POOL_MANAGER environment variable not set");

        // Ethereum Mainnet
        if (block.chainid == 1) {
            weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
            v3Factory = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
        // Ethereum Sepolia
        } else if (block.chainid == 11_155_111) {
            weth = 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9;
            v3Factory = 0x0227628f3F023bb0B980b67D528571c95c6DaC1c;
        // Optimism Mainnet
        } else if (block.chainid == 10) {
            weth = 0x4200000000000000000000000000000000000006;
            v3Factory = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
        // Base Mainnet
        } else if (block.chainid == 8453) {
            weth = 0x4200000000000000000000000000000000000006;
            v3Factory = 0x33128a8fC17869897dcE68Ed026d694621f6FDfD;
        // Optimism Sepolia
        } else if (block.chainid == 11_155_420) {
            weth = 0x4200000000000000000000000000000000000006;
            v3Factory = 0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24;
        // Base Sepolia
        } else if (block.chainid == 84_532) {
            weth = 0x4200000000000000000000000000000000000006;
            v3Factory = 0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24;
        // Arbitrum Mainnet
        } else if (block.chainid == 42_161) {
            weth = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1;
            v3Factory = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
        // Arbitrum Sepolia
        } else if (block.chainid == 421_614) {
            weth = 0x980B62Da83eFf3D4576C647993b0c1D7faf17c73;
            v3Factory = 0x248AB79Bbb9bC29bB72f7Cd42F17e054Fc40188e;
        } else {
            revert("Invalid RPC / no juice contracts deployed on this network");
        }

        deploy();
    }

    function deploy() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Calculate the required hook permission flags.
        uint160 flags = uint160(
            Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG
                | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_ADD_LIQUIDITY_FLAG
                | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
        );

        // Prepare constructor arguments.
        bytes memory constructorArgs = abi.encode(
            IPoolManager(poolManager),
            IJBTokens(jbTokens),
            IJBDirectory(jbDirectory),
            IJBPrices(jbPrices),
            IUniswapV3Factory(v3Factory),
            weth
        );

        // Mine a valid hook address.
        (address hookAddress, bytes32 salt) =
            HookMiner.find(deployer, flags, type(JBUniswapV4Hook).creationCode, constructorArgs);

        console2.log("Deploying JBUniswapV4Hook to:", hookAddress);

        vm.startBroadcast(deployerPrivateKey);

        JBUniswapV4Hook hook = new JBUniswapV4Hook{salt: salt}(
            IPoolManager(poolManager),
            IJBTokens(jbTokens),
            IJBDirectory(jbDirectory),
            IJBPrices(jbPrices),
            IUniswapV3Factory(v3Factory),
            weth
        );

        console2.log("JBUniswapV4Hook deployed at:", address(hook));

        vm.stopBroadcast();
    }

    /// @notice Read a core contract address from the Sphinx deployment JSON.
    function _getCoreAddress(
        string memory basePath,
        string memory networkName,
        string memory contractName
    ) internal view returns (address) {
        string memory json = vm.readFile(
            string.concat(basePath, "nana-core-v6/", networkName, "/", contractName, ".json")
        );
        return stdJson.readAddress(json, ".address");
    }

    /// @notice Map the current chain ID to a Sphinx network name.
    function _getNetworkName() internal view returns (string memory) {
        if (block.chainid == 1) return "ethereum";
        if (block.chainid == 11_155_111) return "ethereum_sepolia";
        if (block.chainid == 10) return "optimism";
        if (block.chainid == 11_155_420) return "optimism_sepolia";
        if (block.chainid == 8453) return "base";
        if (block.chainid == 84_532) return "base_sepolia";
        if (block.chainid == 42_161) return "arbitrum";
        if (block.chainid == 421_614) return "arbitrum_sepolia";
        revert("Unsupported chain");
    }

    function _isDeployed(
        bytes32 salt,
        bytes memory creationCode,
        bytes memory arguments
    ) internal view returns (bool) {
        address _deployedTo = vm.computeCreate2Address({
            salt: salt,
            initCodeHash: keccak256(abi.encodePacked(creationCode, arguments)),
            deployer: address(0x4e59b44847b379578588920cA78FbF26c0B4956C)
        });
        return address(_deployedTo).code.length != 0;
    }
}
