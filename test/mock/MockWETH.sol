// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title Mock WETH
/// @notice Mock WETH implementation for testing native ETH wrapping/unwrapping
contract MockWETH is ERC20 {
    event Deposit(address indexed from, uint256 amount);
    event Withdrawal(address indexed to, uint256 amount);

    constructor() ERC20("Wrapped Ether", "WETH") {}

    function deposit() public payable {
        _mint(msg.sender, msg.value);
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public {
        _burn(msg.sender, amount);
        emit Withdrawal(msg.sender, amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    receive() external payable {
        deposit();
    }

    function decimals() public view virtual override returns (uint8) {
        return 18;
    }

    /// @notice Mint WETH for testing purposes (not part of real WETH interface)
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

