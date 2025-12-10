pragma solidity ^0.8.24;

// @title IWETH
// @notice Interface for WETH
interface IWETH {
    function deposit() external payable;
    function withdraw(uint256) external;
}