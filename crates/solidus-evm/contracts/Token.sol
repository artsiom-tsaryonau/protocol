// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal, standard ERC-20 (no external imports) — deploy mints `supply`
/// to the deployer; transfer + balanceOf are the standard ABI. Used to
/// prove the Solidus EVM subnet runs a real Solidity ERC-20 end-to-end.
contract Token {
    string public name = "Solidus Test Token";
    string public symbol = "STT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
