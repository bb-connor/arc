// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @dev Adversarial token fixture, compiled only by the private claim test harness.
contract WorkClaimTestToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public mode;
    address public callbackTarget;
    bytes public callbackData;
    bool public reentryOk;
    bytes4 public reentryError;

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address to, uint256 amount) external returns (bool) {
        allowance[msg.sender][to] = amount;
        return true;
    }
    function setMode(uint256 value) external { mode = value; }
    function setCallback(address target, bytes calldata data) external {
        callbackTarget = target;
        callbackData = data;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        return _move(msg.sender, to, amount);
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        return _move(from, to, amount);
    }
    function _move(address from, address to, uint256 amount) private returns (bool) {
        if (mode == 1) return false;
        balanceOf[from] -= amount + (mode == 3 ? 1 : 0);
        balanceOf[to] += amount - (mode == 2 ? 1 : 0);
        if (mode == 4) {
            (bool ok, bytes memory data) = callbackTarget.call(callbackData);
            reentryOk = ok;
            if (data.length >= 4) reentryError = bytes4(data);
        }
        if (mode == 5) return false;
        if (mode == 6) { assembly { mstore(0, 2) return(0, 32) } }
        if (mode == 7) { assembly { return(0, 0) } }
        return true;
    }
}
