// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

contract ChioCreate2Factory {
    error EmptyInitCode();
    error DeploymentFailed();

    event Deployed(bytes32 indexed salt, address indexed deployed);

    function deploy(bytes32 salt, bytes calldata initCode) external returns (address deployed) {
        if (initCode.length == 0) {
            revert EmptyInitCode();
        }

        bytes memory code = initCode;
        assembly {
            deployed := create2(0, add(code, 0x20), mload(code), salt)
        }

        if (deployed == address(0)) {
            revert DeploymentFailed();
        }

        emit Deployed(salt, deployed);
    }

    function computeAddress(bytes32 salt, bytes32 initCodeHash) external view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)
        );
        return address(uint160(uint256(hash)));
    }
}
