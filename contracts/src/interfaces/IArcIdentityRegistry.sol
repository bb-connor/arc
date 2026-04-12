// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IArcIdentityRegistry {
    struct OperatorRecord {
        bytes32 edKeyHash;
        address settlementKey;
        uint64 registeredAt;
        bool active;
    }

    struct EntityRecord {
        bytes32 arcEntityId;
        address settlementAddress;
        address operator;
        uint64 registeredAt;
        bool active;
    }

    event OperatorRegistered(
        address indexed operatorAddress,
        bytes32 indexed edKeyHash,
        address settlementKey
    );

    event OperatorDeactivated(address indexed operatorAddress);

    event EntityRegistered(
        bytes32 indexed arcEntityId,
        address indexed settlementAddress,
        address indexed operator
    );

    function registerOperator(
        address operatorAddress,
        bytes32 edKeyHash,
        address settlementKey,
        bytes calldata bindingProof
    ) external;

    function deactivateOperator(address operatorAddress) external;

    function registerEntity(
        bytes32 arcEntityId,
        address settlementAddress,
        bytes calldata bindingProof
    ) external;

    function isOperator(address addr) external view returns (bool);

    function getSettlementKey(address operator) external view returns (address);

    function getEntityAddress(bytes32 arcEntityId) external view returns (address);

    function getOperator(address operator) external view returns (OperatorRecord memory);
}

