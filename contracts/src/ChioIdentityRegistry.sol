// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IChioIdentityRegistry} from "./interfaces/IChioIdentityRegistry.sol";

contract ChioIdentityRegistry is IChioIdentityRegistry {
    error NotAdmin();
    error ZeroAddress();
    error OperatorAlreadyRegistered();
    error OperatorNotActive();
    error EntityAlreadyRegistered();

    event OperatorBindingProofRecorded(address indexed operatorAddress, bytes bindingProof);
    event EntityBindingProofRecorded(bytes32 indexed chioEntityId, bytes bindingProof);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    address public admin;

    mapping(address => OperatorRecord) private operatorRecords;
    mapping(bytes32 => EntityRecord) private entityRecords;

    constructor(address admin_) {
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        address previous = admin;
        admin = newAdmin;
        emit AdminTransferred(previous, newAdmin);
    }

    function registerOperator(
        address operatorAddress,
        bytes32 edKeyHash,
        address settlementKey,
        bytes calldata bindingProof
    ) external onlyAdmin {
        if (operatorAddress == address(0) || settlementKey == address(0)) revert ZeroAddress();
        OperatorRecord storage record = operatorRecords[operatorAddress];
        if (record.registeredAt != 0 && record.active) revert OperatorAlreadyRegistered();

        operatorRecords[operatorAddress] = OperatorRecord({
            edKeyHash: edKeyHash,
            settlementKey: settlementKey,
            registeredAt: uint64(block.timestamp),
            active: true
        });

        emit OperatorRegistered(operatorAddress, edKeyHash, settlementKey);
        emit OperatorBindingProofRecorded(operatorAddress, bindingProof);
    }

    function deactivateOperator(address operatorAddress) external onlyAdmin {
        OperatorRecord storage record = operatorRecords[operatorAddress];
        if (!record.active) revert OperatorNotActive();
        record.active = false;
        emit OperatorDeactivated(operatorAddress);
    }

    function registerEntity(
        bytes32 chioEntityId,
        address settlementAddress,
        bytes calldata bindingProof
    ) external {
        if (!operatorRecords[msg.sender].active) revert OperatorNotActive();
        if (settlementAddress == address(0)) revert ZeroAddress();
        EntityRecord storage record = entityRecords[chioEntityId];
        if (record.registeredAt != 0 && record.active) revert EntityAlreadyRegistered();

        entityRecords[chioEntityId] = EntityRecord({
            chioEntityId: chioEntityId,
            settlementAddress: settlementAddress,
            operator: msg.sender,
            registeredAt: uint64(block.timestamp),
            active: true
        });

        emit EntityRegistered(chioEntityId, settlementAddress, msg.sender);
        emit EntityBindingProofRecorded(chioEntityId, bindingProof);
    }

    function isOperator(address addr) external view returns (bool) {
        return operatorRecords[addr].active;
    }

    function getSettlementKey(address operator) external view returns (address) {
        return operatorRecords[operator].settlementKey;
    }

    function getEntityAddress(bytes32 chioEntityId) external view returns (address) {
        return entityRecords[chioEntityId].settlementAddress;
    }

    function getOperator(address operator) external view returns (OperatorRecord memory) {
        return operatorRecords[operator];
    }
}

