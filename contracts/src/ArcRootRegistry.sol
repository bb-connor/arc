// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IArcIdentityRegistry} from "./interfaces/IArcIdentityRegistry.sol";
import {IArcRootRegistry} from "./interfaces/IArcRootRegistry.sol";
import {ArcMerkle} from "./lib/ArcMerkle.sol";

contract ArcRootRegistry is IArcRootRegistry {
    uint256 public constant MAX_ACTIVE_DELEGATES = 3;

    error OperatorNotAuthorized();
    error InvalidCheckpointSequence();
    error InvalidBatchRange();
    error InvalidMerkleRoot();
    error OperatorKeyHashMismatch();
    error ProofMetadataRequired();
    error InvalidDelegate();
    error DelegateLimitReached();

    IArcIdentityRegistry public immutable identityRegistry;

    mapping(address => mapping(uint64 => RootEntry)) private rootEntries;
    mapping(address => mapping(bytes32 => bool)) private publishedRoots;
    mapping(address => uint64) private latestSeq;
    mapping(address => mapping(address => uint64)) private delegateExpiries;
    mapping(address => uint256) private activeDelegateCounts;

    constructor(address identityRegistry_) {
        identityRegistry = IArcIdentityRegistry(identityRegistry_);
    }

    function publishRoot(
        address operator,
        bytes32 merkleRoot,
        uint64 checkpointSeq,
        uint64 batchStartSeq,
        uint64 batchEndSeq,
        uint64 treeSize,
        bytes32 operatorKeyHash
    ) external {
        _publishSingle(
            operator,
            msg.sender,
            merkleRoot,
            checkpointSeq,
            batchStartSeq,
            batchEndSeq,
            treeSize,
            operatorKeyHash
        );
    }

    function publishRootBatch(
        address operator,
        bytes32[] calldata merkleRoots,
        uint64[] calldata checkpointSeqs,
        uint64[] calldata batchStartSeqs,
        uint64[] calldata batchEndSeqs,
        uint64[] calldata treeSizes,
        bytes32 operatorKeyHash
    ) external {
        uint256 count = merkleRoots.length;
        if (
            count == 0 ||
            checkpointSeqs.length != count ||
            batchStartSeqs.length != count ||
            batchEndSeqs.length != count ||
            treeSizes.length != count
        ) {
            revert InvalidBatchRange();
        }

        for (uint256 i = 0; i < count; ++i) {
            _publishSingle(
                operator,
                msg.sender,
                merkleRoots[i],
                checkpointSeqs[i],
                batchStartSeqs[i],
                batchEndSeqs[i],
                treeSizes[i],
                operatorKeyHash
            );
        }
    }

    function registerDelegate(address delegate, uint64 expiresAt) external {
        if (!identityRegistry.isOperator(msg.sender)) revert OperatorNotAuthorized();
        if (delegate == address(0) || delegate == msg.sender || expiresAt <= block.timestamp) {
            revert InvalidDelegate();
        }

        uint64 currentExpiry = delegateExpiries[msg.sender][delegate];
        bool currentlyActive = currentExpiry >= block.timestamp;
        if (!currentlyActive) {
            uint256 nextCount = activeDelegateCounts[msg.sender] + 1;
            if (nextCount > MAX_ACTIVE_DELEGATES) revert DelegateLimitReached();
            activeDelegateCounts[msg.sender] = nextCount;
        }

        delegateExpiries[msg.sender][delegate] = expiresAt;
        emit DelegateRegistered(msg.sender, delegate, expiresAt);
    }

    function revokeDelegate(address delegate) external {
        uint64 currentExpiry = delegateExpiries[msg.sender][delegate];
        if (currentExpiry == 0) revert InvalidDelegate();
        if (currentExpiry >= block.timestamp) {
            activeDelegateCounts[msg.sender] -= 1;
        }
        delete delegateExpiries[msg.sender][delegate];
        emit DelegateRevoked(msg.sender, delegate);
    }

    function isAuthorizedPublisher(address operator, address publisher)
        public
        view
        returns (bool)
    {
        if (publisher == operator) {
            return identityRegistry.isOperator(operator);
        }
        return
            identityRegistry.isOperator(operator)
                && delegateExpiries[operator][publisher] >= block.timestamp;
    }

    function verifyInclusion(
        bytes32[] calldata,
        bytes32,
        bytes32,
        address
    ) external pure returns (bool) {
        revert ProofMetadataRequired();
    }

    function verifyInclusionDetailed(
        ArcMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 leafHash,
        address operator
    ) external view returns (bool) {
        if (!publishedRoots[operator][root]) {
            return false;
        }
        return ArcMerkle.verifyRFC6962(proof, root, leafHash);
    }

    function getLatestRoot(address operator) external view returns (RootEntry memory) {
        return rootEntries[operator][latestSeq[operator]];
    }

    function getRoot(address operator, uint64 checkpointSeq) external view returns (RootEntry memory) {
        return rootEntries[operator][checkpointSeq];
    }

    function getLatestSeq(address operator) external view returns (uint64) {
        return latestSeq[operator];
    }

    function _publishSingle(
        address operator,
        address publisher,
        bytes32 merkleRoot,
        uint64 checkpointSeq,
        uint64 batchStartSeq,
        uint64 batchEndSeq,
        uint64 treeSize,
        bytes32 operatorKeyHash
    ) internal {
        if (!isAuthorizedPublisher(operator, publisher)) revert OperatorNotAuthorized();
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (batchStartSeq > batchEndSeq || treeSize == 0) revert InvalidBatchRange();
        if (checkpointSeq <= latestSeq[operator]) revert InvalidCheckpointSequence();

        IArcIdentityRegistry.OperatorRecord memory record = identityRegistry.getOperator(operator);
        if (record.edKeyHash != operatorKeyHash) revert OperatorKeyHashMismatch();

        RootEntry memory entry = RootEntry({
            merkleRoot: merkleRoot,
            checkpointSeq: checkpointSeq,
            batchStartSeq: batchStartSeq,
            batchEndSeq: batchEndSeq,
            treeSize: treeSize,
            publishedAt: uint64(block.timestamp),
            operatorKeyHash: operatorKeyHash
        });

        rootEntries[operator][checkpointSeq] = entry;
        latestSeq[operator] = checkpointSeq;
        publishedRoots[operator][merkleRoot] = true;

        emit RootPublished(
            operator,
            publisher,
            checkpointSeq,
            merkleRoot,
            batchStartSeq,
            batchEndSeq,
            treeSize,
            entry.publishedAt,
            operatorKeyHash
        );
    }
}
