// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

library ChioMerkle {
    error InvalidProofMetadata();

    struct Proof {
        bytes32[] auditPath;
        uint256 leafIndex;
        uint256 treeSize;
    }

    function verifyRFC6962(Proof calldata proof, bytes32 root, bytes32 leafHash)
        internal
        pure
        returns (bool)
    {
        if (proof.treeSize == 0 || proof.leafIndex >= proof.treeSize) {
            return false;
        }

        bytes32 computed = leafHash;
        uint256 idx = proof.leafIndex;
        uint256 size = proof.treeSize;
        uint256 pathIndex = 0;

        while (size > 1) {
            if (idx % 2 == 0) {
                if (idx + 1 < size) {
                    if (pathIndex >= proof.auditPath.length) {
                        return false;
                    }
                    computed = sha256(
                        abi.encodePacked(bytes1(0x01), computed, proof.auditPath[pathIndex])
                    );
                    unchecked {
                        ++pathIndex;
                    }
                }
            } else {
                if (pathIndex >= proof.auditPath.length) {
                    return false;
                }
                computed = sha256(
                    abi.encodePacked(bytes1(0x01), proof.auditPath[pathIndex], computed)
                );
                unchecked {
                    ++pathIndex;
                }
            }

            idx /= 2;
            size = (size + 1) / 2;
        }

        return pathIndex == proof.auditPath.length && computed == root;
    }
}

