// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ArcMerkle} from "../lib/ArcMerkle.sol";

interface IArcBondVault {
    struct BondTerms {
        bytes32 bondId;
        bytes32 facilityId;
        address principal;
        address token;
        uint256 collateralAmount;
        uint256 reserveRequirementAmount;
        uint256 expiresAt;
        uint16 reserveRequirementRatioBps;
        address operator;
    }

    event BondLocked(
        bytes32 indexed vaultId,
        bytes32 indexed bondId,
        bytes32 indexed facilityId,
        address principal,
        address token,
        uint256 collateralAmount,
        uint256 expiresAt
    );

    event BondReleased(bytes32 indexed vaultId, bytes32 indexed bondId, uint256 returnedAmount);

    event BondImpaired(
        bytes32 indexed vaultId,
        bytes32 indexed bondId,
        uint256 slashedAmount,
        uint256 returnedAmount
    );

    event BondExpired(bytes32 indexed vaultId, bytes32 indexed bondId, uint256 returnedAmount);

    function deriveVaultId(BondTerms calldata terms) external view returns (bytes32 vaultId);

    function lockBond(BondTerms calldata terms) external returns (bytes32 vaultId);

    function releaseBond(
        bytes32 vaultId,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function releaseBondDetailed(
        bytes32 vaultId,
        ArcMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function impairBond(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function impairBondDetailed(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        ArcMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function expireRelease(bytes32 vaultId) external;

    function getBond(bytes32 vaultId)
        external
        view
        returns (BondTerms memory terms, uint256 lockedAmount, uint256 slashedAmount, bool released, bool expired);
}
