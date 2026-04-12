// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IArcBondVault} from "./interfaces/IArcBondVault.sol";
import {IArcIdentityRegistry} from "./interfaces/IArcIdentityRegistry.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {ArcMerkle} from "./lib/ArcMerkle.sol";
import {ArcRootRegistry} from "./ArcRootRegistry.sol";

contract ArcBondVault is IArcBondVault {
    error InvalidTerms();
    error BondNotFound();
    error BondAlreadyExists();
    error UnauthorizedCaller();
    error AlreadyClosed();
    error BondNotExpired();
    error InvalidSlashDistribution();
    error ProofMetadataRequired();
    error InvalidEvidence();
    error TransferFailed();

    struct BondState {
        BondTerms terms;
        uint256 lockedAmount;
        uint256 slashedAmount;
        bool released;
        bool expired;
    }

    ArcRootRegistry public immutable rootRegistry;
    IArcIdentityRegistry public immutable identityRegistry;

    mapping(bytes32 => BondState) private bonds;

    constructor(address rootRegistry_, address identityRegistry_) {
        rootRegistry = ArcRootRegistry(rootRegistry_);
        identityRegistry = IArcIdentityRegistry(identityRegistry_);
    }

    function deriveVaultId(BondTerms calldata terms) external view returns (bytes32 vaultId) {
        return _deriveVaultId(terms);
    }

    function lockBond(BondTerms calldata terms) external returns (bytes32 vaultId) {
        if (
            terms.principal != msg.sender ||
            terms.bondId == bytes32(0) ||
            terms.facilityId == bytes32(0) ||
            terms.token == address(0) ||
            terms.collateralAmount == 0 ||
            terms.expiresAt <= block.timestamp ||
            !identityRegistry.isOperator(terms.operator)
        ) {
            revert InvalidTerms();
        }

        vaultId = _deriveVaultId(terms);
        if (bonds[vaultId].terms.principal != address(0)) revert BondAlreadyExists();
        bonds[vaultId] = BondState({
            terms: terms,
            lockedAmount: terms.collateralAmount,
            slashedAmount: 0,
            released: false,
            expired: false
        });

        bool ok = IERC20(terms.token).transferFrom(msg.sender, address(this), terms.collateralAmount);
        if (!ok) revert TransferFailed();

        emit BondLocked(
            vaultId,
            terms.bondId,
            terms.facilityId,
            terms.principal,
            terms.token,
            terms.collateralAmount,
            terms.expiresAt
        );
    }

    function releaseBond(
        bytes32,
        bytes32[] calldata,
        bytes32,
        bytes32
    ) external pure {
        revert ProofMetadataRequired();
    }

    function releaseBondDetailed(
        bytes32 vaultId,
        ArcMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external {
        BondState storage bond = _requireBond(vaultId);
        if (msg.sender != bond.terms.operator) revert UnauthorizedCaller();
        if (bond.released || bond.expired) revert AlreadyClosed();
        if (!rootRegistry.verifyInclusionDetailed(proof, root, evidenceHash, bond.terms.operator)) {
            revert InvalidEvidence();
        }

        bond.released = true;
        uint256 returned = bond.lockedAmount - bond.slashedAmount;
        if (returned > 0) {
            bool ok = IERC20(bond.terms.token).transfer(bond.terms.principal, returned);
            if (!ok) revert TransferFailed();
        }
        emit BondReleased(vaultId, bond.terms.bondId, returned);
    }

    function impairBond(
        bytes32,
        uint256,
        address[] calldata,
        uint256[] calldata,
        bytes32[] calldata,
        bytes32,
        bytes32
    ) external pure {
        revert ProofMetadataRequired();
    }

    function impairBondDetailed(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        ArcMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external {
        BondState storage bond = _requireBond(vaultId);
        if (msg.sender != bond.terms.operator) revert UnauthorizedCaller();
        if (bond.released || bond.expired) revert AlreadyClosed();
        if (!rootRegistry.verifyInclusionDetailed(proof, root, evidenceHash, bond.terms.operator)) {
            revert InvalidEvidence();
        }

        if (
            beneficiaries.length == 0 ||
            beneficiaries.length != shares.length ||
            slashAmount == 0 ||
            slashAmount > bond.lockedAmount - bond.slashedAmount
        ) {
            revert InvalidSlashDistribution();
        }

        uint256 totalShares = 0;
        for (uint256 i = 0; i < shares.length; ++i) {
            totalShares += shares[i];
        }
        if (totalShares != slashAmount) revert InvalidSlashDistribution();

        for (uint256 i = 0; i < beneficiaries.length; ++i) {
            bool ok = IERC20(bond.terms.token).transfer(beneficiaries[i], shares[i]);
            if (!ok) revert TransferFailed();
        }

        bond.slashedAmount += slashAmount;
        uint256 returned = bond.lockedAmount - bond.slashedAmount;
        emit BondImpaired(vaultId, bond.terms.bondId, slashAmount, returned);
    }

    function expireRelease(bytes32 vaultId) external {
        BondState storage bond = _requireBond(vaultId);
        if (bond.released || bond.expired) revert AlreadyClosed();
        if (block.timestamp <= bond.terms.expiresAt) revert BondNotExpired();

        bond.expired = true;
        uint256 returned = bond.lockedAmount - bond.slashedAmount;
        if (returned > 0) {
            bool ok = IERC20(bond.terms.token).transfer(bond.terms.principal, returned);
            if (!ok) revert TransferFailed();
        }
        emit BondExpired(vaultId, bond.terms.bondId, returned);
    }

    function getBond(bytes32 vaultId)
        external
        view
        returns (
            BondTerms memory terms,
            uint256 lockedAmount,
            uint256 slashedAmount,
            bool released,
            bool expired
        )
    {
        BondState storage bond = bonds[vaultId];
        return (bond.terms, bond.lockedAmount, bond.slashedAmount, bond.released, bond.expired);
    }

    function _requireBond(bytes32 vaultId) internal view returns (BondState storage bond) {
        bond = bonds[vaultId];
        if (bond.terms.principal == address(0)) revert BondNotFound();
    }

    function _deriveVaultId(BondTerms calldata terms) internal view returns (bytes32 vaultId) {
        vaultId = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                terms.bondId,
                terms.facilityId,
                terms.principal,
                terms.token,
                terms.collateralAmount,
                terms.reserveRequirementAmount,
                terms.expiresAt,
                terms.reserveRequirementRatioBps,
                terms.operator
            )
        );
    }
}
