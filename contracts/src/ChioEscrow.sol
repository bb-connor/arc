// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IChioEscrow} from "./interfaces/IChioEscrow.sol";
import {IChioIdentityRegistry} from "./interfaces/IChioIdentityRegistry.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {IERC20Permit} from "./interfaces/IERC20Permit.sol";
import {ChioMerkle} from "./lib/ChioMerkle.sol";
import {ChioRootRegistry} from "./ChioRootRegistry.sol";

contract ChioEscrow is IChioEscrow {
    error InvalidTerms();
    error EscrowNotFound();
    error EscrowAlreadyExists();
    error EscrowAlreadyRefunded();
    error EscrowExpired();
    error EscrowNotExpired();
    error UnauthorizedCaller();
    error InvalidReleaseAmount();
    error TransferFailed();
    error ProofMetadataRequired();
    error InvalidSignature();
    error OperatorKeyHashMismatch();

    struct EscrowState {
        EscrowTerms terms;
        uint256 deposited;
        uint256 released;
        bool refunded;
    }

    ChioRootRegistry public immutable rootRegistry;
    IChioIdentityRegistry public immutable identityRegistry;

    mapping(bytes32 => EscrowState) private escrows;

    constructor(address rootRegistry_, address identityRegistry_) {
        rootRegistry = ChioRootRegistry(rootRegistry_);
        identityRegistry = IChioIdentityRegistry(identityRegistry_);
    }

    function deriveEscrowId(EscrowTerms calldata terms) external view returns (bytes32 escrowId) {
        return _deriveEscrowId(terms);
    }

    function createEscrow(EscrowTerms calldata terms) external returns (bytes32 escrowId) {
        if (terms.depositor != msg.sender) revert UnauthorizedCaller();
        escrowId = _createEscrow(terms);
        _transferFromToken(terms.token, msg.sender, address(this), terms.maxAmount);
    }

    function createEscrowWithPermit(
        EscrowTerms calldata terms,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bytes32 escrowId) {
        if (terms.depositor != msg.sender) revert UnauthorizedCaller();
        IERC20Permit(terms.token).permit(
            msg.sender,
            address(this),
            terms.maxAmount,
            permitDeadline,
            v,
            r,
            s
        );
        escrowId = _createEscrow(terms);
        _transferFromToken(terms.token, msg.sender, address(this), terms.maxAmount);
    }

    function releaseWithProof(
        bytes32,
        bytes32[] calldata,
        bytes32,
        bytes32,
        uint256
    ) external pure {
        revert ProofMetadataRequired();
    }

    function releaseWithProofDetailed(
        bytes32 escrowId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 settledAmount
    ) external {
        EscrowState storage escrow = _requireEscrow(escrowId);
        _requireBeneficiary(escrow);
        _ensureLive(escrow);
        _ensureReleaseAmount(escrow, settledAmount);
        if (!rootRegistry.verifyInclusionDetailed(proof, root, receiptHash, escrow.terms.operator)) {
            revert InvalidSignature();
        }
        _release(escrowId, escrow, settledAmount, receiptHash, false);
    }

    function releaseWithSignature(
        bytes32 escrowId,
        bytes32 receiptHash,
        uint256 settledAmount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        EscrowState storage escrow = _requireEscrow(escrowId);
        _requireBeneficiary(escrow);
        _ensureLive(escrow);
        _ensureReleaseAmount(escrow, settledAmount);

        IChioIdentityRegistry.OperatorRecord memory operatorRecord =
            identityRegistry.getOperator(escrow.terms.operator);
        if (operatorRecord.edKeyHash != escrow.terms.operatorKeyHash) {
            revert OperatorKeyHashMismatch();
        }

        bytes32 digest = keccak256(
            abi.encodePacked(
                block.chainid, address(this), escrowId, receiptHash, settledAmount
            )
        );
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != operatorRecord.settlementKey) {
            revert InvalidSignature();
        }

        _release(escrowId, escrow, settledAmount, receiptHash, false);
    }

    function partialReleaseWithProof(
        bytes32,
        bytes32[] calldata,
        bytes32,
        bytes32,
        uint256
    ) external pure {
        revert ProofMetadataRequired();
    }

    function partialReleaseWithProofDetailed(
        bytes32 escrowId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 amount
    ) external {
        EscrowState storage escrow = _requireEscrow(escrowId);
        _requireBeneficiary(escrow);
        _ensureLive(escrow);
        _ensureReleaseAmount(escrow, amount);
        if (!rootRegistry.verifyInclusionDetailed(proof, root, receiptHash, escrow.terms.operator)) {
            revert InvalidSignature();
        }
        _release(escrowId, escrow, amount, receiptHash, true);
    }

    function refund(bytes32 escrowId) external {
        EscrowState storage escrow = _requireEscrow(escrowId);
        if (escrow.refunded) revert EscrowAlreadyRefunded();
        if (block.timestamp <= escrow.terms.deadline) revert EscrowNotExpired();

        escrow.refunded = true;
        uint256 remaining = escrow.deposited - escrow.released;
        if (remaining > 0) {
            _transferToken(escrow.terms.token, escrow.terms.depositor, remaining);
        }
        emit EscrowRefunded(escrowId, remaining);
    }

    function getEscrow(bytes32 escrowId)
        external
        view
        returns (EscrowTerms memory terms, uint256 deposited, uint256 released, bool refunded)
    {
        EscrowState storage escrow = escrows[escrowId];
        return (escrow.terms, escrow.deposited, escrow.released, escrow.refunded);
    }

    function _createEscrow(EscrowTerms calldata terms) internal returns (bytes32 escrowId) {
        if (
            terms.capabilityId == bytes32(0) ||
            terms.beneficiary == address(0) ||
            terms.token == address(0) ||
            terms.maxAmount == 0 ||
            terms.deadline <= block.timestamp ||
            !identityRegistry.isOperator(terms.operator)
        ) {
            revert InvalidTerms();
        }

        IChioIdentityRegistry.OperatorRecord memory operatorRecord =
            identityRegistry.getOperator(terms.operator);
        if (operatorRecord.edKeyHash != terms.operatorKeyHash) revert OperatorKeyHashMismatch();

        escrowId = _deriveEscrowId(terms);
        if (escrows[escrowId].terms.depositor != address(0)) revert EscrowAlreadyExists();

        escrows[escrowId] = EscrowState({
            terms: terms,
            deposited: terms.maxAmount,
            released: 0,
            refunded: false
        });

        emit EscrowCreated(
            escrowId,
            terms.capabilityId,
            terms.depositor,
            terms.beneficiary,
            terms.token,
            terms.maxAmount,
            terms.deadline,
            terms.operator
        );
    }

    function _deriveEscrowId(EscrowTerms calldata terms) internal view returns (bytes32 escrowId) {
        escrowId = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                terms.capabilityId,
                terms.depositor,
                terms.beneficiary,
                terms.token,
                terms.maxAmount,
                terms.deadline,
                terms.operator,
                terms.operatorKeyHash
            )
        );
    }

    function _requireEscrow(bytes32 escrowId) internal view returns (EscrowState storage escrow) {
        escrow = escrows[escrowId];
        if (escrow.terms.depositor == address(0)) revert EscrowNotFound();
    }

    function _ensureLive(EscrowState storage escrow) internal view {
        if (escrow.refunded) revert EscrowAlreadyRefunded();
        if (block.timestamp > escrow.terms.deadline) revert EscrowExpired();
    }

    function _requireBeneficiary(EscrowState storage escrow) internal view {
        if (msg.sender != escrow.terms.beneficiary) revert UnauthorizedCaller();
    }

    function _ensureReleaseAmount(EscrowState storage escrow, uint256 amount) internal view {
        if (amount == 0 || escrow.released + amount > escrow.deposited) {
            revert InvalidReleaseAmount();
        }
    }

    function _release(
        bytes32 escrowId,
        EscrowState storage escrow,
        uint256 amount,
        bytes32 receiptHash,
        bool isPartial
    ) internal {
        escrow.released += amount;
        _transferToken(escrow.terms.token, escrow.terms.beneficiary, amount);
        if (isPartial && escrow.released < escrow.deposited) {
            emit EscrowPartialRelease(
                escrowId, amount, escrow.deposited - escrow.released, receiptHash
            );
        } else {
            emit EscrowReleased(escrowId, amount, receiptHash);
        }
    }

    function _transferFromToken(address token, address from, address to, uint256 amount) internal {
        bool ok = IERC20(token).transferFrom(from, to, amount);
        if (!ok) revert TransferFailed();
    }

    function _transferToken(address token, address to, uint256 amount) internal {
        bool ok = IERC20(token).transfer(to, amount);
        if (!ok) revert TransferFailed();
    }
}
