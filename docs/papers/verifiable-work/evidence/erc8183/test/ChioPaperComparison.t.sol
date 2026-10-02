// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MockUSDC} from "upstream/contracts/mocks/MockUSDC.sol";
import {ChioWorkClaimEscrow} from "../provenance/chio/contracts/src/experimental/ChioWorkClaimEscrow.sol";

/// @notice Same zero-fee token, roles, and 100+60 units as the ERC8183 pair fixture.
contract ChioPaperComparisonTest is Test {
    ChioWorkClaimEscrow internal core;
    MockUSDC internal token;
    address internal buyer = makeAddr("buyer");
    address internal intermediary = makeAddr("intermediary");
    address internal worker = makeAddr("worker");
    uint256 internal constant EVALUATOR_KEY = 0x8183;
    address internal evaluator;
    uint64 internal base;

    function setUp() public {
        vm.warp(1_000_000);
        base = uint64(block.timestamp);
        evaluator = vm.addr(EVALUATOR_KEY);
        token = new MockUSDC();
        core = new ChioWorkClaimEscrow(address(this));
        core.setTokenAllowed(address(token), true);
        core.setVerifierAllowed(evaluator, true);
        token.mint(buyer, 100);
        vm.prank(buyer);
        token.approve(address(core), type(uint256).max);
        vm.prank(intermediary);
        token.approve(address(core), type(uint256).max);
    }

    function terms(address payer, address beneficiary, uint256 amount, bytes32 agreement, uint64 offset)
        internal view returns (ChioWorkClaimEscrow.Terms memory)
    {
        return ChioWorkClaimEscrow.Terms({
            agreementDigest: agreement, payer: payer, beneficiary: beneficiary,
            verifier: evaluator, token: address(token), amount: amount,
            submitBy: base + offset + 1 hours,
            challengeUntil: base + offset + 2 hours,
            resolveBy: base + offset + 3 hours,
            refundAfter: base + offset + 4 hours
        });
    }

    function fund(address payer, address beneficiary, uint256 amount, bytes32 agreement, uint64 offset)
        internal returns (bytes32 id)
    {
        ChioWorkClaimEscrow.Terms memory t = terms(payer, beneficiary, amount, agreement, offset);
        vm.prank(payer);
        id = core.fund(t);
    }

    function fundPair(uint64 childOffset) internal returns (bytes32 parent, bytes32 child) {
        token.mint(intermediary, 60);
        parent = fund(buyer, intermediary, 100, keccak256("parent"), 0);
        child = fund(intermediary, worker, 60, keccak256("child"), childOffset);
        assertBalances(0, 0, 0, 160, 160);
    }

    function submit(bytes32 id, address provider) internal {
        vm.prank(provider);
        core.submitClaim(id, keccak256(abi.encode("delivered", id)));
    }

    function decision(bytes32 id, bool accepted) internal {
        (bytes32 digest, bytes memory signature) = signedDecision(id, accepted);
        core.recordDecision(id, digest, accepted, signature);
    }

    function signedDecision(bytes32 id, bool accepted) internal view returns (bytes32 digest, bytes memory signature) {
        ChioWorkClaimEscrow.Work memory w = core.getWork(id);
        digest = keccak256(abi.encode("decision", id, accepted));
        bytes32 domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("ChioWorkClaimEscrow"), keccak256("1"), block.chainid, address(core)
        ));
        bytes32 body = keccak256(abi.encode(
            keccak256("ChioWorkDecision(bytes32 allocationId,bytes32 agreementDigest,bytes32 commitment,bytes32 decisionDigest,bool accepted,address beneficiary,address token,uint256 amount)"),
            id, w.terms.agreementDigest, w.commitment, digest, accepted,
            w.terms.beneficiary, w.terms.token, w.terms.amount
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EVALUATOR_KEY, keccak256(abi.encodePacked("\x19\x01", domain, body)));
        signature = abi.encodePacked(r, s, v);
    }

    function withdraw(bytes32 id, address provider) internal {
        vm.prank(provider);
        core.withdrawPayment(id);
    }

    function assertBalances(uint256 b, uint256 i, uint256 w, uint256 e, uint256 total) internal view {
        assertEq(token.balanceOf(buyer), b, "buyer balance");
        assertEq(token.balanceOf(intermediary), i, "intermediary balance");
        assertEq(token.balanceOf(worker), w, "worker balance");
        assertEq(token.balanceOf(address(core)), e, "escrow balance");
        assertEq(b + i + w + e, total, "conservation");
        assertEq(token.totalSupply(), total, "fixture supply");
    }

    function test_successfulParentAndChildExchangeSeparatesPayableAndPaid() public {
        (bytes32 parent, bytes32 child) = fundPair(0);
        submit(child, worker);
        submit(parent, intermediary);
        vm.warp(base + 2 hours + 1);
        decision(child, true);
        decision(parent, true);
        assertEq(uint256(core.getWork(child).state), uint256(ChioWorkClaimEscrow.State.Payable));
        assertEq(uint256(core.getWork(parent).state), uint256(ChioWorkClaimEscrow.State.Payable));
        assertBalances(0, 0, 0, 160, 160);
        withdraw(child, worker);
        withdraw(parent, intermediary);
        assertBalances(0, 100, 60, 0, 160);
        emit log("Chio success: buyer=0 intermediary=100 worker=60 escrow=0 supply=160");
    }

    function test_independentChildPaymentSurvivesParentRejection() public {
        (bytes32 parent, bytes32 child) = fundPair(0);
        submit(child, worker);
        submit(parent, intermediary);
        vm.warp(base + 2 hours + 1);
        decision(child, true);
        withdraw(child, worker);
        decision(parent, false);
        core.withdrawRefund(parent);
        assertBalances(100, 0, 60, 0, 160);
        emit log("Chio parent rejected after child paid: buyer=100 intermediary=0 worker=60 escrow=0 supply=160");
    }

    function test_earnedChildRemainsWithdrawableAfterParentRefundAndAdminChanges() public {
        (bytes32 parent, bytes32 child) = fundPair(0);
        submit(child, worker);
        submit(parent, intermediary);
        vm.warp(base + 2 hours + 1);
        decision(child, true);
        vm.warp(base + 4 hours + 1);
        core.withdrawRefund(parent);
        assertBalances(100, 0, 0, 60, 160);
        assertEq(uint256(core.getWork(child).state), uint256(ChioWorkClaimEscrow.State.Payable));
        core.setPaused(true);
        core.setTokenAllowed(address(token), false);
        core.setVerifierAllowed(evaluator, false);
        vm.warp(base + 100 days);
        withdraw(child, worker);
        assertBalances(100, 0, 60, 0, 160);
    }

    function test_independentChildCanCompleteAfterParentExpiryRefund() public {
        (bytes32 parent, bytes32 child) = fundPair(4 hours);
        submit(child, worker);
        submit(parent, intermediary);
        vm.warp(base + 4 hours + 1);
        core.withdrawRefund(parent);
        assertBalances(100, 0, 0, 60, 160);
        vm.warp(base + 6 hours + 1);
        decision(child, true);
        withdraw(child, worker);
        assertBalances(100, 0, 60, 0, 160);
    }

    function test_sameOneHundredUnitsCannotFundTwoSixtyUnitJobs() public {
        fund(buyer, intermediary, 60, keccak256("first"), 0);
        ChioWorkClaimEscrow.Terms memory t = terms(buyer, worker, 60, keccak256("second"), 0);
        vm.expectRevert(ChioWorkClaimEscrow.TransferFailed.selector);
        vm.prank(buyer);
        core.fund(t);
        assertBalances(40, 0, 0, 60, 100);
    }

    function test_unsettledParentBudgetCannotFundChildWithoutWorkingCapital() public {
        fund(buyer, intermediary, 100, keccak256("parent"), 0);
        ChioWorkClaimEscrow.Terms memory t = terms(intermediary, worker, 60, keccak256("child"), 0);
        vm.expectRevert(ChioWorkClaimEscrow.TransferFailed.selector);
        vm.prank(intermediary);
        core.fund(t);
        assertBalances(0, 0, 0, 100, 100);
    }

    function test_evaluatorOutageRefundsSubmittedJobAfterDeadline() public {
        bytes32 id = fund(buyer, intermediary, 100, keccak256("outage"), 0);
        submit(id, intermediary);
        vm.warp(base + 4 hours + 1);
        core.withdrawRefund(id);
        assertBalances(100, 0, 0, 0, 100);
    }

    function test_newAcceptanceRejectedAfterResolveByEvenBeforeRefund() public {
        bytes32 id = fund(buyer, intermediary, 100, keccak256("late"), 0);
        submit(id, intermediary);
        vm.warp(base + 3 hours + 1);
        (bytes32 digest, bytes memory signature) = signedDecision(id, true);
        vm.expectRevert(ChioWorkClaimEscrow.OutsideResolutionWindow.selector);
        core.recordDecision(id, digest, true, signature);
        assertBalances(0, 0, 0, 100, 100);
    }
}
