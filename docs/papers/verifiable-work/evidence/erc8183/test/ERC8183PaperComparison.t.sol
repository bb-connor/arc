// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ERC8183} from "upstream/contracts/ERC8183.sol";
import {MockUSDC} from "upstream/contracts/mocks/MockUSDC.sol";

/// @notice Local comparative fixtures against the unmodified upstream implementation.
/// Distinct addresses model roles, not independent real-world operators.
/// Token amounts are raw integer units; fees are zero in both compared systems.
contract ERC8183PaperComparisonTest is Test {
    ERC8183 internal core;
    MockUSDC internal token;
    address internal buyer = makeAddr("buyer");
    address internal intermediary = makeAddr("intermediary");
    address internal worker = makeAddr("worker");
    address internal evaluator = makeAddr("evaluator");
    address internal stranger = makeAddr("stranger");
    uint48 internal expiry;

    function setUp() public {
        vm.warp(1_000_000);
        expiry = uint48(block.timestamp + 1 hours);
        token = new MockUSDC();
        ERC8183 implementation = new ERC8183();
        core = ERC8183(address(new ERC1967Proxy(
            address(implementation), abi.encodeCall(ERC8183.initialize, (address(this), address(this)))
        )));
        core.setPaymentTokenAllowed(address(token), true);
        token.mint(buyer, 100);
        vm.prank(buyer);
        token.approve(address(core), type(uint256).max);
        vm.prank(intermediary);
        token.approve(address(core), type(uint256).max);
        assertEq(core.platformFeeBP(), 0);
        assertEq(core.evaluatorFeeBP(), 0);
    }

    function openJob(address client, address provider, uint256 amount, uint48 until)
        internal returns (uint256 job)
    {
        vm.prank(client);
        job = core.createJob(provider, evaluator, until, "paper fixture", address(0), 0);
        vm.prank(provider);
        core.setBudget(job, address(token), amount, "");
    }

    function fundJob(address client, address provider, uint256 amount, uint48 until)
        internal returns (uint256 job)
    {
        job = openJob(client, provider, amount, until);
        vm.prank(client);
        core.fund(job, address(token), amount, "");
    }

    function fundPair() internal returns (uint256 parent, uint256 child) {
        // Independent 60-unit working capital is essential and is also supplied to Chio.
        token.mint(intermediary, 60);
        parent = fundJob(buyer, intermediary, 100, expiry);
        child = fundJob(intermediary, worker, 60, expiry + 3 hours);
        assertBalances(0, 0, 0, 160, 160);
    }

    function submitJob(uint256 job, address provider) internal {
        vm.prank(provider);
        core.submit(job, keccak256(abi.encode("delivered", job)), "");
    }

    function completeJob(uint256 job) internal {
        vm.prank(evaluator);
        core.complete(job, keccak256(abi.encode("accepted", job)), "");
    }

    function assertBalances(uint256 b, uint256 i, uint256 w, uint256 e, uint256 total) internal view {
        assertEq(token.balanceOf(buyer), b, "buyer balance");
        assertEq(token.balanceOf(intermediary), i, "intermediary balance");
        assertEq(token.balanceOf(worker), w, "worker balance");
        assertEq(token.balanceOf(address(core)), e, "escrow balance");
        assertEq(b + i + w + e, total, "conservation");
        assertEq(token.totalSupply(), total, "fixture supply");
    }

    function test_successfulParentAndChildExchangePaysImmediately() public {
        (uint256 parent, uint256 child) = fundPair();
        submitJob(child, worker);
        completeJob(child);
        assertEq(uint256(core.getJob(child).status), uint256(ERC8183.JobStatus.Completed));
        assertBalances(0, 0, 60, 100, 160);
        submitJob(parent, intermediary);
        completeJob(parent);
        assertBalances(0, 100, 60, 0, 160);
        emit log("ERC8183 success: buyer=0 intermediary=100 worker=60 escrow=0 supply=160");
    }

    function test_independentChildPaymentSurvivesParentRejection() public {
        (uint256 parent, uint256 child) = fundPair();
        submitJob(child, worker);
        completeJob(child);
        submitJob(parent, intermediary);
        vm.prank(evaluator);
        core.reject(parent, bytes32("parent failed"), "");
        assertEq(uint256(core.getJob(parent).status), uint256(ERC8183.JobStatus.Rejected));
        assertEq(uint256(core.getJob(child).status), uint256(ERC8183.JobStatus.Completed));
        assertBalances(100, 0, 60, 0, 160);
        emit log("ERC8183 parent rejected after child paid: buyer=100 intermediary=0 worker=60 escrow=0 supply=160");
    }

    function test_independentChildCanCompleteAfterParentExpiryRefund() public {
        (uint256 parent, uint256 child) = fundPair();
        submitJob(child, worker);
        submitJob(parent, intermediary);
        vm.warp(uint256(expiry) + core.EVALUATION_GRACE_PERIOD());
        vm.prank(stranger);
        core.claimRefund(parent);
        assertBalances(100, 0, 0, 60, 160);
        completeJob(child);
        assertBalances(100, 0, 60, 0, 160);
        emit log("ERC8183 child completed after parent refund: buyer=100 intermediary=0 worker=60 escrow=0 supply=160");
    }

    function test_sameOneHundredUnitsCannotFundTwoSixtyUnitJobs() public {
        uint256 first = fundJob(buyer, intermediary, 60, expiry);
        uint256 second = openJob(buyer, worker, 60, expiry);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, buyer, 40, 60));
        vm.prank(buyer);
        core.fund(second, address(token), 60, "");
        assertEq(uint256(core.getJob(first).status), uint256(ERC8183.JobStatus.Funded));
        assertEq(uint256(core.getJob(second).status), uint256(ERC8183.JobStatus.Open));
        assertBalances(40, 0, 0, 60, 100);
    }

    function test_unsettledParentBudgetCannotFundChildWithoutWorkingCapital() public {
        fundJob(buyer, intermediary, 100, expiry);
        uint256 child = openJob(intermediary, worker, 60, expiry);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, intermediary, 0, 60));
        vm.prank(intermediary);
        core.fund(child, address(token), 60, "");
        assertBalances(0, 0, 0, 100, 100);
    }

    function test_evaluatorOutageRefundsSubmittedJobAfterGrace() public {
        uint256 job = fundJob(buyer, intermediary, 100, expiry);
        submitJob(job, intermediary);
        vm.warp(expiry);
        vm.expectRevert(ERC8183.GracePeriodActive.selector);
        core.claimRefund(job);
        vm.warp(uint256(expiry) + core.EVALUATION_GRACE_PERIOD());
        vm.prank(stranger);
        core.claimRefund(job);
        assertEq(uint256(core.getJob(job).status), uint256(ERC8183.JobStatus.Expired));
        assertBalances(100, 0, 0, 0, 100);
    }

    function test_afterGraceCompletionCanWinIfRefundHasNotExecuted() public {
        uint256 job = fundJob(buyer, intermediary, 100, expiry);
        submitJob(job, intermediary);
        vm.warp(uint256(expiry) + core.EVALUATION_GRACE_PERIOD() + 10 days);
        completeJob(job);
        vm.expectRevert(ERC8183.WrongStatus.selector);
        core.claimRefund(job);
        assertBalances(0, 100, 0, 0, 100);
    }

    function test_afterGraceRefundPreventsLaterCompletion() public {
        uint256 job = fundJob(buyer, intermediary, 100, expiry);
        submitJob(job, intermediary);
        vm.warp(uint256(expiry) + core.EVALUATION_GRACE_PERIOD());
        core.claimRefund(job);
        vm.expectRevert(ERC8183.WrongStatus.selector);
        vm.prank(evaluator);
        core.complete(job, bytes32("late acceptance"), "");
        assertBalances(100, 0, 0, 0, 100);
    }

    function test_approvedMilestoneSurvivesJobRejectionWithRemainingRefund() public {
        uint256 job = fundJob(buyer, intermediary, 100, expiry);
        bytes32 deliverable = keccak256("accepted milestone");
        vm.prank(intermediary);
        core.submitClaim(job, 60, deliverable, "");
        vm.prank(evaluator);
        core.approveClaim(job, 60, deliverable, "");
        assertEq(core.getJob(job).settledAmount, 60);
        assertBalances(0, 60, 0, 40, 100);
        vm.prank(evaluator);
        core.reject(job, bytes32("remaining work failed"), "");
        assertBalances(40, 60, 0, 0, 100);
        emit log("ERC8183 single-job milestone: buyer refund=40 provider paid=60 escrow=0 supply=100");
    }

    function test_pendingMilestoneOutageClientCanClearThenRefund() public {
        uint256 job = fundJob(buyer, intermediary, 100, expiry);
        bytes32 deliverable = keccak256("pending milestone");
        vm.prank(intermediary);
        core.submitClaim(job, 60, deliverable, "");
        vm.warp(uint256(expiry) + core.EVALUATION_GRACE_PERIOD());
        vm.expectRevert(ERC8183.PendingClaimExists.selector);
        core.claimRefund(job);
        vm.prank(buyer);
        core.rejectClaim(job, 60, deliverable, bytes32("client rejected"), "");
        core.claimRefund(job);
        assertBalances(100, 0, 0, 0, 100);
    }

    function test_clientCannotRejectFundedJobWhenEvaluatorIsDistinct() public {
        uint256 job = fundJob(buyer, intermediary, 100, expiry);
        vm.expectRevert(ERC8183.Unauthorized.selector);
        vm.prank(buyer);
        core.reject(job, bytes32("unilateral cancellation"), "");
        assertBalances(0, 0, 0, 100, 100);
    }

    function test_adminPauseBlocksRefundUntilUnpause() public {
        uint256 job = fundJob(buyer, intermediary, 100, expiry);
        vm.warp(expiry);
        core.pause();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        core.claimRefund(job);
        core.unpause();
        core.claimRefund(job);
        assertBalances(100, 0, 0, 0, 100);
    }
}
